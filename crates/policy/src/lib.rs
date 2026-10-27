//! Planarian policy (SPEC §11): one pure function from a transition and the
//! facts the executor derived to a `Decision`.
//!
//! `decide` has no `Proposal` parameter, so nothing a proposer writes can
//! reach it except the transition itself (I14). Its order:
//! 1. authorization (§11 caller identity),
//! 2. hard rejections (core target, catalog, locked option, allowlists),
//! 3. the per-transition table, then the global floors,
//! 4. cumulative-session classification (I11),
//! 5. the autonomy setting, which can only raise a tier to AskFirst and never
//!    touches a `Reject` (I5).
//!
//! Verus subset: no `dyn`, no `unsafe`, no floats. The properties the proofs
//! will state are checked exhaustively in the tests below until Verus runs in CI.

use planarian_schema::{
    Actor, ChangeId, ConfigDiff, Decision, DerivedFacts, Disruption, GenerationId, Hash, ModelId, PolicyVersion,
    Recovery, RejectReason, Scope, Sensitivities, Sensitivity, Session, SystemState, Tier, Transition, UnitId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Bumped by hand whenever the decision logic changes; part of `PolicyVersion`.
pub const POLICY_REVISION: &str = "phase-a.1";

/// Owner settings (not manifest options, not proposal fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// `Observe`, `Runtime` or `Tested`. Anything above it becomes AskFirst.
    pub max_tier: Tier,
    /// `services.planarian.userControllable`: system unit names an
    /// unprivileged user may act on.
    pub user_controllable_units: BTreeSet<String>,
    /// Catalog entries an unprivileged user may apply (display scaling, …).
    pub user_controllable_changes: BTreeSet<ChangeId>,
    /// Runtime options an unprivileged user may set (their own Wi-Fi, …).
    pub user_controllable_options: BTreeSet<String>,
}

impl Default for Settings {
    /// §11 defaults: audio, display scaling, the user's own Wi-Fi selection.
    fn default() -> Self {
        Settings {
            max_tier: Tier::Tested,
            user_controllable_units: ["pipewire", "wireplumber"].map(String::from).into(),
            user_controllable_changes: ["font-scale", "wifi-select"].map(|s| ChangeId(s.into())).into(),
            user_controllable_options: ["font.scale", "audio.volume", "display.brightness", "wifi.network"]
                .map(String::from)
                .into(),
        }
    }
}

/// Shipped tables. Hashed into `PolicyVersion`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tables {
    /// Change-catalog entry ids (§9).
    pub catalog: BTreeSet<ChangeId>,
    /// The core-owned runtime-settable options (§12a).
    pub runtime_allowlist: BTreeSet<String>,
    /// Option-path prefix → sensitivity. Longest prefix wins; no match is Routine.
    pub option_sensitivity: Vec<(String, Sensitivities)>,
    /// Hash-pinned model catalog (Phase B; empty in A).
    pub model_catalog: BTreeSet<ModelId>,
}

impl Tables {
    pub fn option_sensitivity(&self, path: &str) -> Sensitivities {
        self.option_sensitivity
            .iter()
            .filter(|(prefix, _)| path == prefix || path.starts_with(&format!("{prefix}.")))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| Sensitivities::of(&[Sensitivity::Routine]))
    }

    pub fn diff_sensitivity(&self, diff: &ConfigDiff) -> Sensitivities {
        diff.options.keys().fold(Sensitivities::default(), |acc, p| acc.union(&self.option_sensitivity(p)))
    }
}

pub fn policy_version(tables: &Tables) -> PolicyVersion {
    let mut bytes = format!("planarian-policy {} {}\n", env!("CARGO_PKG_VERSION"), POLICY_REVISION).into_bytes();
    bytes.extend(serde_json::to_vec(tables).expect("tables serialize"));
    PolicyVersion(Hash::of(&bytes))
}

/// Established by the daemon from `SO_PEERCRED` and logind, never from the proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub caller: Actor,
    /// Root, or a member of `planarian-admin`.
    pub admin: bool,
    /// The caller has a local (non-remote) session.
    pub local_session: bool,
    /// The session the transition would disrupt is the caller's own.
    pub owns_affected_session: bool,
}

impl Authorization {
    pub fn daemon() -> Authorization {
        Authorization { caller: Actor::Daemon, admin: false, local_session: false, owns_affected_session: false }
    }
}

/// Everything `decide` reads.
#[derive(Clone, Debug)]
pub struct Input<'a> {
    pub transition: &'a Transition,
    pub facts: &'a DerivedFacts,
    pub state: &'a SystemState,
    pub session: &'a Session,
    pub authz: &'a Authorization,
    pub settings: &'a Settings,
    pub tables: &'a Tables,
    /// Option paths the owner set with `mkForce` (§9 `locked_if`).
    pub locked: &'a BTreeSet<String>,
    /// For a `Revert` inside a transaction: the `revert_to` recorded at Prepared.
    pub revert_to: Option<GenerationId>,
}

fn sec_or_ext(s: &Sensitivities) -> bool {
    s.contains(Sensitivity::Security) || s.contains(Sensitivity::External)
}

fn is_user(a: &Actor) -> bool {
    matches!(a, Actor::User { .. })
}

/// The units a transition names directly (its target), for authorization.
fn named_unit(t: &Transition) -> Option<&UnitId> {
    match t {
        Transition::RestartUnit(u) | Transition::StopUnit(u) | Transition::Unsuppress(u) => Some(u),
        Transition::StopAndSuppress { unit, .. } => Some(unit),
        Transition::Suppress(s) => Some(&s.unit),
        Transition::BindDriver { device, .. } => Some(device),
        _ => None,
    }
}

/// §11 authorization: a user may act on units in their own user scope and on
/// user-controllable system units; everything else needs administrator
/// authority. The daemon, the watchdog and the model are not users; their
/// proposals are governed by tiers, except `Resolve`, which only an
/// administrator may issue.
pub fn authorized(t: &Transition, facts: &DerivedFacts, authz: &Authorization, settings: &Settings) -> bool {
    let uid = match &authz.caller {
        Actor::User { uid } => *uid,
        _ => return !matches!(t, Transition::Resolve { .. }),
    };
    if authz.admin {
        return true;
    }
    let unit_ok = |u: &UnitId| match &u.scope {
        Scope::User { uid: owner, .. } => *owner == uid,
        Scope::System => settings.user_controllable_units.contains(&u.name),
    };
    match t {
        Transition::RestartUnit(_)
        | Transition::StopUnit(_)
        | Transition::Suppress(_)
        | Transition::Unsuppress(_)
        | Transition::StopAndSuppress { .. } => named_unit(t).is_some_and(unit_ok),
        Transition::ApplyChange { change, .. } => {
            settings.user_controllable_changes.contains(change)
                && facts.affected_units.iter().all(|u| match &u.scope {
                    Scope::User { uid: owner, .. } => *owner == uid,
                    Scope::System => true,
                })
        }
        Transition::SetRuntimeOption { path, .. } => settings.user_controllable_options.contains(path),
        _ => false,
    }
}

fn base_tier(i: &Input<'_>) -> Result<Tier, RejectReason> {
    let f = i.facts;
    let caller_is_user = is_user(&i.authz.caller);
    let ask_if = |cond: bool, base: Tier| if cond { Tier::AskFirst } else { base };
    Ok(match i.transition {
        Transition::RestartUnit(_) | Transition::StopUnit(_) => ask_if(sec_or_ext(&f.sensitivity), Tier::Runtime),
        Transition::Suppress(_) | Transition::Unsuppress(_) | Transition::StopAndSuppress { .. } => {
            ask_if(!caller_is_user || sec_or_ext(&f.sensitivity), Tier::Runtime)
        }
        Transition::BindDriver { .. } => ask_if(f.sensitivity.contains(Sensitivity::Security), Tier::Tested),
        Transition::ApplyChange { .. } => {
            ask_if(!f.sensitivity.only_routine() || f.touches_manifest || f.touches_canonical_probe, Tier::Tested)
        }
        Transition::SwitchGeneration(g) => {
            let vetted = Some(*g) == i.state.live_tested || *g == i.state.known_good;
            ask_if(!vetted, Tier::Tested)
        }
        Transition::Revert { to } => {
            let vetted = Some(*to) == i.state.live_tested || *to == i.state.known_good;
            let mismatched = i.revert_to.is_some_and(|r| r != *to);
            ask_if(!vetted || mismatched, Tier::Tested)
        }
        Transition::Rollback => ask_if(sec_or_ext(&f.sensitivity), Tier::Runtime),
        Transition::LoadModel(m) => {
            if !i.tables.model_catalog.contains(m) {
                return Err(RejectReason::NotInCatalog);
            }
            Tier::Tested
        }
        Transition::RestoreSnapshot(_) => Tier::AskFirst,
        Transition::CollectGarbage { .. } => Tier::Runtime,
        Transition::SetRuntimeOption { path, .. } => {
            if !i.tables.runtime_allowlist.contains(path) {
                return Err(RejectReason::NotInCatalog);
            }
            Tier::Runtime
        }
        Transition::Resolve { .. } => Tier::Runtime,
    })
}

/// The global floors (§11), applied to every transition kind.
fn floors(i: &Input<'_>, tier: Tier) -> Tier {
    let f = i.facts;
    let a = i.authz;
    let mut t = tier;
    if f.recovery == Recovery::NonReversible {
        t = t.max(Tier::AskFirst);
    }
    let own = is_user(&a.caller) && a.owns_affected_session;
    if matches!(f.disruption, Disruption::SessionLoss | Disruption::DataInterruption) && !own {
        t = t.max(Tier::AskFirst);
    }
    if f.disruption == Disruption::ConnectivityLoss && !(is_user(&a.caller) && a.local_session) {
        t = t.max(Tier::AskFirst);
    }
    t
}

pub fn decide(i: &Input<'_>) -> Decision {
    let f = i.facts;
    if !authorized(i.transition, f, i.authz, i.settings) {
        return Decision::Reject(RejectReason::Unauthorized);
    }
    if f.touches_core || f.sensitivity.contains(Sensitivity::Core) {
        return Decision::Reject(RejectReason::CoreTarget);
    }
    if let Transition::ApplyChange { change, .. } = i.transition
        && !i.tables.catalog.contains(change)
    {
        return Decision::Reject(RejectReason::NotInCatalog);
    }
    if let Some(diff) = &f.config_diff
        && diff.options.keys().any(|p| i.locked.contains(p))
    {
        return Decision::Reject(RejectReason::LockedOption);
    }
    let mut tier = match base_tier(i) {
        Ok(t) => t,
        Err(r) => return Decision::Reject(r),
    };
    tier = floors(i, tier);

    // I11: the session's cumulative effect, including this change, is classified
    // at least as high as anything in it.
    if let Some(diff) = &f.config_diff {
        let cumulative = i.session.cumulative.then(diff);
        if !i.tables.diff_sensitivity(&cumulative).only_routine() || !i.tables.diff_sensitivity(diff).only_routine() {
            tier = tier.max(Tier::AskFirst);
        }
    }
    // A canonical probe's definition never changes below AskFirst (I10).
    if f.touches_canonical_probe {
        tier = tier.max(Tier::AskFirst);
    }
    // The autonomy setting raises, never lowers, and never touches Reject (I5).
    if tier > i.settings.max_tier {
        tier = Tier::AskFirst;
    }
    Decision::Allow(tier)
}

#[cfg(test)]
mod tests;
