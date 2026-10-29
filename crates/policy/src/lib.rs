//! Planarian policy (SPEC §11): one pure function from a transition and the
//! facts the executor derived to a `Decision`.
//!
//! `decide` has no `Proposal` parameter, so nothing a proposer writes can
//! reach it except the transition itself (I14). Its order:
//! 1. authorization (§11 caller identity and capabilities),
//! 2. hard rejections (core target, catalog, locked option, allowlists),
//! 3. the per-transition table, then the global floors (including the
//!    security floor, which asks an administrator: I16),
//! 4. cumulative-session classification (I11),
//! 5. the autonomy setting, which can only raise a tier to AskFirst and never
//!    touches a `Reject` (I5).
//!
//! Verified with Verus (SPEC §17a): `decide` is proved equal to `decide_spec`,
//! and the properties are proved about `decide_spec` in `proofs`. Sets of
//! names are vectors searched linearly, because vstd specifies `BTreeSet` only
//! for key types with an ordering spec, which `String` lacks
//! (docs/deviations.md). Run: `cargo verus verify -p planarian-policy`.

// Verus idioms: `&Vec` for its `@` view, explicit `match` and nested `if`
// rather than `matches!` and let-chains.
#![allow(
    clippy::ptr_arg,
    clippy::match_like_matches_macro,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::redundant_pattern_matching
)]

use planarian_schema::{
    Actor, ApproverClass, Authorization, Capabilities, ChangeId, ConfigDiff, Decision, DerivedFacts, Disruption,
    GenerationId, Grant, Hash, ModelId, PolicyVersion, PrincipalId, Recovery, RejectReason, Scope, Sensitivities, Tier,
    Transition, UnitId,
};
use serde::{Deserialize, Serialize};
use vstd::prelude::*;

pub mod proofs;

/// Bumped by hand whenever the decision logic changes; part of `PolicyVersion`.
pub const POLICY_REVISION: &str = "phase-a.3";

verus! {

// ---------- Names: vectors and linear search ----------

pub open spec fn has_str(v: Seq<String>, s: Seq<char>) -> bool {
    exists|j: int| 0 <= j < v.len() && (#[trigger] v[j])@ == s
}

pub open spec fn has_change(v: Seq<ChangeId>, c: ChangeId) -> bool {
    exists|j: int| 0 <= j < v.len() && (#[trigger] v[j]).0@ == c.0@
}

pub open spec fn has_model(v: Seq<ModelId>, m: ModelId) -> bool {
    exists|j: int| 0 <= j < v.len() && (#[trigger] v[j]).0@ == m.0@
}

/// `path` is `prefix`, or lies under it: `prefix` followed by `.` and more.
pub open spec fn under(path: Seq<char>, prefix: Seq<char>) -> bool {
    path == prefix || (prefix.len() < path.len() && path.subrange(0, prefix.len() as int) == prefix
        && path[prefix.len() as int] == '.')
}

fn str_eq(a: &str, b: &str) -> (r: bool)
    ensures
        r == (a@ == b@),
{
    let n = a.unicode_len();
    if n != b.unicode_len() {
        return false;
    }
    let mut i: usize = 0;
    while i < n
        invariant
            n == a@.len(),
            n == b@.len(),
            i <= n,
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases n - i,
    {
        if a.get_char(i) != b.get_char(i) {
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}

pub fn contains_str(v: &Vec<String>, s: &str) -> (r: bool)
    ensures
        r == has_str(v@, s@),
{
    let mut i: usize = 0;
    while i < v.len()
        invariant
            i <= v@.len(),
            forall|j: int| 0 <= j < i ==> (#[trigger] v@[j])@ != s@,
        decreases v.len() - i,
    {
        if str_eq(v[i].as_str(), s) {
            return true;
        }
        i += 1;
    }
    false
}

pub fn contains_change(v: &Vec<ChangeId>, c: &ChangeId) -> (r: bool)
    ensures
        r == has_change(v@, *c),
{
    let mut i: usize = 0;
    while i < v.len()
        invariant
            i <= v@.len(),
            forall|j: int| 0 <= j < i ==> (#[trigger] v@[j]).0@ != c.0@,
        decreases v.len() - i,
    {
        if str_eq(v[i].0.as_str(), c.0.as_str()) {
            return true;
        }
        i += 1;
    }
    false
}

pub fn contains_model(v: &Vec<ModelId>, m: &ModelId) -> (r: bool)
    ensures
        r == has_model(v@, *m),
{
    let mut i: usize = 0;
    while i < v.len()
        invariant
            i <= v@.len(),
            forall|j: int| 0 <= j < i ==> (#[trigger] v@[j]).0@ != m.0@,
        decreases v.len() - i,
    {
        if str_eq(v[i].0.as_str(), m.0.as_str()) {
            return true;
        }
        i += 1;
    }
    false
}

pub fn is_under(path: &str, prefix: &str) -> (r: bool)
    ensures
        r == under(path@, prefix@),
{
    let n = path.unicode_len();
    let m = prefix.unicode_len();
    if m > n {
        return false;
    }
    let mut i: usize = 0;
    while i < m
        invariant
            n == path@.len(),
            m == prefix@.len(),
            m <= n,
            i <= m,
            forall|j: int| 0 <= j < i ==> path@[j] == prefix@[j],
        decreases m - i,
    {
        if path.get_char(i) != prefix.get_char(i) {
            assert(path@.subrange(0, m as int)[i as int] != prefix@[i as int]);
            return false;
        }
        i += 1;
    }
    assert(path@.subrange(0, m as int) =~= prefix@);
    if m == n {
        assert(path@ =~= prefix@);
        true
    } else {
        path.get_char(m) == '.'
    }
}

// ---------- Settings and tables ----------

/// Owner settings (not manifest options, not proposal fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Settings {
    /// `Observe`, `Runtime` or `Tested`. Anything above it becomes AskFirst.
    pub max_tier: Tier,
    /// `services.planarian.userControllable`: system unit names an
    /// unprivileged user may act on.
    pub user_controllable_units: Vec<String>,
    /// Catalog entries an unprivileged user may apply (display scaling, …).
    pub user_controllable_changes: Vec<ChangeId>,
    /// Runtime options an unprivileged user may set (their own Wi-Fi, …).
    pub user_controllable_options: Vec<String>,
}

/// Shipped tables. Hashed into `PolicyVersion`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Tables {
    /// Change-catalog entry ids (§9).
    pub catalog: Vec<ChangeId>,
    /// The core-owned runtime-settable options (§12a).
    pub runtime_allowlist: Vec<String>,
    /// Option-path prefix → sensitivity. Longest prefix wins (the later entry
    /// on a tie); no match is Routine.
    pub option_sensitivity: Vec<(String, Sensitivities)>,
    /// Hash-pinned model catalog (Phase B; empty in A).
    pub model_catalog: Vec<ModelId>,
}

pub open spec fn routine() -> Sensitivities {
    Sensitivities { routine: true, security: false, user_data: false, external: false, core: false }
}

/// The best match for `path` in `tbl`: the matched prefix's length (-1 for
/// none) and its sensitivity (Routine for none).
pub open spec fn lookup(tbl: Seq<(String, Sensitivities)>, path: Seq<char>) -> (int, Sensitivities)
    decreases tbl.len(),
{
    if tbl.len() == 0 {
        (-1, routine())
    } else {
        let prev = lookup(tbl.drop_last(), path);
        let k = tbl.last().0@;
        if under(path, k) && k.len() >= prev.0 {
            (k.len() as int, tbl.last().1)
        } else {
            prev
        }
    }
}

pub open spec fn path_non_routine(tb: Tables, path: Seq<char>) -> bool {
    !lookup(tb.option_sensitivity@, path).1.routine_only()
}

/// Some option the diff touches is classified above Routine.
pub open spec fn diff_non_routine(tb: Tables, d: ConfigDiff) -> bool {
    exists|j: int| 0 <= j < d.options.entries@.len() && path_non_routine(tb, (#[trigger] d.options.entries@[j]).0@)
}

/// Some option the diff touches was set by the owner with `mkForce`.
pub open spec fn diff_locked(locked: Seq<String>, d: ConfigDiff) -> bool {
    exists|j: int| 0 <= j < d.options.entries@.len() && has_str(locked, (#[trigger] d.options.entries@[j]).0@)
}

impl Tables {
    pub fn option_sensitivity(&self, path: &str) -> (r: Sensitivities)
        ensures
            r == lookup(self.option_sensitivity@, path@).1,
    {
        let tbl = &self.option_sensitivity;
        let mut best: Option<usize> = None;
        let mut sens = Sensitivities { routine: true, security: false, user_data: false, external: false, core: false };
        let mut i: usize = 0;
        while i < tbl.len()
            invariant
                i <= tbl@.len(),
                lookup(tbl@.subrange(0, i as int), path@) == (
                    match best {
                        None => -1int,
                        Some(b) => b as int,
                    },
                    sens,
                ),
            decreases tbl.len() - i,
        {
            let k = tbl[i].0.as_str();
            let len = k.unicode_len();
            let longer = match best {
                None => true,
                Some(b) => len >= b,
            };
            if is_under(path, k) && longer {
                best = Some(len);
                sens = tbl[i].1;
            }
            assert(tbl@.subrange(0, i as int + 1).drop_last() =~= tbl@.subrange(0, i as int));
            i += 1;
        }
        assert(tbl@.subrange(0, tbl@.len() as int) =~= tbl@);
        sens
    }
}

pub fn any_non_routine(tb: &Tables, d: &ConfigDiff) -> (r: bool)
    ensures
        r == diff_non_routine(*tb, *d),
{
    let mut i: usize = 0;
    while i < d.options.entries.len()
        invariant
            i <= d.options.entries@.len(),
            forall|j: int| 0 <= j < i ==> !path_non_routine(*tb, (#[trigger] d.options.entries@[j]).0@),
        decreases d.options.entries.len() - i,
    {
        if !tb.option_sensitivity(d.options.entries[i].0.as_str()).only_routine() {
            assert(path_non_routine(*tb, d.options.entries@[i as int].0@));
            return true;
        }
        i += 1;
    }
    false
}

pub fn any_locked(locked: &Vec<String>, d: &ConfigDiff) -> (r: bool)
    ensures
        r == diff_locked(locked@, *d),
{
    let mut i: usize = 0;
    while i < d.options.entries.len()
        invariant
            i <= d.options.entries@.len(),
            forall|j: int| 0 <= j < i ==> !has_str(locked@, (#[trigger] d.options.entries@[j]).0@),
        decreases d.options.entries.len() - i,
    {
        if contains_str(locked, d.options.entries[i].0.as_str()) {
            assert(has_str(locked@, d.options.entries@[i as int].0@));
            return true;
        }
        i += 1;
    }
    false
}

// ---------- Authorization (§11) ----------

pub open spec fn is_user(a: Actor) -> bool {
    match a {
        Actor::User { .. } => true,
        _ => false,
    }
}

/// A user holding administrator capability. Capabilities count only for
/// users in Phase A: agents are not constructed, and the daemon, watchdog and
/// model are never authorized users.
pub open spec fn is_admin(a: Authorization) -> bool {
    is_user(a.actor) && a.capabilities.administrator
}

/// A caller with a seat: a local, not a remote, session.
pub open spec fn is_local(a: Actor) -> bool {
    match a {
        Actor::User { seat, .. } => seat is Some,
        _ => false,
    }
}

/// The disruption lands on exactly the caller's own session (per session, not per uid).
pub open spec fn own_session(a: Actor, f: DerivedFacts) -> bool {
    match a {
        Actor::User { session, .. } => match session {
            Some(s) => f.affected_sessions@.len() == 1 && f.affected_sessions@[0]@ == s@,
            None => false,
        },
        _ => false,
    }
}

/// A unit a non-admin user `uid` may act on directly: their own user scope
/// (`OwnScope`) or a user-controllable system unit (`UserControllable`).
pub open spec fn unit_ok(u: UnitId, uid: u32, c: Capabilities, s: Settings) -> bool {
    match u.scope {
        Scope::User { uid: owner, .. } => c.own_scope && owner == uid,
        Scope::System => c.user_controllable && has_str(s.user_controllable_units@, u.name@),
    }
}

/// A unit a non-admin user's cataloged change may affect: their own, or any system unit.
pub open spec fn may_affect(u: UnitId, uid: u32) -> bool {
    match u.scope {
        Scope::User { uid: owner, .. } => owner == uid,
        Scope::System => true,
    }
}

pub open spec fn all_may_affect(units: Seq<UnitId>, uid: u32) -> bool {
    forall|j: int| 0 <= j < units.len() ==> may_affect(#[trigger] units[j], uid)
}

/// An override: `SetOverride`, `LiftOverride` or `StopAndSuppress`.
pub open spec fn is_override(t: Transition) -> bool {
    match t {
        Transition::SetOverride(_) | Transition::LiftOverride(_) | Transition::StopAndSuppress { .. } => true,
        _ => false,
    }
}

/// §11: a user may act on units in their own user scope and on
/// user-controllable system units; every other system action needs
/// administrator authority. Authorized to start a unit means authorized to
/// override it, and a non-administrator may also *ask* to override a
/// Security-sensitive unit (held for an administrator by the table). The
/// daemon, the watchdog and the model are not users: their proposals are
/// governed by tiers, except `Resolve`, which only an administrator may issue.
/// An agent (reserved) and the unattributed actor are never authorized.
pub open spec fn authorized_spec(t: Transition, f: DerivedFacts, a: Authorization, s: Settings) -> bool {
    match a.actor {
        Actor::User { uid, .. } => a.capabilities.administrator || match t {
            Transition::RestartUnit(u) => unit_ok(u, uid, a.capabilities, s),
            Transition::StopUnit(u) => unit_ok(u, uid, a.capabilities, s),
            Transition::LiftOverride(u) => unit_ok(u, uid, a.capabilities, s) || f.sensitivity.security,
            Transition::SetOverride(o) => unit_ok(o.unit, uid, a.capabilities, s) || f.sensitivity.security,
            Transition::StopAndSuppress { unit, .. } => unit_ok(unit, uid, a.capabilities, s)
                || f.sensitivity.security,
            Transition::ApplyChange { change, .. } => a.capabilities.user_controllable && has_change(
                s.user_controllable_changes@,
                change,
            ) && all_may_affect(f.affected_units@, uid),
            Transition::SetRuntimeOption { path, .. } => a.capabilities.user_controllable && has_str(
                s.user_controllable_options@,
                path@,
            ),
            _ => false,
        },
        Actor::Agent(_) => false,
        Actor::Unattributed => false,
        _ => match t {
            Transition::Resolve { .. } => false,
            _ => true,
        },
    }
}

fn unit_ok_exec(u: &UnitId, uid: u32, c: &Capabilities, s: &Settings) -> (r: bool)
    ensures
        r == unit_ok(*u, uid, *c, *s),
{
    match &u.scope {
        Scope::User { uid: owner, .. } => c.own_scope && *owner == uid,
        Scope::System => c.user_controllable && contains_str(&s.user_controllable_units, u.name.as_str()),
    }
}

#[verifier::loop_isolation(false)]
pub fn authorized(t: &Transition, facts: &DerivedFacts, authz: &Authorization, settings: &Settings) -> (r: bool)
    ensures
        r == authorized_spec(*t, *facts, *authz, *settings),
{
    let uid = match &authz.actor {
        Actor::User { uid, .. } => *uid,
        Actor::Agent(_) => return false,
        Actor::Unattributed => return false,
        _ => {
            return match t {
                Transition::Resolve { .. } => false,
                _ => true,
            };
        },
    };
    let c = &authz.capabilities;
    if c.administrator {
        return true;
    }
    let security = facts.sensitivity.security;
    match t {
        Transition::RestartUnit(u) => unit_ok_exec(u, uid, c, settings),
        Transition::StopUnit(u) => unit_ok_exec(u, uid, c, settings),
        Transition::LiftOverride(u) => unit_ok_exec(u, uid, c, settings) || security,
        Transition::SetOverride(o) => unit_ok_exec(&o.unit, uid, c, settings) || security,
        Transition::StopAndSuppress { unit, .. } => unit_ok_exec(unit, uid, c, settings) || security,
        Transition::ApplyChange { change, .. } => {
            if !c.user_controllable || !contains_change(&settings.user_controllable_changes, change) {
                return false;
            }
            let mut i: usize = 0;
            while i < facts.affected_units.len()
                invariant
                    i <= facts.affected_units@.len(),
                    forall|j: int| 0 <= j < i ==> may_affect(#[trigger] facts.affected_units@[j], uid),
                decreases facts.affected_units.len() - i,
            {
                let ok = match &facts.affected_units[i].scope {
                    Scope::User { uid: owner, .. } => *owner == uid,
                    Scope::System => true,
                };
                if !ok {
                    assert(!may_affect(facts.affected_units@[i as int], uid));
                    return false;
                }
                i += 1;
            }
            true
        },
        Transition::SetRuntimeOption { path, .. } => c.user_controllable && contains_str(
            &settings.user_controllable_options,
            path.as_str(),
        ),
        _ => false,
    }
}

// ---------- The decision ----------

pub open spec fn sec_or_ext(s: Sensitivities) -> bool {
    s.security || s.external
}

pub open spec fn ask_if(c: bool, t: Tier) -> Tier {
    if c {
        Tier::AskFirst
    } else {
        t
    }
}

/// `Administrator` if `c`, else `k`: classes only ever rise.
pub open spec fn admin_if(c: bool, k: ApproverClass) -> ApproverClass {
    if c {
        ApproverClass::Administrator
    } else {
        k
    }
}

pub open spec fn allow(t: Tier) -> Decision {
    Decision::Allow { tier: t, approver: ApproverClass::AnyApprover }
}

/// Known-good, or the live-tested generation: already shown to work.
pub open spec fn vetted(g: GenerationId, known_good: GenerationId, live_tested: Option<GenerationId>) -> bool {
    live_tested == Some(g) || g == known_good
}

/// Everything `decide` reads.
pub struct Input<'a> {
    pub transition: &'a Transition,
    pub facts: &'a DerivedFacts,
    pub known_good: GenerationId,
    pub live_tested: Option<GenerationId>,
    /// The session's cumulative diff before this change (I11).
    pub cumulative: &'a ConfigDiff,
    pub authz: &'a Authorization,
    pub settings: &'a Settings,
    pub tables: &'a Tables,
    /// Option paths the owner set with `mkForce` (§9 `locked_if`).
    pub locked: &'a Vec<String>,
    /// For a `Revert` inside a transaction: the `revert_to` recorded at Prepared.
    pub revert_to: Option<GenerationId>,
}

/// The override row (§11): AskFirst when the caller is not a user or the unit
/// is External-sensitive; held for an administrator when it is
/// Security-sensitive and the caller is not one.
pub open spec fn override_spec(f: DerivedFacts, a: Authorization) -> Decision {
    let held = f.sensitivity.security && !is_admin(a);
    Decision::Allow {
        tier: ask_if(!is_user(a.actor) || f.sensitivity.external || held, Tier::Runtime),
        approver: admin_if(held, ApproverClass::AnyApprover),
    }
}

/// The per-transition table (§11). The security-floor escalations of the
/// SwitchGeneration, Revert and Rollback rows are the `below_security_floor`
/// floor, which applies to every transition kind.
pub open spec fn base_spec(i: Input) -> Decision {
    let f = *i.facts;
    match *i.transition {
        Transition::RestartUnit(_) => allow(ask_if(sec_or_ext(f.sensitivity), Tier::Runtime)),
        Transition::StopUnit(_) => allow(ask_if(sec_or_ext(f.sensitivity), Tier::Runtime)),
        Transition::SetOverride(_) => override_spec(f, *i.authz),
        Transition::LiftOverride(_) => override_spec(f, *i.authz),
        Transition::StopAndSuppress { .. } => override_spec(f, *i.authz),
        Transition::BindDriver { .. } => allow(ask_if(f.sensitivity.security, Tier::Tested)),
        Transition::ApplyChange { .. } => allow(
            ask_if(!f.sensitivity.routine_only() || f.touches_manifest || f.touches_canonical_probe, Tier::Tested),
        ),
        Transition::SwitchGeneration(g) => allow(ask_if(!vetted(g, i.known_good, i.live_tested), Tier::Tested)),
        Transition::Revert { to } => allow(
            ask_if(
                !vetted(to, i.known_good, i.live_tested) || match i.revert_to {
                    Some(r) => r != to,
                    None => false,
                },
                Tier::Tested,
            ),
        ),
        Transition::Rollback => allow(ask_if(sec_or_ext(f.sensitivity), Tier::Runtime)),
        Transition::LoadModel(m) => if has_model(i.tables.model_catalog@, m) {
            allow(Tier::Tested)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::RestoreSnapshot(_) => allow(Tier::AskFirst),
        Transition::CollectGarbage { .. } => allow(Tier::Runtime),
        Transition::SetRuntimeOption { path, .. } => if has_str(i.tables.runtime_allowlist@, path@) {
            allow(Tier::Runtime)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::Resolve { .. } => allow(Tier::Runtime),
    }
}

/// The global floors (§11) that ask any approver, for every transition kind:
/// non-reversible; session or data loss unless the user's own session;
/// connectivity loss unless a user with a seat; a session or connectivity loss
/// reaching another uid's session unless an administrator.
pub open spec fn floor_spec(f: DerivedFacts, a: Authorization) -> bool {
    f.recovery == Recovery::NonReversible || ((f.disruption == Disruption::SessionLoss || f.disruption
        == Disruption::DataInterruption) && !(is_user(a.actor) && own_session(a.actor, f))) || (f.disruption
        == Disruption::ConnectivityLoss && !is_local(a.actor)) || (f.other_sessions_affected && (f.disruption
        == Disruption::SessionLoss || f.disruption == Disruption::ConnectivityLoss) && !is_admin(a))
}

/// I11: this change's diff, or the session's cumulative diff, is non-Routine.
/// Classifying the two separately covers their composition: an option the
/// change returns to its start drops out of the composed diff, but it is in
/// this change's own diff.
pub open spec fn cumulative_spec(i: Input) -> bool {
    match i.facts.config_diff {
        Some(d) => diff_non_routine(*i.tables, d) || diff_non_routine(*i.tables, *i.cumulative),
        None => false,
    }
}

/// The decision before the autonomy setting.
pub open spec fn uncapped_spec(i: Input) -> Decision {
    let f = *i.facts;
    if !authorized_spec(*i.transition, f, *i.authz, *i.settings) {
        Decision::Reject(RejectReason::Unauthorized)
    } else if f.touches_core || f.sensitivity.core {
        Decision::Reject(RejectReason::CoreTarget)
    } else if match *i.transition {
        Transition::ApplyChange { change, .. } => !has_change(i.tables.catalog@, change),
        _ => false,
    } {
        Decision::Reject(RejectReason::NotInCatalog)
    } else if match f.config_diff {
        Some(d) => diff_locked(i.locked@, d),
        None => false,
    } {
        Decision::Reject(RejectReason::LockedOption)
    } else {
        match base_spec(i) {
            Decision::Allow { tier, approver } => Decision::Allow {
                tier: ask_if(
                    floor_spec(f, *i.authz) || cumulative_spec(i) || f.touches_canonical_probe
                        || f.below_security_floor,
                    tier,
                ),
                // I16: going below the security floor needs an administrator.
                approver: admin_if(f.below_security_floor, approver),
            },
            other => other,
        }
    }
}

/// The autonomy setting: raises a tier above `max` to AskFirst, keeping the
/// approver class; a Reject passes through.
pub open spec fn cap(d: Decision, max: Tier) -> Decision {
    match d {
        Decision::Allow { tier, approver } => if tier.rank() > max.rank() {
            Decision::Allow { tier: Tier::AskFirst, approver }
        } else {
            Decision::Allow { tier, approver }
        },
        other => other,
    }
}

pub open spec fn decide_spec(i: Input) -> Decision {
    cap(uncapped_spec(i), i.settings.max_tier)
}

fn is_user_exec(a: &Actor) -> (r: bool)
    ensures
        r == is_user(*a),
{
    match a {
        Actor::User { .. } => true,
        _ => false,
    }
}

fn is_admin_exec(a: &Authorization) -> (r: bool)
    ensures
        r == is_admin(*a),
{
    is_user_exec(&a.actor) && a.capabilities.administrator
}

fn is_local_exec(a: &Actor) -> (r: bool)
    ensures
        r == is_local(*a),
{
    match a {
        Actor::User { seat, .. } => match seat {
            Some(_) => true,
            None => false,
        },
        _ => false,
    }
}

fn own_session_exec(a: &Actor, f: &DerivedFacts) -> (r: bool)
    ensures
        r == own_session(*a, *f),
{
    match a {
        Actor::User { session, .. } => match session {
            Some(s) => f.affected_sessions.len() == 1 && str_eq(f.affected_sessions[0].as_str(), s.as_str()),
            None => false,
        },
        _ => false,
    }
}

fn sec_or_ext_exec(s: &Sensitivities) -> (r: bool)
    ensures
        r == sec_or_ext(*s),
{
    s.security || s.external
}

fn ask_if_exec(c: bool, t: Tier) -> (r: Tier)
    ensures
        r == ask_if(c, t),
{
    if c {
        Tier::AskFirst
    } else {
        t
    }
}

fn admin_if_exec(c: bool, k: ApproverClass) -> (r: ApproverClass)
    ensures
        r == admin_if(c, k),
{
    if c {
        ApproverClass::Administrator
    } else {
        k
    }
}

fn allow_exec(t: Tier) -> (r: Decision)
    ensures
        r == allow(t),
{
    Decision::Allow { tier: t, approver: ApproverClass::AnyApprover }
}

fn gen_eq(a: GenerationId, b: GenerationId) -> (r: bool)
    ensures
        r == (a == b),
{
    a.0 == b.0
}

fn vetted_exec(g: GenerationId, known_good: GenerationId, live_tested: Option<GenerationId>) -> (r: bool)
    ensures
        r == vetted(g, known_good, live_tested),
{
    let live = match live_tested {
        Some(l) => gen_eq(l, g),
        None => false,
    };
    live || gen_eq(g, known_good)
}

fn override_exec(f: &DerivedFacts, a: &Authorization) -> (r: Decision)
    ensures
        r == override_spec(*f, *a),
{
    let held = f.sensitivity.security && !is_admin_exec(a);
    Decision::Allow {
        tier: ask_if_exec(!is_user_exec(&a.actor) || f.sensitivity.external || held, Tier::Runtime),
        approver: admin_if_exec(held, ApproverClass::AnyApprover),
    }
}

fn base_tier(i: &Input) -> (r: Decision)
    ensures
        r == base_spec(*i),
{
    let f = i.facts;
    match i.transition {
        Transition::RestartUnit(_) => allow_exec(ask_if_exec(sec_or_ext_exec(&f.sensitivity), Tier::Runtime)),
        Transition::StopUnit(_) => allow_exec(ask_if_exec(sec_or_ext_exec(&f.sensitivity), Tier::Runtime)),
        Transition::SetOverride(_) => override_exec(f, i.authz),
        Transition::LiftOverride(_) => override_exec(f, i.authz),
        Transition::StopAndSuppress { .. } => override_exec(f, i.authz),
        Transition::BindDriver { .. } => allow_exec(ask_if_exec(f.sensitivity.security, Tier::Tested)),
        Transition::ApplyChange { .. } => allow_exec(
            ask_if_exec(
                !f.sensitivity.only_routine() || f.touches_manifest || f.touches_canonical_probe,
                Tier::Tested,
            ),
        ),
        Transition::SwitchGeneration(g) => allow_exec(
            ask_if_exec(!vetted_exec(*g, i.known_good, i.live_tested), Tier::Tested),
        ),
        Transition::Revert { to } => {
            let mismatched = match i.revert_to {
                Some(r) => !gen_eq(r, *to),
                None => false,
            };
            allow_exec(ask_if_exec(!vetted_exec(*to, i.known_good, i.live_tested) || mismatched, Tier::Tested))
        },
        Transition::Rollback => allow_exec(ask_if_exec(sec_or_ext_exec(&f.sensitivity), Tier::Runtime)),
        Transition::LoadModel(m) => if contains_model(&i.tables.model_catalog, m) {
            allow_exec(Tier::Tested)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::RestoreSnapshot(_) => allow_exec(Tier::AskFirst),
        Transition::CollectGarbage { .. } => allow_exec(Tier::Runtime),
        Transition::SetRuntimeOption { path, .. } => if contains_str(&i.tables.runtime_allowlist, path.as_str()) {
            allow_exec(Tier::Runtime)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::Resolve { .. } => allow_exec(Tier::Runtime),
    }
}

fn floors(f: &DerivedFacts, a: &Authorization) -> (r: bool)
    ensures
        r == floor_spec(*f, *a),
{
    let user = is_user_exec(&a.actor);
    let non_reversible = match f.recovery {
        Recovery::NonReversible => true,
        _ => false,
    };
    let session = match f.disruption {
        Disruption::SessionLoss | Disruption::DataInterruption => true,
        _ => false,
    };
    let connectivity = match f.disruption {
        Disruption::ConnectivityLoss => true,
        _ => false,
    };
    let reaches_others = match f.disruption {
        Disruption::SessionLoss | Disruption::ConnectivityLoss => f.other_sessions_affected,
        _ => false,
    };
    non_reversible || (session && !(user && own_session_exec(&a.actor, f))) || (connectivity && !is_local_exec(
        &a.actor,
    )) || (reaches_others && !is_admin_exec(a))
}

pub fn decide(i: &Input) -> (r: Decision)
    ensures
        r == decide_spec(*i),
{
    let f = i.facts;
    if !authorized(i.transition, f, i.authz, i.settings) {
        return Decision::Reject(RejectReason::Unauthorized);
    }
    if f.touches_core || f.sensitivity.core {
        return Decision::Reject(RejectReason::CoreTarget);
    }
    if let Transition::ApplyChange { change, .. } = i.transition {
        if !contains_change(&i.tables.catalog, change) {
            return Decision::Reject(RejectReason::NotInCatalog);
        }
    }
    if let Some(d) = &f.config_diff {
        if any_locked(i.locked, d) {
            return Decision::Reject(RejectReason::LockedOption);
        }
    }
    let (base, class) = match base_tier(i) {
        Decision::Allow { tier, approver } => (tier, approver),
        Decision::Reject(r) => return Decision::Reject(r),
    };
    let cumulative = match &f.config_diff {
        Some(d) => any_non_routine(i.tables, d) || any_non_routine(i.tables, i.cumulative),
        None => false,
    };
    let tier = ask_if_exec(
        floors(f, i.authz) || cumulative || f.touches_canonical_probe || f.below_security_floor,
        base,
    );
    let approver = admin_if_exec(f.below_security_floor, class);
    if tier.rank_of() > i.settings.max_tier.rank_of() {
        Decision::Allow { tier: Tier::AskFirst, approver }
    } else {
        Decision::Allow { tier, approver }
    }
}

// ---------- Approval (§11, I19) ----------

/// `approver` may approve, with class `class`, a proposal made by `proposer`:
/// a different principal, holding `Approve`, and `Administrator` too when the
/// class asks for it. Remote principals hold no approval capability by default;
/// the daemon computes capabilities, so that is a fact of `approver`.
pub open spec fn may_approve_spec(approver: Authorization, proposer: PrincipalId, class: ApproverClass) -> bool {
    is_user(approver.actor) && approver.principal != proposer && approver.capabilities.approve && match class {
        ApproverClass::AnyApprover => true,
        ApproverClass::Administrator => approver.capabilities.administrator,
    }
}

pub fn may_approve(approver: &Authorization, proposer: PrincipalId, class: ApproverClass) -> (r: bool)
    ensures
        r == may_approve_spec(*approver, proposer, class),
{
    let holds_class = match class {
        ApproverClass::AnyApprover => true,
        ApproverClass::Administrator => approver.capabilities.administrator,
    };
    is_user_exec(&approver.actor) && approver.principal.0 != proposer.0 && approver.capabilities.approve
        && holds_class
}

/// A capability grant (§11, I19): approved by an administrator who is neither
/// the grantee nor the proposer, and who holds the capability being granted.
pub open spec fn may_grant_spec(approver: Authorization, proposer: PrincipalId, grant: Grant) -> bool {
    may_approve_spec(approver, proposer, ApproverClass::Administrator) && approver.principal != grant.to
        && approver.capabilities.has(grant.capability)
}

pub fn may_grant(approver: &Authorization, proposer: PrincipalId, grant: &Grant) -> (r: bool)
    ensures
        r == may_grant_spec(*approver, proposer, *grant),
{
    may_approve(approver, proposer, ApproverClass::Administrator) && approver.principal.0 != grant.to.0
        && approver.capabilities.contains(grant.capability)
}

} // verus!

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

impl Tables {
    pub fn diff_sensitivity(&self, diff: &ConfigDiff) -> Sensitivities {
        diff.options.keys().fold(Sensitivities::default(), |acc, p| acc.union(&self.option_sensitivity(p)))
    }

    /// Sorted and deduplicated name lists, so equal tables hash equally
    /// whatever order the configuration listed them in.
    pub fn canonical(&self) -> Tables {
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v.dedup();
            v
        };
        let mut catalog = self.catalog.clone();
        catalog.sort();
        catalog.dedup();
        let mut model_catalog = self.model_catalog.clone();
        model_catalog.sort();
        model_catalog.dedup();
        Tables {
            catalog,
            runtime_allowlist: sorted(self.runtime_allowlist.clone()),
            // Order matters here: on equal prefixes the later entry wins.
            option_sensitivity: self.option_sensitivity.clone(),
            model_catalog,
        }
    }
}

pub fn policy_version(tables: &Tables) -> PolicyVersion {
    let mut bytes = format!("planarian-policy {} {}\n", env!("CARGO_PKG_VERSION"), POLICY_REVISION).into_bytes();
    bytes.extend(serde_json::to_vec(&tables.canonical()).expect("tables serialize"));
    PolicyVersion(Hash::of(&bytes))
}

/// The authorization of a non-user actor: no capabilities (§11).
pub fn authorization_of(actor: Actor) -> Authorization {
    Authorization { principal: actor.principal(), actor, capabilities: Capabilities::default() }
}

/// Phase A's capability grants (§11): every user acts on their own scope and
/// the user-controllable units; root and `planarian-admin` members are
/// administrators and approvers. I17 holds because root always is.
pub fn user_authorization(actor: Actor, admin: bool) -> Authorization {
    use planarian_schema::Capability::*;
    let admin = admin || actor.uid() == Some(0);
    let caps = if admin {
        Capabilities::of(&[OwnScope, UserControllable, Administrator, Approve])
    } else {
        Capabilities::of(&[OwnScope, UserControllable])
    };
    Authorization { principal: actor.principal(), actor, capabilities: caps }
}

impl std::fmt::Debug for Input<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("transition", self.transition)
            .field("facts", self.facts)
            .field("authz", self.authz)
            .field("max_tier", &self.settings.max_tier)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
