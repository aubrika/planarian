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
//! Verified with Verus (SPEC §17a): `decide` is proved equal to `decide_spec`,
//! and the properties are proved about `decide_spec` in `proofs`. Sets of
//! names are vectors searched linearly, because vstd specifies `BTreeSet` only
//! for key types with an ordering spec, which `String` lacks
//! (docs/deviations.md). Run: `cargo verus verify -p planarian-policy`.

// Verus idioms: `&Vec` for its `@` view, explicit `match` and nested `if`
// rather than `matches!` and let-chains.
#![allow(clippy::ptr_arg, clippy::match_like_matches_macro, clippy::collapsible_if)]

use planarian_schema::{
    Actor, ChangeId, ConfigDiff, Decision, DerivedFacts, Disruption, GenerationId, Hash, ModelId, PolicyVersion,
    Recovery, RejectReason, Scope, Sensitivities, Tier, Transition, UnitId,
};
use serde::{Deserialize, Serialize};
use vstd::prelude::*;

pub mod proofs;

/// Bumped by hand whenever the decision logic changes; part of `PolicyVersion`.
pub const POLICY_REVISION: &str = "phase-a.2";

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

/// Established by the daemon from `SO_PEERCRED` and logind, never from the proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Authorization {
    pub caller: Actor,
    /// Root, or a member of `planarian-admin`.
    pub admin: bool,
    /// The caller has a local (non-remote) session.
    pub local_session: bool,
    /// The session the transition would disrupt is the caller's own.
    pub owns_affected_session: bool,
}

pub open spec fn is_user(a: Actor) -> bool {
    match a {
        Actor::User { .. } => true,
        _ => false,
    }
}

/// A unit a non-admin user `uid` may act on directly.
pub open spec fn unit_ok(u: UnitId, uid: u32, s: Settings) -> bool {
    match u.scope {
        Scope::User { uid: owner, .. } => owner == uid,
        Scope::System => has_str(s.user_controllable_units@, u.name@),
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

/// §11: a user may act on units in their own user scope and on
/// user-controllable system units; everything else needs administrator
/// authority. The daemon, the watchdog and the model are not users; their
/// proposals are governed by tiers, except `Resolve`, which only an
/// administrator may issue.
pub open spec fn authorized_spec(t: Transition, f: DerivedFacts, a: Authorization, s: Settings) -> bool {
    match a.caller {
        Actor::User { uid } => a.admin || match t {
            Transition::RestartUnit(u) => unit_ok(u, uid, s),
            Transition::StopUnit(u) => unit_ok(u, uid, s),
            Transition::Unsuppress(u) => unit_ok(u, uid, s),
            Transition::Suppress(sup) => unit_ok(sup.unit, uid, s),
            Transition::StopAndSuppress { unit, .. } => unit_ok(unit, uid, s),
            Transition::ApplyChange { change, .. } => has_change(s.user_controllable_changes@, change)
                && all_may_affect(f.affected_units@, uid),
            Transition::SetRuntimeOption { path, .. } => has_str(s.user_controllable_options@, path@),
            _ => false,
        },
        _ => match t {
            Transition::Resolve { .. } => false,
            _ => true,
        },
    }
}

fn unit_ok_exec(u: &UnitId, uid: u32, s: &Settings) -> (r: bool)
    ensures
        r == unit_ok(*u, uid, *s),
{
    match &u.scope {
        Scope::User { uid: owner, .. } => *owner == uid,
        Scope::System => contains_str(&s.user_controllable_units, u.name.as_str()),
    }
}

#[verifier::loop_isolation(false)]
pub fn authorized(t: &Transition, facts: &DerivedFacts, authz: &Authorization, settings: &Settings) -> (r: bool)
    ensures
        r == authorized_spec(*t, *facts, *authz, *settings),
{
    let uid = match &authz.caller {
        Actor::User { uid } => *uid,
        _ => {
            return match t {
                Transition::Resolve { .. } => false,
                _ => true,
            };
        },
    };
    if authz.admin {
        return true;
    }
    match t {
        Transition::RestartUnit(u) => unit_ok_exec(u, uid, settings),
        Transition::StopUnit(u) => unit_ok_exec(u, uid, settings),
        Transition::Unsuppress(u) => unit_ok_exec(u, uid, settings),
        Transition::Suppress(sup) => unit_ok_exec(&sup.unit, uid, settings),
        Transition::StopAndSuppress { unit, .. } => unit_ok_exec(unit, uid, settings),
        Transition::ApplyChange { change, .. } => {
            if !contains_change(&settings.user_controllable_changes, change) {
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
        Transition::SetRuntimeOption { path, .. } => contains_str(&settings.user_controllable_options, path.as_str()),
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

/// The per-transition table (§11).
pub open spec fn base_spec(i: Input) -> Decision {
    let f = *i.facts;
    match *i.transition {
        Transition::RestartUnit(_) => Decision::Allow(ask_if(sec_or_ext(f.sensitivity), Tier::Runtime)),
        Transition::StopUnit(_) => Decision::Allow(ask_if(sec_or_ext(f.sensitivity), Tier::Runtime)),
        Transition::Suppress(_) => Decision::Allow(
            ask_if(!is_user(i.authz.caller) || sec_or_ext(f.sensitivity), Tier::Runtime),
        ),
        Transition::Unsuppress(_) => Decision::Allow(
            ask_if(!is_user(i.authz.caller) || sec_or_ext(f.sensitivity), Tier::Runtime),
        ),
        Transition::StopAndSuppress { .. } => Decision::Allow(
            ask_if(!is_user(i.authz.caller) || sec_or_ext(f.sensitivity), Tier::Runtime),
        ),
        Transition::BindDriver { .. } => Decision::Allow(ask_if(f.sensitivity.security, Tier::Tested)),
        Transition::ApplyChange { .. } => Decision::Allow(
            ask_if(!f.sensitivity.routine_only() || f.touches_manifest || f.touches_canonical_probe, Tier::Tested),
        ),
        Transition::SwitchGeneration(g) => Decision::Allow(
            ask_if(!vetted(g, i.known_good, i.live_tested), Tier::Tested),
        ),
        Transition::Revert { to } => Decision::Allow(
            ask_if(
                !vetted(to, i.known_good, i.live_tested) || match i.revert_to {
                    Some(r) => r != to,
                    None => false,
                },
                Tier::Tested,
            ),
        ),
        Transition::Rollback => Decision::Allow(ask_if(sec_or_ext(f.sensitivity), Tier::Runtime)),
        Transition::LoadModel(m) => if has_model(i.tables.model_catalog@, m) {
            Decision::Allow(Tier::Tested)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::RestoreSnapshot(_) => Decision::Allow(Tier::AskFirst),
        Transition::CollectGarbage { .. } => Decision::Allow(Tier::Runtime),
        Transition::SetRuntimeOption { path, .. } => if has_str(i.tables.runtime_allowlist@, path@) {
            Decision::Allow(Tier::Runtime)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::Resolve { .. } => Decision::Allow(Tier::Runtime),
    }
}

/// The global floors (§11), for every transition kind.
pub open spec fn floor_spec(f: DerivedFacts, a: Authorization) -> bool {
    f.recovery == Recovery::NonReversible || ((f.disruption == Disruption::SessionLoss || f.disruption
        == Disruption::DataInterruption) && !(is_user(a.caller) && a.owns_affected_session)) || (f.disruption
        == Disruption::ConnectivityLoss && !(is_user(a.caller) && a.local_session))
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
            Decision::Allow(b) => Decision::Allow(
                ask_if(floor_spec(f, *i.authz) || cumulative_spec(i) || f.touches_canonical_probe, b),
            ),
            other => other,
        }
    }
}

/// The autonomy setting: raises a tier above `max` to AskFirst; a Reject passes through.
pub open spec fn cap(d: Decision, max: Tier) -> Decision {
    match d {
        Decision::Allow(t) => if t.rank() > max.rank() {
            Decision::Allow(Tier::AskFirst)
        } else {
            Decision::Allow(t)
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

fn base_tier(i: &Input) -> (r: Decision)
    ensures
        r == base_spec(*i),
{
    let f = i.facts;
    match i.transition {
        Transition::RestartUnit(_) => Decision::Allow(ask_if_exec(sec_or_ext_exec(&f.sensitivity), Tier::Runtime)),
        Transition::StopUnit(_) => Decision::Allow(ask_if_exec(sec_or_ext_exec(&f.sensitivity), Tier::Runtime)),
        Transition::Suppress(_) => Decision::Allow(
            ask_if_exec(!is_user_exec(&i.authz.caller) || sec_or_ext_exec(&f.sensitivity), Tier::Runtime),
        ),
        Transition::Unsuppress(_) => Decision::Allow(
            ask_if_exec(!is_user_exec(&i.authz.caller) || sec_or_ext_exec(&f.sensitivity), Tier::Runtime),
        ),
        Transition::StopAndSuppress { .. } => Decision::Allow(
            ask_if_exec(!is_user_exec(&i.authz.caller) || sec_or_ext_exec(&f.sensitivity), Tier::Runtime),
        ),
        Transition::BindDriver { .. } => Decision::Allow(ask_if_exec(f.sensitivity.security, Tier::Tested)),
        Transition::ApplyChange { .. } => Decision::Allow(
            ask_if_exec(
                !f.sensitivity.only_routine() || f.touches_manifest || f.touches_canonical_probe,
                Tier::Tested,
            ),
        ),
        Transition::SwitchGeneration(g) => Decision::Allow(
            ask_if_exec(!vetted_exec(*g, i.known_good, i.live_tested), Tier::Tested),
        ),
        Transition::Revert { to } => {
            let mismatched = match i.revert_to {
                Some(r) => !gen_eq(r, *to),
                None => false,
            };
            Decision::Allow(ask_if_exec(!vetted_exec(*to, i.known_good, i.live_tested) || mismatched, Tier::Tested))
        },
        Transition::Rollback => Decision::Allow(ask_if_exec(sec_or_ext_exec(&f.sensitivity), Tier::Runtime)),
        Transition::LoadModel(m) => if contains_model(&i.tables.model_catalog, m) {
            Decision::Allow(Tier::Tested)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::RestoreSnapshot(_) => Decision::Allow(Tier::AskFirst),
        Transition::CollectGarbage { .. } => Decision::Allow(Tier::Runtime),
        Transition::SetRuntimeOption { path, .. } => if contains_str(&i.tables.runtime_allowlist, path.as_str()) {
            Decision::Allow(Tier::Runtime)
        } else {
            Decision::Reject(RejectReason::NotInCatalog)
        },
        Transition::Resolve { .. } => Decision::Allow(Tier::Runtime),
    }
}

fn floors(f: &DerivedFacts, a: &Authorization) -> (r: bool)
    ensures
        r == floor_spec(*f, *a),
{
    let user = is_user_exec(&a.caller);
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
    non_reversible || (session && !(user && a.owns_affected_session)) || (connectivity && !(user && a.local_session))
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
    let base = match base_tier(i) {
        Decision::Allow(t) => t,
        Decision::Reject(r) => return Decision::Reject(r),
    };
    let cumulative = match &f.config_diff {
        Some(d) => any_non_routine(i.tables, d) || any_non_routine(i.tables, i.cumulative),
        None => false,
    };
    let tier = ask_if_exec(floors(f, i.authz) || cumulative || f.touches_canonical_probe, base);
    if tier.rank_of() > i.settings.max_tier.rank_of() {
        Decision::Allow(Tier::AskFirst)
    } else {
        Decision::Allow(tier)
    }
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

impl Authorization {
    pub fn daemon() -> Authorization {
        Authorization { caller: Actor::Daemon, admin: false, local_session: false, owns_affected_session: false }
    }
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
