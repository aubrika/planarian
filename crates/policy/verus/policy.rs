//! Verus proofs of the policy decision function (SPEC §17a, Phase A targets:
//! I5, I11, the global floors, I10's AskFirst-or-Reject rule, CoreTarget and
//! authorization).
//!
//! `decide_spec`'s body, between the MODEL markers, is textually identical to
//! `decide_model` in `crates/policy/src/model.rs`. A cargo test checks that,
//! and another checks `decide_model` against the shipped `decide` on the full
//! grid. Run: `verus crates/policy/verus/policy.rs`.

use vstd::prelude::*;

verus! {

/// Transition kinds, with the per-kind facts `decide` reads.
pub enum MKind {
    RestartStop,
    SuppressFamily,
    BindDriver,
    ApplyChange { in_catalog: bool },
    SwitchOrRevert { vetted: bool, mismatched: bool },
    Rollback,
    LoadModel { in_catalog: bool },
    RestoreSnapshot,
    CollectGarbage,
    SetRuntimeOption { allowed: bool },
    Resolve,
}

pub struct MFacts {
    pub security: bool,
    pub external: bool,
    pub user_data: bool,
    /// `touches_core`, or Core sensitivity.
    pub core: bool,
    /// 0 None, 1 Brief, 2 SessionLoss, 3 DataInterruption, 4 ConnectivityLoss.
    pub disruption: u8,
    pub non_reversible: bool,
    pub touches_manifest: bool,
    pub touches_canonical_probe: bool,
    /// The diff sets a `mkForce`d option.
    pub locked: bool,
    /// The proposal has a config diff.
    pub has_diff: bool,
    /// That diff, or the session's cumulative diff with it, is non-Routine.
    pub diff_non_routine: bool,
}

pub struct MAuthz {
    pub is_user: bool,
    /// Result of the §11 authorization rule.
    pub authorized: bool,
    pub local_session: bool,
    pub owns_affected_session: bool,
}

/// Tiers: 0 Observe, 1 Runtime, 2 Tested, 3 AskFirst.
/// Reject reasons: 0 Unauthorized, 1 CoreTarget, 2 NotInCatalog, 3 LockedOption.
pub enum MDecision {
    Allow(u8),
    Reject(u8),
}

pub open spec fn decide_spec(k: MKind, f: MFacts, a: MAuthz, max_tier: u8) -> MDecision {
    // BEGIN MODEL
    if !a.authorized {
        MDecision::Reject(0)
    } else if f.core {
        MDecision::Reject(1)
    } else if (match k { MKind::ApplyChange { in_catalog } => !in_catalog, _ => false }) {
        MDecision::Reject(2)
    } else if f.locked {
        MDecision::Reject(3)
    } else if (match k {
        MKind::LoadModel { in_catalog } => !in_catalog,
        MKind::SetRuntimeOption { allowed } => !allowed,
        _ => false,
    }) {
        MDecision::Reject(2)
    } else {
        let sec_or_ext = f.security || f.external;
        let base: u8 = match k {
            MKind::RestartStop => if sec_or_ext { 3 } else { 1 },
            MKind::SuppressFamily => if !a.is_user || sec_or_ext { 3 } else { 1 },
            MKind::BindDriver => if f.security { 3 } else { 2 },
            MKind::ApplyChange { .. } => {
                if sec_or_ext || f.user_data || f.touches_manifest || f.touches_canonical_probe { 3 } else { 2 }
            }
            MKind::SwitchOrRevert { vetted, mismatched } => if !vetted || mismatched { 3 } else { 2 },
            MKind::Rollback => if sec_or_ext { 3 } else { 1 },
            MKind::LoadModel { .. } => 2,
            MKind::RestoreSnapshot => 3,
            MKind::CollectGarbage => 1,
            MKind::SetRuntimeOption { .. } => 1,
            MKind::Resolve => 1,
        };
        let floor_nonrev = f.non_reversible;
        let floor_session = (f.disruption == 2 || f.disruption == 3) && !(a.is_user && a.owns_affected_session);
        let floor_conn = f.disruption == 4 && !(a.is_user && a.local_session);
        let cumulative = f.has_diff && f.diff_non_routine;
        let ask = floor_nonrev || floor_session || floor_conn || cumulative || f.touches_canonical_probe;
        let tier: u8 = if ask { 3 } else { base };
        if tier > max_tier { MDecision::Allow(3) } else { MDecision::Allow(tier) }
    }
    // END MODEL
}

pub open spec fn is_reject(d: MDecision) -> bool {
    match d {
        MDecision::Reject(_) => true,
        MDecision::Allow(_) => false,
    }
}

/// AskFirst, or refused.
pub open spec fn asks_or_rejects(d: MDecision) -> bool {
    match d {
        MDecision::Reject(_) => true,
        MDecision::Allow(t) => t == 3,
    }
}

pub open spec fn tier_of(d: MDecision) -> u8 {
    match d {
        MDecision::Allow(t) => t,
        MDecision::Reject(_) => 255,
    }
}

/// I5: the autonomy setting never turns a Reject into a tier or a tier into a
/// Reject, never changes a Reject's reason, can only raise a tier to
/// AskFirst, and raising it never makes a decision stricter.
pub proof fn i5_autonomy_never_touches_reject(k: MKind, f: MFacts, a: MAuthz, m1: u8, m2: u8)
    ensures
        is_reject(decide_spec(k, f, a, m1)) == is_reject(decide_spec(k, f, a, m2)),
        is_reject(decide_spec(k, f, a, m1)) ==> decide_spec(k, f, a, m1) == decide_spec(k, f, a, m2),
        !is_reject(decide_spec(k, f, a, m1)) ==> (tier_of(decide_spec(k, f, a, m1)) <= m1 || tier_of(decide_spec(k, f, a, m1)) == 3),
        (m1 <= m2 && !is_reject(decide_spec(k, f, a, m1))) ==> tier_of(decide_spec(k, f, a, m2)) <= tier_of(decide_spec(k, f, a, m1)),
{
}

/// I11: when this change's diff, or the session's cumulative diff with it, is
/// non-Routine, the decision is AskFirst or a Reject.
pub proof fn i11_cumulative_classification(k: MKind, f: MFacts, a: MAuthz, m: u8)
    requires
        f.has_diff,
        f.diff_non_routine,
    ensures
        asks_or_rejects(decide_spec(k, f, a, m)),
{
}

/// The global floors (§11) hold for every transition kind.
pub proof fn global_floors(k: MKind, f: MFacts, a: MAuthz, m: u8)
    ensures
        f.non_reversible ==> asks_or_rejects(decide_spec(k, f, a, m)),
        ((f.disruption == 2 || f.disruption == 3) && !(a.is_user && a.owns_affected_session)) ==> asks_or_rejects(decide_spec(k, f, a, m)),
        (f.disruption == 4 && !(a.is_user && a.local_session)) ==> asks_or_rejects(decide_spec(k, f, a, m)),
{
}

/// I10: a change to a canonical probe's definition never runs below AskFirst.
pub proof fn i10_canonical_probes_ask(k: MKind, f: MFacts, a: MAuthz, m: u8)
    requires
        f.touches_canonical_probe,
    ensures
        asks_or_rejects(decide_spec(k, f, a, m)),
{
}

/// The core is never a target; unauthorized callers are refused before anything else.
pub proof fn core_and_authorization(k: MKind, f: MFacts, a: MAuthz, m: u8)
    ensures
        !a.authorized ==> decide_spec(k, f, a, m) == MDecision::Reject(0),
        (a.authorized && f.core) ==> decide_spec(k, f, a, m) == MDecision::Reject(1),
{
}

} // verus!

fn main() {}
