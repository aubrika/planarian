//! The decision function over plain data: the model the Verus proofs are
//! about (`crates/policy/verus/policy.rs`).
//!
//! The chain from proof to shipped code:
//! 1. Verus proves I5, I11, the floors, I10, CoreTarget and authorization on
//!    `decide_spec`, whose body is between the MODEL markers in the Verus file.
//! 2. `model_body_matches_the_verified_body` checks that text is identical to
//!    the body of `decide_model` below.
//! 3. `model_agrees_with_decide` checks that `decide_model` equals the real
//!    `decide` on the full test grid (about 110,000 inputs).

/// Transition kinds, with the per-kind facts `decide` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MAuthz {
    pub is_user: bool,
    /// Result of the §11 authorization rule.
    pub authorized: bool,
    pub local_session: bool,
    pub owns_affected_session: bool,
}

/// Tiers: 0 Observe, 1 Runtime, 2 Tested, 3 AskFirst.
/// Reject reasons: 0 Unauthorized, 1 CoreTarget, 2 NotInCatalog, 3 LockedOption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MDecision {
    Allow(u8),
    Reject(u8),
}

#[allow(unused_parens)]
#[rustfmt::skip]
pub fn decide_model(k: MKind, f: MFacts, a: MAuthz, max_tier: u8) -> MDecision {
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

#[cfg(test)]
mod tests {
    fn body(text: &str) -> String {
        let a = text.find("// BEGIN MODEL").expect("BEGIN marker");
        let b = text.find("// END MODEL").expect("END marker");
        text[a..b].split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The verified body and the tested body are the same text.
    #[test]
    fn model_body_matches_the_verified_body() {
        let verified = include_str!("../verus/policy.rs");
        let tested = include_str!("model.rs");
        assert_eq!(body(verified), body(tested));
    }
}
