//! The journal state machine: which `TxnState` may follow which (§12).
//! Pure; a Verus proof target (I12 paths, write-ahead ordering).

use planarian_schema::{RecoveryStrategy, TxnState};

/// Whether a transaction with recovery strategy `strategy` may move from `from` to `to`.
///
/// Encodes §12 step 7 and the crash-recovery table:
/// - Rejected/Cancelled only before any mutation.
/// - `ReobserveOnly` never reverts and never publishes (Runtime outcomes never
///   trigger generation reversion); it may commit from Activating (crash table).
/// - Only generation operations pass through Published and Promoted.
/// - Any state in which mutation may have happened can end in RecoveryFailed.
pub fn step_allowed(from: &TxnState, to: &TxnState, strategy: RecoveryStrategy) -> bool {
    use RecoveryStrategy as R;
    use TxnState as S;
    let generation = matches!(strategy, R::RevertGeneration | R::RestoreSnapshotThenRevert);
    if from.is_terminal() {
        return false;
    }
    match (from, to) {
        (S::Prepared, S::Staged | S::Built | S::Activating) => true,
        (S::Staged, S::Built | S::Activating) => true,
        (S::Built, S::Activating) => true,
        (f, S::Rejected(_) | S::Cancelled(_)) => f.is_pre_mutation(),
        (S::Activating, S::Checking) => true,
        (S::Activating, S::Committed) => strategy == R::ReobserveOnly,
        (S::Activating | S::Checking | S::Published | S::Promoted, S::Reverting) => strategy != R::ReobserveOnly,
        (S::Checking, S::Committed) => matches!(strategy, R::ReobserveOnly | R::UnbindDevice),
        (S::Checking, S::Published) => generation,
        (S::Published, S::Promoted) => generation,
        (S::Promoted, S::Committed) => generation,
        (S::Reverting, S::Reverted) => true,
        (S::Activating | S::Checking | S::Published | S::Promoted | S::Reverting, S::RecoveryFailed) => true,
        _ => false,
    }
}

/// A short, stable name for a state (journal notes, crash points, catalog `path`).
pub fn tag(s: &TxnState) -> &'static str {
    match s {
        TxnState::Prepared => "Prepared",
        TxnState::Staged => "Staged",
        TxnState::Built => "Built",
        TxnState::Activating => "Activating",
        TxnState::Checking => "Checking",
        TxnState::Published => "Published",
        TxnState::Promoted => "Promoted",
        TxnState::Committed => "Committed",
        TxnState::Reverting => "Reverting",
        TxnState::Reverted => "Reverted",
        TxnState::RecoveryFailed => "RecoveryFailed",
        TxnState::Rejected(_) => "Rejected",
        TxnState::Cancelled(_) => "Cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use planarian_schema::{Actor, RejectReason};

    fn all() -> Vec<TxnState> {
        vec![
            TxnState::Prepared,
            TxnState::Staged,
            TxnState::Built,
            TxnState::Activating,
            TxnState::Checking,
            TxnState::Published,
            TxnState::Promoted,
            TxnState::Committed,
            TxnState::Reverting,
            TxnState::Reverted,
            TxnState::RecoveryFailed,
            TxnState::Rejected(RejectReason::Stale),
            TxnState::Cancelled(Actor::User { uid: 1000 }),
        ]
    }

    const STRATEGIES: [RecoveryStrategy; 4] = [
        RecoveryStrategy::ReobserveOnly,
        RecoveryStrategy::RevertGeneration,
        RecoveryStrategy::UnbindDevice,
        RecoveryStrategy::RestoreSnapshotThenRevert,
    ];

    /// Every non-terminal state has a path to a terminal state (the
    /// reachability half of I12), for every strategy.
    #[test]
    fn terminal_reachable_from_every_state() {
        for strategy in STRATEGIES {
            for start in all().iter().filter(|s| !s.is_terminal()) {
                let mut seen = vec![start.clone()];
                let mut frontier = vec![start.clone()];
                let mut reached = false;
                while let Some(s) = frontier.pop() {
                    for t in all() {
                        if step_allowed(&s, &t, strategy) && !seen.contains(&t) {
                            reached |= t.is_terminal();
                            seen.push(t.clone());
                            frontier.push(t);
                        }
                    }
                }
                // Published/Promoted exist only for generation operations; for the
                // others those states are unreachable, so they need no exit.
                let reachable_at_all = !matches!(start, TxnState::Published | TxnState::Promoted)
                    || matches!(
                        strategy,
                        RecoveryStrategy::RevertGeneration | RecoveryStrategy::RestoreSnapshotThenRevert
                    );
                assert!(reached || !reachable_at_all, "{start:?} under {strategy:?} cannot terminate");
            }
        }
    }

    #[test]
    fn terminal_states_are_final() {
        for strategy in STRATEGIES {
            for from in all().iter().filter(|s| s.is_terminal()) {
                for to in all() {
                    assert!(!step_allowed(from, &to, strategy));
                }
            }
        }
    }

    #[test]
    fn reobserve_only_never_reverts_or_publishes() {
        let r = RecoveryStrategy::ReobserveOnly;
        for from in all() {
            assert!(!step_allowed(&from, &TxnState::Reverting, r));
            assert!(!step_allowed(&from, &TxnState::Published, r));
        }
    }

    #[test]
    fn no_reject_after_mutation() {
        for strategy in STRATEGIES {
            for from in [TxnState::Activating, TxnState::Checking, TxnState::Reverting] {
                assert!(!step_allowed(&from, &TxnState::Rejected(RejectReason::Stale), strategy));
            }
        }
    }
}
