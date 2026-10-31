//! The journal state machine: which `TxnState` may follow which (§12).
//! Pure; a Verus proof target (I12 paths, write-ahead ordering).

use planarian_schema::{RecoveryStrategy, TxnState};
use vstd::prelude::*;

verus! {

/// Whether a transaction with recovery strategy `strategy` may move from `from` to `to`.
///
/// Encodes §12 step 7 and the crash-recovery table:
/// - Rejected/Cancelled only before any mutation.
/// - `ReobserveOnly` never reverts and never publishes (Runtime outcomes never
///   trigger generation reversion); it may commit from Activating (crash table).
/// - Only generation operations pass through Published and Promoted.
/// - The boot-only path (§12 step 7, §12f): Built → Publishing (journaled
///   before the first boot mutation) → AwaitingBoot (a one-shot next-boot
///   entry is armed) → Promoted (it booted and was admitted) or Reverted (it
///   did not; the boot loader already fell back), or Reverting to withdraw the
///   entry. From Publishing, a crash with no entry armed ends Rejected: the
///   publication is all or nothing, so nothing was mutated.
/// - Any state in which mutation may have happened can end in RecoveryFailed.
pub open spec fn step_spec(from: TxnState, to: TxnState, strategy: RecoveryStrategy) -> bool {
    let generation = strategy.reverts_generation();
    let runtime = strategy == RecoveryStrategy::ReobserveOnly;
    if from.terminal() {
        false
    } else {
        match (from, to) {
            (TxnState::Prepared, TxnState::Staged) => true,
            (TxnState::Prepared, TxnState::Built) => true,
            (TxnState::Prepared, TxnState::Activating) => true,
            (TxnState::Staged, TxnState::Built) => true,
            (TxnState::Staged, TxnState::Activating) => true,
            (TxnState::Built, TxnState::Activating) => true,
            (TxnState::Built, TxnState::Publishing) => generation,
            (TxnState::Publishing, TxnState::AwaitingBoot) => generation,
            (TxnState::Publishing, TxnState::Rejected(_)) => generation,
            (TxnState::AwaitingBoot, TxnState::Promoted) => generation,
            (TxnState::AwaitingBoot, TxnState::Reverting) => generation,
            (TxnState::AwaitingBoot, TxnState::Reverted) => generation,
            (_, TxnState::Rejected(_)) => from.pre_mutation(),
            (_, TxnState::Cancelled(_)) => from.pre_mutation(),
            (TxnState::Activating, TxnState::Checking) => true,
            (TxnState::Activating, TxnState::Committed) => runtime,
            (TxnState::Activating, TxnState::Reverting) => !runtime,
            (TxnState::Checking, TxnState::Reverting) => !runtime,
            (TxnState::Published, TxnState::Reverting) => !runtime,
            (TxnState::Promoted, TxnState::Reverting) => !runtime,
            (TxnState::Checking, TxnState::Committed) => runtime || strategy == RecoveryStrategy::UnbindDevice,
            (TxnState::Checking, TxnState::Published) => generation,
            (TxnState::Published, TxnState::Promoted) => generation,
            (TxnState::Promoted, TxnState::Committed) => generation,
            (TxnState::Reverting, TxnState::Reverted) => true,
            (_, TxnState::RecoveryFailed) => !from.pre_mutation(),
            _ => false,
        }
    }
}

pub fn step_allowed(from: &TxnState, to: &TxnState, strategy: RecoveryStrategy) -> (r: bool)
    ensures
        r == step_spec(*from, *to, strategy),
{
    let generation = match strategy {
        RecoveryStrategy::RevertGeneration | RecoveryStrategy::RestoreSnapshotThenRevert => true,
        _ => false,
    };
    let runtime = match strategy {
        RecoveryStrategy::ReobserveOnly => true,
        _ => false,
    };
    let device = match strategy {
        RecoveryStrategy::UnbindDevice => true,
        _ => false,
    };
    if from.is_terminal() {
        return false;
    }
    match (from, to) {
        (TxnState::Prepared, TxnState::Staged) => true,
        (TxnState::Prepared, TxnState::Built) => true,
        (TxnState::Prepared, TxnState::Activating) => true,
        (TxnState::Staged, TxnState::Built) => true,
        (TxnState::Staged, TxnState::Activating) => true,
        (TxnState::Built, TxnState::Activating) => true,
        (TxnState::Built, TxnState::Publishing) => generation,
        (TxnState::Publishing, TxnState::AwaitingBoot) => generation,
        (TxnState::Publishing, TxnState::Rejected(_)) => generation,
        (TxnState::AwaitingBoot, TxnState::Promoted) => generation,
        (TxnState::AwaitingBoot, TxnState::Reverting) => generation,
        (TxnState::AwaitingBoot, TxnState::Reverted) => generation,
        (_, TxnState::Rejected(_)) => from.is_pre_mutation(),
        (_, TxnState::Cancelled(_)) => from.is_pre_mutation(),
        (TxnState::Activating, TxnState::Checking) => true,
        (TxnState::Activating, TxnState::Committed) => runtime,
        (TxnState::Activating, TxnState::Reverting) => !runtime,
        (TxnState::Checking, TxnState::Reverting) => !runtime,
        (TxnState::Published, TxnState::Reverting) => !runtime,
        (TxnState::Promoted, TxnState::Reverting) => !runtime,
        (TxnState::Checking, TxnState::Committed) => runtime || device,
        (TxnState::Checking, TxnState::Published) => generation,
        (TxnState::Published, TxnState::Promoted) => generation,
        (TxnState::Promoted, TxnState::Committed) => generation,
        (TxnState::Reverting, TxnState::Reverted) => true,
        (_, TxnState::RecoveryFailed) => !from.is_pre_mutation(),
        _ => false,
    }
}

/// How far a state is from the end: every allowed step lowers it.
pub open spec fn rank(s: TxnState) -> nat {
    match s {
        TxnState::Prepared => 8,
        TxnState::Staged => 7,
        TxnState::Built => 6,
        TxnState::Activating => 5,
        TxnState::Checking => 4,
        TxnState::Publishing => 4,
        TxnState::Published => 3,
        TxnState::AwaitingBoot => 3,
        TxnState::Promoted => 2,
        TxnState::Reverting => 1,
        _ => 0,
    }
}

/// I12, termination: every allowed step lowers the rank, so a transaction
/// takes at most eight steps and never cycles.
pub proof fn i12_steps_terminate(from: TxnState, to: TxnState, strategy: RecoveryStrategy)
    requires
        step_spec(from, to, strategy),
    ensures
        rank(to) < rank(from),
{
}

/// I12, progress: from every state that is not terminal, a step to a
/// terminal state is allowed: Cancelled before any mutation, RecoveryFailed
/// after. So whoever holds the lease can always finish the transaction.
pub proof fn i12_terminal_always_reachable(from: TxnState, strategy: RecoveryStrategy, by: planarian_schema::Actor)
    requires
        !from.terminal(),
    ensures
        from.pre_mutation() ==> step_spec(from, TxnState::Cancelled(by), strategy),
        !from.pre_mutation() ==> step_spec(from, TxnState::RecoveryFailed, strategy),
{
}

/// Terminal states have no successors.
pub proof fn terminal_is_final(from: TxnState, to: TxnState, strategy: RecoveryStrategy)
    requires
        from.terminal(),
    ensures
        !step_spec(from, to, strategy),
{
}

/// Rejected and Cancelled happen only before anything was mutated, or (for
/// Rejected) from Publishing, whose all-or-nothing publication armed nothing.
pub proof fn refusal_only_before_mutation(from: TxnState, to: TxnState, strategy: RecoveryStrategy)
    requires
        step_spec(from, to, strategy),
        to is Rejected || to is Cancelled,
    ensures
        from.pre_mutation() || (from is Publishing && to is Rejected),
{
}

/// Runtime operations never revert a generation and never publish (§12).
pub proof fn runtime_never_reverts(from: TxnState, to: TxnState)
    requires
        step_spec(from, to, RecoveryStrategy::ReobserveOnly),
    ensures
        !(to is Reverting),
        !(to is Published),
        !(to is Promoted),
{
}

/// Only generation operations publish a boot entry (also a one-shot one) or promote overrides.
pub proof fn only_generations_publish(from: TxnState, to: TxnState, strategy: RecoveryStrategy)
    requires
        step_spec(from, to, strategy),
        to is Published || to is Promoted || to is Publishing || to is AwaitingBoot,
    ensures
        strategy.reverts_generation(),
{
}

/// A boot-only candidate is never live-activated: Publishing is journaled
/// before any boot mutation (R01), AwaitingBoot is reached only through it,
/// and left only for Promoted or a revert.
pub proof fn boot_only_never_activates(from: TxnState, to: TxnState, strategy: RecoveryStrategy)
    requires
        step_spec(from, to, strategy),
    ensures
        to is Publishing ==> from is Built,
        to is AwaitingBoot ==> from is Publishing,
        from is Publishing ==> (to is AwaitingBoot || to is Rejected || to is RecoveryFailed),
        from is AwaitingBoot ==> (to is Promoted || to is Reverting || to is Reverted || to is RecoveryFailed),
{
}

/// A generation operation commits only after it was published and promoted.
pub proof fn generations_commit_after_promotion(from: TxnState, strategy: RecoveryStrategy)
    requires
        step_spec(from, TxnState::Committed, strategy),
        strategy.reverts_generation(),
    ensures
        from is Promoted,
{
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
        TxnState::Publishing => "Publishing",
        TxnState::AwaitingBoot => "AwaitingBoot",
        TxnState::Promoted => "Promoted",
        TxnState::Committed => "Committed",
        TxnState::Reverting => "Reverting",
        TxnState::Reverted => "Reverted",
        TxnState::RecoveryFailed => "RecoveryFailed",
        TxnState::Rejected(_) => "Rejected",
        TxnState::Cancelled(_) => "Cancelled",
    }
}

} // verus!

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
            TxnState::Publishing,
            TxnState::AwaitingBoot,
            TxnState::Promoted,
            TxnState::Committed,
            TxnState::Reverting,
            TxnState::Reverted,
            TxnState::RecoveryFailed,
            TxnState::Rejected(RejectReason::Stale),
            TxnState::Cancelled(Actor::user(1000)),
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
