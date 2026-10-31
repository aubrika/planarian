//! Kani harnesses for the kernel's decision rules (SPEC §17a: exec
//! orchestration gets Kani harnesses and proptest in Phase A).
//!
//! The kernel itself journals through serde JSON, which bounded model
//! checking cannot get through, so its decisions are pure functions it calls
//! (`recovery_action`, `should_take_over`, `next_epoch`, `fence_admits`,
//! `swap_step`) and these harnesses check them for every input. The ordering
//! of journal writes around backend calls is covered by the Verus ledger
//! rules and by the exec crash-point property tests.
//!
//! Run: `cargo kani -p planarian-txn` (see docs/verification.md).

use crate::kernel::{
    LEASE_GRACE, RecoveryAction, SwapStep, fence_admits, next_epoch, recovery_action, should_take_over, swap_step,
};
use crate::machine::step_allowed;
use planarian_schema::{Actor, Hash, RecoveryStrategy, RejectReason, Timestamp, TxnState};

fn any_state() -> TxnState {
    let i: u8 = kani::any();
    match i % 15 {
        0 => TxnState::Prepared,
        1 => TxnState::Staged,
        2 => TxnState::Built,
        3 => TxnState::Activating,
        4 => TxnState::Checking,
        5 => TxnState::Published,
        6 => TxnState::Promoted,
        7 => TxnState::Reverting,
        8 => TxnState::Committed,
        9 => TxnState::Reverted,
        10 => TxnState::RecoveryFailed,
        11 => TxnState::Rejected(RejectReason::Interrupted),
        12 => TxnState::AwaitingBoot,
        13 => TxnState::PublishingBoot,
        _ => TxnState::Cancelled(Actor::Daemon),
    }
}

fn any_strategy() -> RecoveryStrategy {
    let i: u8 = kani::any();
    match i % 4 {
        0 => RecoveryStrategy::ReobserveOnly,
        1 => RecoveryStrategy::RevertGeneration,
        2 => RecoveryStrategy::UnbindDevice,
        _ => RecoveryStrategy::RestoreSnapshotThenRevert,
    }
}

fn in_window(s: &TxnState) -> bool {
    matches!(
        s,
        TxnState::Activating
            | TxnState::Checking
            | TxnState::PublishingBoot
            | TxnState::Published
            | TxnState::Promoted
            | TxnState::Reverting
    )
}

/// A variant index: comparing these avoids the derived `PartialEq`, whose
/// string comparison CBMC cannot bound.
fn idx(s: &TxnState) -> u8 {
    match s {
        TxnState::Prepared => 0,
        TxnState::Staged => 1,
        TxnState::Built => 2,
        TxnState::Activating => 3,
        TxnState::Checking => 4,
        TxnState::Published => 5,
        TxnState::Promoted => 6,
        TxnState::Reverting => 7,
        TxnState::Committed => 8,
        TxnState::Reverted => 9,
        TxnState::RecoveryFailed => 10,
        TxnState::Rejected(_) => 11,
        TxnState::Cancelled(_) => 12,
        TxnState::AwaitingBoot => 13,
        TxnState::PublishingBoot => 14,
    }
}

/// One path recovery can journal: starts at `from`, every step allowed by
/// the state machine, ends terminal.
fn path_ok(from: &TxnState, strategy: RecoveryStrategy, path: &[TxnState]) {
    assert!(idx(&path[0]) == idx(from));
    let mut i = 0;
    while i + 1 < path.len() {
        assert!(step_allowed(&path[i], &path[i + 1], strategy));
        i += 1;
    }
    assert!(path[path.len() - 1].is_terminal());
}

/// SPEC §10's only admission pause is Promoted. Completion paths continue to
/// use path_ok's terminal assertion; this checks the actual pending path.
fn admitted_boot_wait_ok(from: &TxnState, strategy: RecoveryStrategy, path: &[TxnState]) {
    assert!(idx(&path[0]) == idx(from));
    let mut i = 0;
    while i + 1 < path.len() {
        assert!(step_allowed(&path[i], &path[i + 1], strategy));
        i += 1;
    }
    assert!(idx(&path[path.len() - 1]) == idx(&TxnState::Promoted));
}

/// `revert_generation` / `revert_device` from `from`: Reverting (unless
/// already there), then Reverted or RecoveryFailed.
fn reverts_ok(from: &TxnState, strategy: RecoveryStrategy) {
    use TxnState::*;
    if idx(from) == idx(&Reverting) {
        path_ok(from, strategy, &[Reverting, Reverted]);
        path_ok(from, strategy, &[Reverting, RecoveryFailed]);
    } else {
        path_ok(from, strategy, &[from.clone(), Reverting, Reverted]);
        path_ok(from, strategy, &[from.clone(), Reverting, RecoveryFailed]);
    }
}

/// `check_then_commit` from Checking: publish, promote, commit; a third
/// party's override edit during promotion; or revert (probes failed, publish
/// failed, promotion failed).
fn check_generation_ok(strategy: RecoveryStrategy) {
    use TxnState::*;
    path_ok(&Checking, strategy, &[Checking, Published, Promoted, Committed]);
    path_ok(&Checking, strategy, &[Checking, Published, RecoveryFailed]);
    path_ok(&Checking, strategy, &[Checking, Published, Reverting, Reverted]);
    path_ok(&Checking, strategy, &[Checking, Published, Reverting, RecoveryFailed]);
    reverts_ok(&Checking, strategy);
}

/// Every sequence of states the kernel can journal when recovery takes
/// `action` from `from`, read off the `Kernel` function the action runs, is
/// a legal path.
fn action_ok(action: RecoveryAction, from: &TxnState, strategy: RecoveryStrategy) {
    use RecoveryAction as A;
    use TxnState::*;
    match action {
        A::Reject => path_ok(from, strategy, &[from.clone(), Rejected(RejectReason::Interrupted)]),
        A::Reobserve => path_ok(from, strategy, &[from.clone(), Committed]),
        A::CandidateActive => {
            // Activating → Checking, then as from Checking; or revert.
            assert!(step_allowed(from, &Checking, strategy));
            check_generation_ok(strategy);
            reverts_ok(from, strategy);
        }
        A::CheckGeneration => check_generation_ok(strategy),
        A::RecheckPublished => {
            path_ok(from, strategy, &[Published, Promoted, Committed]);
            path_ok(from, strategy, &[Published, RecoveryFailed]);
            reverts_ok(from, strategy);
        }
        A::WriteCommitted => {
            // Boot-only admission parks here until the same-boot checkpoint;
            // checkpoint failure restores the publishing boot/default source.
            admitted_boot_wait_ok(from, strategy, &[Promoted]);
            path_ok(from, strategy, &[Promoted, Committed]);
            path_ok(from, strategy, &[Promoted, RecoveryFailed]);
            reverts_ok(from, strategy);
        }
        A::RevertGeneration | A::RevertDevice => reverts_ok(from, strategy),
        A::DriverBound => {
            path_ok(from, strategy, &[from.clone(), Checking, Committed]);
            path_ok(from, strategy, &[from.clone(), Checking, Reverting, Reverted]);
            path_ok(from, strategy, &[from.clone(), Checking, Reverting, RecoveryFailed]);
            reverts_ok(from, strategy);
        }
        A::CheckDevice => {
            path_ok(from, strategy, &[Checking, Committed]);
            reverts_ok(from, strategy);
        }
        A::ReconcileBootPublication => {
            admitted_boot_wait_ok(from, strategy, &[PublishingBoot, AwaitingBoot, Promoted]);
            path_ok(from, strategy, &[PublishingBoot, AwaitingBoot, Promoted, RecoveryFailed]);
            path_ok(from, strategy, &[PublishingBoot, AwaitingBoot, RecoveryFailed]);
            path_ok(from, strategy, &[PublishingBoot, AwaitingBoot, Reverting, Reverted]);
            path_ok(from, strategy, &[PublishingBoot, Reverted]);
            path_ok(from, strategy, &[PublishingBoot, RecoveryFailed]);
        }
        A::AwaitBoot => {
            // After a reboot (before one, the transaction is left as is):
            // the candidate booted and passed, failed, or did not boot.
            admitted_boot_wait_ok(from, strategy, &[AwaitingBoot, Promoted]);
            path_ok(from, strategy, &[AwaitingBoot, Promoted, RecoveryFailed]);
            path_ok(from, strategy, &[AwaitingBoot, RecoveryFailed]);
            path_ok(from, strategy, &[AwaitingBoot, Reverted]);
            reverts_ok(from, strategy);
        }
        A::Fail => path_ok(from, strategy, &[from.clone(), RecoveryFailed]),
    }
}

/// The crash-recovery table agrees with the journal state machine: from
/// every state a live transaction can be left in, under every strategy,
/// every path recovery can take starts at that state, takes only steps
/// `machine::step_allowed` permits (the Verus-verified rules), and ends in a
/// terminal state or the explicit admitted-boot checkpoint wait. Nothing
/// mutated is ever answered with a refusal, and
/// anything not yet mutated is.
#[kani::proof]
#[kani::unwind(6)]
fn recovery_table_follows_the_state_machine() {
    let state = any_state();
    let strategy = any_strategy();
    kani::assume(!state.is_terminal());
    let action = recovery_action(&state, strategy);
    assert!((action == RecoveryAction::Reject) == state.is_pre_mutation());
    action_ok(action, &state, strategy);
}

/// The watchdog takes a transaction over only inside the mutation window,
/// never from itself, and never from a live owner that is within its deadline
/// or has renewed within the grace period; a dead owner's transaction in the
/// window is always taken. No clock value makes the rule overflow.
#[kani::proof]
fn watchdog_takes_over_only_when_it_should() {
    let state = any_state();
    let (mine, alive): (bool, bool) = (kani::any(), kani::any());
    let (now, deadline, renewed): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let r = should_take_over(&state, mine, alive, Timestamp(now), Timestamp(deadline), Timestamp(renewed));
    if r {
        assert!(!mine && in_window(&state));
    }
    if alive && (now <= deadline || now <= renewed.saturating_add(LEASE_GRACE.0)) {
        assert!(!r);
    }
    if !alive && !mine && in_window(&state) {
        assert!(r);
    }
    if alive && !mine && in_window(&state) && now > deadline && now > renewed.saturating_add(LEASE_GRACE.0) {
        assert!(r);
    }
}

/// Fencing (I15): a takeover's epoch is above both the journaled lease and
/// the store's fence; once the fence holds it, the previous owner's epoch and
/// every other epoch are refused and the new owner's admitted; a second
/// takeover fences out the first. Epoch arithmetic never overflows: at the
/// end of the epoch space a takeover backs off instead.
#[kani::proof]
fn takeover_fences_out_the_previous_owner() {
    let old: u64 = kani::any();
    let fence: Option<u64> = if kani::any() { Some(kani::any()) } else { None };
    let e: u64 = kani::any();
    assert!(!fence_admits(None, e));
    match next_epoch(old, fence) {
        None => assert!(old == u64::MAX || fence == Some(u64::MAX)),
        Some(new) => {
            assert!(new > old);
            if let Some(f) = fence {
                assert!(new > f);
            }
            assert!(!fence_admits(Some(new), old));
            assert!(fence_admits(Some(new), new));
            assert_eq!(fence_admits(Some(new), e), e == new);
            if let Some(again) = next_epoch(new, Some(new)) {
                assert!(again > new);
                assert!(!fence_admits(Some(again), new));
            }
        }
    }
}

fn any_hash() -> Hash {
    // Two bytes vary; the rest are fixed: equality is all `swap_step` uses.
    let mut h = [0u8; 32];
    h[0] = kani::any();
    h[31] = kani::any();
    Hash(h)
}

/// The override swap (§9 step 4) never overwrites a file a third party
/// changed: it swaps only when the live file holds the expected source, and
/// is done exactly when it already holds the target. After a completed swap,
/// the revert direction swaps back.
#[kani::proof]
fn override_swap_never_overwrites_a_third_party() {
    let (current, from, to) = (any_hash(), any_hash(), any_hash());
    match swap_step(&current, &from, &to) {
        SwapStep::Done => assert!(current == to),
        SwapStep::Swap => assert!(current == from && current != to),
        SwapStep::ThirdParty => assert!(current != from && current != to),
    }
    if current == to && from != to {
        assert_eq!(swap_step(&current, &to, &from), SwapStep::Swap);
    }
}
