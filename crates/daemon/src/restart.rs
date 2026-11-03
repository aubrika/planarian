//! What a restart prepares again (§12f), as a function of the journal: the
//! waiting generations a crash interrupted, and the ones a rollback
//! withdrew that nothing has prepared again yet. Pure, so it has its own
//! tests; `Core::start` calls it once the crash table has run.

use planarian_schema::*;
use planarian_txn::ledger::Ledger;
use std::collections::BTreeSet;

/// What to prepare again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrepareAgain {
    /// Waiting generations interrupted by this restart: in `Built` for an
    /// activation window (§12f), or a change parked for approval (§12 step
    /// 4: tokens do not survive a restart). The crash table made them
    /// `Rejected(Interrupted)`.
    pub reprepare: Vec<(TxnId, Transition)>,
    /// What a rollback withdrew and nothing names in `prepared_again_from`,
    /// from the journal, so a restart between the two loses nothing and
    /// prepares nothing twice. Prepared again once the rollback is terminal.
    pub withdrawn: Vec<(TxnId, Transition)>,
}

/// `terminal_before`: the transactions already terminal before this
/// restart's reconciliation (those it interrupted are the others). Those
/// the journal says were `NotPreparedAgain` are in neither list.
pub fn prepare_again(ledger: &Ledger, terminal_before: &BTreeSet<TxnId>) -> PrepareAgain {
    // A restart that decided not to prepare a transaction again said so
    // (`NotPreparedAgain`); no later restart tries it.
    let declined = ledger.not_prepared_again();
    let reprepare: Vec<(TxnId, Transition)> = ledger
        .terminal
        .iter()
        .filter(|(id, t)| {
            !terminal_before.contains(id)
                && !declined.contains(id)
                && t.state == TxnState::Rejected(RejectReason::Interrupted)
                && t.path.iter().rev().nth(1).is_some_and(|p| p == "Built" || p == "Prepared")
        })
        .map(|(id, t)| (*id, t.transition.clone()))
        .collect();
    let named: BTreeSet<TxnId> = ledger
        .live
        .values()
        .filter_map(|t| t.txn.prepared_again_from)
        .chain(ledger.terminal.values().filter_map(|t| t.prepared_again_from))
        .collect();
    let withdrawn: Vec<(TxnId, Transition)> = ledger
        .terminal
        .iter()
        .filter(|(id, t)| {
            t.withdrawn_for.is_some()
                && t.state == TxnState::Rejected(RejectReason::Interrupted)
                && !named.contains(id)
                && !declined.contains(id)
                && !reprepare.iter().any(|(r, _)| r == *id)
        })
        .map(|(id, t)| (*id, t.transition.clone()))
        .collect();
    PrepareAgain { reprepare, withdrawn }
}

#[cfg(test)]
mod tests {
    use super::*;
    use planarian_txn::ledger::TerminalTxn;
    use proptest::prelude::*;

    /// The function as it was in `Core::start`, before `NotPreparedAgain`:
    /// the frame the new one is held to when nothing was declined.
    fn before(ledger: &Ledger, terminal_before: &BTreeSet<TxnId>) -> PrepareAgain {
        let reprepare: Vec<(TxnId, Transition)> = ledger
            .terminal
            .iter()
            .filter(|(id, t)| {
                !terminal_before.contains(id)
                    && t.state == TxnState::Rejected(RejectReason::Interrupted)
                    && t.path.iter().rev().nth(1).is_some_and(|p| p == "Built" || p == "Prepared")
            })
            .map(|(id, t)| (*id, t.transition.clone()))
            .collect();
        let named: BTreeSet<TxnId> = ledger
            .live
            .values()
            .filter_map(|t| t.txn.prepared_again_from)
            .chain(ledger.terminal.values().filter_map(|t| t.prepared_again_from))
            .collect();
        let withdrawn: Vec<(TxnId, Transition)> = ledger
            .terminal
            .iter()
            .filter(|(id, t)| {
                t.withdrawn_for.is_some()
                    && t.state == TxnState::Rejected(RejectReason::Interrupted)
                    && !named.contains(id)
                    && !reprepare.iter().any(|(r, _)| r == *id)
            })
            .map(|(id, t)| (*id, t.transition.clone()))
            .collect();
        PrepareAgain { reprepare, withdrawn }
    }

    #[derive(Clone, Debug)]
    struct Entry {
        interrupted: bool,
        penultimate: u8,
        withdrawn_for: bool,
        prepared_again_from: Option<u64>,
        before: bool,
        declined: bool,
    }

    fn entry() -> impl Strategy<Value = Entry> {
        (
            prop_oneof![4 => Just(true), 1 => Just(false)],
            0..3u8,
            any::<bool>(),
            prop_oneof![3 => Just(None), 1 => (1..8u64).prop_map(Some)],
            prop_oneof![1 => Just(true), 3 => Just(false)],
            prop_oneof![1 => Just(true), 2 => Just(false)],
        )
            .prop_map(|(interrupted, penultimate, withdrawn_for, prepared_again_from, before, declined)| {
                Entry { interrupted, penultimate, withdrawn_for, prepared_again_from, before, declined }
            })
    }

    fn terminal(e: &Entry) -> TerminalTxn {
        let step = ["Built", "Prepared", "Checking"][e.penultimate as usize % 3];
        TerminalTxn {
            state: if e.interrupted { TxnState::Rejected(RejectReason::Interrupted) } else { TxnState::Committed },
            epoch: 1,
            owner: OwnerId::Daemon { pid: 1, boot_id: Hash::ZERO },
            path: vec![step.into(), "Rejected".into()],
            transition: Transition::Rollback,
            why: String::new(),
            withdrawn_for: e.withdrawn_for.then_some(TxnId(99)),
            prepared_again_from: e.prepared_again_from.map(TxnId),
        }
    }

    proptest! {
        /// What a restart prepares again is a function of the journal: a
        /// transaction a restart declined (`NotPreparedAgain`) is in neither
        /// list, whatever else is true of it; nothing is added; and with
        /// nothing declined the answer is exactly the earlier function's.
        #[test]
        fn a_declined_transaction_is_never_prepared_again(entries in proptest::collection::vec(entry(), 1..10)) {
            let mut ledger = Ledger::default();
            let mut terminal_before = BTreeSet::new();
            let mut declined = vec![];
            for (i, e) in entries.iter().enumerate() {
                let id = TxnId(i as u64 + 1);
                ledger.terminal.insert(id, terminal(e));
                if e.before {
                    terminal_before.insert(id);
                }
                if e.declined {
                    declined.push(id);
                }
            }
            let reference = before(&ledger, &terminal_before);
            ledger.not_prepared_again = declined.clone();
            let got = prepare_again(&ledger, &terminal_before);
            let ids = |l: &[(TxnId, Transition)]| l.iter().map(|(i, _)| *i).collect::<Vec<_>>();
            for id in ids(&got.reprepare).into_iter().chain(ids(&got.withdrawn)) {
                prop_assert!(!declined.contains(&id), "{id:?} was declined");
                prop_assert!(
                    ids(&reference.reprepare).contains(&id) || ids(&reference.withdrawn).contains(&id),
                    "{id:?} is new"
                );
            }
            // Exactly the earlier answer without the declined ones.
            let drop = |l: &[(TxnId, Transition)]| l.iter().filter(|(i, _)| !declined.contains(i)).cloned().collect::<Vec<_>>();
            prop_assert_eq!(&got.reprepare, &drop(&reference.reprepare));
            // A withdrawn transaction is declined out of `withdrawn` only, so one that was not
            // reprepared stays prepared-again-able by nobody else.
            prop_assert!(got.reprepare.iter().all(|(i, _)| !got.withdrawn.iter().any(|(w, _)| w == i)));
            ledger.not_prepared_again.clear();
            prop_assert_eq!(prepare_again(&ledger, &terminal_before), reference);
        }
    }
}
