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
/// restart's reconciliation (those it interrupted are the others).
pub fn prepare_again(ledger: &Ledger, terminal_before: &BTreeSet<TxnId>) -> PrepareAgain {
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
