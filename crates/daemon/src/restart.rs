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
    use planarian_txn::ledger::{Entry, Record};
    use proptest::prelude::*;
    use proptest::test_runner::Config as PConfig;

    fn pconfig(cases: u32) -> PConfig {
        let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(cases);
        PConfig { cases, failure_persistence: None, ..PConfig::default() }
    }

    /// A transaction as the journal first records it (exec's shape; nothing
    /// `prepare_again` reads but the id, the state and `prepared_again_from`).
    fn txn(id: TxnId, again: Option<TxnId>) -> Transaction {
        let transition = Transition::RestartUnit(UnitId::service("gym-web"));
        Transaction {
            id,
            state: TxnState::Prepared,
            lease: Lease {
                txn: id,
                owner: OwnerId::Daemon { pid: 1, boot_id: Hash::ZERO },
                epoch: 1,
                worker_pid: None,
                renewed: Timestamp(0),
                jobs: vec![],
            },
            base_source: None,
            staged_source: None,
            candidate_nar: None,
            base_override: None,
            candidate_override: None,
            gc_root: None,
            recovery: transition.recovery(),
            transition,
            facts: DerivedFacts {
                affected_units: Vec::new(),
                sensitivity: Sensitivities::default(),
                disruption: Disruptions::of(Disruption::Brief),
                recovery: Recovery::Idempotent,
                touches_manifest: false,
                touches_canonical_probe: false,
                changes_desired: false,
                below_security_floor: false,
                restores_unattributed_stop: false,
                restarts_failed_unit: false,
                removes_sensitivity: Default::default(),
                removes: Default::default(),
                removes_each: Default::default(),
                restarts_held_unit: false,
                other_sessions_affected: false,
                affected_sessions: Vec::new(),
                touches_core: false,
                caller: Actor::Daemon,
                config_diff: None,
            },
            base: GenerationId(1),
            candidate: None,
            policy: PolicyVersion(Hash::ZERO),
            approval: None,
            snapshot: None,
            expected: Expectation {
                units: Default::default(),
                generation: None,
                may_change: Default::default(),
                others_unchanged: true,
                settle: Settle::Duration(Millis::secs(15)),
            },
            started: Timestamp(1_000_000),
            deadline: Timestamp(1_000_000 + 15 * 60 * 1000),
            revert_to: GenerationId(1),
            prior_driver: None,
            check: CheckContext::default(),
            prepared_again_from: again,
        }
    }

    /// Where a script moves a transaction.
    #[derive(Clone, Debug)]
    enum To {
        Staged,
        Built,
        /// `Rejected(Interrupted)`, withdrawn for a rollback or not.
        Interrupted(Option<u8>),
        /// Another rejection or a cancellation, which no daemon journals with
        /// a withdrawal but a record may carry one.
        Rejected(Option<u8>),
        Cancelled(Option<u8>),
    }

    #[derive(Clone, Debug)]
    enum Op {
        /// A new transaction, preparing again a withdrawn one (or none, or a
        /// transaction that does not exist).
        Prepare(Option<u8>),
        Move(prop::sample::Index, To),
    }

    fn ops() -> impl Strategy<Value = Vec<Op>> {
        let to = prop_oneof![
            3 => Just(To::Staged),
            3 => Just(To::Built),
            4 => proptest::option::of(0u8..4).prop_map(To::Interrupted),
            1 => proptest::option::of(0u8..4).prop_map(To::Rejected),
            1 => proptest::option::of(0u8..4).prop_map(To::Cancelled),
        ];
        proptest::collection::vec(
            prop_oneof![
                3 => proptest::option::weighted(0.4, 1u8..8).prop_map(Op::Prepare),
                7 => (any::<prop::sample::Index>(), to).prop_map(|(i, t)| Op::Move(i, t)),
            ],
            1..30,
        )
    }

    /// What the script did, kept as it goes (not read back from the ledger):
    /// each transaction's states entered, its withdrawal, and who it names.
    #[derive(Default)]
    struct Model {
        history: BTreeMap<TxnId, Vec<TxnState>>,
        withdrawn_for: BTreeMap<TxnId, TxnId>,
        again: BTreeMap<TxnId, TxnId>,
    }

    use std::collections::BTreeMap;

    fn build(ops: &[Op]) -> (Ledger, Vec<Entry>, Model) {
        let mut l = Ledger::default();
        let mut entries = vec![];
        let mut m = Model::default();
        let mut next = 1u64;
        let mut seq = 0u64;
        let mut apply = |l: &mut Ledger, r: Record| -> bool {
            let e = Entry { seq: seq + 1, at: Timestamp(1_000 + seq), record: r };
            if l.apply(e.clone()).is_ok() {
                seq += 1;
                entries.push(e);
                true
            } else {
                false
            }
        };
        for op in ops {
            match op {
                Op::Prepare(from) => {
                    let id = TxnId(next);
                    let again = from.map(|f| TxnId(f as u64));
                    if apply(&mut l, Record::Prepared(Box::new(txn(id, again)))) {
                        next += 1;
                        m.history.insert(id, vec![TxnState::Prepared]);
                        if let Some(a) = again {
                            m.again.insert(id, a);
                        }
                    }
                }
                Op::Move(i, to) => {
                    let ids: Vec<TxnId> = m.history.keys().copied().collect();
                    if ids.is_empty() {
                        continue;
                    }
                    let id = ids[i.index(ids.len())];
                    let (state, withdrawn_for) = match to {
                        To::Staged => (TxnState::Staged, None),
                        To::Built => (TxnState::Built, None),
                        To::Interrupted(r) => {
                            (TxnState::Rejected(RejectReason::Interrupted), r.map(|r| TxnId(1000 + r as u64)))
                        }
                        To::Rejected(r) => {
                            (TxnState::Rejected(RejectReason::Precondition), r.map(|r| TxnId(1000 + r as u64)))
                        }
                        To::Cancelled(r) => (TxnState::Cancelled(Actor::Daemon), r.map(|r| TxnId(1000 + r as u64))),
                    };
                    let rec =
                        Record::Advance { txn: id, epoch: 1, to: state.clone(), note: String::new(), withdrawn_for };
                    if apply(&mut l, rec) {
                        m.history.get_mut(&id).unwrap().push(state);
                        if let Some(w) = withdrawn_for {
                            m.withdrawn_for.insert(id, w);
                        }
                    }
                }
            }
        }
        (l, entries, m)
    }

    fn replayed(entries: &[Entry]) -> Ledger {
        let mut l = Ledger::default();
        for e in entries {
            l.apply(e.clone()).expect("a record that applied once applies again");
        }
        l
    }

    fn ids(v: &[(TxnId, Transition)]) -> Vec<TxnId> {
        v.iter().map(|(i, _)| *i).collect()
    }

    proptest! {
        #![proptest_config(pconfig(512))]

        /// J4 (§12f, #26): over any journal of preparations, steps,
        /// interruptions and withdrawals (replayed through the ledger's own
        /// fold), and any set of transactions that were already terminal
        /// before the restart: no transaction is prepared twice, nor in both
        /// lists; one that any transaction names in `prepared_again_from` is
        /// never prepared again; and the answer is exactly what the script
        /// says (an oracle kept as the script ran, not read from the
        /// ledger): the interrupted ones that were waiting in Built or
        /// Prepared and not terminal before, and the withdrawn ones that
        /// nothing names. It is the same after compaction (the ledger
        /// through its checkpoint's JSON) and after replaying the journal again.
        #[test]
        fn what_a_restart_prepares_again_is_what_the_journal_says(ops in ops(), before_mask in any::<u16>()) {
            let (ledger, entries, m) = build(&ops);
            let terminal: Vec<TxnId> = ledger.terminal.keys().copied().collect();
            let before: BTreeSet<TxnId> = terminal.iter().enumerate().filter(|(i, _)| before_mask >> (i % 16) & 1 == 1).map(|(_, t)| *t).collect();
            let got = prepare_again(&ledger, &before);
            let (re, wd) = (ids(&got.reprepare), ids(&got.withdrawn));

            // No id twice, and none in both.
            let re_set: BTreeSet<TxnId> = re.iter().copied().collect();
            let wd_set: BTreeSet<TxnId> = wd.iter().copied().collect();
            prop_assert_eq!(re_set.len(), re.len(), "reprepare twice: {:?}", re);
            prop_assert_eq!(wd_set.len(), wd.len(), "withdrawn twice: {:?}", wd);
            prop_assert!(re_set.is_disjoint(&wd_set), "in both: {:?} {:?}", re, wd);

            // Nothing a transaction names is prepared again.
            let named: BTreeSet<TxnId> = m.again.values().copied().collect();
            prop_assert!(wd_set.is_disjoint(&named), "named but prepared again: {:?}", wd_set.intersection(&named).collect::<Vec<_>>());

            // The oracle.
            let interrupted = |id: &TxnId| matches!(m.history[id].last(), Some(TxnState::Rejected(RejectReason::Interrupted)));
            let was_waiting = |id: &TxnId| {
                let h = &m.history[id];
                h.len() >= 2 && matches!(h[h.len() - 2], TxnState::Built | TxnState::Prepared)
            };
            let want_re: BTreeSet<TxnId> = m.history.keys().filter(|i| interrupted(i) && !before.contains(i) && was_waiting(i)).copied().collect();
            let want_wd: BTreeSet<TxnId> = m
                .history
                .keys()
                .filter(|i| interrupted(i) && m.withdrawn_for.contains_key(i) && !named.contains(i) && !want_re.contains(i))
                .copied()
                .collect();
            prop_assert_eq!(&re_set, &want_re, "reprepare");
            prop_assert_eq!(&wd_set, &want_wd, "withdrawn");

            // The same after compaction and after replay.
            let compacted: Ledger = serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
            prop_assert_eq!(&prepare_again(&compacted, &before), &got, "after compaction");
            prop_assert_eq!(&prepare_again(&replayed(&entries), &before), &got, "after replay");
        }
    }

    use planarian_txn::ledger::TerminalTxn;

    /// The function as it was in `Core::start`, before `NotPreparedAgain`:
    /// the frame the new one is held to when nothing was declined.
    fn earlier(ledger: &Ledger, terminal_before: &BTreeSet<TxnId>) -> PrepareAgain {
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
    struct Shape {
        interrupted: bool,
        penultimate: u8,
        withdrawn_for: bool,
        prepared_again_from: Option<u64>,
        before: bool,
        declined: bool,
    }

    fn shape() -> impl Strategy<Value = Shape> {
        (
            prop_oneof![4 => Just(true), 1 => Just(false)],
            0..3u8,
            any::<bool>(),
            prop_oneof![3 => Just(None), 1 => (1..8u64).prop_map(Some)],
            prop_oneof![1 => Just(true), 3 => Just(false)],
            prop_oneof![1 => Just(true), 2 => Just(false)],
        )
            .prop_map(|(interrupted, penultimate, withdrawn_for, prepared_again_from, before, declined)| {
                Shape { interrupted, penultimate, withdrawn_for, prepared_again_from, before, declined }
            })
    }

    fn terminal_of(e: &Shape) -> TerminalTxn {
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
        fn a_declined_transaction_is_never_prepared_again(entries in proptest::collection::vec(shape(), 1..10)) {
            let mut ledger = Ledger::default();
            let mut terminal_before = BTreeSet::new();
            let mut declined = vec![];
            for (i, e) in entries.iter().enumerate() {
                let id = TxnId(i as u64 + 1);
                ledger.terminal.insert(id, terminal_of(e));
                if e.before {
                    terminal_before.insert(id);
                }
                if e.declined {
                    declined.push(id);
                }
            }
            let reference = earlier(&ledger, &terminal_before);
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
