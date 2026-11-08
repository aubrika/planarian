//! §12c: a decisive field a transaction carries (a candidate's NAR hash, the
//! probes passing before, a withdrawal's links) is required of a target that
//! predates the export, and stays required once its record is compacted away
//! (J23, `docs/regression-ledger.md`). The unit tests in the journal pin each
//! path; this states it over histories, so a checkpoint cannot drop one
//! (the fail-open C6 names for `candidate_nar`).

mod common;

use common::*;
use planarian_schema::*;
use proptest::prelude::*;
use proptest::test_runner::{Config, FailurePersistence};

#[derive(Clone, Debug)]
struct Step {
    candidate_nar: bool,
    pre_passing: bool,
    reject: bool,
    compact: bool,
    restart: bool,
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(
        (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
            |(candidate_nar, pre_passing, reject, compact, restart)| Step {
                candidate_nar,
                pre_passing,
                reject,
                compact,
                restart,
            },
        ),
        1..8,
    )
}

fn has(needs: &planarian_txn::journal::JournalRequirements, kind: &str, path: &str) -> bool {
    needs.fields.get(kind).is_some_and(|f| f.iter().any(|p| p == path))
}

proptest! {
    #![proptest_config(Config { cases: 48, failure_persistence: None::<Box<dyn FailurePersistence>>, ..Config::default() })]

    /// Whatever was prepared (with or without a candidate hash or probes
    /// passing before), rejected or left live, and wherever the journal was
    /// compacted or the daemon restarted: the requirements before and after
    /// are the same, they name `candidate_nar` and `check.pre_passing` for
    /// as long as a transaction that set them is in the journal, and this
    /// build's descriptor reads them.
    #[test]
    fn what_a_transaction_set_stays_required_through_compaction(history in steps()) {
        let rig = Rig::new();
        let mut kernel = rig.daemon();
        let (mut nar, mut pre) = (false, false);
        for s in history {
            let mut t = txn(Transition::RestartUnit(web()), Actor::user(ADMIN));
            if s.candidate_nar {
                t.candidate_nar = Some(Hash([7; 32]));
            }
            if s.pre_passing {
                t.check.pre_passing.insert(web(), vec![ProbeId("p".into())]);
            }
            let id = kernel.prepare(t).unwrap();
            nar |= s.candidate_nar;
            pre |= s.pre_passing;
            if s.reject {
                kernel.reject(id, RejectReason::Other("fixture declined".into())).unwrap();
            }
            let before = kernel.journal.required_decisive().unwrap();
            if s.compact {
                kernel.journal.compact().unwrap();
            }
            if s.restart {
                kernel = rig.daemon();
            }
            let after = kernel.journal.required_decisive().unwrap();
            prop_assert_eq!(&before, &after);
            prop_assert_eq!(has(&after, "Prepared", "candidate_nar"), nar, "{:?}", after);
            prop_assert_eq!(has(&after, "Prepared", "check.pre_passing"), pre, "{:?}", after);
            // Their checkpoint spellings are one requirement with them, from
            // the first record on (not toggling as a transaction leaves the
            // live set).
            prop_assert_eq!(has(&after, "checkpoint", "live.*.txn.candidate_nar"), nar, "{:?}", after);
            prop_assert_eq!(has(&after, "checkpoint", "live.*.txn.check.pre_passing"), pre, "{:?}", after);
            prop_assert!(after.unsupported_by(&planarian_txn::journal::supported()).is_empty());
        }
    }
}
