//! Property tests for the journal (§12c) and its replay, written as catch-up
//! coverage for bugs fixed during development (`docs/regression-ledger.md`):
//!
//! - #41: an intact tail record that did not parse was truncated as if torn.
//!   Stated whole: open truncates only a torn tail, never an intact frame.
//! - #26: a withdrawal (`Advance.withdrawn_for`) and its re-preparation
//!   (`Transaction.prepared_again_from`) lived only in memory. Stated whole:
//!   whatever the history and wherever it was compacted, the journal reopens
//!   to the live ledger, and every link written is read back.
//!
//! `PROPTEST_CASES` raises the case counts for a deeper local run.

mod common;

use common::*;
use planarian_schema::*;
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::{Entry, Ledger, Record};
use planarian_txn::store::{MemStore, Store};
use proptest::prelude::*;
use proptest::test_runner::{Config, FailurePersistence};
use std::collections::BTreeMap;

fn config(cases: u32) -> Config {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(cases);
    Config { cases, failure_persistence: None::<Box<dyn FailurePersistence>>, ..Config::default() }
}

/// `n` simple records (incidents), each appended and fsync'd. Returns the
/// store and each record's [start, end) byte range in the log.
fn written(n: usize) -> (MemStore, Vec<(u64, u64)>) {
    // Small, so open's search for a later intact record stays quick.
    let store = MemStore::new(1 << 14);
    let mut j = Journal::open(store.clone()).unwrap();
    let mut frames = Vec::new();
    for i in 0..n {
        let start = j.offset();
        j.append(Timestamp(1_000 + i as u64), incident(i as u64)).unwrap();
        frames.push((start, j.offset()));
    }
    (store, frames)
}

fn incident(i: u64) -> Record {
    Record::Incident(Incident {
        id: IncidentId(i),
        kind: IncidentKind::Repair,
        target: UnitId::service("gym-flap"),
        divergence: (DesiredStatus::Running, UnitStatus::Failed(Reason::ExitCode(1))),
        opened: Timestamp(1_000),
        attempts: vec![],
        budget_left: 3,
        state: IncidentState::Open,
        backoff: Millis::secs(30),
        next_attempt: Timestamp(1_000),
        regressions: 0,
    })
}

/// What a single-record edit did to the payload, judged independently of the
/// journal: it no longer parses as an entry, it parses but names another seq
/// (§12c's "mismatched" record, truncated as the tail), or it parses as the
/// same seq.
#[derive(Debug, PartialEq)]
enum Edited {
    Unparsable,
    OtherSeq,
    SameSeq,
}

fn judge(payload: &[u8], seq: u64) -> Edited {
    match serde_json::from_slice::<Entry>(payload) {
        Err(_) => Edited::Unparsable,
        Ok(e) if e.seq != seq => Edited::OtherSeq,
        Ok(_) => Edited::SameSeq,
    }
}

/// How many records a store holds, intact and in order, from offset 0.
fn intact_records(store: &MemStore) -> usize {
    let mut n = 0;
    while planarian_txn::journal::tamper(store, n, |_| {}).unwrap() {
        n += 1;
    }
    n
}

proptest! {
    #![proptest_config(config(256))]

    /// #41 (§12c Format), the torn half: a crash part-way through writing the
    /// last record leaves some prefix of its frame, then zeros or stale
    /// bytes. Open drops exactly that record, keeps every earlier one, and
    /// the journal takes the next append in its place.
    #[test]
    fn a_torn_tail_drops_only_the_last_record(
        n in 1..12usize,
        cut in any::<prop::sample::Index>(),
        fill in prop_oneof![Just(0u8), any::<u8>()],
    ) {
        let (store, frames) = written(n);
        let (start, end) = frames[n - 1];
        let k = start + cut.index((end - start) as usize) as u64;
        store.write_at(k, &vec![fill; (end - k) as usize]).unwrap();
        let mut j = Journal::open(store.clone()).expect("a torn tail opens");
        prop_assert_eq!(j.ledger().last_seq, n as u64 - 1);
        prop_assert_eq!(j.offset(), start);
        j.append(Timestamp(9_999), incident(99)).unwrap();
        prop_assert_eq!(Journal::open(store).unwrap().ledger().last_seq, n as u64);
    }

    /// #41 (§12c Format), the intact half: an edit to any one record, re-framed
    /// so its CRC holds and its `prev` is its own (the frame is intact, not
    /// torn), never makes open truncate a record. A payload that no longer
    /// parses is `Integrity`, on every open, with every record still on disk;
    /// before the fix an unparsable *last* record was zeroed as a torn tail.
    #[test]
    fn an_intact_frame_is_never_truncated(
        n in 1..10usize,
        which in any::<prop::sample::Index>(),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let (store, _) = written(n);
        let i = which.index(n);
        let mut edited = None;
        let found = planarian_txn::journal::tamper(&store, i, |p| {
            let k = at.index(p.len());
            // A real edit: never the byte already there.
            p[k] = if p[k] == byte { byte ^ 1 } else { byte };
            edited = Some(p.clone());
        })
        .unwrap();
        prop_assert!(found);
        let verdict = judge(&edited.unwrap(), i as u64 + 1);
        // §12c's "mismatched" record names another seq inside an intact
        // frame; it is the tail's to drop, so it says nothing here.
        prop_assume!(verdict != Edited::OtherSeq);
        let first = Journal::open(store.clone());
        match (&verdict, &first) {
            (Edited::Unparsable, Err(JournalError::Integrity(_))) => {}
            (Edited::Unparsable, other) => {
                return Err(TestCaseError::fail(format!(
                    "record {} of {n} does not parse but open gave {:?}",
                    i + 1,
                    other.as_ref().map(|j| j.ledger().last_seq)
                )));
            }
            // Parsable: the unkeyed chain cannot see an edit of the last
            // record (B-8); an earlier one breaks the next record's chain.
            (Edited::SameSeq, Ok(j)) => {
                prop_assert_eq!(i, n - 1, "an edit before the tail was accepted");
                prop_assert_eq!(j.ledger().last_seq, n as u64);
            }
            (Edited::SameSeq, Err(JournalError::Integrity(_))) => {}
            (_, other) => {
                return Err(TestCaseError::fail(format!("unexpected open: {:?}", other.as_ref().err())));
            }
        }
        // Nothing was truncated or zeroed, and a second open agrees.
        prop_assert_eq!(intact_records(&store), n);
        let second = Journal::open(store.clone());
        prop_assert_eq!(first.is_ok(), second.is_ok());
        if let (Ok(a), Ok(b)) = (first, second) {
            prop_assert_eq!(a.ledger(), b.ledger());
        }
    }
}

/// One step of a history over the fake machine's kernel.
#[derive(Clone, Debug)]
enum Step {
    /// Prepare an update (a generation change) or a unit restart.
    Prepare(bool),
    /// Run the nth live transaction to its end.
    Run(prop::sample::Index),
    /// §12f: withdraw the nth live transaction for rollback `TxnId(1000 + r)`.
    Withdraw(prop::sample::Index, u8),
    /// Reject the nth live transaction (no rollback named).
    Reject(prop::sample::Index),
    /// §12f: prepare again the nth withdrawn transaction not yet prepared again.
    PrepareAgain(prop::sample::Index),
    Compact,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        3 => any::<bool>().prop_map(Step::Prepare),
        2 => any::<prop::sample::Index>().prop_map(Step::Run),
        2 => (any::<prop::sample::Index>(), any::<u8>()).prop_map(|(i, r)| Step::Withdraw(i, r)),
        1 => any::<prop::sample::Index>().prop_map(Step::Reject),
        2 => any::<prop::sample::Index>().prop_map(Step::PrepareAgain),
        2 => Just(Step::Compact),
    ]
}

/// What the history wrote, kept by the test: each withdrawal's rollback and
/// each re-preparation's source.
#[derive(Default)]
struct Links {
    withdrawn_for: BTreeMap<TxnId, TxnId>,
    prepared_again_from: BTreeMap<TxnId, TxnId>,
}

fn prepared_again_from(l: &Ledger, id: TxnId) -> Option<TxnId> {
    match l.live.get(&id) {
        Some(t) => t.txn.prepared_again_from,
        None => l.terminal.get(&id).and_then(|t| t.prepared_again_from),
    }
}

// Each case replays the journal after every step, so fewer cases than the
// default keep CI under half a minute here; `PROPTEST_CASES` goes deeper.
proptest! {
    #![proptest_config(config(48))]

    /// #26 (§12f, I18): after every step of a random history of prepares,
    /// runs, withdrawals, rejections, re-preparations and compactions, the
    /// journal reopened from its bytes (as the restarted daemon and the
    /// watchdog do) equals the live ledger, and every withdrawal and
    /// re-preparation link the history wrote is read back. Before the fix the
    /// withdrawal lived only in the daemon's memory.
    #[test]
    fn reopening_keeps_every_link(steps in proptest::collection::vec(step(), 1..24)) {
        let rig = Rig::new();
        let mut d = rig.daemon();
        let mut links = Links::default();
        for s in steps {
            let live: Vec<TxnId> = d.journal.sync_ledger().unwrap().live.keys().copied().collect();
            match s {
                Step::Prepare(update) => {
                    let t = if update { good_change() } else { txn(Transition::RestartUnit(web()), Actor::user(ADMIN)) };
                    let _ = d.prepare(t);
                }
                Step::Run(i) if !live.is_empty() => {
                    let _ = d.run(live[i.index(live.len())]);
                }
                Step::Withdraw(i, r) if !live.is_empty() => {
                    let id = live[i.index(live.len())];
                    let rollback = TxnId(1000 + r as u64);
                    if d.withdraw(id, rollback).is_ok() {
                        links.withdrawn_for.insert(id, rollback);
                    }
                }
                Step::Reject(i) if !live.is_empty() => {
                    let _ = d.reject(live[i.index(live.len())], RejectReason::Interrupted);
                }
                Step::PrepareAgain(i) => {
                    let open: Vec<TxnId> = links
                        .withdrawn_for
                        .keys()
                        .filter(|w| !links.prepared_again_from.values().any(|f| f == *w))
                        .copied()
                        .collect();
                    if !open.is_empty() {
                        let from = open[i.index(open.len())];
                        let mut t = good_change();
                        t.prepared_again_from = Some(from);
                        if let Ok(id) = d.prepare(t) {
                            links.prepared_again_from.insert(id, from);
                        }
                    }
                }
                Step::Compact => d.journal.compact().unwrap(),
                _ => {}
            }
            let live = d.journal.sync_ledger().unwrap().clone();
            // The restarted daemon and the watchdog each open the store so.
            {
                let reopened = Journal::open(rig.store.clone()).unwrap();
                let l = reopened.ledger();
                prop_assert_eq!(l, &live);
                for (id, rollback) in &links.withdrawn_for {
                    prop_assert_eq!(l.terminal.get(id).and_then(|t| t.withdrawn_for), Some(*rollback), "{:?}", id);
                }
                for (id, from) in &links.prepared_again_from {
                    prop_assert_eq!(prepared_again_from(l, *id), Some(*from), "{:?}", id);
                }
            }
        }
    }
}

/// One hold event, or a compaction, or a reopen (the daemon restarting).
#[derive(Clone, Debug)]
enum HoldStep {
    Apply(u8, bool),
    Lift(u8),
    Compact,
    Reopen,
}

fn hold_step() -> impl Strategy<Value = HoldStep> {
    prop_oneof![
        4 => (0..4u8, any::<bool>()).prop_map(|(u, f)| HoldStep::Apply(u, f)),
        3 => (0..4u8).prop_map(HoldStep::Lift),
        1 => Just(HoldStep::Compact),
        1 => Just(HoldStep::Reopen),
    ]
}

fn held_unit(u: u8) -> UnitId {
    UnitId::service(&format!("vpn-{u}"))
}

proptest! {
    #![proptest_config(config(256))]

    /// D14 (§12d, #35/#40): the journal's holds are its recovery source of
    /// truth after a restart. For any sequence of applies and lifts (either
    /// may repeat), with compactions and reopens anywhere, `holds()` is the
    /// set of units whose last event is an apply, on the live handle and on a
    /// journal reopened from its bytes.
    #[test]
    fn holds_are_the_last_event_per_unit(steps in proptest::collection::vec(hold_step(), 1..40)) {
        use planarian_txn::ledger::HoldBy;
        // Small: after a compaction, open searches the stale bytes past the
        // log's end for a later intact record, byte by byte.
        let store = MemStore::new(1 << 14);
        let mut j = Journal::open(store.clone()).unwrap();
        let mut model: BTreeMap<u8, bool> = BTreeMap::new();
        for (k, s) in steps.into_iter().enumerate() {
            let at = Timestamp(1_000 + k as u64);
            match s {
                HoldStep::Apply(u, on_failure) => {
                    let by = if on_failure { HoldBy::OnFailure } else { HoldBy::Daemon };
                    j.append(at, Record::HoldApplied { unit: held_unit(u), by }).unwrap();
                    model.insert(u, true);
                }
                HoldStep::Lift(u) => {
                    j.append(at, Record::HoldLifted { unit: held_unit(u), reason: "Readiness passes".into() }).unwrap();
                    model.insert(u, false);
                }
                HoldStep::Compact => j.compact().unwrap(),
                HoldStep::Reopen => j = Journal::open(store.clone()).unwrap(),
            }
            let expect: std::collections::BTreeSet<UnitId> =
                model.iter().filter(|(_, on)| **on).map(|(u, _)| held_unit(*u)).collect();
            prop_assert_eq!(j.ledger().holds(), expect.clone(), "live");
            prop_assert_eq!(Journal::open(store.clone()).unwrap().ledger().holds(), expect, "reopened");
        }
    }
}
