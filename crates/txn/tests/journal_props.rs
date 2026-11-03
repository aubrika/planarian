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
//!
//! Stores are 1 MiB (`store`): J16's fix (#54) made `Journal::open` after a
//! compaction linear in the store, so histories that compact run at a size
//! with real leftovers past the tail. `at_the_default_journal_size` reruns
//! the properties that compact at the 64 MiB default, behind `#[ignore]`.

mod common;

use common::*;
use planarian_schema::*;
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::{Entry, Ledger, Record};
use planarian_txn::store::{MemStore, Store};
use proptest::prelude::*;
use proptest::test_runner::{Config, FailurePersistence};
use std::collections::BTreeMap;

thread_local! {
    /// Overrides for `at_the_default_journal_size`: the store's size, and
    /// the cases per property.
    static STORE: std::cell::Cell<u64> = const { std::cell::Cell::new(1 << 20) };
    static CASES: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// The store's size for a property whose history compacts.
fn store() -> MemStore {
    MemStore::new(STORE.with(std::cell::Cell::get))
}

fn config(cases: u32) -> Config {
    let cases = CASES
        .with(std::cell::Cell::get)
        .or_else(|| std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()))
        .unwrap_or(cases);
    Config { cases, failure_persistence: None::<Box<dyn FailurePersistence>>, ..Config::default() }
}

/// `n` simple records (incidents), each appended and fsync'd. Returns the
/// store and each record's [start, end) byte range in the log.
fn written(n: usize) -> (MemStore, Vec<(u64, u64)>) {
    let store = store();
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
    // Every step reopens a 1 MiB store twice; 32 cases keep CI near ten
    // seconds. `PROPTEST_CASES` goes deeper.
    #![proptest_config(config(32))]

    /// D14 (§12d, #35/#40): the journal's holds are its recovery source of
    /// truth after a restart. For any sequence of applies and lifts (either
    /// may repeat), with compactions and reopens anywhere, `holds()` is the
    /// set of units whose last event is an apply, on the live handle and on a
    /// journal reopened from its bytes.
    #[test]
    fn holds_are_the_last_event_per_unit(steps in proptest::collection::vec(hold_step(), 1..40)) {
        use planarian_txn::ledger::HoldBy;
        let store = store();
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

/// How a checkpoint is damaged: bytes flipped or cut off, as a bad disk or
/// a torn write leaves it, or its payload edited and re-framed with a valid
/// CRC, as a naive editor would.
#[derive(Clone, Debug)]
enum Damage {
    Flip(prop::sample::Index, u8),
    Truncate(prop::sample::Index),
    Reframe(prop::sample::Index, u8),
}

fn damage() -> impl Strategy<Value = Damage> {
    prop_oneof![
        (any::<prop::sample::Index>(), 1..=255u8).prop_map(|(i, x)| Damage::Flip(i, x)),
        any::<prop::sample::Index>().prop_map(Damage::Truncate),
        (any::<prop::sample::Index>(), any::<u8>()).prop_map(|(i, b)| Damage::Reframe(i, b)),
    ]
}

/// The frame format (journal.rs's header): `len | crc32c | seq | prev |
/// payload`, the CRC over the format tag, `seq`, `prev` and the payload.
fn reframe(bytes: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let (seq, prev) = (&bytes[8..16], &bytes[16..48]);
    let mut payload = bytes[48..].to_vec();
    edit(&mut payload);
    let mut body = Vec::new();
    body.extend_from_slice(seq);
    body.extend_from_slice(prev);
    body.extend_from_slice(&payload);
    let mut out = Vec::new();
    out.extend_from_slice(&((32 + payload.len()) as u32).to_le_bytes());
    out.extend_from_slice(&crc32c::crc32c_append(crc32c::crc32c(b"planarian-journal-2"), &body).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

proptest! {
    #![proptest_config(config(256))]

    /// J8 (C16, `7059f7d`): a damaged checkpoint opens as `Integrity`, the
    /// posture's input, never as a fresh start or another error. Before the
    /// fix it was `Corrupt`. Only a re-framed payload that still parses,
    /// agrees with its seq and keeps the ledger invariant can open: the
    /// unkeyed chain cannot see that edit (B-8).
    #[test]
    fn a_damaged_checkpoint_is_integrity(n in 1..10usize, after in 0..4usize, d in damage()) {
        let (store, _) = written(n);
        let mut j = Journal::open(store.clone()).unwrap();
        j.compact().unwrap();
        for k in 0..after {
            j.append(Timestamp(5_000 + k as u64), incident(50 + k as u64)).unwrap();
        }
        drop(j);
        let good = store.read_checkpoint().unwrap().expect("a checkpoint");
        let mut may_open = false;
        let bad = match d {
            Damage::Flip(i, x) => {
                let mut b = good.clone();
                let k = i.index(b.len());
                b[k] ^= x;
                b
            }
            Damage::Truncate(i) => good[..i.index(good.len())].to_vec(),
            Damage::Reframe(i, byte) => {
                let b = reframe(&good, |p| {
                    let k = i.index(p.len());
                    p[k] = if p[k] == byte { byte ^ 1 } else { byte };
                });
                let seq = u64::from_le_bytes(b[8..16].try_into().unwrap());
                may_open = serde_json::from_slice::<Ledger>(&b[48..])
                    .is_ok_and(|l| l.last_seq == seq && l.well_formed());
                b
            }
        };
        store.write_checkpoint(&bad).unwrap();
        match Journal::open(store.clone()) {
            Err(JournalError::Integrity(_)) => {}
            Ok(_) if may_open => {}
            Ok(j) => {
                return Err(TestCaseError::fail(format!(
                    "a damaged checkpoint ({d:?}) opened, at seq {}",
                    j.ledger().last_seq
                )));
            }
            Err(e) => return Err(TestCaseError::fail(format!("a damaged checkpoint ({d:?}) gave {e:?}, not Integrity"))),
        }
    }
}

/// A step against the store directly: a write (possibly overlapping
/// earlier ones), a sync, or a power loss.
#[derive(Clone, Debug)]
enum IoStep {
    Write(u8, u8, u8),
    Sync,
    Crash,
}

fn io_step() -> impl Strategy<Value = IoStep> {
    prop_oneof![
        5 => (0..200u8, 1..56u8, any::<u8>()).prop_map(|(o, l, b)| IoStep::Write(o, l, b)),
        2 => Just(IoStep::Sync),
        2 => Just(IoStep::Crash),
    ]
}

/// A step against the journal: an append, a torn append, or a power loss.
#[derive(Clone, Debug)]
enum CrashStep {
    Append,
    TornAppend(prop::sample::Index),
    Crash,
}

fn crash_step() -> impl Strategy<Value = CrashStep> {
    prop_oneof![
        5 => Just(CrashStep::Append),
        1 => any::<prop::sample::Index>().prop_map(CrashStep::TornAppend),
        2 => Just(CrashStep::Crash),
    ]
}

proptest! {
    #![proptest_config(config(256))]

    /// J9 (P21, #32): the fake's "journal fsync is durable" contract can
    /// fail. Against a model of the disk (what a read sees, and what the
    /// last sync made durable), for any sequence of overlapping writes,
    /// syncs and power losses, `MemStore` reads back the model: a crash
    /// keeps exactly what the last sync covered. Before the fix `sync` was a
    /// no-op and nothing was ever lost.
    #[test]
    fn a_crash_keeps_exactly_what_was_synced(steps in proptest::collection::vec(io_step(), 1..40)) {
        const SIZE: usize = 256;
        let store = MemStore::new(SIZE as u64);
        let mut current = vec![0u8; SIZE];
        let mut durable = current.clone();
        for s in steps {
            match s {
                IoStep::Write(off, len, b) => {
                    let (off, len) = (off as usize, len as usize);
                    store.write_at(off as u64, &vec![b; len]).unwrap();
                    current[off..off + len].fill(b);
                }
                IoStep::Sync => {
                    store.sync().unwrap();
                    durable = current.clone();
                }
                IoStep::Crash => {
                    store.crash();
                    current = durable.clone();
                }
            }
            prop_assert_eq!(store.read_at(0, SIZE).unwrap(), current.clone());
        }
    }

    /// J9, the journal's side: every append is fsync'd before it is applied
    /// (§12 write-ahead), so a power loss after it keeps it, and a torn
    /// append is lost whole. After any sequence, the journal reopens to
    /// exactly the appends that returned `Ok`.
    #[test]
    fn an_accepted_append_survives_any_crash(steps in proptest::collection::vec(crash_step(), 1..24)) {
        let store = store();
        let mut j = Journal::open(store.clone()).unwrap();
        let mut accepted = 0u64;
        for s in steps {
            match s {
                CrashStep::Append => {
                    j.append(Timestamp(1_000 + accepted), incident(accepted)).unwrap();
                    accepted += 1;
                }
                CrashStep::TornAppend(keep) => {
                    store.tear_next_write(keep.index(64));
                    prop_assert!(j.append(Timestamp(1_000 + accepted), incident(accepted)).is_err(), "a torn append is refused");
                    store.crash();
                    j = Journal::open(store.clone()).unwrap();
                }
                CrashStep::Crash => {
                    store.crash();
                    j = Journal::open(store.clone()).unwrap();
                }
            }
            prop_assert_eq!(j.ledger().last_seq, accepted);
            prop_assert_eq!(Journal::open(store.clone()).unwrap().ledger().last_seq, accepted);
        }
    }
}

/// The properties whose histories compact (D14, J8, J9), at the daemon's
/// default journal size (64 MiB, `DEFAULT_CAPACITY`), a few cases each.
/// `cargo test --release -p planarian-txn --test journal_props -- --ignored`.
#[test]
#[ignore]
fn at_the_default_journal_size() {
    STORE.with(|s| s.set(planarian_txn::store::DEFAULT_CAPACITY));
    CASES.with(|c| c.set(Some(4)));
    holds_are_the_last_event_per_unit();
    a_damaged_checkpoint_is_integrity();
    an_accepted_append_survives_any_crash();
}
