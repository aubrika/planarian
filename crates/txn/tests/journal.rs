//! Journal format, torn writes, compaction (§12c).

mod common;

use common::*;
use planarian_schema::*;
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::{Entry, Record};
use planarian_txn::store::{FileStore, MemStore, Store};

/// A realistic history: commits, a revert, a suppression, an incident, a
/// RecoveryFailed and its resolution.
fn history() -> Vec<Entry> {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let a = d.prepare(good_change()).unwrap();
    d.run(a).unwrap();
    let t = txn(
        Transition::StopAndSuppress { unit: web(), until: Until::Explicit, reason: "working on it".into() },
        Actor::User { uid: ADMIN },
    );
    let s = d.prepare(t).unwrap();
    d.run(s).unwrap();
    d.journal
        .append(
            Timestamp(2_000_000),
            Record::Incident(Incident {
                id: IncidentId(7),
                kind: IncidentKind::Repair,
                target: UnitId::service("gym-flap"),
                divergence: (DesiredStatus::Running, UnitStatus::Failed(Reason::ExitCode(1))),
                opened: Timestamp(1_000_000),
                attempts: vec![],
                budget_left: 0,
                state: IncidentState::Cooldown { until: Timestamp(9_000_000) },
                backoff: Millis::secs(300),
                next_attempt: Timestamp(9_000_000),
                regressions: 0,
            }),
        )
        .unwrap();
    rig.w().env_fault = true;
    let mut bad = change("listen-address");
    bad.base = G2;
    bad.revert_to = G2;
    bad.candidate = Some((G1, path(G1)));
    bad.base_override = Some(cand_override());
    bad.candidate_override = Some(base_override());
    let f = d.prepare(bad).unwrap();
    assert_eq!(d.run(f).unwrap(), TxnState::RecoveryFailed);
    rig.w().env_fault = false;
    let r = d
        .prepare(txn(Transition::Resolve { txn: f, resolution: Resolution::AsReverted }, Actor::User { uid: ADMIN }))
        .unwrap();
    d.run(r).unwrap();
    d.journal.segment().unwrap()
}

#[test]
fn replay_from_checkpoint_equals_full_replay() {
    let entries = history();
    assert!(entries.len() > 30);

    let full = MemStore::new(1 << 20);
    let mut j = Journal::open(full.clone()).unwrap();
    for e in &entries {
        j.append(e.at, e.record.clone()).unwrap();
    }
    let full_ledger = Journal::open(full).unwrap().ledger().clone();

    for every in [1, 2, 3, 7, 13] {
        let compacting = MemStore::new(1 << 20);
        let mut j = Journal::open(compacting.clone()).unwrap();
        for (i, e) in entries.iter().enumerate() {
            j.append(e.at, e.record.clone()).unwrap();
            if i % every == every - 1 {
                j.compact().unwrap();
            }
        }
        assert_eq!(j.ledger(), &full_ledger, "live ledger, compacting every {every}");
        let reopened = Journal::open(compacting).unwrap();
        assert_eq!(reopened.ledger(), &full_ledger, "reopened, compacting every {every}");
    }

    // The checkpointed state includes what §12c requires to survive.
    assert_eq!(full_ledger.suppressions.len(), 1);
    assert_eq!(full_ledger.suppressions[0].until, Until::Explicit);
    assert_eq!(full_ledger.incidents[&IncidentId(7)].budget_left, 0);
    assert!(!full_ledger.interlocked(), "resolved");
    assert_eq!(full_ledger.live_tested, Some(G2));
}

#[test]
fn torn_record_is_truncated_never_interpreted() {
    let entries = history();
    let store = MemStore::new(1 << 20);
    let mut j = Journal::open(store.clone()).unwrap();
    for e in &entries[..10] {
        j.append(e.at, e.record.clone()).unwrap();
    }
    let before = j.ledger().clone();
    store.tear_next_write(20);
    assert!(j.append(entries[10].at, entries[10].record.clone()).is_err());
    drop(j);

    let mut j = Journal::open(store.clone()).unwrap();
    assert_eq!(j.ledger(), &before, "the torn record is not applied");
    // Appending continues at the torn position, and a reopen agrees.
    for e in &entries[10..20] {
        j.append(e.at, e.record.clone()).unwrap();
    }
    let after = j.ledger().clone();
    assert_eq!(Journal::open(store).unwrap().ledger(), &after);
}

#[test]
fn interrupted_checkpoint_keeps_the_old_one() {
    let entries = history();
    let store = MemStore::new(1 << 20);
    let mut j = Journal::open(store.clone()).unwrap();
    for e in &entries[..10] {
        j.append(e.at, e.record.clone()).unwrap();
    }
    j.compact().unwrap();
    for e in &entries[10..20] {
        j.append(e.at, e.record.clone()).unwrap();
    }
    let ledger = j.ledger().clone();
    store.fail_next_checkpoint();
    assert!(j.compact().is_err());
    assert_eq!(Journal::open(store).unwrap().ledger(), &ledger);
}

#[test]
fn crash_between_checkpoint_and_log_reset() {
    let entries = history();
    let store = MemStore::new(1 << 20);
    let mut j = Journal::open(store.clone()).unwrap();
    for e in &entries[..10] {
        j.append(e.at, e.record.clone()).unwrap();
    }
    let ledger = j.ledger().clone();
    // The checkpoint lands; the write that resets the log does not.
    store.tear_next_write(0);
    assert!(j.compact().is_err());
    drop(j);
    let mut j = Journal::open(store.clone()).unwrap();
    assert_eq!(j.ledger(), &ledger, "old segment skipped, nothing applied twice");
    for e in &entries[10..15] {
        j.append(e.at, e.record.clone()).unwrap();
    }
    let ledger = j.ledger().clone();
    assert_eq!(Journal::open(store).unwrap().ledger(), &ledger);
}

#[test]
fn another_handle_follows_a_compaction() {
    let entries = history();
    let store = MemStore::new(1 << 20);
    let mut a = Journal::open(store.clone()).unwrap();
    let mut b = Journal::open(store.clone()).unwrap();
    for e in &entries[..10] {
        a.append(e.at, e.record.clone()).unwrap();
    }
    a.compact().unwrap();
    for e in &entries[10..15] {
        a.append(e.at, e.record.clone()).unwrap();
    }
    // b never saw any of this; it catches up through the checkpoint and the new segment.
    b.append(entries[15].at, entries[15].record.clone()).unwrap();
    for e in &entries[16..20] {
        a.append(e.at, e.record.clone()).unwrap();
    }
    assert_eq!(a.ledger().last_seq, 20);
    assert_eq!(b.sync_ledger().unwrap(), a.ledger());
}

#[test]
fn compaction_threshold_and_full() {
    let entries = history();
    let store = MemStore::new(8 * 1024);
    let mut j = Journal::open(store).unwrap();
    let mut hit_threshold = false;
    for e in &entries {
        match j.append(e.at, e.record.clone()) {
            Ok(_) => hit_threshold |= j.needs_compaction(),
            Err(JournalError::Full) => break,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(hit_threshold, "75% is reported before the journal is full");
    j.compact().unwrap();
    assert!(!j.needs_compaction());
}

#[test]
fn file_store_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let jdir = dir.path().join("journal");
    let tdir = dir.path().join("txn");
    let entries = history();
    let ledger = {
        let store = FileStore::open(&jdir, &tdir, 1 << 20).unwrap();
        let mut j = Journal::open(store).unwrap();
        for e in &entries[..12] {
            j.append(e.at, e.record.clone()).unwrap();
        }
        j.compact().unwrap();
        for e in &entries[12..25] {
            j.append(e.at, e.record.clone()).unwrap();
        }
        j.ledger().clone()
    };
    assert_eq!(std::fs::metadata(jdir.join("journal")).unwrap().len(), 1 << 20, "preallocated");

    // Garbage after the last record is a torn tail: ignored, then truncated.
    {
        let j = Journal::open(FileStore::open(&jdir, &tdir, 1 << 20).unwrap()).unwrap();
        j.store().write_at(j.offset(), b"\x30\0\0\0garbage that is not a frame").unwrap();
    }
    let mut j = Journal::open(FileStore::open(&jdir, &tdir, 1 << 20).unwrap()).unwrap();
    assert_eq!(j.ledger(), &ledger);
    j.append(entries[25].at, entries[25].record.clone()).unwrap();
    let ledger = j.ledger().clone();
    drop(j);
    assert_eq!(Journal::open(FileStore::open(&jdir, &tdir, 1 << 20).unwrap()).unwrap().ledger(), &ledger);

    let store = FileStore::open(&jdir, &tdir, 1 << 20).unwrap();
    store.set_fence(TxnId(3), 2).unwrap();
    assert_eq!(store.fence(TxnId(3)).unwrap(), Some(2));
    assert_eq!(store.fence(TxnId(4)).unwrap(), None);
    assert_eq!(store.read_sentinel().unwrap(), None);
    store.write_sentinel(b"RecoveryFailed txn=3 test").unwrap();
    let j = Journal::open(store).unwrap();
    assert!(j.ledger().interlock.contains_key(&TxnId(3)));
}

/// A checkpoint is checked against the ledger invariant before use; two
/// generation changes in flight at once (I6) is refused.
#[test]
fn ledger_invariant_checked_on_load() {
    use planarian_txn::ledger::{Ledger, LiveTxn};
    let live = |id: u64, state: TxnState| {
        let mut t = good_change();
        t.id = TxnId(id);
        t.lease.txn = TxnId(id);
        t.state = state;
        (TxnId(id), LiveTxn { txn: t, ops: vec![], path: vec![], why: String::new() })
    };
    let mut l = Ledger { next_txn: 3, ..Ledger::default() };
    l.live.entries = vec![live(1, TxnState::Activating), live(2, TxnState::Prepared)];
    assert!(l.well_formed());
    l.live.entries[1] = live(2, TxnState::Checking);
    assert!(!l.well_formed(), "two generation changes in flight");
    l.live.entries[1] = live(1, TxnState::Prepared);
    assert!(!l.well_formed(), "duplicate id");
    l.live.entries = vec![live(5, TxnState::Prepared)];
    assert!(!l.well_formed(), "id not yet issued");

    // The vector-backed maps serialize as the JSON objects they replaced.
    l.live.entries = vec![live(1, TxnState::Prepared)];
    let json = serde_json::to_value(&l).unwrap();
    assert!(json["live"]["1"].is_object());
    assert_eq!(serde_json::from_value::<Ledger>(json).unwrap(), l);
}
