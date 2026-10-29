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
        Actor::user(ADMIN),
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
    let r =
        d.prepare(txn(Transition::Resolve { txn: f, resolution: Resolution::AsReverted }, Actor::user(ADMIN))).unwrap();
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
    assert_eq!(full_ledger.overrides.len(), 1);
    assert_eq!(full_ledger.overrides[0].until, Until::Explicit);
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

// ---------- I18: the hash chain ----------

fn filled(n: usize) -> (MemStore, Journal<MemStore>) {
    let store = MemStore::new(1 << 20);
    let mut j = Journal::open(store.clone()).unwrap();
    for e in history().into_iter().take(n) {
        j.append(e.at, e.record).unwrap();
    }
    (store, j)
}

/// Change one digit of the record's timestamp, keeping its length.
fn edit_at(p: &mut Vec<u8>) {
    #![allow(clippy::ptr_arg)] // the `tamper` callback type
    let s = String::from_utf8(p.clone()).unwrap();
    let i = s.find("\"at\":").unwrap() + 5;
    p[i] = if p[i] == b'9' { b'1' } else { p[i] + 1 };
}

#[test]
fn edited_record_breaks_the_chain_on_read() {
    let (store, j) = filled(10);
    drop(j);
    assert!(planarian_txn::journal::tamper(&store, 4, edit_at).unwrap());
    match Journal::open(store.clone()) {
        Err(JournalError::Integrity(why)) => assert!(why.contains("record 6"), "{why}"),
        other => panic!("{:?}", other.map(|j| j.ledger().last_seq)),
    }
    // Nothing was truncated: the evidence stays.
    assert!(planarian_txn::journal::tamper(&store, 9, |_| {}).unwrap(), "record 10 still there");
}

#[test]
fn damaged_middle_record_is_not_a_torn_tail() {
    let (store, j) = filled(10);
    // A byte a quarter of the way in: inside an early record, with later ones after it.
    let off = j.offset() / 4;
    drop(j);
    let mut b = store.read_at(off, 1).unwrap();
    b[0] ^= 0x40;
    store.write_at(off, &b).unwrap();
    assert!(matches!(Journal::open(store.clone()), Err(JournalError::Integrity(_))));
}

#[test]
fn torn_tail_is_still_truncated() {
    let (store, mut j) = filled(5);
    store.tear_next_write(20);
    assert!(j.append(Timestamp(9), Record::LiveTested(None)).is_err());
    let j = Journal::open(store).unwrap();
    assert_eq!(j.ledger().last_seq, 5);
}

#[test]
fn edit_after_read_is_caught_by_verify_chain() {
    let (store, mut j) = filled(8);
    j.verify_chain().unwrap();
    assert!(planarian_txn::journal::tamper(&store, 2, edit_at).unwrap());
    assert!(matches!(j.verify_chain(), Err(JournalError::Integrity(_))));
}

#[test]
fn compaction_carries_the_chain_head() {
    let (store, mut j) = filled(6);
    let head = j.head();
    j.compact().unwrap();
    j.append(Timestamp(1), Record::LiveTested(None)).unwrap();
    let mut k = Journal::open(store.clone()).unwrap();
    assert_eq!(k.ledger().last_seq, 7);
    assert_ne!(k.head(), head);
    k.verify_chain().unwrap();
    // Editing the record after the checkpoint is detected against the checkpoint's head.
    j.append(Timestamp(2), Record::LiveTested(None)).unwrap();
    assert!(planarian_txn::journal::tamper(&store, 0, edit_at).unwrap());
    assert!(matches!(Journal::open(store), Err(JournalError::Integrity(_))));
}

#[test]
fn format_one_journal_is_refused_not_truncated() {
    let store = MemStore::new(1 << 16);
    // A format-1 frame: len | crc32c(seq | payload) | seq | payload.
    let payload = br#"{"seq":1}"#;
    let mut body = 1u64.to_le_bytes().to_vec();
    body.extend_from_slice(payload);
    let mut f = (payload.len() as u32).to_le_bytes().to_vec();
    f.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    f.extend_from_slice(&body);
    store.write_at(0, &f).unwrap();
    assert!(matches!(Journal::open(store.clone()), Err(JournalError::Legacy)));
    assert_eq!(store.read_at(0, f.len()).unwrap(), f, "left as found");
}

/// §12c: an interlock set through the sentinel (the journal was full on the
/// recovery path) is cleared by `planarian resolve` and stays cleared across
/// restarts, with or without a compaction in between; and the journal opens.
#[test]
fn sentinel_interlock_is_resolved_for_good() {
    for compact in [false, true] {
        let s = MemStore::new(1 << 16);
        s.write_sentinel(b"RecoveryFailed txn=3 journal full").unwrap();
        let mut j = Journal::open(s.clone()).unwrap();
        assert!(j.ledger().interlocked());
        if compact {
            j.compact().unwrap();
        }
        j.append(
            Timestamp(1),
            Record::Resolved { txn: TxnId(3), resolution: Resolution::AsReverted, by: Actor::user(0) },
        )
        .unwrap();
        assert!(!j.ledger().interlocked());
        let again = Journal::open(s.clone()).unwrap_or_else(|e| panic!("compact={compact}: {e:?}"));
        assert!(!again.ledger().interlocked(), "compact={compact}: the interlock came back");
        // And after a later compaction too (the sentinel is cleared there).
        let mut again = again;
        again.compact().unwrap();
        let third = Journal::open(s.clone()).unwrap();
        assert!(!third.ledger().interlocked(), "compact={compact}: back after a compaction");
    }
}

/// A sentinel whose Resolved is in the log but which was not yet cleared (a
/// crash in between) replays in order: the journal opens, not interlocked.
#[test]
fn sentinel_resolved_before_clearing_replays_in_order() {
    let s = MemStore::new(1 << 16);
    s.write_sentinel(b"RecoveryFailed txn=3 journal full").unwrap();
    let mut j = Journal::open(s.clone()).unwrap();
    j.append(Timestamp(1), Record::Resolved { txn: TxnId(3), resolution: Resolution::AsReverted, by: Actor::user(0) })
        .unwrap();
    // The crash: the sentinel is back on disk.
    s.write_sentinel(b"RecoveryFailed txn=3 journal full").unwrap();
    let again = Journal::open(s.clone()).unwrap();
    assert!(!again.ledger().interlocked());
}

/// I18: zeroing a middle record's header does not silently drop it and the
/// records after it.
#[test]
fn erased_middle_header_is_an_integrity_failure() {
    let s = MemStore::new(1 << 16);
    let mut j = Journal::open(s.clone()).unwrap();
    let mut offs = vec![];
    for i in 0..5u64 {
        offs.push(j.offset());
        j.append(Timestamp(i), Record::KnownGood(GenerationId(i + 1))).unwrap();
    }
    drop(j);
    s.write_at(offs[2], &[0u8; 16]).unwrap();
    assert!(matches!(Journal::open(s), Err(JournalError::Integrity(_))));
}
