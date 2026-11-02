//! P21, written from the spec before the change (reviewer's case).
//!
//! §17a lists, among the assumptions the proofs rely on, "the journal's fsync
//! is durable", and the fake must be a second implementation of every such
//! assumption (`fake-assumptions-conformance`, §18.12). §12: the journal is
//! "append-only, write-ahead, fsync'd". For the fake's "Journal fsync is
//! durable" contract to be able to fail, `MemStore` must tell bytes written
//! from bytes synced: a power loss (`MemStore::crash`) keeps exactly what the
//! last `sync` covered.

use planarian_schema::*;
use planarian_txn::journal::Journal;
use planarian_txn::ledger::Record;
use planarian_txn::store::{MemStore, Store};

#[test]
fn a_write_not_yet_synced_is_lost_in_a_crash() {
    let s = MemStore::new(1 << 16);
    let before = s.read_at(0, 4).unwrap();
    s.write_at(0, b"abcd").unwrap();
    assert_eq!(s.read_at(0, 4).unwrap(), b"abcd", "readable before the crash");
    s.crash();
    assert_eq!(s.read_at(0, 4).unwrap(), before, "never synced: gone after the crash");
}

#[test]
fn a_synced_write_survives_a_crash() {
    let s = MemStore::new(1 << 16);
    s.write_at(0, b"abcd").unwrap();
    s.sync().unwrap();
    s.write_at(4, b"efgh").unwrap();
    s.crash();
    assert_eq!(s.read_at(0, 4).unwrap(), b"abcd", "covered by the sync");
    assert_ne!(s.read_at(4, 4).unwrap(), b"efgh", "written after the sync: gone");
}

/// The journal syncs each record it appends (§12 "fsync'd"), so a record the
/// journal accepted survives a crash, and the replay sees it.
#[test]
fn an_appended_record_survives_a_crash() {
    let store = MemStore::new(1 << 20);
    let mut j = Journal::open(store.clone()).expect("open");
    j.append(Timestamp(1), Record::KnownGood(GenerationId(7))).expect("append");
    drop(j);
    store.crash();
    let j = Journal::open(store).expect("replays after the crash");
    assert_eq!(j.ledger().known_good, Some(GenerationId(7)));
}
