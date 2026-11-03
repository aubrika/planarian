//! The scan's cost (§12c): opening a journal is linear in the store,
//! whatever its history of appends and compactions.

use super::*;
use crate::store::{FileStore, MemStore};
use planarian_schema::GenerationId;
use proptest::prelude::*;
use std::cell::Cell;

thread_local! {
    /// Bytes run through the frame CRC on this thread (`crc`).
    pub(super) static CRC_BYTES: Cell<u64> = const { Cell::new(0) };
}

fn crc_bytes<R>(f: impl FnOnce() -> R) -> (R, u64) {
    let before = CRC_BYTES.with(Cell::get);
    let r = f();
    (r, CRC_BYTES.with(Cell::get) - before)
}

/// A record whose payload grows with `pad` (a longer generation number is
/// not enough; a known-good generation is the smallest valid record).
fn append(j: &mut Journal<MemStore>, i: u64) -> Result<Entry, JournalError> {
    j.append(Timestamp(i), Record::KnownGood(GenerationId(i + 1)))
}

#[derive(Clone, Debug)]
enum Op {
    Append(u16),
    Compact,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![4 => (1u16..400).prop_map(Op::Append), 1 => Just(Op::Compact)]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// After any appends and compactions, `Journal::open` CRCs O(capacity)
    /// bytes: each frame in the log once, the checkpoint once, and nothing
    /// for the leftovers past the tail. (Before the header check it CRC'd
    /// the claimed length at every offset of the leftovers: quadratic.)
    #[test]
    fn open_is_linear_in_the_store(ops in proptest::collection::vec(op(), 1..12)) {
        let capacity = 128 << 10;
        let store = MemStore::new(capacity);
        let mut j = Journal::open(store.clone()).unwrap();
        let mut i = 0;
        let mut compacted = false;
        for o in ops {
            match o {
                Op::Append(n) => {
                    for _ in 0..n {
                        if j.needs_compaction() {
                            j.compact().unwrap();
                            compacted = true;
                        }
                        append(&mut j, i).unwrap();
                        i += 1;
                    }
                }
                Op::Compact => {
                    j.compact().unwrap();
                    compacted = true;
                }
            }
        }
        let checkpoint = store.read_checkpoint().unwrap().map_or(0, |c| c.len() as u64);
        let (opened, crcd) = crc_bytes(|| Journal::open(store.clone()));
        let opened = opened.unwrap();
        prop_assert_eq!(opened.ledger().last_seq, j.ledger().last_seq);
        // The log once and the checkpoint twice (loaded, and its seq read
        // again), with one frame's slack.
        prop_assert!(
            crcd <= capacity + 2 * checkpoint + 4096,
            "open CRC'd {} bytes for a {} byte store (checkpoint {}, compacted: {})",
            crcd, capacity, checkpoint, compacted
        );
    }
}

/// The case behind the property, fixed: a store filled, compacted, and
/// written a little past offset 0, so stale frames fill the rest.
#[test]
fn open_after_a_compaction_does_not_search_the_leftovers_quadratically() {
    let capacity = 256 << 10;
    let store = MemStore::new(capacity);
    let mut j = Journal::open(store.clone()).unwrap();
    let mut i = 0;
    while !j.needs_compaction() {
        append(&mut j, i).unwrap();
        i += 1;
    }
    j.compact().unwrap();
    for _ in 0..3 {
        append(&mut j, i).unwrap();
        i += 1;
    }
    let checkpoint = store.read_checkpoint().unwrap().map_or(0, |c| c.len() as u64);
    let (opened, crcd) = crc_bytes(|| Journal::open(store.clone()));
    assert_eq!(opened.unwrap().ledger().last_seq, j.ledger().last_seq);
    assert!(crcd <= capacity + 2 * checkpoint + 4096, "open CRC'd {crcd} bytes for a {capacity} byte store");
}

/// The measurement for the PR: a 64 MiB FileStore filled to compaction,
/// compacted, then a few records. Not a check (wall time); run with
/// `cargo test -p planarian-txn --release -- --ignored --nocapture open_time`.
#[test]
#[ignore]
fn open_time_at_64_mib() {
    let dir = tempfile::tempdir().unwrap();
    let capacity = 64 << 20;
    let store = FileStore::open(dir.path(), &dir.path().join("txn"), capacity).unwrap();
    let mut j = Journal::open(store).unwrap();
    let mut i = 0;
    while !j.needs_compaction() {
        j.append(Timestamp(i), Record::KnownGood(GenerationId(i + 1))).unwrap();
        i += 1;
    }
    j.compact().unwrap();
    for _ in 0..3 {
        j.append(Timestamp(i), Record::KnownGood(GenerationId(i + 1))).unwrap();
        i += 1;
    }
    drop(j);
    for _ in 0..3 {
        let t = std::time::Instant::now();
        let (opened, crcd) =
            crc_bytes(|| Journal::open(FileStore::open(dir.path(), &dir.path().join("txn"), capacity).unwrap()));
        opened.unwrap();
        eprintln!("open_time_at_64_mib: {:?}, {crcd} bytes CRC'd, {i} records", t.elapsed());
    }
}

/// I18 holds after a compaction too: a record in the middle of the new log
/// damaged (its CRC fails) while a later intact record follows is Integrity,
/// not a torn tail; and the leftovers past the tail, all at or below the
/// checkpoint's seq, are never taken for that later record.
#[test]
fn after_a_compaction_a_damaged_middle_record_is_still_integrity() {
    let capacity = 256 << 10;
    let store = MemStore::new(capacity);
    let mut j = Journal::open(store.clone()).unwrap();
    let mut i = 0;
    while !j.needs_compaction() {
        append(&mut j, i).unwrap();
        i += 1;
    }
    j.compact().unwrap();
    let first = append(&mut j, i).unwrap();
    let size = (HEADER + PREV + serde_json::to_vec(&first).unwrap().len()) as u64;
    for k in 1..5 {
        append(&mut j, i + k).unwrap();
    }
    // Only leftovers past the tail: the torn-tail path, no Integrity.
    assert!(Journal::open(store.clone()).is_ok());
    // Damage the second record's payload (its CRC no longer holds).
    let at = size + (HEADER + PREV) as u64 + 2;
    let b = store.read_at(at, 1).unwrap()[0];
    store.write_at(at, &[b ^ 0x20]).unwrap();
    match Journal::open(store.clone()) {
        Err(JournalError::Integrity(m)) => assert!(m.contains("is damaged, but record"), "{m}"),
        Err(e) => panic!("expected Integrity, got {e:?}"),
        Ok(_) => panic!("expected Integrity, got an open journal"),
    }
}
