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
    /// The scan as it was before it read a body only for a header that
    /// could be the next record (the reference for `scan_outcomes_are_unchanged`).
    pub(super) static OLD_SCAN: Cell<bool> = const { Cell::new(false) };
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

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    /// I18 and §12c *Format*, after a compaction or not: damage anywhere in
    /// any record but the last (header, chain hash or payload, its first
    /// bytes included, so it fails `could_follow` itself) is Integrity: a
    /// later intact record is still found, so nothing is truncated as a torn
    /// tail. Damage to the last record is the torn-tail case: truncated to
    /// the record before it (or Integrity).
    #[test]
    fn any_damage_before_the_last_record_is_integrity(
        compact in any::<bool>(),
        n in 2usize..8,
        which in any::<prop::sample::Index>(),
        pos in any::<prop::sample::Index>(),
        x in 1u8..=255,
    ) {
        let capacity = 64 << 10;
        let store = MemStore::new(capacity);
        let mut j = Journal::open(store.clone()).unwrap();
        let mut i = 0;
        if compact {
            while !j.needs_compaction() {
                append(&mut j, i).unwrap();
                i += 1;
            }
            j.compact().unwrap();
        }
        // Each new record's offset and size in the log (it starts at 0).
        let mut records = Vec::new();
        let mut off = 0u64;
        for _ in 0..n {
            let e = append(&mut j, i).unwrap();
            i += 1;
            let size = (HEADER + PREV + serde_json::to_vec(&e).unwrap().len()) as u64;
            records.push((off, size));
            off += size;
        }
        let last = j.ledger().last_seq;
        drop(j);
        let k = which.index(n);
        let (o, size) = records[k];
        let at = o + pos.index(size as usize) as u64;
        let b = store.read_at(at, 1).unwrap()[0];
        store.write_at(at, &[b ^ x]).unwrap();
        let r = Journal::open(store.clone());
        if k + 1 < n {
            prop_assert!(
                matches!(r, Err(JournalError::Integrity(_))),
                "record {} of {} damaged at byte {} of {} (compacted: {}): {:?}",
                k, n, at - o, size, compact, r.as_ref().map(|j| j.ledger().last_seq)
            );
        } else {
            match r {
                Ok(j) => prop_assert_eq!(j.ledger().last_seq, last - 1),
                Err(JournalError::Integrity(_)) => {}
                Err(e) => prop_assert!(false, "the last record damaged gave {:?}", e),
            }
        }
    }
}

/// A record of one of several kinds, of any size from tiny to a few KiB.
fn record(kind: u8, n: u64, size: usize) -> Record {
    let unit = planarian_schema::UnitId::service(&format!("u{}-{}", n % 7, "x".repeat(size)));
    match kind % 6 {
        0 => Record::KnownGood(GenerationId(n + 1)),
        1 => Record::LiveTested(Some(GenerationId(n + 1))),
        2 => Record::HoldApplied { unit, by: crate::ledger::HoldBy::Daemon },
        3 => Record::HoldLifted { unit, reason: "y".repeat(size) },
        4 => Record::AgentStarted { name: "a".repeat(size.max(1)), instance: [n as u8; 16], by: 1000 },
        _ => Record::TokenUsed { nonce: [n as u8; 16], expires: Timestamp(n), approver: 0, txn: 0 },
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// The other side of `could_follow`: every frame `append` writes passes
    /// it, for any record kind and size and before or after compactions. So
    /// the search for a later record never skips one the journal wrote (I18:
    /// a damaged record before it stays Integrity). A change to the frame or
    /// the payload encoding has to keep this green.
    #[test]
    fn every_appended_frame_could_follow(
        ops in proptest::collection::vec((0u8..6, 0usize..3000, proptest::bool::weighted(0.05)), 1..200)
    ) {
        let capacity = 256 << 10;
        let store = MemStore::new(capacity);
        let mut j = Journal::open(store.clone()).unwrap();
        for (n, (kind, size, compact)) in ops.into_iter().enumerate() {
            if compact || j.needs_compaction() {
                j.compact().unwrap();
            }
            let at = j.offset();
            let rec = record(kind, n as u64, size);
            let e = match j.append(Timestamp(n as u64), rec) {
                Ok(e) => e,
                // A record the ledger refuses here (e.g. lifting no hold) or
                // one too big for what is left: not a frame written.
                Err(JournalError::Ledger(_) | JournalError::Full) => continue,
                Err(e) => panic!("{e:?}"),
            };
            let bytes = store.read_at(at, (capacity - at) as usize).unwrap();
            prop_assert!(
                could_follow(&bytes, e.seq - 1, capacity),
                "the frame of record {} (kind {}, {} bytes asked) does not pass could_follow",
                e.seq, kind, size
            );
        }
    }
}

// ---- The scan reads a body only for a header that could be the next record.

/// A MemStore that counts the log bytes read through it.
#[derive(Clone)]
struct Counting(MemStore, std::sync::Arc<std::sync::atomic::AtomicU64>);

impl Counting {
    fn take(&self) -> u64 {
        self.1.swap(0, std::sync::atomic::Ordering::Relaxed)
    }
}

impl Store for Counting {
    type Guard = <MemStore as Store>::Guard;
    fn lock(&self) -> io::Result<Self::Guard> {
        self.0.lock()
    }
    fn capacity(&self) -> u64 {
        self.0.capacity()
    }
    fn read_at(&self, off: u64, len: usize) -> io::Result<Vec<u8>> {
        let b = self.0.read_at(off, len)?;
        self.1.fetch_add(b.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(b)
    }
    fn write_at(&self, off: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.write_at(off, bytes)
    }
    fn sync(&self) -> io::Result<()> {
        self.0.sync()
    }
    fn read_checkpoint(&self) -> io::Result<Option<Vec<u8>>> {
        self.0.read_checkpoint()
    }
    fn write_checkpoint(&self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_checkpoint(bytes)
    }
    fn read_sentinel(&self) -> io::Result<Option<Vec<u8>>> {
        self.0.read_sentinel()
    }
    fn write_sentinel(&self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_sentinel(bytes)
    }
    fn fence(&self, txn: TxnId) -> io::Result<Option<u64>> {
        self.0.fence(txn)
    }
    fn set_fence(&self, txn: TxnId, epoch: u64) -> io::Result<()> {
        self.0.set_fence(txn, epoch)
    }
    fn create_fence(&self, txn: TxnId, epoch: u64) -> io::Result<()> {
        self.0.create_fence(txn, epoch)
    }
    fn forget_fences<F: Fn(TxnId) -> bool>(&self, keep: F) -> io::Result<Vec<TxnId>> {
        self.0.forget_fences(keep)
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// After any history with compactions, each append reads about its own
    /// record, and each catch-up by another handle about what was appended
    /// since; only the first catch-up after a compaction reads the store
    /// once (the reload). Before, both read HEADER + len at the tail, len
    /// being whatever the leftovers there claim: the rest of the store, on
    /// every append and catch-up until the log overwrote them.
    #[test]
    fn appends_and_catch_ups_read_what_was_appended(
        rounds in proptest::collection::vec((1u64..80, proptest::bool::weighted(0.25)), 1..10)
    ) {
        let capacity = 128 << 10;
        let mem = MemStore::new(capacity);
        let wc = Counting(mem.clone(), Default::default());
        let rc = Counting(mem.clone(), Default::default());
        let mut w = Journal::open(wc.clone()).unwrap();
        let mut r = Journal::open(rc.clone()).unwrap();
        let mut i = 0;
        for (n, compact) in rounds {
            let before = w.offset();
            let mut compacted = false;
            for _ in 0..n {
                if w.needs_compaction() {
                    w.compact().unwrap();
                    compacted = true;
                }
                wc.take();
                let at = w.offset();
                w.append(Timestamp(i), Record::KnownGood(GenerationId(i + 1))).unwrap();
                i += 1;
                let size = w.offset() - at;
                let read = wc.take();
                prop_assert!(read <= 2 * size + 256, "an append of {} bytes read {}", size, read);
            }
            if compact {
                w.compact().unwrap();
                compacted = true;
            }
            let appended = if compacted { w.offset() } else { w.offset() - before };
            rc.take();
            r.sync_ledger().unwrap();
            prop_assert_eq!(r.ledger().last_seq, w.ledger().last_seq);
            let read = rc.take();
            // Each frame's header is read twice (to size it, then whole).
            let bound = 2 * appended + 1024 + if compacted { capacity } else { 0 };
            prop_assert!(read <= bound, "a catch-up read {} for {} appended (compacted: {})", read, appended, compacted);
        }
    }
}

/// A copy of a store's log and checkpoint.
fn copy(m: &MemStore) -> MemStore {
    let c = MemStore::new(m.capacity());
    c.write_at(0, &m.read_at(0, m.capacity() as usize).unwrap()).unwrap();
    if let Some(cp) = m.read_checkpoint().unwrap() {
        c.write_checkpoint(&cp).unwrap();
    }
    c
}

/// What an open did: its ledger's last seq and head, or the error's kind
/// and message; and the log bytes it left (a torn tail's header is zeroed).
fn outcome(m: &MemStore, old: bool) -> (Result<(u64, Hash), String>, Vec<u8>) {
    let c = copy(m);
    OLD_SCAN.with(|o| o.set(old));
    let r = Journal::open(c.clone()).map(|j| (j.ledger().last_seq, j.head())).map_err(|e| format!("{e:?}"));
    OLD_SCAN.with(|o| o.set(false));
    (r, c.read_at(0, c.capacity() as usize).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    /// The new scan accepts, truncates and reports Integrity exactly as the
    /// old one, on any store: records, compactions (leftovers past the
    /// tail), a crash between a checkpoint and the log's reset (the
    /// skipping case), and damage anywhere. Same ledger and head, same
    /// error, same bytes left on disk.
    #[test]
    fn scan_outcomes_are_unchanged(
        before in 0u64..300,
        compact in any::<bool>(),
        unreset in any::<bool>(),
        after in 0u64..40,
        damage in proptest::collection::vec((any::<prop::sample::Index>(), 1u8..=255), 0..3),
    ) {
        let capacity = 32 << 10;
        let store = MemStore::new(capacity);
        let mut j = Journal::open(store.clone()).unwrap();
        let mut i = 0;
        for _ in 0..before {
            if j.needs_compaction() {
                j.compact().unwrap();
            }
            append(&mut j, i).unwrap();
            i += 1;
        }
        if compact {
            if unreset {
                // A crash after the checkpoint, before the log restarts at 0:
                // the old segment is still there, at or below its seq.
                let payload = serde_json::to_vec(j.ledger()).unwrap();
                store.write_checkpoint(&frame(j.ledger().last_seq, &j.head(), &payload)).unwrap();
            } else {
                j.compact().unwrap();
            }
        }
        if !(compact && unreset) {
            for _ in 0..after {
                if j.needs_compaction() {
                    break;
                }
                append(&mut j, i).unwrap();
                i += 1;
            }
        }
        drop(j);
        let used = capacity as usize;
        for (at, x) in damage {
            let at = at.index(used) as u64;
            let b = store.read_at(at, 1).unwrap()[0];
            store.write_at(at, &[b ^ x]).unwrap();
        }
        let old = outcome(&store, true);
        let new = outcome(&store, false);
        prop_assert_eq!(&new.0, &old.0);
        prop_assert!(new.1 == old.1, "the bytes left on disk differ");
    }
}
