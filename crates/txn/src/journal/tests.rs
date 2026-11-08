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
    /// A deliberate bug in the frame reader, for the tests that show the
    /// class tests catch it (`mutants_are_caught`).
    pub(super) static MUTANT: Cell<Mutant> = const { Cell::new(Mutant::None) };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Mutant {
    None,
    /// An intact frame's unsupported class is mistaken for a torn tail.
    InvalidClassIsTorn,
    /// The format-3 class is not part of the hash-chain commitment.
    ClassOutsideChain,
    /// A decisive frame is read as informational: an unknown decisive kind is skipped.
    AnyClassSkips,
    /// An informational frame of a kind this build knows is skipped when it does not parse.
    KnownKindSkips,
    /// An informational frame of an unknown kind is damage, not a skip.
    NoSkip,
    /// Format 2 frames are not read.
    NoFormat2,
    /// `could_follow` knows only the format 2 payload offset.
    CouldFollowFormat2Only,
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
    let size = (HEADER + PREV + 1 + serde_json::to_vec(&first).unwrap().len()) as u64;
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
            let size = (HEADER + PREV + 1 + serde_json::to_vec(&e).unwrap().len()) as u64;
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
                store.write_checkpoint(&frame(j.ledger().last_seq, &j.head(), Class::Decisive, &payload)).unwrap();
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

/// What a catch-up did (`sync_ledger`: `refresh`, then `scan(false)`, or a
/// reload after another handle's compaction): a reader opens `base`'s copy,
/// a writer appends `n` more (compacting at `compact_at`, if any), the
/// damage is applied, and the reader catches up, with the old scan or the
/// new; its ledger's last seq and head or its error, and the bytes left.
fn catch_up_outcome(
    base: &MemStore,
    n: u64,
    compact_at: Option<u64>,
    damage: &[(prop::sample::Index, u8)],
    old: bool,
) -> (Result<(u64, Hash), String>, Vec<u8>) {
    let c = copy(base);
    let mut r = Journal::open(c.clone()).unwrap();
    let mut w = Journal::open(c.clone()).unwrap();
    for k in 0..n {
        if compact_at == Some(k) || w.needs_compaction() {
            w.compact().unwrap();
        }
        append(&mut w, 10_000 + k).unwrap();
    }
    drop(w);
    for (at, x) in damage {
        let at = at.index(c.capacity() as usize) as u64;
        let b = c.read_at(at, 1).unwrap()[0];
        c.write_at(at, &[b ^ x]).unwrap();
    }
    OLD_SCAN.with(|o| o.set(old));
    let res = r.sync_ledger().map(|l| l.last_seq).map(|s| (s, r.head())).map_err(|e| format!("{e:?}"));
    OLD_SCAN.with(|o| o.set(false));
    (res, c.read_at(0, c.capacity() as usize).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    /// The reviewer's (#57): the catch-up path a kept handle runs (the
    /// renewer's, every 20 s; the watchdog's) has the same outcomes with the
    /// new scan as with the old: after appends, a compaction by the other
    /// handle (leftovers past the tail), and damage anywhere. Same ledger
    /// and head, or the same error, and the same bytes left.
    #[test]
    fn catch_up_outcomes_are_unchanged(
        before in 0u64..300,
        n in 0u64..120,
        compact_at in proptest::option::of(0u64..120),
        damage in proptest::collection::vec((any::<prop::sample::Index>(), 1u8..=255), 0..3),
    ) {
        let store = MemStore::new(32 << 10);
        let mut j = Journal::open(store.clone()).unwrap();
        for i in 0..before {
            if j.needs_compaction() {
                j.compact().unwrap();
            }
            append(&mut j, i).unwrap();
        }
        drop(j);
        let old = catch_up_outcome(&store, n, compact_at, &damage, true);
        let new = catch_up_outcome(&store, n, compact_at, &damage, false);
        prop_assert_eq!(&new.0, &old.0);
        prop_assert!(new.1 == old.1, "the bytes left on disk differ");
    }
}

/// `compact_returning_segment` (reviewer, #65): the entries it returns are
/// exactly those its checkpoint replaced, even while another handle (the
/// renewer's `Renew`, the watchdog) appends. `segment()` then `compact()`
/// each take the store lock alone, so an append between them is
/// checkpointed but missing from what was saved.
#[test]
fn a_returned_segment_is_exactly_what_the_checkpoint_replaced() {
    let store = MemStore::new(1 << 20);
    let mut a = Journal::open(store.clone()).unwrap();
    append(&mut a, 0).unwrap();
    let mut b = Journal::open(store.clone()).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let writer = std::thread::spawn(move || {
        let mut i = 1;
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = append(&mut b, i);
            i += 1;
        }
    });
    let mut previous = a.checkpoint_seq;
    let mut failure = None;
    for _ in 0..300 {
        let segment = a.compact_returning_segment().unwrap();
        let replaced = segment.last().map_or(previous, |e| e.seq);
        let contiguous = segment.windows(2).all(|w| w[0].seq + 1 == w[1].seq)
            && segment.first().is_none_or(|e| e.seq == previous + 1);
        if a.checkpoint_seq != replaced || !contiguous {
            failure = Some((a.checkpoint_seq, replaced, segment.len(), previous));
            break;
        }
        previous = a.checkpoint_seq;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    writer.join().unwrap();
    assert!(failure.is_none(), "(checkpoint, last returned, returned, previous) = {failure:?}");
}

/// A MemStore that counts the lock acquisitions, and the store accesses
/// (log, checkpoint) made while no guard is held.
#[derive(Clone)]
struct LockWatch {
    store: MemStore,
    held: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    locks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    bare: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[allow(dead_code)] // field 0 is held for its Drop (the store lock), never read
struct WatchGuard(<MemStore as Store>::Guard, std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for WatchGuard {
    fn drop(&mut self) {
        self.1.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl LockWatch {
    fn new(capacity: u64) -> LockWatch {
        LockWatch {
            store: MemStore::new(capacity),
            held: Default::default(),
            locks: Default::default(),
            bare: Default::default(),
        }
    }

    fn access(&self) {
        if self.held.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            self.bare.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// (lock acquisitions, accesses without the lock) since the last call.
    fn take(&self) -> (usize, usize) {
        let o = std::sync::atomic::Ordering::SeqCst;
        (self.locks.swap(0, o), self.bare.swap(0, o))
    }
}

impl Store for LockWatch {
    type Guard = WatchGuard;
    fn lock(&self) -> io::Result<Self::Guard> {
        let g = self.store.lock()?;
        self.held.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.locks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(WatchGuard(g, self.held.clone()))
    }
    fn capacity(&self) -> u64 {
        self.store.capacity()
    }
    fn read_at(&self, off: u64, len: usize) -> io::Result<Vec<u8>> {
        self.access();
        self.store.read_at(off, len)
    }
    fn write_at(&self, off: u64, bytes: &[u8]) -> io::Result<()> {
        self.access();
        self.store.write_at(off, bytes)
    }
    fn sync(&self) -> io::Result<()> {
        self.store.sync()
    }
    fn read_checkpoint(&self) -> io::Result<Option<Vec<u8>>> {
        self.access();
        self.store.read_checkpoint()
    }
    fn write_checkpoint(&self, bytes: &[u8]) -> io::Result<()> {
        self.access();
        self.store.write_checkpoint(bytes)
    }
    fn read_sentinel(&self) -> io::Result<Option<Vec<u8>>> {
        self.store.read_sentinel()
    }
    fn write_sentinel(&self, bytes: &[u8]) -> io::Result<()> {
        self.store.write_sentinel(bytes)
    }
    fn fence(&self, txn: TxnId) -> io::Result<Option<u64>> {
        self.store.fence(txn)
    }
    fn set_fence(&self, txn: TxnId, epoch: u64) -> io::Result<()> {
        self.store.set_fence(txn, epoch)
    }
    fn create_fence(&self, txn: TxnId, epoch: u64) -> io::Result<()> {
        self.store.create_fence(txn, epoch)
    }
    fn forget_fences<F: Fn(TxnId) -> bool>(&self, keep: F) -> io::Result<Vec<TxnId>> {
        self.store.forget_fences(keep)
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// The stress above can only fail by luck. This is the invariant it
    /// stands for, with no thread: `compact_returning_segment` reads the log
    /// and writes the checkpoint under one acquisition of the store lock,
    /// held throughout (every log and checkpoint access happens while a
    /// guard is live), whatever the journal holds, with or without a second
    /// handle's appends not yet seen; and what it returns is exactly the
    /// entries since the last checkpoint, the second handle's included.
    #[test]
    fn compact_returning_segment_reads_and_checkpoints_under_one_lock(
        rounds in proptest::collection::vec((0u8..6, 0u8..6), 1..8)
    ) {
        let watch = LockWatch::new(1 << 20);
        let mut a = Journal::open(watch.clone()).unwrap();
        let mut b = Journal::open(watch.clone()).unwrap();
        let mut seq = 0u64;
        let mut since: Vec<u64> = vec![];
        for (mine, theirs) in rounds {
            let app = |j: &mut Journal<LockWatch>, i: u64| j.append(Timestamp(i), Record::KnownGood(GenerationId(i + 1))).map(|e| e.seq);
            for _ in 0..mine {
                seq += 1;
                since.push(app(&mut a, seq).unwrap());
            }
            for _ in 0..theirs {
                seq += 1;
                since.push(app(&mut b, seq).unwrap());
            }
            watch.take();
            let segment = a.compact_returning_segment().unwrap();
            let (locks, bare) = watch.take();
            prop_assert_eq!(locks, 1, "one acquisition for the read and the checkpoint");
            prop_assert_eq!(bare, 0, "store accessed without the lock held");
            prop_assert_eq!(segment.iter().map(|e| e.seq).collect::<Vec<_>>(), since.clone(), "exactly what the checkpoint replaced");
            since.clear();
        }
    }
}

// ---- Record classes (frame format 3) and format 2 frames.

/// One log entry, as the test writes it.
#[derive(Clone, Debug)]
enum Item {
    /// A known record, in a format 3 frame.
    Known3(u64),
    /// A known record, in a format 2 frame.
    Known2(u64),
    /// An informational record of a kind this build does not know, format 3.
    Unknown(u8),
}

/// What follows the items, and must be refused.
#[derive(Clone, Debug, PartialEq)]
enum Last {
    Nothing,
    /// An unknown kind in a decisive format 3 frame.
    UnknownDecisive,
    /// An unknown kind in a format 2 frame.
    UnknownFormat2,
    /// A known kind whose payload does not parse, in an informational frame.
    BrokenKnownInformational,
}

fn items() -> impl Strategy<Value = (Vec<Item>, Last)> {
    let item = prop_oneof![
        3 => (0u64..50).prop_map(Item::Known3),
        2 => (0u64..50).prop_map(Item::Known2),
        3 => (0u8..5).prop_map(Item::Unknown),
    ];
    let last = prop_oneof![
        2 => Just(Last::Nothing),
        1 => Just(Last::UnknownDecisive),
        1 => Just(Last::UnknownFormat2),
        1 => Just(Last::BrokenKnownInformational),
    ];
    (proptest::collection::vec(item, 1..24), last)
}

/// An entry's JSON with its record's kind renamed: a record from a newer build.
fn newer(seq: u64, n: u64, kind: &str) -> Vec<u8> {
    let e = Entry { seq, at: Timestamp(n), record: Record::KnownGood(GenerationId(n + 1)) };
    String::from_utf8(serde_json::to_vec(&e).unwrap()).unwrap().replace("KnownGood", kind).into_bytes()
}

/// Write `items` into a fresh store as a hand-built, chained log.
fn build(items: &[Item], last: &Last, capacity: u64) -> (MemStore, Hash, Option<GenerationId>) {
    let store = MemStore::new(capacity);
    let (mut off, mut head, mut known) = (0u64, Hash::ZERO, None);
    let put = |bytes: Vec<u8>, off: &mut u64| {
        store.write_at(*off, &bytes).unwrap();
        *off += bytes.len() as u64;
    };
    for (i, it) in items.iter().enumerate() {
        let seq = i as u64 + 1;
        let (bytes, _payload) = match it {
            Item::Known3(n) | Item::Known2(n) => {
                let e = Entry { seq, at: Timestamp(*n), record: Record::KnownGood(GenerationId(n + 1)) };
                known = Some(GenerationId(n + 1));
                let payload = serde_json::to_vec(&e).unwrap();
                let v3 = matches!(it, Item::Known3(_));
                (
                    if v3 { frame(seq, &head, Class::Decisive, &payload) } else { frame_v2(seq, &head, &payload) },
                    payload,
                )
            }
            Item::Unknown(k) => {
                let payload = newer(seq, 0, &format!("Frob{k}"));
                (frame(seq, &head, Class::Informational, &payload), payload)
            }
        };
        let f = unframe(&bytes).expect("test writes an intact frame");
        head = frame_head(&f);
        put(bytes, &mut off);
    }
    let seq = items.len() as u64 + 1;
    match last {
        Last::Nothing => {}
        Last::UnknownDecisive => put(frame(seq, &head, Class::Decisive, &newer(seq, 0, "Frob9")), &mut off),
        Last::UnknownFormat2 => put(frame_v2(seq, &head, &newer(seq, 0, "Frob9")), &mut off),
        Last::BrokenKnownInformational => {
            let p = newer(seq, 0, "KnownGood");
            let p = String::from_utf8(p).unwrap().replace("{\"KnownGood\":1}", "{\"KnownGood\":\"x\"}").into_bytes();
            put(frame(seq, &head, Class::Informational, &p), &mut off);
        }
    }
    (store, head, known)
}

/// The class property, as one check so the mutants can run it too: a log of
/// known records (either format) and informational records of unknown kinds opens
/// to the ledger of the known ones, with every seq counted and the chain
/// carried through the skipped ones, then takes an append that a reopen
/// reads; and what `last` adds is Integrity, with nothing truncated.
fn classes_hold(items: &[Item], last: &Last) -> Result<(), String> {
    let (store, head, known) = build(items, last, 64 << 10);
    read_classes(store, head, known, items.len() as u64, last)
}

/// Only the consumer runs under a mutant. In particular, the fixture's
/// format-2 frames must be decoded with the clean reader while constructing
/// their expected chain heads, before the NoFormat2 mutant is enabled.
fn read_classes(store: MemStore, head: Hash, known: Option<GenerationId>, n: u64, last: &Last) -> Result<(), String> {
    let before = store.read_at(0, 64 << 10).unwrap();
    let opened = Journal::open(store.clone());
    if *last != Last::Nothing {
        return match opened {
            Err(JournalError::Integrity(_)) if store.read_at(0, 64 << 10).unwrap() == before => Ok(()),
            Err(JournalError::Integrity(_)) => Err(format!("{last:?} was Integrity but the log was changed")),
            Ok(_) => Err(format!("{last:?} opened")),
            Err(e) => Err(format!("{last:?} gave {e:?}, not Integrity")),
        };
    }
    let mut j = opened.map_err(|e| format!("{e:?}"))?;
    if j.ledger().last_seq != n {
        return Err(format!("last_seq {} for {n} records", j.ledger().last_seq));
    }
    if j.head() != head {
        return Err("the chain did not carry through the records".into());
    }
    if j.ledger().known_good != known {
        return Err(format!("known_good {:?}, expected {known:?}", j.ledger().known_good));
    }
    j.append(Timestamp(99), Record::KnownGood(GenerationId(1000))).map_err(|e| format!("append: {e:?}"))?;
    let again = Journal::open(store.clone()).map_err(|e| format!("reopen: {e:?}"))?;
    if again.ledger().last_seq != n + 1 || again.ledger().known_good != Some(GenerationId(1000)) {
        return Err("the appended record was not read back".into());
    }
    // A second handle catching up reads the same (the refresh path).
    let mut other = Journal::open(store).map_err(|e| format!("{e:?}"))?;
    if other.sync_ledger().map_err(|e| format!("{e:?}"))?.last_seq != n + 1 {
        return Err("a catch-up missed the record".into());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn classes_hold_for_any_mix((items, last) in items()) {
        MUTANT.with(|m| m.set(Mutant::None));
        if let Err(e) = classes_hold(&items, &last) {
            prop_assert!(false, "{}", e);
        }
    }
}

/// Every mutant is caught by the class property on a log that has what it
/// breaks (rule 23). The generator weights those shapes (checked below).
#[test]
fn mutants_are_caught() {
    let mix = [Item::Known2(1), Item::Known3(2), Item::Unknown(1), Item::Known3(3)];
    let cases: [(Mutant, Vec<Item>, Last); 5] = [
        (Mutant::AnyClassSkips, mix.to_vec(), Last::UnknownDecisive),
        (Mutant::AnyClassSkips, mix.to_vec(), Last::UnknownFormat2),
        (Mutant::KnownKindSkips, mix.to_vec(), Last::BrokenKnownInformational),
        (Mutant::NoSkip, mix.to_vec(), Last::Nothing),
        (Mutant::NoFormat2, mix.to_vec(), Last::Nothing),
    ];
    for (m, items, last) in cases {
        MUTANT.with(|c| c.set(Mutant::None));
        classes_hold(&items, &last).unwrap_or_else(|e| panic!("clean run failed: {e}"));
        let (store, head, known) = build(&items, &last, 64 << 10);
        MUTANT.with(|c| c.set(m));
        let r = read_classes(store, head, known, items.len() as u64, &last);
        MUTANT.with(|c| c.set(Mutant::None));
        assert!(r.is_err(), "mutant {m:?} was not caught on {items:?} + {last:?}");
    }
}

/// `could_follow` accepts the frames of both formats; a version that knows
/// only format 2's payload offset does not (so the search for a later record
/// would miss format 3 frames, and a damaged record before one would be
/// truncated as a torn tail rather than Integrity).
#[test]
fn could_follow_reads_both_formats() {
    let e = Entry { seq: 5, at: Timestamp(1), record: Record::KnownGood(GenerationId(2)) };
    let payload = serde_json::to_vec(&e).unwrap();
    let cap = 64 << 10;
    for (name, bytes) in [
        ("format 3 decisive", frame(5, &Hash::ZERO, Class::Decisive, &payload)),
        ("format 3 informational", frame(5, &Hash::ZERO, Class::Informational, &payload)),
        ("format 2", frame_v2(5, &Hash::ZERO, &payload)),
    ] {
        MUTANT.with(|m| m.set(Mutant::None));
        assert!(could_follow(&bytes, 4, cap), "{name} does not pass could_follow");
        MUTANT.with(|m| m.set(Mutant::CouldFollowFormat2Only));
        let blind = could_follow(&bytes, 4, cap);
        MUTANT.with(|m| m.set(Mutant::None));
        assert_eq!(blind, name == "format 2", "{name}: the format-2-only mutant");
        // Not the next record: the same frame, past `last_seq`'s window.
        assert!(!could_follow(&bytes, 5, cap), "{name} follows its own seq");
    }
}

/// After a compaction, a log of format 3 frames with skipped records opens in
/// time linear in the store (the leftovers past the tail are not searched at
/// every offset), as before the class byte.
#[test]
fn open_after_compaction_with_skipped_frames_is_linear() {
    let capacity: u64 = 128 << 10;
    let (store, _, _) = build(
        &(0..400).map(|i| if i % 3 == 0 { Item::Unknown((i % 5) as u8) } else { Item::Known3(i) }).collect::<Vec<_>>(),
        &Last::Nothing,
        capacity,
    );
    let mut j = Journal::open(store.clone()).unwrap();
    j.compact().unwrap();
    for i in 0..40 {
        append(&mut j, i).unwrap();
    }
    let checkpoint = store.read_checkpoint().unwrap().map_or(0, |c| c.len() as u64);
    let (opened, crcd) = crc_bytes(|| Journal::open(store.clone()));
    let opened = opened.unwrap();
    assert_eq!(opened.ledger().last_seq, j.ledger().last_seq);
    assert!(crcd <= capacity + 2 * checkpoint + 4096, "open CRC'd {crcd} bytes for a {capacity} byte store");
}

/// `KINDS` is the set of kinds the match in `kind_and_class` names, each
/// kind is the serialized variant name, and the decisive ones are exactly the
/// kinds that match classes `Decisive` (`Skipped` is the reader's, never
/// written).
#[test]
fn kinds_are_the_variants() {
    let src = include_str!("../journal.rs");
    let arms = src.split("fn kind_and_class").nth(1).unwrap().split("pub fn class_of").next().unwrap();
    for k in KINDS {
        let one = arms.matches(&format!("(\"{k}\", D)")).count() + arms.matches(&format!("(\"{k}\", I)")).count();
        assert_eq!(one, 1, "{k} is not one arm of kind_and_class");
    }
    assert_eq!(arms.matches(", D)").count() + arms.matches(", I)").count(), KINDS.len(), "an arm is not in KINDS");
    for k in DECISIVE_KINDS {
        assert!(KINDS.contains(k));
        assert_eq!(arms.matches(&format!("(\"{k}\", D)")).count(), 1, "{k} is listed decisive but its arm is not D");
    }
    let informational: Vec<&&str> = KINDS.iter().filter(|k| !DECISIVE_KINDS.contains(k)).collect();
    assert_eq!(informational, [&"ExecProbeFlagged", &"Skipped"], "everything else is decisive");
    // The name is what serde writes.
    for kind in 0..6 {
        let r = record(kind, 3, 2);
        let e = Entry { seq: 1, at: Timestamp(0), record: r.clone() };
        let v: serde_json::Value = serde_json::to_value(&e).unwrap();
        let key = v["record"].as_object().unwrap().keys().next().unwrap().clone();
        assert_eq!(kind_and_class(&r).0, key);
    }
}

/// Skipped is a reader's record: appending one is refused.
#[test]
fn skipped_is_not_written() {
    let mut j = Journal::open(MemStore::new(16 << 10)).unwrap();
    assert!(matches!(j.append(Timestamp(0), Record::Skipped { kind: "X".into() }), Err(JournalError::Corrupt(_))));
}

/// A damaged record with format 3 frames after it is Integrity, not a torn
/// tail to truncate: the search for a later record has to see format 3. With
/// `could_follow` knowing only format 2 the later records are missed, the log
/// is cut at the damage, and the records after it are lost without a word.
#[test]
fn a_damaged_record_before_format_3_frames_is_integrity() {
    let items: Vec<Item> = (0..6).map(Item::Known3).collect();
    let run = || {
        let (store, _, _) = build(&items, &Last::Nothing, 64 << 10);
        // Flip a byte in the second frame's payload (its CRC then fails).
        let first = store.read_at(0, HEADER).unwrap();
        let first_len = HEADER + u32::from_le_bytes(first[0..4].try_into().unwrap()) as usize;
        let at = (first_len + HEADER + PREV + 1 + 12) as u64;
        let b = store.read_at(at, 1).unwrap()[0];
        store.write_at(at, &[b ^ 0x55]).unwrap();
        Journal::open(store).map(|j| j.ledger().last_seq)
    };
    MUTANT.with(|m| m.set(Mutant::None));
    assert!(matches!(run(), Err(JournalError::Integrity(_))), "{:?}", run());
    MUTANT.with(|m| m.set(Mutant::CouldFollowFormat2Only));
    let blind = run();
    MUTANT.with(|m| m.set(Mutant::None));
    assert!(matches!(blind, Ok(1)), "the format-2-only mutant should have truncated at the damage: {blind:?}");
}

/// An editor reseals only the class byte's frame, retaining the next frame
/// and its predecessor hash. An older reader must still find Integrity,
/// rather than silently skip a decisive kind it does not understand (I18).
fn class_edit_is_integrity(prefix: usize, suffix: u64) -> Result<(), String> {
    let store = MemStore::new(64 << 10);
    let (mut off, mut head) = (0u64, Hash::ZERO);
    for i in 0..prefix {
        let payload = newer(i as u64 + 1, i as u64, "KnownGood");
        let bytes = frame_v2(i as u64 + 1, &head, &payload);
        head = chain(&head, i as u64 + 1, &payload);
        store.write_at(off, &bytes).unwrap();
        off += bytes.len() as u64;
    }
    let seq = prefix as u64 + 1;
    let payload = newer(seq, suffix, "FutureDecision");
    let original = frame(seq, &head, Class::Decisive, &payload);
    let next_head = chain_v3(&head, seq, Class::Decisive, &payload);
    let next_payload = newer(seq + 1, 7, "KnownGood");
    let next = frame(seq + 1, &next_head, Class::Decisive, &next_payload);
    store.write_at(off, &original).unwrap();
    store.write_at(off + original.len() as u64, &next).unwrap();
    // Exactly the partial edit from the review: class 0 -> 1, resealed
    // CRC; neither payload, next frame, nor its chain head is rewritten.
    store.write_at(off, &frame(seq, &head, Class::Informational, &payload)).unwrap();
    let before = store.read_at(0, 64 << 10).unwrap();
    match Journal::open(store.clone()) {
        Err(JournalError::Integrity(_)) if store.read_at(0, 64 << 10).unwrap() == before => Ok(()),
        other => Err(format!("class-only edit opened or changed the log: {:?}", other.map(|j| j.ledger.last_seq))),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn class_only_edits_are_integrity(prefix in 0usize..12, suffix in 0u64..u64::MAX) {
        MUTANT.with(|m| m.set(Mutant::None));
        prop_assert!(class_edit_is_integrity(prefix, suffix).is_ok());
    }

    #[test]
    fn a_read_handles_chain_detects_a_class_edit(n in 2usize..12, which in any::<prop::sample::Index>()) {
        let store = MemStore::new(64 << 10);
        let mut j = Journal::open(store.clone()).unwrap();
        let mut frames = vec![];
        for i in 0..n {
            let start = j.offset();
            append(&mut j, i as u64).unwrap();
            frames.push((start, j.offset() - start));
        }
        let (start, length) = frames[which.index(n)];
        let bytes = store.read_at(start, length as usize).unwrap();
        let f = unframe(&bytes).unwrap();
        let edited = frame(f.seq, &f.prev, Class::Informational, f.payload);
        store.write_at(start, &edited).unwrap();
        prop_assert!(matches!(j.verify_chain(), Err(JournalError::Integrity(_))));
    }
}

#[test]
fn the_class_outside_the_chain_mutant_is_caught() {
    MUTANT.with(|m| m.set(Mutant::None));
    class_edit_is_integrity(1, 3).unwrap();
    MUTANT.with(|m| m.set(Mutant::ClassOutsideChain));
    let result = class_edit_is_integrity(1, 3);
    MUTANT.with(|m| m.set(Mutant::None));
    assert!(result.is_err(), "the old class-only partial edit must open under the mutant");
}

#[test]
fn an_empty_journal_requires_the_format_its_transition_will_write() {
    let store = MemStore::new(64 << 10);
    let mut j = Journal::open(store).unwrap();
    let needs = j.required_decisive().unwrap();
    assert_eq!(needs.format, 3);
    assert!(needs.kinds.iter().any(|kind| kind == "Prepared"));
    assert!(needs.kinds.iter().any(|kind| kind == "Advance"));
    assert!(!needs.unsupported_by(&original()).is_empty());
    assert!(needs.unsupported_by(&supported()).is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// The descriptor is retained across every compaction/reopen, including
    /// requirements whose decisive record is no longer in the physical log.
    #[test]
    fn decisive_requirements_survive_compaction(
        history in proptest::collection::vec((0u8..6, any::<bool>()), 1..32),
    ) {
        let store = MemStore::new(64 << 10);
        let mut j = Journal::open(store.clone()).unwrap();
        for (i, (kind, compact)) in history.into_iter().enumerate() {
            j.append(Timestamp(i as u64), record(kind, i as u64, 1)).unwrap();
            let before = j.required_decisive().unwrap();
            if compact {
                j.compact().unwrap();
                j = Journal::open(store.clone()).unwrap();
            }
            let after = j.required_decisive().unwrap();
            prop_assert_eq!(&before, &after);
            prop_assert!(after.unsupported_by(&supported()).is_empty());
        }
    }

    /// Omitting any single advertised decisive kind or field is observable;
    /// a target advertising the complete requirements is always compatible.
    #[test]
    fn compatibility_checks_every_decisive_requirement(
        kind in 0usize..DECISIVE_KINDS.len(),
        field in any::<bool>(),
    ) {
        let needs = supported();
        prop_assert!(needs.unsupported_by(&needs).is_empty());
        let mut target = needs.clone();
        if field {
            target.fields.get_mut("Prepared").unwrap().clear();
        } else {
            target.kinds.remove(kind);
        }
        prop_assert!(!needs.unsupported_by(&target).is_empty());
    }
}

#[test]
fn a_checkpoint_cannot_hide_an_unknown_decisive_requirement() {
    let store = MemStore::new(64 << 10);
    let mut j = Journal::open(store.clone()).unwrap();
    append(&mut j, 0).unwrap();
    j.compact().unwrap();
    let bytes = store.read_checkpoint().unwrap().unwrap();
    let f = unframe(&bytes).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(f.payload).unwrap();
    value[compat::CHECKPOINT_REQUIREMENTS]["kinds"].as_array_mut().unwrap().push("FutureDecision".into());
    let payload = serde_json::to_vec(&value).unwrap();
    store.write_checkpoint(&frame(f.seq, &f.prev, f.class, &payload)).unwrap();
    assert!(matches!(Journal::open(store), Err(JournalError::Integrity(_))));
}

#[test]
fn a_compacted_decisive_field_stays_required_without_its_record() {
    let store = MemStore::new(64 << 10);
    let mut state = serde_json::to_value(Ledger::default()).unwrap();
    let mut needs = JournalRequirements::empty();
    needs.fields.insert("Prepared".into(), vec!["facts.journal_incompatibility".into()]);
    state[compat::CHECKPOINT_REQUIREMENTS] = serde_json::to_value(&needs).unwrap();
    store.write_checkpoint(&frame(0, &Hash::ZERO, Class::Decisive, &serde_json::to_vec(&state).unwrap())).unwrap();
    let mut j = Journal::open(store.clone()).unwrap();
    assert_eq!(j.required_decisive().unwrap(), needs);
    j.compact().unwrap();
    let mut again = Journal::open(store).unwrap();
    assert_eq!(again.required_decisive().unwrap(), needs);
}

fn invalid_class_log(prefix: &[bool], class: u8, later: bool) -> (MemStore, Journal<MemStore>) {
    let items: Vec<_> = prefix
        .iter()
        .enumerate()
        .map(|(i, old)| if *old { Item::Known2(i as u64) } else { Item::Known3(i as u64) })
        .collect();
    let (store, _, _) = build(&items, &Last::Nothing, 64 << 10);
    let mut j = Journal::open(store.clone()).unwrap();
    let start = j.offset();
    append(&mut j, 41).unwrap();
    let length = j.offset() - start;
    if later {
        append(&mut j, 42).unwrap();
    }
    let bytes = store.read_at(start, length as usize).unwrap();
    let f = unframe(&bytes).unwrap();
    store.write_at(start, &frame(f.seq, &f.prev, Class::Invalid(class), f.payload)).unwrap();
    (store, j)
}

fn invalid_class_is_integrity(prefix: &[bool], class: u8, later: bool) -> Result<(), String> {
    let (store, _) = invalid_class_log(prefix, class, later);
    let before = store.read_at(0, 64 << 10).unwrap();
    match Journal::open(store.clone()) {
        Err(JournalError::Integrity(_)) if store.read_at(0, 64 << 10).unwrap() == before => Ok(()),
        other => {
            Err(format!("unsupported class {class} opened or changed the log: {:?}", other.map(|j| j.ledger.last_seq)))
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// A valid CRC does not make an unknown semantic class a torn record.
    /// Preserve it as evidence, at the tail or before a later record and
    /// after any mixture of the two supported frame formats.
    #[test]
    fn an_intact_unknown_class_is_integrity_and_kept(
        prefix in proptest::collection::vec(any::<bool>(), 0..12),
        class in 2u8..=255,
        later in any::<bool>(),
    ) {
        MUTANT.with(|m| m.set(Mutant::None));
        prop_assert!(invalid_class_is_integrity(&prefix, class, later).is_ok());
    }

    #[test]
    fn every_read_helper_refuses_an_intact_unknown_class(
        prefix in proptest::collection::vec(any::<bool>(), 0..8),
        class in 2u8..=255,
    ) {
        let (store, mut j) = invalid_class_log(&prefix, class, false);
        let before = store.read_at(0, 64 << 10).unwrap();
        prop_assert!(matches!(j.verify_chain(), Err(JournalError::Integrity(_))));
        prop_assert!(matches!(j.segment(), Err(JournalError::Integrity(_))));
        prop_assert!(matches!(j.required_decisive(), Err(JournalError::Integrity(_))));
        prop_assert_eq!(store.read_at(0, 64 << 10).unwrap(), before);
    }

    #[test]
    fn a_checkpoint_with_an_unknown_class_is_integrity(class in 2u8..=255) {
        let store = MemStore::new(64 << 10);
        let mut j = Journal::open(store.clone()).unwrap();
        append(&mut j, 0).unwrap();
        j.compact().unwrap();
        let bytes = store.read_checkpoint().unwrap().unwrap();
        let f = unframe(&bytes).unwrap();
        let edited = frame(f.seq, &f.prev, Class::Invalid(class), f.payload);
        store.write_checkpoint(&edited).unwrap();
        prop_assert!(matches!(j.required_decisive(), Err(JournalError::Integrity(_))));
        prop_assert!(matches!(j.verify_chain(), Err(JournalError::Integrity(_))));
        prop_assert!(matches!(Journal::open(store.clone()), Err(JournalError::Integrity(_))));
        prop_assert_eq!(store.read_checkpoint().unwrap().unwrap(), edited);
    }
}

#[test]
fn the_invalid_class_is_torn_mutant_is_caught() {
    MUTANT.with(|m| m.set(Mutant::None));
    invalid_class_is_integrity(&[true, false], 2, false).unwrap();
    MUTANT.with(|m| m.set(Mutant::InvalidClassIsTorn));
    let result = invalid_class_is_integrity(&[true, false], 2, false);
    MUTANT.with(|m| m.set(Mutant::None));
    assert!(result.is_err(), "the old decoder must truncate this intact tail under the mutant");
}

#[test]
fn an_unknown_class_after_damage_is_still_an_intact_later_record() {
    let (store, _) = invalid_class_log(&[false], 255, false);
    let at = (HEADER + PREV + 1 + 12) as u64;
    let byte = store.read_at(at, 1).unwrap()[0];
    store.write_at(at, &[byte ^ 1]).unwrap();
    let before = store.read_at(0, 64 << 10).unwrap();
    assert!(matches!(Journal::open(store.clone()), Err(JournalError::Integrity(_))));
    assert_eq!(store.read_at(0, 64 << 10).unwrap(), before);
}

/// An Exec flag is informational, leaves decisions unchanged and, if unknown, is skipped.
#[test]
fn an_informational_kind_is_written_informational_and_applies_to_nothing() {
    let store = MemStore::new(64 << 10);
    let mut j = Journal::open(store.clone()).unwrap();
    append(&mut j, 0).unwrap();
    let before = serde_json::to_value(j.ledger()).unwrap();
    let flagged = Record::ExecProbeFlagged {
        unit: planarian_schema::UnitId::service("u"),
        probe: "p".into(),
        argv0: "sh".into(),
    };
    let at = j.offset();
    let e = j.append(Timestamp(5), flagged.clone()).unwrap();
    // On disk: format 3, class byte 1.
    let header = store.read_at(at, HEADER).unwrap();
    let len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
    let bytes = store.read_at(at, HEADER + len).unwrap();
    let f = unframe(&bytes).expect("intact");
    assert_eq!((f.format, f.class), (3, Class::Informational));
    // Known to this reader: it reads as itself and changes only last_seq.
    let again = Journal::open(store.clone()).unwrap();
    assert_eq!(again.ledger().last_seq, e.seq);
    let mut after = serde_json::to_value(again.ledger()).unwrap();
    let mut was = before;
    after["last_seq"] = 0.into();
    was["last_seq"] = 0.into();
    assert_eq!(after, was, "an informational record changes nothing in the ledger");
    // Unknown to a reader (renamed, as a newer build's kind would be to an older one): skipped.
    let json = String::from_utf8(f.payload.to_vec()).unwrap().replace("ExecProbeFlagged", "FromTheFuture");
    let entry = decode(&Frame {
        seq: e.seq,
        prev: f.prev,
        class: Class::Informational,
        format: 3,
        payload: json.as_bytes(),
        size: 0,
    });
    assert_eq!(entry.unwrap().record, Record::Skipped { kind: "FromTheFuture".into() });
}

/// Informational flags never raise the generation compatibility floor.
#[test]
fn an_exec_flag_adds_no_decisive_journal_requirement() {
    let mut j = Journal::open(MemStore::new(64 << 10)).unwrap();
    let before = j.required_decisive().unwrap();
    let flagged = Record::ExecProbeFlagged {
        unit: planarian_schema::UnitId::service("u"),
        probe: "p".into(),
        argv0: "sh".into(),
    };
    j.append(Timestamp(5), flagged).unwrap();
    assert_eq!(j.required_decisive().unwrap(), before);
    j.compact().unwrap();
    assert_eq!(j.required_decisive().unwrap(), before);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Filter known Exec flags out of generated histories: every decision
    /// and decisive requirement stays identical, through reopen/compaction.
    #[test]
    fn known_exec_flags_never_change_decisions_or_requirements(
        steps in proptest::collection::vec((0u8..4, any::<u16>(), 1usize..4, any::<bool>(), any::<bool>()), 1..20),
    ) {
        let flagged_store = MemStore::new(64 << 10);
        let plain_store = MemStore::new(64 << 10);
        let mut flagged = Journal::open(flagged_store.clone()).unwrap();
        let mut plain = Journal::open(plain_store.clone()).unwrap();
        for (kind, value, flags, compact, reopen) in steps {
            let generation = GenerationId(value as u64);
            let decision = match kind {
                0 => Record::KnownGood(generation),
                1 => Record::LiveTested(Some(generation)),
                2 => Record::AcceptedBaseline(Some(generation)),
                _ => Record::SecurityFloor(Some(generation)),
            };
            flagged.append(Timestamp(1), decision.clone()).unwrap();
            plain.append(Timestamp(1), decision).unwrap();
            for probe in 0..flags {
                let record = Record::ExecProbeFlagged {
                    unit: planarian_schema::UnitId::service(&format!("u{value}")),
                    probe: format!("p{probe}"),
                    argv0: format!("command{value}"),
                };
                prop_assert_eq!(class_of(&record), Class::Informational);
                flagged.append(Timestamp(2), record).unwrap();
            }
            for phase in 0..3 {
                if phase == 1 && reopen {
                    flagged = Journal::open(flagged_store.clone()).unwrap();
                    plain = Journal::open(plain_store.clone()).unwrap();
                }
                if phase == 2 && compact {
                    flagged.compact().unwrap();
                    plain.compact().unwrap();
                    flagged = Journal::open(flagged_store.clone()).unwrap();
                    plain = Journal::open(plain_store.clone()).unwrap();
                }
                let mut actual = serde_json::to_value(flagged.ledger()).unwrap();
                let mut expected = serde_json::to_value(plain.ledger()).unwrap();
                actual.as_object_mut().unwrap().remove("last_seq");
                expected.as_object_mut().unwrap().remove("last_seq");
                prop_assert_eq!(actual, expected, "phase {}", phase);
                prop_assert_eq!(flagged.required_decisive().unwrap(), plain.required_decisive().unwrap(), "phase {}", phase);
            }
        }
    }
}

proptest! {
    /// A retained refusal needs its decisive kind and checkpoint field,
    /// both before compaction and after reopening the compacted journal.
    #[test]
    fn a_declined_transaction_remains_a_decisive_requirement(txn in any::<u64>()) {
        let store = MemStore::new(64 << 10);
        let mut j = Journal::open(store.clone()).unwrap();
        let mut previous = supported();
        previous.kinds.retain(|kind| kind != "NotPreparedAgain");
        previous.fields.get_mut("checkpoint").unwrap().retain(|field| field != "not_prepared_again");
        prop_assert!(j.required_decisive().unwrap().unsupported_by(&previous).is_empty());
        j.append(Timestamp(5), Record::NotPreparedAgain { txn: TxnId(txn), reason: "refused".into() }).unwrap();
        let required = j.required_decisive().unwrap();
        let missing = required.unsupported_by(&previous);
        prop_assert!(missing.contains(&"record kind NotPreparedAgain".to_owned()));
        prop_assert!(missing.contains(&"decisive field checkpoint.not_prepared_again".to_owned()));
        let mut missing_field = supported();
        missing_field.fields.get_mut("checkpoint").unwrap().retain(|field| field != "not_prepared_again");
        prop_assert_eq!(required.unsupported_by(&missing_field), vec!["decisive field checkpoint.not_prepared_again"]);
        j.compact().unwrap();
        let mut again = Journal::open(store).unwrap();
        prop_assert_eq!(again.required_decisive().unwrap(), required);
        prop_assert_eq!(again.ledger().not_prepared_again(), [TxnId(txn)].into_iter().collect());
    }
}

/// §12c ("Each build exports the kinds and decisive fields it reads"): the
/// descriptor `planariad --journal-kinds` prints is `supported()`. It
/// round-trips as the requirements a target is compared with, reads at least
/// the original set a build without an export is taken to read (what the
/// first format-2 build, 90f1e37, read: format 2, 16 kinds, no decisive
/// field), and names exactly the decisive kinds.
#[test]
fn the_exported_descriptor_is_this_builds_reader() {
    let json = serde_json::to_string(&supported()).unwrap();
    let back: compat::JournalRequirements = serde_json::from_str(&json).unwrap();
    assert_eq!(back, supported());
    assert_eq!(back.format, 3);
    let mut decisive: Vec<String> = DECISIVE_KINDS.iter().map(|k| (*k).to_owned()).collect();
    decisive.sort();
    let mut kinds = back.kinds.clone();
    kinds.sort();
    assert_eq!(kinds, decisive, "the descriptor's kinds are the decisive kinds");
    let o = original();
    assert_eq!((o.format, o.kinds.len()), (2, 16), "docs/deviations.md names the original set as format 2, 16 kinds");
    assert!(o.fields.is_empty(), "the first format-2 build wrote no decisive field a later one added");
    for added in ["ExternalAccepted", "AgentStarted", "HoldApplied", "HoldLifted", "NotPreparedAgain"] {
        assert!(!o.kinds.iter().any(|k| k == added), "{added} was added during format 2");
        assert!(back.kinds.iter().any(|k| k == added));
    }
    assert!(o.unsupported_by(&back).is_empty(), "a build reads at least the original set");
}

/// Registry guard: a `#[serde(default)]` field is how a field is added
/// without breaking older journals, and a reader that ignores one can act on a
/// wrong value. So each defaulted field in the journal's records, the ledger
/// they fold into and the transaction they carry is classified here: present
/// in the first format-2 build (90f1e37), so in the original set a build
/// without an export is taken to read; or added during format 2, with the
/// commit that added it, and then the descriptor must name a path for it (so
/// a journal that uses it asks before a transition to a build that predates
/// the export). A new defaulted field fails until a person classifies it.
///
/// The commit for each entry is the first one in which the field is in its
/// struct or variant, found by walking `git log` over crates/txn/src/ledger.rs
/// and crates/schema/src/txn.rs, and whether it is in 90f1e37 by
/// `git merge-base --is-ancestor <commit> 90f1e37`.
#[test]
fn every_defaulted_field_of_a_decisive_kind_is_classified() {
    #[derive(Clone, Copy)]
    enum Era {
        /// In the first format-2 build.
        Original,
        /// Added during format 2, by this commit.
        AddedDuringFormat2(&'static str),
    }
    use Era::{AddedDuringFormat2 as Added, Original};
    let table: &[(&str, Era)] = &[
        ("why", Original),            // LiveTxn.why, b462e32
        ("security_floor", Original), // Ledger.security_floor, d1f133c
        ("boot_at", Added("89eb2b4")),
        ("approver", Added("d9e1ed2")),
        ("txn", Added("d9e1ed2")),
        ("instance", Added("8231a07")),
        ("boot_only", Added("4e5cd1c")),
        ("external", Added("db5b0f4")),
        ("agents", Added("805cd1c")),
        ("hold_events", Added("d10bc80")),
        ("candidate_nar", Added("82a76ab")),
        ("pre_passing", Added("ff11187")),
        ("withdrawn_for", Added("2a24d30")),
        ("prepared_again_from", Added("2a24d30")),
        ("not_prepared_again", Added("b21f867")),
    ];
    let sources = [include_str!("../ledger.rs"), include_str!("../../../schema/src/txn.rs")];
    let mut found: Vec<String> = vec![];
    for src in sources {
        let lines: Vec<&str> = src.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            if !l.trim_start().starts_with("#[serde(default") {
                continue;
            }
            let field = lines[i + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.starts_with("///") && !l.starts_with("#["))
                .and_then(|l| l.trim_start_matches("pub ").split(':').next())
                .expect("a field follows the attribute")
                .to_owned();
            found.push(field);
        }
    }
    found.sort();
    found.dedup();
    for f in &found {
        assert!(
            table.iter().any(|(n, _)| n == f),
            "`#[serde(default)]` field `{f}` is unclassified: add it to this table (original, or added during format 2 with its commit) and name its path in `supported()`"
        );
    }
    let paths: Vec<String> = supported().fields.values().flatten().cloned().collect();
    for (name, class) in table {
        assert!(found.iter().any(|f| f == name), "`{name}` is classified but is no longer a defaulted field");
        let described = paths.iter().any(|p| p.rsplit('.').next() == Some(*name));
        match class {
            Added(commit) => {
                assert!(commit.len() == 7, "{name}: a short commit id");
                assert!(
                    described,
                    "`{name}` was added during format 2 ({commit}) but the descriptor names no path for it"
                );
            }
            Original => {
                assert!(!described, "`{name}` is in the first format-2 build: the descriptor must not require it")
            }
        }
    }
}

/// The kinds and fields added during format 2 are decisive for a build that
/// predates the export: a journal that holds one asks before a transition to
/// such a build (§12c AskFirst), and a field at its default does not.
#[test]
fn what_was_added_during_format_2_is_required_of_a_target_that_predates_the_export() {
    use crate::ledger::HoldBy;
    let unit = planarian_schema::UnitId::service("gym-web");
    // (Every record also needs format 3; that is not what is under test.)
    let needs = |r: &Record| {
        let mut m = compat::record_requirements(r).unwrap().unsupported_by(&original());
        m.retain(|x| !x.starts_with("journal format"));
        m
    };
    let renew = |boot_at| Record::Renew {
        txn: planarian_schema::TxnId(1),
        epoch: 1,
        worker_pid: None,
        boot_at: Timestamp(boot_at),
    };
    assert_eq!(needs(&renew(5)), vec!["decisive field Renew.boot_at"]);
    assert!(needs(&renew(0)).is_empty(), "a boot time at its default needs nothing");
    let token = |approver, txn| Record::TokenUsed { nonce: [1; 16], expires: Timestamp(9), approver, txn };
    // Root (uid 0) and the first transaction (id 0) are real values.
    let both = vec!["decisive field TokenUsed.approver", "decisive field TokenUsed.txn"];
    assert_eq!(needs(&token(7, 0)), both);
    assert_eq!(needs(&token(7, 3)), both);
    assert_eq!(needs(&token(0, 0)), both);
    let agent = |instance| Record::AgentStarted { name: "a".into(), instance, by: 1000 };
    assert_eq!(
        needs(&agent([1; 16])),
        vec!["decisive field AgentStarted.instance", "decisive field checkpoint.agents", "record kind AgentStarted"]
    );
    assert_eq!(needs(&agent([0; 16])), vec!["decisive field checkpoint.agents", "record kind AgentStarted"]);
    for (record, kind, field) in [
        (Record::HoldApplied { unit: unit.clone(), by: HoldBy::Daemon }, "HoldApplied", "hold_events"),
        (Record::HoldLifted { unit: unit.clone(), reason: "r".into() }, "HoldLifted", "hold_events"),
        (Record::ExternalAccepted { seq: 1, digest: planarian_schema::Hash([0; 32]) }, "ExternalAccepted", "external"),
        (
            Record::NotPreparedAgain { txn: planarian_schema::TxnId(2), reason: "r".into() },
            "NotPreparedAgain",
            "not_prepared_again",
        ),
    ] {
        assert_eq!(
            needs(&record),
            vec![format!("decisive field checkpoint.{field}"), format!("record kind {kind}")],
            "{kind}"
        );
        // And this build reads it.
        assert!(compat::record_requirements(&record).unwrap().unsupported_by(&supported()).is_empty());
    }
}

/// A transaction's decisive fields added during format 2 are required once
/// set: a candidate's NAR hash (losing it skips C6's check, which fails open)
/// and the probes passing before (R07), on `Prepared` and in a checkpoint.
#[test]
fn a_prepared_transactions_added_fields_are_required_once_set() {
    use serde_json::json;
    let required = |kind: &str, v: serde_json::Value| {
        let mut r = compat::JournalRequirements { format: 3, kinds: vec![], fields: Default::default() };
        compat::fields_in(kind, &v, &mut r);
        r.fields.into_values().flatten().collect::<Vec<_>>()
    };
    assert_eq!(required("Prepared", json!({"candidate_nar": [1, 2, 3]})), ["candidate_nar"]);
    assert!(required("Prepared", json!({"candidate_nar": null})).is_empty(), "None at its default");
    assert_eq!(required("Prepared", json!({"check": {"pre_passing": {"u": ["p"]}}})), ["check.pre_passing"]);
    assert!(required("Prepared", json!({"check": {"pre_passing": {}}})).is_empty());
    assert_eq!(
        required("checkpoint", json!({"live": {"1": {"txn": {"candidate_nar": [9]}, "boot_only": true}}})),
        ["live.*.boot_only", "live.*.txn.candidate_nar"]
    );
    assert!(required("checkpoint", json!({"live": {"1": {"boot_only": false}}})).is_empty());
}

/// A value that is zero for real is set: the first transaction's id is 0, so
/// a `withdrawn_for`, `prepared_again_from` or `TokenUsed.txn` of `TxnId(0)`
/// must be required, and an approver of 0 is root, who approves most things.
/// Only a field that can never be zero for real (a boot time, an agent's
/// InvocationID, an unset flag) reads zero as unset. (A zero counted as unset
/// everywhere dropped the first; the list then kept two.)
#[test]
fn a_value_of_zero_is_a_set_field_unless_zero_can_never_be_real() {
    use serde_json::json;
    let required = |kind: &str, v: serde_json::Value| {
        let mut r = compat::JournalRequirements { format: 3, kinds: vec![], fields: Default::default() };
        compat::fields_in(kind, &v, &mut r);
        r.fields.into_values().flatten().collect::<Vec<_>>()
    };
    assert_eq!(required("Advance", json!({"withdrawn_for": 0})), ["withdrawn_for"]);
    assert_eq!(required("Prepared", json!({"prepared_again_from": 0})), ["prepared_again_from"]);
    assert_eq!(required("checkpoint", json!({"terminal": {"3": {"withdrawn_for": 0}}})), ["terminal.*.withdrawn_for"]);
    assert_eq!(required("checkpoint", json!({"not_prepared_again": [0]})), ["not_prepared_again"]);
    assert_eq!(required("TokenUsed", json!({"approver": 0, "txn": 0})), ["approver", "txn"]);
    assert!(required("Renew", json!({"boot_at": 0})).is_empty());
    assert!(required("AgentStarted", json!({"instance": [0, 0, 0, 0]})).is_empty());
    assert_eq!(required("AgentStarted", json!({"instance": [0, 0, 0, 1]})), ["instance"]);
    assert!(required("checkpoint", json!({"live": {"1": {"boot_only": false}}})).is_empty());
}

mod active_props {
    use super::*;
    use serde_json::{Value, json};

    fn json_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            prop_oneof![Just(0i64), Just(1), Just(-1), any::<i64>()].prop_map(|n| json!(n)),
            prop_oneof![Just(String::new()), "[a-z]{1,4}"].prop_map(Value::String),
        ];
        leaf.prop_recursive(3, 24, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                prop::collection::btree_map("[a-c]", inner, 0..4).prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    /// The independent model: a field a reader must understand is one that is
    /// present, and, where zero is the default, has a non-default leaf. (Where
    /// zero is real, anything but null, an empty list or an empty map is set.)
    fn model(v: &Value, zero_default: bool) -> bool {
        match v {
            Value::Null => false,
            Value::Bool(b) => !zero_default || *b,
            Value::Number(n) => !zero_default || n.as_i64() != Some(0),
            Value::String(s) => !zero_default || !s.is_empty(),
            Value::Array(a) if zero_default => a.iter().any(|x| model(x, true)),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn active_is_true_exactly_when_the_model_says_so(v in json_value(), zero_default in any::<bool>()) {
            prop_assert_eq!(compat::active(&v, &[], zero_default), model(&v, zero_default), "{:?}", v);
        }

        /// A path into a value reaches the same decision as the value at its end.
        #[test]
        fn a_path_is_followed_to_the_value(v in json_value(), zero_default in any::<bool>()) {
            let wrapped = json!({"live": {"7": {"txn": {"f": v.clone()}}}});
            prop_assert_eq!(
                compat::active(&wrapped, &["live", "*", "txn", "f"], zero_default),
                model(&v, zero_default)
            );
            prop_assert!(!compat::active(&wrapped, &["live", "*", "txn", "absent"], zero_default));
        }
    }
}

mod reads_what_it_writes {
    use super::*;
    use crate::ledger::HoldBy;

    fn written() -> impl Strategy<Value = Record> {
        let unit = planarian_schema::UnitId::service("gym-web");
        prop_oneof![
            (any::<u64>(), any::<u64>()).prop_map(|(n, boot_at)| Record::Renew {
                txn: planarian_schema::TxnId(n),
                epoch: n,
                worker_pid: None,
                boot_at: Timestamp(boot_at),
            }),
            (prop_oneof![Just(0u64), any::<u64>()], prop_oneof![Just(0u64), any::<u64>()])
                .prop_map(|(approver, txn)| Record::TokenUsed { nonce: [3; 16], expires: Timestamp(1), approver, txn }),
            any::<[u8; 16]>().prop_map(|instance| Record::AgentStarted { name: "a".into(), instance, by: 1000 }),
            any::<u64>().prop_map(|n| Record::Advance {
                txn: planarian_schema::TxnId(n),
                epoch: 1,
                to: planarian_schema::TxnState::Prepared,
                note: String::new(),
                withdrawn_for: (n % 2 == 0).then_some(planarian_schema::TxnId(n / 2)),
            }),
            Just(Record::HoldApplied { unit: unit.clone(), by: HoldBy::Daemon }),
            Just(Record::HoldLifted { unit, reason: "r".into() }),
            any::<u64>().prop_map(|seq| Record::ExternalAccepted { seq, digest: planarian_schema::Hash([1; 32]) }),
            any::<u64>().prop_map(|n| Record::NotPreparedAgain { txn: planarian_schema::TxnId(n), reason: "r".into() }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        /// A build reads everything it writes: what a record it writes needs
        /// of a reader, this build's own descriptor supplies.
        /// Root and the first transaction are real values: whatever the
        /// approver and the transaction, both are named as reasons.
        #[test]
        fn a_token_names_its_approver_and_transaction_whatever_their_values(approver in prop_oneof![Just(0u64), any::<u64>()], txn in prop_oneof![Just(0u64), any::<u64>()]) {
            let r = Record::TokenUsed { nonce: [3; 16], expires: Timestamp(1), approver, txn };
            let mut m = compat::record_requirements(&r).unwrap().unsupported_by(&original());
            m.retain(|x| !x.starts_with("journal format"));
            prop_assert_eq!(m, vec!["decisive field TokenUsed.approver", "decisive field TokenUsed.txn"]);
        }

        #[test]
        fn a_build_reads_everything_it_writes(r in written()) {
            let needs = compat::record_requirements(&r).unwrap();
            prop_assert!(needs.unsupported_by(&supported()).is_empty(), "{:?}", needs.unsupported_by(&supported()));
        }
    }
}
