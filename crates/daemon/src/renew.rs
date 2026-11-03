//! Lease renewal (§12): while this daemon is busy in a long backend call, a
//! thread renews the leases it holds, so the watchdog does not take over
//! from a live daemon. It keeps one journal handle and catches up on what
//! others appended (`sync_ledger`), rather than opening the journal again
//! each time: opening reads the checkpoint and the whole log, and after a
//! compaction the rest of the store, so renewing would cost the journal's
//! size every 20 s and be slowest when the journal is fullest.

use planarian_schema::{OwnerId, Timestamp};
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::Record;
use planarian_txn::store::Store;

/// One renewal: catch up, then a `Renew` for every transaction `me` holds
/// mid-flight. Returns how many it renewed. An error leaves the handle to
/// be dropped and opened again.
pub fn renew<S: Store>(
    j: &mut Journal<S>,
    me: &OwnerId,
    now: Timestamp,
    boot_at: Timestamp,
) -> Result<usize, JournalError> {
    let live: Vec<_> = j
        .sync_ledger()?
        .live
        .values()
        .filter(|t| t.txn.lease.owner == *me && !t.txn.state.is_pre_mutation())
        .map(|t| (t.txn.id, t.txn.lease.epoch, t.txn.lease.worker_pid))
        .collect();
    let mut n = 0;
    for (txn, epoch, worker_pid) in live {
        // A lost race (the watchdog took over meanwhile) refuses the record;
        // the others are still renewed.
        if j.append(now, Record::Renew { txn, epoch, worker_pid, boot_at }).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use planarian_schema::{GenerationId, TxnId};
    use planarian_txn::store::MemStore;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A MemStore that counts the log bytes read through it.
    #[derive(Clone)]
    struct Counting(MemStore, Arc<AtomicU64>);

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
            self.1.fetch_add(b.len() as u64, Ordering::Relaxed);
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

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// A renewal with a kept handle costs what others appended since the
        /// last one, not the journal's size, before and after compactions.
        /// Only the first renewal after a compaction pays once for the store
        /// (it reloads: the checkpoint, then one bounded search of the
        /// leftovers, #54). Before the scan read the body only for a header
        /// that could be the next record, every catch-up after a compaction
        /// read the rest of the store: the leftovers' "length".
        #[test]
        fn a_renewal_costs_what_was_appended(rounds in proptest::collection::vec((1u64..120, proptest::bool::weighted(0.25)), 1..10)) {
            let capacity = 256 << 10;
            let mem = MemStore::new(capacity);
            let mut daemon = Journal::open(mem.clone()).unwrap();
            let read = Arc::new(AtomicU64::new(0));
            let mut r = Journal::open(Counting(mem.clone(), read.clone())).unwrap();
            let me = OwnerId::Daemon { pid: 1, boot_id: planarian_schema::Hash::ZERO };
            let mut i = 0;
            for (n, compact) in rounds {
                let before = daemon.offset();
                let mut compacted = false;
                for _ in 0..n {
                    if daemon.needs_compaction() {
                        daemon.compact().unwrap();
                        compacted = true;
                    }
                    daemon.append(Timestamp(i), Record::KnownGood(GenerationId(i + 1))).unwrap();
                    i += 1;
                }
                if compact {
                    daemon.compact().unwrap();
                    compacted = true;
                }
                let appended = if compacted { daemon.offset() } else { daemon.offset() - before };
                read.store(0, Ordering::Relaxed);
                renew(&mut r, &me, Timestamp(0), Timestamp(0)).unwrap();
                prop_assert_eq!(r.ledger().last_seq, daemon.ledger().last_seq);
                let cost = read.load(Ordering::Relaxed);
                // Each frame's header is read twice (to size it, then whole).
                let bound = 2 * appended + 1024 + if compacted { capacity } else { 0 };
                prop_assert!(cost <= bound, "renewal read {} bytes; {} appended since (compacted: {})", cost, appended, compacted);
            }
        }
    }
}
