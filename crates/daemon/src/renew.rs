//! Lease renewal (§12): while this daemon is busy in a long backend call, a
//! thread renews the leases it holds, so the watchdog does not take over
//! from a live daemon. It keeps one journal handle and catches up on what
//! others appended (`sync_ledger`), rather than opening the journal again
//! each time: opening reads the checkpoint and the whole log, and after a
//! compaction the rest of the store, so renewing would cost the journal's
//! size every 20 s and be slowest when the journal is fullest.

use planarian_schema::{OwnerId, Timestamp, TxnId};
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::{Ledger, Record};
use planarian_txn::store::Store;

/// A lease to renew: the transaction, its epoch and its worker.
pub type Due = (TxnId, u64, Option<u32>);

/// The leases `me` holds on transactions mid-flight (past their last
/// pre-mutation state), each with the epoch and worker its lease has.
pub fn due(l: &Ledger, me: &OwnerId) -> Vec<Due> {
    l.live
        .values()
        .filter(|t| t.txn.lease.owner == *me && !t.txn.state.is_pre_mutation())
        .map(|t| (t.txn.id, t.txn.lease.epoch, t.txn.lease.worker_pid))
        .collect()
}

/// A `Renew` for each lease in `due`. A record refused (a takeover won the
/// race since `due` was read) costs only itself; the others are renewed.
/// Returns how many were.
pub fn renew_due<S: Store>(j: &mut Journal<S>, due: &[Due], now: Timestamp, boot_at: Timestamp) -> usize {
    due.iter()
        .filter(|(txn, epoch, worker_pid)| {
            j.append(now, Record::Renew { txn: *txn, epoch: *epoch, worker_pid: *worker_pid, boot_at }).is_ok()
        })
        .count()
}

/// One renewal: catch up, then renew what `me` holds mid-flight. An error
/// catching up leaves the handle to be dropped and opened again.
pub fn renew<S: Store>(
    j: &mut Journal<S>,
    me: &OwnerId,
    now: Timestamp,
    boot_at: Timestamp,
) -> Result<usize, JournalError> {
    let d = due(j.sync_ledger()?, me);
    Ok(renew_due(j, &d, now, boot_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use planarian_schema::*;
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

    /// A transaction leased to `owner` (exec's shape, nothing the renewer
    /// reads but the lease and the state).
    fn txn(id: TxnId, owner: OwnerId, worker_pid: Option<u32>) -> Transaction {
        let transition = Transition::RestartUnit(UnitId::service("gym-web"));
        Transaction {
            id,
            state: TxnState::Prepared,
            lease: Lease { txn: id, owner, epoch: 1, worker_pid, renewed: Timestamp(0), jobs: vec![] },
            base_source: None,
            staged_source: None,
            candidate_nar: None,
            base_override: None,
            candidate_override: None,
            gc_root: None,
            recovery: transition.recovery(),
            transition,
            facts: DerivedFacts {
                affected_units: Vec::new(),
                sensitivity: Sensitivities::default(),
                disruption: Disruptions::of(Disruption::Brief),
                recovery: Recovery::Idempotent,
                touches_manifest: false,
                touches_canonical_probe: false,
                changes_desired: false,
                below_security_floor: false,
                journal_incompatibility: Vec::new(),
                restores_unattributed_stop: false,
                restarts_failed_unit: false,
                removes_sensitivity: Default::default(),
                removes: Default::default(),
                removes_each: Default::default(),
                restarts_held_unit: false,
                other_sessions_affected: false,
                affected_sessions: Vec::new(),
                touches_core: false,
                caller: Actor::Daemon,
                config_diff: None,
            },
            base: GenerationId(1),
            candidate: None,
            policy: PolicyVersion(Hash::ZERO),
            approval: None,
            snapshot: None,
            expected: Expectation {
                units: Default::default(),
                generation: None,
                may_change: Default::default(),
                others_unchanged: true,
                settle: Settle::Duration(Millis::secs(15)),
            },
            started: Timestamp(1_000_000),
            deadline: Timestamp(1_000_000 + 15 * 60 * 1000),
            revert_to: GenerationId(1),
            prior_driver: None,
            check: CheckContext::default(),
            prepared_again_from: None,
        }
    }

    /// One round: new transactions (owner 0 me, 1 another daemon, 2 the
    /// watchdog; mid-flight or not; a worker), some earlier ones advanced
    /// past their last pre-mutation state, maybe a compaction, then a
    /// renewal; and which of this daemon's due leases the watchdog takes
    /// over between reading what is due and renewing.
    type Round = (Vec<(u8, bool, Option<u32>)>, Vec<prop::sample::Index>, bool, Vec<prop::sample::Index>);

    fn round() -> impl Strategy<Value = Round> {
        (
            proptest::collection::vec((0u8..3, any::<bool>(), proptest::option::of(1u32..9999)), 0..5),
            proptest::collection::vec(any::<prop::sample::Index>(), 0..3),
            proptest::bool::weighted(0.2),
            proptest::collection::vec(any::<prop::sample::Index>(), 0..2),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// The coordinator's (#58, after prop-auditor's): after each
        /// renewal, exactly the leases this daemon holds on transactions
        /// mid-flight are fresh, each with its own epoch and worker; not
        /// another daemon's, not the watchdog's, not one before its first
        /// mutation; whatever other handles appended and compacted in
        /// between. A lease taken over between reading what is due and
        /// renewing it refuses only its own record. (Renewing every live
        /// lease, or none, fails it.)
        #[test]
        fn exactly_my_mid_flight_leases_are_renewed(rounds in proptest::collection::vec(round(), 1..6)) {
            let me = OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO };
            let owners = [me.clone(), OwnerId::Daemon { pid: 200, boot_id: Hash::ZERO }, OwnerId::Watchdog { pid: 300, boot_id: Hash::ZERO }];
            let mem = MemStore::new(1 << 20);
            let mut w = Journal::open(mem.clone()).unwrap();
            let mut r = Journal::open(mem.clone()).unwrap();
            let mut t = 10;
            for (fresh, advance, compact, races) in rounds {
                t += 10;
                for (owner, mid, worker) in fresh {
                    let id = TxnId(w.ledger().next_txn.max(1));
                    w.append(Timestamp(t), Record::Prepared(Box::new(txn(id, owners[owner as usize].clone(), worker)))).unwrap();
                    if mid {
                        w.append(Timestamp(t), Record::Advance { txn: id, epoch: 1, to: TxnState::Activating, note: String::new(), withdrawn_for: None }).unwrap();
                    }
                }
                // Advance some transactions still before their first mutation.
                let waiting: Vec<(TxnId, u64)> = w.ledger().live.values().filter(|l| l.txn.state.is_pre_mutation()).map(|l| (l.txn.id, l.txn.lease.epoch)).collect();
                for ix in advance {
                    if waiting.is_empty() { break; }
                    let (id, epoch) = waiting[ix.index(waiting.len())];
                    if w.ledger().live.get(&id).is_some_and(|l| l.txn.state.is_pre_mutation()) {
                        w.append(Timestamp(t), Record::Advance { txn: id, epoch, to: TxnState::Activating, note: String::new(), withdrawn_for: None }).unwrap();
                    }
                }
                if compact {
                    w.compact().unwrap();
                }
                let boot_at = Timestamp(t + 5);
                let d = due(r.sync_ledger().unwrap(), &me);
                let want: Vec<Due> = r.ledger().live.values()
                    .filter(|l| l.txn.lease.owner == me && !l.txn.state.is_pre_mutation())
                    .map(|l| (l.txn.id, l.txn.lease.epoch, l.txn.lease.worker_pid))
                    .collect();
                prop_assert_eq!(&d, &want);
                // The watchdog wins some races after `due` was read.
                let mut raced = vec![];
                for ix in races {
                    if d.is_empty() { break; }
                    let (id, epoch, _) = d[ix.index(d.len())];
                    if raced.contains(&id) { continue; }
                    let lease = Lease { txn: id, owner: owners[2].clone(), epoch: epoch + 1, worker_pid: None, renewed: Timestamp(t), jobs: vec![] };
                    w.append(Timestamp(t), Record::Takeover { txn: id, from_epoch: epoch, lease }).unwrap();
                    raced.push(id);
                }
                let renewed = renew_due(&mut r, &d, Timestamp(t + 5), boot_at);
                prop_assert_eq!(renewed, d.len() - raced.len());
                let l = w.sync_ledger().unwrap().clone();
                for live in l.live.values() {
                    let lease = &live.txn.lease;
                    let should = d.iter().any(|(id, _, _)| *id == live.txn.id) && !raced.contains(&live.txn.id);
                    prop_assert_eq!(
                        lease.renewed == boot_at, should,
                        "txn {:?} ({:?}, {:?}, epoch {}): renewed {:?}", live.txn.id, lease.owner, live.txn.state, lease.epoch, lease.renewed
                    );
                    if should {
                        let (_, epoch, worker) = d.iter().find(|(id, _, _)| *id == live.txn.id).unwrap();
                        prop_assert_eq!((lease.epoch, lease.worker_pid, &lease.owner), (*epoch, *worker, &me));
                    }
                }
            }
        }
    }
}
