//! Driving one transaction through the journal (§12 step 7, step 8, the
//! crash-recovery table, ownership and fencing).
//!
//! The kernel owns ordering: what is journaled before which backend call, who
//! may advance, and what recovery does from each state. Proposal handling,
//! policy, staging and approval sit above it in `exec`; the backends, probes
//! and process control sit below it, behind `Host`.

use crate::journal::{Journal, JournalError};
use crate::ledger::{LedgerError, LiveTxn, Reconciliation, Record};
use crate::machine::tag;
use crate::store::Store;
use planarian_schema::{
    Actor, GenerationBackend, GenerationId, Hash, InventoryBackend, JobId, Lease, Millis, OpId, Outcome, OwnerId,
    RecoveryStrategy, RejectReason, Suppression, Timestamp, Transaction, Transition, TxnId, TxnState,
};

/// Job-drain wait during takeover (§16 operational limits).
pub const JOB_DRAIN: Millis = Millis::secs(60);
/// How long a lease may go unrenewed before the watchdog treats the owner as gone,
/// once the transaction's deadline has passed.
pub const LEASE_GRACE: Millis = Millis::secs(30);

/// Which probe run a check belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckPhase {
    /// After activating the candidate (or binding the new driver).
    Candidate,
    /// After reverting.
    Revert,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail(String),
}

/// Everything the kernel needs from below. One generic parameter (no `dyn`, §6).
pub trait Host {
    type Gen: GenerationBackend;
    type Inv: InventoryBackend;

    fn generations(&self) -> &Self::Gen;
    fn inventory(&self) -> &Self::Inv;
    /// Perform a `ReobserveOnly` transition's backend effect (restart, stop,
    /// runtime option, GC). Suppression bookkeeping is the kernel's job, not this.
    fn execute_runtime(&self, t: &Transition, op: &OpId) -> Outcome;
    /// Settle, then observe and compare against the expectation; the outcome is
    /// recorded, never acted on (§12 step 7, UnitOp).
    fn reobserve(&self, txn: &Transaction) -> Outcome;
    /// Run the applicable Readiness probes from the candidate's UnitDefs and the
    /// installed core, plus the expectation and executor-owned requirements.
    fn check(&self, txn: &Transaction, phase: CheckPhase) -> Verdict;
    /// Remove a GC root (I3). Returns false if it could not be removed.
    fn release_gc_root(&self, path: &str) -> bool;
    fn now(&self) -> Timestamp;
    fn sleep(&self, d: Millis);
    /// SIGTERM then SIGKILL the process group via pidfd; true once confirmed dead.
    fn kill_worker(&self, pid: u32) -> bool;
    fn pid_alive(&self, pid: u32) -> bool;
}

#[derive(Debug)]
pub enum KernelError {
    Journal(JournalError),
    /// A fault-injected crash (fake harness): this handle must be discarded.
    Crashed,
    /// Another owner holds the lease; this handle no longer owns the transaction.
    LostLease(TxnId),
    NotLive(TxnId),
}

impl From<JournalError> for KernelError {
    fn from(e: JournalError) -> Self {
        match e {
            JournalError::Ledger(LedgerError::StaleEpoch { txn, .. }) => KernelError::LostLease(txn),
            e => KernelError::Journal(e),
        }
    }
}

type R<T> = Result<T, KernelError>;

/// Fault injection for the fake harness: stop dead (as if SIGKILLed) right after
/// a record is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// After the Advance record into this state (by `machine::tag`).
    State(&'static str),
    /// After the OpBegin record for this call, before the call is made.
    OpBegun(&'static str),
    /// After the call returned, before its OpAck is journaled.
    OpCalled(&'static str),
}

pub struct Kernel<S: Store, H: Host> {
    pub journal: Journal<S>,
    pub host: H,
    pub me: OwnerId,
    pub crash_at: Option<CrashPoint>,
    /// The worker pid recorded in leases this handle takes.
    pub worker_pid: Option<u32>,
    /// Epochs this handle holds, by transaction. Every record and backend call
    /// carries the handle's own epoch, never the ledger's current one, so a
    /// handle whose lease was taken is refused (I15).
    held: std::collections::BTreeMap<TxnId, u64>,
}

impl<S: Store, H: Host> Kernel<S, H> {
    pub fn new(journal: Journal<S>, host: H, me: OwnerId) -> Self {
        Kernel { journal, host, me, crash_at: None, worker_pid: None, held: Default::default() }
    }

    fn live(&mut self, id: TxnId) -> R<LiveTxn> {
        self.journal.sync_ledger()?.live.get(&id).cloned().ok_or(KernelError::NotLive(id))
    }

    fn epoch(&self, txn: TxnId) -> R<u64> {
        self.held.get(&txn).copied().ok_or(KernelError::LostLease(txn))
    }

    fn record(&mut self, r: Record) -> R<()> {
        let now = self.host.now();
        let txn = match &r {
            Record::Advance { txn, .. } | Record::Takeover { txn, .. } | Record::Renew { txn, .. } => Some(*txn),
            Record::OpBegin { op, .. } | Record::OpAck { op, .. } => Some(op.txn),
            _ => None,
        };
        match self.journal.append(now, r) {
            Err(JournalError::Full) => {
                // A transaction that may already have mutated the system cannot
                // be left without a record: fixed-size sentinel, interlock (§12c).
                let mutating =
                    txn.and_then(|t| self.journal.ledger().live.get(&t)).filter(|l| !l.txn.state.is_pre_mutation());
                if let Some(l) = mutating {
                    let id = l.txn.id;
                    self.journal.write_sentinel(id, "journal full on the recovery path")?;
                }
                Err(KernelError::Journal(JournalError::Full))
            }
            r => r.map(|_| ()).map_err(KernelError::from),
        }
    }

    fn advance(&mut self, txn: &Transaction, to: TxnState, note: &str) -> R<()> {
        let epoch = self.epoch(txn.id)?;
        let rec = Record::Advance { txn: txn.id, epoch, to: to.clone(), note: note.into() };
        self.record(rec)?;
        if to.is_terminal()
            && to != TxnState::Committed
            && let Some(root) = &txn.gc_root
        {
            self.host.release_gc_root(root);
        }
        if self.crash_at == Some(CrashPoint::State(tag(&to))) {
            return Err(KernelError::Crashed);
        }
        Ok(())
    }

    /// Journal a durable OpId, then make the mutating call tagged with it, then
    /// journal its outcome.
    fn call(&mut self, txn: TxnId, name: &'static str, f: impl FnOnce(&H, &OpId) -> Outcome) -> R<Outcome> {
        self.call_op(txn, name, f).map(|(_, o)| o)
    }

    fn call_op(&mut self, txn: TxnId, name: &'static str, f: impl FnOnce(&H, &OpId) -> Outcome) -> R<(OpId, Outcome)> {
        let epoch = self.epoch(txn)?;
        let l = self.journal.sync_ledger()?.live.get(&txn).cloned().ok_or(KernelError::NotLive(txn))?;
        let op = OpId { txn, epoch, seq: l.ops.len() as u64 + 1 };
        self.record(Record::OpBegin { op, call: name.into() })?;
        if self.crash_at == Some(CrashPoint::OpBegun(name)) {
            return Err(KernelError::Crashed);
        }
        let outcome = f(&self.host, &op);
        if outcome.is_fenced() {
            return Err(KernelError::LostLease(txn));
        }
        if self.crash_at == Some(CrashPoint::OpCalled(name)) {
            return Err(KernelError::Crashed);
        }
        self.record(Record::OpAck { op, outcome: outcome.clone() })?;
        Ok((op, outcome))
    }

    /// After a call that did not report success, make sure the work it started
    /// has stopped before deciding anything from the observed state: wait for
    /// its tagged jobs, cancel what remains, and wait again.
    fn drain_op(&mut self, txn: TxnId, op: &OpId) -> R<Result<(), String>> {
        let jobs = match self.host.generations().jobs_tagged(op) {
            Ok(Some(jobs)) => jobs,
            Ok(None) => return Ok(Err(format!("backend cannot say what op {op} started"))),
            Err(o) => return Ok(Err(format!("jobs_tagged({op}): {o:?}"))),
        };
        if jobs.is_empty() || self.wait_gone(&jobs)? {
            return Ok(Ok(()));
        }
        for job in &jobs {
            self.call(txn, "cancel", |h, op| h.generations().cancel(job, op))?;
        }
        if self.wait_gone(&jobs)? {
            Ok(Ok(()))
        } else {
            Ok(Err(format!("jobs of op {op} still pending after cancel and {}s drain", JOB_DRAIN.0 / 1000)))
        }
    }

    /// Wait up to `JOB_DRAIN` for `jobs` to leave the supervisor's queue.
    fn wait_gone(&mut self, jobs: &[JobId]) -> R<bool> {
        let deadline = self.host.now().plus(JOB_DRAIN);
        loop {
            match self.host.generations().pending_jobs() {
                Ok(pending) if !jobs.iter().any(|j| pending.contains(j)) => return Ok(true),
                Ok(_) => {}
                Err(_) => return Ok(false),
            }
            if self.host.now() >= deadline {
                return Ok(false);
            }
            self.host.sleep(Millis::secs(1));
        }
    }

    // ---------- Creation and pre-mutation exits ----------

    /// Journal `Prepared` (§12 step 4) with this handle as owner at epoch 1.
    /// The transaction's id is assigned here.
    pub fn prepare(&mut self, mut txn: Transaction) -> R<TxnId> {
        // Keep the preallocation's headroom for recovery records (§12c).
        if self.journal.needs_compaction() {
            self.journal.compact()?;
        }
        let now = self.host.now();
        let me = self.me.clone();
        let worker = self.worker_pid;
        self.journal
            .locked(|j| {
                let id = TxnId(j.ledger().next_txn.max(1));
                txn.id = id;
                txn.state = TxnState::Prepared;
                txn.recovery = txn.transition.recovery();
                txn.lease = Lease { txn: id, owner: me, epoch: 1, worker_pid: worker, renewed: now, jobs: vec![] };
                j.store().set_fence(id, 1)?;
                j.append(now, Record::Prepared(Box::new(txn))).map(|_| id)
            })?
            .map_err(KernelError::from)
            .inspect(|id| {
                self.held.insert(*id, 1);
            })
    }

    /// Terminal `Rejected` from a pre-mutation state (§12 step 5).
    pub fn reject(&mut self, id: TxnId, reason: RejectReason) -> R<TxnState> {
        let l = self.live(id)?;
        let to = TxnState::Rejected(reason);
        self.advance(&l.txn, to.clone(), "rejected before mutation")?;
        Ok(to)
    }

    pub fn cancel(&mut self, id: TxnId, by: Actor) -> R<TxnState> {
        let l = self.live(id)?;
        let to = TxnState::Cancelled(by);
        self.advance(&l.txn, to.clone(), "withdrawn before mutation")?;
        Ok(to)
    }

    // ---------- Fresh execution ----------

    /// Execute a prepared (and, if AskFirst, approved) transaction to a terminal state.
    pub fn run(&mut self, id: TxnId) -> R<TxnState> {
        let l = self.live(id)?;
        if self.held.get(&id) != Some(&l.txn.lease.epoch) {
            return Err(KernelError::LostLease(id));
        }
        if !l.txn.state.is_pre_mutation() {
            return self.recover_steps(id);
        }
        match l.txn.recovery {
            RecoveryStrategy::ReobserveOnly => self.run_reobserve(&l.txn),
            RecoveryStrategy::RevertGeneration => self.run_generation(&l.txn),
            RecoveryStrategy::UnbindDevice => self.run_device(&l.txn),
            RecoveryStrategy::RestoreSnapshotThenRevert => {
                // Phase C. Refuse rather than run half a protocol.
                self.reject(id, RejectReason::Other("RestoreSnapshot is Phase C".into()))
            }
        }
    }

    fn run_reobserve(&mut self, txn: &Transaction) -> R<TxnState> {
        self.advance(txn, TxnState::Activating, "")?;
        let caller = txn.facts.caller.clone();
        let outcome = match &txn.transition {
            Transition::StopAndSuppress { unit, until, reason } => {
                // The suppression is journaled before the stop (§12, §14).
                let s = Suppression { unit: unit.clone(), until: until.clone(), reason: reason.clone(), by: caller };
                self.record(Record::Suppressed(s))?;
                let stop = Transition::StopUnit(unit.clone());
                self.call(txn.id, "stop", |h, op| h.execute_runtime(&stop, op))?
            }
            Transition::Suppress(s) => {
                let s = Suppression { by: caller, ..s.clone() };
                self.record(Record::Suppressed(s))?;
                Outcome::Succeeded
            }
            Transition::Unsuppress(u) => {
                self.record(Record::Unsuppressed(u.clone()))?;
                Outcome::Succeeded
            }
            Transition::Resolve { txn: target, resolution } => {
                self.record(Record::Resolved { txn: *target, resolution: *resolution, by: caller })?;
                Outcome::Succeeded
            }
            t => {
                let t = t.clone();
                self.call(txn.id, "runtime", |h, op| h.execute_runtime(&t, op))?
            }
        };
        self.advance(txn, TxnState::Checking, &format!("{outcome:?}"))?;
        self.finish_reobserve(txn)
    }

    fn finish_reobserve(&mut self, txn: &Transaction) -> R<TxnState> {
        let observed = self.host.reobserve(txn);
        self.advance(txn, TxnState::Committed, &format!("observed: {observed:?}"))?;
        Ok(TxnState::Committed)
    }

    fn candidate(txn: &Transaction) -> Option<GenerationId> {
        txn.candidate.as_ref().map(|(g, _)| *g)
    }

    fn run_generation(&mut self, txn: &Transaction) -> R<TxnState> {
        let Some((cand, path)) = txn.candidate.clone() else {
            return self.reject(txn.id, RejectReason::Other("no candidate".into()));
        };
        let expected = txn.staged_source.unwrap_or(Hash::ZERO);
        match self.host.generations().verify_candidate(&path, &expected) {
            Ok(true) => {}
            _ => return self.reject(txn.id, RejectReason::Other("candidate failed verification".into())),
        }
        self.advance(txn, TxnState::Activating, "")?;
        let (op, outcome) = self.call_op(txn.id, "activate_live", |h, op| h.generations().activate_live(cand, op))?;
        if !outcome.is_success()
            && let Err(why) = self.drain_op(txn.id, &op)?
        {
            return self.recovery_failed(txn, &why);
        }
        if outcome.is_success() || self.host.generations().current().ok() == Some(cand) {
            self.advance(txn, TxnState::Checking, &format!("{outcome:?}"))?;
            self.check_then_commit(txn)
        } else {
            self.revert_generation(txn, &format!("activation: {outcome:?}"))
        }
    }

    /// From Checking: probes decide.
    fn check_then_commit(&mut self, txn: &Transaction) -> R<TxnState> {
        match self.host.check(txn, CheckPhase::Candidate) {
            Verdict::Pass => self.commit_from_checking(txn),
            Verdict::Fail(why) => self.revert_generation(txn, &why),
        }
    }

    /// publish_boot → Published → promote → Promoted → Committed. Each step is idempotent.
    fn commit_from_checking(&mut self, txn: &Transaction) -> R<TxnState> {
        let cand = Self::candidate(txn).expect("generation transactions have a candidate");
        let published = self.call(txn.id, "publish_boot", |h, op| h.generations().publish_boot(cand, op))?;
        if !published.is_success() {
            // /boot full and the like: a Checking failure (§12c).
            return self.revert_generation(txn, &format!("publish_boot: {published:?}"));
        }
        self.advance(txn, TxnState::Published, "")?;
        self.promote_and_commit(txn)
    }

    fn promote_and_commit(&mut self, txn: &Transaction) -> R<TxnState> {
        match self.swap_override(txn, txn.base_override, txn.candidate_override)? {
            Swap::Done => {}
            Swap::Failed(why) => return self.revert_generation(txn, &format!("promotion: {why}")),
            Swap::ThirdParty => {
                self.advance(txn, TxnState::RecoveryFailed, "override changed by a third party during promotion")?;
                return Ok(TxnState::RecoveryFailed);
            }
        }
        self.advance(txn, TxnState::Promoted, "")?;
        self.write_committed(txn)
    }

    fn write_committed(&mut self, txn: &Transaction) -> R<TxnState> {
        self.advance(txn, TxnState::Committed, "")?;
        if let Some(cand) = Self::candidate(txn) {
            self.record(Record::LiveTested(Some(cand)))?;
        }
        Ok(TxnState::Committed)
    }

    /// Hash-compared, idempotent override replacement (§9 step 4): if the live
    /// file already hashes to `to`, done; if it hashes to `from`, swap; anything
    /// else means a third party changed it.
    fn swap_override(&mut self, txn: &Transaction, from: Option<Hash>, to: Option<Hash>) -> R<Swap> {
        let (Some(from), Some(to)) = (from, to) else {
            return Ok(Swap::Done);
        };
        let current = match self.host.generations().override_hash() {
            Ok(h) => h,
            Err(o) => return Ok(Swap::Failed(format!("{o:?}"))),
        };
        if current == to {
            return Ok(Swap::Done);
        }
        if current != from {
            return Ok(Swap::ThirdParty);
        }
        let o = self.call(txn.id, "swap_override", |h, op| h.generations().swap_override(&from, &to, op))?;
        Ok(if o.is_success() { Swap::Done } else { Swap::Failed(format!("{o:?}")) })
    }

    fn revert_generation(&mut self, txn: &Transaction, why: &str) -> R<TxnState> {
        let state = self.live(txn.id)?.txn.state;
        if state != TxnState::Reverting {
            self.advance(txn, TxnState::Reverting, why)?;
        }
        let to = txn.revert_to;
        let activated = self.call(txn.id, "activate_live(revert_to)", |h, op| h.generations().activate_live(to, op))?;
        if !activated.is_success() && self.host.generations().current().ok() != Some(to) {
            return self.recovery_failed(txn, &format!("revert activation: {activated:?}"));
        }
        let published = self.call(txn.id, "publish_boot(revert_to)", |h, op| h.generations().publish_boot(to, op))?;
        if !published.is_success() {
            return self.recovery_failed(txn, &format!("revert publish_boot: {published:?}"));
        }
        match self.swap_override(txn, txn.candidate_override, txn.base_override)? {
            Swap::Done => {}
            Swap::Failed(why) => return self.recovery_failed(txn, &format!("override restore: {why}")),
            Swap::ThirdParty => return self.recovery_failed(txn, "override changed by a third party"),
        }
        match self.host.check(txn, CheckPhase::Revert) {
            Verdict::Pass => {
                self.advance(txn, TxnState::Reverted, why)?;
                Ok(TxnState::Reverted)
            }
            Verdict::Fail(f) => self.recovery_failed(txn, &format!("revert probes: {f}")),
        }
    }

    fn recovery_failed(&mut self, txn: &Transaction, why: &str) -> R<TxnState> {
        self.advance(txn, TxnState::RecoveryFailed, why)?;
        Ok(TxnState::RecoveryFailed)
    }

    fn run_device(&mut self, txn: &Transaction) -> R<TxnState> {
        let Transition::BindDriver { device, driver } = &txn.transition else {
            return self.reject(txn.id, RejectReason::Other("device op without BindDriver".into()));
        };
        self.advance(txn, TxnState::Activating, &format!("previous driver: {:?}", txn.prior_driver))?;
        let (device, driver) = (device.clone(), driver.clone());
        let bound = self.call(txn.id, "bind", |h, op| h.inventory().bind(&device, &driver, op))?;
        if !bound.is_success() {
            return self.revert_device(txn, &format!("bind: {bound:?}"));
        }
        self.advance(txn, TxnState::Checking, "")?;
        self.check_device(txn)
    }

    fn check_device(&mut self, txn: &Transaction) -> R<TxnState> {
        match self.host.check(txn, CheckPhase::Candidate) {
            Verdict::Pass => {
                self.advance(txn, TxnState::Committed, "")?;
                Ok(TxnState::Committed)
            }
            Verdict::Fail(why) => self.revert_device(txn, &why),
        }
    }

    /// Unbind and rebind the previously bound driver; never a generation rollback.
    fn revert_device(&mut self, txn: &Transaction, why: &str) -> R<TxnState> {
        let Transition::BindDriver { device, .. } = &txn.transition else { unreachable!("device op") };
        let device = device.clone();
        if self.live(txn.id)?.txn.state != TxnState::Reverting {
            self.advance(txn, TxnState::Reverting, why)?;
        }
        let unbound = self.call(txn.id, "unbind", |h, op| h.inventory().unbind(&device, op))?;
        if !unbound.is_success() && self.host.inventory().bound_driver(&device).ok() != Some(None) {
            return self.recovery_failed(txn, &format!("unbind: {unbound:?}"));
        }
        if let Some(prev) = txn.prior_driver.clone() {
            let rebound = self.call(txn.id, "bind(previous)", |h, op| h.inventory().bind(&device, &prev, op))?;
            if !rebound.is_success() {
                return self.recovery_failed(txn, &format!("rebind previous: {rebound:?}"));
            }
        }
        match self.host.check(txn, CheckPhase::Revert) {
            Verdict::Pass => {
                self.advance(txn, TxnState::Reverted, why)?;
                Ok(TxnState::Reverted)
            }
            Verdict::Fail(f) => self.recovery_failed(txn, &format!("revert probes: {f}")),
        }
    }

    // ---------- Ownership ----------

    /// Whether the watchdog should take this transaction over (§12 recovery watchdog).
    pub fn watchdog_should_take_over(&self, txn: &Transaction) -> bool {
        let in_window = matches!(
            txn.state,
            TxnState::Activating | TxnState::Checking | TxnState::Published | TxnState::Promoted | TxnState::Reverting
        );
        if !in_window || txn.lease.owner == self.me {
            return false;
        }
        let now = self.host.now();
        let owner_dead = !self.host.pid_alive(txn.lease.owner.pid());
        let unrenewed = now > txn.deadline && now > txn.lease.renewed.plus(LEASE_GRACE);
        owner_dead || unrenewed
    }

    /// Take the lease (epoch + 1), fence the old owner, establish confirmed
    /// quiescence. Returns the lease this handle now holds, or `Ok(None)` if
    /// quiescence could not be confirmed (RecoveryFailed has been written).
    /// `seen_epoch` is the epoch the caller based its decision on; if another
    /// owner took over since, this one backs off with `LostLease`.
    pub fn take_over(&mut self, id: TxnId, seen_epoch: u64) -> R<Option<Lease>> {
        let now = self.host.now();
        let me = self.me.clone();
        let worker = self.worker_pid;
        let (old, new) = self.journal.locked(|j| -> Result<(Lease, Lease), KernelError> {
            let l = j.ledger().live.get(&id).cloned().ok_or(KernelError::NotLive(id))?;
            let old = l.txn.lease.clone();
            if old.epoch != seen_epoch {
                return Err(KernelError::LostLease(id));
            }
            // The fence may already be ahead of the journal if a previous
            // takeover crashed between the two writes.
            let fence = j.store().fence(id).map_err(|e| KernelError::Journal(e.into()))?.unwrap_or(0);
            let epoch = old.epoch.max(fence) + 1;
            let new = Lease { txn: id, owner: me, epoch, worker_pid: worker, renewed: now, jobs: vec![] };
            // Fence first: from here on the old owner's calls are refused.
            j.store().set_fence(id, epoch).map_err(|e| KernelError::Journal(e.into()))?;
            j.append(now, Record::Takeover { txn: id, from_epoch: old.epoch, lease: new.clone() })?;
            Ok((old, new))
        })??;
        self.held.insert(id, new.epoch);

        let l = self.live(id)?;
        if l.txn.state.is_pre_mutation() {
            return Ok(Some(new));
        }
        match self.quiesce(&l, &old)? {
            Ok(()) => Ok(Some(new)),
            Err(why) => {
                self.advance(&l.txn, TxnState::RecoveryFailed, &format!("quiescence not confirmed: {why}"))?;
                Ok(None)
            }
        }
    }

    /// Kill the old worker; cancel every job in the old lease and every job
    /// tagged with an unacknowledged OpId; wait for them to leave the queue.
    fn quiesce(&mut self, l: &LiveTxn, old: &Lease) -> R<Result<(), String>> {
        if let Some(pid) = old.worker_pid
            && !self.host.kill_worker(pid)
        {
            return Ok(Err(format!("worker {pid} did not die")));
        }
        let mut jobs: Vec<JobId> = old.jobs.clone();
        let unacked: Vec<OpId> = l.unacked_ops().map(|o| o.op).collect();
        for op in &unacked {
            match self.host.generations().jobs_tagged(op) {
                Ok(Some(found)) => jobs.extend(found),
                Ok(None) => return Ok(Err(format!("backend cannot say what op {op} started"))),
                Err(o) => return Ok(Err(format!("jobs_tagged({op}): {o:?}"))),
            }
        }
        jobs.sort();
        jobs.dedup();
        for job in &jobs {
            self.call(l.txn.id, "cancel", |h, op| h.generations().cancel(job, op))?;
        }
        if !self.wait_gone(&jobs)? {
            return Ok(Err(format!("jobs still pending after {}s drain", JOB_DRAIN.0 / 1000)));
        }
        for op in unacked {
            self.record(Record::OpAck { op, outcome: Outcome::Unknown("superseded by takeover".into()) })?;
        }
        Ok(Ok(()))
    }

    // ---------- Recovery ----------

    /// Take over (from `seen_epoch`) and run the crash-recovery table.
    pub fn recover(&mut self, id: TxnId, seen_epoch: u64) -> R<TxnState> {
        if self.take_over(id, seen_epoch)?.is_none() {
            return Ok(TxnState::RecoveryFailed);
        }
        self.recover_steps(id)
    }

    /// The crash-recovery table (§12). Assumes this handle holds the lease.
    fn recover_steps(&mut self, id: TxnId) -> R<TxnState> {
        let l = self.live(id)?;
        let txn = l.txn;
        use RecoveryStrategy as S;
        match (&txn.state, txn.recovery) {
            (s, _) if s.is_pre_mutation() => self.reject(id, RejectReason::Interrupted),
            (TxnState::Activating, S::ReobserveOnly) => {
                // A StopAndSuppress whose suppression is durable but whose stop
                // may not have happened: the suppression holds; re-observe and record.
                self.finish_reobserve(&txn)
            }
            (TxnState::Checking, S::ReobserveOnly) => self.finish_reobserve(&txn),
            (TxnState::Activating, S::RevertGeneration) => {
                let cand = Self::candidate(&txn);
                if cand.is_some() && self.host.generations().current().ok() == cand {
                    self.advance(&txn, TxnState::Checking, "recovery: candidate is active")?;
                    self.check_then_commit(&txn)
                } else {
                    self.revert_generation(&txn, "recovery: candidate not active")
                }
            }
            (TxnState::Checking, S::RevertGeneration) => self.check_then_commit(&txn),
            (TxnState::Published, S::RevertGeneration) => match self.host.check(&txn, CheckPhase::Candidate) {
                Verdict::Pass => {
                    let cand = Self::candidate(&txn).expect("candidate");
                    let o = self.call(id, "publish_boot", |h, op| h.generations().publish_boot(cand, op))?;
                    if !o.is_success() {
                        return self.revert_generation(&txn, &format!("publish_boot: {o:?}"));
                    }
                    self.promote_and_commit(&txn)
                }
                Verdict::Fail(why) => self.revert_generation(&txn, &why),
            },
            (TxnState::Promoted, S::RevertGeneration) => self.write_committed(&txn),
            (TxnState::Reverting, S::RevertGeneration) => self.revert_generation(&txn, "recovery: re-run revert"),
            (TxnState::Activating, S::UnbindDevice) => {
                let Transition::BindDriver { device, driver } = &txn.transition else { unreachable!() };
                if self.host.inventory().bound_driver(device).ok().flatten().as_ref() == Some(driver) {
                    self.advance(&txn, TxnState::Checking, "recovery: candidate driver bound")?;
                    self.check_device(&txn)
                } else {
                    self.revert_device(&txn, "recovery: candidate driver not bound")
                }
            }
            (TxnState::Checking, S::UnbindDevice) => self.check_device(&txn),
            (TxnState::Reverting, S::UnbindDevice) => self.revert_device(&txn, "recovery: re-run revert"),
            (s, strategy) => {
                let why = format!("no recovery path for {} under {strategy:?}", tag(s));
                self.recovery_failed(&txn, &why)
            }
        }
    }

    /// Daemon start (§12 daemon restart reconciliation): wait out transactions a
    /// live watchdog holds, recover the rest, and journal what was found and done.
    /// Returns the transactions left to a live watchdog.
    pub fn reconcile(&mut self) -> R<Vec<TxnId>> {
        let live: Vec<LiveTxn> = self.journal.sync_ledger()?.live.values().cloned().collect();
        let mut found = vec![];
        let mut actions = vec![];
        let mut waiting = vec![];
        for l in live {
            found.push((l.txn.id, l.txn.state.clone()));
            let holder = &l.txn.lease.owner;
            if holder.is_watchdog() && self.host.pid_alive(holder.pid()) {
                actions.push(format!("txn {}: held by the watchdog; waiting", l.txn.id.0));
                waiting.push(l.txn.id);
                continue;
            }
            let end = self.recover(l.txn.id, l.txn.lease.epoch)?;
            actions.push(format!("txn {}: found {}, now {}", l.txn.id.0, tag(&l.txn.state), tag(&end)));
        }
        // Report what the watchdog finished while this daemon was down.
        let ledger = self.journal.ledger();
        for (id, t) in ledger.terminal.iter().rev().take(16) {
            if t.owner.is_watchdog() {
                found.push((*id, t.state.clone()));
                actions.push(format!(
                    "txn {}: the watchdog took over and finished it: {} (path {})",
                    id.0,
                    tag(&t.state),
                    t.path.join(" → ")
                ));
            }
        }
        self.record(Record::Reconciliation(Reconciliation { by: self.me.clone(), found, actions }))?;
        Ok(waiting)
    }
}

enum Swap {
    Done,
    Failed(String),
    ThirdParty,
}
