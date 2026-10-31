//! Driving one transaction through the journal (§12 step 7, step 8, the
//! crash-recovery table, ownership and fencing).
//!
//! The kernel owns ordering: what is journaled before which backend call, who
//! may advance, and what recovery does from each state. Proposal handling,
//! policy, staging and approval sit above it in `exec`; the backends, probes
//! and process control sit below it, behind `Host`.

use crate::journal::{Journal, JournalError};
use crate::ledger::{LedgerError, LiveTxn, OpRecord, Reconciliation, Record};
use crate::machine::tag;
use crate::store::Store;
use planarian_schema::{
    Actor, Attribution, GenerationBackend, GenerationId, Hash, InventoryBackend, JobId, Lease, Millis, OpId, Outcome,
    Override, OverrideDesired, OwnerId, RecoveryStrategy, RejectReason, Timestamp, Transaction, Transition, TxnId,
    TxnState, UnitId,
};

/// Job-drain wait during takeover (§16 operational limits).
pub const JOB_DRAIN: Millis = Millis::secs(60);
/// How long a lease may go unrenewed before the watchdog treats the owner as gone,
/// once the transaction's deadline has passed.
pub const LEASE_GRACE: Millis = Millis::secs(30);

/// One row of the crash-recovery table (§12): what recovery does from the
/// state a transaction was left in. `Kernel::recover_steps` dispatches on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Nothing was mutated: end `Rejected(Interrupted)`.
    Reject,
    /// A runtime operation: re-observe and commit.
    Reobserve,
    /// A generation was being activated: Checking if the candidate is active, else revert.
    CandidateActive,
    /// A generation was being checked: probes decide.
    CheckGeneration,
    /// The boot entry was written: probes, then publish again and promote, or revert.
    RecheckPublished,
    /// The override was promoted: write Committed.
    WriteCommitted,
    /// A generation revert was under way: run it again (it is idempotent).
    RevertGeneration,
    /// A boot-only publication was under way: ask what was armed (R01).
    Publishing,
    /// A driver was being bound: Checking if it is bound, else revert.
    DriverBound,
    /// A driver bind was being checked: probes decide.
    CheckDevice,
    /// A driver revert was under way: run it again.
    RevertDevice,
    /// A boot-only candidate waits for its boot (§12 step 7): leave it until
    /// a reboot; then confirm it if it booted, else Reverted.
    AwaitBoot,
    /// No recovery path: RecoveryFailed.
    Fail,
}

/// Whether the watchdog should take a transaction over (§12 recovery
/// watchdog): only in the window where mutation may be under way, never from
/// itself, and only when the owner is dead or has let both the transaction's
/// deadline and its lease's grace period pass.
pub fn should_take_over(
    state: &TxnState,
    boot_only: bool,
    mine: bool,
    owner_alive: bool,
    now: Timestamp,
    deadline: Timestamp,
    renewed: Timestamp,
) -> bool {
    // A boot-only Promoted waits for the daemon's confirmation checkpoint
    // (§12 crash table); the watchdog does not advance it.
    let in_window = match state {
        TxnState::Activating
        | TxnState::Checking
        | TxnState::Publishing
        | TxnState::Published
        | TxnState::Reverting => true,
        TxnState::Promoted => !boot_only,
        _ => false,
    };
    if !in_window || mine {
        return false;
    }
    let unrenewed = now > deadline && now > renewed.plus(LEASE_GRACE);
    !owner_alive || unrenewed
}

/// The epoch a takeover writes: above both the journaled lease's and the
/// store's fence (which may be ahead if an earlier takeover crashed between
/// the two writes). `None` when epochs are exhausted.
pub fn next_epoch(lease_epoch: u64, fence: Option<u64>) -> Option<u64> {
    lease_epoch.max(fence.unwrap_or(0)).checked_add(1)
}

/// Whether a backend call tagged with `epoch` may proceed, given the store's
/// fence for its transaction (I15): only the current owner's epoch passes.
pub fn fence_admits(fence: Option<u64>, epoch: u64) -> bool {
    fence == Some(epoch)
}

/// The hash-compared override replacement (§9 step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapStep {
    /// The live file already holds the target.
    Done,
    /// The live file holds the expected source: replace it.
    Swap,
    /// Someone else changed it: never overwrite.
    ThirdParty,
}

pub fn swap_step(current: &Hash, from: &Hash, to: &Hash) -> SwapStep {
    if current == to {
        SwapStep::Done
    } else if current == from {
        SwapStep::Swap
    } else {
        SwapStep::ThirdParty
    }
}

/// The crash-recovery table (§12).
pub fn recovery_action(state: &TxnState, strategy: RecoveryStrategy) -> RecoveryAction {
    use RecoveryAction as A;
    use RecoveryStrategy as S;
    match (state, strategy) {
        (s, _) if s.is_pre_mutation() => A::Reject,
        (TxnState::Activating | TxnState::Checking, S::ReobserveOnly) => A::Reobserve,
        (TxnState::Activating, S::RevertGeneration) => A::CandidateActive,
        (TxnState::Checking, S::RevertGeneration) => A::CheckGeneration,
        (TxnState::Published, S::RevertGeneration) => A::RecheckPublished,
        (TxnState::Promoted, S::RevertGeneration) => A::WriteCommitted,
        (TxnState::Reverting, S::RevertGeneration) => A::RevertGeneration,
        (TxnState::AwaitingBoot, S::RevertGeneration) => A::AwaitBoot,
        (TxnState::Publishing, S::RevertGeneration) => A::Publishing,
        (TxnState::Activating, S::UnbindDevice) => A::DriverBound,
        (TxnState::Checking, S::UnbindDevice) => A::CheckDevice,
        (TxnState::Reverting, S::UnbindDevice) => A::RevertDevice,
        _ => A::Fail,
    }
}

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
    /// runtime option, GC). Override bookkeeping is the kernel's job, not this.
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
    /// The boot clock (`CLOCK_BOOTTIME`): leases, deadlines and waits (§12h).
    fn boot_now(&self) -> Timestamp;
    fn sleep(&self, d: Millis);
    /// SIGTERM then SIGKILL the process group via pidfd; true once confirmed dead.
    fn kill_worker(&self, pid: u32) -> bool;
    fn pid_alive(&self, pid: u32) -> bool;
    /// §12e, I25: the security fixes `txn`'s candidate brings, absent from
    /// the floor generation and every generation between it and the
    /// candidate (every earlier one, with no floor). Part of the commit:
    /// an error here means the transaction does not commit yet.
    fn floor_fixes(&self, _txn: &Transaction, _floor: Option<GenerationId>) -> Result<Vec<String>, Outcome> {
        Ok(vec![])
    }
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
        let deadline = self.host.boot_now().plus(JOB_DRAIN);
        loop {
            match self.host.generations().pending_jobs() {
                Ok(pending) if !jobs.iter().any(|j| pending.contains(j)) => return Ok(true),
                Ok(_) => {}
                Err(_) => return Ok(false),
            }
            if self.host.boot_now() >= deadline {
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
                txn.lease = Lease {
                    txn: id,
                    owner: me,
                    epoch: 1,
                    worker_pid: worker,
                    renewed: self.host.boot_now(),
                    jobs: vec![],
                };
                // Exclusive: an id is never prepared twice (C5).
                j.store().create_fence(id, 1)?;
                let r = j.append(now, Record::Prepared(Box::new(txn))).map(|_| id);
                if r.is_err() {
                    // No record names it; take the fence back.
                    let _ = j.store().forget_fences(|t| t != id);
                }
                r
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

    // ---------- Activation scheduling (§12f) ----------

    /// A verified generation candidate waits in `Built` for an activation
    /// window. It holds no lease-gated mutation and counts as active for I6;
    /// `run` takes it on from there.
    pub fn wait_built(&mut self, id: TxnId, why: &str) -> R<TxnState> {
        let l = self.live(id)?;
        if l.txn.state != TxnState::Built {
            self.advance(&l.txn, TxnState::Built, why)?;
        }
        Ok(TxnState::Built)
    }

    /// The boot-only path (§12 step 7): publish the candidate as a one-shot
    /// next-boot entry, the base still the default, and wait in
    /// `AwaitingBoot`; the boot it was published for confirms or reverts it
    /// (`await_boot`).
    pub fn run_boot_only(&mut self, id: TxnId) -> R<TxnState> {
        let l = self.live(id)?;
        if self.held.get(&id) != Some(&l.txn.lease.epoch) {
            return Err(KernelError::LostLease(id));
        }
        let txn = l.txn;
        let Some((cand, path)) = txn.candidate.clone() else {
            return self.reject(id, RejectReason::Other("no candidate".into()));
        };
        let expected = txn.candidate_nar;
        if self.host.generations().verify_candidate(&path, expected.as_ref()) != Ok(true) {
            return self.reject(id, RejectReason::Other("candidate failed verification".into()));
        }
        self.wait_built(id, "takes effect at boot")?;
        // R01: durable before the first boot mutation, so a crash in the
        // publication is found and asked about, never missed.
        self.advance(&txn, TxnState::Publishing, "publishing to boot once")?;
        // S01: the running generation, which publishes the candidate, stays
        // the default and is the fallback; never known_good automatically.
        let base = txn.base;
        let o = self.call(id, "publish_boot_once", |h, op| h.generations().publish_boot_once(cand, base, op))?;
        if !o.is_success() {
            // All or nothing (the backend's contract): nothing was published.
            let to = TxnState::Rejected(RejectReason::Other(format!("publish_boot_once: {o:?}")));
            self.advance(&txn, to.clone(), "nothing was published")?;
            return Ok(to);
        }
        self.advance(&txn, TxnState::AwaitingBoot, "published to boot once; restart to finish")?;
        Ok(TxnState::AwaitingBoot)
    }

    /// The crash table's Publishing row (§12): the `publish_boot_once` op
    /// acknowledged success → AwaitingBoot; no acknowledgement → ask the boot
    /// loader whether the one-shot entry is armed: armed → AwaitingBoot, not
    /// armed → Rejected(Interrupted); it cannot say → RecoveryFailed.
    fn recover_publishing(&mut self, txn: &Transaction, ops: &[OpRecord]) -> R<TxnState> {
        let Some(cand) = Self::candidate(txn) else {
            return self.recovery_failed(txn, "Publishing without a candidate");
        };
        let publish = ops.iter().rev().find(|o| o.call == "publish_boot_once");
        // Only a definite answer settles it: success armed the entry, and a
        // failure armed nothing (all or nothing). No answer, an Unknown (as a
        // takeover acknowledges the calls it superseded) or a Partial: ask.
        let armed = match publish.and_then(|o| o.ack.as_ref()) {
            Some(Outcome::Succeeded) => true,
            Some(Outcome::Failed(_)) => false,
            _ => match self.host.generations().one_shot_pending() {
                Ok(pending) => pending == Some(cand),
                Err(o) => {
                    return self
                        .recovery_failed(txn, &format!("cannot tell whether the one-shot entry is armed: {o:?}"));
                }
            },
        };
        if armed {
            self.advance(txn, TxnState::AwaitingBoot, "recovery: the one-shot entry is armed")?;
            Ok(TxnState::AwaitingBoot)
        } else {
            let to = TxnState::Rejected(RejectReason::Interrupted);
            self.advance(txn, to.clone(), "recovery: nothing was published")?;
            Ok(to)
        }
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
        let caller = txn.facts.caller.clone();
        // The suppression is journaled before the stop (§12, §14), and before
        // Activating: once the user's "stop" is recorded at all, the repair
        // loop leaves the unit alone, whatever happens to the rest.
        // An override the daemon or an agent sets would be gamed success (§15);
        // a caller that is not a user never gets this far through policy.
        match &txn.transition {
            Transition::StopAndSuppress { unit, until, reason } => {
                let s = Override::attested(
                    unit.clone(),
                    OverrideDesired::Stopped,
                    until.clone(),
                    reason.clone(),
                    caller.clone(),
                );
                self.record(Record::OverrideSet(s))?;
            }
            Transition::SetOverride(s) => match s.desired {
                OverrideDesired::LeaveAlone | OverrideDesired::Stopped => {
                    let s = Override { by: caller.clone(), attribution: Attribution::Attested, ..s.clone() };
                    self.record(Record::OverrideSet(s))?;
                }
                OverrideDesired::Absent | OverrideDesired::Detected => {
                    return self
                        .reject(txn.id, RejectReason::Other("Phase A overrides are LeaveAlone or Stopped".into()));
                }
            },
            _ => {}
        }
        self.advance(txn, TxnState::Activating, "")?;
        let outcome = match &txn.transition {
            Transition::StopAndSuppress { unit, .. } => {
                let stop = Transition::StopUnit(unit.clone());
                self.call(txn.id, "stop", |h, op| h.execute_runtime(&stop, op))?
            }
            // Journaled above; a Stopped override also stops the unit.
            Transition::SetOverride(s) if s.desired == OverrideDesired::Stopped => {
                let stop = Transition::StopUnit(s.unit.clone());
                self.call(txn.id, "stop", |h, op| h.execute_runtime(&stop, op))?
            }
            Transition::SetOverride(_) => Outcome::Succeeded,
            Transition::LiftOverride(u) => {
                self.record(Record::OverrideLifted(u.clone()))?;
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
        let expected = txn.candidate_nar;
        match self.host.generations().verify_candidate(&path, expected.as_ref()) {
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

    /// Activating a generation restarts every active target, and with them
    /// the services they want, including ones a user stopped on purpose.
    /// Stop those again (principle 9: don't fight the user). Idempotent.
    fn restop_suppressed(&mut self, txn: &Transaction) -> R<()> {
        let now = self.host.now();
        let units: Vec<UnitId> = self
            .journal
            .sync_ledger()?
            .overrides
            .iter()
            .filter(|s| s.desired == OverrideDesired::Stopped && s.holds_at(now))
            .map(|s| s.unit.clone())
            .collect();
        for u in units {
            let stop = Transition::StopUnit(u);
            self.call(txn.id, "stop(suppressed)", |h, op| h.execute_runtime(&stop, op))?;
        }
        Ok(())
    }

    /// From Checking: probes decide.
    fn check_then_commit(&mut self, txn: &Transaction) -> R<TxnState> {
        self.restop_suppressed(txn)?;
        match self.host.check(txn, CheckPhase::Candidate) {
            Verdict::Pass => self.commit_from_checking(txn),
            Verdict::Fail(why) => self.revert_generation(txn, &why),
        }
    }

    /// publish_boot → Published → promote → Promoted → Committed. Each step is idempotent.
    /// Only after this owner's own probes passed (check_then_commit).
    fn commit_from_checking(&mut self, txn: &Transaction) -> R<TxnState> {
        let cand = Self::candidate(txn).expect("generation transactions have a candidate");
        let published = self.call(txn.id, "publish_boot", |h, op| h.generations().publish_boot(cand, op))?;
        if !published.is_success() {
            // /boot full and the like: a Checking failure (§12c).
            return self.revert_generation(txn, &format!("publish_boot: {published:?}"));
        }
        self.advance(txn, TxnState::Published, "probes passed")?;
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

    /// The transaction took the boot-only path (§12 step 7): its journal
    /// path passed AwaitingBoot.
    pub fn boot_only(&self, id: TxnId) -> bool {
        self.journal.ledger().live.get(&id).is_some_and(|l| l.boot_only || l.path.iter().any(|p| p == "AwaitingBoot"))
    }

    /// §10 admission of a boot-only candidate that booted and passed its
    /// Readiness probes: it becomes the default and its override is
    /// promoted; the transaction is Promoted (admitted, not confirmed) until
    /// the 10-minute confirmation checkpoint of this boot.
    fn admit_boot_only(&mut self, txn: &Transaction, cand: GenerationId) -> R<TxnState> {
        let o = self.call(txn.id, "publish_boot", |h, op| h.generations().publish_boot(cand, op))?;
        if !o.is_success() {
            return self.withdraw_boot_only(txn, false, &format!("publish_boot: {o:?}"));
        }
        match self.swap_override(txn, txn.base_override, txn.candidate_override)? {
            Swap::Done => {}
            Swap::Failed(why) => return self.withdraw_boot_only(txn, false, &format!("promotion: {why}")),
            Swap::ThirdParty => {
                return self.recovery_failed(txn, "override changed by a third party during promotion");
            }
        }
        self.advance(txn, TxnState::Promoted, "admitted at boot; confirmed at the 10-minute checkpoint")?;
        Ok(TxnState::Promoted)
    }

    /// §10 confirmation, at the 10-minute checkpoint of the boot that
    /// admitted a boot-only candidate (only the daemon calls this): the
    /// candidate still runs and the canonical probes pass → bookkeeping and
    /// Committed; otherwise it is withdrawn (§12 step 7).
    pub fn confirm_boot_only(&mut self, id: TxnId, healthy: bool) -> R<TxnState> {
        let l = self.live(id)?;
        if self.held.get(&id) != Some(&l.txn.lease.epoch) {
            return Err(KernelError::LostLease(id));
        }
        let txn = l.txn;
        if txn.state != TxnState::Promoted || !self.boot_only(id) {
            return Ok(txn.state);
        }
        let running = self.host.generations().last_booted().ok() == Self::candidate(&txn);
        if healthy && running {
            self.write_committed(&txn)
        } else {
            self.withdraw_boot_only(&txn, true, "not confirmed: canonical probes failed at the 10-minute checkpoint")
        }
    }

    /// Withdraw an admitted or published boot-only candidate (§12 step 7):
    /// the publishing generation is the boot default again and the base
    /// override is restored; nothing is activated live, so the machine runs
    /// the candidate until the next restart, which completes it.
    fn withdraw_boot_only(&mut self, txn: &Transaction, promoted: bool, why: &str) -> R<TxnState> {
        if self.live(txn.id)?.txn.state != TxnState::Reverting {
            self.advance(txn, TxnState::Reverting, why)?;
        }
        let back = txn.base;
        let o = self.call(txn.id, "publish_boot(publishing)", |h, op| h.generations().publish_boot(back, op))?;
        if !o.is_success() {
            return self.recovery_failed(txn, &format!("withdraw publish_boot: {o:?}"));
        }
        if promoted {
            match self.swap_override(txn, txn.candidate_override, txn.base_override)? {
                Swap::Done => {}
                Swap::Failed(why) => return self.recovery_failed(txn, &format!("override restore: {why}")),
                Swap::ThirdParty => return self.recovery_failed(txn, "override changed by a third party"),
            }
        }
        self.advance(txn, TxnState::Reverted, why)?;
        Ok(TxnState::Reverted)
    }

    /// A boot-only Promoted found at startup (§12 crash table). The same
    /// boot (a daemon restart): leave it for this boot's checkpoint. A later
    /// boot: the AwaitingBoot row, admission again: the candidate booted and
    /// passes → still Promoted, confirmed at this boot's checkpoint;
    /// otherwise withdrawn.
    fn readmit_boot_only(&mut self, txn: &Transaction, same_boot: bool) -> R<TxnState> {
        if same_boot {
            return Ok(TxnState::Promoted);
        }
        let cand = Self::candidate(txn);
        if self.host.generations().last_booted().ok() != cand {
            return self.withdraw_boot_only(txn, true, "another generation booted before the change was confirmed");
        }
        match self.host.check(txn, CheckPhase::Candidate) {
            Verdict::Pass => Ok(TxnState::Promoted),
            Verdict::Fail(why) => self.withdraw_boot_only(txn, true, &why),
        }
    }

    /// The crash table's AwaitingBoot row (§12): no reboot since the one-shot
    /// entry was published (it is still pending), leave it; after a reboot,
    /// the candidate booted →
    /// the boot-confirmation probes decide (pass: it becomes the default,
    /// Promoted, Committed; fail: revert); it did not boot → Reverted.
    pub fn await_boot(&mut self, txn: &Transaction) -> R<TxnState> {
        let Some(cand) = Self::candidate(txn) else {
            return self.recovery_failed(txn, "AwaitingBoot without a candidate");
        };
        let gens = self.host.generations();
        // Still pending, or the boot loader cannot say: no reboot yet; leave it.
        match gens.one_shot_pending() {
            Ok(Some(g)) if g == cand => return Ok(TxnState::AwaitingBoot),
            Err(_) => return Ok(TxnState::AwaitingBoot),
            _ => {}
        }
        if gens.last_booted().ok() != Some(cand) {
            self.advance(txn, TxnState::Reverted, "the boot-only candidate did not boot; the default entry did")?;
            return Ok(TxnState::Reverted);
        }
        // §10 admission: Readiness probes once; pass → Promoted (admitted);
        // fail → withdrawn, so the next boot falls back.
        match self.host.check(txn, CheckPhase::Candidate) {
            Verdict::Pass => self.admit_boot_only(txn, cand),
            Verdict::Fail(why) => self.withdraw_boot_only(txn, false, &why),
        }
    }

    /// Post-commit bookkeeping, then `Committed` (I25), on every path that
    /// commits a generation: the daemon's, the watchdog's, the boot-only
    /// confirmation's. The floor record precedes `Committed`; if the floor
    /// cannot be derived or journaled, the transaction stays where it is
    /// (`Promoted`) and is completed later, never committed without it.
    fn write_committed(&mut self, txn: &Transaction) -> R<TxnState> {
        if let Some(cand) = Self::candidate(txn) {
            let floor = self.journal.ledger().security_floor;
            if floor.is_none_or(|f| f.0 < cand.0) {
                match self.host.floor_fixes(txn, floor) {
                    Ok(fixes) if !fixes.is_empty() => self.record(Record::SecurityFloor(Some(cand)))?,
                    Ok(_) => {}
                    Err(_) => return Ok(self.live(txn.id)?.txn.state),
                }
            }
            if let Some(h) = &txn.candidate_override {
                let _ = self.host.generations().record_override(cand, h);
            }
        }
        // A boot-only candidate is never live_tested (§10); it is confirmed.
        let boot_only = self.boot_only(txn.id);
        self.advance(txn, TxnState::Committed, "")?;
        if let Some(cand) = Self::candidate(txn)
            && !boot_only
        {
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
        match swap_step(&current, &from, &to) {
            SwapStep::Done => return Ok(Swap::Done),
            SwapStep::ThirdParty => return Ok(Swap::ThirdParty),
            SwapStep::Swap => {}
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
        let (op, activated) =
            self.call_op(txn.id, "activate_live(revert_to)", |h, op| h.generations().activate_live(to, op))?;
        if !activated.is_success() {
            // Never decide from the observed state while the revert's own job may still run.
            if let Err(why) = self.drain_op(txn.id, &op)? {
                return self.recovery_failed(txn, &format!("revert activation: {why}"));
            }
        }
        if !activated.is_success() && self.host.generations().current().ok() != Some(to) {
            return self.recovery_failed(txn, &format!("revert activation: {activated:?}"));
        }
        self.restop_suppressed(txn)?;
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
        should_take_over(
            &txn.state,
            self.boot_only(txn.id),
            txn.lease.owner == self.me,
            // An owner from an earlier boot is gone, whatever now holds its pid.
            txn.lease.owner.boot_id() == self.me.boot_id() && self.host.pid_alive(txn.lease.owner.pid()),
            self.host.boot_now(),
            txn.deadline,
            txn.lease.renewed,
        )
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
            let fence = j.store().fence(id).map_err(|e| KernelError::Journal(e.into()))?;
            let epoch = next_epoch(old.epoch, fence).ok_or(KernelError::LostLease(id))?;
            let new =
                Lease { txn: id, owner: me, epoch, worker_pid: worker, renewed: self.host.boot_now(), jobs: vec![] };
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
        let before = self.live(id)?.txn;
        let same_boot = before.lease.owner.boot_id() == self.me.boot_id();
        if self.take_over(id, seen_epoch)?.is_none() {
            return Ok(TxnState::RecoveryFailed);
        }
        if before.state == TxnState::Promoted && self.boot_only(id) {
            let txn = self.live(id)?.txn;
            return self.readmit_boot_only(&txn, same_boot);
        }
        self.recover_steps(id)
    }

    /// The crash-recovery table (§12), as `recovery_action` gives it.
    /// Assumes this handle holds the lease.
    fn recover_steps(&mut self, id: TxnId) -> R<TxnState> {
        let l = self.live(id)?;
        let txn = l.txn;
        use RecoveryAction as A;
        match recovery_action(&txn.state, txn.recovery) {
            A::Reject => self.reject(id, RejectReason::Interrupted),
            // Activating: a StopAndSuppress whose suppression is durable but whose
            // stop may not have happened: the suppression holds; re-observe and record.
            A::Reobserve => self.finish_reobserve(&txn),
            A::CandidateActive => {
                let cand = Self::candidate(&txn);
                if cand.is_some() && self.host.generations().current().ok() == cand {
                    self.advance(&txn, TxnState::Checking, "recovery: candidate is active")?;
                    self.check_then_commit(&txn)
                } else {
                    self.revert_generation(&txn, "recovery: candidate not active")
                }
            }
            A::CheckGeneration => self.check_then_commit(&txn),
            A::RecheckPublished => match self.host.check(&txn, CheckPhase::Candidate) {
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
            A::WriteCommitted => self.write_committed(&txn),
            A::RevertGeneration => self.revert_generation(&txn, "recovery: re-run revert"),
            A::DriverBound => {
                let Transition::BindDriver { device, driver } = &txn.transition else { unreachable!() };
                if self.host.inventory().bound_driver(device).ok().flatten().as_ref() == Some(driver) {
                    self.advance(&txn, TxnState::Checking, "recovery: candidate driver bound")?;
                    self.check_device(&txn)
                } else {
                    self.revert_device(&txn, "recovery: candidate driver not bound")
                }
            }
            A::CheckDevice => self.check_device(&txn),
            A::RevertDevice => self.revert_device(&txn, "recovery: re-run revert"),
            A::AwaitBoot => self.await_boot(&txn),
            A::Publishing => self.recover_publishing(&txn, &l.ops),
            A::Fail => {
                let why = format!("no recovery path for {} under {:?}", tag(&txn.state), txn.recovery);
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
                let why = if t.why.is_empty() { String::new() } else { format!("; because {}", t.why) };
                actions.push(format!(
                    "txn {}: the watchdog took over and finished it: {} (path {}){why}",
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
