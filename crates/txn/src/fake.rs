//! In-memory fake backends for the txn-kernel harness (catalog `harness = "fake"`).
//!
//! One `FakeWorld` is shared by every `FakeHost`, the same way the daemon and the
//! watchdog share one machine. Fencing reads the epochs in the shared `MemStore`,
//! as real backends read the journal's. Every mutating call is logged, so tests
//! can assert that calls never overlap and that stale owners were refused.

use crate::kernel::{CheckPhase, Host, Verdict};
use crate::store::{MemStore, Store};
use planarian_schema::{
    Built, DeviceInfo, DriverRef, EvaluatedGeneration, GenerationBackend, GenerationId, Hash, InventoryBackend, JobId,
    Millis, Observed, OpId, OverrideSet, PinnedSource, Resources, StagedSource, StorePath, Timestamp, Transaction,
    Transition, UnitId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Debug)]
pub struct FakeJob {
    pub op: OpId,
    pub done_at: Timestamp,
    pub cancellable: bool,
    /// The generation that becomes current when the job completes.
    pub activates: Option<GenerationId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallLog {
    pub at: Timestamp,
    pub op: OpId,
    pub call: String,
    pub fenced: bool,
    /// Supervisor jobs pending when the call was admitted.
    pub pending: usize,
}

#[derive(Debug, Default)]
pub struct World {
    pub now: Timestamp,
    pub current: GenerationId,
    pub boot_default: GenerationId,
    pub boot_entries: BTreeSet<GenerationId>,
    pub generations: BTreeMap<GenerationId, StorePath>,
    /// Generations whose probes fail.
    pub bad: BTreeSet<GenerationId>,
    /// Every probe fails (an environmental fault coinciding with a change).
    pub env_fault: bool,
    pub override_hash: Hash,
    pub units: BTreeMap<UnitId, Observed>,
    pub devices: BTreeMap<UnitId, Option<DriverRef>>,
    /// Probes fail while any device is bound to one of these drivers.
    pub bad_drivers: BTreeSet<String>,
    pub jobs: BTreeMap<JobId, FakeJob>,
    pub next_job: u64,
    /// `activate_live` accepts the job but never replies; the job runs for this long.
    pub slow_activation: Option<(Millis, bool)>,
    /// `activate_live` of these generations fails outright.
    pub fail_activate: BTreeSet<GenerationId>,
    pub fail_publish: bool,
    pub jobs_tagged_unknown: bool,
    pub calls: Vec<CallLog>,
    pub alive: BTreeSet<u32>,
    pub unkillable: BTreeSet<u32>,
    pub gc_roots: BTreeSet<String>,
}

impl World {
    fn tick(&mut self) {
        let now = self.now;
        let done: Vec<JobId> = self.jobs.iter().filter(|(_, j)| j.done_at <= now).map(|(id, _)| id.clone()).collect();
        for id in done {
            let job = self.jobs.remove(&id).expect("listed");
            if let Some(g) = job.activates {
                self.current = g;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct FakeHost {
    pub world: Arc<Mutex<World>>,
    pub store: MemStore,
}

impl FakeHost {
    pub fn new(world: Arc<Mutex<World>>, store: MemStore) -> FakeHost {
        FakeHost { world, store }
    }

    pub fn w(&self) -> MutexGuard<'_, World> {
        let mut w = self.world.lock().unwrap_or_else(|e| e.into_inner());
        w.tick();
        w
    }

    /// Fence and log a mutating call. Returns false if the call must be refused.
    fn admit(&self, w: &mut World, op: &OpId, call: &str) -> bool {
        let current = self.store.fence(op.txn).ok().flatten();
        let fenced = !crate::kernel::fence_admits(current, op.epoch);
        let pending = w.jobs.len();
        w.calls.push(CallLog { at: w.now, op: *op, call: call.into(), fenced, pending });
        !fenced
    }
}

use planarian_schema::Outcome;

impl GenerationBackend for FakeHost {
    fn current(&self) -> Result<GenerationId, Outcome> {
        Ok(self.w().current)
    }

    fn boot_entries(&self) -> Result<Vec<GenerationId>, Outcome> {
        Ok(self.w().boot_entries.iter().copied().collect())
    }

    fn boot_default(&self) -> Result<GenerationId, Outcome> {
        Ok(self.w().boot_default)
    }

    fn last_booted(&self) -> Result<GenerationId, Outcome> {
        Ok(self.w().boot_default)
    }

    fn stage(&self, _owner: &PinnedSource, _overrides: &OverrideSet) -> Result<StagedSource, Outcome> {
        Err(Outcome::Failed("fake: staging is exec's concern".into()))
    }

    fn source_hash(&self, _owner: &PinnedSource) -> Result<Hash, Outcome> {
        Err(Outcome::Failed("fake: staging is exec's concern".into()))
    }

    fn evaluate(&self, _src: &StagedSource) -> Result<EvaluatedGeneration, Outcome> {
        Err(Outcome::Failed("fake: evaluation is exec's concern".into()))
    }

    fn build(&self, _eval: &EvaluatedGeneration) -> Result<Built, Outcome> {
        Err(Outcome::Failed("fake: building is exec's concern".into()))
    }

    fn verify_candidate(&self, path: &StorePath, _expected: &Hash) -> Result<bool, Outcome> {
        Ok(self.w().generations.values().any(|p| p == path))
    }

    fn pending_jobs(&self) -> Result<Vec<JobId>, Outcome> {
        Ok(self.w().jobs.keys().cloned().collect())
    }

    fn jobs_tagged(&self, op: &OpId) -> Result<Option<Vec<JobId>>, Outcome> {
        let w = self.w();
        if w.jobs_tagged_unknown {
            return Ok(None);
        }
        Ok(Some(w.jobs.iter().filter(|(_, j)| j.op == *op).map(|(id, _)| id.clone()).collect()))
    }

    fn override_hash(&self) -> Result<Hash, Outcome> {
        Ok(self.w().override_hash)
    }

    fn activate_live(&self, g: GenerationId, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, &format!("activate_live({})", g.0)) {
            return Outcome::fenced();
        }
        if w.fail_activate.contains(&g) {
            return Outcome::Failed(format!("activation of {} failed (injected)", g.0));
        }
        if let Some((delay, cancellable)) = w.slow_activation {
            w.next_job += 1;
            let id = JobId(format!("job-{}", w.next_job));
            let done_at = w.now.plus(delay);
            w.jobs.insert(id, FakeJob { op: *op, done_at, cancellable, activates: Some(g) });
            return Outcome::Unknown("job accepted; reply withheld".into());
        }
        w.current = g;
        Outcome::Succeeded
    }

    fn publish_boot(&self, g: GenerationId, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, &format!("publish_boot({})", g.0)) {
            return Outcome::fenced();
        }
        if w.fail_publish {
            return Outcome::Failed("ENOSPC on /boot (injected)".into());
        }
        w.boot_entries.insert(g);
        w.boot_default = g;
        Outcome::Succeeded
    }

    fn protect(&self, g: GenerationId, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, &format!("protect({})", g.0)) {
            return Outcome::fenced();
        }
        Outcome::Succeeded
    }

    fn cancel(&self, job: &JobId, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, &format!("cancel({})", job.0)) {
            return Outcome::fenced();
        }
        match w.jobs.get(job) {
            Some(j) if j.cancellable => {
                w.jobs.remove(job);
                Outcome::Succeeded
            }
            Some(_) => Outcome::Failed("job cannot be cancelled".into()),
            None => Outcome::Succeeded,
        }
    }

    fn swap_override(&self, from: &Hash, to: &Hash, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, "swap_override") {
            return Outcome::fenced();
        }
        if w.override_hash == *to {
            return Outcome::Succeeded;
        }
        if w.override_hash != *from {
            return Outcome::Failed("override changed by a third party".into());
        }
        w.override_hash = *to;
        Outcome::Succeeded
    }

    fn path_of(&self, g: GenerationId) -> Result<StorePath, Outcome> {
        self.w().generations.get(&g).cloned().ok_or_else(|| Outcome::Failed(format!("no generation {}", g.0)))
    }

    fn evaluate_built(&self, _path: &StorePath) -> Result<EvaluatedGeneration, Outcome> {
        Err(Outcome::Failed("fake: evaluation is exec's concern".into()))
    }

    fn read_overrides(&self) -> Result<(OverrideSet, Hash), Outcome> {
        Ok((OverrideSet::default(), self.w().override_hash))
    }

    fn remember_override(&self, set: &OverrideSet) -> Result<Hash, Outcome> {
        Ok(Hash::of(&serde_json::to_vec(set).expect("serializes")))
    }

    fn override_for(&self, _g: GenerationId) -> Result<Option<Hash>, Outcome> {
        Ok(None)
    }

    fn record_override(&self, _g: GenerationId, _hash: &Hash) -> Result<(), Outcome> {
        Ok(())
    }

    fn release_root(&self, root: &str) -> bool {
        self.w().gc_roots.remove(root)
    }

    fn collect_garbage(&self, _protect: &[GenerationId], _emergency: bool, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, "collect_garbage") {
            return Outcome::fenced();
        }
        Outcome::Succeeded
    }

    fn gc_plan(&self, _protect: &[GenerationId], _emergency: bool) -> Result<planarian_schema::gc::GcPlan, Outcome> {
        Ok(planarian_schema::gc::plan(&[], &[], 0, 0, |_| 0))
    }

    fn space_report(&self) -> Option<planarian_schema::gc::SpaceReport> {
        None
    }
}

impl InventoryBackend for FakeHost {
    fn devices(&self) -> Result<Vec<DeviceInfo>, Outcome> {
        Ok(self.w().devices.iter().map(|(id, d)| DeviceInfo { id: id.clone(), driver: d.clone() }).collect())
    }

    fn resources(&self) -> Result<Resources, Outcome> {
        Ok(Resources::default())
    }

    fn bound_driver(&self, device: &UnitId) -> Result<Option<DriverRef>, Outcome> {
        Ok(self.w().devices.get(device).cloned().flatten())
    }

    fn bind(&self, device: &UnitId, driver: &DriverRef, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, &format!("bind({device}, {})", driver.name)) {
            return Outcome::fenced();
        }
        w.devices.insert(device.clone(), Some(driver.clone()));
        Outcome::Succeeded
    }

    fn unbind(&self, device: &UnitId, op: &OpId) -> Outcome {
        let mut w = self.w();
        if !self.admit(&mut w, op, &format!("unbind({device})")) {
            return Outcome::fenced();
        }
        w.devices.insert(device.clone(), None);
        Outcome::Succeeded
    }
}

impl Host for FakeHost {
    type Gen = FakeHost;
    type Inv = FakeHost;

    fn generations(&self) -> &FakeHost {
        self
    }

    fn inventory(&self) -> &FakeHost {
        self
    }

    fn execute_runtime(&self, t: &Transition, op: &OpId) -> Outcome {
        let mut w = self.w();
        let name = match t {
            Transition::RestartUnit(u) => format!("restart({u})"),
            Transition::StopUnit(u) => format!("stop({u})"),
            other => format!("{other:?}"),
        };
        if !self.admit(&mut w, op, &name) {
            return Outcome::fenced();
        }
        match t {
            Transition::RestartUnit(u) => {
                w.units.insert(u.clone(), Observed::Active);
            }
            Transition::StopUnit(u) => {
                w.units.insert(u.clone(), Observed::Bound);
            }
            _ => {}
        }
        Outcome::Succeeded
    }

    fn reobserve(&self, _txn: &Transaction) -> Outcome {
        Outcome::Succeeded
    }

    fn check(&self, _txn: &Transaction, _phase: CheckPhase) -> Verdict {
        let w = self.w();
        if w.env_fault {
            return Verdict::Fail("canonical probe failed (environment)".into());
        }
        if w.bad.contains(&w.current) {
            return Verdict::Fail(format!("probes fail on generation {}", w.current.0));
        }
        if let Some((dev, d)) =
            w.devices.iter().find(|(_, d)| d.as_ref().is_some_and(|d| w.bad_drivers.contains(&d.name)))
        {
            return Verdict::Fail(format!("{dev} bound to {}", d.as_ref().expect("checked").name));
        }
        Verdict::Pass
    }

    fn release_gc_root(&self, path: &str) -> bool {
        self.w().gc_roots.remove(path)
    }

    fn now(&self) -> Timestamp {
        self.w().now
    }

    fn sleep(&self, d: Millis) {
        let mut w = self.w();
        w.now = w.now.plus(d);
        w.tick();
    }

    fn kill_worker(&self, pid: u32) -> bool {
        let mut w = self.w();
        if w.unkillable.contains(&pid) {
            return false;
        }
        w.alive.remove(&pid);
        true
    }

    fn pid_alive(&self, pid: u32) -> bool {
        self.w().alive.contains(&pid)
    }
}
