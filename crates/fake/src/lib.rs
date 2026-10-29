//! A fake machine: every backend trait, in memory, deterministic.
//!
//! It models what the catalog's fake-harness cases need. The NixOS side has
//! generations, an owner source tree, the override file, a tiny evaluator
//! (option rules that break, remove or alter units), builds, live activation,
//! boot entries and GC. The systemd side has units that crash, flap, fail on
//! start, or are restarted by systemd itself. Devices have drivers. logind
//! has sessions. There are external dependencies, runtime options, and
//! processes (owner and worker pids). Fencing reads the epochs in the shared
//! journal store, as real backends read the journal's.
//!
//! Time advances only through `Clock::sleep` or `Fake::advance`.

use planarian_changes::render;
use planarian_schema::*;
pub use planarian_txn::store::MemStore;
use planarian_txn::store::Store;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The unit fails to start in generations where the rule holds.
    Break(UnitId),
    /// The unit is not part of such generations (disabled).
    Remove(UnitId),
    /// The evaluated unit files for planariad change (touches_core).
    TouchCore,
    /// The probe definition on a unit changes (a manifest edit).
    ReplaceProbe(UnitId, ProbeDef),
    /// Kernel/boot change: needs a reboot to be confirmed.
    NeedsReboot,
    /// A system service the generation declares (watched or not), defined in
    /// `file` (§15 provenance). `gym-bad-payload` is the catalog's payload:
    /// it takes gym-web's port `PAYLOAD_DELAY` after it comes up.
    Declare { service: String, file: String },
    /// The package at this version, with or without nixpkgs'
    /// `knownVulnerabilities` (§12e).
    Package { name: String, version: String, insecure: bool },
}

/// An outcome injected into the next call of one name (the gym's
/// `backend_result` and the assumptions conformance run): the effect lands
/// but the call reports failure (Partial) or cannot say (Unknown), or the
/// call is refused before any effect as if fenced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Injected {
    Partial,
    Unknown,
    Fenced,
}

/// If option `option` evaluates to `value`, apply `effect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub option: String,
    pub value: Value,
    pub effect: Effect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Health {
    Ok,
    /// Http probes get a 503; the process stays active.
    Http503,
    /// The service answers requests after this long (Http probes); it still
    /// accepts connections at once.
    Delay(Millis),
    /// Every network probe, connecting included, takes this long (the port
    /// is unreachable rather than slow).
    Stall(Millis),
}

#[derive(Clone, Debug)]
pub struct UnitSim {
    pub observed: Observed,
    /// How the main process last ended (`ended_by`).
    pub ended: Option<Ending>,
    pub health: Health,
    /// Exits this long after each start (flapping).
    pub fail_after: Option<Millis>,
    /// Fails every start (corrupt state file).
    pub fail_on_start: bool,
    /// systemd `Restart=` with this RestartSec.
    pub systemd_restart: Option<Millis>,
    pub started_at: Timestamp,
    pub failed_at: Option<Timestamp>,
    pub restarts: u32,
    /// Restarts systemd made on its own (`NRestarts`).
    pub auto_restarts: u32,
}

impl UnitSim {
    pub fn active(now: Timestamp) -> UnitSim {
        UnitSim {
            observed: Observed::Active,
            ended: None,
            health: Health::Ok,
            fail_after: None,
            fail_on_start: false,
            systemd_restart: None,
            started_at: now,
            failed_at: None,
            restarts: 0,
            auto_restarts: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Gen {
    pub path: StorePath,
    pub eval: EvaluatedGeneration,
    pub broken: BTreeSet<UnitId>,
    /// The profile link's owner and time (`created_by`).
    pub created: (u32, Timestamp),
}

/// How long the gym's bad payload behaves before it takes gym-web's port:
/// past any generation check (§15 malicious declaration).
pub const PAYLOAD_DELAY: Millis = Millis::secs(240);

#[derive(Clone, Debug)]
pub struct Job {
    pub op: OpId,
    pub done_at: Timestamp,
    pub cancellable: bool,
    pub activates: GenerationId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub at: Timestamp,
    pub op: OpId,
    pub call: String,
    pub fenced: bool,
}

#[derive(Debug, Default)]
pub struct World {
    pub now: Timestamp,
    // ---- NixOS ----
    /// The owner's configuration as evaluated without any override.
    pub base_units: UnitDefs,
    pub base_user_units: Vec<UnitDef>,
    pub base_options: BTreeMap<String, Value>,
    /// The base generation's packages (pname → version) and the insecure ones (§12e).
    pub base_packages: BTreeMap<String, String>,
    pub base_insecure: BTreeSet<String>,
    /// Outcomes to inject, by call name (`restart`, `activate_live`, …), once each.
    pub inject: BTreeMap<String, Injected>,
    /// The owner flake's inputs, name → (rev, store path).
    pub base_inputs: BTreeMap<String, (String, String)>,
    /// Who the next out-of-band generation is created by (uid).
    pub rebuild_uid: u32,
    /// When the bad payload takes gym-web's port (set when a generation
    /// declaring it is applied).
    pub payload_at: Option<Timestamp>,
    pub rules: Vec<Rule>,
    /// Options the owner `mkForce`d.
    pub forced: BTreeSet<String>,
    pub core_units: BTreeMap<String, Hash>,
    /// Tracked owner files (path → content) and untracked ones.
    pub owner_files: BTreeMap<String, String>,
    pub untracked: BTreeSet<String>,
    pub gens: BTreeMap<GenerationId, Gen>,
    pub current: GenerationId,
    pub booted: GenerationId,
    pub boot_default: GenerationId,
    pub boot_entries: BTreeSet<GenerationId>,
    pub overrides: OverrideSet,
    pub override_store: BTreeMap<Hash, OverrideSet>,
    pub gen_overrides: BTreeMap<GenerationId, Hash>,
    pub staged: BTreeMap<String, (OverrideSet, BTreeMap<String, String>)>,
    pub gc_roots: BTreeSet<String>,
    pub collected: Vec<GenerationId>,
    pub fail_publish: bool,
    /// Drivers that bind but cannot drive the device.
    pub bad_drivers: BTreeSet<String>,
    /// Hooks for faults that happen during a transaction: the owner edits a
    /// tracked file while staging; the store fills during the build; a port is
    /// blocked when the candidate activates.
    pub edit_on_stage: bool,
    /// The owner adds this untracked file while staging (after the copy).
    pub untracked_on_stage: Option<String>,
    pub nospace_on_build: bool,
    /// How many times `build` ran.
    pub builds: usize,
    pub block_on_activate: BTreeSet<UnitId>,
    pub fail_activate: BTreeSet<GenerationId>,
    pub slow_activation: Option<(Millis, bool)>,
    pub jobs: BTreeMap<JobId, Job>,
    /// When each job started, and when it finished or was cancelled.
    pub job_spans: BTreeMap<JobId, (Job, Timestamp, Option<Timestamp>)>,
    pub next_job: u64,
    pub jobs_tagged_unknown: bool,
    // ---- systemd / logind / devices ----
    pub units: BTreeMap<UnitId, UnitSim>,
    pub devices: BTreeMap<UnitId, Option<DriverRef>>,
    pub sessions: Vec<SessionInfo>,
    /// Whether the compositor runs in each session's cgroup (§9); a session
    /// not listed falls back to the user's graphical-session target.
    pub compositors: BTreeMap<String, bool>,
    /// A generation published to boot once (§12f), and generations whose boot
    /// fails (the gym's `fail_boot`).
    pub one_shot: Option<GenerationId>,
    pub fail_one_shot: bool,
    /// Units planted outside the generation (the boot report finds them).
    pub foreign_units: Vec<String>,
    /// Sessions in which foreground work holds (§10 quiet mode).
    pub foreground: BTreeSet<String>,
    pub power: Option<PowerSource>,
    /// Probes of these units fail regardless (e.g. a port blocked by nftables).
    pub blocked: BTreeSet<UnitId>,
    /// External dependencies that are down, by name (`gym-upstream`).
    pub external_down: BTreeSet<String>,
    /// External dependencies whose traffic is dropped on the way (a dead
    /// gateway): their probes, and their clients', time out.
    pub external_unreachable: BTreeSet<String>,
    /// How many probe batches ran (a status request must not run one).
    pub probe_batches: u64,
    /// Free bytes and size of filesystems, by path.
    pub fs: BTreeMap<String, (u64, u64)>,
    /// §12b bounds, and the last collection's report. Each generation's
    /// closure counts as `GEN_BYTES`, nothing shared.
    pub gc_budget: gc::GcBudget,
    pub space_report: Option<gc::SpaceReport>,
    pub runtime: BTreeMap<String, Value>,
    /// Wi-Fi: the networks NetworkManager knows, and those in range.
    pub wifi_known: Vec<String>,
    pub wifi_in_range: BTreeSet<String>,
    // ---- processes ----
    pub alive: BTreeSet<u32>,
    pub unkillable: BTreeSet<u32>,
    pub calls: Vec<Call>,
}

impl World {
    fn key(id: &UnitId) -> UnitId {
        let mut k = id.clone();
        if let Scope::User { uid, .. } = k.scope {
            k.scope = Scope::User { uid, session: None };
        }
        k
    }

    fn override_hash_of(set: &OverrideSet) -> Hash {
        Hash::of(render(set).as_bytes())
    }

    fn source_hash_of(files: &BTreeMap<String, String>, overrides: &OverrideSet) -> Hash {
        let mut bytes = serde_json::to_vec(files).expect("files serialize");
        bytes.extend(render(overrides).as_bytes());
        Hash::of(&bytes)
    }

    /// The fake evaluator.
    pub fn evaluate(&self, overrides: &OverrideSet) -> (EvaluatedGeneration, BTreeSet<UnitId>) {
        let mut options = self.base_options.clone();
        for (k, v) in &overrides.assignments {
            if !self.forced.contains(k) {
                options.insert(k.clone(), v.clone());
            }
        }
        let mut units = self.base_units.clone();
        let mut core = self.core_units.clone();
        let mut broken = BTreeSet::new();
        let mut needs_reboot = false;
        let mut packages = self.base_packages.clone();
        let mut insecure = self.base_insecure.clone();
        let mut declarations: BTreeMap<String, Vec<String>> = self
            .base_units
            .keys()
            .filter(|u| u.kind == UnitKind::Service && u.scope == Scope::System)
            .map(|u| (u.name.clone(), vec!["/etc/nixos/configuration.nix".to_string()]))
            .collect();
        for r in &self.rules {
            if options.get(&r.option) != Some(&r.value) {
                continue;
            }
            match &r.effect {
                Effect::Break(u) => {
                    broken.insert(u.clone());
                }
                Effect::Remove(u) => {
                    units.remove(u);
                    declarations.remove(&u.name);
                }
                Effect::Declare { service, file } => {
                    declarations.entry(service.clone()).or_default().push(file.clone());
                }
                Effect::TouchCore => {
                    core.insert("planariad.service".into(), Hash::of(b"changed"));
                }
                Effect::ReplaceProbe(u, p) => {
                    if let Some(d) = units.get_mut(u) {
                        d.probes.retain(|x| x.id != p.id);
                        d.probes.push(p.clone());
                    }
                }
                Effect::NeedsReboot => needs_reboot = true,
                Effect::Package { name, version, insecure: bad } => {
                    packages.insert(name.clone(), version.clone());
                    if *bad {
                        insecure.insert(name.clone());
                    } else {
                        insecure.remove(name);
                    }
                }
            }
        }
        let locked = overrides.assignments.keys().filter(|k| self.forced.contains(*k)).cloned().collect();
        let eval = EvaluatedGeneration {
            source: Hash::ZERO,
            options,
            units,
            user_units: self.base_user_units.clone(),
            activation: ActivationPlan { needs_reboot_to_confirm: needs_reboot, ..Default::default() },
            locked,
            core_units: core,
            packages,
            insecure,
            declarations,
            inputs: self.base_inputs.clone(),
        };
        (eval, broken)
    }

    pub fn add_generation(&mut self, overrides: &OverrideSet) -> GenerationId {
        let (eval, broken) = self.evaluate(overrides);
        let id = GenerationId(self.gens.keys().map(|g| g.0).max().unwrap_or(0) + 1);
        let path = StorePath(format!("/nix/store/{:03}-nixos-system-fake", id.0));
        let created = (self.rebuild_uid, self.now);
        self.gens.insert(id, Gen { path, eval, broken, created });
        id
    }

    pub fn apply_generation(&mut self, g: GenerationId) {
        let generation = self.gens[&g].clone();
        let now = self.now;
        for id in generation.eval.units.keys() {
            if id.kind != UnitKind::Service || id.name.starts_with("external:") {
                continue;
            }
            let sim = self.units.entry(id.clone()).or_insert_with(|| UnitSim::active(now));
            if generation.broken.contains(id) || sim.fail_on_start {
                sim.observed = Observed::Failed(Reason::ExitCode(1));
                sim.ended = Some(Ending::Exited(1));
                sim.failed_at = Some(now);
            } else if sim.observed != Observed::Active {
                sim.observed = Observed::Active;
                sim.started_at = now;
            }
        }
        // The bad payload starts with the generation and bides its time.
        self.payload_at = if generation.eval.declarations.contains_key("gym-bad-payload") {
            self.payload_at.or(Some(now.plus(PAYLOAD_DELAY)))
        } else {
            // Gone with its generation: the port is free again.
            if self.payload_at == Some(Timestamp(u64::MAX))
                && let Some(web) = self.units.get_mut(&UnitId::service("gym-web"))
            {
                web.fail_on_start = false;
            }
            None
        };
        // Units the generation no longer has are stopped and gone.
        let gone: Vec<UnitId> = self
            .units
            .keys()
            .filter(|u| {
                u.scope == Scope::System && u.kind == UnitKind::Service && !generation.eval.units.contains_key(u)
            })
            .cloned()
            .collect();
        for u in gone {
            self.units.get_mut(&u).expect("listed").observed = Observed::Absent;
        }
        self.current = g;
    }

    /// Advance time-driven behaviour to `now`.
    pub fn advance_to(&mut self, now: Timestamp) {
        self.now = now;
        // It takes gym-web's port: gym-web crashes and cannot start again.
        if self.payload_at.is_some_and(|t| t <= now) {
            self.payload_at = Some(Timestamp(u64::MAX));
            if let Some(web) = self.units.get_mut(&UnitId::service("gym-web")) {
                web.fail_on_start = true;
                web.observed = Observed::Failed(Reason::ExitCode(1));
                web.ended = Some(Ending::Signal(11));
                web.failed_at = Some(now);
            }
        }
        let done: Vec<JobId> = self.jobs.iter().filter(|(_, j)| j.done_at <= now).map(|(k, _)| k.clone()).collect();
        for id in done {
            let job = self.jobs.remove(&id).expect("listed");
            if let Some(span) = self.job_spans.get_mut(&id) {
                span.2 = Some(job.done_at);
            }
            self.apply_generation(job.activates);
        }
        let broken = self.gens.get(&self.current).map(|g| g.broken.clone()).unwrap_or_default();
        for (id, sim) in self.units.iter_mut() {
            if sim.observed == Observed::Active
                && let Some(after) = sim.fail_after
                && now.0 >= sim.started_at.0 + after.0
            {
                sim.observed = Observed::Failed(Reason::ExitCode(1));
                sim.ended = Some(Ending::Exited(1));
                sim.failed_at = Some(Timestamp(sim.started_at.0 + after.0));
            }
            if let (Observed::Failed(_), Some(rs), Some(at)) = (&sim.observed, sim.systemd_restart, sim.failed_at)
                && now.0 >= at.0 + rs.0
            {
                sim.restarts += 1;
                sim.auto_restarts += 1;
                if sim.fail_on_start || broken.contains(id) {
                    sim.failed_at = Some(now);
                } else {
                    sim.observed = Observed::Active;
                    sim.started_at = now;
                }
            }
        }
    }

    /// `systemctl stop` outside Planarian: systemd also stops every unit that
    /// `Requires=` it (transitively).
    pub fn stop_out_of_band(&mut self, unit: &UnitId) {
        let mut todo = vec![unit.clone()];
        while let Some(u) = todo.pop() {
            if let Some(sim) = self.units.get_mut(&u)
                && sim.observed == Observed::Active
            {
                // A stop job: SIGTERM, then inactive.
                sim.observed = Observed::Bound;
                sim.ended = Some(Ending::Signal(15));
            }
            for (id, d) in &self.base_units {
                if d.edges.iter().any(|e| e.to == u && e.kind == EdgeKind::Requires) {
                    todo.push(id.clone());
                }
            }
        }
    }

    /// SIGKILL a unit's main process.
    pub fn kill(&mut self, unit: &UnitId) {
        self.signal(unit, 9);
    }

    /// Send `sig` to a unit's main process, as `systemctl kill` does. SIGTERM,
    /// SIGINT, SIGHUP and SIGPIPE are clean exits to systemd (inactive); any
    /// other signal fails the unit.
    pub fn signal(&mut self, unit: &UnitId, sig: i32) {
        let now = self.now;
        if let Some(sim) = self.units.get_mut(unit) {
            sim.ended = Some(Ending::Signal(sig));
            if matches!(sig, 1 | 2 | 13 | 15) {
                sim.observed = Observed::Bound;
            } else {
                sim.observed = Observed::Failed(Reason::ExitCode(128 + sig));
                sim.failed_at = Some(now);
            }
        }
    }

    /// The kernel's OOM killer ends the unit (`Result=oom-kill`).
    pub fn oom(&mut self, unit: &UnitId) {
        let now = self.now;
        if let Some(sim) = self.units.get_mut(unit) {
            sim.ended = Some(Ending::OomKill);
            sim.observed = Observed::Failed(Reason::ExitCode(137));
            sim.failed_at = Some(now);
        }
    }

    pub fn reboot(&mut self) {
        // A one-shot entry boots once; one that fails to boot falls back to
        // the default (the boot loader's own fallback).
        self.booted = match self.one_shot.take() {
            Some(g) if !self.fail_one_shot => g,
            _ => self.boot_default,
        };
        let now = self.now;
        for id in self.jobs.keys() {
            if let Some(span) = self.job_spans.get_mut(id) {
                span.2 = Some(now);
            }
        }
        self.jobs.clear();
        self.sessions.clear();
        let g = self.booted;
        for sim in self.units.values_mut() {
            sim.observed = Observed::Bound;
        }
        self.apply_generation(g);
    }

    fn start(&mut self, id: &UnitId) -> Outcome {
        let now = self.now;
        let broken = self.gens.get(&self.current).is_some_and(|g| g.broken.contains(id));
        let present =
            self.gens.get(&self.current).is_none_or(|g| g.eval.units.contains_key(id) || id.scope != Scope::System);
        if !present {
            return Outcome::Failed(format!("{id} not found"));
        }
        let sim = self.units.entry(Self::key(id)).or_insert_with(|| UnitSim::active(now));
        sim.restarts += 1;
        if broken || sim.fail_on_start {
            sim.observed = Observed::Failed(Reason::ExitCode(1));
            sim.ended = Some(Ending::Exited(1));
            sim.failed_at = Some(now);
            return Outcome::Failed(format!("{id} failed to start"));
        }
        sim.observed = Observed::Active;
        sim.health = Health::Ok;
        sim.started_at = now;
        Outcome::Succeeded
    }
}

/// The handle every backend trait is implemented on. Cheap to clone; all
/// clones share one world and one journal store.
#[derive(Clone, Debug)]
pub struct Fake {
    pub world: Arc<Mutex<World>>,
    pub store: MemStore,
}

impl Fake {
    pub fn new(world: World, store: MemStore) -> Fake {
        Fake { world: Arc::new(Mutex::new(world)), store }
    }

    pub fn w(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn advance(&self, d: Millis) {
        let mut w = self.w();
        let t = w.now.plus(d);
        w.advance_to(t);
    }

    fn admit(&self, w: &mut World, op: &OpId, call: String) -> bool {
        let fenced = self.store.fence(op.txn).ok().flatten() != Some(op.epoch);
        w.calls.push(Call { at: w.now, op: *op, call, fenced });
        !fenced
    }

    /// One mutating backend call: fenced on a stale epoch before any effect
    /// (docs/assumptions.md), and subject to an injected outcome
    /// (`World::inject`, keyed by the call's name before its parenthesis).
    fn run(&self, op: &OpId, call: String, f: impl FnOnce(&mut World) -> Outcome) -> Outcome {
        let mut w = self.w();
        let name = call.split('(').next().unwrap_or("").to_string();
        let injected = w.inject.remove(&name);
        if injected == Some(Injected::Fenced) {
            let at = w.now;
            w.calls.push(Call { at, op: *op, call, fenced: true });
            return Outcome::fenced();
        }
        if !self.admit(&mut w, op, call) {
            return Outcome::fenced();
        }
        let out = f(&mut w);
        match injected {
            Some(Injected::Partial) => Outcome::Failed("partially applied (injected)".into()),
            Some(Injected::Unknown) => Outcome::Unknown("no answer (injected)".into()),
            _ => out,
        }
    }
}

impl UnitBackend for Fake {
    fn observe(&self, id: &UnitId) -> Result<Observed, Outcome> {
        let w = self.w();
        Ok(w.units.get(&World::key(id)).map(|s| s.observed.clone()).unwrap_or(Observed::Absent))
    }

    fn ended_by(&self, id: &UnitId) -> Option<Ending> {
        self.w().units.get(&World::key(id)).and_then(|s| s.ended)
    }

    fn auto_restarts(&self, id: &UnitId) -> Option<u32> {
        self.w().units.get(&World::key(id)).map(|s| s.auto_restarts)
    }

    fn foreign_units(&self) -> Vec<String> {
        self.w().foreign_units.clone()
    }

    fn list(&self) -> Result<Vec<UnitId>, Outcome> {
        Ok(self.w().units.keys().cloned().collect())
    }

    fn restart(&self, id: &UnitId, op: &OpId) -> Outcome {
        self.run(op, format!("restart({id})"), |w| w.start(id))
    }

    fn stop(&self, id: &UnitId, op: &OpId) -> Outcome {
        self.run(op, format!("stop({id})"), |w| {
            let now = w.now;
            let sim = w.units.entry(World::key(id)).or_insert_with(|| UnitSim::active(now));
            sim.observed = Observed::Bound;
            Outcome::Succeeded
        })
    }
}

impl GenerationBackend for Fake {
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
        Ok(self.w().booted)
    }

    fn created_by(&self, g: GenerationId) -> Option<(u32, Timestamp)> {
        self.w().gens.get(&g).map(|x| x.created)
    }

    fn stage(&self, _owner: &PinnedSource, overrides: &OverrideSet) -> Result<StagedSource, Outcome> {
        let mut w = self.w();
        let dir = format!("/var/lib/planarian/stage/{}", w.staged.len() + 1);
        let files = w.owner_files.clone();
        let base = w.overrides.clone();
        w.staged.insert(dir.clone(), (overrides.clone(), files.clone()));
        let candidate_override = World::override_hash_of(overrides);
        w.override_store.insert(candidate_override, overrides.clone());
        if std::mem::take(&mut w.edit_on_stage) {
            w.owner_files.insert("configuration.nix".into(), "{ edited-during-build = true; }".into());
        }
        let excluded: Vec<String> = w.untracked.iter().cloned().collect();
        if let Some(f) = w.untracked_on_stage.take() {
            w.untracked.insert(f);
        }
        Ok(StagedSource {
            dir,
            base_source: World::source_hash_of(&files, &base),
            staged_source: World::source_hash_of(&files, overrides),
            base_override: World::override_hash_of(&base),
            candidate_override,
            excluded,
        })
    }

    fn source_hash(&self, _owner: &PinnedSource) -> Result<Hash, Outcome> {
        let w = self.w();
        Ok(World::source_hash_of(&w.owner_files, &w.overrides))
    }

    fn untracked(&self, _owner: &PinnedSource) -> Vec<String> {
        self.w().untracked.iter().cloned().collect()
    }

    fn evaluate(&self, src: &StagedSource) -> Result<EvaluatedGeneration, Outcome> {
        let w = self.w();
        let (overrides, _) = w.staged.get(&src.dir).ok_or_else(|| Outcome::Failed("no such stage".into()))?;
        let (mut eval, _) = w.evaluate(overrides);
        eval.source = src.staged_source;
        Ok(eval)
    }

    fn build(&self, eval: &EvaluatedGeneration) -> Result<Built, Outcome> {
        let mut w = self.w();
        w.builds += 1;
        if std::mem::take(&mut w.nospace_on_build) {
            return Err(Outcome::Failed("error: writing to file: No space left on device".into()));
        }
        let staged = w
            .staged
            .values()
            .find(|(o, files)| World::source_hash_of(files, o) == eval.source)
            .cloned()
            .ok_or_else(|| Outcome::Failed("build: unknown evaluation".into()))?;
        // Nix builds are deterministic: the same evaluation yields the same path.
        let existing =
            w.gens.iter().find(|(_, x)| x.eval.source == eval.source && eval.source != Hash::ZERO).map(|(g, _)| *g);
        let g = match existing {
            Some(g) => g,
            None => {
                let g = w.add_generation(&staged.0);
                w.gens.get_mut(&g).expect("added").eval.source = eval.source;
                g
            }
        };
        let cur = w.gens[&w.current].clone();
        let new = w.gens[&g].clone();
        let mut plan = new.eval.activation.clone();
        for u in new.eval.units.keys() {
            match cur.eval.units.get(u) {
                None => {
                    plan.start.insert(u.clone());
                }
                Some(old) if old != &new.eval.units[u] || new.broken.contains(u) != cur.broken.contains(u) => {
                    plan.restart.insert(u.clone());
                }
                _ => {}
            }
        }
        for (k, v) in &new.eval.options {
            if cur.eval.options.get(k) != Some(v) {
                // An option change restarts the services of its module (`services.<name>.…`).
                if let Some(svc) = k.strip_prefix("services.").and_then(|r| r.split('.').next()) {
                    let id = UnitId::service(svc);
                    if new.eval.units.contains_key(&id) {
                        plan.restart.insert(id);
                    }
                }
            }
        }
        for u in cur.eval.units.keys() {
            if !new.eval.units.contains_key(u) {
                plan.stop.insert(u.clone());
            }
        }
        let root = format!("/nix/var/nix/gcroots/planarian/builds/{}", eval.source.to_hex());
        w.gc_roots.insert(root.clone());
        Ok(Built { generation: g, path: new.path, root, activation: plan })
    }

    fn verify_candidate(&self, path: &StorePath, _expected: &Hash) -> Result<bool, Outcome> {
        let w = self.w();
        Ok(w.gens.values().any(|g| &g.path == path)
            && !w.collected.iter().any(|c| w.gens.get(c).is_some_and(|g| &g.path == path)))
    }

    fn pending_jobs(&self) -> Result<Vec<JobId>, Outcome> {
        Ok(self.w().jobs.keys().cloned().collect())
    }

    fn jobs_tagged(&self, op: &OpId) -> Result<Option<Vec<JobId>>, Outcome> {
        let w = self.w();
        if w.jobs_tagged_unknown {
            return Ok(None);
        }
        Ok(Some(w.jobs.iter().filter(|(_, j)| j.op == *op).map(|(k, _)| k.clone()).collect()))
    }

    fn override_hash(&self) -> Result<Hash, Outcome> {
        Ok(World::override_hash_of(&self.w().overrides))
    }

    fn activate_live(&self, g: GenerationId, op: &OpId) -> Outcome {
        self.run(op, format!("activate_live({})", g.0), |w| {
            if !w.gens.contains_key(&g) {
                return Outcome::Failed(format!("no generation {}", g.0));
            }
            if w.fail_activate.contains(&g) {
                return Outcome::Failed(format!("switch-to-configuration test failed for {}", g.0));
            }
            if g != w.booted && !w.block_on_activate.is_empty() {
                let b = std::mem::take(&mut w.block_on_activate);
                w.blocked.extend(b);
            }
            if let Some((delay, cancellable)) = w.slow_activation {
                w.next_job += 1;
                let id = JobId(format!("job-{}", w.next_job));
                let done_at = w.now.plus(delay);
                let job = Job { op: *op, done_at, cancellable, activates: g };
                let now = w.now;
                w.job_spans.insert(id.clone(), (job.clone(), now, None));
                w.jobs.insert(id, job);
                return Outcome::Unknown("activation job accepted; no reply".into());
            }
            w.apply_generation(g);
            Outcome::Succeeded
        })
    }

    fn publish_boot(&self, g: GenerationId, op: &OpId) -> Outcome {
        self.run(op, format!("publish_boot({})", g.0), |w| {
            // Only a generation whose files are not yet on /boot needs new space.
            if w.fail_publish && !w.boot_entries.contains(&g) {
                // /boot is full from here on, as on the gym VM.
                if let Some((free, _)) = w.fs.get_mut("/boot") {
                    *free = 0;
                }
                return Outcome::Failed("No space left on device (/boot)".into());
            }
            w.boot_entries.insert(g);
            w.boot_default = g;
            Outcome::Succeeded
        })
    }

    fn publish_boot_once(&self, g: GenerationId, keep: GenerationId, op: &OpId) -> Outcome {
        self.run(op, format!("publish_boot_once({})", g.0), |w| {
            w.boot_entries.insert(g);
            w.boot_default = keep;
            w.one_shot = Some(g);
            Outcome::Succeeded
        })
    }

    fn one_shot_pending(&self) -> Result<Option<GenerationId>, Outcome> {
        Ok(self.w().one_shot)
    }

    fn protect(&self, g: GenerationId, op: &OpId) -> Outcome {
        self.run(op, format!("protect({})", g.0), |_| Outcome::Succeeded)
    }

    fn cancel(&self, job: &JobId, op: &OpId) -> Outcome {
        self.run(op, format!("cancel({})", job.0), |w| match w.jobs.get(job) {
            Some(j) if j.cancellable => {
                w.jobs.remove(job);
                let now = w.now;
                if let Some(span) = w.job_spans.get_mut(job) {
                    span.2 = Some(now);
                }
                Outcome::Succeeded
            }
            Some(_) => Outcome::Failed("job cannot be cancelled".into()),
            None => Outcome::Succeeded,
        })
    }

    fn swap_override(&self, from: &Hash, to: &Hash, op: &OpId) -> Outcome {
        self.run(op, "swap_override".into(), |w| {
            let cur = World::override_hash_of(&w.overrides);
            if cur == *to {
                return Outcome::Succeeded;
            }
            if cur != *from {
                return Outcome::Failed("override file changed by a third party".into());
            }
            match w.override_store.get(to).cloned() {
                Some(set) => {
                    w.overrides = set;
                    Outcome::Succeeded
                }
                None => Outcome::Failed("override content unknown".into()),
            }
        })
    }

    fn path_of(&self, g: GenerationId) -> Result<StorePath, Outcome> {
        self.w().gens.get(&g).map(|x| x.path.clone()).ok_or_else(|| Outcome::Failed(format!("no generation {}", g.0)))
    }

    fn evaluate_built(&self, path: &StorePath) -> Result<EvaluatedGeneration, Outcome> {
        self.w()
            .gens
            .values()
            .find(|g| &g.path == path)
            .map(|g| g.eval.clone())
            .ok_or_else(|| Outcome::Failed("unknown store path".into()))
    }

    fn read_overrides(&self) -> Result<(OverrideSet, Hash), Outcome> {
        let w = self.w();
        Ok((w.overrides.clone(), World::override_hash_of(&w.overrides)))
    }

    fn remember_override(&self, set: &OverrideSet) -> Result<Hash, Outcome> {
        let h = World::override_hash_of(set);
        self.w().override_store.insert(h, set.clone());
        Ok(h)
    }

    fn override_for(&self, g: GenerationId) -> Result<Option<Hash>, Outcome> {
        Ok(self.w().gen_overrides.get(&g).copied())
    }

    fn record_override(&self, g: GenerationId, hash: &Hash) -> Result<(), Outcome> {
        self.w().gen_overrides.insert(g, *hash);
        Ok(())
    }

    fn release_root(&self, root: &str) -> bool {
        self.w().gc_roots.remove(root)
    }

    fn collect_garbage(&self, protect: &[GenerationId], emergency: bool, op: &OpId) -> Outcome {
        self.run(op, "collect_garbage".into(), |w| {
            let plan = w.gc_plan(protect, emergency);
            let freed = plan.delete.len() as u64 * GEN_BYTES;
            w.collected.extend(plan.delete.iter().copied());
            for (free, size) in w.fs.values_mut() {
                *free = (*free + freed).min(*size);
            }
            w.space_report = Some(gc::SpaceReport::of(&plan, w.now));
            Outcome::Succeeded
        })
    }

    fn gc_plan(&self, protect: &[GenerationId], emergency: bool) -> Result<gc::GcPlan, Outcome> {
        Ok(self.w().gc_plan(protect, emergency))
    }

    fn space_report(&self) -> Option<gc::SpaceReport> {
        self.w().space_report.clone()
    }
}

/// The closure size of one fake generation.
pub const GEN_BYTES: u64 = 2_000_000_000;

impl World {
    fn gc_plan(&self, protect: &[GenerationId], emergency: bool) -> gc::GcPlan {
        let on_disk: Vec<GenerationId> = self.gens.keys().copied().filter(|g| !self.collected.contains(g)).collect();
        let mut keep: Vec<GenerationId> = protect.to_vec();
        keep.extend([self.current, self.boot_default]);
        // Built candidates still rooted under gcroots/planarian/builds survive.
        keep.extend(on_disk.iter().copied().filter(|g| {
            let generation = &self.gens[g];
            self.gc_roots.iter().any(|r| r.ends_with(&generation.eval.source.to_hex()))
        }));
        let fs_size = self.fs.get("/nix").map(|(_, size)| *size).unwrap_or(u64::MAX);
        let b = self.gc_budget;
        let count = if emergency { b.keep_emergency } else { b.keep_generations };
        gc::plan(&on_disk, &keep, count, b.max_bytes(fs_size), |gs| gs.len() as u64 * GEN_BYTES)
    }
}

impl InventoryBackend for Fake {
    fn devices(&self) -> Result<Vec<DeviceInfo>, Outcome> {
        // A driver that can't drive the device leaves it effectively unbound.
        let w = self.w();
        Ok(w.devices.iter().map(|(id, d)| DeviceInfo { id: id.clone(), driver: d.clone() }).collect())
    }

    fn resources(&self) -> Result<Resources, Outcome> {
        Ok(Resources { mem_total_mb: 16_000, mem_available_mb: 12_000, fs_free_bytes: BTreeMap::new() })
    }

    fn bound_driver(&self, device: &UnitId) -> Result<Option<DriverRef>, Outcome> {
        Ok(self.w().devices.get(device).cloned().flatten())
    }

    fn bind(&self, device: &UnitId, driver: &DriverRef, op: &OpId) -> Outcome {
        self.run(op, format!("bind({device}, {})", driver.name), |w| {
            w.devices.insert(device.clone(), Some(driver.clone()));
            Outcome::Succeeded
        })
    }

    fn unbind(&self, device: &UnitId, op: &OpId) -> Outcome {
        self.run(op, format!("unbind({device})"), |w| {
            w.devices.insert(device.clone(), None);
            Outcome::Succeeded
        })
    }
}

impl ProbeBackend for Fake {
    fn run_batch(&self, jobs: &[(UnitId, ProbeDef)]) -> Vec<ProbeResult> {
        let mut w = self.w();
        w.probe_batches += 1;
        jobs.iter()
            .map(|(unit, p)| {
                if let ProbeKind::FreeSpace { path, min_bytes, min_permille } = &p.kind {
                    return match w.fs.get(path) {
                        Some((free, size)) if *free >= *min_bytes && free * 1000 >= size * *min_permille as u64 => {
                            ProbeResult::Pass
                        }
                        Some((free, _)) => ProbeResult::Fail(format!("{free} bytes free on {path}")),
                        None => ProbeResult::Error(format!("no filesystem at {path}")),
                    };
                }
                if w.blocked.contains(unit) {
                    return ProbeResult::Fail("connection refused".into());
                }
                // A sound card is listed while snd-hda0 is driven.
                if p.id.0 == "pipewire-has-a-card" {
                    return match w.devices.get(&UnitId::device("snd-hda0")).cloned().flatten() {
                        Some(d) if !w.bad_drivers.contains(&d.name) => ProbeResult::Pass,
                        _ => ProbeResult::Fail("no sound card".into()),
                    };
                }
                // A device's own check: driven by a driver that can drive it.
                if unit.kind == UnitKind::Device && matches!(p.kind, ProbeKind::Exec { .. }) {
                    return match w.devices.get(unit).cloned().flatten() {
                        Some(d) if !w.bad_drivers.contains(&d.name) => ProbeResult::Pass,
                        Some(d) => ProbeResult::Fail(format!("{} cannot drive it", d.name)),
                        None => ProbeResult::Fail("no driver".into()),
                    };
                }
                // A Wi-Fi interface is healthy while associated with a network in range.
                if w.base_units.get(unit).and_then(|d| d.runtime_repair.as_deref()) == Some("wifi.network") {
                    return match w.runtime.get("wifi.network") {
                        Some(Value::Str(n)) if w.wifi_in_range.contains(n) => ProbeResult::Pass,
                        _ => ProbeResult::Fail("not associated".into()),
                    };
                }
                let unreachable = |u: &UnitId| {
                    u.name.strip_prefix("external:").is_some_and(|x| w.external_unreachable.contains(x))
                        || w.base_units.get(u).is_some_and(|d| {
                            d.edges.iter().any(|e| {
                                e.to.name.strip_prefix("external:").is_some_and(|x| w.external_unreachable.contains(x))
                            })
                        })
                };
                if unreachable(unit) {
                    return ProbeResult::Timeout;
                }
                if let Some(ext) = unit.name.strip_prefix("external:") {
                    return if w.external_down.contains(ext) {
                        ProbeResult::Fail(format!("{ext}: connection refused"))
                    } else {
                        ProbeResult::Pass
                    };
                }
                // A client of a down external dependency sees its upstream fail.
                if w.base_units.get(unit).is_some_and(|d| {
                    d.edges
                        .iter()
                        .any(|e| e.to.name.strip_prefix("external:").is_some_and(|x| w.external_down.contains(x)))
                }) {
                    return ProbeResult::Fail("upstream unavailable (502)".into());
                }
                match w.units.get(&World::key(unit)) {
                    None => ProbeResult::Fail("not running".into()),
                    Some(sim) if sim.observed != Observed::Active => ProbeResult::Fail("connection refused".into()),
                    Some(sim) => match (&sim.health, &p.kind) {
                        (Health::Ok, _) => ProbeResult::Pass,
                        (Health::Http503, ProbeKind::Http { .. }) => ProbeResult::Fail("HTTP 503".into()),
                        (Health::Http503, _) => ProbeResult::Pass,
                        // A slow answer to the request; connecting is still quick.
                        (Health::Delay(d), ProbeKind::Http { .. }) if d.0 > p.timeout.0 => ProbeResult::Timeout,
                        (Health::Delay(_), _) => ProbeResult::Pass,
                        (Health::Stall(d), _) if d.0 > p.timeout.0 => ProbeResult::Timeout,
                        (Health::Stall(_), _) => ProbeResult::Pass,
                    },
                }
            })
            .collect()
    }
}

impl SessionBackend for Fake {
    fn sessions(&self) -> Result<Vec<SessionInfo>, Outcome> {
        Ok(self.w().sessions.clone())
    }

    fn compositor_running(&self, s: &SessionInfo) -> Option<bool> {
        self.w().compositors.get(&s.id).copied()
    }

    fn foreground(&self) -> Vec<String> {
        self.w().foreground.iter().cloned().collect()
    }

    fn power(&self) -> Option<PowerSource> {
        self.w().power
    }
}

impl RuntimeOptionBackend for Fake {
    fn get(&self, path: &str) -> Option<Value> {
        self.w().runtime.get(path).cloned()
    }

    fn set(&self, path: &str, value: &Value, op: &OpId) -> Outcome {
        self.run(op, format!("set({path})"), |w| {
            w.runtime.insert(path.into(), value.clone());
            Outcome::Succeeded
        })
    }

    fn alternatives(&self, path: &str) -> Vec<Value> {
        let w = self.w();
        match path {
            "wifi.network" => {
                let current = w.runtime.get(path);
                w.wifi_known
                    .iter()
                    .filter(|n| w.wifi_in_range.contains(*n))
                    .map(|n| Value::Str(n.clone()))
                    .filter(|v| Some(v) != current)
                    .collect()
            }
            _ => vec![],
        }
    }
}

impl ProcessBackend for Fake {
    fn kill_group(&self, pid: u32) -> bool {
        let mut w = self.w();
        if w.unkillable.contains(&pid) {
            return false;
        }
        w.alive.remove(&pid);
        true
    }

    fn alive(&self, pid: u32) -> bool {
        self.w().alive.contains(&pid)
    }
}

impl Clock for Fake {
    fn now(&self) -> Timestamp {
        self.w().now
    }

    fn sleep(&self, d: Millis) {
        self.advance(d);
    }
}

impl Backends for Fake {
    type Units = Fake;
    type Gens = Fake;
    type Inv = Fake;
    type Probes = Fake;
    type Sessions = Fake;
    type Runtime = Fake;
    type Procs = Fake;
    type Clock = Fake;

    fn units(&self) -> &Fake {
        self
    }
    fn generations(&self) -> &Fake {
        self
    }
    fn inventory(&self) -> &Fake {
        self
    }
    fn probes(&self) -> &Fake {
        self
    }
    fn sessions(&self) -> &Fake {
        self
    }
    fn runtime(&self) -> &Fake {
        self
    }
    fn processes(&self) -> &Fake {
        self
    }
    fn clock(&self) -> &Fake {
        self
    }
}

/// A fake machine built from the gym fixtures (catalog `[[fixture]]`), on its
/// first generation, healthy, with nobody logged in.
pub fn gym_world(store: MemStore) -> Fake {
    let mut w = World { now: Timestamp(1_700_000_000_000), power: Some(PowerSource::Ac), ..Default::default() };
    w.base_units = fixtures::gym_units();
    w.base_user_units = fixtures::gym_user_units();
    w.base_options = [
        ("services.gym-web.listenAddress".to_string(), Value::Str("127.0.0.1".into())),
        ("services.openssh.enable".to_string(), Value::Bool(true)),
        ("planarian.reference.fontScale".to_string(), Value::Str("1".into())),
        ("gym.vulnlib".to_string(), Value::Str("1.0".into())),
        ("gym.kernelParam".to_string(), Value::Str("".into())),
        ("services.gym-bad-payload.enable".to_string(), Value::Bool(false)),
        ("gym.modules".to_string(), Value::Str("old".into())),
    ]
    .into();
    // gym-vulnlib 1.0 carries knownVulnerabilities; 1.1 fixes them (§12e).
    w.base_packages = [("gym-vulnlib".to_string(), "1.0".to_string())].into();
    w.base_insecure = ["gym-vulnlib".to_string()].into();
    w.base_inputs = [("gym-modules".to_string(), ("old".to_string(), "/nix/store/aaa-gym-modules".to_string()))].into();
    w.rules = vec![
        // A flake input update whose new module declares the payload.
        Rule {
            option: "gym.modules".into(),
            value: Value::Str("new".into()),
            effect: Effect::Declare {
                service: "gym-bad-payload".into(),
                file: "/nix/store/bbb-gym-modules/module.nix".into(),
            },
        },
        // The bad payload: a declared service, off by default, defined in the
        // gym's own module (§15 malicious declaration).
        Rule {
            option: "services.gym-bad-payload.enable".into(),
            value: Value::Bool(true),
            effect: Effect::Declare { service: "gym-bad-payload".into(), file: "/etc/nixos/configuration.nix".into() },
        },
        // A kernel parameter: takes effect only at boot (§12f).
        Rule {
            option: "gym.kernelParam".into(),
            value: Value::Str("virtio_gpu.modeset=0".into()),
            effect: Effect::NeedsReboot,
        },
        Rule {
            option: "gym.vulnlib".into(),
            value: Value::Str("1.1".into()),
            effect: Effect::Package { name: "gym-vulnlib".into(), version: "1.1".into(), insecure: false },
        },
        Rule {
            option: "services.gym-web.listenAddress".into(),
            value: Value::Str("192.0.2.10".into()),
            effect: Effect::Break(UnitId::service("gym-web")),
        },
        Rule {
            option: "services.openssh.enable".into(),
            value: Value::Bool(false),
            effect: Effect::Remove(UnitId::service("sshd")),
        },
    ];
    w.core_units = [
        ("planariad.service".to_string(), Hash::of(b"planariad")),
        ("planarian-recovery.service".to_string(), Hash::of(b"recovery")),
    ]
    .into();
    w.owner_files = [
        ("flake.nix".to_string(), "{ outputs = …; }".to_string()),
        ("configuration.nix".to_string(), "{ … }".to_string()),
    ]
    .into();
    w.devices = [
        (UnitId::device("snd-hda0"), Some(DriverRef { name: "snd_hda_intel".into(), module: None })),
        (UnitId::device("net-gym0"), Some(DriverRef { name: "virtio_net".into(), module: None })),
        (UnitId::device("gpu0"), Some(DriverRef { name: "virtio_gpu".into(), module: None })),
        (UnitId::device("wlan-hwsim"), Some(DriverRef { name: "mac80211_hwsim".into(), module: None })),
    ]
    .into();
    w.wifi_known = vec!["gym-ap-a".into(), "gym-ap-b".into()];
    w.wifi_in_range = ["gym-ap-a".to_string(), "gym-ap-b".to_string()].into();
    w.runtime.insert("wifi.network".into(), Value::Str("gym-ap-a".into()));
    w.bad_drivers.insert("vfio-pci".into());
    w.fs = [
        ("/".to_string(), (40_000_000_000, 100_000_000_000)),
        ("/nix".to_string(), (40_000_000_000, 100_000_000_000)),
        ("/boot".to_string(), (400_000_000, 1_000_000_000)),
        ("/var/lib/planarian".to_string(), (40_000_000_000, 100_000_000_000)),
    ]
    .into();
    let g = w.add_generation(&OverrideSet::default());
    w.boot_entries.insert(g);
    w.boot_default = g;
    w.booted = g;
    w.override_store.insert(World::override_hash_of(&OverrideSet::default()), OverrideSet::default());
    let now = w.now;
    for id in w.base_units.keys() {
        if id.kind == UnitKind::Service && !id.name.starts_with("external:") {
            w.units.insert(id.clone(), UnitSim::active(now));
        }
    }
    if let Some(sim) = w.units.get_mut(&UnitId::service("gym-restartful")) {
        sim.systemd_restart = Some(Millis::secs(5));
    }
    w.apply_generation(g);
    Fake::new(w, store)
}

pub mod fixtures;
