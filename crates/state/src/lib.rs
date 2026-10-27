//! State assembly (SPEC §10): each tick, observe every unit, run the probes
//! that are due, evaluate conditions, and assemble a `SystemState`.
//!
//! Desired state comes from the evaluated manifest, observed state from the
//! backends, health from the probes. The three stay separate: `SystemState`
//! keeps observations and evidence, and status is derived on demand.
//!
//! Canonical probes come from the installed core package, never from the
//! generation's manifest (I10). The manifest can add `User` probes; a
//! definition it gives for a canonical probe id is replaced by the core's.
//!
//! No process spawning and no reads of `/proc`, `/sys` or `/nix`: everything
//! goes through the backend traits (§6).

use planarian_schema::{
    Backends, Cadence, Clock, Condition, DriverRef, Evidence, GenerationBackend, GenerationId, Hash, InventoryBackend,
    Millis, Observed, PowerSource, ProbeBackend, ProbeCost, ProbeDef, ProbeId, ProbeKind, ProbeOrigin, ProbeResult,
    ProbeRole, Reason, Scope, SessionBackend, SessionInfo, Suppression, SystemState, Timestamp, UnitBackend, UnitDef,
    UnitDefs, UnitId, UnitKind,
};
use std::collections::{BTreeMap, BTreeSet};

pub const TICK: Millis = Millis::secs(5);
pub const MIN_STALE: Millis = Millis::secs(30);
pub const HARDWARE_CADENCE: Millis = Millis::secs(60);
pub const HARDWARE_CADENCE_BATTERY: Millis = Millis::secs(300);
/// Warn if a tick takes longer than this (§10).
pub const TICK_BUDGET: Millis = Millis(500);

pub use planarian_schema::Manifest;

/// Canonical probes shipped in the core package, by unit name.
pub type Canonical = BTreeMap<String, Vec<ProbeDef>>;

/// Replace or add the core's canonical probes on a unit (I10). Probes the
/// manifest marks Canonical but the core does not ship are demoted to User.
pub fn apply_canonical(def: &mut UnitDef, canonical: &Canonical) {
    let core = canonical.get(&def.id.name).cloned().unwrap_or_default();
    let core_ids: BTreeSet<&ProbeId> = core.iter().map(|p| &p.id).collect();
    def.probes.retain(|p| !core_ids.contains(&p.id));
    for p in def.probes.iter_mut() {
        p.origin = ProbeOrigin::User;
    }
    def.probes.extend(core);
}

/// Baselines and suppressions from the journal, which `state` does not own.
#[derive(Clone, Debug, Default)]
pub struct Context {
    pub known_good: GenerationId,
    pub live_tested: Option<GenerationId>,
    pub accepted_baseline: Option<GenerationId>,
    pub suppressions: Vec<Suppression>,
    pub core_hash: Hash,
}

#[derive(Clone, Debug, Default)]
pub struct Assembler {
    manifest: Manifest,
    canonical: Canonical,
    evidence: BTreeMap<(UnitId, ProbeId), Evidence>,
    last_run: BTreeMap<(UnitId, ProbeId), Timestamp>,
    on_demand: BTreeSet<(UnitId, ProbeId)>,
    pub failed_since: BTreeMap<UnitId, Timestamp>,
    pub known_drivers: BTreeMap<UnitId, DriverRef>,
    pub sessions: Vec<SessionInfo>,
    /// When each session id was first observed (stands in for an unknown creation time).
    session_seen: BTreeMap<String, Timestamp>,
    pub on_battery: bool,
    /// Ticks that went over budget (logged by the daemon).
    pub slow_ticks: u64,
}

impl Assembler {
    pub fn new(manifest: Manifest, canonical: Canonical) -> Assembler {
        let mut a = Assembler { canonical, ..Default::default() };
        a.set_manifest(manifest);
        a
    }

    /// A new generation's manifest (after a commit, revert or boot).
    pub fn set_manifest(&mut self, mut manifest: Manifest) {
        for def in manifest.units.values_mut() {
            apply_canonical(def, &self.canonical);
        }
        for def in manifest.user_units.iter_mut() {
            apply_canonical(def, &self.canonical);
        }
        self.manifest = manifest;
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// System units plus one instance of each user template per user with an
    /// established session (§10: a user service is desired only while that
    /// user's session exists).
    pub fn defs(&self) -> UnitDefs {
        let mut defs = self.manifest.units.clone();
        let uids: BTreeSet<u32> = self.sessions.iter().filter(|s| s.establishes()).map(|s| s.uid).collect();
        for t in &self.manifest.user_units {
            for uid in &uids {
                let id = UnitId {
                    kind: t.id.kind,
                    name: t.id.name.clone(),
                    scope: Scope::User { uid: *uid, session: None },
                };
                let mut d = t.clone();
                d.id = id.clone();
                d.desired.when =
                    Condition::All(vec![t.desired.when.clone(), Condition::SessionEstablished { uid: Some(*uid) }]);
                for e in d.edges.iter_mut() {
                    e.from = id.clone();
                    if let Scope::User { .. } = e.to.scope {
                        e.to.scope = Scope::User { uid: *uid, session: None };
                    }
                }
                defs.insert(id, d);
            }
        }
        defs
    }

    /// Run a Diagnostic (or any) probe on the next tick: user-initiated diagnostics (§10).
    pub fn request(&mut self, unit: &UnitId, probe: &ProbeId) {
        self.on_demand.insert((unit.clone(), probe.clone()));
    }

    /// Re-run every Readiness probe of `unit` now (diagnostic incident: re-observe).
    pub fn reprobe(&mut self, unit: &UnitId) {
        self.last_run.retain(|(u, _), _| u != unit);
    }

    fn interval(&self, p: &ProbeDef) -> Option<Millis> {
        let base = match p.cadence {
            Cadence::EveryTick | Cadence::OnEvent => TICK,
            Cadence::Every(d) => d,
            Cadence::OnDemand => return None,
        };
        Some(if p.cost == ProbeCost::WakesHardware {
            let floor = if self.on_battery { HARDWARE_CADENCE_BATTERY } else { HARDWARE_CADENCE };
            Millis(base.0.max(floor.0))
        } else {
            base
        })
    }

    fn stale_after(&self, p: &ProbeDef) -> Millis {
        let interval = self.interval(p).unwrap_or(TICK);
        Millis((interval.0 * 3).max(p.timeout.0 * 2 + TICK.0).max(MIN_STALE.0))
    }

    fn due(&self, unit: &UnitId, p: &ProbeDef, now: Timestamp) -> bool {
        let key = (unit.clone(), p.id.clone());
        if self.on_demand.contains(&key) {
            return true;
        }
        // Side-effecting probes only ever run on demand (§10, §18.4); Diagnostic
        // probes never run on a cadence.
        if p.role == ProbeRole::Diagnostic || p.check_contract().is_err() {
            return false;
        }
        match (self.interval(p), self.last_run.get(&key)) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(i), Some(last)) => now.0 >= last.0 + i.0,
        }
    }

    fn observe_unit<B: Backends>(
        &mut self,
        b: &B,
        def: &UnitDef,
        devices: &BTreeMap<UnitId, Option<DriverRef>>,
    ) -> Observed {
        let id = &def.id;
        let now = b.clock().now();
        if id.kind == UnitKind::Device {
            if id.name.starts_with("fs-") {
                return Observed::Active; // a mounted filesystem; its probe judges space
            }
            return match devices.get(id) {
                None => Observed::Absent,
                Some(None) => Observed::Detected,
                Some(Some(d)) => {
                    self.known_drivers.insert(id.clone(), d.clone());
                    Observed::Bound
                }
            };
        }
        if id.name.starts_with("external:") {
            return Observed::Active; // nothing local to observe; its probes decide
        }
        if let Some((target, within)) = def.probes.iter().find_map(|p| match &p.kind {
            ProbeKind::SessionTarget { target, within } => Some((target.clone(), *within)),
            _ => None,
        }) {
            return self.observe_session_target(b, &target, within, now);
        }
        match b.units().observe(id) {
            Ok(o) => o,
            Err(e) => Observed::Unknown { since: now, reason: format!("backend: {e:?}") },
        }
    }

    /// §9 graphical-session: the target must be reached in each user session
    /// within `within` of that session's creation. Pending sessions make the
    /// unit Transitioning; a missed deadline makes it inactive, and its probe
    /// (evaluated in `session_target_result`) fails.
    fn observe_session_target<B: Backends>(&self, b: &B, target: &str, within: Millis, now: Timestamp) -> Observed {
        let mut pending = false;
        for s in self.sessions.iter().filter(|s| s.establishes()) {
            let tid = UnitId {
                kind: UnitKind::Target,
                name: target.into(),
                scope: Scope::User { uid: s.uid, session: Some(s.id.clone()) },
            };
            match b.units().observe(&tid) {
                Ok(Observed::Active) => {}
                _ if now.0 < s.created.0 + within.0 => pending = true,
                _ => return Observed::Bound,
            }
        }
        if pending { Observed::Transitioning { from: Box::new(Observed::Bound), since: now } } else { Observed::Active }
    }

    fn session_target_result<B: Backends>(&self, b: &B, target: &str, within: Millis, now: Timestamp) -> ProbeResult {
        for s in self.sessions.iter().filter(|s| s.establishes()) {
            let tid = UnitId {
                kind: UnitKind::Target,
                name: target.into(),
                scope: Scope::User { uid: s.uid, session: Some(s.id.clone()) },
            };
            match b.units().observe(&tid) {
                Ok(Observed::Active) => {}
                _ if now.0 < s.created.0 + within.0 => {}
                _ => {
                    return ProbeResult::Fail(format!(
                        "{target} not reached within {}s of session {} (uid {})",
                        within.0 / 1000,
                        s.id,
                        s.uid
                    ));
                }
            }
        }
        ProbeResult::Pass
    }

    /// One tick: observe, probe, assemble.
    pub fn observe<B: Backends>(&mut self, b: &B, ctx: &Context) -> SystemState {
        let started = b.clock().now();
        let now = started;

        self.sessions = b.sessions().sessions().unwrap_or_default();
        for s in self.sessions.iter_mut() {
            let seen = *self.session_seen.entry(s.id.clone()).or_insert(now);
            if s.created.0 == 0 {
                s.created = seen;
            }
        }
        let live: BTreeSet<String> = self.sessions.iter().map(|s| s.id.clone()).collect();
        self.session_seen.retain(|id, _| live.contains(id));
        let power = b.sessions().power();
        self.on_battery = power == Some(PowerSource::Battery);
        let devices: BTreeMap<UnitId, Option<DriverRef>> =
            b.inventory().devices().unwrap_or_default().into_iter().map(|d| (d.id, d.driver)).collect();

        let mut conditions = BTreeSet::new();
        for s in self.sessions.iter().filter(|s| s.establishes()) {
            conditions.insert(Condition::SessionEstablished { uid: Some(s.uid) });
        }
        match power {
            Some(PowerSource::Ac) => {
                conditions.insert(Condition::OnAcPower);
            }
            Some(PowerSource::Battery) => {
                conditions.insert(Condition::OnBattery);
            }
            None => {}
        }
        for d in devices.keys() {
            conditions.insert(Condition::DeviceConnected(d.clone()));
        }

        let defs = self.defs();
        let mut observed: BTreeMap<UnitId, Observed> = BTreeMap::new();
        for def in defs.values() {
            let o = self.observe_unit(b, def, &devices);
            match &o {
                Observed::Failed(_) => {
                    self.failed_since.entry(def.id.clone()).or_insert(now);
                }
                _ => {
                    self.failed_since.remove(&def.id);
                }
            }
            observed.insert(def.id.clone(), o);
        }

        // Probes that are due. SystemdActive and SessionTarget are answered here;
        // the rest go to the probe backend as one concurrent batch.
        let mut batch: Vec<(UnitId, ProbeDef)> = vec![];
        let mut local: Vec<(UnitId, ProbeDef, ProbeResult)> = vec![];
        for def in defs.values() {
            for p in &def.probes {
                if !self.due(&def.id, p, now) {
                    continue;
                }
                match &p.kind {
                    ProbeKind::SystemdActive => {
                        let r = match &observed[&def.id] {
                            Observed::Active | Observed::Bound if def.id.kind == UnitKind::Device => ProbeResult::Pass,
                            Observed::Active => ProbeResult::Pass,
                            Observed::Unknown { reason, .. } => ProbeResult::Error(reason.clone()),
                            other => ProbeResult::Fail(format!("{other:?}")),
                        };
                        local.push((def.id.clone(), p.clone(), r));
                    }
                    ProbeKind::SessionTarget { target, within } => {
                        let r = self.session_target_result(b, target, *within, now);
                        local.push((def.id.clone(), p.clone(), r));
                    }
                    _ => batch.push((def.id.clone(), p.clone())),
                }
            }
        }
        let results = if batch.is_empty() { vec![] } else { b.probes().run_batch(&batch) };
        for ((unit, p), r) in batch.into_iter().zip(results) {
            local.push((unit, p, r));
        }
        for (unit, p, result) in local {
            let key = (unit.clone(), p.id.clone());
            self.on_demand.remove(&key);
            self.last_run.insert(key.clone(), now);
            let stale_after = self.stale_after(&p);
            self.evidence.insert(key, Evidence { probe: p.id.clone(), result, at: now, stale_after });
        }
        // Drop evidence for units or probes that no longer exist.
        self.evidence.retain(|(u, pid), _| defs.get(u).is_some_and(|d| d.probes.iter().any(|p| &p.id == pid)));

        let units = observed
            .into_iter()
            .map(|(id, o)| {
                let ev: Vec<Evidence> =
                    self.evidence.iter().filter(|((u, _), _)| *u == id).map(|(_, e)| e.clone()).collect();
                (id, (o, ev))
            })
            .collect();

        let generation = b.generations().current().unwrap_or(ctx.known_good);
        let resources = b.inventory().resources().unwrap_or_default();
        let finished = b.clock().now();
        if finished.0.saturating_sub(started.0) > TICK_BUDGET.0 {
            self.slow_ticks += 1;
        }
        SystemState {
            generation,
            known_good: ctx.known_good,
            live_tested: ctx.live_tested,
            accepted_baseline: ctx.accepted_baseline,
            units,
            suppressions: ctx.suppressions.clone(),
            conditions,
            resources,
            core_hash: ctx.core_hash,
            observed_at: now,
        }
    }
}

/// A `Reason` for a unit observed failed with a backend error.
pub fn backend_reason(msg: &str) -> Reason {
    Reason::Backend(msg.into())
}

#[cfg(test)]
mod tests;
