//! The fake harness: a fake machine, the real daemon core, and a watchdog
//! process, driven tick by tick by a catalog entry's steps.

use planarian_changes::{CatalogConfig, ListenAddress};
use planarian_daemon::{Core, CoreConfig, Peer};
use planarian_exec::Config as ExecConfig;
use planarian_exec::host::ExecHost;
use planarian_fake::{Fake, Health, MemStore, fixtures, gym_world};
use planarian_ipc::{Request, Response};
use planarian_policy::{Settings, Tables};
use planarian_schema::*;
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::kernel::{CrashPoint, Kernel};
use planarian_txn::ledger::{Entry, Ledger, Record};
use planarian_txn::machine::tag;
use planarian_txn::store::Store as _;
use std::collections::{BTreeMap, BTreeSet};
use toml::Value as T;

pub const TICK: Millis = Millis::secs(5);
pub const DAEMON_PID: u32 = 100;
pub const WATCHDOG_PID: u32 = 200;

#[derive(Debug)]
pub struct Unsupported(pub String);

pub fn config() -> CoreConfig {
    CoreConfig {
        exec: ExecConfig {
            settings: Settings::default(),
            tables: Tables {
                catalog: [
                    "service-enable",
                    "font-scale",
                    "listen-address",
                    "repair:reenable-predicted",
                    "repair:reapply",
                    "gym:security-fix",
                    "gym:kernel-param",
                    "gym:touch-core",
                    "gym:newlib",
                    "gym:drop-probe",
                    "gym:firewall-step",
                ]
                .map(|s| ChangeId(s.into()))
                .into(),
                runtime_allowlist: ["font.scale", "wifi.network"].map(String::from).into(),
                option_sensitivity: vec![
                    ("services.openssh".into(), Sensitivities::of(&[Sensitivity::Security])),
                    ("networking.firewall".into(), Sensitivities::of(&[Sensitivity::Security])),
                ],
                model_catalog: Default::default(),
            },
            catalog: CatalogConfig {
                services: [
                    ("sshd".into(), "services.openssh.enable".into()),
                    // Declared, off by default (catalog family malicious-declaration).
                    ("gym-bad-payload".into(), "services.gym-bad-payload.enable".into()),
                ]
                .into(),
                font_scale_option: "planarian.reference.fontScale".into(),
                font_scales: ["0.75", "1", "1.25", "1.5", "2"].map(String::from).into(),
                listen_addresses: [(
                    "gym-web".into(),
                    ListenAddress {
                        option: "services.gym-web.listenAddress".into(),
                        permitted: vec!["127.0.0.1".into(), "192.0.2.10".into()],
                    },
                )]
                .into(),
                gym_choices: [
                    (
                        "gym:security-fix".into(),
                        planarian_changes::GymChoice {
                            option: "gym.vulnlib".into(),
                            arg: "version".into(),
                            permitted: vec!["1.1".into(), "1.2".into()],
                        },
                    ),
                    (
                        "gym:newlib".into(),
                        planarian_changes::GymChoice {
                            option: "gym.newlib".into(),
                            arg: "version".into(),
                            permitted: vec!["1.0".into(), "2.0".into()],
                        },
                    ),
                    (
                        "gym:touch-core".into(),
                        planarian_changes::GymChoice {
                            option: "gym.touchCore".into(),
                            arg: "value".into(),
                            permitted: vec!["on".into()],
                        },
                    ),
                    (
                        "gym:drop-probe".into(),
                        planarian_changes::GymChoice {
                            option: "gym.dropProbe".into(),
                            arg: "probe".into(),
                            permitted: vec!["sshd-tcp".into()],
                        },
                    ),
                    (
                        "gym:firewall-step".into(),
                        planarian_changes::GymChoice {
                            option: "networking.firewall.gymStep".into(),
                            arg: "step".into(),
                            permitted: vec!["1".into()],
                        },
                    ),
                    (
                        "gym:kernel-param".into(),
                        planarian_changes::GymChoice {
                            option: "gym.kernelParam".into(),
                            arg: "param".into(),
                            permitted: vec!["virtio_gpu.modeset=0".into()],
                        },
                    ),
                ]
                .into(),
                ..Default::default()
            },
            owner: PinnedSource { root: "/etc/nixos".into(), kind: SourceKind::Git },
            canonical: fixtures::canonical(),
        },
        runtime_options: vec![],
        fresh_boot: true,
        startup_grace: planarian_daemon::STARTUP_GRACE,
        posture: planarian_schema::Posture::Standard,
        posture_decl: Default::default(),
        agent_limits: Default::default(),
    }
}

pub struct Sim {
    pub fake: Fake,
    pub core: Option<Core<Fake, MemStore>>,
    /// The posture `set_setting posture` chose; kept across daemon restarts.
    pub posture: planarian_schema::Posture,
    /// Reboots so far: the boot id the daemon and watchdog see.
    pub boots: u64,
    fresh_boot: bool,
    daemon_pid: u32,
    /// The daemon is killed and must not be restarted (catalog `hold_down`).
    held: bool,
    crash: Option<CrashPoint>,
    pub start: Timestamp,
    pub responses: Vec<Response>,
    pub notices: Vec<String>,
    /// Generation ids for the catalog's symbolic names.
    pub base: GenerationId,
    pub candidate: Option<GenerationId>,
    /// Executor log records (I7) from every daemon instance.
    pub log: Vec<planarian_daemon::LogRecord>,
    /// Every status each unit showed, by tick.
    pub seen_status: BTreeMap<UnitId, std::collections::BTreeSet<String>>,
    /// Every incident ever opened: (target, kind, first seen, last state, regressions, budget).
    pub seen_incidents: BTreeMap<IncidentId, Incident>,
    pub first_incident_at: BTreeMap<UnitId, Timestamp>,
    /// Statuses just before the first step (for `others_unchanged`).
    pub pre_status: BTreeMap<UnitId, String>,
    /// Units the entry's own steps act on (exempt from `others_unchanged`).
    pub touched: std::collections::BTreeSet<UnitId>,
    /// Journal entries saved before a compaction discards them, and whether one happened.
    history: Vec<Entry>,
    compacted: bool,
    torn_seen: bool,
    /// Approvals issued and held back (`approve_pending` with `hold_token`).
    held_tokens: Vec<Hash>,
    timeline: BTreeMap<UnitId, Vec<(Timestamp, String)>>,
    start_probe_defs: String,
    /// Stages and builds when the entry's steps began.
    start_work: (usize, usize),
    start_roots: std::collections::BTreeSet<String>,
    /// planariad's side of the failure posture (§12d); see `PostureSeen`.
    pub posture_seen: crate::evidence::PostureSeen,
}

/// `root`, `user:<uid>` or `user:<uid>@<session>`; user:1001 is the gym's administrator.
pub fn peer(actor: &str) -> Peer {
    let (who, session) = match actor.split_once('@') {
        Some((w, s)) => (w, Some(s)),
        None => (actor, None),
    };
    if let Some(name) = who.strip_prefix("agent:") {
        // A dynamic uid, as systemd would give it.
        // Its instance is filled in when it sends (`request_peer`): the
        // running unit's, as its cgroup would show it.
        return Peer::agent(61184, name, None);
    }
    let p = match who {
        "root" => Peer::new(0, true),
        // I17: root with no administrator group behind it (an emptied
        // planarian-admin); root is an administrator all the same.
        "root:nogroup" => Peer::new(0, false),
        "user:1001" => Peer::new(1001, true),
        a => Peer::new(a.strip_prefix("user:").and_then(|u| u.parse().ok()).unwrap_or(1000), false),
    };
    match session {
        Some(s) => p.in_session(s),
        None => p,
    }
}

/// The authorization the daemon would compute for `actor` on the gym's seat:
/// a local, active session (`gym` unless the actor names one).
/// The gym's administrators: root and uid 1001 (in `planarian-admin`).
fn gym_admins() -> std::sync::Arc<dyn Fn(u32) -> bool + Send + Sync> {
    std::sync::Arc::new(|uid| uid == 0 || uid == 1001)
}

fn gym_authz(actor: &str) -> planarian_schema::Authorization {
    let pe = peer(actor);
    let session = pe.session.clone().unwrap_or_else(|| "gym".into());
    let a = Actor::User { uid: pe.uid, session: Some(session), seat: Some("seat0".into()), active: true };
    planarian_policy::user_authorization(a, pe.admin)
}

/// "90s", "5m", "24h1m"; "stale_after" means a probe's staleness window (30 s
/// for the fixtures), optionally "+<duration>".
pub fn dur(v: &T) -> Option<Millis> {
    let s = v.as_str()?;
    if let Some(rest) = s.strip_prefix("stale_after") {
        let extra = match rest.strip_prefix('+') {
            Some(r) => dur(&T::String(r.into()))?,
            None => Millis(0),
        };
        return Some(Millis(35_000 + extra.0));
    }
    let mut total = 0u64;
    let mut rest = s;
    while !rest.is_empty() {
        let i = rest.find(|c: char| !c.is_ascii_digit())?;
        let n: u64 = rest[..i].parse().ok()?;
        let unit_end = rest[i..].find(|c: char| c.is_ascii_digit()).map(|j| i + j).unwrap_or(rest.len());
        total += match &rest[i..unit_end] {
            "ms" => n,
            "s" => n * 1000,
            "m" => n * 60_000,
            "h" => n * 3_600_000,
            _ => return None,
        };
        rest = &rest[unit_end..];
    }
    Some(Millis(total))
}

pub fn unit(s: &str) -> UnitId {
    s.parse().unwrap_or_else(|_| UnitId::service(s))
}

pub fn value(v: &T) -> Value {
    match v {
        T::Boolean(b) => Value::Bool(*b),
        T::Integer(i) => Value::Int(*i),
        T::String(s) => Value::Str(s.clone()),
        other => Value::Str(other.to_string()),
    }
}

impl Sim {
    pub fn new() -> Sim {
        let store = MemStore::new(16 << 20);
        let fake = gym_world(store.clone());
        fake.w().alive.extend([DAEMON_PID, WATCHDOG_PID]);
        let mut j = Journal::open(store).expect("journal");
        let now = fake.w().now;
        j.append(now, Record::KnownGood(GenerationId(1))).expect("enroll");
        let mut core = Core::start(j, fake.clone(), OwnerId::Daemon { pid: DAEMON_PID, boot_id: Hash::ZERO }, config());
        core.admin_of = gym_admins();
        Sim {
            fake,
            core: Some(core),
            posture: planarian_schema::Posture::Standard,
            boots: 0,
            fresh_boot: false,
            daemon_pid: DAEMON_PID,
            held: false,
            crash: None,
            start: now,
            responses: vec![],
            notices: vec![],
            base: GenerationId(1),
            candidate: None,
            log: vec![],
            seen_status: BTreeMap::new(),
            seen_incidents: BTreeMap::new(),
            first_incident_at: BTreeMap::new(),
            pre_status: BTreeMap::new(),
            touched: Default::default(),
            history: vec![],
            compacted: false,
            torn_seen: false,
            held_tokens: vec![],
            timeline: BTreeMap::new(),
            start_probe_defs: String::new(),
            start_work: (0, 0),
            start_roots: Default::default(),
            posture_seen: Default::default(),
        }
    }

    /// The run proper starts now: what the machine looks like before the first step.
    pub fn begin(&mut self) {
        self.start = self.now();
        self.pre_status = self.statuses();
        self.start_probe_defs = self.probe_defs();
        let w = self.fake.w();
        self.start_work = (w.stages, w.builds);
        drop(w);
        self.start_roots = self.build_roots();
    }

    fn build_roots(&self) -> std::collections::BTreeSet<String> {
        self.fake.w().gc_roots.iter().filter(|r| r.contains("/builds/")).cloned().collect()
    }

    /// The probe definitions the daemon evaluates, per unit.
    fn probe_defs(&mut self) -> String {
        let defs = self.observe().1;
        let probes: BTreeMap<String, Vec<ProbeDef>> =
            defs.iter().map(|(id, d)| (id.to_string(), d.probes.clone())).collect();
        serde_json::to_string(&probes).expect("serializes")
    }

    /// Save the journal's current segment before something discards it.
    fn save_segment(&mut self) {
        if let Ok(mut j) = Journal::open(self.fake.store.clone())
            && let Ok(seg) = j.segment()
        {
            for e in seg {
                if self.history.last().is_none_or(|h| h.seq < e.seq) {
                    self.history.push(e);
                }
            }
        }
    }

    pub fn now(&self) -> Timestamp {
        self.fake.w().now
    }

    pub fn ledger(&self) -> Ledger {
        Journal::open(self.fake.store.clone()).map(|j| j.ledger().clone()).unwrap_or_default()
    }

    fn harvest(&mut self) {
        let now = self.now();
        if let Some(c) = self.core.as_mut() {
            self.notices.extend(c.notices.drain(..));
            self.log.append(&mut c.log);
            for i in c.incidents.incidents.values() {
                self.first_incident_at.entry(i.target.clone()).or_insert(now);
                self.seen_incidents.insert(i.id, i.clone());
            }
        }
    }

    /// Everything the judge reads (check.rs).
    pub fn evidence(&mut self) -> crate::evidence::Evidence {
        let finals = self.statuses();
        self.save_segment();
        let entries: Vec<Entry> = self.history.iter().filter(|e| e.at >= self.start).cloned().collect();
        let full_replay = self.compacted.then(|| {
            let mut l = Ledger::default();
            for e in &self.history {
                let _ = l.apply(e.clone());
            }
            l
        });
        let probe_defs = (self.start_probe_defs.clone(), self.probe_defs());
        let gc_roots = (self.start_roots.clone(), self.build_roots());
        // Which generation each transaction reverts to, to name activations.
        let revert_to: BTreeMap<TxnId, GenerationId> = self
            .history
            .iter()
            .filter_map(|e| match &e.record {
                Record::Prepared(t) => Some((t.id, t.revert_to)),
                _ => None,
            })
            .collect();
        let journal_replays = Journal::open(self.fake.store.clone()).is_ok();
        let w = self.fake.w();
        let mut restarts: BTreeMap<UnitId, i64> = BTreeMap::new();
        for c in w.calls.iter().filter(|c| !c.fenced) {
            if let Some(u) = c.call.strip_prefix("restart(").and_then(|r| r.strip_suffix(')')) {
                *restarts.entry(unit(u)).or_default() += 1;
            }
        }
        let name = |call: &str, txn: TxnId| -> String {
            match call.strip_prefix("activate_live(").and_then(|g| g.strip_suffix(')')).and_then(|g| g.parse().ok()) {
                Some(g) if revert_to.get(&txn) == Some(&GenerationId(g)) => "activate_live(revert_to)".into(),
                Some(_) => "activate_live(candidate)".into(),
                None => call.to_string(),
            }
        };
        let jobs: std::collections::BTreeSet<OpId> = w.job_spans.values().map(|(j, _, _)| j.op).collect();
        let effects: Vec<crate::evidence::Effect> = w
            .calls
            .iter()
            .filter(|c| !c.fenced && !jobs.contains(&c.op))
            .map(|c| crate::evidence::Effect {
                call: name(&c.call, c.op.txn),
                txn: c.op.txn,
                epoch: c.op.epoch,
                seq: c.op.seq,
                start: c.at,
                end: Some(c.at),
            })
            .chain(w.job_spans.values().map(|(j, start, end)| crate::evidence::Effect {
                call: name(&format!("activate_live({})", j.activates.0), j.op.txn),
                txn: j.op.txn,
                epoch: j.op.epoch,
                seq: j.op.seq,
                start: *start,
                end: *end,
            }))
            .collect();
        let drivers = w.devices.iter().filter_map(|(d, r)| r.as_ref().map(|r| (d.clone(), r.name.clone()))).collect();
        let options = w.gens.get(&w.current).map(|g| g.eval.options.clone()).unwrap_or_default();
        let (current, boot_default, boot_entries, collected, overrides_empty) = (
            w.current,
            w.boot_default,
            w.boot_entries.iter().copied().collect(),
            w.collected.to_vec(),
            w.overrides.assignments.is_empty(),
        );
        let override_hash = Some(planarian_fake::World::override_hash_of(&w.overrides));
        let work = Some((w.stages - self.start_work.0, w.builds - self.start_work.1));
        let third_party_override = w.third_party_override;
        // §12 (R01): boot selection, roots, overrides and the journal agree.
        let ledger = self.ledger();
        let mut disagree = vec![];
        if w.boot_default != w.current {
            disagree.push(format!("boot default {} is not the running generation {}", w.boot_default.0, w.current.0));
        }
        if let Some(g) = w.one_shot {
            disagree.push(format!("a one-shot entry for generation {} is still armed", g.0));
        }
        if let (Some(h), Some(rec)) = (override_hash, w.gen_overrides.get(&w.current))
            && h != *rec
        {
            disagree.push(format!("the override file is not the one generation {} was committed with", w.current.0));
        }
        let live_roots: BTreeSet<&String> = ledger.live.values().filter_map(|t| t.txn.gc_root.as_ref()).collect();
        for r in w.gc_roots.iter().filter(|r| r.contains("/builds/") && !live_roots.contains(r)) {
            let entry =
                w.boot_entries.iter().any(|g| w.gens.get(g).is_some_and(|x| r.ends_with(&x.eval.source.to_hex())));
            if !entry {
                disagree.push(format!("GC root {r} belongs to no live transaction or boot entry"));
            }
        }
        for t in ledger.live.values() {
            disagree.push(format!("transaction {} is still {}", t.txn.id.0, tag(&t.txn.state)));
        }
        drop(w);
        crate::evidence::Evidence {
            current,
            boot_default,
            base: self.base,
            candidate: self.candidate,
            boot_entries,
            collected,
            work,
            overrides_empty,
            override_hash,
            third_party_override,
            agreement: Some(disagree),
            ledger,
            journal_replays,
            log: self.log.clone(),
            pre_status: self.pre_status.clone(),
            finals,
            touched: self.touched.clone(),
            seen_status: self.seen_status.clone(),
            seen_incidents: self.seen_incidents.clone(),
            open_incidents: self
                .core
                .as_ref()
                .map(|c| {
                    c.incidents
                        .incidents
                        .values()
                        .filter(|i| i.state != IncidentState::Closed)
                        .map(|i| (i.target.clone(), i.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            first_incident_at: self.first_incident_at.clone(),
            start: self.start,
            restarts,
            notices: self.notices.clone(),
            responses: self.responses.clone(),
            entries: Some(entries),
            full_replay,
            effects: Some(effects),
            status_timeline: Some(self.timeline.clone()),
            drivers: Some(drivers),
            options: Some(options),
            probe_defs: Some(probe_defs),
            gc_roots: Some(gc_roots),
            posture: crate::evidence::PostureSeen {
                chain_broken: matches!(Journal::open(self.fake.store.clone()), Err(JournalError::Integrity(_))),
                ..self.posture_seen.clone()
            },
        }
    }

    /// The current status of every unit, by name.
    pub fn statuses(&mut self) -> BTreeMap<UnitId, String> {
        let (s, defs) = self.observe();
        defs.keys()
            .map(|id| (id.clone(), format!("{:?}", s.status(id, &defs)).split('(').next().unwrap_or("").to_string()))
            .collect()
    }

    fn observe(&mut self) -> (SystemState, UnitDefs) {
        match self.core.as_mut() {
            Some(c) => c.observe(),
            None => {
                // The daemon is held down: observe the way it would.
                let g = self.fake.w().current;
                let gens = &self.fake;
                use planarian_schema::GenerationBackend;
                let m = gens
                    .path_of(g)
                    .and_then(|p| gens.evaluate_built(&p))
                    .map(|e| planarian_exec::derive::manifest_of(&e))
                    .unwrap_or_default();
                let mut a = planarian_state::Assembler::new(m, fixtures::canonical());
                let l = self.ledger();
                let ctx = planarian_state::Context {
                    known_good: l.known_good.unwrap_or(g),
                    live_tested: l.live_tested,
                    accepted_baseline: l.accepted_baseline,
                    security_floor: l.security_floor,
                    overrides: l.overrides.clone(),
                    core_hash: Hash::ZERO,
                };
                let s = a.observe(&self.fake, &ctx);
                let d = a.defs();
                (s, d)
            }
        }
    }

    /// Record what the daemon saw at the start of the last tick.
    fn record_status(&mut self) {
        if let Some((s, defs)) = self.core.as_ref().and_then(|c| c.last_observation().cloned()) {
            for id in defs.keys() {
                let st = s.status(id, &defs);
                let name = format!("{st:?}");
                let name = name.split('(').next().unwrap_or("").to_string();
                let line = self.timeline.entry(id.clone()).or_default();
                if line.last().is_none_or(|(_, n)| *n != name) {
                    line.push((s.observed_at, name.clone()));
                }
                self.seen_status.entry(id.clone()).or_default().insert(name);
            }
        }
    }

    /// The watchdog's 10 s pass.
    fn watchdog(&mut self) {
        if !self.fake.w().alive.contains(&WATCHDOG_PID) {
            return;
        }
        let Ok(j) = Journal::open(self.fake.store.clone()) else { return };
        let mut k = Kernel::new(
            j,
            ExecHost::new(self.fake.clone(), fixtures::canonical()),
            OwnerId::Watchdog { pid: WATCHDOG_PID, boot_id: self.boot_id() },
        );
        let live: Vec<Transaction> = k.journal.ledger().live.values().map(|l| l.txn.clone()).collect();
        for t in live {
            if k.watchdog_should_take_over(&t) {
                let r = k.recover(t.id, t.lease.epoch);
                self.notices.push(format!("watchdog: transaction {} found in {} → {r:?}", t.id.0, tag(&t.state)));
            }
        }
    }

    pub fn tick(&mut self) {
        self.fake.advance(TICK);
        if let Some(c) = self.core.as_mut() {
            c.tick();
            if let Some(why) = c.integrity.take() {
                self.harvest();
                self.integrity(why);
            }
        }
        self.record_status();
        if ((self.now().0 - self.start.0) / TICK.0).is_multiple_of(2) {
            self.watchdog();
        }
        self.harvest();
    }

    fn boot_id(&self) -> Hash {
        if self.boots == 0 { Hash::ZERO } else { Hash::of(format!("boot {}", self.boots).as_bytes()) }
    }

    fn kill_daemon(&mut self) {
        self.fake.w().alive.remove(&self.daemon_pid);
        self.core = None;
    }

    /// planariad stopped with status 78: posture.nix routes it to Integrity.
    fn integrity(&mut self, why: String) {
        self.kill_daemon();
        self.held = true;
        self.posture_seen.classes.insert("integrity".into());
        self.posture_seen.finding = Some(why.clone());
        self.notices.push(format!("INTEGRITY: {why}"));
    }

    fn start_daemon(&mut self) {
        self.daemon_pid += 1;
        let pid = self.daemon_pid;
        let j = match Journal::open(self.fake.store.clone()) {
            Ok(j) => j,
            Err(JournalError::Integrity(why)) => {
                return self.integrity(format!("journal: integrity: {why}"));
            }
            Err(e) => panic!("journal: {e:?}"),
        };
        self.fake.w().alive.insert(pid);
        let mut cfg = config();
        cfg.fresh_boot = std::mem::take(&mut self.fresh_boot);
        cfg.posture = self.posture;
        let boot_id = self.boot_id();
        let mut core = Core::start(j, self.fake.clone(), OwnerId::Daemon { pid, boot_id }, cfg);
        core.admin_of = gym_admins();
        // The executor log of the earlier runs, as the daemon reads it back.
        core.remember(self.log.clone());
        self.core = Some(core);
        self.harvest();
    }

    /// Send a request as `actor`; a crash point set by a later `kill_process`
    /// fires inside it.
    fn request(&mut self, actor: &str, req: Request) -> Result<(), Unsupported> {
        self.request_peer(peer(actor), req)
    }

    fn request_peer(&mut self, mut p: Peer, req: Request) -> Result<(), Unsupported> {
        if let (Some(name), None) = (&p.agent, p.instance) {
            p.instance = self.fake.w().agent_instances.get(name).copied();
        }
        let Some(core) = self.core.as_mut() else { return Err(Unsupported("request while the daemon is down".into())) };
        core.ex.kernel.crash_at = self.crash.clone();
        let r = core.handle(p, req);
        let crashed = matches!(&r, Response::Error { message } if message.contains("Crashed"));
        if let Some(c) = self.core.as_mut() {
            c.ex.kernel.crash_at = None;
        }
        self.responses.push(r);
        self.harvest();
        // An interrupted journal write is a crash mid-write: the process is gone.
        if crashed || (self.fake.store.torn() && !self.torn_seen) {
            self.torn_seen = self.fake.store.torn();
            self.kill_daemon();
            self.crash = None;
        }
        self.track_candidate();
        Ok(())
    }

    fn track_candidate(&mut self) {
        let l = self.ledger();
        // The generation the entry's change builds: a rollback's, revert's or
        // switch's target is an existing generation, not a candidate.
        if let Some(c) = l
            .live
            .values()
            .filter(|t| {
                !matches!(
                    t.txn.transition,
                    Transition::Rollback | Transition::Revert { .. } | Transition::SwitchGeneration { .. }
                )
            })
            .filter_map(|t| t.txn.candidate.as_ref().map(|(g, _)| *g))
            .next_back()
        {
            self.candidate = Some(c);
        }
        let w = self.fake.w();
        if self.candidate.is_none() && w.gens.len() > 1 {
            drop(w);
            self.candidate = self.fake.w().gens.keys().copied().max().filter(|g| *g != self.base);
        }
    }

    /// Run until `pred` holds or `limit` passes.
    fn until(&mut self, limit: Millis, mut pred: impl FnMut(&mut Sim) -> bool) {
        let end = self.now().plus(limit);
        while self.now() < end && !pred(self) {
            self.tick();
        }
    }

    fn journal_reached(&self, state: &str) -> bool {
        let l = self.ledger();
        l.live.values().any(|t| t.path.iter().any(|p| p == state))
            || l.terminal.values().any(|t| t.path.iter().any(|p| p == state))
    }

    /// Pre-scan the steps. Transactions run synchronously here, so a step
    /// timed to a journal state (`when = { journal = X }`) is armed before the
    /// transaction it refers to: a planariad kill becomes a crash point on the
    /// last transaction before it; the other faults become hooks in the fake
    /// machine. Returns the indices of steps consumed this way, and the index
    /// of the step the crash point belongs to.
    pub fn arm(&mut self, steps: &[&T]) -> (std::collections::BTreeSet<usize>, Option<(usize, CrashPoint)>) {
        let mut consumed = std::collections::BTreeSet::new();
        let mut crash = None;
        let is_txn = |s: &T| {
            s.get("transition").is_some()
                || matches!(s.get("raw").and_then(T::as_str), Some("ask" | "cli" | "approve_pending"))
        };
        for (i, s) in steps.iter().enumerate() {
            for (key, point) in [("op_called", CrashPoint::OpCalled as fn(_) -> _), ("op_begun", CrashPoint::OpBegun)] {
                if let Some(call) = s.get("when").and_then(|w| w.get(key)).and_then(T::as_str) {
                    let call: &'static str = Box::leak(call.to_string().into_boxed_str());
                    if let Some(j) = (0..i).rev().find(|j| is_txn(steps[*j])) {
                        crash = Some((j, point(call)));
                    }
                }
            }
            if s.get("when").is_some_and(|w| w.get("op_called").is_some() || w.get("op_begun").is_some()) {
                continue;
            }
            let Some(state) = s.get("when").and_then(|w| w.get("journal")).and_then(T::as_str) else { continue };
            let get = |k: &str| s.get(k).and_then(T::as_str).unwrap_or("");
            match get("raw") {
                "kill_process" if get("process") == "planariad" => {
                    let state: &'static str = Box::leak(state.to_string().into_boxed_str());
                    // With a slow activation worker set up, "during Activating"
                    // means while that worker runs: once the call has started it.
                    let slow_worker = steps.iter().any(|x| {
                        x.get("raw").and_then(T::as_str) == Some("slow_backend")
                            && x.get("call").and_then(T::as_str) == Some("activate_live")
                    });
                    let point = if state == "OpId" || (state == "Activating" && slow_worker) {
                        CrashPoint::OpCalled("activate_live")
                    } else {
                        CrashPoint::State(state)
                    };
                    if let Some(j) = (0..i).rev().find(|j| is_txn(steps[*j])) {
                        crash = Some((j, point));
                    }
                }
                // The write of the record entering this state is torn.
                "interrupt_write" if get("target") == "record" => {
                    self.fake.store.tear_write_containing(&format!("\"to\":\"{state}\""));
                    consumed.insert(i);
                }
                "edit_owner_source" if s.get("tracked").and_then(T::as_bool) != Some(false) => {
                    self.fake.w().edit_on_stage = true;
                    consumed.insert(i);
                }
                "fill_fs" if get("fs") == "device:fs-nix" => {
                    let mut w = self.fake.w();
                    w.nospace_on_build = true;
                    if let Some((free, _)) = w.fs.get_mut("/nix") {
                        *free = 0;
                    }
                    consumed.insert(i);
                }
                "edit_override_file" if state == "Published" => {
                    self.fake.w().third_party_on_publish = true;
                    consumed.insert(i);
                }
                "fill_fs" if get("fs") == "device:fs-boot" => {
                    self.fake.w().fail_publish = true;
                    consumed.insert(i);
                }
                "block_network" if get("dst") == "127.0.0.1" => {
                    self.fake.w().block_on_activate.insert(UnitId::service("sshd"));
                    consumed.insert(i);
                }
                _ => {}
            }
        }
        (consumed, crash)
    }

    pub fn set_crash(&mut self, p: Option<CrashPoint>) {
        self.crash = p;
    }

    pub fn step(&mut self, s: &T) -> Result<(), Unsupported> {
        let get = |k: &str| s.get(k).and_then(T::as_str).unwrap_or("");
        for k in ["unit", "device"] {
            if let Some(u) = s.get(k).and_then(T::as_str) {
                self.touched.insert(unit(u));
            }
        }
        let actor = s.get("actor").and_then(T::as_str).unwrap_or("user:1001").to_string();
        if let Some(t) = s.get("transition").and_then(T::as_str) {
            return self.transition(t, s, &actor);
        }
        match get("raw") {
            "kill_unit" => {
                let sig = match get("signal") {
                    "SIGHUP" => 1,
                    "SIGINT" => 2,
                    "SIGABRT" => 6,
                    "SIGSEGV" => 11,
                    "SIGTERM" => 15,
                    _ => 9,
                };
                self.fake.w().signal(&unit(get("unit")), sig)
            }
            "oom" => self.fake.w().oom(&unit(get("unit"))),
            "stop_unit_out_of_band" => self.fake.w().stop_out_of_band(&unit(get("unit"))),
            "set_knob" | "set_persistent_knob" => self.knob(&unit(get("unit")), get("knob"), s.get("value"))?,
            "corrupt_state" => {
                if let Some(sim) = self.fake.w().units.get_mut(&unit(get("unit"))) {
                    sim.fail_on_start = true;
                }
            }
            "unbind_driver" => {
                self.fake.w().devices.insert(unit(get("device")), None);
            }
            "block_network" => match (get("dst"), s.get("port").and_then(T::as_integer)) {
                ("127.0.0.1", Some(22)) => {
                    self.fake.w().blocked.insert(UnitId::service("sshd"));
                }
                // Dropped, as the VM's iptables DROP does: probes time out.
                ("10.0.2.2", None) => {
                    self.fake.w().external_unreachable.insert("gym-upstream".into());
                }
                (d, p) => return Err(Unsupported(format!("block_network {d} {p:?}"))),
            },
            "unblock_network" => {
                let mut w = self.fake.w();
                w.blocked.clear();
                w.external_unreachable.clear();
            }
            // An access point goes away: NetworkManager drops the network
            // and does not pick another (autoconnect is off for the others).
            "stop_host_service" if get("name").starts_with("hostapd-") => {
                let ssid = get("name").trim_start_matches("hostapd-").to_string();
                let mut w = self.fake.w();
                w.wifi_in_range.remove(&ssid);
                if w.runtime.get("wifi.network") == Some(&Value::Str(ssid)) {
                    w.runtime.remove("wifi.network");
                }
            }
            "stop_host_service" if get("name") == "gym-upstream" => {
                self.fake.w().external_down.insert("gym-upstream".into());
            }
            "start_host_service" if get("name") == "gym-upstream" => {
                self.fake.w().external_down.remove("gym-upstream");
            }
            "kill_process" => match get("process") {
                "planariad" => {
                    if s.get("when").is_some() {
                        // Armed by `arm`; if it has not fired yet, wait for it.
                        self.until(Millis::secs(600), |sim| sim.core.is_none());
                    } else {
                        self.kill_daemon();
                    }
                }
                "planarian-recovery" => {
                    self.fake.w().alive.remove(&WATCHDOG_PID);
                }
                p => return Err(Unsupported(format!("kill_process {p}"))),
            },
            "hold_down" => self.held = true,
            // I18: edit a retained record's bytes in place, CRC recomputed, so
            // only the hash chain can tell (the next record's `prev`).
            "break_journal_chain" => {
                if get("when") == "powered-off" {
                    self.kill_daemon();
                }
                let n = Journal::open(self.fake.store.clone())
                    .and_then(|mut j| j.segment())
                    .map(|seg| seg.len())
                    .map_err(|e| Unsupported(format!("break_journal_chain: {e:?}")))?;
                if n < 3 {
                    return Err(Unsupported("break_journal_chain: fewer than 3 records".into()));
                }
                let edited = planarian_txn::journal::tamper(&self.fake.store, n / 2, |p| {
                    if let Some(b) = p.iter_mut().find(|b| b.is_ascii_digit()) {
                        *b = if *b == b'9' { b'1' } else { *b + 1 };
                    }
                });
                if !matches!(edited, Ok(true)) {
                    return Err(Unsupported(format!("break_journal_chain: {edited:?}")));
                }
            }
            // I18: delete a retained record (not edit it), the rest re-framed
            // so every frame is intact; only the chain can tell.
            "delete_journal_record" => {
                let n = s.get("record").and_then(T::as_integer).unwrap_or(1) as usize;
                let gone = planarian_txn::journal::delete(&self.fake.store, n)
                    .map_err(|e| Unsupported(format!("delete_journal_record: {e}")))?;
                if !gone {
                    return Err(Unsupported(format!("delete_journal_record: no record {n}")));
                }
            }
            // `sudo planarian-ack` (nix/posture.nix): an administrator's clears
            // the alarm, journaled with identity; anyone else's is refused.
            "ack_alarm" => {
                if peer(&actor).admin {
                    self.posture_seen.acks.push(actor.clone());
                } else {
                    self.posture_seen.refused_acks.push(actor.clone());
                }
            }
            "release" | "restart_process" => match get("process") {
                "planariad" => {
                    self.held = false;
                    // `systemctl restart`: a running daemon stops first.
                    if get("raw") == "restart_process" && self.core.is_some() {
                        self.kill_daemon();
                    }
                    if self.core.is_none() {
                        self.start_daemon();
                    }
                }
                "planarian-recovery" => {
                    self.fake.w().alive.insert(WATCHDOG_PID);
                }
                p => return Err(Unsupported(format!("restart_process {p}"))),
            },
            "wait" => match s.get("for") {
                Some(T::Table(t)) if t.contains_key("journal") => {
                    let state = t["journal"].as_str().unwrap_or("").to_string();
                    self.until(Millis::secs(1800), |sim| sim.journal_reached(&state));
                }
                Some(v) => {
                    let d = dur(v).ok_or_else(|| Unsupported(format!("wait {v}")))?;
                    self.until(d, |_| false);
                }
                None => {}
            },
            "ask" => self.request(&actor, Request::Ask { phrase: get("phrase").into(), choice: None })?,
            // In the fake a peer's session comes only from the actor string,
            // so a gone peer is one without a session.
            "request_then_exit" => {
                let req: Request = serde_json::from_value(
                    serde_json::to_value(s.get("request").ok_or_else(|| Unsupported("request".into()))?)
                        .map_err(|e| Unsupported(e.to_string()))?,
                )
                .map_err(|e| Unsupported(format!("request_then_exit: {e}")))?;
                let actor = get("actor");
                let who = actor.split('@').next().unwrap_or("user:1000").to_string();
                self.request(&who, req)?;
            }
            // I14: a request carrying fields it must not set (a caller, a
            // sensitivity, affected units), parsed as the daemon parses it.
            "forge_proposal_fields" => {
                let r = s.get("request").and_then(T::as_table).ok_or_else(|| Unsupported("request".into()))?;
                let args: BTreeMap<String, Value> = r
                    .get("args")
                    .and_then(T::as_table)
                    .map(|a| a.iter().map(|(k, v)| (k.clone(), value(v))).collect())
                    .unwrap_or_default();
                let change = ChangeId(r.get("change").and_then(T::as_str).unwrap_or("").into());
                let mut line = serde_json::to_value(Request::Apply { change, args }).expect("serializes");
                let forged = serde_json::to_value(s.get("fields").cloned().unwrap_or(T::Table(Default::default())))
                    .map_err(|e| Unsupported(e.to_string()))?;
                if let (Some(o), Some(f)) = (line.as_object_mut(), forged.as_object()) {
                    o.extend(f.clone());
                }
                let req: Request =
                    serde_json::from_value(line).map_err(|e| Unsupported(format!("forge_proposal_fields: {e}")))?;
                self.request(&actor, req)?;
            }
            "agent_run" => {
                let name = get("name");
                let argv: Vec<String> = s
                    .get("argv")
                    .and_then(T::as_array)
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let actor = s.get("as").and_then(T::as_str).unwrap_or("user:1001").to_string();
                self.request(&actor, Request::AgentRun { name: name.to_string(), argv })?;
            }
            "cli" => {
                let argv: Vec<String> = s
                    .get("argv")
                    .and_then(T::as_array)
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                // Present an approval held earlier (the hash it was issued for).
                // The admin connects to a network outside Planarian.
                if let ["internal", "wifi-connect", ssid] =
                    argv.iter().map(String::as_str).collect::<Vec<_>>().as_slice()
                {
                    self.fake.w().runtime.insert("wifi.network".into(), Value::Str(ssid.to_string()));
                    return Ok(());
                }
                if argv.first().map(String::as_str) == Some("internal")
                    && argv.get(1).map(String::as_str) == Some("present-token")
                {
                    for h in self.held_tokens.clone() {
                        self.request_peer(peer(&actor).at_terminal(), Request::Approve { hash: h })?;
                    }
                    return Ok(());
                }
                let req = self.cli(&argv)?;
                self.request(&actor, req)?;
            }
            "approve_pending" => {
                let pending: Vec<Hash> =
                    self.core.as_ref().map(|c| c.ex.parked.values().map(|p| p.bound_to).collect()).unwrap_or_default();
                if s.get("hold_token").and_then(T::as_bool) == Some(true) {
                    self.held_tokens.extend(pending);
                    return Ok(());
                }
                // As the step's actor, at a terminal unless `via = "no-tty"`.
                let actor = s.get("actor").and_then(T::as_str).unwrap_or("root").to_string();
                let tty = s.get("via").and_then(T::as_str) != Some("no-tty");
                for h in pending {
                    let p = if tty { peer(&actor).at_terminal() } else { peer(&actor) };
                    self.request_peer(p, Request::Approve { hash: h })?;
                }
            }
            "greeter_login" => {
                let uid = s.get("uid").and_then(T::as_integer).unwrap_or(1000) as u32;
                let now = self.now();
                self.fake.w().sessions.push(SessionInfo {
                    id: format!("s{uid}"),
                    uid,
                    class: "user".into(),
                    seat: Some("seat0".into()),
                    remote: false,
                    active: true,
                    idle: false,
                    created: now,
                });
                let sim = planarian_fake::UnitSim::active(now);
                for name in ["pipewire", "wireplumber"] {
                    self.fake.w().units.insert(
                        UnitId {
                            kind: UnitKind::Service,
                            name: name.into(),
                            scope: Scope::User { uid, session: None },
                        },
                        sim.clone(),
                    );
                }
                // The compositor brings the user's graphical session up.
                self.fake.w().units.insert(
                    UnitId {
                        kind: UnitKind::Target,
                        name: "graphical-session".into(),
                        scope: Scope::User { uid, session: None },
                    },
                    sim,
                );
            }
            // The machine restarts: the boot loader picks the entry (a one-shot
            // first, unless it fails), and the daemon starts on a fresh boot.
            "reboot" => {
                self.kill_daemon();
                self.fake.w().reboot();
                self.boots += 1;
                self.fresh_boot = true;
                self.start_daemon();
            }
            "fail_boot" => self.fake.w().fail_one_shot = true,
            "logout" => {
                let uid = s.get("uid").and_then(T::as_integer).unwrap_or(1000) as u32;
                self.fake.w().sessions.retain(|x| x.uid != uid);
            }
            // §10: a named logind session, at a seat or (no seat) remote; its
            // compositor comes up unless `compositor = "fails"`.
            "session_login" => {
                let uid = s.get("uid").and_then(T::as_integer).unwrap_or(1000) as u32;
                let id = get("session").to_string();
                let seat = s.get("seat").and_then(T::as_str).map(String::from);
                // An SSH-only login (no seat) starts no compositor.
                let compositor = seat.is_some() && get("compositor") != "fails";
                let now = self.now();
                let mut w = self.fake.w();
                w.sessions.push(SessionInfo {
                    id: id.clone(),
                    uid,
                    class: "user".into(),
                    remote: seat.is_none(),
                    seat,
                    active: true,
                    idle: false,
                    created: now,
                });
                w.compositors.insert(id, compositor);
                let sim = planarian_fake::UnitSim::active(now);
                for name in ["pipewire", "wireplumber"] {
                    let u = UnitId {
                        kind: UnitKind::Service,
                        name: name.into(),
                        scope: Scope::User { uid, session: None },
                    };
                    w.units.entry(u).or_insert_with(|| sim.clone());
                }
            }
            "session_logout" => {
                let id = get("session").to_string();
                let mut w = self.fake.w();
                w.sessions.retain(|x| x.id != id);
                w.compositors.remove(&id);
                // The user manager (and its services) ends with the uid's last session.
                let uids: BTreeSet<u32> = w.sessions.iter().map(|x| x.uid).collect();
                w.units.retain(|u, _| !matches!(u.scope, Scope::User { uid, .. } if !uids.contains(&uid)));
            }
            "foreground" => {
                let id = get("session").to_string();
                let on = s.get("on").and_then(T::as_bool).unwrap_or(true);
                let mut w = self.fake.w();
                if on {
                    w.foreground.insert(id);
                } else {
                    w.foreground.remove(&id);
                }
            }
            "slow_backend" if get("call") == "activate_live" => {
                let d = s.get("delay").and_then(dur).unwrap_or(Millis::secs(120));
                let uncancellable = s.get("uncancellable").and_then(T::as_bool).unwrap_or(false);
                self.fake.w().slow_activation = Some((d, !uncancellable));
            }
            "withhold_reply" if get("call") == "activate_live" => {
                self.fake.w().slow_activation = Some((Millis::secs(30), false));
            }
            "backend_result" => match (get("call"), get("result")) {
                ("jobs_tagged", "None") => self.fake.w().jobs_tagged_unknown = true,
                // A policy table changes (one no decision here reads), so the
                // policy version every approval is bound to changes.
                ("policy_version", "bumped") => {
                    let c =
                        self.core.as_mut().ok_or_else(|| Unsupported("policy bump while the daemon is down".into()))?;
                    c.ex.cfg.tables.model_catalog.push(ModelId("gym:policy-bump".into()));
                }
                ("evaluate", "planariad-unit-changed") => {
                    self.fake.w().rules.push(planarian_fake::Rule {
                        option: "planarian.reference.fontScale".into(),
                        value: Value::Str("1.25".into()),
                        effect: planarian_fake::Effect::TouchCore,
                    });
                }
                ("dry_activate", r @ ("exit-nonzero" | "timeout" | "truncated")) => {
                    self.fake.w().dry_activate_fails = Some(format!("dry activation: {r}"));
                }
                ("verify_candidate", "nar-mismatch") => {
                    self.fake.w().nar_mismatch = true;
                }
                ("activate_live", "Failed") => {
                    let base = self.base;
                    self.fake.w().fail_activate.insert(base);
                }
                (c, r) => return Err(Unsupported(format!("backend_result {c} {r}"))),
            },
            "edit_owner_source" => {
                let path = get("path").to_string();
                let tracked = s.get("tracked").and_then(T::as_bool).unwrap_or(true);
                if tracked {
                    let mut w = self.fake.w();
                    w.owner_files.insert(path, "edited".into());
                    // An edit that enables a service, not yet rebuilt: the
                    // owner's tree (what staging copies) now declares it.
                    if let Some(svc) = s.get("enables").and_then(T::as_str) {
                        w.base_options.insert(format!("services.{svc}.enable"), Value::Bool(true));
                    }
                } else {
                    self.fake.w().untracked.insert(path);
                }
            }
            // Suspended: time passes and nothing runs, the daemon included;
            // on resume its evidence is stale and it ticks on as before.
            "suspend" => {
                let d = s.get("duration").and_then(dur).ok_or_else(|| Unsupported("suspend duration".into()))?;
                self.fake.advance(d);
            }
            // §12h: only the wall clock moves; the boot clock does not.
            "set_wall_clock" => {
                let by = get("by");
                let (neg, rest) = match by.strip_prefix('-') {
                    Some(r) => (true, r.to_string()),
                    None => (false, by.trim_start_matches('+').to_string()),
                };
                let d = dur(&T::String(rest)).ok_or_else(|| Unsupported(format!("set_wall_clock {by}")))?;
                let ms = d.0 as i64;
                self.fake.w().wall_skew += if neg { -ms } else { ms };
            }
            "advance_clock" => {
                let d = s.get("by").and_then(dur).ok_or_else(|| Unsupported("advance_clock".into()))?;
                self.fake.advance(d);
                if let Some(c) = self.core.as_mut() {
                    c.tick();
                }
            }
            // A checkpoint write is torn: the compaction fails, and the old
            // checkpoint and log must stand.
            "interrupt_write" if get("target") == "checkpoint" => {
                self.save_segment();
                self.compacted = true;
                self.fake.store.fail_next_checkpoint();
                if let Some(c) = self.core.as_mut() {
                    let _ = c.ex.kernel.journal.compact();
                } else {
                    let _ = Journal::open(self.fake.store.clone()).map(|mut j| j.compact());
                }
            }
            // §12c (C16): a checkpoint whose bytes were damaged while the
            // daemon was down; its CRC no longer matches.
            "corrupt_checkpoint" => {
                self.kill_daemon();
                let mut b = self
                    .fake
                    .store
                    .read_checkpoint()
                    .ok()
                    .flatten()
                    .ok_or_else(|| Unsupported("corrupt_checkpoint: no checkpoint".into()))?;
                let mid = b.len() / 2;
                b[mid] ^= 0x20;
                self.fake.store.write_checkpoint(&b).map_err(|e| Unsupported(e.to_string()))?;
            }
            "force_compaction" => {
                self.save_segment();
                self.compacted = true;
                if let Some(c) = self.core.as_mut() {
                    let _ = c.ex.kernel.journal.compact();
                } else {
                    let _ = Journal::open(self.fake.store.clone()).map(|mut j| j.compact());
                }
            }
            "hotunplug" => {
                self.fake.w().devices.remove(&unit(get("device")));
            }
            "fill_fs" => {
                let path = match get("fs") {
                    "device:fs-nix" => "/nix",
                    "device:fs-boot" => "/boot",
                    "device:fs-journal" => "/var/lib/planarian",
                    _ => "/",
                };
                if get("until") == "full" && path == "/boot" {
                    self.fake.w().fail_publish = true;
                }
                if let Some((free, size)) = self.fake.w().fs.get_mut(path) {
                    *free = if get("until") == "full" { 0 } else { *size / 100 };
                }
            }
            "set_setting" => match get("key") {
                "gc.retain_all" => {
                    self.fake.w().gc_budget.retain_all = s.get("value").and_then(T::as_bool).unwrap_or(true);
                }
                "gc.generation_budget_percent" => {
                    let pct =
                        s.get("value").and_then(T::as_float).ok_or_else(|| Unsupported("set_setting value".into()))?;
                    self.fake.w().gc_budget.generations_permille = (pct * 10.0).round() as u32;
                }
                "userControllable" => {
                    let units: Vec<String> = s
                        .get("value")
                        .and_then(T::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(T::as_str)
                        .map(|u| unit(u).name)
                        .collect();
                    let c = self.core.as_mut().ok_or_else(|| Unsupported("daemon down".into()))?;
                    c.ex.cfg.settings.user_controllable_units.extend(units);
                }
                "userControllableChanges" => {
                    let add: Vec<ChangeId> = s
                        .get("value")
                        .and_then(T::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(T::as_str)
                        .map(|c| ChangeId(c.into()))
                        .collect();
                    let c = self.core.as_mut().ok_or_else(|| Unsupported("daemon down".into()))?;
                    c.ex.cfg.settings.user_controllable_changes.extend(add);
                }
                "max_tier" => {
                    let tier = match s.get("value").and_then(T::as_str) {
                        Some("Observe") => Tier::Observe,
                        Some("Runtime") => Tier::Runtime,
                        Some("Tested") => Tier::Tested,
                        v => return Err(Unsupported(format!("set_setting max_tier {v:?}"))),
                    };
                    let c = self.core.as_mut().ok_or_else(|| Unsupported("daemon down".into()))?;
                    c.ex.cfg.settings.max_tier = tier;
                }
                "posture" => {
                    self.posture = match s.get("value").and_then(T::as_str) {
                        Some("Relaxed") => planarian_schema::Posture::Relaxed,
                        Some("Guarded") => planarian_schema::Posture::Guarded,
                        Some("Sealed") => planarian_schema::Posture::Sealed,
                        _ => planarian_schema::Posture::Standard,
                    };
                    let p = self.posture;
                    if let Some(c) = self.core.as_mut() {
                        c.set_posture(p);
                    }
                }
                k => return Err(Unsupported(format!("set_setting {k}"))),
            },
            "out_of_band_rebuild" => {
                let edit = get("edit");
                let activate = s.get("activate").and_then(T::as_bool).unwrap_or(false);
                let mut w = self.fake.w();
                if let Some(n) = edit
                    .strip_prefix("create ")
                    .and_then(|r| r.split_whitespace().next())
                    .and_then(|n| n.parse::<usize>().ok())
                {
                    for _ in 0..n {
                        let o = OverrideSet::default();
                        let g = w.add_generation(&o);
                        w.boot_entries.insert(g);
                    }
                } else if edit == "build-only NetworkManager store path" {
                    // R04: equal manifests; only the network unit's store
                    // path differs, which only a dry activation sees.
                    let g = w.add_generation(&OverrideSet::default());
                    let nm = UnitId::service("NetworkManager");
                    w.gens.get_mut(&g).expect("added").eval.activation.restart.insert(nm);
                    w.boot_entries.insert(g);
                } else if edit.contains("gym-web ExecStart=/bin/false") {
                    let o = OverrideSet::default();
                    let g = w.add_generation(&o);
                    w.gens.get_mut(&g).expect("added").broken.insert(UnitId::service("gym-web"));
                    if activate {
                        // The owner switched to it themselves: it is their generation now.
                        w.boot_entries.insert(g);
                        w.boot_default = g;
                        let sim = w.units.get_mut(&UnitId::service("gym-web")).expect("gym-web");
                        sim.observed = Observed::Failed(Reason::ExitCode(1));
                        w.current = g;
                    }
                } else if edit.starts_with("update input gym-modules") {
                    // The supply-chain path: the input moves to a revision
                    // whose module declares the payload; root switches.
                    w.base_options.insert("gym.modules".into(), Value::Str("new".into()));
                    w.base_inputs.insert("gym-modules".into(), ("new".into(), "/nix/store/bbb-gym-modules".into()));
                    w.rebuild_uid = if actor == "root" { 0 } else { peer(&actor).uid };
                    let g = w.add_generation(&OverrideSet::default());
                    w.rebuild_uid = 0;
                    w.boot_entries.insert(g);
                    w.boot_default = g;
                    w.apply_generation(g);
                } else if edit == "enable gym-bad-payload" {
                    // The owner's configuration now enables it; root switches.
                    w.base_options.insert("services.gym-bad-payload.enable".into(), Value::Bool(true));
                    w.rebuild_uid = if actor == "root" { 0 } else { peer(&actor).uid };
                    let g = w.add_generation(&OverrideSet::default());
                    w.rebuild_uid = 0;
                    w.boot_entries.insert(g);
                    w.boot_default = g;
                    w.apply_generation(g);
                } else {
                    return Err(Unsupported(format!("out_of_band_rebuild {edit:?}")));
                }
            }
            other => return Err(Unsupported(format!("raw action {other:?}"))),
        }
        self.harvest();
        Ok(())
    }

    fn knob(&mut self, u: &UnitId, knob: &str, v: Option<&T>) -> Result<(), Unsupported> {
        let mut w = self.fake.w();
        let now = w.now;
        let sim = w.units.get_mut(u).ok_or_else(|| Unsupported(format!("no unit {u}")))?;
        match (knob, v) {
            ("health", Some(T::Integer(503))) => sim.health = Health::Http503,
            ("health_delay", Some(d)) => sim.health = Health::Delay(dur(d).unwrap_or(Millis::secs(15))),
            ("probe_delay", Some(d)) => sim.health = Health::Stall(dur(d).unwrap_or(Millis::secs(15))),
            ("fail_after", Some(d)) => {
                sim.fail_after = dur(d);
                sim.started_at = now;
            }
            ("fail_on_start", Some(T::Boolean(b))) => sim.fail_on_start = *b,
            (k, v) => return Err(Unsupported(format!("knob {k}={v:?}"))),
        }
        Ok(())
    }

    fn cli(&self, argv: &[String]) -> Result<Request, Unsupported> {
        let a: Vec<&str> = argv.iter().map(String::as_str).collect();
        Ok(match a.as_slice() {
            ["override", u] => Request::SetOverride {
                unit: unit(u),
                until: Until::Explicit,
                desired: planarian_schema::OverrideDesired::LeaveAlone,
            },
            ["override", u, "--stop" | "--stopped"] => Request::SetOverride {
                unit: unit(u),
                until: Until::Explicit,
                desired: planarian_schema::OverrideDesired::Stopped,
            },
            ["stop", u] => Request::Stop { unit: unit(u) },
            ["restart", u] => Request::Restart { unit: unit(u) },
            ["ack"] => Request::Acknowledge { unit: None },
            ["ack", u] => Request::Acknowledge { unit: Some(unit(u)) },
            ["release", u] => Request::LiftOverride { unit: unit(u) },
            ["resolve", _t, how] => {
                let l = self.ledger();
                // `resolve any`: the interlocked transaction, or with none
                // interlocked, one that does not exist (authorization is
                // decided before the transaction is looked up).
                let txn = match (l.interlock.keys().next(), *_t) {
                    (Some(t), _) => *t,
                    (None, "any") => TxnId(u64::MAX),
                    (None, _) => return Err(Unsupported("resolve: nothing interlocked".into())),
                };
                let resolution = match *how {
                    "--as-committed" => Resolution::AsCommitted,
                    "--as-reverted" => Resolution::AsReverted,
                    _ => Resolution::ManualRepaired,
                };
                Request::Resolve { txn, resolution }
            }
            ["diagnose", u, "--probe", p] => Request::Diagnose { unit: unit(u), probe: Some(ProbeId(p.to_string())) },
            ["undo"] => Request::Undo,
            other => return Err(Unsupported(format!("cli {other:?}"))),
        })
    }

    fn transition(&mut self, t: &str, s: &T, actor: &str) -> Result<(), Unsupported> {
        let get = |k: &str| s.get(k).and_then(T::as_str).unwrap_or("").to_string();
        let req = match t {
            "ApplyChange" => {
                let args: BTreeMap<String, Value> = s
                    .get("args")
                    .and_then(T::as_table)
                    .map(|a| a.iter().map(|(k, v)| (k.clone(), value(v))).collect())
                    .unwrap_or_default();
                Request::Apply { change: ChangeId(get("change")), args }
            }
            "RestartUnit" if s.get("expected").is_some() || s.get("observed").is_some() => {
                let core = self.core.as_mut().ok_or_else(|| Unsupported("daemon down".into()))?;
                let (st, defs) = core.observe();
                let t = Transition::RestartUnit(unit(&get("unit")));
                let mut expected = planarian_schema::spec::predict(&t, &st, &defs);
                if let Some(m) = s.get("expected").and_then(|e| e.get("may_change")).and_then(T::as_array) {
                    expected.may_change = m.iter().filter_map(T::as_str).map(unit).collect();
                }
                let observed = if s.get("observed").is_some() { Hash::ZERO } else { st.digest() };
                let p = Proposal { observed, expected, transition: t, reason: "gym".into(), source: Source::User };
                let pe = peer(actor);
                let authz = gym_authz(actor);
                let policy = core.ex.policy_version();
                let r = core.ex.submit(p.clone(), authz, &st, &defs);
                let (facts, decision) = core.ex.last.clone().unzip();
                let now = self.fake.w().now;
                self.log.push(planarian_daemon::LogRecord {
                    at: now,
                    proposal: p,
                    caller: Actor::user(pe.uid),
                    pre_digest: st.digest(),
                    policy,
                    result: r,
                    facts,
                    decision,
                    post_digest: None,
                    path: vec![],
                    why: String::new(),
                    agent: None,
                });
                return Ok(());
            }
            "RestartUnit" => Request::Restart { unit: unit(&get("unit")) },
            "CollectGarbage" => Request::Gc,
            "Rollback" => return self.direct(actor, Transition::Rollback),
            // Restoring a snapshot overwrites user data (NonReversible).
            "RestoreSnapshot" => {
                let id = SnapshotId(get("snapshot"));
                return self.direct(actor, Transition::RestoreSnapshot(id));
            }
            "SwitchGeneration" => {
                let g = self.fake.w().gens.keys().copied().max().unwrap_or(GenerationId(1));
                self.candidate = Some(g);
                return self.direct(actor, Transition::SwitchGeneration(g));
            }
            "BindDriver" => {
                let device = unit(&get("device"));
                let driver = DriverRef { name: get("driver"), module: None };
                return self.direct(actor, Transition::BindDriver { device, driver });
            }
            "SetOverride" => Request::SetOverride {
                unit: unit(&get("unit")),
                until: Until::Explicit,
                desired: planarian_schema::OverrideDesired::LeaveAlone,
            },
            other => return Err(Unsupported(format!("transition {other}"))),
        };
        self.request(actor, req)
    }

    /// Submit through the executor directly, for transitions the CLI doesn't expose.
    fn direct(&mut self, actor: &str, t: Transition) -> Result<(), Unsupported> {
        let crash = self.crash.clone();
        let core = self.core.as_mut().ok_or_else(|| Unsupported("daemon down".into()))?;
        core.ex.kernel.crash_at = crash;
        let (st, defs) = core.observe();
        let p = Proposal {
            observed: st.digest(),
            expected: planarian_schema::spec::predict(&t, &st, &defs),
            transition: t,
            reason: "gym".into(),
            source: Source::User,
        };
        let pe = peer(actor);
        let authz = gym_authz(actor);
        let policy = core.ex.policy_version();
        let r = core.ex.submit(p.clone(), authz, &st, &defs);
        let (facts, decision) = core.ex.last.clone().unzip();
        if let Some(c) = self.core.as_mut() {
            c.ex.kernel.crash_at = None;
        }
        let crashed = matches!(&r, planarian_exec::Submitted::Error(e) if e.contains("Crashed"));
        let now = self.fake.w().now;
        self.log.push(planarian_daemon::LogRecord {
            at: now,
            proposal: p,
            caller: Actor::user(pe.uid),
            pre_digest: st.digest(),
            policy,
            result: r,
            facts,
            decision,
            post_digest: None,
            path: vec![],
            why: String::new(),
            agent: None,
        });
        if crashed {
            self.kill_daemon();
            self.crash = None;
        }
        Ok(())
    }

    /// Run ticks for the rest of the window, restarting the daemon unless held down.
    pub fn run_window(&mut self, window: Millis) {
        let end = self.start.plus(window);
        while self.now() < end {
            if self.core.is_none() && !self.held {
                self.start_daemon();
            }
            self.tick();
        }
    }
}
