//! The daemon loop (SPEC §10, §13) and request handling (§14, §16).
//!
//! Each tick does the following, in order:
//! 1. assemble state;
//! 2. advance the incidents and journal any that changed;
//! 3. re-probe the targets of diagnostic incidents;
//! 4. unless the machine is busy or interlocked, ask the diagnoser for one
//!    incident and submit its proposal through the executor;
//! 5. expire approvals, compact the journal, and run the boot-confirmation
//!    checkpoint.
//!
//! Every change goes through `Executor::submit`; nothing here calls a mutating
//! backend method.

use crate::render;
use planarian_diagnose as diagnose;
use planarian_exec::{Config as ExecConfig, Executor, PrebuildJob, Prebuilt, Submitted, derive::manifest_of};
use planarian_incident::Manager;
use planarian_intent::{self as intent, Interpretation};
use planarian_ipc::{
    Choice, ConsoleReport, GraphEdge, GraphNode, LogLine, Pending, Request, Response, StatusReport, TxnSummary, UnitRow,
};
use planarian_policy::{authorization_of, user_authorization};
use planarian_schema::spec::predict;
use planarian_schema::*;
use planarian_state::{Assembler, Context};
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::{Ledger, Record};
use planarian_txn::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The 10-minute checkpoint for boot confirmation and initial enrollment (§10, §16).
pub const CONFIRM_AFTER: Millis = Millis::secs(600);
const NOTICES_KEPT: usize = 64;
/// How long an external dependency's probes time out before it is said.
const UNREACHABLE_AFTER: Millis = Millis::secs(120);

#[derive(Clone, Debug)]
pub struct CoreConfig {
    pub exec: ExecConfig,
    /// Keywords and steps for "make X bigger" (§14).
    pub runtime_options: Vec<intent::RuntimeOption>,
    /// The first start of the daemon on this boot (NextBoot overrides end).
    pub fresh_boot: bool,
    /// The default startup grace (units may set their own).
    pub startup_grace: Millis,
    /// The failure posture the generation declares (§12d); Phase A ships Standard.
    pub posture: Posture,
}

/// How long a generation's new declarations are named in incident reports (§15).
pub const NEW_DECLARATIONS_FOR: Millis = Millis::secs(24 * 3600);

/// How often the running daemon re-reads its journal's hash chain (I18).
pub const CHAIN_CHECK_EVERY: Millis = Millis::secs(3600);

/// The caller of a request, from `SO_PEERCRED`, group membership and logind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    /// Root, or a member of `planarian-admin`.
    pub admin: bool,
    /// The logind session of the calling process (`sd_pid_get_session`), if any.
    pub session: Option<String>,
}

impl Peer {
    pub const fn new(uid: u32, admin: bool) -> Peer {
        Peer { uid, admin, session: None }
    }

    pub fn in_session(mut self, session: &str) -> Peer {
        self.session = Some(session.into());
        self
    }
}

/// The executor log (I7): one record per submitted proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    pub at: Timestamp,
    pub proposal: Proposal,
    pub caller: Actor,
    pub pre_digest: Hash,
    pub policy: PolicyVersion,
    pub result: Submitted,
    /// What the executor derived and decided, when it got that far.
    #[serde(default)]
    pub facts: Option<DerivedFacts>,
    #[serde(default)]
    pub decision: Option<Decision>,
    /// The state after, and the transaction's journal path and last reason
    /// (which carries the probe verdict).
    #[serde(default)]
    pub post_digest: Option<Hash>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub why: String,
}

pub struct Core<B: Backends + Clone, S: Store> {
    pub ex: Executor<B, S>,
    pub b: B,
    pub asm: Assembler,
    pub incidents: Manager,
    pub notices: VecDeque<String>,
    /// How many notices there have ever been (the deque keeps the last
    /// `NOTICES_KEPT`), so the binary can print each new one once.
    pub notices_total: u64,
    /// Drained by the binary into the executor log file.
    pub log: Vec<LogRecord>,
    cfg: CoreConfig,
    last: Option<(SystemState, UnitDefs)>,
    choices: BTreeMap<u32, Vec<intent::Match>>,
    incident_parked: BTreeMap<IncidentId, TxnId>,
    confirm: Option<(GenerationId, Timestamp)>,
    manifest_gen: GenerationId,
    /// The running generation's manifest, before the external source joins it.
    gen_manifest: planarian_schema::Manifest,
    /// The external desired-state document in force (§9 hook), verified by `main`.
    pub external: Option<crate::hooks::DesiredDoc>,
    /// Services the running generation declares that the one before it did
    /// not, with where each came from, and since when (§15: a malicious
    /// declaration is reported with its origin).
    pub new_declarations: Vec<(String, String)>,
    new_declarations_since: Timestamp,
    interlock_noted: bool,
    /// Incidents whose opening was already announced.
    diag_noted: BTreeSet<IncidentId>,
    /// External dependencies whose probes time out: since when, and
    /// whether that was said (§10: Unknown, never Failed, so no incident).
    unreachable: BTreeMap<UnitId, (Timestamp, bool)>,
    /// When the journal's hash chain was last re-read from disk (I18).
    chain_checked: Option<Timestamp>,
    /// A broken chain found while running; `main` stops on it (§12d: the
    /// response is in the posture units, not here).
    pub integrity: Option<String>,
    /// Each unit's status at the previous tick, to see transitions (§11 residue).
    prev_status: BTreeMap<UnitId, UnitStatus>,
    /// The boot report runs on the first tick after boot (§10).
    boot_report_due: bool,
    /// Quiet mode (§12f) and the notices it holds back.
    quiet: bool,
    quiet_queue: Vec<String>,
    /// Waiting generations interrupted by a restart, to prepare again (§12f).
    reprepare: Vec<Transition>,
    /// Units Planarian's own transactions touched since the previous tick, and
    /// whether a generation changed: their stops are not someone else's.
    touched: BTreeSet<UnitId>,
    generation_touched: bool,
    /// When to next check the §12b collection bounds.
    next_gc_check: Timestamp,
    /// The space report last noticed.
    space_noted: Timestamp,
    /// Executor log records waiting for their post-state (I7).
    awaiting_post: Vec<LogRecord>,
    /// Set by the daemon: a catalog change's stage, evaluate and build are
    /// handed back as a `PrebuildJob` (`take_deferred`) to run on another
    /// thread, instead of running inside `handle`. Off in tests and the gym.
    pub defer: bool,
    /// Set by the daemon while a deferred change builds elsewhere: what, and since when.
    pub building: Option<(String, Timestamp)>,
    deferred: Option<(PrebuildJob<B::Gens>, Resume)>,
}

/// How to finish a request whose slow part ran elsewhere.
#[derive(Clone, Debug)]
pub struct Resume {
    peer: Peer,
    kind: ResumeKind,
}

#[derive(Clone, Debug)]
enum ResumeKind {
    Submit { t: Transition, source: Source, reason: String },
    Request(Request),
}

impl Resume {
    /// A few words for "busy with …".
    pub fn describe(&self) -> String {
        match &self.kind {
            ResumeKind::Submit { t, .. } => render::transition(t),
            ResumeKind::Request(r) => crate::snapshot::describe(r),
        }
    }
}

/// How often the daemon checks the §12b collection bounds.
pub const GC_CHECK: Millis = Millis(3600 * 1000);

fn outcome_of(state: &TxnState) -> Outcome {
    match state {
        TxnState::Committed => Outcome::Succeeded,
        TxnState::Reverted => Outcome::Failed("reverted".into()),
        s => Outcome::Unknown(format!("{s:?}")),
    }
}

impl<B: Backends + Clone, S: Store> Core<B, S> {
    /// Start: adopt the running generation, reconcile the journal, restore
    /// incidents, load the manifest, and schedule boot confirmation.
    pub fn start(journal: Journal<S>, b: B, me: OwnerId, cfg: CoreConfig) -> Core<B, S> {
        let fresh = cfg.fresh_boot;
        let mut ex = Executor::new(journal, b.clone(), me, cfg.exec.clone());
        ex.adopt_current();
        let mut notices = VecDeque::new();
        let terminal_before: BTreeSet<TxnId> = ex.kernel.journal.ledger().terminal.keys().copied().collect();
        match ex.kernel.reconcile() {
            Ok(waiting) if !waiting.is_empty() => {
                notices.push_back(format!("waiting for the recovery watchdog to finish transaction(s) {waiting:?}"))
            }
            Ok(_) => {}
            Err(e) => notices.push_back(format!("journal reconciliation failed: {e:?}")),
        }
        let ledger = ex.kernel.journal.ledger().clone();
        // §12f: a generation that was waiting in Built for an activation
        // window is Rejected(Interrupted) by the crash table, and re-prepared.
        let reprepare: Vec<Transition> = ledger
            .terminal
            .iter()
            .filter(|(id, t)| {
                !terminal_before.contains(id)
                    && t.state == TxnState::Rejected(RejectReason::Interrupted)
                    && t.path.iter().rev().nth(1).is_some_and(|p| p == "Built")
            })
            .map(|(_, t)| t.transition.clone())
            .collect();
        let mut incidents = Manager::restore(ledger.incidents.values().cloned());
        incidents.startup_grace = cfg.startup_grace;
        let current = b.generations().current().unwrap_or_default();
        let manifest = match b.generations().path_of(current).and_then(|p| b.generations().evaluate_built(&p)) {
            Ok(e) => manifest_of(&e),
            Err(o) => {
                notices.push_back(format!(
                    "the running generation has no Planarian manifest ({o:?}); nothing is watched until a generation built with services.planarian.enable is running"
                ));
                Default::default()
            }
        };
        let asm = Assembler::new(manifest.clone(), cfg.exec.canonical.clone());
        let now = b.clock().now();
        let last_booted = b.generations().last_booted().ok();
        let confirm = match ledger.known_good {
            None => Some((current, now.plus(CONFIRM_AFTER))),
            Some(_)
                if ledger.live_tested.is_some()
                    && ledger.live_tested == last_booted
                    && last_booted == Some(current) =>
            {
                Some((current, now.plus(CONFIRM_AFTER)))
            }
            _ => None,
        };
        let mut core = Core {
            ex,
            b,
            asm,
            incidents,
            notices_total: notices.len() as u64,
            notices,
            log: vec![],
            cfg,
            last: None,
            choices: BTreeMap::new(),
            incident_parked: BTreeMap::new(),
            confirm,
            manifest_gen: current,
            gen_manifest: manifest,
            external: None,
            new_declarations: vec![],
            new_declarations_since: now,
            interlock_noted: false,
            diag_noted: BTreeSet::new(),
            unreachable: BTreeMap::new(),
            chain_checked: None,
            integrity: None,
            prev_status: BTreeMap::new(),
            boot_report_due: fresh,
            quiet: false,
            quiet_queue: vec![],
            reprepare: vec![],
            touched: BTreeSet::new(),
            generation_touched: false,
            next_gc_check: Timestamp(0),
            space_noted: Timestamp(0),
            awaiting_post: Vec::new(),
            defer: false,
            building: None,
            deferred: None,
        };
        if core.cfg.fresh_boot {
            for s in ledger.overrides.iter().filter(|s| s.until == Until::NextBoot) {
                core.journal(Record::OverrideLifted(s.unit.clone()));
            }
        }
        if let Some(r) = &ledger.last_reconciliation {
            for a in &r.actions {
                core.notice(format!("reconciliation: {a}"));
            }
        }
        core.reprepare = reprepare;
        core.note_declarations(None, current, false);
        core
    }

    /// The observation the last tick (or request) acted on.
    pub fn last_observation(&self) -> Option<&(SystemState, UnitDefs)> {
        self.last.as_ref()
    }

    pub fn notice(&mut self, s: String) {
        // Quiet mode (§12f): non-urgent notices wait and come as one batch.
        if self.quiet && !urgent(&s) {
            self.quiet_queue.push(s);
            return;
        }
        self.say(s);
    }

    fn say(&mut self, s: String) {
        if self.notices.len() >= NOTICES_KEPT {
            self.notices.pop_front();
        }
        self.notices.push_back(s);
        self.notices_total += 1;
    }

    /// The notices made since `printed` of them (counted by
    /// `notices_total`) were seen, oldest first: what to journal next.
    pub fn notices_since(&self, printed: u64) -> impl Iterator<Item = &String> {
        let new = self.notices_total.saturating_sub(printed).min(self.notices.len() as u64) as usize;
        self.notices.iter().skip(self.notices.len() - new)
    }

    fn journal(&mut self, r: Record) {
        let now = self.b.clock().now();
        if let Err(e) = self.ex.kernel.journal.append(now, r) {
            self.notice(format!("journal write failed: {e:?}"));
        }
    }

    pub fn ledger(&mut self) -> Ledger {
        self.ex.kernel.journal.sync_ledger().cloned().unwrap_or_default()
    }

    fn context(&self, l: &Ledger, current: GenerationId) -> Context {
        let now = self.b.clock().now();
        Context {
            known_good: l.known_good.unwrap_or(current),
            live_tested: l.live_tested,
            accepted_baseline: l.accepted_baseline,
            overrides: l.overrides.iter().filter(|s| s.holds_at(now)).cloned().collect(),
            security_floor: l.security_floor,
            core_hash: Hash::ZERO,
        }
    }

    /// Generations GC must keep (I3): known-good, previous, current, boot
    /// default, live-tested, accepted baseline, and every in-flight candidate.
    fn protect(&self, l: &Ledger, current: GenerationId) -> Vec<GenerationId> {
        let gens = self.b.generations();
        let mut p = vec![current];
        p.extend(l.known_good);
        p.extend(l.live_tested);
        p.extend(l.accepted_baseline);
        p.extend(gens.boot_default().ok());
        if let Ok(entries) = gens.boot_entries() {
            p.extend(entries.into_iter().filter(|g| *g < current).max());
        }
        p.extend(l.live.values().filter_map(|t| t.txn.candidate.as_ref().map(|(g, _)| *g)));
        p.sort();
        p.dedup();
        p
    }

    /// Observe without acting (also used to answer requests).
    pub fn observe(&mut self) -> (SystemState, UnitDefs) {
        let l = self.ledger();
        let current = self.b.generations().current().unwrap_or(self.manifest_gen);
        if current != self.manifest_gen {
            if let Ok(e) = self.b.generations().path_of(current).and_then(|p| self.b.generations().evaluate_built(&p)) {
                self.gen_manifest = manifest_of(&e);
                self.asm.set_manifest(self.effective_manifest().0);
            }
            let prev = self.manifest_gen;
            self.manifest_gen = current;
            self.note_declarations(Some(prev), current, true);
        }
        let ctx = self.context(&l, current);
        let protect = self.protect(&l, current);
        self.ex.update_context(ctx.clone(), protect);
        // No baseline yet: never above Runtime (§16 initial enrollment).
        self.ex.cfg.settings.max_tier = if l.known_good.is_none() {
            self.cfg.exec.settings.max_tier.min(Tier::Runtime)
        } else {
            self.cfg.exec.settings.max_tier
        };
        let s = self.asm.observe(&self.b, &ctx);
        let defs = self.asm.defs();
        self.last = Some((s.clone(), defs.clone()));
        if !self.awaiting_post.is_empty() {
            let digest = s.digest();
            for mut r in self.awaiting_post.drain(..) {
                r.post_digest = Some(digest);
                self.log.push(r);
            }
        }
        (s, defs)
    }

    fn proposal(&self, t: Transition, s: &SystemState, defs: &UnitDefs, source: Source, reason: String) -> Proposal {
        Proposal { observed: s.digest(), expected: predict(&t, s, defs), transition: t, reason, source }
    }

    fn submit(&mut self, p: Proposal, authz: Authorization, s: &SystemState, defs: &UnitDefs) -> Submitted {
        let now = self.b.clock().now();
        let pre = s.digest();
        let policy = self.ex.policy_version();
        let caller = authz.actor.clone();
        let mut result = self.ex.submit(p.clone(), authz.clone(), s, defs);
        if let Some((facts, _)) = self.ex.last.clone() {
            self.touched.extend(facts.affected_units.iter().cloned());
            // §11: the affected sessions are notified either way.
            if facts.other_sessions_affected {
                let others: Vec<String> = self
                    .asm
                    .sessions
                    .iter()
                    .filter(|x| {
                        x.establishes() && Some(x.uid) != caller.uid() && facts.affected_sessions.contains(&x.id)
                    })
                    .map(|x| format!("{} (uid {})", x.id, x.uid))
                    .collect();
                self.notice(format!(
                    "{}: {} would also affect other people's sessions: {}",
                    render::transition(&p.transition),
                    match caller.uid() {
                        Some(u) => format!("asked for by uid {u}"),
                        None => "proposed by Planarian".to_string(),
                    },
                    others.join(", ")
                ));
            }
        }
        self.generation_touched |= p.transition.changes_generation();
        if let Submitted::Finished { txn, state, .. } = &result {
            match state {
                TxnState::Built => self.notice(format!(
                    "transaction {}: {} is ready and waits for a quiet moment (it would interrupt what you are doing)",
                    txn.0,
                    render::transition(&p.transition)
                )),
                TxnState::AwaitingBoot => self.notice(format!(
                    "transaction {}: {} takes effect when you restart; restart to finish",
                    txn.0,
                    render::transition(&p.transition)
                )),
                _ => {}
            }
        }
        if let Some((g, fixes)) = self.ex.floor_raised.take() {
            self.notice(format!(
                "security floor is now generation {} (it fixes {}); going back below it needs an administrator",
                g.0,
                fixes.join(", ")
            ));
        }
        if let (Transition::RestartUnit(u), Submitted::Finished { .. }) = (&p.transition, &result) {
            self.incidents.started(u, now);
        }
        let (facts, decision) = self.ex.last.clone().unzip();
        let excluded = std::mem::take(&mut self.ex.excluded);
        if !excluded.is_empty() {
            self.notice(format!(
                "left out of the build because git does not track them (Nix cannot see them): {}",
                excluded.join(", ")
            ));
        }
        let txn = match &result {
            Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } => Some(*txn),
            _ => None,
        };
        let l = self.ledger();
        let (path, why) = match txn {
            Some(t) => (
                l.path(t).map(<[String]>::to_vec).unwrap_or_default(),
                l.live
                    .get(&t)
                    .map(|x| x.why.clone())
                    .or_else(|| l.terminal.get(&t).map(|x| x.why.clone()))
                    .unwrap_or_default(),
            ),
            None => (vec![], String::new()),
        };
        let record = LogRecord {
            at: now,
            proposal: p,
            caller,
            pre_digest: pre,
            policy,
            result: result.clone(),
            facts,
            decision,
            post_digest: None,
            path,
            why,
        };
        // A finished transaction's record waits for the next observation for
        // its post-state (observing here would run the probes again).
        if matches!(result, Submitted::Finished { .. }) {
            self.awaiting_post.push(record);
        } else {
            self.log.push(record);
        }
        // §12a: the runtime change is in effect; persist it in the background.
        if let Submitted::Finished { followup: Some(wb), .. } = &mut result {
            let mut wb = wb.clone();
            let (s2, d2) = self.observe();
            wb.observed = s2.digest();
            match self.ex.submit(wb.clone(), authz.clone(), &s2, &d2) {
                Submitted::Finished { state: TxnState::Committed, .. } => {}
                Submitted::Parked { approve, .. } => {
                    self.notice(format!("saving the setting needs approval: planarian approve {approve}"))
                }
                other => self.notice(format!(
                    "this setting will not survive reboot: saving it failed ({})",
                    render::submitted_short(&other)
                )),
            }
        }
        result
    }

    fn canonical_healthy(&self, s: &SystemState, defs: &UnitDefs) -> bool {
        defs.iter()
            .filter(|(_, d)| {
                d.probes.iter().any(|p| p.origin == ProbeOrigin::Canonical && p.role == ProbeRole::Readiness)
            })
            .all(|(id, _)| !s.expected(id, defs) || s.status(id, defs) == UnitStatus::Running)
    }

    /// One tick of the loop.
    /// Change the posture (the gym's `set_setting posture`; on a machine the
    /// generation declares it, §12d).
    pub fn set_posture(&mut self, p: Posture) {
        self.cfg.posture = p;
    }

    /// §11, the unattributed residue: a unit seen running at the last tick and
    /// now ended by a termination signal (a `kill`, or a `systemctl stop`
    /// Planarian did not issue), which systemd will not restart and which is
    /// not Security-sensitive, is taken as intended under the Relaxed and
    /// Standard postures: an inferred `Override` until the next boot, recorded
    /// as an observation (it never passes through `decide`), with a notice
    /// and an undo. Units that went down with it are linked to it. A
    /// Security-sensitive unit's stop is always a fault, and alarmed; crash
    /// signals, exit statuses and OOM kills are faults. Owner decision Q5.
    /// Returns whether it recorded anything.
    fn residue(&mut self, s: &SystemState, defs: &UnitDefs) -> bool {
        let now = s.observed_at;
        let lenient = matches!(self.cfg.posture, Posture::Relaxed | Posture::Standard);
        let mut down: BTreeMap<UnitId, Ending> = BTreeMap::new();
        let mut current = BTreeMap::new();
        for (u, def) in defs {
            let st = s.status(u, defs);
            let was_up = matches!(self.prev_status.get(u), Some(UnitStatus::Running | UnitStatus::Degraded(_)));
            let now_down = matches!(st, UnitStatus::Failed(_) | UnitStatus::Stopped);
            current.insert(u.clone(), st);
            if !(was_up && now_down)
                || def.id.kind != UnitKind::Service
                || self.touched.contains(u)
                || self.generation_touched
                || !s.expected(u, defs)
            {
                continue;
            }
            let Some(e) = self.b.units().ended_by(u).filter(Ending::is_termination) else { continue };
            if def.sensitivity.contains(Sensitivity::Security) {
                self.notice(format!(
                    "ALARM: {u}, which is security-sensitive, was stopped outside Planarian ({}); starting it again",
                    signal_name(e)
                ));
                continue;
            }
            let restartful = def.systemd_restart.as_ref().is_some_and(|p| p.restart);
            if lenient && !restartful {
                down.insert(u.clone(), e);
            }
        }
        self.prev_status = current;
        self.touched.clear();
        self.generation_touched = false;
        if down.is_empty() {
            return false;
        }
        // The units whose stop no other stop in this batch explains.
        let roots: Vec<UnitId> = down
            .keys()
            .filter(|u| !down.keys().any(|r| r != *u && planarian_schema::spec::dependents(r, defs).contains(*u)))
            .cloned()
            .collect();
        for r in roots {
            let with: Vec<UnitId> = planarian_schema::spec::dependents(&r, defs)
                .into_iter()
                .filter(|d| *d != r && down.contains_key(d))
                .collect();
            let how = signal_name(down[&r]);
            let mut record = |unit: UnitId, reason: String| {
                let o = Override {
                    unit,
                    desired: OverrideDesired::Stopped,
                    until: Until::NextBoot,
                    reason,
                    by: Actor::Unattributed,
                    attribution: Attribution::Inferred,
                };
                self.journal(Record::OverrideSet(o));
            };
            record(r.clone(), format!("stopped outside Planarian ({how})"));
            for d in &with {
                record(d.clone(), format!("stopped together with {r}"));
            }
            let also = if with.is_empty() {
                String::new()
            } else {
                format!(
                    " (and {}, which went down with it)",
                    with.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(", ")
                )
            };
            self.notice(format!(
                "{r}: stopped outside Planarian ({how}); I take that as intended and leave it stopped until the next boot{also}. To start it again: planarian release {r}"
            ));
        }
        let _ = now;
        true
    }

    /// The services `cur` declares that `prev` (default: the boot entry
    /// before it) did not, and where each came from: the transaction that
    /// built `cur` (from the journal's Prepared record: its caller and
    /// transition, written to planarian/overrides.nix), or else a rebuild
    /// outside Planarian (the generation's creator and time, and the files
    /// that define the service).
    fn note_declarations(&mut self, prev: Option<GenerationId>, cur: GenerationId, announce: bool) {
        let gens = self.b.generations();
        let prev = prev.or_else(|| gens.boot_entries().ok()?.into_iter().filter(|g| *g < cur).max());
        let decls = |g: GenerationId| gens.path_of(g).and_then(|p| gens.evaluate_built(&p)).map(|e| e.declarations);
        let (Some(prev), Ok(now_d)) = (prev, decls(cur)) else { return };
        let Ok(before) = decls(prev) else { return };
        let added: Vec<(&String, &Vec<String>)> = now_d.iter().filter(|(k, _)| !before.contains_key(*k)).collect();
        if added.is_empty() {
            self.new_declarations.clear();
            return;
        }
        let made = self.ex.kernel.journal.segment().ok().and_then(|seg| {
            seg.into_iter().rev().find_map(|e| match e.record {
                Record::Prepared(t) if t.candidate.as_ref().is_some_and(|(g, _)| *g == cur) => Some(t),
                _ => None,
            })
        });
        let who = |a: &Actor| match a {
            Actor::User { uid: 0, .. } => "root".to_string(),
            Actor::User { uid, .. } => format!("uid {uid}"),
            a => format!("{a:?}"),
        };
        let created = gens.created_by(cur);
        self.new_declarations = added
            .into_iter()
            .map(|(svc, files)| {
                let how = match &made {
                    Some(t) => format!(
                        "by {} through {} (transaction {}), written to planarian/overrides.nix",
                        who(&t.facts.caller),
                        render::transition(&t.transition),
                        t.id.0
                    ),
                    None => format!(
                        "by {} through an out-of-band nixos-rebuild, defined in {}; generation created at {}",
                        created.map(|(uid, _)| who(&Actor::user(uid))).unwrap_or_else(|| "an unknown user".into()),
                        if files.is_empty() { "an unknown file".to_string() } else { files.join(", ") },
                        created.map(|(_, at)| render::when(at)).unwrap_or_else(|| "an unknown time".into())
                    ),
                };
                (svc.clone(), format!("service:{svc} is new in generation {}, {how}", cur.0))
            })
            .collect();
        self.new_declarations_since = self.b.clock().now();
        if announce {
            let list: Vec<String> = self.new_declarations.iter().map(|(_, o)| o.clone()).collect();
            self.notice(format!("generation {} declares new services: {}", cur.0, list.join("; ")));
        }
    }

    /// The generation's manifest with the external document's units joined
    /// (§9): a unit the generation declares stays the generation's. Returns
    /// the units the document declared that the generation overrode.
    fn effective_manifest(&self) -> (planarian_schema::Manifest, Vec<UnitId>) {
        let mut m = self.gen_manifest.clone();
        let mut shadowed = vec![];
        for (id, def) in self.external.iter().flat_map(|d| d.units.iter()) {
            if m.units.contains_key(id) {
                shadowed.push(id.clone());
            } else {
                m.units.insert(id.clone(), def.clone());
            }
        }
        (m, shadowed)
    }

    /// Where a unit's declaration came from, when not the generation (§9;
    /// future-work T5: an implant has a provenance trail).
    pub fn origin_of(&self, unit: &UnitId) -> Option<String> {
        let d = self.external.as_ref()?;
        (d.units.contains_key(unit) && !self.gen_manifest.units.contains_key(unit)).then(|| {
            format!(
                "the external desired-state source (issuer {:?}, sequence {})",
                if d.issuer.is_empty() { "unnamed" } else { &d.issuer },
                d.seq
            )
        })
    }

    /// The health report (§10 hook), with the profile the core computes.
    pub fn health_report(&mut self) -> crate::hooks::HealthReport {
        let (s, defs) = self.observe();
        crate::hooks::report(crate::hooks::DisclosureProfile::Minimal, &s, &defs, self.incidents.incidents.values())
    }

    /// A verified external document is now in force (or, with `None`, the
    /// configuration dropped the source).
    pub fn set_external(&mut self, doc: Option<crate::hooks::DesiredDoc>) {
        let said = doc.as_ref().map(|d| {
            let names: Vec<String> = d.units.keys().map(|u| u.to_string()).collect();
            format!(
                "external desired state in force: sequence {} from {:?}, declaring {}",
                d.seq,
                if d.issuer.is_empty() { "an unnamed issuer" } else { &d.issuer },
                if names.is_empty() { "nothing".to_string() } else { names.join(", ") }
            )
        });
        self.external = doc;
        let (m, shadowed) = self.effective_manifest();
        self.asm.set_manifest(m);
        if let Some(s) = said {
            self.notice(s);
        }
        if !shadowed.is_empty() {
            let names: Vec<String> = shadowed.iter().map(|u| u.to_string()).collect();
            self.notice(format!(
                "the external desired state also declares {}, which this generation declares; the generation's declaration stands",
                names.join(", ")
            ));
        }
    }

    pub fn tick(&mut self) {
        let (s, defs) = self.observe();
        let now = s.observed_at;

        // §12f quiet mode: while foreground work holds in any session.
        let quiet = s.conditions.iter().any(|c| matches!(c, Condition::Foreground { .. }));
        if self.quiet && !quiet && !self.quiet_queue.is_empty() {
            let batch = std::mem::take(&mut self.quiet_queue);
            self.say(format!("while you were busy ({}): {}", batch.len(), batch.join(" · ")));
        }
        self.quiet = quiet;
        self.asm.quiet = quiet;

        // §10 boot report, on the first tick after boot: units from outside the
        // generation are an Integrity failure (§12d); the journal chain was
        // checked when it was opened, and the core hash by planarian-recovery.
        if std::mem::take(&mut self.boot_report_due) {
            let foreign = self.b.units().foreign_units();
            for u in &foreign {
                self.notice(format!("INTEGRITY: boot report: {u} runs, but this generation does not declare it"));
            }
            if !foreign.is_empty() {
                self.integrity = Some(format!("boot report: undeclared units: {}", foreign.join(", ")));
                return;
            }
        }

        for t in std::mem::take(&mut self.reprepare) {
            let p = self.proposal(t.clone(), &s, &defs, Source::Maintenance, "prepared again after a restart".into());
            let r = self.submit(p, authorization_of(Actor::Daemon), &s, &defs);
            self.notice(format!(
                "{}: prepared again after a restart: {}",
                render::transition(&t),
                render::submitted_short(&r)
            ));
        }

        // §11: stops nobody attributed, before anything treats them as faults.
        let (s, defs) = if self.residue(&s, &defs) { self.observe() } else { (s, defs) };

        // I18: re-read the retained journal against the head this daemon holds.
        if self.chain_checked.is_none_or(|t| now.0.saturating_sub(t.0) >= CHAIN_CHECK_EVERY.0) {
            self.chain_checked = Some(now);
            if let Err(JournalError::Integrity(why)) = self.ex.kernel.journal.verify_chain() {
                self.integrity = Some(format!("journal: the hash chain is broken: {why}"));
                return;
            }
        }

        for inc in self.incidents.tick(now, &s, &defs) {
            if matches!(inc.state, IncidentState::Escalated { .. }) && inc.attempts.is_empty() {
                self.notice(format!(
                    "{}: escalated: it failed again soon after each of {} repairs; it needs a person (no automatic action for an hour)",
                    inc.target, inc.regressions
                ));
            }
            // A repair incident opens: say what failed, in the probes' words.
            // In quiet mode the repair's own notice is the one notice (§12f).
            if inc.kind == IncidentKind::Repair
                && inc.attempts.is_empty()
                && !self.quiet
                && self.diag_noted.insert(inc.id)
            {
                let failing: Vec<String> = s
                    .units
                    .get(&inc.target)
                    .map(|(_, ev)| {
                        ev.iter()
                            .filter_map(|e| match &e.result {
                                ProbeResult::Fail(m) => Some(format!("{}: {m}", e.probe.0)),
                                _ => None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                // §1: name the deepest divergent unit below it, when it isn't itself.
                let none = BTreeMap::new();
                let inputs = diagnose::Inputs {
                    state: &s,
                    defs: &defs,
                    failed_since: &self.asm.failed_since,
                    known_drivers: &self.asm.known_drivers,
                    current_planarian_built: false,
                    alternatives: &none,
                };
                let root = diagnose::root_cause(&inc.target, &inputs);
                let because = if root == inc.target { String::new() } else { format!(" (root cause: {root})") };
                let origin = self.origin_of(&inc.target).map(|o| format!("; declared by {o}")).unwrap_or_default();
                // §15: what this generation added, with its origin, while recent.
                let origin = if !self.new_declarations.is_empty()
                    && now.0.saturating_sub(self.new_declarations_since.0) < NEW_DECLARATIONS_FOR.0
                {
                    let list: Vec<&str> = self.new_declarations.iter().take(3).map(|(_, o)| o.as_str()).collect();
                    format!("{origin}; new since the previous generation: {}", list.join("; "))
                } else {
                    origin
                };
                self.notice(format!(
                    "{}: {:?}{because}{}{origin}",
                    inc.target,
                    inc.divergence.1,
                    if failing.is_empty() { String::new() } else { format!(" ({})", failing.join("; ")) }
                ));
            }
            if inc.kind == IncidentKind::Diagnostic
                && inc.state != IncidentState::Closed
                && self.diag_noted.insert(inc.id)
            {
                // Re-observe through the Readiness probes that still answer;
                // never a restart (§10).
                let answering: Vec<String> = defs
                    .get(&inc.target)
                    .map(|d| {
                        let ev = s.units.get(&inc.target).map(|(_, e)| e.as_slice()).unwrap_or(&[]);
                        d.probes
                            .iter()
                            .filter(|p| p.role == ProbeRole::Readiness)
                            .filter(|p| {
                                !ev.iter().any(|e| {
                                    e.probe == p.id && matches!(e.result, ProbeResult::Timeout | ProbeResult::Error(_))
                                })
                            })
                            .map(|p| p.id.0.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                self.notice(format!(
                    "{}: its health is unknown (checks time out); re-observing through {} rather than restarting it",
                    inc.target,
                    if answering.is_empty() { "its other checks".into() } else { answering.join(", ") }
                ));
            }
            self.journal(Record::Incident(inc));
        }
        let diag: Vec<UnitId> = self.incidents.diagnostic().iter().map(|i| i.target.clone()).collect();
        for t in diag {
            self.asm.reprobe(&t);
        }

        let l = self.ledger();
        if l.interlocked() {
            if !self.interlock_noted {
                self.notice(
                    "recovery failed; autonomous repair is stopped until an administrator runs `planarian resolve`"
                        .into(),
                );
                self.interlock_noted = true;
            }
        } else {
            self.interlock_noted = false;
            // Unit repairs may run while a generation awaits its boot (I6).
            let busy = l.live.values().any(|t| !t.txn.state.is_pre_mutation() && t.txn.state != TxnState::AwaitingBoot);
            if !busy {
                self.repair_one(&s, &defs, &l);
            }
            // §12f: an activation window opened for a waiting generation.
            if !busy {
                for (id, r) in self.ex.activate_waiting(&s) {
                    self.notice(format!(
                        "transaction {}: activated now that nothing is in the way: {}",
                        id.0,
                        render::submitted_short(&r)
                    ));
                }
            }
            // Quiet mode defers garbage collection (§12f).
            if !busy && !self.quiet && now >= self.next_gc_check {
                self.next_gc_check = now.plus(GC_CHECK);
                self.collect_if_over(&s, &defs);
            }
        }

        for t in self.ex.expire() {
            self.notice(format!("approval for transaction {} expired", t.0));
        }
        if self.ex.kernel.journal.needs_compaction()
            && let Err(e) = self.ex.kernel.journal.compact()
        {
            self.notice(format!("journal compaction failed: {e:?}"));
        }
        self.confirm_boot(&s, &defs, now);
        self.note_space();
        self.note_unreachable(&s, &defs, now);
    }

    /// §10: a probe that times out yields Unknown, never Failed, so an
    /// external dependency that stops answering (traffic dropped at a
    /// gateway) opens no incident and nothing local is touched. Still, say
    /// so once it has lasted, and again when it answers.
    fn note_unreachable(&mut self, s: &SystemState, defs: &UnitDefs, now: Timestamp) {
        for (id, def) in defs {
            if !def.sensitivity.contains(Sensitivity::External) {
                continue;
            }
            let timing_out: Vec<String> = match (s.status(id, defs), s.units.get(id)) {
                (UnitStatus::Unknown, Some((_, ev))) => ev
                    .iter()
                    .filter(|e| matches!(e.result, ProbeResult::Timeout | ProbeResult::Error(_)))
                    .map(|e| e.probe.0.clone())
                    .collect(),
                _ => vec![],
            };
            if timing_out.is_empty() {
                if let Some((_, true)) = self.unreachable.remove(id) {
                    self.notice(format!("{id}: answers again"));
                }
                continue;
            }
            let (since, said) = *self.unreachable.entry(id.clone()).or_insert((now, false));
            if !said && now >= since.plus(UNREACHABLE_AFTER) {
                self.unreachable.insert(id.clone(), (since, true));
                self.notice(format!(
                    "{id}: can't reach it: {} timing out for {} min; it may be the network on the way there, so nothing local is restarted",
                    timing_out.join(", "),
                    (now.0 - since.0) / 60_000
                ));
            }
        }
    }

    /// §12b: a collection that could not meet the space budget says so.
    fn note_space(&mut self) {
        let Some(r) = self.b.generations().space_report() else { return };
        if r.at <= self.space_noted {
            return;
        }
        self.space_noted = r.at;
        if let Some(short) = r.shortfall {
            self.notice(format!(
                "BudgetUnsatisfiable: the generations Planarian must keep use {} over the space budget of {}; everything else was collected, so the budget is a target, not a guarantee",
                render::bytes(short),
                render::bytes(r.max_bytes)
            ));
        }
    }

    /// §12b: when the generations exceed a bound and something can be
    /// collected, collect (Runtime, daemon-initiated).
    fn collect_if_over(&mut self, s: &SystemState, defs: &UnitDefs) {
        let l = self.ledger();
        let protect = self.protect(&l, s.generation);
        let Ok(plan) = self.b.generations().gc_plan(&protect, false) else { return };
        if plan.delete.is_empty() {
            return;
        }
        let reason = format!(
            "{} generation(s) over the collection bounds (keep {}, {} of {} bytes)",
            plan.delete.len(),
            plan.kept.len(),
            plan.kept_bytes,
            plan.max_bytes
        );
        let p = self.proposal(Transition::CollectGarbage { emergency: false }, s, defs, Source::Maintenance, reason);
        let _ = self.submit(p, authorization_of(Actor::Daemon), s, defs);
    }

    fn repair_one(&mut self, s: &SystemState, defs: &UnitDefs, l: &Ledger) {
        let now = s.observed_at;
        // Drop parked links whose approval was decided.
        let parked = self.ex.parked.clone();
        self.incident_parked.retain(|_, t| parked.contains_key(t));
        let Some(inc) =
            self.incidents.actionable(now).into_iter().find(|i| !self.incident_parked.contains_key(&i.id)).cloned()
        else {
            return;
        };
        let current = s.generation;
        let alternatives: BTreeMap<String, Vec<Value>> = defs
            .values()
            .filter_map(|d| d.runtime_repair.clone())
            .collect::<BTreeSet<String>>()
            .into_iter()
            .map(|opt| {
                let alts = self.ex.b.runtime().alternatives(&opt);
                (opt, alts)
            })
            .collect();
        let inputs = diagnose::Inputs {
            state: s,
            defs,
            failed_since: &self.asm.failed_since,
            known_drivers: &self.asm.known_drivers,
            current_planarian_built: l.live_tested == Some(current),
            alternatives: &alternatives,
        };
        // The deepest divergent unit below the target (§13 step 1), named
        // whenever it isn't the target itself.
        let root = diagnose::root_cause(&inc.target, &inputs);
        let because = if root == inc.target { String::new() } else { format!(" (root cause: {root})") };
        // Every other unit in trouble now, with its root cause (named if this
        // repair turns out to be theirs). Not just open incidents: a unit can
        // diverge inside its startup grace, before it has one.
        let others_rooted: Vec<(UnitId, UnitId, UnitStatus)> = defs
            .keys()
            .filter(|u| **u != inc.target && s.expected(u, defs))
            .filter_map(|u| {
                let st = s.status(u, defs);
                matches!(st, UnitStatus::Degraded(_) | UnitStatus::Failed(_) | UnitStatus::Stopped)
                    .then(|| (u.clone(), diagnose::root_cause(u, &inputs), st))
            })
            .collect();
        match diagnose::next(&inc, &inputs) {
            None => {
                if let Some(i) = self.incidents.exhausted(inc.id, now) {
                    self.journal(Record::Incident(i));
                }
                self.notice(format!(
                    "{}: {:?}{because} and nothing I know how to do would fix it; it needs a person (I'll look again in an hour)",
                    inc.target, inc.divergence.1
                ));
            }
            // §12e, I16: no automatic rollback below the security floor.
            Some(c)
                if c.transition == Transition::Rollback && s.security_floor.is_some_and(|f| s.known_good.0 < f.0) =>
            {
                if let Some(i) = self.incidents.escalate(inc.id, EscalationReason::RevertBlockedByFloor, now) {
                    self.journal(Record::Incident(i));
                }
                self.notice(format!(
                    "{}: {:?}{because}; rolling back would go below the security floor (generation {}), so it needs an administrator: the known-good generation {} lacks a security fix",
                    inc.target,
                    inc.divergence.1,
                    s.security_floor.map(|f| f.0).unwrap_or_default(),
                    s.known_good.0
                ));
            }
            Some(c) if self.ex.parked.values().any(|p| p.proposal.transition == c.transition) => {
                // Another incident with the same root cause is already waiting on
                // this exact change: wait with it rather than ask twice.
                let txn = self.ex.parked.values().find(|p| p.proposal.transition == c.transition).map(|p| p.txn);
                if let Some(t) = txn {
                    self.incident_parked.insert(inc.id, t);
                }
            }
            Some(c) => {
                // Stopped cleanly rather than crashed: likely someone outside
                // Planarian stopped it. Say how to make that stick.
                if inc.attempts.is_empty()
                    && matches!(c.transition, Transition::RestartUnit(_))
                    && c.target.kind == UnitKind::Service
                    && s.status(&c.target, defs) == UnitStatus::Stopped
                {
                    self.notice(format!(
                        "{}: it was stopped, not crashed, so I'm starting it again; to keep it stopped: planarian override {}",
                        c.target, c.target
                    ));
                }
                let p = self.proposal(
                    c.transition.clone(),
                    s,
                    defs,
                    Source::Diagnoser { incident: inc.id },
                    c.reason.clone(),
                );
                match self.submit(p, authorization_of(Actor::Daemon), s, defs) {
                    Submitted::Finished { txn, state, .. } => {
                        if let Some(i) = self.incidents.record_attempt(inc.id, txn, outcome_of(&state), now) {
                            if matches!(i.state, IncidentState::Cooldown { .. }) {
                                self.notice(format!(
                                    "{}: tried {} time(s) and it keeps failing; it needs a person (I'll try once more in {} min)",
                                    inc.target,
                                    i.attempts.len(),
                                    i.backoff.0 / 60_000
                                ));
                            }
                            self.journal(Record::Incident(i));
                        }
                        self.notice(format!(
                            "{}: {} → {:?}{because}",
                            inc.target,
                            render::transition(&c.transition),
                            state
                        ));
                        // §1: other units in trouble because of the one just
                        // repaired are told so (their incidents close once
                        // they are well again).
                        if state == TxnState::Committed {
                            let dependents: Vec<(UnitId, UnitStatus)> = others_rooted
                                .iter()
                                .filter(|(t, root, _)| *root == c.target && *t != c.target)
                                .map(|(t, _, st)| (t.clone(), st.clone()))
                                .collect();
                            for (d, st) in dependents {
                                self.notice(format!(
                                    "{d}: {st:?} (root cause: {}); repaired with {}",
                                    c.target,
                                    render::transition(&c.transition)
                                ));
                            }
                        }
                    }
                    Submitted::Parked { txn, approve, facts } => {
                        self.incident_parked.insert(inc.id, txn);
                        self.notice(format!(
                            "{}: {} needs approval ({}): planarian approve {approve}",
                            inc.target,
                            render::transition(&c.transition),
                            render::facts_summary(&facts)
                        ));
                    }
                    Submitted::Rejected { reason, detail, .. } => {
                        if let Some(i) = self.incidents.exhausted(inc.id, now) {
                            self.journal(Record::Incident(i));
                        }
                        self.notice(format!(
                            "{}: {} refused ({reason:?}: {detail})",
                            inc.target,
                            render::transition(&c.transition)
                        ));
                    }
                    Submitted::Error(e) => self.notice(format!("{}: {e}", inc.target)),
                }
            }
        }
    }

    fn confirm_boot(&mut self, s: &SystemState, defs: &UnitDefs, now: Timestamp) {
        let Some((g, at)) = self.confirm else { return };
        if now < at {
            return;
        }
        self.confirm = None;
        if s.generation == g && self.canonical_healthy(s, defs) {
            self.journal(Record::KnownGood(g));
            self.notice(format!("generation {} is now the boot-confirmed known-good baseline", g.0));
        } else {
            self.notice(format!(
                "generation {} was not confirmed: canonical probes were failing at the 10-minute checkpoint",
                g.0
            ));
        }
    }

    // ---------- Requests ----------

    /// §10: `Actor::User { uid, session, seat, active }` from the caller's
    /// logind session; a remote session has no seat and is never local.
    fn authz(&self, peer: &Peer) -> Authorization {
        let info =
            peer.session.as_ref().and_then(|id| self.asm.sessions.iter().find(|x| &x.id == id && x.uid == peer.uid));
        let actor = Actor::User {
            uid: peer.uid,
            session: info.map(|x| x.id.clone()),
            seat: info.filter(|x| !x.remote).and_then(|x| x.seat.clone()),
            active: info.is_some_and(|x| x.active),
        };
        user_authorization(actor, peer.admin)
    }

    /// The slow part of the request just handled, if `handle` deferred it:
    /// run the job anywhere, then pass its result to `resume`. Until then the
    /// answer `handle` returned is a placeholder, not for the caller.
    pub fn take_deferred(&mut self) -> Option<(PrebuildJob<B::Gens>, Resume)> {
        self.deferred.take()
    }

    /// Finish a deferred request with its prebuilt candidate: plan, decide
    /// and run it as `handle` would have, against a fresh observation.
    pub fn resume(&mut self, r: Resume, prebuilt: Prebuilt) -> Response {
        self.ex.prebuilt = Some(prebuilt);
        let defer = std::mem::replace(&mut self.defer, false);
        let resp = match r.kind {
            ResumeKind::Submit { t, source, reason } => self.user_submit(t, r.peer, source, reason),
            ResumeKind::Request(req) => self.handle(r.peer, req),
        };
        self.defer = defer;
        self.ex.prebuilt = None;
        resp
    }

    fn user_submit(&mut self, t: Transition, peer: Peer, source: Source, reason: String) -> Response {
        if self.defer
            && self.deferred.is_none()
            && let Some(job) = self.ex.prebuild_job(&t)
        {
            self.deferred = Some((job, Resume { peer, kind: ResumeKind::Submit { t, source, reason } }));
            return Response::Ok { message: "deferred".into() };
        }
        let (s, defs) = self.observe();
        let p = self.proposal(t, &s, &defs, source, reason);
        let authz = self.authz(&peer);
        let r = self.submit(p, authz, &s, &defs);
        render::response(&r)
    }

    fn status(&mut self) -> StatusReport {
        // The tick's observation (at most a tick old): answering a status
        // request must not run the probes again, or frequent readers (the
        // tray, the console) hold the core for a probe timeout each.
        let (s, defs) = self.last.clone().unwrap_or_else(|| self.observe());
        let l = self.ledger();
        let units = defs
            .keys()
            .map(|u| {
                let status = s.status(u, &defs);
                UnitRow { unit: u.clone(), detail: render::evidence(&s, u), expected: s.expected(u, &defs), status }
            })
            .collect();
        let pending = self
            .ex
            .parked
            .values()
            .map(|p| Pending {
                txn: p.txn,
                approve: p.bound_to,
                what: render::transition(&p.proposal.transition),
                facts: p.facts.clone(),
                issued: p.issued,
            })
            .collect();
        StatusReport {
            generation: s.generation,
            known_good: l.known_good,
            live_tested: l.live_tested,
            accepted_baseline: l.accepted_baseline,
            boot_default: self.b.generations().boot_default().ok(),
            baseline_note: l
                .known_good
                .is_none()
                .then(|| "no baseline yet: autonomy is limited to Runtime until this generation is confirmed".into()),
            units,
            incidents: self.incidents.incidents.values().cloned().collect(),
            pending,
            in_flight: l
                .live
                .values()
                .map(|t| (t.txn.id, t.txn.state.clone(), render::transition(&t.txn.transition)))
                .collect(),
            interlock: l
                .interlock
                .values()
                .map(|i| {
                    (i.txn, format!("{} failed from {}: {}", render::transition(&i.transition), i.failed_from, i.note))
                })
                .collect(),
            reconciliation: l.last_reconciliation.map(|r| r.actions),
            notices: self
                .building
                .as_ref()
                .map(|(what, since)| {
                    let mins = self.b.clock().now().0.saturating_sub(since.0) / 60_000;
                    format!("building {what} ({mins} min so far); repairs go on meanwhile")
                })
                .into_iter()
                .chain(self.notices.iter().cloned())
                .collect(),
            space: self.b.generations().space_report(),
        }
    }

    /// §16a: what the read-only console shows.
    fn console(&mut self) -> ConsoleReport {
        let status = self.status();
        let (s, defs) = self.last.clone().unwrap_or_else(|| self.observe());
        let l = self.ledger();
        let nodes = defs
            .iter()
            .map(|(u, def)| {
                let health = s.status(u, &defs);
                let observed = match s.units.get(u).map(|(o, _)| o) {
                    None => "not observed".to_string(),
                    Some(Observed::Failed(r)) => format!("Failed: {r:?}"),
                    Some(Observed::Unknown { reason, .. }) => format!("Unknown: {reason}"),
                    Some(Observed::Transitioning { .. }) => "Transitioning".to_string(),
                    // A loaded, inactive service is observed as `Bound`.
                    Some(Observed::Bound) if u.kind != UnitKind::Device => "Stopped".to_string(),
                    Some(o) => format!("{o:?}"),
                };
                GraphNode {
                    unit: u.clone(),
                    desired: format!("{:?}", def.desired.status),
                    expected: s.expected(u, &defs),
                    observed,
                    stale: health == UnitStatus::Unknown,
                    suppressed: matches!(health, UnitStatus::Overridden(_)),
                    health,
                }
            })
            .collect();
        let edges = defs
            .values()
            .flat_map(|d| d.edges.iter().map(|e| GraphEdge { from: e.from.clone(), to: e.to.clone(), kind: e.kind }))
            .collect();
        let mut timeline: Vec<TxnSummary> = l
            .live
            .values()
            .map(|t| TxnSummary {
                txn: t.txn.id,
                what: render::transition(&t.txn.transition),
                path: t.path.clone(),
                state: t.txn.state.clone(),
                live: true,
                by_watchdog: t.txn.lease.owner.is_watchdog(),
                why: t.why.clone(),
            })
            .chain(l.terminal.iter().map(|(id, t)| TxnSummary {
                txn: *id,
                what: render::transition(&t.transition),
                path: t.path.clone(),
                state: t.state.clone(),
                live: false,
                by_watchdog: t.owner.is_watchdog(),
                why: t.why.clone(),
            }))
            .collect();
        timeline.sort_by_key(|t| std::cmp::Reverse(t.txn));
        let gens = self.b.generations();
        let current = s.generation;
        let previous = gens.boot_entries().ok().and_then(|e| e.into_iter().filter(|g| *g < current).max());
        let last_change_reverted = l
            .terminal
            .values()
            .rev()
            .find(|t| t.transition.changes_generation())
            .is_some_and(|t| t.state == TxnState::Reverted);
        ConsoleReport {
            status,
            nodes,
            edges,
            timeline,
            previous,
            last_booted: gens.last_booted().ok(),
            candidates: l.live.values().filter_map(|t| t.txn.candidate.as_ref().map(|(g, _)| *g)).collect(),
            last_change_reverted,
            now: s.observed_at,
        }
    }

    fn intent_index(&self, defs: &UnitDefs) -> intent::Index {
        let changes = planarian_changes::entries(&self.cfg.exec.catalog)
            .into_iter()
            .map(|e| intent::CatalogEntry { id: e.id, description: e.description })
            .collect();
        let options = self
            .cfg
            .runtime_options
            .iter()
            .map(|o| intent::RuntimeOption {
                current: self.b.runtime().get(&o.path).or(o.current.clone()),
                ..o.clone()
            })
            .collect();
        intent::Index::new(defs, changes, options)
    }

    pub fn handle(&mut self, peer: Peer, req: Request) -> Response {
        match req {
            Request::Status => Response::Status(Box::new(self.status())),
            Request::Incidents => {
                Response::Incidents { incidents: self.incidents.incidents.values().cloned().collect() }
            }
            Request::Log { limit } => {
                let entries = self.ex.kernel.journal.segment().unwrap_or_default();
                let lines = entries
                    .iter()
                    .rev()
                    .take(limit)
                    .rev()
                    .map(|e| LogLine { seq: e.seq, at: e.at, text: render::record(&e.record) })
                    .collect();
                Response::Log { lines }
            }
            Request::Ask { phrase, choice } => {
                if let Some(i) = choice {
                    let Some(m) = self.choices.remove(&peer.uid).and_then(|c| c.into_iter().nth(i)) else {
                        return Response::Error { message: "no such choice; ask again".into() };
                    };
                    let src = Source::Intent { phrase: phrase.clone(), confidence: m.confidence };
                    return self.user_submit(m.transition, peer, src, format!("asked: \"{phrase}\""));
                }
                let (_, defs) = self.observe();
                let now = self.b.clock().now();
                match intent::interpret(&phrase, &self.intent_index(&defs), now) {
                    Interpretation::Propose(m) => {
                        let src = Source::Intent { phrase: phrase.clone(), confidence: m.confidence };
                        self.user_submit(m.transition, peer, src, format!("asked: \"{phrase}\" → {}", m.understood))
                    }
                    Interpretation::Confirm(ms) => {
                        let choices = ms
                            .iter()
                            .enumerate()
                            .map(|(index, m)| Choice { index, understood: m.understood.clone(), confidence: m.confidence.0 })
                            .collect();
                        self.choices.insert(peer.uid, ms);
                        Response::Confirm { choices }
                    }
                    Interpretation::Unmatched => Response::Unmatched {
                        message: "I don't know how to do that yet. Try `planarian status`, or phrases like \"restart wifi\", \"stop backups until I say\", \"make text bigger\".".into(),
                    },
                }
            }
            Request::Apply { change, args } => {
                self.user_submit(Transition::ApplyChange { change, args }, peer, Source::User, "from the CLI".into())
            }
            Request::SetOverride { unit, until, desired } => {
                // `by` is overwritten from the caller's credentials by the executor (§11).
                let s = Override::attested(unit, desired, until, "from the CLI".into(), Actor::user(peer.uid));
                self.user_submit(Transition::SetOverride(s), peer, Source::User, "from the CLI".into())
            }
            Request::LiftOverride { unit } => {
                let r = self.user_submit(
                    Transition::LiftOverride(unit.clone()),
                    peer.clone(),
                    Source::User,
                    "from the CLI".into(),
                );
                // Releasing an inferred stop also releases what went down with it.
                let with = format!("stopped together with {unit}");
                let linked: Vec<UnitId> = self
                    .ledger()
                    .overrides
                    .iter()
                    .filter(|o| o.attribution == Attribution::Inferred && o.reason == with)
                    .map(|o| o.unit.clone())
                    .collect();
                for u in linked {
                    let _ = self.user_submit(Transition::LiftOverride(u), peer.clone(), Source::User, with.clone());
                }
                let now = self.b.clock().now();
                if let Some(i) = self.incidents.human_acted(&unit, now) {
                    self.journal(Record::Incident(i));
                }
                r
            }
            Request::Stop { unit } => {
                // §14: a CLI StopUnit is rewritten so the repair loop can't race it.
                let t = Transition::StopAndSuppress {
                    unit: unit.clone(),
                    until: Until::NextBoot,
                    reason: "stopped from the CLI".into(),
                };
                match self.user_submit(t, peer, Source::User, "planarian stop".into()) {
                    Response::Done { txn, state, message } => Response::Done {
                        txn,
                        state,
                        message: format!(
                            "{message}. Note: `stop` means stop and leave stopped until the next boot; `planarian release {unit}` lets it run again."
                        ),
                    },
                    other => other,
                }
            }
            Request::Restart { unit } => {
                self.user_submit(Transition::RestartUnit(unit), peer, Source::User, "from the CLI".into())
            }
            Request::Gc => self.user_submit(
                Transition::CollectGarbage { emergency: false },
                peer,
                Source::User,
                "from the CLI".into(),
            ),
            Request::Undo => {
                let current = self.b.generations().current().unwrap_or_default();
                let prev =
                    self.b.generations().boot_entries().unwrap_or_default().into_iter().filter(|g| *g < current).max();
                match prev {
                    Some(to) => {
                        self.user_submit(Transition::Revert { to }, peer, Source::User, "planarian undo".into())
                    }
                    None => Response::Error { message: "there is no earlier generation to go back to".into() },
                }
            }
            Request::Approve { hash, tty } => {
                if peer.uid != 0 || !tty {
                    return Response::Error {
                        message: "approve requires root at an interactive terminal (Phase A)".into(),
                    };
                }
                if self.defer && self.deferred.is_none() {
                    let t = self.ex.parked.values().find(|p| p.bound_to == hash).map(|p| p.proposal.transition.clone());
                    if let Some(job) = t.and_then(|t| self.ex.prebuild_job(&t)) {
                        let req = Request::Approve { hash, tty };
                        self.deferred = Some((job, Resume { peer, kind: ResumeKind::Request(req) }));
                        return Response::Ok { message: "deferred".into() };
                    }
                }
                let (s, defs) = self.observe();
                let approver = self.authz(&peer);
                let r = self.ex.approve(&hash, &approver, &s, &defs);
                render::response(&r)
            }
            Request::Cancel { txn } => {
                let Some(p) = self.ex.parked.get(&txn) else {
                    return Response::Error { message: "no such pending change".into() };
                };
                if !peer.admin && p.authz.actor.uid() != Some(peer.uid) {
                    return Response::Error {
                        message: "only whoever asked for it, or an administrator, can withdraw it".into(),
                    };
                }
                let r = self.ex.cancel(txn, Actor::user(peer.uid));
                render::response(&r)
            }
            Request::Resolve { txn, resolution } => self.user_submit(
                Transition::Resolve { txn, resolution },
                peer,
                Source::User,
                "planarian resolve".into(),
            ),
            Request::MarkSecurityFloor => {
                if !peer.admin {
                    return Response::Error { message: "mark-security-floor requires administrator authority".into() };
                }
                let (s, _) = self.observe();
                let l = self.ledger();
                let g = s.generation;
                // §12e: the floor only moves forward, and never to a
                // generation that has not at least committed live.
                if l.known_good != Some(g) && l.live_tested != Some(g) {
                    return Response::Error {
                        message: format!("generation {} has not committed live or been boot-confirmed", g.0),
                    };
                }
                if l.security_floor.is_some_and(|f| f.0 >= g.0) {
                    return Response::Error {
                        message: format!(
                            "the security floor is already generation {}",
                            l.security_floor.unwrap_or(g).0
                        ),
                    };
                }
                self.journal(Record::SecurityFloor(Some(g)));
                Response::Ok {
                    message: format!(
                        "generation {} is now the security floor; going back below it needs an administrator",
                        g.0
                    ),
                }
            }
            Request::MarkGood { accept_unconfirmed } => {
                if !peer.admin {
                    return Response::Error { message: "mark-good requires administrator authority".into() };
                }
                let (s, defs) = self.observe();
                let failing: Vec<String> = defs
                    .keys()
                    .filter(|u| {
                        s.expected(u, &defs)
                            && matches!(
                                s.status(u, &defs),
                                UnitStatus::Degraded(_) | UnitStatus::Failed(_) | UnitStatus::Unknown
                            )
                    })
                    .map(|u| u.to_string())
                    .collect();
                if !failing.is_empty() {
                    return Response::Error {
                        message: format!("refused: Readiness probes are failing on {}", failing.join(", ")),
                    };
                }
                let booted = self.b.generations().last_booted().ok();
                if booted == Some(s.generation) {
                    self.journal(Record::KnownGood(s.generation));
                    Response::Ok { message: format!("generation {} is now known-good", s.generation.0) }
                } else if accept_unconfirmed {
                    self.journal(Record::AcceptedBaseline(Some(s.generation)));
                    Response::Ok {
                        message: format!(
                            "generation {} accepted as the recovery baseline; it is not boot-confirmed and does not replace the known-good boot entry",
                            s.generation.0
                        ),
                    }
                } else {
                    Response::Error {
                        message:
                            "this generation has not been booted; reboot into it first, or use --accept-unconfirmed"
                                .into(),
                    }
                }
            }
            Request::Console => Response::Console(Box::new(self.console())),
            #[cfg(feature = "gym-hooks")]
            Request::GymPropose { transition, stale_digest, may_change } => {
                let (s, defs) = self.observe();
                let mut p = self.proposal(transition, &s, &defs, Source::User, "gym".into());
                if stale_digest {
                    p.observed = Hash::ZERO;
                }
                if let Some(m) = may_change {
                    p.expected.may_change = m.into_iter().collect();
                }
                let authz = self.authz(&peer);
                let r = self.submit(p, authz, &s, &defs);
                render::response(&r)
            }
            #[cfg(feature = "gym-hooks")]
            Request::GymCompact => match self.ex.kernel.journal.compact() {
                Ok(_) => Response::Ok { message: "compacted".into() },
                Err(e) => Response::Error { message: format!("{e:?}") },
            },
            #[cfg(not(feature = "gym-hooks"))]
            Request::GymPropose { .. } | Request::GymCompact => {
                Response::Error { message: "not available in this build (gym-hooks)".into() }
            }
            Request::Diagnose { unit, probe } => {
                let (_, defs) = self.observe();
                let Some(def) = defs.get(&unit) else {
                    return Response::Error { message: format!("no unit {unit}") };
                };
                let probes: Vec<ProbeId> = match probe {
                    Some(p) => vec![p],
                    None => def.probes.iter().map(|p| p.id.clone()).collect(),
                };
                for p in &probes {
                    let audible = def
                        .probes
                        .iter()
                        .any(|d| &d.id == p && matches!(d.side_effects, SideEffects::Audible | SideEffects::Visible));
                    if audible && !self.asm.sessions.iter().any(|x| x.uid == peer.uid && x.establishes()) {
                        return Response::Error {
                            message: format!("{} makes sound or light; run it from your own session", p.0),
                        };
                    }
                    self.asm.request(&unit, p);
                }
                Response::Ok { message: format!("running {} probe(s) on {unit} at the next tick", probes.len()) }
            }
        }
    }
}

#[cfg(test)]
mod tests;

fn signal_name(e: Ending) -> String {
    match e {
        Ending::Signal(1) => "SIGHUP".into(),
        Ending::Signal(2) => "SIGINT".into(),
        Ending::Signal(9) => "SIGKILL".into(),
        Ending::Signal(15) => "SIGTERM, as `systemctl stop` sends".into(),
        Ending::Signal(n) => format!("signal {n}"),
        Ending::Exited(n) => format!("exit status {n}"),
        Ending::OomKill => "the OOM killer".into(),
    }
}

/// Notices quiet mode never holds back (§12f): alarms, integrity findings,
/// what a repair did, and anything that needs a person.
fn urgent(s: &str) -> bool {
    s.starts_with("ALARM")
        || s.starts_with("INTEGRITY")
        || s.contains(" → ")
        || s.contains("needs a person")
        || s.contains("needs approval")
}
