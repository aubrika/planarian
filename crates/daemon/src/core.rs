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
/// The "restart to finish" notice repeats this often while a change waits
/// for its boot (§12f).
const RESTART_REMINDER: Millis = Millis::secs(24 * 3600);

#[derive(Clone, Debug)]
pub struct CoreConfig {
    pub exec: ExecConfig,
    /// Keywords and steps for "make X bigger" (§14).
    pub runtime_options: Vec<intent::RuntimeOption>,
    /// The first start of the daemon on this boot (NextBoot overrides end).
    pub fresh_boot: bool,
    /// The default startup grace (units may set their own).
    pub startup_grace: Millis,
    /// The failure posture in force (§12d, P16: the stronger of the booted
    /// and the running generation's); Phase A ships Standard.
    pub posture: Posture,
    /// What each generation declares, for `planarian posture`.
    pub posture_decl: crate::config::PostureDecl,
    /// Limits on launched agents (§12d, R05).
    pub agent_limits: planarian_schema::backend::AgentLimits,
    /// Leave recoveries that may activate a generation until after ready
    /// (`Core::finish_recovery`, #9): the daemon and the fake harness set it,
    /// and call `finish_recovery` once ready.
    pub defer_recovery: bool,
}

/// How long a generation's new declarations are named in incident reports (§15).
pub const NEW_DECLARATIONS_FOR: Millis = Millis::secs(24 * 3600);

/// How often the running daemon re-reads its journal's hash chain (I18).
pub const CHAIN_CHECK_EVERY: Millis = Millis::secs(3600);
/// §12d: how long a tick waits for the host to confirm a hold the daemon
/// asks for on a network tool's stop outside Planarian; past it the hold
/// counts as held (fail closed) and its job goes on in the host.
pub const HOLD_WAIT: Millis = Millis::secs(5);
/// §12d: how long a hold the host has not confirmed waits before it is
/// asked for again (its job may still land meanwhile; the host is checked
/// every tick).
pub const HOLD_UNCONFIRMED_RETRY: Millis = Millis::secs(60);
/// §12d: the first and the longest wait between re-applies of a hold whose
/// firewall table is missing.
pub const HOLD_RETRY_MIN: Millis = Millis::secs(10);
pub const HOLD_RETRY_MAX: Millis = Millis::secs(300);

/// The caller of a request, from `SO_PEERCRED`, group membership and logind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    /// Root, or a member of `planarian-admin`.
    pub admin: bool,
    /// The logind session of the calling process (`sd_pid_get_session`), if any.
    pub session: Option<String>,
    /// The agent this process belongs to: its cgroup is the unit
    /// `planarian-agent-<name>` (§11). An agent is its own principal, never
    /// the uid it runs under, and is never an administrator or in a session.
    pub agent: Option<String>,
    /// The agent unit's instance the process runs in (its InvocationID,
    /// from the cgroup), which authority is bound to (I24).
    pub instance: Option<planarian_schema::InstanceId>,
    /// The calling process has a controlling terminal, read by the daemon
    /// from its pidfd (§11, B-3). Never taken from the request.
    pub tty: bool,
}

impl Peer {
    pub const fn new(uid: u32, admin: bool) -> Peer {
        Peer { uid, admin, session: None, agent: None, instance: None, tty: false }
    }

    /// A process in agent `name`'s unit, in the given instance of it.
    pub fn agent(uid: u32, name: &str, instance: Option<planarian_schema::InstanceId>) -> Peer {
        Peer { uid, admin: false, session: None, agent: Some(name.into()), instance, tty: false }
    }

    pub const fn at_terminal(mut self) -> Peer {
        self.tty = true;
        self
    }

    pub fn in_session(mut self, session: &str) -> Peer {
        self.session = Some(session.into());
        self
    }
}

/// An agent's principal id: in its own range, above every uid and the
/// daemon's ids, stable across restarts (FNV-1a of the name).
pub fn agent_principal(name: &str) -> PrincipalId {
    let h = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3));
    PrincipalId((1 << 40) | (h & 0xffff_ffff))
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
    /// The agent that sent the request, acting for `caller` (§11).
    #[serde(default)]
    pub agent: Option<String>,
    /// §12 step 6 (C18): the transaction touches user data and no snapshot
    /// was taken, because Phase A has no snapshot backend; it continued.
    #[serde(default)]
    pub no_snapshot: bool,
    /// I7: an approved execution names who approved it and the `bound_to`
    /// of the token used; a submission parked for approval carries the
    /// `bound_to` it waits on.
    #[serde(default)]
    pub approver: Option<Actor>,
    #[serde(default)]
    pub bound_to: Option<Hash>,
}

/// §12 step 6 (C18): a transaction that got past step 5 (it ran, or waits
/// for its activation window) with `UserData` among its sensitivities,
/// where snapshots are unsupported (always, in Phase A: no snapshot backend
/// is wired), logs `NoSnapshot` and continues.
fn no_snapshot(result: &Submitted, facts: Option<&DerivedFacts>) -> bool {
    matches!(result, Submitted::Finished { .. }) && facts.is_some_and(|f| f.sensitivity.contains(Sensitivity::UserData))
}

pub struct Core<B: Backends + Clone, S: Store> {
    /// Whether a uid is an administrator (root or `planarian-admin`), for
    /// the user an agent acts for; set by the daemon from the group file.
    pub admin_of: std::sync::Arc<dyn Fn(u32) -> bool + Send + Sync>,
    /// The agent behind the request being handled, for its log records.
    acting_agent: Option<String>,
    /// Recoveries left by start until after ready (`finish_recovery`).
    after_ready: Vec<TxnId>,
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
    /// Slow ticks warned (P9), and when the last warning was.
    pub slow_tick_warnings: u64,
    last_slow_warning: Option<Timestamp>,
    slow_ticks_unwarned: u64,
    /// §12a write-backs queued behind an active generation transaction,
    /// with their caller (P7). Submitted once none is live.
    writebacks: Vec<(Proposal, Authorization)>,
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
    /// When each transaction in `AwaitingBoot` was last said to need a
    /// restart (`CLOCK_BOOTTIME`); repeated daily (§12f).
    restart_reminded: BTreeMap<TxnId, Timestamp>,
    /// The attributed way to stop a unit has been taught once (§16, P23).
    residue_taught: bool,
    /// Canonical units repaired while an admitted boot-only change waits
    /// for its confirmation; any one means it is not confirmed (§10).
    repaired_before_confirmation: BTreeSet<UnitId>,
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
    /// Security units' systemd restart counts at the previous tick (§11:
    /// a kill systemd itself repaired is still alarmed).
    prev_auto_restarts: BTreeMap<UnitId, u32>,
    /// The boot report runs on the first tick after boot (§10).
    boot_report_due: bool,
    /// The last boot report this daemon ran, for `planarian report boot`.
    last_boot_report: Option<(Timestamp, GenerationId, String)>,
    /// Quiet mode (§12f) and the notices it holds back.
    quiet: bool,
    quiet_queue: Vec<String>,
    /// Waiting generations interrupted by a restart, to prepare again (§12f).
    reprepare: Vec<(TxnId, Transition)>,
    /// §12d: the hold's firewall table was there at the last check (or no
    /// hold was active). The alarm is raised once, on the change to missing
    /// or uncheckable.
    hold_table_seen: bool,
    /// §12d: this episode's "removed" alarm and `HoldApplied` are written
    /// (separately from the "could not be checked" one, so an episode that
    /// starts uncheckable still journals the re-apply).
    hold_missing_noted: bool,
    /// §12d: while the table is missing, the next re-apply (boot clock) and
    /// the wait after it, doubling to `HOLD_RETRY_MAX`.
    hold_retry: Option<(Timestamp, Millis)>,
    /// §12d: units the daemon itself asked the host to hold for a stop
    /// outside Planarian (the residue path); their `HoldApplied` is by it.
    daemon_held: BTreeSet<UnitId>,
    /// §12d: units whose hold the host has not confirmed in time (alarmed
    /// once), and when to ask again: a wedged hold job is not re-called on
    /// every tick, where it would spend the whole hold budget and starve
    /// other units' lifts.
    hold_unconfirmed: BTreeMap<UnitId, Timestamp>,
    /// §12d: units whose lift the host has not confirmed (`HoldLifted` is
    /// journaled; the host may still hold them), and when to ask again. While
    /// one stands, the unit is not journaled as held again, and its lift is
    /// retried quietly at `HOLD_UNCONFIRMED_RETRY`'s cadence, so a hung lift
    /// neither churns the journal nor spends every tick's budget.
    lift_unconfirmed: BTreeMap<UnitId, Timestamp>,
    /// §9: Exec probes already flagged in the journal this run (a record and
    /// a notice, once per probe and command, the first time each is seen).
    exec_flagged: BTreeSet<(UnitId, String, String)>,
    /// An append error may have followed the write. Its preceding sequence
    /// bounds where a retry looks for an already-written flag.
    exec_flag_pending: BTreeMap<(UnitId, String, String), u64>,
    /// §12d: the end of this tick's hold budget (`hold_wait`).
    hold_left: Millis,
    /// Generation transactions withdrawn from `Built` for a rollback about to
    /// run (§12f, I6; owner decision, Nov 2), with when each began waiting,
    /// to prepare again once no generation transaction is active.
    withdrawn: Vec<(TxnId, Transition, Option<Timestamp>)>,
    /// From the executor log of earlier runs: each transaction's proposal and
    /// caller, so one prepared again keeps its source and caller (§12, C21).
    pub earlier: BTreeMap<TxnId, (Proposal, Actor)>,
    /// Units Planarian's own transactions touched since the previous tick, and
    /// whether a generation changed: their stops are not someone else's.
    touched: BTreeSet<UnitId>,
    generation_touched: bool,
    /// §12d: the running generation's exported network tools (a template ends
    /// in `@`), `None` while they could not be read: never an empty set made
    /// of a failed read (rule 21).
    network_tools: Option<BTreeSet<String>>,
    /// The tools among them that no manifest unit declares: held and alarmed
    /// when they stop, never restarted, never an incident. Set each observe.
    unmanaged: BTreeSet<UnitId>,
    unmanaged_unreadable_noted: bool,
    /// Per unmanaged tool, whether netwatch said it protected traffic the last
    /// time it was observed running (its latch): a footprint exists only while
    /// an instance runs, so when it is down this says what it was doing. Its
    /// key is "seen running". And where the rotation through the rest has
    /// reached.
    unmanaged_latch: BTreeMap<UnitId, bool>,
    unmanaged_cursor: usize,
    /// The last `list` of systemd's units for template instances, and when.
    unmanaged_listed: Option<(Timestamp, Option<Vec<UnitId>>)>,
    unmanaged_many_noted: bool,
    /// A switch outside Planarian seen at `.0`: its stops and starts follow
    /// the profile change by more than a tick, so they stay explained until
    /// `.1` (see `SWITCH_SETTLE`).
    switch_window: Option<(Timestamp, Timestamp)>,
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
    /// The hash of the core-hash record the running generation installs
    /// (`/etc/planarian/core.sha256`, I2), for `SystemState.core_hash` and
    /// so for `digest()` (P19). Read when the daemon names the record
    /// (`set_core_hash_record`) and again whenever the running generation
    /// changes; zero where no record exists (tests, the fake harness).
    core_hash: Hash,
    core_hash_record: Option<std::path::PathBuf>,
    /// The agent behind each change parked for approval, for the approved
    /// execution's log record (I7).
    parked_agents: BTreeMap<TxnId, Option<String>>,
    /// §12d: held units whose hold an attested release lifted, until the
    /// release ends; and held units whose failed repair administrators have
    /// been told about (once per hold).
    hold_released: BTreeMap<UnitId, Option<Timestamp>>,
    /// A release marker/lift or marker cleanup that has not succeeded yet.
    /// Retried quietly, and included even after the tool stops protecting.
    release_unconfirmed: BTreeMap<UnitId, Timestamp>,
    hold_notified: BTreeSet<UnitId>,
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

/// How long after seeing a generation change outside Planarian the stops of
/// its non-Security units stay explained (the quiet period after the last
/// tick that saw queued work).
pub const SWITCH_SETTLE: Millis = Millis::secs(60);
/// The most a switch may keep explaining stops, however busy the queue.
pub const SWITCH_SETTLE_MAX: Millis = Millis::secs(600);
/// P9: a slow tick is warned at most this often (the count rides along).
pub const SLOW_TICK_WARN_EVERY: Millis = Millis::secs(60);

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
        let mut deferred = vec![];
        match ex.kernel.reconcile_deferring(cfg.defer_recovery) {
            Ok((waiting, d)) => {
                if !waiting.is_empty() {
                    notices.push_back(format!("waiting for the recovery watchdog to finish transaction(s) {waiting:?}"))
                }
                deferred = d;
            }
            Err(e) => notices.push_back(format!("journal reconciliation failed: {e:?}")),
        }
        let ledger = ex.kernel.journal.ledger().clone();
        // What the restart prepares again (§12f): see `restart::prepare_again`.
        let again = crate::restart::prepare_again(&ledger, &terminal_before);
        let mut incidents = Manager::restore(ledger.incidents.values().cloned());
        incidents.startup_grace = cfg.startup_grace;
        let current = b.generations().current().unwrap_or_default();
        let mut network_tools = None;
        let manifest = match b.generations().path_of(current).and_then(|p| b.generations().evaluate_built(&p)) {
            Ok(e) => {
                network_tools = Some(e.network_tools.clone());
                manifest_of(&e)
            }
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
        // §10: a boot-only change admitted at this boot is confirmed at its
        // 10-minute checkpoint.
        let admitted = ledger.live.values().any(|t| {
            t.txn.state == TxnState::Promoted
                && t.path.iter().any(|p| p == "AwaitingBoot")
                && t.txn.candidate.as_ref().map(|(g, _)| *g) == Some(current)
        });
        let confirm = match ledger.known_good {
            _ if admitted => Some((current, now.plus(CONFIRM_AFTER))),
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
            core_hash: Hash::ZERO,
            core_hash_record: None,
            parked_agents: BTreeMap::new(),
            hold_released: BTreeMap::new(),
            release_unconfirmed: BTreeMap::new(),
            hold_notified: BTreeSet::new(),
            after_ready: deferred,
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
            slow_tick_warnings: 0,
            last_slow_warning: None,
            slow_ticks_unwarned: 0,
            writebacks: vec![],
            confirm,
            manifest_gen: current,
            gen_manifest: manifest,
            external: None,
            new_declarations: vec![],
            new_declarations_since: now,
            interlock_noted: false,
            restart_reminded: BTreeMap::new(),
            residue_taught: false,
            repaired_before_confirmation: BTreeSet::new(),
            diag_noted: BTreeSet::new(),
            unreachable: BTreeMap::new(),
            chain_checked: None,
            integrity: None,
            admin_of: std::sync::Arc::new(|uid| uid == 0),
            acting_agent: None,
            prev_status: BTreeMap::new(),
            prev_auto_restarts: BTreeMap::new(),
            boot_report_due: fresh,
            last_boot_report: None,
            quiet: false,
            quiet_queue: vec![],
            reprepare: vec![],
            hold_table_seen: true,
            hold_missing_noted: false,
            hold_retry: None,
            daemon_held: BTreeSet::new(),
            hold_unconfirmed: BTreeMap::new(),
            lift_unconfirmed: BTreeMap::new(),
            exec_flagged: BTreeSet::new(),
            exec_flag_pending: BTreeMap::new(),
            hold_left: HOLD_WAIT,
            withdrawn: vec![],
            earlier: BTreeMap::new(),
            touched: BTreeSet::new(),
            generation_touched: false,
            network_tools,
            unmanaged: BTreeSet::new(),
            unmanaged_unreadable_noted: false,
            unmanaged_latch: BTreeMap::new(),
            unmanaged_cursor: 0,
            unmanaged_listed: None,
            unmanaged_many_noted: false,
            switch_window: None,
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
        core.reprepare = again.reprepare;
        core.withdrawn = again.withdrawn.into_iter().map(|(id, t)| (id, t, None)).collect();
        core.note_declarations(None, current, false);
        core
    }

    /// Records from the executor log of earlier runs (§12, C21): what each
    /// transaction was proposed as, and by whom.
    pub fn remember(&mut self, records: impl IntoIterator<Item = LogRecord>) {
        for r in records {
            if let Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } = &r.result {
                self.earlier.insert(*txn, (r.proposal, r.caller));
            }
        }
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

    /// P19: the record the running generation installs, for the state's
    /// `core_hash`; read now and on every generation change.
    pub fn set_core_hash_record(&mut self, record: std::path::PathBuf) {
        self.core_hash_record = Some(record);
        self.read_core_hash();
    }

    /// The core hash the observed state carries (P19).
    pub fn core_hash(&self) -> Hash {
        self.core_hash
    }

    /// An unreadable record (not a missing one) keeps the value already
    /// held and says so: nothing is derived from a failed read (rule 21).
    fn read_core_hash(&mut self) {
        let Some(record) = self.core_hash_record.clone() else { return };
        match crate::config::core_hash(&record) {
            Ok(h) => self.core_hash = h,
            Err(e) => {
                self.notice(format!("the core hash record could not be read ({e}); the state keeps the last one read"))
            }
        }
    }

    fn context(&self, l: &Ledger, current: GenerationId) -> Context {
        let now = self.b.clock().now();
        Context {
            known_good: l.known_good.unwrap_or(current),
            live_tested: l.live_tested,
            accepted_baseline: l.accepted_baseline,
            overrides: l.overrides.iter().filter(|s| s.holds_at(now)).cloned().collect(),
            security_floor: l.security_floor,
            core_hash: self.core_hash,
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

    /// What `finish_recovery` will do, for "busy with …"; None if nothing.
    pub fn pending_recovery(&self) -> Option<String> {
        match self.after_ready.as_slice() {
            [] => None,
            [one] => Some(format!("recovering transaction {} after the restart", one.0)),
            many => Some(format!("recovering {} transactions after the restart", many.len())),
        }
    }

    /// After ready: run the recoveries start left (`CoreConfig::defer_recovery`).
    pub fn finish_recovery(&mut self) {
        let ids = std::mem::take(&mut self.after_ready);
        if let Err(e) = self.ex.kernel.finish_deferred(&ids) {
            self.notice(format!("journal reconciliation after ready failed: {e:?}"));
        }
    }

    /// §12d: the exported network tools no manifest unit declares, as units:
    /// a template (`name@`) as each instance systemd lists. An unreadable
    /// export is never an empty set: the last set read stands, and with none
    /// the daemon says so (once) and tries again. A failed list leaves the
    /// instances of the previous tick.
    fn refresh_unmanaged(&mut self, defs: &UnitDefs, keep: &BTreeSet<UnitId>) {
        if self.network_tools.is_none() {
            let read = self
                .b
                .generations()
                .current()
                .and_then(|g| self.b.generations().path_of(g))
                .and_then(|p| self.b.generations().evaluate_built(&p));
            match read {
                Ok(e) => {
                    self.network_tools = Some(e.network_tools);
                    self.unmanaged_unreadable_noted = false;
                }
                Err(o) => {
                    if !std::mem::replace(&mut self.unmanaged_unreadable_noted, true) {
                        self.notice(format!(
                            "ALARM: this generation's network tools could not be read ({o:?}); a network tool Planarian does not manage is not watched until they can"
                        ));
                    }
                    return;
                }
            }
        }
        let Some(tools) = self.network_tools.clone() else { return };
        // `observe` runs several times a tick, and listing systemd's units is
        // a command: once a tick is enough (a failed list stays failed that
        // long, and keeps the previous instances).
        let now = self.b.clock().now();
        let listed = if tools.iter().any(|t| t.ends_with('@')) {
            match &self.unmanaged_listed {
                Some((at, l)) if now.0 < at.0 + planarian_state::TICK.0 => l.clone(),
                _ => {
                    let l = self.b.units().list().ok();
                    self.unmanaged_listed = Some((now, l.clone()));
                    l
                }
            }
        } else {
            None
        };
        self.unmanaged = crate::hold::unmanaged_set(&tools, listed.as_deref(), &self.unmanaged, keep, defs);
        self.unmanaged_latch.retain(|u, _| self.unmanaged.contains(u));
    }

    /// Observe without acting (also used to answer requests).
    pub fn observe(&mut self) -> (SystemState, UnitDefs) {
        let l = self.ledger();
        let current = self.b.generations().current().unwrap_or(self.manifest_gen);
        if current != self.manifest_gen {
            if let Ok(e) = self.b.generations().path_of(current).and_then(|p| self.b.generations().evaluate_built(&p)) {
                self.network_tools = Some(e.network_tools.clone());
                self.gen_manifest = manifest_of(&e);
                self.asm.set_manifest(self.effective_manifest().0);
            }
            let prev = self.manifest_gen;
            self.manifest_gen = current;
            // A switch outside Planarian stops and starts units too: none of
            // that is a person's stop (§11 residue).
            self.generation_touched = true;
            let seen = self.b.clock().now();
            self.switch_window = Some((seen, seen.plus(SWITCH_SETTLE)));
            self.note_declarations(Some(prev), current, true);
            // P19: a switch may install another core record.
            self.read_core_hash();
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
        let mut s = self.asm.observe(&self.b, &ctx);
        // §12d: what is held now, the journal's and the host's (fail closed:
        // either one holding is held).
        s.holds = l.holds();
        if let Ok(h) = self.b.units().held() {
            s.holds.extend(h);
        }
        let mut defs = self.asm.defs();
        // §12d: the network tools that protect traffic now. Fail closed: an
        // unreadable watch counts every tool as protecting.
        let standing: BTreeSet<UnitId> = s
            .holds
            .iter()
            .chain(self.hold_released.keys())
            .chain(self.release_unconfirmed.keys())
            .chain(self.lift_unconfirmed.keys())
            .cloned()
            .collect();
        self.refresh_unmanaged(&defs, &standing);
        let tools: Vec<UnitId> =
            crate::hold::network_tools(&defs).map(|d| d.id.clone()).chain(self.unmanaged.iter().cloned()).collect();
        s.protecting = if tools.is_empty() {
            BTreeSet::new()
        } else {
            self.b.units().protecting(&tools).unwrap_or_else(|_| tools.iter().cloned().collect())
        };
        // §12d: each network-security unit's hold unit, known (so releasing
        // it derives the hold's administrator floor) but never expected.
        let holds: Vec<UnitDef> = crate::hold::network_tools(&defs)
            .map(crate::hold::hold_def)
            .chain(self.unmanaged.iter().map(|u| crate::hold::hold_def(&crate::hold::unmanaged_def(u))))
            .collect();
        for d in holds {
            defs.entry(d.id.clone()).or_insert(d);
        }
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
        self.submit_from(p, authz, s, defs, None)
    }

    /// `again`: the withdrawn transaction this prepares again (§12f), set
    /// only by `prepare_again`.
    fn submit_from(
        &mut self,
        p: Proposal,
        authz: Authorization,
        s: &SystemState,
        defs: &UnitDefs,
        again: Option<TxnId>,
    ) -> Submitted {
        let now = self.b.clock().now();
        let pre = s.digest();
        let policy = self.ex.policy_version();
        let caller = authz.actor.clone();
        let built = self.waiting_built();
        let result = match again {
            Some(from) => self.ex.submit_again(p.clone(), from, authz.clone(), s, defs),
            None => self.ex.submit(p.clone(), authz.clone(), s, defs),
        };
        self.note_withdrawn(built);
        self.committed_hold_release(&p.transition, &result, defs);
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
        if let Submitted::Parked { txn, .. } = &result {
            self.parked_agents.insert(*txn, self.acting_agent.clone());
        }
        let record = LogRecord {
            at: now,
            no_snapshot: no_snapshot(&result, facts.as_ref()),
            approver: None,
            bound_to: match &result {
                Submitted::Parked { approve, .. } => Some(*approve),
                _ => None,
            },
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
            agent: self.acting_agent.clone(),
        };
        // A finished transaction's record waits for the next observation for
        // its post-state (observing here would run the probes again).
        if matches!(result, Submitted::Finished { .. }) {
            self.awaiting_post.push(record);
        } else {
            self.log.push(record);
        }
        // §12a: the runtime change is in effect; persist it in the background.
        if let Submitted::Finished { followup: Some(wb), .. } = &result {
            self.writebacks.push((wb.clone(), authz.clone()));
            self.flush_writebacks();
        }
        result
    }

    /// §12d *Network security fails closed*, each tick. The journal's holds
    /// (`Ledger::holds`) are the source of truth after a restart; they are
    /// reconciled with the host's (`held`), and any disagreement keeps the
    /// hold (fail closed).
    /// Returns whether it applied a hold the observed state does not show.
    /// What is left of this tick's hold budget: every hold call on the tick
    /// (apply, lift, the table check, a re-apply) waits
    /// at most this, and none is made once it is spent (the caller takes it
    /// as "cannot say", the fail-closed side). So a stuck `systemctl` or
    /// `nft` holds the tick up for HOLD_WAIT in all, not per call (reviewer,
    /// #61). The budget is not counted from the tick's
    /// start: only the time the hold calls take is spent (hold_spent), so
    /// probes the hold itself slows (their traffic is dropped) never spend it
    /// (catalog 41644729493, vm-netsec; reviewer, 7c2edfc); and lifts are
    /// made first (network_holds), so other units' calls cannot keep a unit
    /// that is back held (a livelock). A call skipped for want of budget is
    /// not news: it is made next tick, and alarms nothing.
    fn hold_wait(&self) -> Option<Millis> {
        (self.hold_left.0 > 0).then_some(self.hold_left)
    }

    /// Spends what a hold call begun at `t0` took from the tick's budget.
    fn hold_spent(&mut self, t0: Timestamp) {
        let took = self.b.clock().boot_now().0.saturating_sub(t0.0);
        self.hold_left = Millis(self.hold_left.0.saturating_sub(took));
    }

    /// Every spelling of the same committed effect, including an approval,
    /// must create the backend marker before lifting the host's hold.
    fn committed_hold_release(&mut self, t: &Transition, r: &Submitted, defs: &UnitDefs) {
        if matches!(r, Submitted::Finished { state: TxnState::Committed, .. })
            && let Transition::SetOverride(o) = t
            && o.holds_at(self.b.clock().now())
            && let Some(u) = crate::hold::released(o)
            && defs.get(&u).is_some_and(|d| d.holds)
        {
            self.release_host(&u, crate::hold::release_until(&o.until), HOLD_WAIT);
        }
    }

    fn release_host(&mut self, u: &UnitId, until: Option<Timestamp>, wait: Millis) {
        match self.b.units().release_hold(u, until, wait) {
            Outcome::Succeeded => {
                self.hold_released.insert(u.clone(), until);
                self.release_unconfirmed.remove(u);
                self.lift_unconfirmed.remove(u);
                if self.ledger().holds().contains(u) {
                    self.journal(Record::HoldLifted {
                        unit: u.clone(),
                        reason: "released by an attested override".into(),
                    });
                }
            }
            o => self.release_unconfirmed(u, format!("its hold could not be released: {o:?}")),
        }
    }

    fn release_unconfirmed(&mut self, u: &UnitId, why: String) {
        let later = self.b.clock().boot_now().plus(HOLD_UNCONFIRMED_RETRY);
        if self.release_unconfirmed.insert(u.clone(), later).is_none() {
            self.notice(format!("ALARM: {u}: {why}; Planarian will retry"));
        }
    }

    /// Compact the journal and return the entries it discarded (the segment
    /// it checkpointed), read in the same core call: no tick of this daemon
    /// can journal between the two, so they are exactly what the checkpoint
    /// replaced (under one hold of the store lock, so another handle's
    /// append cannot fall between either). The gym's forced compaction saves
    /// them for the judge's full-history replay (`replay_equivalent`).
    pub fn compact_saving(
        &mut self,
    ) -> Result<Vec<planarian_txn::ledger::Entry>, planarian_txn::journal::JournalError> {
        self.ex.kernel.journal.compact_returning_segment()
    }

    /// §9: "`Exec` probes ... are flagged in the console and the journal":
    /// one notice (which the binary writes to the system journal) the first
    /// time each is seen. The console and `planarian status` flag them in
    /// the unit rows (`render::evidence`).
    fn flag_exec_probes(&mut self, defs: &UnitDefs) {
        for (u, d) in defs {
            for p in &d.probes {
                if let ProbeKind::Exec { argv, .. } = &p.kind {
                    let argv0 = argv.first().cloned().unwrap_or_default();
                    let key = (u.clone(), p.id.0.clone(), argv0.clone());
                    if self.exec_flagged.contains(&key) {
                        continue;
                    }
                    let written = (|| -> Result<(), JournalError> {
                        if let Some(after) = self.exec_flag_pending.get(&key).copied() {
                            // An I/O error does not say whether the frame was
                            // written. Reconcile it before retrying; a frame
                            // read back is confirmed only after sync succeeds.
                            self.ex.kernel.journal.sync_ledger()?;
                            let found = self.ex.kernel.journal.segment()?.iter().any(|e| {
                                e.seq > after
                                    && matches!(
                                        &e.record,
                                        Record::ExecProbeFlagged { unit, probe, argv0: seen }
                                            if unit == u && probe == &p.id.0 && seen == &argv0
                                    )
                            });
                            if found {
                                self.ex.kernel.journal.store().sync()?;
                                return Ok(());
                            }
                            // Compaction may have discarded an unconfirmed
                            // informational frame. Then emit a fresh flag.
                        }
                        let after = self.ex.kernel.journal.ledger().last_seq;
                        let record =
                            Record::ExecProbeFlagged { unit: u.clone(), probe: p.id.0.clone(), argv0: argv0.clone() };
                        match self.ex.kernel.journal.append(self.b.clock().now(), record) {
                            Ok(_) => Ok(()),
                            Err(e) => {
                                self.exec_flag_pending.entry(key.clone()).or_insert(after);
                                Err(e)
                            }
                        }
                    })();
                    match written {
                        Ok(()) => {
                            self.exec_flag_pending.remove(&key);
                            self.exec_flagged.insert(key);
                            self.notice(format!(
                                "{u}: probe {} is an Exec probe: it runs a command ({argv0}) rather than a typed check",
                                p.id.0
                            ));
                        }
                        Err(e) => self.notice(format!("journal write failed: {e:?}")),
                    }
                }
            }
        }
    }

    /// `s` and `defs` with the unmanaged network tools this tick looks at
    /// added as units, observed through the backend (see
    /// `hold::unmanaged_observed` for what is down; an unreadable one is
    /// Unknown: neither held nor lifted).
    ///
    /// Always looked at: the tools whose hold stands or is pending, and every
    /// tool seen running whose latch says it protected traffic (a down one is
    /// held on the next tick, whatever their number: more than
    /// `UNMANAGED_MANY` is said once). The rest, never seen running or seen
    /// not protecting, at most `UNMANAGED_OBSERVE_PER_TICK`, rotating.
    ///
    /// A footprint exists only while an instance runs, and a tool with none
    /// counts as protecting (fail closed, #78), so what a tool was doing is
    /// latched while it is observed running (netwatch's `protecting`). When it
    /// is down: held if the latch says it protected, or nothing was ever
    /// recorded (still fail closed); a restart of one that protected nothing
    /// holds nothing. A new run overwrites the latch.
    fn with_unmanaged(&mut self, s: &SystemState, defs: &UnitDefs) -> (SystemState, UnitDefs) {
        let (mut s, mut defs) = (s.clone(), defs.clone());
        let standing = |me: &Self, u: &UnitId| {
            s.holds.contains(u)
                || me.hold_released.contains_key(u)
                || me.release_unconfirmed.contains_key(u)
                || me.lift_unconfirmed.contains_key(u)
        };
        let all: Vec<UnitId> = self.unmanaged.iter().cloned().collect();
        let (must, rest): (Vec<UnitId>, Vec<UnitId>) = all.into_iter().partition(|u| standing(self, u));
        // A plain tool's footprint is netwatch's own word whether it runs or
        // not, so one reported protecting is looked at every tick; an
        // instance's is gone when it stops, so its latch says.
        let (every, rotate): (Vec<UnitId>, Vec<UnitId>) = rest.into_iter().partition(|u| {
            self.unmanaged_latch.get(u) == Some(&true)
                || (planarian_backend_netwatch::host::footprint_outlives_the_unit(u) && s.protecting.contains(u))
        });
        let take = rotate.len().min(crate::hold::UNMANAGED_OBSERVE_PER_TICK);
        let start = if rotate.is_empty() { 0 } else { self.unmanaged_cursor % rotate.len() };
        self.unmanaged_cursor = start + take;
        let chosen: Vec<UnitId> = must.into_iter().chain(every).collect();
        if chosen.len() > crate::hold::UNMANAGED_MANY {
            if !std::mem::replace(&mut self.unmanaged_many_noted, true) {
                self.notice(format!(
                    "warning: {} unmanaged network tools are observed every tick; a tick takes longer for them",
                    chosen.len()
                ));
            }
        } else {
            self.unmanaged_many_noted = false;
        }
        // The tools always looked at, in a few commands (a chunk is one
        // `systemctl show`), then the rotation's, unless the first took the
        // tick's whole budget for this work: managed observation and the
        // holds that follow are not made to wait behind it.
        let t0 = self.b.clock().now();
        for chunk in chosen.chunks(crate::hold::UNMANAGED_BATCH) {
            self.observe_unmanaged(&mut s, &mut defs, chunk);
        }
        let spent = self.b.clock().now().0.saturating_sub(t0.0);
        if spent < crate::hold::UNMANAGED_BUDGET.0 {
            let pick: Vec<UnitId> = (0..take).map(|i| rotate[(start + i) % rotate.len()].clone()).collect();
            self.observe_unmanaged(&mut s, &mut defs, &pick);
            self.unmanaged_cursor = start + take;
        } else {
            self.unmanaged_cursor = start;
        }
        (s, defs)
    }

    /// Observe `units` in one backend call and put each in `s` and `defs`,
    /// updating latches (`with_unmanaged`).
    fn observe_unmanaged(&mut self, s: &mut SystemState, defs: &mut UnitDefs, units: &[UnitId]) {
        if units.is_empty() {
            return;
        }
        let results = self.b.units().observe_many(units);
        for (u, (observed, ended)) in units.iter().zip(results) {
            let held = s.holds.contains(u);
            let observed = match observed {
                Ok(raw) => {
                    let seen = crate::hold::unmanaged_observed(raw.clone(), ended, held);
                    let down =
                        matches!(seen, Observed::Failed(_) | Observed::Absent | Observed::Bound | Observed::Detected);
                    if raw == Observed::Active {
                        // Running: what netwatch says it protects now is its latch.
                        self.unmanaged_latch.insert(u.clone(), s.protecting.contains(u));
                    } else if down
                        && !planarian_backend_netwatch::host::footprint_outlives_the_unit(u)
                        && self.unmanaged_latch.get(u) == Some(&false)
                    {
                        // A stopped instance has no footprint, so netwatch's
                        // "protecting" for it is only the fail-closed
                        // default; it protected nothing when it ran.
                        s.protecting.remove(u);
                    }
                    seen
                }
                Err(o) => Observed::Unknown { since: s.observed_at, reason: format!("{o:?}") },
            };
            s.units.insert(u.clone(), (observed, vec![]));
            defs.insert(u.clone(), crate::hold::unmanaged_def(u));
        }
    }

    fn network_holds(&mut self, s: &SystemState, defs: &UnitDefs) -> bool {
        use crate::hold;
        use planarian_txn::ledger::HoldBy;
        let mut applied = false;
        let journaled = self.ledger().holds();
        let host = self.b.units().held();
        // The units this tick looks after: network-security units (tools
        // protecting traffic), and any tool whose hold stands (journaled or
        // on the host) whether or not it still protects, so that hold is
        // lifted once the unit is back. A tool that is not protecting is
        // never held.
        let units: Vec<UnitId> = hold::network_tools(defs)
            .filter(|d| {
                s.protecting.contains(&d.id)
                    || journaled.contains(&d.id)
                    || host.as_ref().is_ok_and(|h| h.contains(&d.id))
                    || self.hold_released.contains_key(&d.id)
                    || self.release_unconfirmed.contains_key(&d.id)
            })
            .map(|d| d.id.clone())
            .collect();
        if units.is_empty() {
            return false;
        }
        // Anything else flushing the ruleset removes the hold's table while
        // the units stay held: put it back (journal, alarm, re-apply).
        let mut holding = journaled.clone();
        if let Ok(h) = &host {
            holding.extend(h.iter().cloned());
        }
        // Lifts first, before the table check and any unit's hold: a unit
        // that is back is never kept held because the tick's hold budget
        // went on other units' calls (catalog 41644729493). A unit whose
        // release just ended, or that OnFailure= held unseen, takes the
        // loop below (it has its own bookkeeping first).
        let mut lifted = BTreeSet::new();
        for u in &units {
            if journaled.contains(u)
                && !self.hold_released.contains_key(u)
                && s.override_of(&hold::hold_unit(u)).is_none()
                && !hold::failed(s, defs, u)
                && hold::back(s, defs, u)
                && self.lift_back(u)
            {
                lifted.insert(u.clone());
            }
        }
        // A unit whose lift is pending is back and journaled as lifted, though
        // the host still lists it: not a standing hold, so a flushed table
        // is not re-applied for it (reviewer, #72).
        holding.retain(|u| {
            let pending = self.lift_unconfirmed.contains_key(u) && !hold::failed(s, defs, u) && hold::back(s, defs, u);
            !(lifted.contains(u) || pending)
        });
        if holding.is_empty() {
            self.hold_table_seen = true;
            self.hold_missing_noted = false;
            self.hold_retry = None;
        } else {
            self.hold_table(&holding, &units);
        }
        for u in units {
            // Taken every tick, so an entry never outlives the tick that set it.
            let asked = self.daemon_held.remove(&u);
            let in_journal = journaled.contains(&u);
            // None: the host cannot say; a failed unit is then held again
            // (the call is idempotent).
            let on_host = host.as_ref().ok().map(|h| h.contains(&u));
            if on_host == Some(true) {
                // The host has it: a later timeout is news again.
                self.hold_unconfirmed.remove(&u);
            }
            if on_host == Some(false) && !hold::failed(s, defs, &u) {
                // Neither failed nor held: the next episode's timeout alarms again.
                self.hold_unconfirmed.remove(&u);
            }
            if lifted.contains(&u) {
                continue;
            }
            // An attested Stopped override is the release effect. Both the
            // backend marker and the lift must succeed before it is recorded
            // as complete; a failed/unknown call is retried within the tick's
            // shared hold budget, even if the tool no longer protects traffic.
            let now = self.b.clock().boot_now();
            let due = self.release_unconfirmed.get(&u).is_none_or(|next| now >= *next);
            let release = s.override_of(&hold::hold_unit(&u)).filter(|o| hold::released(o).is_some());
            if let Some(o) = release {
                let until = hold::release_until(&o.until);
                // A wall-clock rollback must not revive a timed release
                // whose original boot bound has passed. Verify the persisted
                // marker even if the host has not applied a new hold yet.
                // Missing/unreadable bounds fail closed, including restart
                // after an initial marker write failed: never invent a new
                // deadline from the old wall-clock override.
                let active = match until.map(|until| self.b.units().timed_release_active(&u, until)) {
                    None | Some(Ok(true)) => true,
                    Some(Ok(false)) => {
                        self.release_unconfirmed(
                            &u,
                            "its timed release has expired or its original bound is missing".into(),
                        );
                        false
                    }
                    Some(Err(o)) => {
                        self.release_unconfirmed(&u, format!("its timed release could not be verified: {o:?}"));
                        false
                    }
                };
                if active
                    && (self.hold_released.get(&u) != Some(&until) || on_host != Some(false))
                    && due
                    && let Some(wait) = self.hold_wait()
                {
                    let t0 = self.b.clock().boot_now();
                    self.release_host(&u, until, wait);
                    self.hold_spent(t0);
                }
                if active {
                    continue;
                }
            }
            if release.is_none()
                && (self.hold_released.contains_key(&u) || self.release_unconfirmed.contains_key(&u))
                && due
            {
                // The release ended. A failed cleanup keeps its retry state;
                // failure to remove a marker must never be silently accepted.
                match self.b.units().end_release(&u) {
                    Outcome::Succeeded => {
                        self.hold_released.remove(&u);
                        self.release_unconfirmed.remove(&u);
                    }
                    o => self.release_unconfirmed(&u, format!("its release marker could not be removed: {o:?}")),
                }
            }
            // (`!in_journal` is defensive: a unit journaled as held has its entry
            // dropped by the failed-again arm first.)
            if self.lift_unconfirmed.contains_key(&u) && !in_journal {
                match on_host {
                    // The host cannot say: the entry stands, and the unit is
                    // handled as below (the lift is asked again when it can).
                    None => {}
                    // The lift landed after all.
                    Some(false) if !hold::failed(s, defs, &u) => {
                        self.lift_unconfirmed.remove(&u);
                        self.hold_notified.remove(&u);
                        self.notice(format!("{u} is back; network traffic flows again"));
                        continue;
                    }
                    // Still held on the host only because its lift is
                    // pending: not a new hold. Retried when due.
                    Some(true) if !hold::failed(s, defs, &u) && hold::back(s, defs, &u) => {
                        let now = self.b.clock().boot_now();
                        if self.lift_unconfirmed.get(&u).is_some_and(|next| now >= *next)
                            && self.hold_wait().is_some()
                            && self.running_now(&u)
                        {
                            self.lift_host(&u);
                        }
                        continue;
                    }
                    // Failed again, or not back: the hold is real again.
                    Some(_) => {
                        self.lift_unconfirmed.remove(&u);
                    }
                }
            }
            // A cache/pending marker kept this tool in the loop solely for
            // cleanup. Once it no longer protects and has no standing hold,
            // cleanup must not start a new hold on its traffic.
            if !s.protecting.contains(&u) && !in_journal && on_host == Some(false) {
                continue;
            }
            if hold::failed(s, defs, &u) {
                if !in_journal {
                    // systemd's OnFailure= already holds a crash or a kill;
                    // a stop outside Planarian is the daemon's to hold.
                    // Daemon when the daemon asked (residue): also when its
                    // hold job merged with OnFailure='s for the same unit
                    // (systemd merges the two starts into one job), which is
                    // fine: the hold is the same either way.
                    let by = if asked || on_host != Some(true) { HoldBy::Daemon } else { HoldBy::OnFailure };
                    self.journal(Record::HoldApplied { unit: u.clone(), by });
                    self.notice(if self.unmanaged.contains(&u) { hold::unmanaged_alarm(&u) } else { hold::alarm(&u) });
                }
                if on_host != Some(true) {
                    let now = self.b.clock().boot_now();
                    // Asked already and not yet due again: its job may still
                    // land, and the host is checked every tick (above).
                    // A skip for want of budget waits too: asked next tick, quietly.
                    let waiting =
                        self.hold_unconfirmed.get(&u).is_some_and(|next| now < *next) || self.hold_wait().is_none();
                    let o = match self.hold_wait() {
                        _ if waiting => Outcome::Unknown("waiting for its hold job".into()),
                        Some(w) => {
                            let t0 = self.b.clock().boot_now();
                            let o = self.b.units().hold(&u, w);
                            self.hold_spent(t0);
                            o
                        }
                        None => Outcome::Unknown("no time left on this tick".into()),
                    };
                    match o {
                        // A failure alarms each time; a hold the host has not
                        // confirmed in time (its job may still land), once.
                        o @ Outcome::Failed(_) => {
                            self.notice(format!("ALARM: {u}: its traffic could not be held ({o:?})"))
                        }
                        _ if waiting => {}
                        o @ Outcome::Unknown(_) => {
                            let later = self.b.clock().boot_now().plus(HOLD_UNCONFIRMED_RETRY);
                            if self.hold_unconfirmed.insert(u.clone(), later).is_none() {
                                self.notice(format!("ALARM: {u}: its traffic could not be held ({o:?})"))
                            }
                        }
                        _ => applied |= !s.holds.contains(&u),
                    }
                }
                // Repair failed: the hold stays, and administrators hear of it once.
                let given_up = self.incidents.active_for(&u).is_some_and(|i| {
                    matches!(i.state, IncidentState::Cooldown { .. } | IncidentState::Escalated { .. })
                });
                if given_up && self.hold_notified.insert(u.clone()) {
                    self.notice(format!(
                        "ALARM: {u}: repair failed; its network traffic stays blocked. It needs a person: an administrator can fix it, or lift the hold with `planarian hold release {}`",
                        u.name
                    ));
                }
            } else if in_journal || on_host == Some(true) {
                if !in_journal {
                    // OnFailure= held it while the daemon was not looking: its
                    // traffic is blocked all the same, so the person is told
                    // (once: the hold is journaled now, so the failed branch
                    // above does not say it again).
                    self.journal(Record::HoldApplied { unit: u.clone(), by: HoldBy::OnFailure });
                    self.notice(if self.unmanaged.contains(&u) { hold::unmanaged_alarm(&u) } else { hold::alarm(&u) });
                }
                // Only a hold that stood before this observation lifts on
                // it: the alarm above and the lift are never one observation
                // (catalog run 42504673480).
                if in_journal && hold::back(s, defs, &u) {
                    self.lift_back(&u);
                }
            }
        }
        applied
    }

    /// Lifts a back unit's hold: journaled, then asked of the host. False
    /// when the tick has no budget left: nothing is done, and it is lifted
    /// on a later tick.
    fn lift_back(&mut self, u: &UnitId) -> bool {
        if self.hold_wait().is_none() || !self.running_now(u) {
            return false;
        }
        self.journal(Record::HoldLifted { unit: u.clone(), reason: "Running, and its Readiness probes pass".into() });
        self.lift_host(u);
        true
    }

    /// Whether systemd says the unit is Running at this moment. The tick's
    /// state was read before its probes, which can take seconds, so a lift
    /// asks again: a tool killed since (OnFailure= has held it) must not have
    /// its traffic opened on the old reading. `deactivating`, `failed`, a
    /// cgroup that merely still has processes, and a read that fails all
    /// keep the hold (fail closed).
    fn running_now(&self, u: &UnitId) -> bool {
        matches!(self.b.units().observe(u), Ok(Observed::Active))
    }

    /// Asks the host to lift a hold already journaled as lifted. A lift the
    /// host has not confirmed is noticed once, then retried quietly.
    fn lift_host(&mut self, u: &UnitId) {
        let o = match self.hold_wait() {
            Some(w) => {
                let t0 = self.b.clock().boot_now();
                let o = self.b.units().lift_hold(u, w);
                self.hold_spent(t0);
                o
            }
            None => Outcome::Unknown("no time left on this tick".into()),
        };
        match o {
            o @ (Outcome::Failed(_) | Outcome::Unknown(_)) => {
                let later = self.b.clock().boot_now().plus(HOLD_UNCONFIRMED_RETRY);
                if self.lift_unconfirmed.insert(u.clone(), later).is_none() {
                    self.notice(format!("{u}: the hold could not be lifted ({o:?}); its traffic stays blocked"))
                }
            }
            _ => {
                self.lift_unconfirmed.remove(u);
                self.hold_notified.remove(u);
                self.notice(format!("{u} is back; network traffic flows again"));
            }
        }
    }

    /// §12d: the hold's table, while a hold stands. Missing: alarm once, then
    /// re-apply (a reload, which never lifts; `HoldApplied` journaled
    /// first), and retry with backoff until a check finds it. Uncheckable:
    /// alarm once and check again next tick; nothing is re-applied blind.
    fn hold_table(&mut self, holding: &BTreeSet<UnitId>, units: &[UnitId]) {
        use planarian_txn::ledger::HoldBy;
        if self.hold_wait().is_none() {
            // Not checked this tick, for want of budget: not "uncheckable".
            return;
        }
        let present = match self.hold_wait() {
            Some(w) => {
                let t0 = self.b.clock().boot_now();
                let o = self.b.units().hold_table_present(w);
                self.hold_spent(t0);
                o
            }
            None => Err(Outcome::Unknown("no time left on this tick".into())),
        };
        let held: Vec<UnitId> = holding.iter().filter(|u| units.contains(u)).cloned().collect();
        match &present {
            Ok(true) => {
                self.hold_table_seen = true;
                self.hold_missing_noted = false;
                self.hold_retry = None;
                return;
            }
            Err(o) => {
                if self.hold_table_seen {
                    for u in &held {
                        self.notice(format!(
                            "ALARM: {u}: the network hold's firewall table could not be checked ({o:?}); checking again"
                        ));
                    }
                }
                self.hold_table_seen = false;
                return;
            }
            Ok(false) => {}
        }
        let now = self.b.clock().boot_now();
        let first = !self.hold_missing_noted;
        if !first && self.hold_retry.is_some_and(|(next, _)| now < next) {
            return;
        }
        self.hold_missing_noted = true;
        for u in &held {
            if first {
                self.journal(Record::HoldApplied { unit: u.clone(), by: HoldBy::Daemon });
                self.notice(format!("ALARM: {u}: the network hold was removed from the firewall; re-applying it"));
            }
            if self.hold_wait().is_none() {
                continue;
            }
            let o = match self.hold_wait() {
                Some(w) => {
                    let t0 = self.b.clock().boot_now();
                    let o = self.b.units().reapply_hold(u, w);
                    self.hold_spent(t0);
                    o
                }
                None => Outcome::Unknown("no time left on this tick".into()),
            };
            if let o @ (Outcome::Failed(_) | Outcome::Unknown(_)) = o
                && first
            {
                self.notice(format!("ALARM: {u}: its traffic could not be held again ({o:?}); retrying"));
            }
        }
        self.hold_table_seen = false;
        // No budget left: the check is skipped, which is not "not found", and
        // leaves the backoff alone.
        let found = match self.hold_wait() {
            Some(w) => {
                let t0 = self.b.clock().boot_now();
                let r = matches!(self.b.units().hold_table_present(w), Ok(true));
                self.hold_spent(t0);
                Some(r)
            }
            None => None,
        };
        if found == Some(true) {
            self.hold_table_seen = true;
            self.hold_missing_noted = false;
            self.hold_retry = None;
        } else if found == Some(false) {
            let wait =
                self.hold_retry.map_or(HOLD_RETRY_MIN, |(_, w)| Millis(w.0.saturating_mul(2).min(HOLD_RETRY_MAX.0)));
            self.hold_retry = Some((Timestamp(now.0.saturating_add(wait.0)), wait));
        }
    }

    /// Prepare again transactions interrupted before they mutated (by a
    /// restart, or withdrawn for a repair rollback).
    fn prepare_again(
        &mut self,
        list: Vec<(TxnId, Transition, Option<Timestamp>)>,
        why: &str,
        s: &SystemState,
        defs: &UnitDefs,
    ) {
        for (id, t, since) in list {
            // Its original source and caller (C21), so floors that depend on
            // who asked (the own-session exemption) still apply; the daemon's
            // own only when no record of it survives.
            let (source, authz) = match self.earlier.get(&id).cloned() {
                Some((p, caller @ Actor::User { .. })) => {
                    let admin = caller.uid().is_some_and(|u| (self.admin_of)(u));
                    (p.source, user_authorization(caller, admin))
                }
                Some((p, caller)) => (p.source, authorization_of(caller)),
                None => (Source::Maintenance, authorization_of(Actor::Daemon)),
            };
            let incident = match &source {
                Source::Diagnoser { incident } => Some(*incident),
                _ => None,
            };
            let p = self.proposal(t.clone(), s, defs, source, format!("prepared again {why}"));
            // Journaled with it: this is what prepares `id` again (§12f).
            let r = self.submit_from(p, authz, s, defs, Some(id));
            // A diagnoser's repair that waits again keeps its incident with it.
            if let (
                Some(inc),
                Submitted::Finished { txn, state: TxnState::Built, .. } | Submitted::Parked { txn, .. },
            ) = (incident, &r)
            {
                self.incident_parked.insert(inc, *txn);
            }
            // A withdrawal never extends a change's parking limit (I12).
            if let (Some(since), Submitted::Finished { txn, state: TxnState::Built, .. }) = (since, &r) {
                self.ex.keep_waiting_since(*txn, since);
            }
            // A permanent refusal is remembered; Stale means retry against
            // fresh state, so it must not suppress a later restart.
            if let Submitted::Rejected { reason, detail, .. } = &r
                && reason != &RejectReason::Stale
            {
                self.journal(Record::NotPreparedAgain { txn: id, reason: format!("{reason:?}: {detail}") });
            }
            self.notice(format!("{}: prepared again {why}: {}", render::transition(&t), render::submitted_short(&r)));
        }
    }

    /// Generation transactions waiting in `Built`, with when each began
    /// waiting: what a rollback about to run would withdraw (§12f, I6).
    fn waiting_built(&mut self) -> Vec<(TxnId, Transition, Option<Timestamp>)> {
        let l = self.ledger();
        l.live
            .values()
            .filter(|t| t.txn.transition.changes_generation() && t.txn.state == TxnState::Built)
            .map(|t| (t.txn.id, t.txn.transition.clone(), self.ex.waiting_since(t.txn.id)))
            .collect()
    }

    /// §12f, I6 (owner decision, Nov 2): a rollback of any source withdraws
    /// what waits in `Built` at the moment it is about to run (admitted, and
    /// approved if it asked; `exec::schedule`). Those of `before` the
    /// executor withdrew are remembered, with their proposal, caller and
    /// parking start, to prepare again once the rollback is terminal.
    fn note_withdrawn(&mut self, before: Vec<(TxnId, Transition, Option<Timestamp>)>) {
        if before.is_empty() {
            return;
        }
        let l = self.ledger();
        for (id, t, since) in before {
            if l.terminal.get(&id).is_none_or(|x| x.state != TxnState::Rejected(RejectReason::Interrupted)) {
                continue;
            }
            if !self.earlier.contains_key(&id) {
                let asked = self.log.iter().chain(&self.awaiting_post).find(|r| {
                    matches!(r.result, Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } if txn == id)
                });
                if let Some(r) = asked {
                    self.earlier.insert(id, (r.proposal.clone(), r.caller.clone()));
                }
            }
            self.notice(format!(
                "{}: set aside for a rollback (transaction {}); it will be prepared again once the rollback is done",
                render::transition(&t),
                id.0
            ));
            self.withdrawn.push((id, t, since));
        }
    }

    /// The response to a submission; one parked for approval says, in one
    /// line, what it would change (§16 *Approvals show the change*).
    fn respond(&self, r: &Submitted) -> Response {
        let mut resp = render::response(r);
        if let Response::NeedsApproval { txn, why, .. } = &mut resp
            && let Some(p) = self.ex.parked.get(txn)
            && let Some(sum) = self.approval_diff(*txn, &p.proposal.transition, &p.facts).summary()
        {
            *why = if why.is_empty() { sum } else { format!("{why}; {sum}") };
        }
        resp
    }

    /// §16 *Approvals show the change*: built from the derived facts (from
    /// the evaluated generations), never from the proposal.
    fn approval_diff(&self, txn: TxnId, t: &Transition, f: &DerivedFacts) -> planarian_ipc::ApprovalDiff {
        // The options, from the evaluated generations (§16): the one the
        // transaction runs on against its candidate. A generation built
        // outside Planarian has no recorded override, so the override diff
        // alone would show nothing it changes. If either evaluation cannot be
        // read, the core's override diff from the facts stands.
        let evaluated = self.evaluated_diff(txn);
        let options = evaluated.as_ref().or(f.config_diff.as_ref());
        // The units it would remove or stop: derive's `removes`, the same set
        // as `removes_sensitivity` (§11 Rollback row), each with its own.
        let (removed, each_known) = crate::approval::removed(f);
        let mut diff =
            crate::approval::diff(t, options, evaluated.is_some(), &removed, each_known, &self.ex.cfg.tables);
        if !f.journal_incompatibility.is_empty() {
            let warning = format!(
                "The target Planarian cannot read decisive journal data: {}. Administrator approval is required; the target may stop with Integrity or lose these decisions.",
                f.journal_incompatibility.join(", ")
            );
            diff.note = Some(match diff.note {
                Some(note) => format!("{note}; {warning}"),
                None => warning,
            });
        }
        diff
    }

    /// Every option whose value differs between a live generation
    /// transaction's base and its candidate, as both evaluate.
    fn evaluated_diff(&self, txn: TxnId) -> Option<ConfigDiff> {
        let live = self.ex.kernel.journal.ledger().live.get(&txn)?;
        let (_, cand_path) = live.txn.candidate.as_ref()?;
        let gens = self.b.generations();
        let base = gens.path_of(live.txn.base).and_then(|p| gens.evaluate_built(&p)).ok()?;
        let cand = gens.evaluate_built(cand_path).ok()?;
        let mut d = ConfigDiff::default();
        for k in base.options.keys().chain(cand.options.keys()) {
            let (old, new) = (base.options.get(k), cand.options.get(k));
            if old != new {
                d.options.insert(k.clone(), (old.cloned(), new.cloned()));
            }
        }
        Some(d)
    }

    /// A generation transaction is live, in any state (I6: one waiting in
    /// `Built` counts).
    fn generation_active(&mut self) -> bool {
        self.ledger().live.values().any(|t| t.txn.transition.changes_generation())
    }

    /// §12a (P7): submit the queued write-backs, unless a generation
    /// transaction is active: then they stay queued, which is not a failure
    /// and gives no notice. One refused as busy goes back on the queue.
    fn flush_writebacks(&mut self) {
        while !self.writebacks.is_empty() && !self.generation_active() {
            let (mut wb, authz) = self.writebacks.remove(0);
            let (s2, d2) = self.observe();
            wb.observed = s2.digest();
            match self.ex.submit(wb.clone(), authz.clone(), &s2, &d2) {
                Submitted::Finished { state: TxnState::Committed, .. } => {}
                Submitted::Rejected { reason: RejectReason::Other(w), .. } if w == "busy" => {
                    self.writebacks.insert(0, (wb, authz));
                    return;
                }
                Submitted::Parked { approve, .. } => {
                    self.notice(format!("saving the setting needs approval: planarian approve {approve}"))
                }
                other => self.notice(format!(
                    "this setting will not survive reboot: saving it failed ({})",
                    render::submitted_short(&other)
                )),
            }
        }
    }

    /// §13 (P22): for each unit, the catalog change last committed for it,
    /// if the override file no longer carries what it set.
    fn lost_changes(&self, l: &Ledger) -> BTreeMap<UnitId, (ChangeId, BTreeMap<String, Value>)> {
        let Ok((live, _)) = self.ex.b.generations().read_overrides() else { return BTreeMap::new() };
        let mut last: BTreeMap<UnitId, (ChangeId, BTreeMap<String, Value>)> = BTreeMap::new();
        // Terminal records in id order: the last commit for a unit wins.
        for t in l.terminal.values() {
            let (TxnState::Committed, Transition::ApplyChange { change, args }) = (&t.state, &t.transition) else {
                continue;
            };
            let (change, args) = if change.0 == planarian_changes::REAPPLY {
                match args.get("change") {
                    Some(Value::Str(c)) => {
                        let mut a = args.clone();
                        a.remove("change");
                        (ChangeId(c.clone()), a)
                    }
                    _ => continue,
                }
            } else {
                (change.clone(), args.clone())
            };
            if let Some(u) = planarian_changes::target_of(&change, &args) {
                last.insert(u, (change, args));
            }
        }
        let cat = &self.ex.cfg.catalog;
        last.retain(|_, (c, a)| {
            c.0 != "repair:reenable-predicted"
                && planarian_changes::handle(cat, c, a).is_ok_and(|set| !planarian_changes::carried(&live, &set))
        });
        last
    }

    fn is_canonical(&self, u: &UnitId, defs: &UnitDefs) -> bool {
        defs.get(u).is_some_and(|d| {
            d.probes.iter().any(|p| p.origin == ProbeOrigin::Canonical && p.role == ProbeRole::Readiness)
        })
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

    /// Whether a switch outside Planarian is still settling at `now`: from
    /// the tick that saw the generation change until `SWITCH_SETTLE` after
    /// the last tick that still saw work queued, and never beyond
    /// `SWITCH_SETTLE_MAX` after the change. A person's stop after the window
    /// is a person's. Known limits (D24): the queue is systemd's whole job
    /// queue (`queued_jobs()`; an `Err` counts as busy, so the window then
    /// runs to the cap); the window is not restored
    /// after a daemon restart; a person's stop of a non-Security unit inside
    /// the window is read as a fault and repaired.
    fn in_switch_window(&mut self, now: Timestamp) -> bool {
        let Some((since, until)) = self.switch_window else { return false };
        let cap = since.plus(SWITCH_SETTLE_MAX);
        let busy = now.0 < until.0 && self.b.units().queued_jobs().map_or(true, |j| !j.is_empty());
        let until = if busy { Timestamp(until.0.max(now.plus(SWITCH_SETTLE).0)) } else { until };
        let until = Timestamp(until.0.min(cap.0));
        if now.0 >= until.0 {
            self.switch_window = None;
            return false;
        }
        self.switch_window = Some((since, until));
        true
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
        // Units that crashed this tick (up before, failed now): units that
        // require them and went down with them are part of that fault.
        let crashed: BTreeSet<UnitId> = defs
            .keys()
            .filter(|u| {
                matches!(self.prev_status.get(*u), Some(UnitStatus::Running | UnitStatus::Degraded(_)))
                    && matches!(s.status(u, defs), UnitStatus::Failed(_))
            })
            .cloned()
            .collect();
        use planarian_exec::residue::EndingFacts;
        let host_held = self.b.units().held();
        let mut tried_hold = false;
        let in_switch = self.in_switch_window(now);
        for (u, def) in defs {
            let st = s.status(u, defs);
            // A Security unit killed by a termination signal that systemd
            // restarted between two ticks: Planarian never saw it down, but
            // it was still stopped outside Planarian (§11). Alarmed; systemd
            // has already restored it.
            if def.sensitivity.contains(Sensitivity::Security)
                && def.id.kind == UnitKind::Service
                && let Some(n) = self.b.units().auto_restarts(u)
            {
                let before = self.prev_auto_restarts.insert(u.clone(), n);
                // (Once systemd has restarted it, ExecMain* describe the new
                // process, so how the old one ended is no longer visible.)
                if before.is_some_and(|b| n > b) && !self.touched.contains(u) {
                    self.notice(format!(
                        "ALARM: {u}, which is security-sensitive, ended outside Planarian (killed, stopped or crashed); systemd started it again"
                    ));
                }
            }
            let was_up = matches!(self.prev_status.get(u), Some(UnitStatus::Running | UnitStatus::Degraded(_)));
            let now_down = matches!(st, UnitStatus::Failed(_) | UnitStatus::Stopped);
            current.insert(u.clone(), st.clone());
            // The decision is the pure classifier's (U3; Kani: exec::kani).
            let facts = EndingFacts {
                was_up,
                now_down,
                stopped_cleanly: st == UnitStatus::Stopped,
                ended: if was_up && now_down { self.b.units().ended_by(u) } else { None },
                service: def.id.kind == UnitKind::Service,
                // Inside a switch window only non-Security units are explained:
                // a Security unit's stop is always a fault, restarted and
                // alarmed (§11).
                touched_by_planarian: self.touched.contains(u)
                    || self.generation_touched
                    || (in_switch && !def.sensitivity.contains(Sensitivity::Security)),
                expected: s.expected(u, defs),
                requirement_crashed: def
                    .edges
                    .iter()
                    .any(|e| e.from == *u && e.kind == EdgeKind::Requires && crashed.contains(&e.to)),
                security: def.sensitivity.contains(Sensitivity::Security),
                stops_are_faults: def.stops_are_faults,
                systemd_restarts: def.systemd_restart.as_ref().is_some_and(|p| p.restart),
                lenient,
                network_tool: def.holds && s.protecting.contains(u),
                held: s.holds.contains(u) || host_held.as_ref().is_ok_and(|h| h.contains(u)),
                hold_tried: false,
            };
            use planarian_exec::residue::Residue;
            let mut r = planarian_exec::residue::classify(&facts);
            if let Residue::HoldFirst(_) = r {
                // §12d: "by planariad for a stop outside Planarian that is
                // not attributed": ask the host, whose condition (the
                // footprint, a release) decides, as OnFailure= does. A hold
                // the host cannot confirm counts as held (fail closed: the
                // unit is restarted, never inferred stopped). The next
                // network_holds journals it, by the daemon.
                // Deliberate and rare: the tick waits for the hold unit to
                // start (its condition waits about 3 s), at most HOLD_WAIT;
                // only here (a network tool's unattributed stop outside
                // Planarian), and P9's slow-tick warning says so by design.
                // Past HOLD_WAIT the hold counts as held (below) and its job
                // goes on in systemd: the socket, approvals and other repairs
                // are not stalled for `hold::apply`'s 30 s. Deciding before the residue is recorded is the
                // point: an Inferred stop must not be written for a unit
                // whose traffic is then held.
                let now = self.b.clock().boot_now();
                let waiting =
                    self.hold_unconfirmed.get(u).is_some_and(|next| now < *next) || self.hold_wait().is_none();
                let o = match self.hold_wait() {
                    _ if waiting => Outcome::Unknown("waiting for its hold job".into()),
                    Some(w) => {
                        let t0 = self.b.clock().boot_now();
                        let o = self.b.units().hold(u, w);
                        self.hold_spent(t0);
                        o
                    }
                    None => Outcome::Unknown("no time left on this tick".into()),
                };
                let held = match o {
                    Outcome::Unknown(_) if !waiting => {
                        // Not confirmed: alarmed once, and asked for again
                        // only after the retry (network_holds checks the host
                        // every tick meanwhile).
                        if self.hold_unconfirmed.insert(u.clone(), now.plus(HOLD_UNCONFIRMED_RETRY)).is_none() {
                            self.notice(format!("ALARM: {u}: its traffic could not be held ({o:?})"));
                        }
                        true
                    }
                    Outcome::Failed(_) | Outcome::Unknown(_) => true,
                    _ => self.b.units().held().map_or(true, |h| h.contains(u)),
                };
                if held {
                    self.daemon_held.insert(u.clone());
                }
                tried_hold = true;
                r = planarian_exec::residue::classify(&EndingFacts { held, hold_tried: true, ..facts });
            }
            match r {
                Residue::NotAStop | Residue::Fault => {}
                // The hold's own alarm (network_holds) is the alarm; the
                // incident manager restarts it, without asking
                // (`restarts_held_unit`).
                Residue::AlarmHeld(_) => {}
                Residue::HoldFirst(_) => unreachable!("classified again with hold_tried"),
                Residue::AlarmSecurity(e) => self.notice(format!(
                    "ALARM: {u}, which is security-sensitive, was stopped outside Planarian ({}); starting it again",
                    signal_name(e)
                )),
                // inferStops = false (B-11): never inferred as intent; a
                // fault, which the incident manager repairs.
                Residue::AlarmMustRun(e) => self.notice(format!(
                    "ALARM: {u}, which must keep running, was stopped outside Planarian ({}); starting it again",
                    signal_name(e)
                )),
                Residue::Intended(e) => {
                    down.insert(u.clone(), e);
                }
            }
        }
        self.prev_status = current;
        self.touched.clear();
        self.generation_touched = false;
        if down.is_empty() {
            return tried_hold;
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
                    acknowledged: false,
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
            // §16 (P23): the first time, teach the attributed form.
            let teach = if std::mem::replace(&mut self.residue_taught, true) {
                String::new()
            } else {
                format!(" Next time, planarian stop {r} does the same with your name on it.")
            };
            self.notice(format!(
                "{r}: stopped outside Planarian ({how}); I take that as intended and leave it stopped until the next boot{also}. To start it again: planarian release {r}.{teach}"
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
        let eval = |g: GenerationId| gens.path_of(g).and_then(|p| gens.evaluate_built(&p));
        let (Some(prev), Ok(now_e)) = (prev, eval(cur)) else { return };
        let Ok(before_e) = eval(prev) else { return };
        let (now_d, before) = (&now_e.declarations, &before_e.declarations);
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
                        "by {} through {} (transaction {}), written to planarian/overrides.nix; defined in {}",
                        who(&t.facts.caller),
                        render::transition(&t.transition),
                        t.id.0,
                        if files.is_empty() { "an unknown file".to_string() } else { files.join(", ") }
                    ),
                    None => format!(
                        "by {} through {}, defined in {}; generation created at {}",
                        created.map(|(uid, _)| who(&Actor::user(uid))).unwrap_or_else(|| "an unknown user".into()),
                        // A file inside a flake input's source: that input,
                        // and its lock change since the previous generation.
                        match now_e.inputs.iter().find(|(_, (_, path))| {
                            !path.is_empty() && files.iter().any(|f| f.starts_with(path.as_str()))
                        }) {
                            Some((name, (rev, _))) => format!(
                                "flake input {name} ({} → {rev}) in an out-of-band nixos-rebuild",
                                before_e.inputs.get(name).map(|(r, _)| r.as_str()).unwrap_or("not an input before")
                            ),
                            None => "an out-of-band nixos-rebuild".into(),
                        },
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
                m.units.insert(id.clone(), crate::hooks::sanitized(def));
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
    /// A verified external document accepted: journaled (its sequence and
    /// digest, B-16) when newer than the last one the journal accepted, then
    /// put in force.
    pub fn accept_external(&mut self, doc: crate::hooks::DesiredDoc, digest: Hash) {
        if self.ledger().external.is_none_or(|(s, _)| doc.seq > s) {
            self.journal(Record::ExternalAccepted { seq: doc.seq, digest });
        }
        self.set_external(Some(doc));
    }

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

    /// The boot report (§10), once per boot: units from outside the
    /// generation. `main` runs it before signalling ready, so nothing that
    /// waits for planarian-ready.target starts before it is clean; the first
    /// tick runs it otherwise (the gym). The finding, if any.
    pub fn boot_report(&mut self) -> Option<String> {
        if !std::mem::take(&mut self.boot_report_due) {
            return None;
        }
        let foreign = self.b.units().foreign_units();
        for u in &foreign {
            self.notice(format!("INTEGRITY: boot report: {u} runs, but this generation does not declare it"));
        }
        let g = self.b.generations().current().unwrap_or_default();
        let text = if foreign.is_empty() {
            "clean: every running unit is declared by this generation".to_string()
        } else {
            format!("INTEGRITY: undeclared units: {}", foreign.join(", "))
        };
        self.last_boot_report = Some((self.b.clock().now(), g, text));
        (!foreign.is_empty()).then(|| format!("boot report: undeclared units: {}", foreign.join(", ")))
    }

    pub fn tick(&mut self) {
        // §12d: all hold calls in this tick share one HOLD_WAIT, spent only
        // by the hold calls themselves (hold_wait).
        self.hold_left = HOLD_WAIT;
        // I7's agent for an approval is needed only while the change is
        // parked; a cancelled, expired, invalidated or refused one leaves.
        // An approved one leaves `ex.parked` only inside `Executor::approve`,
        // and the Approve handler writes its record in the same call, so
        // the record never misses its agent (a slow build is deferred before
        // `approve`, while the change is still parked).
        let parked = &self.ex.parked;
        self.parked_agents.retain(|t, _| parked.contains_key(t));
        let (s, defs) = self.observe();
        let now = s.observed_at;
        // P9: a tick over its 500 ms budget is warned, with the probes that
        // ran in it (they are the usual cause).
        // At most one warning a minute, counting the slow ticks between.
        if let Some((took, ran)) = self.asm.slow_tick.take() {
            self.slow_ticks_unwarned += 1;
            if self.last_slow_warning.is_none_or(|t| now.0 >= t.0 + SLOW_TICK_WARN_EVERY.0) {
                eprintln!(
                    "planariad: warning: slow tick: {} ms (budget {} ms; {} slow tick(s) since the last warning); probes run: {}",
                    took.0,
                    planarian_state::TICK_BUDGET.0,
                    self.slow_ticks_unwarned,
                    if ran.is_empty() { "none".to_string() } else { ran.join(", ") }
                );
                self.slow_tick_warnings += 1;
                self.slow_ticks_unwarned = 0;
                self.last_slow_warning = Some(now);
            }
        }

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
        if let Some(why) = self.boot_report() {
            self.integrity = Some(why);
            return;
        }

        let again = std::mem::take(&mut self.reprepare).into_iter().map(|(id, t)| (id, t, None)).collect();
        self.prepare_again(again, "after a restart", &s, &defs);
        // §12f: what a rollback withdrew, once that rollback is terminal.
        if !self.withdrawn.is_empty() && !self.generation_active() {
            let again = std::mem::take(&mut self.withdrawn);
            self.prepare_again(again, "after the rollback", &s, &defs);
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

        // §12d: the hold is in place before the incident opens; a hold the
        // daemon just applied is in the state the repair is derived from.
        let held = if self.unmanaged.is_empty() {
            self.network_holds(&s, &defs)
        } else {
            // The unmanaged tools are hold subjects only: seen and defined
            // for this call, never in the state or defs the incident manager
            // and the residue read, so none is repaired or opens an incident.
            let (hs, hd) = self.with_unmanaged(&s, &defs);
            self.network_holds(&hs, &hd)
        };
        let (s, defs) = if held { self.observe() } else { (s, defs) };

        self.flag_exec_probes(&defs);

        // §13: a hold opened here runs from the decision, after the probes.
        let decided = self.b.clock().now();
        for inc in self.incidents.tick_at(now, decided, &s, &defs) {
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
                    lost_changes: &BTreeMap::new(),
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
                                    e.probe == p.id
                                        && matches!(
                                            e.result,
                                            ProbeResult::Timeout | ProbeResult::Abandoned | ProbeResult::Error(_)
                                        )
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
            self.asm.reobserve(&t, now);
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
            // Unit repairs may run while a generation awaits its boot, and
            // once it is admitted at boot (I6).
            let busy = l.live.values().any(|t| {
                !t.txn.state.is_pre_mutation()
                    && t.txn.state != TxnState::AwaitingBoot
                    && !(t.txn.state == TxnState::Promoted && t.boot_only)
            });
            if !busy {
                self.repair_one(&s, &defs, &l);
            }
            // §12f: an activation window opened for a waiting generation.
            if !busy {
                for (id, r) in self.ex.activate_waiting(&s, &defs) {
                    // A repair that waited is an attempt once it runs.
                    let linked: Vec<IncidentId> =
                        self.incident_parked.iter().filter(|(_, t)| **t == id).map(|(i, _)| *i).collect();
                    for inc in linked {
                        self.incident_parked.remove(&inc);
                        if let Submitted::Finished { state, .. } = &r
                            && let Some(i) =
                                self.incidents.record_attempt(inc, id, outcome_of(state), self.b.clock().now())
                        {
                            self.journal(Record::Incident(i));
                        }
                    }
                    if matches!(r, Submitted::Finished { state: TxnState::Rejected(RejectReason::Stale), .. }) {
                        self.notice(format!(
                            "transaction {}: not activated: the configuration, the override file or what the change would do changed while it waited; ask for it again",
                            id.0
                        ));
                        continue;
                    }
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

        // §12a: write-backs that waited for a generation transaction.
        if !l.interlocked() {
            self.flush_writebacks();
        }

        for t in self.ex.expire() {
            self.notice(format!("approval for transaction {} expired", t.0));
        }
        self.remind_restart(&l);
        for (t, change) in self.ex.expire_waiting() {
            // §12f: the incident, if any, reopens.
            self.incident_parked.retain(|_, w| *w != t);
            self.notice(format!(
                "transaction {} cancelled: it waited a day in Built without an activation window ({}); issue it again to retry",
                t.0,
                render::transition(&change)
            ));
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

    /// §12f: a transaction in `AwaitingBoot` has no time limit; the "restart
    /// to finish" notice is repeated once a day until that restart.
    fn remind_restart(&mut self, l: &Ledger) {
        let now = self.b.clock().boot_now();
        let waiting: Vec<(TxnId, String)> = l
            .live
            .values()
            .filter(|t| t.txn.state == TxnState::AwaitingBoot)
            .map(|t| (t.txn.id, render::transition(&t.txn.transition)))
            .collect();
        self.restart_reminded.retain(|id, _| waiting.iter().any(|(w, _)| w == id));
        for (id, what) in waiting {
            let last = *self.restart_reminded.entry(id).or_insert(now);
            if now > last.plus(RESTART_REMINDER) {
                self.restart_reminded.insert(id, now);
                self.notice(format!("transaction {}: {what} is still waiting for a restart; restart to finish", id.0));
            }
        }
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
                    .filter(|e| {
                        matches!(e.result, ProbeResult::Timeout | ProbeResult::Abandoned | ProbeResult::Error(_))
                    })
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
        // Drop parked links whose approval was decided or whose wait in
        // Built ended.
        let parked = self.ex.parked.clone();
        let ex = &self.ex;
        self.incident_parked.retain(|_, t| parked.contains_key(t) || ex.is_waiting(*t));
        // §12f (P8): in quiet mode a deferred repair is deferred in fact: the
        // loop skips it, so its budget and backoff do not advance.
        let quiet = self.quiet;
        let Some(inc) = self
            .incidents
            .actionable(now)
            .into_iter()
            .filter(|i| !quiet || foreground_depends_on(&i.target, defs))
            .find(|i| !self.incident_parked.contains_key(&i.id))
            .cloned()
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
            lost_changes: &self.lost_changes(l),
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
        // §13: a cooldown or hold set here runs from the decision, read
        // after the work before it, as an attempt's backoff does (not from
        // the observation's start).
        match diagnose::next(&inc, &inputs) {
            None => {
                if let Some(i) = self.incidents.exhausted(inc.id, self.b.clock().now()) {
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
                if let Some(i) =
                    self.incidents.escalate(inc.id, EscalationReason::RevertBlockedByFloor, self.b.clock().now())
                {
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
                // §10: a canonical unit that needs repair before an admitted
                // boot-only change is confirmed counts against it.
                let admitted = l.live.values().any(|t| t.txn.state == TxnState::Promoted && t.boot_only);
                if admitted && self.is_canonical(&c.target, defs) {
                    self.repaired_before_confirmation.insert(c.target.clone());
                }
                match self.submit(p, authorization_of(Actor::Daemon), s, defs) {
                    // §12f: waiting in Built for an activation window is not an
                    // attempt; the incident waits with it, and reopens if the
                    // wait expires.
                    Submitted::Finished { txn, state: TxnState::Built, .. } => {
                        self.incident_parked.insert(inc.id, txn);
                    }
                    Submitted::Finished { txn, state, .. } => {
                        // §13: the backoff runs from the attempt itself, not
                        // from the observation that found it actionable
                        // (which may have taken a while): read after it ran,
                        // so the next attempt is never closer than the floor.
                        let at = self.b.clock().now();
                        if let Some(i) = self.incidents.record_attempt(inc.id, txn, outcome_of(&state), at) {
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
                        let changes = self
                            .approval_diff(txn, &c.transition, &facts)
                            .summary()
                            .map(|s| format!("; {s}"))
                            .unwrap_or_default();
                        self.notice(format!(
                            "{}: {} needs approval ({}{changes}): planarian approve {approve}",
                            inc.target,
                            render::transition(&c.transition),
                            render::facts_summary(&facts)
                        ));
                    }
                    Submitted::Rejected { reason, detail, .. } => {
                        if let Some(i) = self.incidents.exhausted(inc.id, self.b.clock().now()) {
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
        let healthy = s.generation == g && self.canonical_healthy(s, defs);
        // §10, §12 step 7: the admitted boot-only change commits, or is
        // withdrawn, here and only here.
        let admitted: Vec<TxnId> = self
            .ledger()
            .live
            .values()
            .filter(|t| t.txn.state == TxnState::Promoted && t.path.iter().any(|p| p == "AwaitingBoot"))
            .map(|t| t.txn.id)
            .collect();
        // Repairs run meanwhile, but a canonical unit that needed one is
        // evidence against the change, even if it is up again now.
        let repaired = std::mem::take(&mut self.repaired_before_confirmation);
        for id in admitted {
            match self.ex.kernel.confirm_boot_only(id, healthy && repaired.is_empty()) {
                Ok(TxnState::Committed) => {}
                Ok(TxnState::Reverted) => {
                    let back = self.b.generations().boot_default().map(|d| d.0).unwrap_or_default();
                    let why = if repaired.is_empty() {
                        "canonical probes were failing at the 10-minute checkpoint".to_string()
                    } else {
                        let units: Vec<String> = repaired.iter().map(|u| u.to_string()).collect();
                        format!("{} needed a repair before the 10-minute checkpoint", units.join(", "))
                    };
                    self.notice(format!(
                        "transaction {}: not confirmed ({why}); generation {back} is the default again \
                         and a restart completes the withdrawal",
                        id.0
                    ))
                }
                Ok(other) => self.notice(format!("transaction {}: confirmation left it {other:?}", id.0)),
                Err(e) => self.notice(format!("transaction {}: confirmation failed: {e:?}", id.0)),
            }
        }
        if healthy {
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
    fn authz(&mut self, peer: &Peer) -> Authorization {
        if let Some(name) = &peer.agent {
            // §11 (owner decision, 2026-10-30): an agent has the permissions
            // of the user who started it, judged as that user with no login
            // session and no terminal. One the journal has no start for is
            // granted nothing.
            // Bound to the instance the peer runs in, never the name (I24).
            let instance = peer.instance.map(|i| i.0).unwrap_or_default();
            let Some(by) = self.ledger().agent_for(name, instance) else {
                let actor = Actor::Agent(agent_principal(name));
                return Authorization { principal: actor.principal(), actor, capabilities: Capabilities::default() };
            };
            let actor = Actor::User { uid: by, session: None, seat: None, active: false };
            return user_authorization(actor, (self.admin_of)(by));
        }
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

    fn user_submit(&mut self, mut t: Transition, peer: Peer, source: Source, reason: String) -> Response {
        // §12d: even an explicitly unbounded hold release ends at boot. Use
        // the same lifetime for the override and its backend marker.
        if let Transition::SetOverride(o) = &mut t
            && crate::hold::released(o).is_some()
            && o.until == Until::Explicit
        {
            o.until = Until::NextBoot;
        }
        // Admission before work (R09): a caller refused anyway queues no
        // staging or build; `submit` then refuses it, logged.
        let who = self.authz(&peer);
        let admitted = self.ex.admit(&t, &who).is_ok();
        if admitted
            && self.defer
            && self.deferred.is_none()
            && let Some(job) = self.ex.prebuild_job(&t)
        {
            self.deferred = Some((job, Resume { peer, kind: ResumeKind::Submit { t, source, reason } }));
            return Response::Ok { message: "deferred".into() };
        }
        let (s, defs) = self.observe();
        let p = self.proposal(t, &s, &defs, source, reason);
        let authz = self.authz(&peer);
        let t = p.transition.clone();
        let r = self.submit(p, authz, &s, &defs);
        // §16: the notice shows what a generation change waiting for
        // approval would change.
        if let Submitted::Parked { txn, approve, facts } = &r
            && let Some(changes) = self.approval_diff(*txn, &t, facts).summary()
        {
            self.notice(format!(
                "{} needs approval ({}; {changes}): planarian approve {approve}",
                render::transition(&t),
                render::facts_summary(facts)
            ));
        }
        let mut resp = self.respond(&r);
        // Who may approve it (§11): an administrator, when the class says so.
        if let (Response::NeedsApproval { txn, why, .. }, Submitted::Parked { .. }) = (&mut resp, &r)
            && self.ex.parked.get(txn).is_some_and(|p| p.class == ApproverClass::Administrator)
        {
            why.push_str("; an administrator must approve it");
        }
        resp
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
                UnitRow {
                    unit: u.clone(),
                    detail: render::evidence(&s, &defs, u),
                    expected: s.expected(u, &defs),
                    status,
                }
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
                diff: self.approval_diff(p.txn, &p.proposal.transition, &p.facts),
                // Shown to people: the boot-clock issue time on the wall clock.
                issued: Timestamp(
                    self.b.clock().now().0.saturating_sub(self.b.clock().boot_now().0.saturating_sub(p.issued.0)),
                ),
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
            inferred: l
                .overrides
                .iter()
                .filter(|o| o.attribution == Attribution::Inferred && !o.acknowledged)
                .map(|o| (o.unit.clone(), o.reason.clone()))
                .collect(),
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
        self.acting_agent = peer.agent.clone();
        let r = self.handle_as(peer, req);
        self.acting_agent = None;
        r
    }

    fn handle_as(&mut self, peer: Peer, req: Request) -> Response {
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
            Request::HoldRelease { unit, until } => {
                // §12d: an attested override on the hold unit, through the
                // executor like any override, with the hold's administrator
                // floor regardless of the held tool's tags: authority, or
                // AskFirst with an Administrator approver (§11).
                let hold = crate::hold::hold_unit(&unit);
                let (_, defs) = self.observe();
                if !defs.contains_key(&hold) {
                    return Response::Error {
                        message: format!("{unit} is not a network-security unit; there is no hold to release"),
                    };
                }
                let reason = format!("planarian hold release {}", unit.name);
                let o = Override::attested(
                    hold,
                    OverrideDesired::Stopped,
                    until.clone(),
                    reason.clone(),
                    Actor::user(peer.uid),
                );
                self.user_submit(Transition::SetOverride(o), peer, Source::User, reason)
            }
            Request::LiftOverride { unit } => {
                let r = self.user_submit(
                    Transition::LiftOverride(unit.clone()),
                    peer.clone(),
                    Source::User,
                    "from the CLI".into(),
                );
                // Incident control state changes only on an authorized,
                // successful human action (§13, R08): a refused or failed
                // release leaves the record, its budget and cooldown alone.
                let released = matches!(&r, Response::Done { state: TxnState::Committed, .. });
                if !released {
                    return r;
                }
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
            Request::Acknowledge { unit } => {
                if peer.agent.is_some() {
                    return Response::Rejected {
                        reason: "Unauthorized".into(),
                        message: "an agent cannot acknowledge".into(),
                    };
                }
                let open: Vec<Override> = self
                    .ledger()
                    .overrides
                    .iter()
                    .filter(|o| o.attribution == Attribution::Inferred && !o.acknowledged)
                    .filter(|o| unit.as_ref().is_none_or(|u| *u == o.unit))
                    .cloned()
                    .collect();
                for o in &open {
                    self.journal(Record::OverrideSet(Override { acknowledged: true, ..o.clone() }));
                }
                if !open.is_empty() {
                    self.notice(format!(
                        "uid {} acknowledged: {}",
                        peer.uid,
                        open.iter().map(|o| format!("{} (inferred override)", o.unit)).collect::<Vec<_>>().join(", ")
                    ));
                }
                Response::Ok {
                    message: format!("{} inferred override(s) acknowledged; they hold until they end", open.len()),
                }
            }
            Request::AgentRun { name, argv } => {
                if peer.agent.is_some() {
                    return Response::Rejected {
                        reason: "Unauthorized".into(),
                        message: "an agent cannot start agents".into(),
                    };
                }
                if !planarian_schema::backend::valid_agent_name(&name) || argv.is_empty() {
                    return Response::Error {
                        message: "agent run <name> -- <command>: the name is 1-32 of a-z, 0-9 and -".into(),
                    };
                }
                // A name in use is refused, so a second start never rebinds
                // what a running agent may do (I24, B-20).
                if self.b.units().agent_running(&name) {
                    let owner = self.ledger().agent_owner(&name);
                    return Response::Rejected {
                        reason: "Unauthorized".into(),
                        message: match owner {
                            Some(u) => format!("agent {name} is already running, started by uid {u}; stop it first"),
                            None => format!("agent {name} is already running; stop it first"),
                        },
                    };
                }
                // §12d (R05): a per-uid limit on agents running at once.
                let limit = self.cfg.agent_limits.per_uid;
                let mine = self
                    .ledger()
                    .agents
                    .iter()
                    .filter(|(n, _, by)| *by == peer.uid && self.b.units().agent_running(n))
                    .map(|(n, _, _)| n.clone())
                    .collect::<BTreeSet<_>>();
                if mine.len() as u32 >= limit {
                    return Response::Rejected {
                        reason: "Unauthorized".into(),
                        message: format!(
                            "uid {} already runs {} agent(s), the limit (services.planarian.agents.limits.perUid = {limit})",
                            peer.uid,
                            mine.len()
                        ),
                    };
                }
                match self.b.units().start_agent(&name, &argv, &self.cfg.agent_limits) {
                    Ok(instance) => {
                        // Journaled once it has started, with the instance it
                        // started as: a failed start binds nothing (I24).
                        self.journal(Record::AgentStarted { name: name.clone(), instance: instance.0, by: peer.uid });
                        self.notice(format!(
                            "agent {name} started by uid {} ({}); it acts with that user's permissions",
                            peer.uid,
                            planarian_schema::backend::agent_unit(&name)
                        ));
                        Response::Ok { message: format!("agent {name} is running with your permissions") }
                    }
                    Err(other) => Response::Error { message: format!("could not start agent {name}: {other:?}") },
                }
            }
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
            Request::Approve { hash } => {
                if peer.uid != 0 || !peer.tty {
                    return Response::Error {
                        message: "approve requires root at an interactive terminal (Phase A)".into(),
                    };
                }
                if self.defer && self.deferred.is_none() {
                    let t = self.ex.parked.values().find(|p| p.bound_to == hash).map(|p| p.proposal.transition.clone());
                    if let Some(job) = t.and_then(|t| self.ex.prebuild_job(&t)) {
                        let req = Request::Approve { hash };
                        self.deferred = Some((job, Resume { peer, kind: ResumeKind::Request(req) }));
                        return Response::Ok { message: "deferred".into() };
                    }
                }
                let (s, defs) = self.observe();
                let approver = self.authz(&peer);
                let parked = self.ex.parked.values().find(|p| p.bound_to == hash).cloned();
                let (pre, policy) = (s.digest(), self.ex.policy_version());
                let built = self.waiting_built();
                let r = self.ex.approve(&hash, &approver, &s, &defs);
                self.note_withdrawn(built);
                if let Some(pk) = &parked {
                    self.committed_hold_release(&pk.proposal.transition, &r, &defs);
                }
                // Re-bound and asked again under a new id (§12 step 4): the
                // proposer's agent goes with it.
                if let (Some(pk), Submitted::Parked { txn: again, .. }) = (&parked, &r)
                    && *again != pk.txn
                    && let Some(agent) = self.parked_agents.remove(&pk.txn)
                {
                    self.parked_agents.insert(*again, agent);
                }
                // I7: the approved execution writes its own log record; an
                // approval passes §12 step 6 here, not at submission (C18).
                if let (Some(pk), Submitted::Finished { txn, .. }) = (parked, &r) {
                    let l = self.ledger();
                    // The proposer's agent, not whoever is acting now.
                    let agent = self.parked_agents.remove(&pk.txn).flatten();
                    let rec = if *txn == pk.txn {
                        LogRecord {
                            at: self.b.clock().now(),
                            no_snapshot: no_snapshot(&r, Some(&pk.facts)),
                            approver: Some(approver.actor.clone()),
                            bound_to: Some(hash),
                            proposal: pk.proposal,
                            caller: pk.authz.actor,
                            pre_digest: pre,
                            policy,
                            result: r.clone(),
                            facts: Some(pk.facts),
                            decision: Some(Decision::Allow { tier: Tier::AskFirst, approver: pk.class }),
                            post_digest: None,
                            path: l.path(*txn).map(<[String]>::to_vec).unwrap_or_default(),
                            why: l.terminal.get(txn).map(|x| x.why.clone()).unwrap_or_default(),
                            agent,
                        }
                    } else {
                        // Re-bound (§12 step 4), and the fresh decision no
                        // longer asks: it ran as an ordinary submission under
                        // a new id, approved by nobody. Log it as one, with the
                        // new plan's facts and decision.
                        let (facts, decision) = self.ex.last.clone().unzip();
                        let mut proposal = pk.proposal;
                        proposal.observed = pre;
                        LogRecord {
                            at: self.b.clock().now(),
                            no_snapshot: no_snapshot(&r, facts.as_ref()),
                            approver: None,
                            bound_to: None,
                            proposal,
                            caller: pk.authz.actor,
                            pre_digest: pre,
                            policy,
                            result: r.clone(),
                            facts,
                            decision,
                            post_digest: None,
                            path: l.path(*txn).map(<[String]>::to_vec).unwrap_or_default(),
                            why: l.terminal.get(txn).map(|x| x.why.clone()).unwrap_or_default(),
                            agent,
                        }
                    };
                    self.awaiting_post.push(rec);
                }
                self.respond(&r)
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
                self.respond(&r)
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
                // §16 (K10): root at an interactive terminal, the terminal
                // established by the daemon from the peer, as for approve.
                if peer.uid != 0 || !peer.tty {
                    return Response::Error {
                        message: "mark-good requires root at an interactive terminal (Phase A)".into(),
                    };
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
            // §16 (P17): the last boot report, and the posture in force.
            Request::ReportBoot => match &self.last_boot_report {
                Some((at, g, text)) => Response::Ok {
                    message: format!("boot report for generation {} at {}: {text}", g.0, render::when(*at)),
                },
                None => Response::Ok {
                    message: "no boot report since planariad started (it runs once, on the first start after boot)"
                        .into(),
                },
            },
            Request::Posture => {
                let d = &self.cfg.posture_decl;
                let mut message = format!(
                    "posture: {:?}, boot-ready timeout {} s (this generation declares {:?}, {} s)",
                    self.cfg.posture,
                    d.timeout_in_force(),
                    d.declared,
                    d.declared_timeout_secs
                );
                if d.weaker_waiting() {
                    message.push_str("; the weaker declaration takes effect at the next boot");
                }
                Response::Ok { message }
            }
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
                self.respond(&r)
            }
            #[cfg(feature = "gym-hooks")]
            Request::GymCompact => match self.compact_saving() {
                Ok(entries) => Response::Compacted {
                    entries: entries.iter().filter_map(|e| serde_json::to_value(e).ok()).collect(),
                },
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
                // Only units the caller may act on: their own user scope, the
                // units users control, or any for an administrator (§11).
                let mine = matches!(unit.scope, Scope::User { uid, .. } if uid == peer.uid);
                let controllable = self.ex.cfg.settings.user_controllable_units.contains(&unit.name);
                if !(peer.admin || mine || controllable) {
                    return Response::Rejected {
                        reason: "Unauthorized".into(),
                        message: format!("you may not probe {unit}"),
                    };
                }
                let probes: Vec<ProbeId> = match probe {
                    Some(p) => vec![p],
                    None => def.probes.iter().map(|p| p.id.clone()).collect(),
                };
                for p in &probes {
                    let audible = def
                        .probes
                        .iter()
                        .any(|d| &d.id == p && matches!(d.side_effects, SideEffects::Audible | SideEffects::Visible));
                    // Sound or light only from the caller's own seated session.
                    let seated = peer.session.as_ref().is_some_and(|id| {
                        self.asm
                            .sessions
                            .iter()
                            .any(|x| &x.id == id && x.uid == peer.uid && x.seat.is_some() && !x.remote)
                    });
                    if audible && !seated {
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

/// §12f: units foreground work plausibly depends on, whose repairs quiet
/// mode does not defer: a user's own units (audio), devices (sound, GPU,
/// input, network cards), and units whose restart drops a session or the
/// network (compositor, display manager, network, Bluetooth).
fn foreground_depends_on(u: &UnitId, defs: &UnitDefs) -> bool {
    matches!(u.scope, Scope::User { .. })
        || u.kind == UnitKind::Device
        || u.name.contains("bluetooth")
        || defs
            .get(u)
            .is_some_and(|d| matches!(d.restart_disruption, Disruption::SessionLoss | Disruption::ConnectivityLoss))
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
