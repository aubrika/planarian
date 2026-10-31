//! What a run left behind, in the form the judge reads (check.rs). The fake
//! harness fills it from the simulated machine (`Sim::evidence`); the VM
//! harness fills it from a real one: the journal, the executor log, the
//! daemon's notices and a status sampler (live.rs).

use planarian_daemon::LogRecord;
use planarian_ipc::Response;
use planarian_schema::*;
use planarian_txn::ledger::{Entry, Ledger};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// The generation running, and the one the boot menu defaults to.
    pub current: GenerationId,
    pub boot_default: GenerationId,
    /// The catalog's symbolic generations.
    pub base: GenerationId,
    pub candidate: Option<GenerationId>,
    /// Generations in the boot menu, and those garbage-collected during the run.
    pub boot_entries: Vec<GenerationId>,
    pub collected: Vec<GenerationId>,
    /// Sources staged and candidates built during the run (fake harness).
    #[serde(default)]
    pub work: Option<(usize, usize)>,
    /// The live override file assigns nothing (it is the base's).
    pub overrides_empty: bool,
    /// The live override file's hash at the end, and the hash of what a
    /// third party wrote to it during the run (I23), if one did.
    #[serde(default)]
    pub override_hash: Option<Hash>,
    /// What disagrees among boot selection, GC roots, the override file and
    /// the journal at the end (empty: they agree); None where the harness
    /// cannot see all four.
    pub agreement: Option<Vec<String>>,
    #[serde(default)]
    pub third_party_override: Option<Hash>,
    /// The journal at the end, and whether it replays cleanly.
    pub ledger: Ledger,
    pub journal_replays: bool,
    /// Executor log records (I7) written during the run.
    pub log: Vec<LogRecord>,
    /// Statuses just before the first step, and at the end.
    pub pre_status: BTreeMap<UnitId, String>,
    pub finals: BTreeMap<UnitId, String>,
    /// Units the entry's own steps act on (exempt from `others_unchanged`).
    pub touched: BTreeSet<UnitId>,
    /// Every status each unit showed during the run.
    pub seen_status: BTreeMap<UnitId, BTreeSet<String>>,
    /// Every incident seen during the run (latest version of each), and the
    /// ones still open at the end, by target.
    pub seen_incidents: BTreeMap<IncidentId, Incident>,
    pub open_incidents: BTreeMap<UnitId, Incident>,
    pub first_incident_at: BTreeMap<UnitId, Timestamp>,
    pub start: Timestamp,
    /// Restarts Planarian performed, per unit.
    pub restarts: BTreeMap<UnitId, i64>,
    /// The daemon's notices, and the answers to the entry's own requests.
    pub notices: Vec<String>,
    pub responses: Vec<Response>,

    // What the harness can supply beyond that; `None` where it cannot, and a
    // check that needs it is then reported unchecked.
    /// Every journal entry written during the run, across compactions.
    #[serde(default)]
    pub entries: Option<Vec<Entry>>,
    /// The ledger from replaying that whole history, when the run compacted
    /// the journal (the live ledger then comes from the checkpoint plus tail).
    #[serde(default)]
    pub full_replay: Option<Ledger>,
    /// Backend mutations that went through (not fenced), with the time each
    /// one's effect lasted: an instant, or a background job's run.
    #[serde(default)]
    pub effects: Option<Vec<Effect>>,
    /// Each unit's status changes, in order.
    #[serde(default)]
    pub status_timeline: Option<BTreeMap<UnitId, Vec<(Timestamp, String)>>>,
    /// The driver bound to each device at the end.
    #[serde(default)]
    pub drivers: Option<BTreeMap<UnitId, String>>,
    /// The running generation's evaluated options.
    #[serde(default)]
    pub options: Option<BTreeMap<String, Value>>,
    /// The probe definitions in force at the start and at the end.
    #[serde(default)]
    pub probe_defs: Option<(String, String)>,
    /// Planarian's build GC roots at the start and at the end.
    #[serde(default)]
    pub gc_roots: Option<(BTreeSet<String>, BTreeSet<String>)>,
    /// The failure posture (§12d) as the run left it.
    #[serde(default)]
    pub posture: PostureSeen,
}

/// What the failure posture did. The fake harness models only planariad's
/// side (it stops with status 78, routed to Integrity); the responses are
/// systemd's and only the VM harness observes them (`responses: None`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PostureSeen {
    /// Failure classes reached during the run (`absent`, `crashed`, `integrity`).
    pub classes: BTreeSet<String>,
    /// The integrity finding planariad reported.
    pub finding: Option<String>,
    /// Responses observed while failed: alarm, notify_admins, disable_agents,
    /// restrict_remote, restrict_login, halt_to_recovery, alarm_dismissable.
    pub responses: Option<BTreeSet<String>>,
    /// Acknowledgements journaled (`user:1001`) and refused (`user:1000`).
    pub acks: Vec<String>,
    pub refused_acks: Vec<String>,
    /// The restrictions were lifted once ready again.
    pub lifted: bool,
    /// The journal's open at the end failed its chain check (I18 detected).
    pub chain_broken: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Effect {
    /// `activate_live(candidate)`, `activate_live(revert_to)`, `restart(<unit>)`, …
    pub call: String,
    pub txn: TxnId,
    pub epoch: u64,
    /// The journaled call (`OpBegin`) this effect came from.
    pub seq: u64,
    pub start: Timestamp,
    /// `None`: still running at the end.
    pub end: Option<Timestamp>,
}
