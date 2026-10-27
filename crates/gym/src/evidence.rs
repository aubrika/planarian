//! What a run left behind, in the form the judge reads (check.rs). The fake
//! harness fills it from the simulated machine (`Sim::evidence`); the VM
//! harness fills it from a real one: the journal, the executor log, the
//! daemon's notices and a status sampler (live.rs).

use planarian_daemon::LogRecord;
use planarian_ipc::Response;
use planarian_schema::*;
use planarian_txn::ledger::Ledger;
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
    /// The live override file assigns nothing (it is the base's).
    pub overrides_empty: bool,
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
}
