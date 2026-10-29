//! The daemon's Unix-socket protocol (`/run/planarian/planariad.sock`).
//!
//! One newline-terminated JSON `Request` per connection, answered by one
//! JSON `Response`. The caller's identity is never part of the request: the
//! daemon takes it from `SO_PEERCRED` (§11).

use planarian_schema::{
    ChangeId, DerivedFacts, EdgeKind, GenerationId, Hash, Incident, IncidentState, OverrideDesired, ProbeId,
    Resolution, Timestamp, Transition, TxnId, TxnState, UnitId, UnitStatus, Until, Value,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SOCKET: &str = "/run/planarian/planariad.sock";

fn leave_alone() -> OverrideDesired {
    OverrideDesired::LeaveAlone
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    Status,
    Log {
        limit: usize,
    },
    Incidents,
    /// `ask "<phrase>"`; `choice` picks one of a previous `Confirm`'s options.
    Ask {
        phrase: String,
        choice: Option<usize>,
    },
    Apply {
        change: ChangeId,
        args: BTreeMap<String, Value>,
    },
    SetOverride {
        unit: UnitId,
        until: Until,
        #[serde(default = "leave_alone")]
        desired: OverrideDesired,
    },
    LiftOverride {
        unit: UnitId,
    },
    /// A `StopUnit` from the CLI; rewritten to `StopAndSuppress { NextBoot }` (§14).
    Stop {
        unit: UnitId,
    },
    Restart {
        unit: UnitId,
    },
    Gc,
    Undo,
    /// Root and an interactive TTY (checked by the client; root re-checked here).
    Approve {
        hash: Hash,
        tty: bool,
    },
    Cancel {
        txn: TxnId,
    },
    Resolve {
        txn: TxnId,
        resolution: Resolution,
    },
    MarkGood {
        accept_unconfirmed: bool,
    },
    Diagnose {
        unit: UnitId,
        probe: Option<ProbeId>,
    },
    /// Everything the read-only console shows (§16a), in one answer.
    Console,
    /// The gym's VM harness: submit `transition` as a proposal from the
    /// caller, optionally with a stale digest or a narrowed `may_change`.
    /// Answered only by a daemon built with `gym-hooks`.
    GymPropose {
        transition: Transition,
        stale_digest: bool,
        may_change: Option<Vec<UnitId>>,
    },
    /// The gym's VM harness: compact the journal now. `gym-hooks` only.
    GymCompact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRow {
    pub unit: UnitId,
    pub status: UnitStatus,
    pub expected: bool,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub txn: TxnId,
    pub approve: Hash,
    pub what: String,
    pub facts: DerivedFacts,
    pub issued: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    pub generation: GenerationId,
    pub known_good: Option<GenerationId>,
    pub live_tested: Option<GenerationId>,
    pub accepted_baseline: Option<GenerationId>,
    pub boot_default: Option<GenerationId>,
    /// "no baseline yet" until initial enrollment (§16).
    pub baseline_note: Option<String>,
    pub units: Vec<UnitRow>,
    pub incidents: Vec<Incident>,
    pub pending: Vec<Pending>,
    pub in_flight: Vec<(TxnId, TxnState, String)>,
    pub interlock: Vec<(TxnId, String)>,
    pub reconciliation: Option<Vec<String>>,
    pub notices: Vec<String>,
    /// The last garbage collection's result (§12b).
    #[serde(default)]
    pub space: Option<planarian_schema::gc::SpaceReport>,
}

/// One node of the console's Graph view: what is desired, what is observed,
/// and how healthy it is, kept apart (three indicators, not one colour).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub unit: UnitId,
    /// "Running", "Stopped", … and whether its condition holds now.
    pub desired: String,
    pub expected: bool,
    /// The supervisor's view: "Active", "Failed: …", "Unknown: …".
    pub observed: String,
    pub health: UnitStatus,
    pub suppressed: bool,
    /// Its readiness evidence is stale or unknown.
    pub stale: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: UnitId,
    pub to: UnitId,
    pub kind: EdgeKind,
}

/// One transaction in the console's Timeline view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxnSummary {
    pub txn: TxnId,
    pub what: String,
    /// Journal states, in order.
    pub path: Vec<String>,
    pub state: TxnState,
    pub live: bool,
    pub by_watchdog: bool,
    pub why: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleReport {
    pub status: StatusReport,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Newest first.
    pub timeline: Vec<TxnSummary>,
    pub previous: Option<GenerationId>,
    pub last_booted: Option<GenerationId>,
    /// Generations an in-flight transaction is building or activating.
    pub candidates: Vec<GenerationId>,
    /// The most recent generation change was reverted.
    pub last_change_reverted: bool,
    /// The daemon's clock when it answered.
    #[serde(default)]
    pub now: Timestamp,
}

impl ConsoleReport {
    /// §16a: something needs a person: an open incident, a pending approval,
    /// the recovery interlock, a reconciliation record, or a reverted change.
    /// The console starts visible, and the tray turns amber or red.
    pub fn needs_attention(&self) -> bool {
        let s = &self.status;
        s.incidents.iter().any(|i| i.state != IncidentState::Closed)
            || !s.pending.is_empty()
            || !s.interlock.is_empty()
            || s.reconciliation.as_ref().is_some_and(|a| !a.is_empty())
            || self.last_change_reverted
    }
}

/// A unit status in words.
pub fn status_words(s: &UnitStatus) -> String {
    use UnitStatus as S;
    use planarian_schema::Reason;
    match s {
        S::Running => "running".into(),
        S::Degraded(probes) => {
            let names: Vec<&str> = probes.iter().map(|p| p.0.as_str()).collect();
            format!("running, but failing its health check ({})", names.join(", "))
        }
        S::Stopped => "stopped".into(),
        S::Overridden(d) => match d {
            planarian_schema::OverrideDesired::LeaveAlone => "left alone on request".into(),
            planarian_schema::OverrideDesired::Stopped => "stopped on request".into(),
            planarian_schema::OverrideDesired::Absent => "disabled on request".into(),
            planarian_schema::OverrideDesired::Detected => "detached on request".into(),
        },
        S::Unknown => "unknown (no fresh evidence)".into(),
        S::Failed(Reason::ExitCode(c)) => format!("failed (exit code {c})"),
        S::Failed(Reason::DriverError(e)) => format!("failed (driver: {e})"),
        S::Failed(Reason::Backend(e)) => format!("failed ({e})"),
        S::Absent => "absent".into(),
        S::Detected => "detected, no driver bound".into(),
        S::Bound => "bound to its driver".into(),
        S::Transitioning => "starting or stopping".into(),
        S::NotExpected => "not expected now".into(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    pub seq: u64,
    pub at: Timestamp,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Choice {
    pub index: usize,
    pub understood: String,
    pub confidence: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Response {
    Status(Box<StatusReport>),
    Console(Box<ConsoleReport>),
    Log {
        lines: Vec<LogLine>,
    },
    Incidents {
        incidents: Vec<Incident>,
    },
    /// A transaction ran to a terminal state.
    Done {
        txn: TxnId,
        state: TxnState,
        message: String,
    },
    /// AskFirst: waiting for `planarian approve <approve>` (as root).
    NeedsApproval {
        txn: TxnId,
        approve: Hash,
        what: String,
        why: String,
    },
    Rejected {
        reason: String,
        message: String,
    },
    /// The phrase matched more than one thing; ask again with `choice`.
    Confirm {
        choices: Vec<Choice>,
    },
    Unmatched {
        message: String,
    },
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
}

impl Request {
    pub fn encode(&self) -> String {
        let mut s = serde_json::to_string(self).expect("request serializes");
        s.push('\n');
        s
    }
}

impl Response {
    pub fn encode(&self) -> String {
        let mut s = serde_json::to_string(self).expect("response serializes");
        s.push('\n');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let r = Request::SetOverride {
            unit: "service:gym-web".parse().unwrap(),
            until: Until::Explicit,
            desired: planarian_schema::OverrideDesired::LeaveAlone,
        };
        let s = r.encode();
        assert!(s.contains("\"op\":\"set-override\""), "{s}");
        assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
        let a = Request::Ask { phrase: "restart wifi".into(), choice: None };
        assert_eq!(serde_json::from_str::<Request>(&a.encode()).unwrap(), a);
    }
}
