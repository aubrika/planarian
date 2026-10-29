//! Read-only answers while the core is busy.
//!
//! The core handles one request at a time, and a generation change can hold
//! it for many minutes (evaluate, build, activate, check). Before handling a
//! request that may take that long, the daemon takes a snapshot of what
//! `status`, `log`, `incidents` and the console would show; until the request
//! finishes, those are answered from the snapshot, marked as such, instead of
//! waiting behind it.

use crate::core::{Core, Peer};
use planarian_ipc::{ConsoleReport, LogLine, Request, Response};
use planarian_schema::{Backends, Incident};
use planarian_txn::store::Store;
use std::time::Instant;

/// Lines of the log kept for `planarian log` while busy.
const LOG_LINES: usize = 1000;

#[derive(Clone, Debug)]
pub struct Snapshot {
    console: ConsoleReport,
    incidents: Vec<Incident>,
    log: Vec<LogLine>,
}

/// What the core is doing instead of answering.
#[derive(Clone, Debug)]
pub struct Busy {
    pub with: String,
    pub since: Instant,
}

/// Requests that only read, and so may be answered from a snapshot.
pub fn read_only(req: &Request) -> bool {
    matches!(req, Request::Status | Request::Log { .. } | Request::Incidents | Request::Console)
}

/// A few words for "busy with …".
pub fn describe(req: &Request) -> String {
    match req {
        Request::Apply { change, .. } => format!("the change {}", change.0),
        Request::Ask { phrase, .. } => format!("\"{phrase}\""),
        Request::Approve { .. } => "an approved change".into(),
        Request::Undo => "undo".into(),
        Request::Gc => "garbage collection".into(),
        Request::Restart { unit } => format!("restarting {unit}"),
        Request::Stop { unit } => format!("stopping {unit}"),
        Request::MarkGood { .. } => "mark-good".into(),
        Request::Resolve { txn, .. } => format!("resolving transaction {}", txn.0),
        Request::Diagnose { unit, .. } => format!("diagnosing {unit}"),
        _ => "a request".into(),
    }
}

impl Snapshot {
    /// One observation: the console report carries the status report.
    pub fn take<B: Backends + Clone, S: Store>(core: &mut Core<B, S>) -> Option<Snapshot> {
        let me = Peer::new(0, false);
        let Response::Console(console) = core.handle(me.clone(), Request::Console) else { return None };
        let Response::Incidents { incidents } = core.handle(me.clone(), Request::Incidents) else { return None };
        let Response::Log { lines } = core.handle(me, Request::Log { limit: LOG_LINES }) else { return None };
        Some(Snapshot { console: *console, incidents, log: lines })
    }

    pub fn answer(&self, req: &Request, busy: &Busy) -> Option<Response> {
        let mins = busy.since.elapsed().as_secs() / 60;
        let note = format!(
            "busy with {} for {}: this is how things stood when it started",
            busy.with,
            if mins == 0 { "under a minute".to_string() } else { format!("{mins} min") }
        );
        Some(match req {
            Request::Status => {
                let mut s = self.console.status.clone();
                s.notices.insert(0, note);
                Response::Status(Box::new(s))
            }
            Request::Console => {
                let mut c = self.console.clone();
                c.status.notices.insert(0, note);
                Response::Console(Box::new(c))
            }
            Request::Incidents => Response::Incidents { incidents: self.incidents.clone() },
            Request::Log { limit } => {
                let skip = self.log.len().saturating_sub(*limit);
                Response::Log { lines: self.log[skip..].to_vec() }
            }
            _ => return None,
        })
    }
}
