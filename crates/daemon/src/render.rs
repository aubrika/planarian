//! Plain-language rendering of transitions, records and results.

use planarian_exec::Submitted;
use planarian_ipc::Response;
use planarian_schema::*;
use planarian_txn::ledger::Record;
use planarian_txn::machine::tag;

pub fn value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        Value::List(l) => format!("[{}]", l.iter().map(value).collect::<Vec<_>>().join(", ")),
    }
}

pub fn until(u: &Until) -> String {
    match u {
        Until::Explicit => "until you lift it".into(),
        Until::NextBoot => "until the next boot".into(),
        Until::At(t) => format!("until {}", t.0),
    }
}

pub fn transition(t: &Transition) -> String {
    match t {
        Transition::RestartUnit(u) => format!("restart {u}"),
        Transition::StopUnit(u) => format!("stop {u}"),
        Transition::BindDriver { device, driver } => format!("bind {} to {device}", driver.name),
        Transition::ApplyChange { change, args } => {
            let a: Vec<String> = args.iter().map(|(k, v)| format!("{k}={}", value(v))).collect();
            format!("apply {} {}", change.0, a.join(" ")).trim_end().to_string()
        }
        Transition::SwitchGeneration(g) => format!("switch to generation {}", g.0),
        Transition::Revert { to } => format!("revert to generation {}", to.0),
        Transition::Rollback => "roll back to the known-good generation".into(),
        Transition::LoadModel(m) => format!("load model {}", m.0),
        Transition::RestoreSnapshot(s) => format!("restore snapshot {}", s.0),
        Transition::CollectGarbage { emergency: true } => "emergency garbage collection".into(),
        Transition::CollectGarbage { .. } => "garbage collection".into(),
        Transition::SetRuntimeOption { path, value: v } => format!("set {path} to {}", value(v)),
        Transition::Suppress(s) => format!("leave {} alone {}", s.unit, until(&s.until)),
        Transition::Unsuppress(u) => format!("stop leaving {u} alone"),
        Transition::StopAndSuppress { unit, until: u, .. } => format!("stop {unit} and leave it stopped {}", until(u)),
        Transition::Resolve { txn, resolution } => format!("resolve transaction {} as {resolution:?}", txn.0),
    }
}

pub fn record(r: &Record) -> String {
    match r {
        Record::Prepared(t) => {
            format!("txn {}: prepared: {} (by {:?})", t.id.0, transition(&t.transition), t.facts.caller)
        }
        Record::Advance { txn, to, note, .. } if note.is_empty() => format!("txn {}: {}", txn.0, tag(to)),
        Record::Advance { txn, to, note, .. } => format!("txn {}: {} — {note}", txn.0, tag(to)),
        Record::Takeover { txn, lease, .. } => {
            format!("txn {}: taken over by {:?} (epoch {})", txn.0, lease.owner, lease.epoch)
        }
        Record::Renew { txn, .. } => format!("txn {}: lease renewed", txn.0),
        Record::OpBegin { op, call } => format!("txn {}: {call}", op.txn.0),
        Record::OpAck { op, outcome } => format!("txn {}: → {outcome:?}", op.txn.0),
        Record::Suppressed(s) => format!("{} left alone {} (by {:?})", s.unit, until(&s.until), s.by),
        Record::Unsuppressed(u) => format!("{u} no longer left alone"),
        Record::Incident(i) => format!(
            "incident {} on {}: {:?}, {} attempt(s), budget {}",
            i.id.0,
            i.target,
            i.state,
            i.attempts.len(),
            i.budget_left
        ),
        Record::KnownGood(g) => format!("generation {} confirmed known-good", g.0),
        Record::LiveTested(Some(g)) => format!("generation {} passed its live tests", g.0),
        Record::LiveTested(None) => "live-tested generation cleared".into(),
        Record::AcceptedBaseline(g) => format!("accepted baseline: {g:?}"),
        Record::TokenUsed { .. } => "approval token used".into(),
        Record::Resolved { txn, resolution, by } => format!("txn {} resolved as {resolution:?} by {by:?}", txn.0),
        Record::Reconciliation(r) => format!("reconciliation by {:?}: {}", r.by, r.actions.join("; ")),
    }
}

pub fn evidence(s: &SystemState, u: &UnitId) -> String {
    let Some((o, ev)) = s.units.get(u) else { return String::new() };
    let mut parts = vec![format!("{o:?}")];
    for e in ev {
        let r = match &e.result {
            ProbeResult::Pass => "pass".to_string(),
            ProbeResult::Fail(m) => format!("FAIL ({m})"),
            ProbeResult::Timeout => "timeout".to_string(),
            ProbeResult::Error(m) => format!("error ({m})"),
        };
        let stale = if e.fresh_at(s.observed_at) { "" } else { ", stale" };
        parts.push(format!("{}: {r}{stale}", e.probe.0));
    }
    parts.join("; ")
}

pub fn submitted_short(s: &Submitted) -> String {
    match s {
        Submitted::Rejected { reason, detail, .. } => format!("{reason:?}: {detail}"),
        Submitted::Parked { approve, .. } => format!("needs approval {approve}"),
        Submitted::Finished { state, .. } => tag(state).to_string(),
        Submitted::Error(e) => e.clone(),
    }
}

pub fn facts_summary(f: &DerivedFacts) -> String {
    let mut why = vec![];
    if f.sensitivity.contains(Sensitivity::Security) {
        why.push("it touches security-relevant settings".to_string());
    }
    if f.sensitivity.contains(Sensitivity::External) {
        why.push("it affects external connectivity".to_string());
    }
    if f.sensitivity.contains(Sensitivity::UserData) {
        why.push("it touches user data".to_string());
    }
    match f.disruption {
        Disruption::SessionLoss => why.push("it would end your graphical session".into()),
        Disruption::DataInterruption => why.push("it would interrupt a data service".into()),
        Disruption::ConnectivityLoss => why.push("it would drop network connectivity".into()),
        _ => {}
    }
    if f.recovery == Recovery::NonReversible {
        why.push("it cannot be undone".into());
    }
    if f.touches_manifest {
        why.push("it changes Planarian's own manifest".into());
    }
    if f.touches_canonical_probe {
        why.push("it changes a canonical health check".into());
    }
    if why.is_empty() {
        why.push("the autonomy setting requires approval".into());
    }
    let units: Vec<String> = f.affected_units.iter().map(|u| u.to_string()).collect();
    format!("{}; affects {}", why.join(", "), if units.is_empty() { "no units".into() } else { units.join(", ") })
}

pub fn response(s: &Submitted) -> Response {
    match s {
        Submitted::Finished { txn, state, .. } => {
            let message = match state {
                TxnState::Committed => "done".to_string(),
                TxnState::Reverted => "the change failed its health checks and was reverted; nothing changed".to_string(),
                TxnState::RecoveryFailed => "the change failed AND reverting it failed; autonomous repair is stopped. See `planarian status`, then `planarian resolve`".to_string(),
                TxnState::Rejected(r) => format!("not done: {r:?}"),
                TxnState::Cancelled(_) => "withdrawn".to_string(),
                s => tag(s).to_string(),
            };
            Response::Done { txn: *txn, state: state.clone(), message }
        }
        Submitted::Parked { txn, approve, facts } => Response::NeedsApproval {
            txn: *txn,
            approve: *approve,
            what: format!("transaction {}", txn.0),
            why: facts_summary(facts),
        },
        Submitted::Rejected { reason, detail, .. } => {
            Response::Rejected { reason: format!("{reason:?}"), message: detail.clone() }
        }
        Submitted::Error(e) => Response::Error { message: e.clone() },
    }
}

/// A size for people: `1.5 GB`, `300 MB`.
pub fn bytes(n: u64) -> String {
    const GB: f64 = 1e9;
    const MB: f64 = 1e6;
    let x = n as f64;
    if x >= GB { format!("{:.1} GB", x / GB) } else { format!("{:.0} MB", x / MB) }
}
