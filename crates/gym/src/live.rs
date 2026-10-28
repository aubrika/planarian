//! The VM harness's in-VM half. `nix/tests/gym-vm.nix` boots a NixOS VM with
//! the gym fixtures and a Planarian built with `gym-hooks`, then drives one
//! catalog entry through these commands:
//!
//!   planarian-gym vm plan  --id ID       how each step runs: vm, host, armed or unsupported
//!   planarian-gym vm begin --id ID       wait for a healthy baseline, record it, start sampling
//!   planarian-gym vm step  --id ID --index N
//!   planarian-gym vm request --json REQ  (run as the step's actor, via runuser)
//!   planarian-gym vm sample               the status sampler (a transient unit)
//!   planarian-gym vm judge --id ID       wait the window, gather evidence, judge
//!
//! Host steps (reboot, suspend, hot-unplug, the upstream machine) are done by
//! the test driver. Steps timed to a journal state are armed: a planariad kill
//! becomes a crash point (`/run/planarian-gym/crash`) on the request before
//! it, as in the fake harness; other timed steps run from a watcher.

use crate::check;
use crate::evidence::{Effect, Evidence};
use crate::sim::{dur, unit, value};
use planarian_backend_linux::{Paths, Real};
use planarian_daemon::LogRecord;
use planarian_daemon::config::{CONFIG, FileConfig};
use planarian_exec::Submitted;
use planarian_ipc::{ConsoleReport, Request, Response, SOCKET};
use planarian_schema::*;
use planarian_txn::journal::Journal;
use planarian_txn::ledger::{Entry, Ledger, Record};
use planarian_txn::store::FileStore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use toml::Value as T;

/// Where a run keeps its state (survives a reboot of the VM).
pub const RUN: &str = "/var/lib/gym-run";
const HOOKS_DIR: &str = "/run/planarian-gym";

/// The VM's users, by catalog actor.
fn user_for(actor: &str) -> &'static str {
    match actor {
        "root" => "root",
        "user:1000" => "alice",
        "user:1002" => "carol",
        // user:1001 is the owner (planarian-admin).
        _ => "bob",
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Plan {
    /// Per step: "vm", "host", "armed" (done by a crash point or watcher) or
    /// "unsupported: …".
    pub steps: Vec<String>,
    /// Crash points to arm before the request at a step index.
    pub crash_before: BTreeMap<usize, String>,
    /// Steps a watcher performs when the journal reaches a state.
    pub watched: BTreeMap<usize, String>,
    pub hold: bool,
    pub window_secs: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Start {
    at: Timestamp,
    unix: u64,
    base: GenerationId,
    boot_entries: Vec<GenerationId>,
    log_lines: usize,
    pre_status: BTreeMap<UnitId, String>,
    touched: BTreeSet<UnitId>,
    #[serde(default)]
    probe_defs: String,
    #[serde(default)]
    gc_roots: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Sample {
    at: Timestamp,
    status: BTreeMap<UnitId, String>,
    incidents: Vec<Incident>,
    notices: Vec<String>,
}

fn steps(entry: &T) -> Vec<T> {
    ["setup", "inject", "after"]
        .iter()
        .flat_map(|k| match entry.get(k) {
            Some(T::Array(a)) => a.clone(),
            Some(t @ T::Table(_)) => vec![t.clone()],
            _ => vec![],
        })
        .collect()
}

fn s<'a>(step: &'a T, k: &str) -> &'a str {
    step.get(k).and_then(T::as_str).unwrap_or("")
}

fn is_request(step: &T) -> bool {
    step.get("transition").is_some() || matches!(s(step, "raw"), "ask" | "cli" | "approve_pending")
}

/// How each step runs in a VM.
pub fn plan(entry: &T) -> Plan {
    let all = steps(entry);
    let mut p = Plan { window_secs: crate::window(entry).0 / 1000, ..Default::default() };
    let mut changed_generation = false;
    for (i, st) in all.iter().enumerate() {
        if matches!(s(st, "transition"), "ApplyChange" | "SwitchGeneration" | "Rollback") {
            changed_generation = true;
        }
        // The test VM boots its kernel directly, not through its boot menu,
        // so a reboot always comes back to the system it was started with.
        if s(st, "raw") == "reboot" && changed_generation {
            p.steps.push("unsupported: booting a published generation (the test VM has no boot loader)".into());
            continue;
        }
        let when = st.get("when").and_then(|w| w.get("journal")).and_then(T::as_str);
        let op_called = st.get("when").and_then(|w| w.get("op_called")).and_then(T::as_str);
        let after = st.get("when").and_then(|w| w.get("after"));
        let raw = s(st, "raw");
        let slow_activation = all.iter().any(|x| s(x, "raw") == "slow_backend" && s(x, "call") == "activate_live");
        let kind = if op_called == Some("activate_live") && raw == "kill_process" && slow_activation {
            // The slow part runs in the activation's own unit: kill the daemon
            // from outside once that unit is running (an in-daemon crash point
            // would fire only after the slow call returned).
            p.watched.insert(i, "unit:planarian-op-".into());
            "armed".into()
        } else if let Some(call) = op_called {
            match (0..i).rev().find(|j| is_request(&all[*j])) {
                Some(j) if raw == "kill_process" => {
                    p.crash_before.insert(j, format!("OpCalled:{call}"));
                    "armed".to_string()
                }
                _ => format!("unsupported: {raw} timed to {call}"),
            }
        } else if let Some(a) = after {
            p.watched.insert(i, format!("after:{}", a.as_str().unwrap_or("0s")));
            "armed".into()
        } else if let Some(state) = when {
            match raw {
                // With a slow activation set up, "during Activating" means
                // while its unit runs: kill the daemon from outside then.
                "kill_process" if s(st, "process") == "planariad" && state == "Activating" && slow_activation => {
                    p.watched.insert(i, "unit:planarian-op-".into());
                    "armed".into()
                }
                "kill_process" if s(st, "process") == "planariad" => {
                    let point =
                        if state == "OpId" { "OpCalled:activate_live".to_string() } else { format!("State:{state}") };
                    match (0..i).rev().find(|j| is_request(&all[*j])) {
                        Some(j) => {
                            p.crash_before.insert(j, point);
                            "armed".to_string()
                        }
                        None => "unsupported: a timed kill with no request before it".into(),
                    }
                }
                "edit_owner_source" | "block_network" | "fill_fs" => {
                    p.watched.insert(i, state.to_string());
                    "armed".into()
                }
                other => format!("unsupported: {other} timed to the journal"),
            }
        } else if st.get("when").is_some() {
            format!("unsupported: {} timed by {:?}", raw, st.get("when"))
        } else if st.get("transition").is_some() {
            match s(st, "transition") {
                "ApplyChange" | "RestartUnit" | "CollectGarbage" | "Rollback" | "SwitchGeneration" | "BindDriver"
                | "Suppress" => "vm".into(),
                t => format!("unsupported: transition {t}"),
            }
        } else {
            match raw {
                "reboot" | "suspend" | "hotunplug" | "stop_host_service" | "start_host_service" => "host".into(),
                "kill_unit"
                | "stop_unit_out_of_band"
                | "set_knob"
                | "set_persistent_knob"
                | "corrupt_state"
                | "unbind_driver"
                | "block_network"
                | "unblock_network"
                | "kill_process"
                | "hold_down"
                | "release"
                | "restart_process"
                | "wait"
                | "ask"
                | "cli"
                | "approve_pending"
                | "greeter_login"
                | "logout"
                | "fill_fs"
                | "edit_owner_source"
                | "out_of_band_rebuild"
                | "advance_clock"
                | "slow_backend"
                | "withhold_reply"
                | "backend_result"
                | "set_setting" => "vm".into(),
                "force_compaction" => "vm".into(),
                "interrupt_write" => format!("unsupported: {raw} needs to interrupt the daemon's own write"),
                other => format!("unsupported: {other}"),
            }
        };
        if raw == "hold_down" {
            p.hold = true;
        }
        p.steps.push(kind);
    }
    p
}

fn config() -> FileConfig {
    let path = std::env::var("PLANARIAN_CONFIG").unwrap_or_else(|_| CONFIG.into());
    FileConfig::load(Path::new(&path)).unwrap_or_else(|e| die(&format!("{path}: {e}")))
}

fn real(cfg: &FileConfig) -> Real {
    let paths = Paths {
        state: cfg.state_dir.clone(),
        owner: cfg.owner.clone(),
        flake_attr: cfg.flake_attr.clone(),
        ..Default::default()
    };
    Real::new(paths, cfg.devices.clone())
}

fn die(m: &str) -> ! {
    eprintln!("planarian-gym vm: {m}");
    std::process::exit(2)
}

fn sh(cmd: &str) -> bool {
    Command::new("sh").arg("-c").arg(cmd).status().map(|s| s.success()).unwrap_or(false)
}

fn sh_out(cmd: &str) -> String {
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

pub fn call(req: &Request) -> Result<Response, String> {
    let path = std::env::var("PLANARIAN_SOCKET").unwrap_or_else(|_| SOCKET.into());
    let mut c = UnixStream::connect(&path).map_err(|e| format!("{path}: {e}"))?;
    c.write_all(req.encode().as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(c).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| format!("bad answer: {e}"))
}

fn console() -> Option<ConsoleReport> {
    match call(&Request::Console) {
        Ok(Response::Console(r)) => Some(*r),
        _ => None,
    }
}

fn status_name(st: &UnitStatus) -> String {
    format!("{st:?}").split('(').next().unwrap_or("").to_string()
}

fn statuses(r: &ConsoleReport) -> BTreeMap<UnitId, String> {
    r.nodes.iter().map(|n| (n.unit.clone(), status_name(&n.health))).collect()
}

fn run_dir() -> PathBuf {
    let d = PathBuf::from(RUN);
    let _ = std::fs::create_dir_all(&d);
    let _ = sh(&format!("chmod 1777 {RUN}"));
    d
}

fn read_json<V: for<'de> Deserialize<'de>>(p: &Path) -> Option<V> {
    serde_json::from_slice(&std::fs::read(p).ok()?).ok()
}

fn write_json<V: Serialize>(p: &Path, v: &V) {
    let _ = std::fs::write(p, serde_json::to_vec_pretty(v).expect("serializes"));
}

/// The journal as the daemon left it: a copy, replayed.
fn ledger(cfg: &FileConfig) -> (Ledger, bool) {
    match journal_copy(cfg) {
        Some(j) => (j.ledger().clone(), true),
        None => (Ledger::default(), false),
    }
}

/// The entries since the journal's last checkpoint.
fn segment(cfg: &FileConfig) -> Vec<Entry> {
    journal_copy(cfg).and_then(|mut j| j.segment().ok()).unwrap_or_default()
}

/// Journal entries saved before a forced compaction discarded them.
const SAVED: &str = "entries-saved.json";

fn journal_copy(cfg: &FileConfig) -> Option<Journal<FileStore>> {
    let paths = Paths { state: cfg.state_dir.clone(), ..Default::default() };
    let tmp = PathBuf::from(format!("{RUN}/journal-copy"));
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = sh(&format!(
        "mkdir -p {t} && cp -a {j} {t}/journal && cp -a {x} {t}/txn 2>/dev/null; true",
        t = tmp.display(),
        j = paths.journal_dir().display(),
        x = paths.txn_dir().display()
    ));
    match FileStore::open(&tmp.join("journal"), &tmp.join("txn"), cfg.journal_bytes).map(Journal::open) {
        Ok(Ok(j)) => Some(j),
        _ => None,
    }
}

/// The probe definitions of the running generation, per unit.
fn probe_defs(cfg: &FileConfig) -> String {
    let b = real(cfg);
    let g = Backends::generations(&b);
    let eval = g.current().and_then(|c| g.path_of(c)).and_then(|p| g.evaluate_built(&p));
    match eval {
        Ok(e) => {
            let probes: BTreeMap<String, Vec<ProbeDef>> =
                e.units.iter().map(|(id, d)| (id.to_string(), d.probes.clone())).collect();
            serde_json::to_string(&probes).expect("serializes")
        }
        Err(o) => format!("unreadable: {o:?}"),
    }
}

/// The TCP ports a unit's network probes connect to.
fn probe_ports(cfg: &FileConfig, u: &UnitId) -> Vec<u16> {
    let b = real(cfg);
    let g = Backends::generations(&b);
    let Ok(e) = g.current().and_then(|c| g.path_of(c)).and_then(|p| g.evaluate_built(&p)) else { return vec![] };
    let port = |hostport: &str| hostport.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
    e.units
        .get(u)
        .map(|d| {
            d.probes
                .iter()
                .filter_map(|p| match &p.kind {
                    ProbeKind::Tcp { addr } => port(addr),
                    ProbeKind::Http { url, .. } => {
                        url.split("://").nth(1).and_then(|r| r.split('/').next()).and_then(port)
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn build_roots() -> BTreeSet<String> {
    std::fs::read_dir("/nix/var/nix/gcroots/planarian/builds")
        .map(|rd| rd.flatten().map(|e| e.path().display().to_string()).collect())
        .unwrap_or_default()
}

/// Backend mutations, from the journal's calls: an activation runs as the
/// transient unit `planarian-op-<txn>-<epoch>-<seq>` and lasts as long as
/// systemd says it ran; any other call is an instant at its OpBegin. Calls
/// the backend fenced, and calls never acknowledged that left no unit, are
/// not effects.
fn effects(entries: &[Entry], since_unix: u64) -> Vec<Effect> {
    #[derive(Deserialize)]
    struct J {
        #[serde(rename = "UNIT")]
        unit: Option<String>,
        #[serde(rename = "MESSAGE")]
        message: Option<String>,
        #[serde(rename = "__REALTIME_TIMESTAMP")]
        at: String,
    }
    let mut spans: BTreeMap<String, (Option<Timestamp>, Option<Timestamp>)> = BTreeMap::new();
    for l in sh_out(&format!("journalctl -o json --no-pager --since @{since_unix} _PID=1")).lines() {
        let Ok(j) = serde_json::from_str::<J>(l) else { continue };
        let (Some(u), Some(m)) = (j.unit, j.message) else { continue };
        let Some(name) = u.strip_suffix(".service").filter(|n| n.starts_with("planarian-op-")) else { continue };
        let at = Timestamp(j.at.parse::<u64>().unwrap_or(0) / 1000);
        let span = spans.entry(name.to_string()).or_default();
        if m.starts_with("Starting") || m.starts_with("Started") {
            span.0.get_or_insert(at);
        } else if m.starts_with("Finished")
            || m.starts_with("Stopped")
            || m.starts_with("Failed")
            || m.contains("Deactivated")
        {
            span.1 = Some(at);
        }
    }
    let revert_name = |call: &str| -> String {
        match call {
            "activate_live" => "activate_live(candidate)".into(),
            other => other.to_string(),
        }
    };
    let acks: BTreeMap<OpId, Outcome> = entries
        .iter()
        .filter_map(|x| match &x.record {
            Record::OpAck { op, outcome } => Some((*op, outcome.clone())),
            _ => None,
        })
        .collect();
    entries
        .iter()
        .filter_map(|x| {
            let Record::OpBegin { op, call } = &x.record else { return None };
            if acks.get(op).is_some_and(Outcome::is_fenced) {
                return None;
            }
            let unit = format!("planarian-op-{}-{}-{}", op.txn.0, op.epoch, op.seq);
            let (start, end) = match spans.get(&unit) {
                Some((s, e)) => (s.unwrap_or(x.at), *e),
                None if acks.contains_key(op) => (x.at, Some(x.at)),
                None => return None,
            };
            Some(Effect { call: revert_name(call), txn: op.txn, epoch: op.epoch, seq: op.seq, start, end })
        })
        .collect()
}

fn journal_reached(cfg: &FileConfig, state: &str) -> bool {
    let (l, _) = ledger(cfg);
    l.live.values().any(|t| t.path.iter().any(|p| p == state))
        || l.terminal.values().any(|t| t.path.iter().any(|p| p == state))
}

/// Wait for a healthy baseline: the daemon answers, every expected unit is
/// up with no incident left over from boot, and this generation is the
/// known-good one.
fn begin(entry: &T) {
    let cfg = config();
    let dir = run_dir();
    let p = plan(entry);
    write_json(&dir.join("plan.json"), &p);
    let deadline = Instant::now() + Duration::from_secs(1200);
    loop {
        if let Some(r) = console() {
            let unhealthy: Vec<String> = r
                .nodes
                .iter()
                .filter(|n| n.expected && !matches!(n.health, UnitStatus::Running | UnitStatus::Bound))
                .map(|n| format!("{} {:?}", n.unit, n.health))
                .chain(
                    r.status
                        .incidents
                        .iter()
                        .filter(|i| i.state != IncidentState::Closed)
                        .map(|i| format!("incident on {} ({:?})", i.target, i.state)),
                )
                .collect();
            if unhealthy.is_empty() {
                break;
            }
            if Instant::now() > deadline {
                die(&format!("no healthy baseline: {unhealthy:?}"));
            }
        } else if Instant::now() > deadline {
            die("planariad does not answer");
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    if ledger(&cfg).0.known_good.is_none() {
        sh("script -qec 'planarian mark-good' /dev/null");
        let until = Instant::now() + Duration::from_secs(300);
        while ledger(&cfg).0.known_good.is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    if p.hold {
        // A held-down daemon must stay down after a kill: no restart.
        sh(
            "mkdir -p /run/systemd/system/planariad.service.d && printf '[Service]\\nRestart=no\\n' > /run/systemd/system/planariad.service.d/gym-hold.conf && systemctl daemon-reload",
        );
    }
    let r = console().unwrap_or_else(|| die("planariad stopped answering"));
    let gens = real(&cfg);
    let g = planarian_schema::Backends::generations(&gens);
    let touched = steps(entry)
        .iter()
        .flat_map(|st| ["unit", "device"].map(|k| st.get(k).and_then(T::as_str).map(unit)))
        .flatten()
        .collect();
    let start = Start {
        at: r.now,
        unix: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        base: g.current().unwrap_or(r.status.generation),
        boot_entries: g.boot_entries().unwrap_or_default(),
        log_lines: std::fs::read_to_string(cfg.state_dir.join("log/executor.jsonl"))
            .map(|t| t.lines().count())
            .unwrap_or(0),
        pre_status: statuses(&r),
        touched,
        probe_defs: probe_defs(&cfg),
        gc_roots: build_roots(),
    };
    write_json(&dir.join("start.json"), &start);
    let _ = std::fs::write(dir.join("responses.jsonl"), "");
    let _ = sh(&format!("chmod 666 {RUN}/responses.jsonl"));
    let exe = std::env::current_exe().map(|e| e.display().to_string()).unwrap_or_else(|_| "planarian-gym".into());
    sh(&format!(
        "systemctl stop gym-sampler 2>/dev/null; systemd-run --unit=gym-sampler -E PLANARIAN_GYM_CATALOG {exe} vm sample"
    ));
    for state in p.watched.values() {
        if let Some(call) = pause_call(state) {
            hooks_set(call, serde_json::json!({ "pause": state }));
        }
    }
    for (i, state) in &p.watched {
        sh(&format!(
            "systemd-run --unit=gym-watch-{i} -E PLANARIAN_GYM_CATALOG {exe} vm step --id {} --index {i} --watched {state}",
            s(entry, "id")
        ));
    }
    println!("begin: base generation {}, {} units", start.base.0, start.pre_status.len());
}

/// The status sampler: every 2 s, what the daemon shows.
fn sample() {
    let path = PathBuf::from(RUN).join("samples.jsonl");
    loop {
        if let Some(r) = console()
            && let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path)
        {
            let smp = Sample {
                at: r.now,
                status: statuses(&r),
                incidents: r.status.incidents.clone(),
                notices: r.status.notices.clone(),
            };
            let _ = writeln!(f, "{}", serde_json::to_string(&smp).expect("serializes"));
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Send a request as the step's actor and record the answer.
fn request_as(actor: &str, req: &Request) -> Result<(), String> {
    let exe = std::env::current_exe().map(|e| e.display().to_string()).unwrap_or_else(|_| "planarian-gym".into());
    let json = serde_json::to_string(req).expect("serializes");
    let user = user_for(actor);
    let q = json.replace('\'', "'\\''");
    let cmd = if user == "root" {
        format!("{exe} vm request --json '{q}'")
    } else {
        format!("runuser -u {user} -- {exe} vm request --json '{q}'")
    };
    if sh(&cmd) { Ok(()) } else { Err(format!("request as {user} failed")) }
}

fn request(json: &str) {
    let req: Request = serde_json::from_str(json).unwrap_or_else(|e| die(&format!("request: {e}")));
    let resp = call(&req).unwrap_or_else(|e| Response::Error { message: e });
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(PathBuf::from(RUN).join("responses.jsonl")) {
        let _ = writeln!(f, "{}", serde_json::to_string(&resp).expect("serializes"));
    }
    println!("{}", serde_json::to_string(&resp).expect("serializes"));
}

fn unit_cmd(u: &UnitId) -> (String, String) {
    let suffix = match u.kind {
        UnitKind::Target => "target",
        _ => "service",
    };
    match u.scope {
        Scope::User { uid, .. } => (
            format!("systemctl --user --machine={}@", user_for(&format!("user:{uid}"))),
            format!("{}.{suffix}", u.name),
        ),
        Scope::System => ("systemctl".into(), format!("{}.{suffix}", u.name)),
    }
}

/// Run one step inside the VM.
/// The backend call the daemon pauses before when a step is timed to this
/// journal state (gym hooks `pause`). Staging and the build happen before
/// the transaction is prepared, so `Staged` is never journaled: the build
/// is where the source is staged. Publishing follows `Checking` at once.
fn pause_call(state: &str) -> Option<&'static str> {
    match state {
        "Staged" | "Built" => Some("build"),
        "Checking" => Some("publish_boot"),
        _ => None,
    }
}

fn step(entry: &T, i: usize, watched: Option<&str>) {
    let cfg = config();
    let all = steps(entry);
    let st = all.get(i).unwrap_or_else(|| die("no such step"));
    let p: Plan = read_json(&PathBuf::from(RUN).join("plan.json")).unwrap_or_else(|| plan(entry));
    if let Some(after) = watched.and_then(|w| w.strip_prefix("after:")) {
        let d = dur(&T::String(after.into())).unwrap_or(Millis(0));
        std::thread::sleep(Duration::from_millis(d.0));
    } else if let Some(prefix) = watched.and_then(|w| w.strip_prefix("unit:")) {
        let until = Instant::now() + Duration::from_secs(3600);
        while sh_out(&format!("systemctl list-units --state=active --no-legend --plain '{prefix}*'")).trim().is_empty()
            && Instant::now() < until
        {
            std::thread::sleep(Duration::from_millis(200));
        }
    } else if let Some(state) = watched.filter(|w| pause_call(w).is_some()) {
        // The daemon waits at the marker; inject, then let it go on.
        let marker = PathBuf::from(HOOKS_DIR).join(format!("paused-{state}"));
        let until = Instant::now() + Duration::from_secs(3600);
        while !marker.exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        let actor = st.get("actor").and_then(T::as_str).unwrap_or("user:1001").to_string();
        let r = run_step(&cfg, st, &actor);
        eprintln!("gym: step {i} at the {state} pause: {r:?}");
        let _ = std::fs::remove_file(&marker);
        if let Err(e) = r {
            die(&format!("step {i}: {e}"));
        }
        return;
    } else if let Some(state) = watched {
        let until = Instant::now() + Duration::from_secs(3600);
        while !journal_reached(&cfg, state) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
    } else if p.steps.get(i).map(String::as_str) == Some("armed") {
        return;
    }
    if let Some(point) = p.crash_before.get(&i) {
        sh(&format!("mkdir -p {HOOKS_DIR} && printf '%s' '{point}' > {HOOKS_DIR}/crash"));
    }
    let actor = st.get("actor").and_then(T::as_str).unwrap_or("user:1001").to_string();
    let r = run_step(&cfg, st, &actor);
    if let Err(e) = r {
        die(&format!("step {i}: {e}"));
    }
}

fn hooks_set(key: &str, value: serde_json::Value) {
    let path = format!("{HOOKS_DIR}/hooks.json");
    let mut v: serde_json::Value =
        std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(serde_json::json!({}));
    v[key] = value;
    let _ = std::fs::create_dir_all(HOOKS_DIR);
    let _ = std::fs::write(&path, serde_json::to_vec(&v).expect("serializes"));
}

fn run_step(cfg: &FileConfig, st: &T, actor: &str) -> Result<(), String> {
    let get = |k: &str| s(st, k).to_string();
    if let Some(t) = st.get("transition").and_then(T::as_str) {
        let req = match t {
            "ApplyChange" => Request::Apply {
                change: ChangeId(get("change")),
                args: st
                    .get("args")
                    .and_then(T::as_table)
                    .map(|a| a.iter().map(|(k, v)| (k.clone(), value(v))).collect())
                    .unwrap_or_default(),
            },
            "RestartUnit" if st.get("expected").is_some() || st.get("observed").is_some() => Request::GymPropose {
                transition: Transition::RestartUnit(unit(&get("unit"))),
                stale_digest: st.get("observed").is_some(),
                may_change: st
                    .get("expected")
                    .and_then(|e| e.get("may_change"))
                    .and_then(T::as_array)
                    .map(|m| m.iter().filter_map(T::as_str).map(unit).collect()),
            },
            "RestartUnit" => Request::Restart { unit: unit(&get("unit")) },
            "CollectGarbage" => Request::Gc,
            "Suppress" => Request::Suppress { unit: unit(&get("unit")), until: Until::Explicit },
            "Rollback" => {
                Request::GymPropose { transition: Transition::Rollback, stale_digest: false, may_change: None }
            }
            "SwitchGeneration" => {
                let g = Backends::generations(&real(cfg)).boot_entries().unwrap_or_default().into_iter().max();
                let g = g.ok_or("no generation to switch to")?;
                Request::GymPropose {
                    transition: Transition::SwitchGeneration(g),
                    stale_digest: false,
                    may_change: None,
                }
            }
            "BindDriver" => Request::GymPropose {
                transition: Transition::BindDriver {
                    device: unit(&get("device")),
                    driver: DriverRef { name: get("driver"), module: None },
                },
                stale_digest: false,
                may_change: None,
            },
            other => return Err(format!("transition {other}")),
        };
        return request_as(actor, &req);
    }
    match get("raw").as_str() {
        "kill_unit" => {
            let (ctl, name) = unit_cmd(&unit(&get("unit")));
            let sig = st.get("signal").and_then(T::as_str).unwrap_or("SIGKILL");
            sh(&format!("{ctl} kill --signal={sig} {name}"));
        }
        "stop_unit_out_of_band" => {
            let (ctl, name) = unit_cmd(&unit(&get("unit")));
            sh(&format!("{ctl} stop {name}"));
        }
        "set_knob" | "set_persistent_knob" if get("knob") == "probe_delay" => {
            // The probe itself stalls, connecting included: drop the packets
            // to the unit's probe ports (a connect cannot be made slow from
            // inside the service).
            for port in probe_ports(cfg, &unit(&get("unit"))) {
                sh(&format!("iptables -I INPUT -p tcp --dport {port} -j DROP"));
            }
        }
        "set_knob" | "set_persistent_knob" => {
            let u = unit(&get("unit"));
            let v = match st.get("value") {
                Some(T::String(x)) => x.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            };
            // A user unit's knobs are per user (cosmic-comp@1000).
            let n = match u.scope {
                Scope::User { uid, .. } => format!("{}@{uid}", u.name),
                _ => u.name.clone(),
            };
            // A one-off knob is marked so the fixture drops it when it restarts.
            let once = if get("raw") == "set_knob" {
                format!(" && touch /var/lib/gym-knobs/{n}/{}.once", get("knob"))
            } else {
                String::new()
            };
            sh(&format!(
                "mkdir -p /var/lib/gym-knobs/{n} && chmod 755 /var/lib/gym-knobs /var/lib/gym-knobs/{n} && printf '%s' '{v}' > /var/lib/gym-knobs/{n}/{k}{once}",
                k = get("knob")
            ));
        }
        "corrupt_state" => {
            sh(&format!("printf 'corrupt{{' > {}", get("path")));
        }
        "unbind_driver" => {
            let dev = unit(&get("device"));
            let sysfs = cfg.devices.get(&dev.name).ok_or(format!("no sysfs path for {dev}"))?;
            sh(&format!(
                "d=$(readlink -f {s}); drv=$(readlink -f $d/driver); echo $(basename $d) > $drv/unbind",
                s = sysfs.display()
            ));
        }
        "block_network" => {
            let port = st.get("port").and_then(T::as_integer);
            let rule = match port {
                Some(p) => format!("-d {} -p tcp --dport {p}", get("dst")),
                None => format!("-d {}", get("dst")),
            };
            // A port blocked on this machine refuses connections (as the fake
            // models it); an unreachable remote host just stops answering.
            if get("dst").starts_with("127.") {
                let tcp = if port.is_some() { rule.clone() } else { format!("{rule} -p tcp") };
                sh(&format!("iptables -I OUTPUT {tcp} -j REJECT --reject-with tcp-reset"));
            } else {
                sh(&format!(
                    "iptables -I OUTPUT {rule} -j DROP && iptables -I INPUT {} -j DROP",
                    rule.replace("-d ", "-s ").replace("--dport", "--sport")
                ));
            }
        }
        "unblock_network" => {
            sh("iptables -F OUTPUT; iptables -F INPUT; true");
        }
        "kill_process" => match get("process").as_str() {
            "planariad" => {
                sh("systemctl kill --signal=SIGKILL planariad");
            }
            "planarian-recovery" => {
                sh("systemctl kill --signal=SIGKILL planarian-recovery");
            }
            p => return Err(format!("kill_process {p}")),
        },
        "hold_down" => {
            sh(&format!(
                "systemctl stop {}",
                if get("process") == "planarian-recovery" { "planarian-recovery" } else { "planariad" }
            ));
        }
        "release" | "restart_process" => {
            sh("rm -f /run/systemd/system/planariad.service.d/gym-hold.conf; systemctl daemon-reload");
            let name = if get("process") == "planarian-recovery" { "planarian-recovery" } else { "planariad" };
            sh(&format!("systemctl restart {name}"));
        }
        "wait" => match st.get("for") {
            Some(T::Table(t)) if t.contains_key("journal") => {
                let state = t["journal"].as_str().unwrap_or("");
                let until = Instant::now() + Duration::from_secs(1800);
                while !journal_reached(cfg, state) && Instant::now() < until {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Some(v) => {
                let d = dur(v).ok_or(format!("wait {v}"))?;
                std::thread::sleep(Duration::from_millis(d.0));
            }
            None => {}
        },
        "ask" => request_as(actor, &Request::Ask { phrase: get("phrase"), choice: None })?,
        "cli" => {
            let argv: Vec<String> = st
                .get("argv")
                .and_then(T::as_array)
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let a: Vec<&str> = argv.iter().map(String::as_str).collect();
            let req = match a.as_slice() {
                ["suppress", u] => Request::Suppress { unit: unit(u), until: Until::Explicit },
                ["stop", u] => Request::Stop { unit: unit(u) },
                ["resolve", _, how] => {
                    let txn = *ledger(cfg).0.interlock.keys().next().ok_or("resolve: nothing interlocked")?;
                    let resolution = match *how {
                        "--as-committed" => Resolution::AsCommitted,
                        "--as-reverted" => Resolution::AsReverted,
                        _ => Resolution::ManualRepaired,
                    };
                    Request::Resolve { txn, resolution }
                }
                ["diagnose", u, "--probe", p] => {
                    Request::Diagnose { unit: unit(u), probe: Some(ProbeId(p.to_string())) }
                }
                // The admin connects to a network outside Planarian.
                ["internal", "wifi-connect", ssid] => {
                    if !sh(&format!("nmcli connection up id {ssid}")) {
                        return Err(format!("nmcli could not connect to {ssid}"));
                    }
                    return Ok(());
                }
                other => return Err(format!("cli {other:?}")),
            };
            request_as(actor, &req)?;
        }
        "approve_pending" => {
            let r = console().ok_or("daemon down")?;
            for p in r.status.pending {
                request_as("root", &Request::Approve { hash: p.approve, tty: true })?;
            }
        }
        "greeter_login" => {
            let uid = st.get("uid").and_then(T::as_integer).unwrap_or(1000);
            let user = user_for(&format!("user:{uid}"));
            let tty = 2 + (uid - 1000).clamp(0, 5);
            sh(&format!(
                "systemd-run --unit=gym-session-{uid} -p PAMName=login -p User={user} -p TTYPath=/dev/tty{tty} \
                 -p StandardInput=tty -p StandardOutput=tty sleep infinity; sleep 5"
            ));
        }
        "logout" => {
            let uid = st.get("uid").and_then(T::as_integer).unwrap_or(1000);
            sh(&format!(
                "systemctl stop gym-session-{uid}; loginctl terminate-user {}; true",
                user_for(&format!("user:{uid}"))
            ));
        }
        "fill_fs" => {
            let path = match get("fs").as_str() {
                "device:fs-nix" => "/nix/.rw-store",
                "device:fs-boot" => "/boot",
                "device:fs-journal" => "/var/lib/planarian",
                _ => "/",
            };
            // Leave the journal's reserved headroom at the boundary; nothing when full.
            let leave = if get("until") == "reserved-boundary" { 1 << 20 } else { 0 };
            sh(&format!(
                "avail=$(df --output=avail -B1 {path} | tail -1); n=$((avail - {leave})); \
                 [ $n -gt 0 ] && fallocate -l $n {path}/.gym-fill || dd if=/dev/zero of={path}/.gym-fill bs=1M 2>/dev/null; true"
            ));
        }
        "edit_owner_source" => {
            let root = cfg.owner.display().to_string();
            let path = get("path");
            if !sh(&format!("echo '# edited by the gym' >> {root}/{path}")) {
                return Err(format!("could not edit {root}/{path}"));
            }
            if st.get("tracked").and_then(T::as_bool) != Some(false) {
                sh(&format!("cd {root} && git add {path} 2>/dev/null; true"));
            }
            eprintln!("gym: edited {root}/{path}: {}", sh_out(&format!("git -C {root} status --short")).trim());
        }
        "out_of_band_rebuild" => {
            // The VM carries these as prebuilt specialisations (nix/tests/gym-vm.nix).
            let edit = get("edit");
            let name = if edit.contains("12 throwaway") {
                "throwaway"
            } else if edit.contains("sshd-tcp.timeout") {
                "weak-sshd-probe"
            } else if edit.contains("ExecStart=/bin/false") {
                "gym-web-false"
            } else {
                return Err(format!("out_of_band_rebuild {edit}"));
            };
            let activate = st.get("activate").and_then(T::as_bool).unwrap_or(false);
            let n = if name == "throwaway" { 12 } else { 1 };
            for k in 0..n {
                let spec = if name == "throwaway" { format!("throwaway{}", k % 2) } else { name.to_string() };
                sh(&format!(
                    "p=$(readlink -f /run/booted-system)/specialisation/{spec}; \
                     nix-env -p /nix/var/nix/profiles/system --set $(readlink -f $p)"
                ));
            }
            if activate {
                sh(&format!(
                    "$(readlink -f /run/booted-system)/specialisation/{name}/bin/switch-to-configuration test"
                ));
            }
        }
        "force_compaction" => {
            let cfg = config();
            let mut saved: Vec<Entry> = read_json(&PathBuf::from(RUN).join(SAVED)).unwrap_or_default();
            for e in segment(&cfg) {
                if saved.last().is_none_or(|l| l.seq < e.seq) {
                    saved.push(e);
                }
            }
            write_json(&PathBuf::from(RUN).join(SAVED), &saved);
            request_as("root", &Request::GymCompact)?
        }
        "advance_clock" => {
            let d = st.get("by").and_then(dur).ok_or("advance_clock")?;
            sh(&format!("timedatectl set-ntp false 2>/dev/null; date -s \"+{} seconds\"", d.0 / 1000));
        }
        "slow_backend" => {
            let d = st.get("delay").and_then(dur).unwrap_or(Millis::secs(120));
            let uncancellable = st.get("uncancellable").and_then(T::as_bool).unwrap_or(false);
            hooks_set(&get("call"), serde_json::json!({ "delay_secs": d.0 / 1000, "uncancellable": uncancellable }));
        }
        "withhold_reply" => {
            hooks_set(&get("call"), serde_json::json!({ "withhold": true }));
        }
        "backend_result" => {
            let key = match st.get("generation").and_then(T::as_str) {
                Some("revert_to") => {
                    let start: Start = read_json(&PathBuf::from(RUN).join("start.json")).unwrap_or_default();
                    format!("{}@{}", get("call"), start.base.0)
                }
                _ => get("call"),
            };
            hooks_set(&key, serde_json::json!({ "result": get("result") }));
        }
        other => return Err(format!("raw {other}")),
    }
    Ok(())
}

/// Gather what the run left behind.
fn evidence() -> Evidence {
    let cfg = config();
    let dir = PathBuf::from(RUN);
    let start: Start = read_json(&dir.join("start.json")).unwrap_or_default();
    let (ledger, journal_replays) = ledger(&cfg);
    let log: Vec<LogRecord> = std::fs::read_to_string(cfg.state_dir.join("log/executor.jsonl"))
        .unwrap_or_default()
        .lines()
        .skip(start.log_lines)
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let samples: Vec<Sample> = std::fs::read_to_string(dir.join("samples.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|smp: &Sample| smp.at >= start.at)
        .collect();
    let responses: Vec<Response> = std::fs::read_to_string(dir.join("responses.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let notices: Vec<String> = sh_out(&format!("journalctl -u planariad -o cat --since @{} --no-pager", start.unix))
        .lines()
        .filter_map(|l| l.strip_prefix("planariad: ").map(String::from))
        .chain(samples.iter().flat_map(|smp| smp.notices.clone()))
        .collect();
    let mut seen_status: BTreeMap<UnitId, BTreeSet<String>> = BTreeMap::new();
    let mut seen_incidents: BTreeMap<IncidentId, Incident> = BTreeMap::new();
    let mut first_incident_at: BTreeMap<UnitId, Timestamp> = BTreeMap::new();
    for smp in &samples {
        for (u, st) in &smp.status {
            seen_status.entry(u.clone()).or_default().insert(st.clone());
        }
        for i in &smp.incidents {
            first_incident_at.entry(i.target.clone()).or_insert(smp.at);
            seen_incidents.insert(i.id, i.clone());
        }
    }
    let final_report = console();
    let finals = final_report
        .as_ref()
        .map(statuses)
        .unwrap_or_else(|| samples.last().map(|smp| smp.status.clone()).unwrap_or_default());
    let open_incidents = final_report
        .as_ref()
        .map(|r| r.status.incidents.iter().map(|i| (i.target.clone(), i.clone())).collect())
        .unwrap_or_default();
    let mut restarts: BTreeMap<UnitId, i64> = BTreeMap::new();
    for r in &log {
        if let (Transition::RestartUnit(u), Submitted::Finished { .. }) = (&r.proposal.transition, &r.result) {
            *restarts.entry(u.clone()).or_default() += 1;
        }
    }
    // The whole journal history: what a forced compaction discarded, then
    // the current segment.
    let saved: Option<Vec<Entry>> = read_json(&dir.join(SAVED));
    let mut entries = saved.clone().unwrap_or_default();
    for x in segment(&cfg) {
        if entries.last().is_none_or(|l| l.seq < x.seq) {
            entries.push(x);
        }
    }
    let full_replay = saved.map(|_| {
        let mut l = Ledger::default();
        for x in &entries {
            let _ = l.apply(x.clone());
        }
        l
    });
    let mut timeline: BTreeMap<UnitId, Vec<(Timestamp, String)>> = BTreeMap::new();
    for smp in &samples {
        for (u, st) in &smp.status {
            let line = timeline.entry(u.clone()).or_default();
            if line.last().is_none_or(|(_, n)| n != st) {
                line.push((smp.at, st.clone()));
            }
        }
    }
    // The evaluated options a committed change set, as Planarian evaluated
    // them (the derived facts' config diff), on top of the base.
    let mut options: BTreeMap<String, Value> = BTreeMap::new();
    for r in &log {
        if let (Submitted::Finished { state: TxnState::Committed, .. }, Some(f)) = (&r.result, &r.facts)
            && let Some(d) = &f.config_diff
        {
            for (k, (_, new)) in d.options.iter() {
                match new {
                    Some(v) => options.insert(k.clone(), v.clone()),
                    None => options.remove(k),
                };
            }
        }
    }
    let backend = real(&cfg);
    let drivers: BTreeMap<UnitId, String> = start
        .pre_status
        .keys()
        .filter(|u| u.kind == UnitKind::Device)
        .filter_map(|u| Backends::inventory(&backend).bound_driver(u).ok().flatten().map(|d| (u.clone(), d.name)))
        .collect();
    let g = Backends::generations(&backend);
    let boot_entries = g.boot_entries().unwrap_or_default();
    let collected = start.boot_entries.iter().copied().filter(|x| !boot_entries.contains(x)).collect();
    let candidate = ledger
        .live
        .values()
        .filter_map(|t| t.txn.candidate.as_ref().map(|(c, _)| *c))
        .max()
        .or_else(|| boot_entries.iter().copied().filter(|x| *x > start.base).max());
    Evidence {
        current: g.current().unwrap_or_default(),
        boot_default: g.boot_default().unwrap_or_default(),
        base: start.base,
        candidate,
        boot_entries,
        collected,
        overrides_empty: g.read_overrides().map(|(o, _)| o.assignments.is_empty()).unwrap_or(true),
        ledger,
        journal_replays,
        log,
        pre_status: start.pre_status,
        finals,
        touched: start.touched,
        seen_status,
        seen_incidents,
        open_incidents,
        first_incident_at,
        start: start.at,
        restarts,
        notices,
        responses,
        entries: Some(entries.iter().filter(|x| x.at >= start.at).cloned().collect()),
        full_replay,
        effects: Some(effects(&entries, start.unix)),
        status_timeline: Some(timeline),
        drivers: Some(drivers),
        options: Some(options),
        probe_defs: Some((start.probe_defs, probe_defs(&cfg))),
        gc_roots: Some((start.gc_roots, build_roots())),
    }
}

/// Keys whose truth can change late in the window: judge them only at its end.
fn needs_full_window(post: &T) -> bool {
    post.as_table().is_some_and(|t| {
        t.keys().any(|k| {
            k.starts_with("no_")
                || matches!(k.as_str(), "others_unchanged" | "status_never" | "metrics" | "invariants" | "one_of")
        })
    })
}

/// Wait the window (ending early once the entry passes, if nothing in it
/// could still turn), then judge.
fn judge(entry: &T) -> i32 {
    let dir = PathBuf::from(RUN);
    let p: Plan = read_json(&dir.join("plan.json")).unwrap_or_else(|| plan(entry));
    let post = entry.get("required_post").cloned().unwrap_or(T::Table(Default::default()));
    let unsupported: Vec<String> = p.steps.iter().filter(|s| s.starts_with("unsupported")).cloned().collect();
    let full = needs_full_window(&post);
    let end = Instant::now() + Duration::from_secs(p.window_secs);
    let min = Instant::now() + Duration::from_secs(60.min(p.window_secs));
    let (mut v, mut e);
    loop {
        e = evidence();
        v = check::judge(&e, &post);
        let now = Instant::now();
        if now >= end || (!full && now >= min && v.failures.is_empty()) {
            break;
        }
        std::thread::sleep(Duration::from_secs(20));
    }
    sh("systemctl stop gym-sampler 2>/dev/null; true");
    // A run the sampler never saw proves nothing.
    if unsupported.is_empty() && e.seen_status.is_empty() {
        v.failures.push("harness: no status samples (gym-sampler)".into());
    }
    write_json(&dir.join("evidence.json"), &e);
    let result = if !unsupported.is_empty() {
        "UNSUPPORTED"
    } else if !v.failures.is_empty() {
        "FAIL"
    } else if !v.unchecked.is_empty() {
        "PARTIAL"
    } else {
        "PASS"
    };
    let notes: Vec<String> = unsupported
        .into_iter()
        .chain(v.failures.iter().cloned())
        .chain(v.unchecked.iter().map(|u| format!("unchecked: {u}")))
        .collect();
    let id = s(entry, "id");
    write_json(&dir.join("verdict.json"), &serde_json::json!({ "id": id, "result": result, "notes": notes }));
    println!("RESULT {result} {id}");
    for n in &notes {
        println!("  {n}");
    }
    0
}

pub fn main(args: &[String], entries: &[T]) -> i32 {
    let arg = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let sub = args.first().map(String::as_str).unwrap_or("");
    let entry = || -> T {
        let id = arg("--id").unwrap_or_else(|| die("--id"));
        entries.iter().find(|e| s(e, "id") == id).cloned().unwrap_or_else(|| die(&format!("no entry {id}")))
    };
    match sub {
        "plan" => {
            println!("{}", serde_json::to_string(&plan(&entry())).expect("serializes"));
            0
        }
        "begin" => {
            begin(&entry());
            0
        }
        "step" => {
            let i: usize = arg("--index").and_then(|i| i.parse().ok()).unwrap_or_else(|| die("--index"));
            step(&entry(), i, arg("--watched").as_deref());
            0
        }
        "request" => {
            request(&arg("--json").unwrap_or_else(|| die("--json")));
            0
        }
        "sample" => {
            sample();
            0
        }
        "judge" => judge(&entry()),
        "evidence" => {
            println!("{}", serde_json::to_string_pretty(&evidence()).expect("serializes"));
            0
        }
        other => die(&format!("unknown vm command {other:?}")),
    }
}
