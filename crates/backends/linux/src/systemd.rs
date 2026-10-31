//! `UnitBackend` over systemd (§8 systemd mapping).
//!
//! `active` → Active; `failed` → Failed(exit status); `inactive`/`dead` →
//! Bound; `activating`/`deactivating`/`reloading` → Transitioning; not
//! found → Absent; a systemctl error → Err (state reports Unknown).
//! User-scope units go through the user's manager (`--machine=<uid>@.host --user`).

use crate::admitted;
use crate::cmd::run;
use planarian_schema::{Ending, Observed, OpId, Outcome, Reason, Scope, Timestamp, UnitBackend, UnitId, UnitKind};
use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Duration;

pub const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
pub const JOB_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug)]
pub struct Systemd {
    txn_dir: PathBuf,
}

pub fn unit_name(id: &UnitId) -> String {
    let suffix = match id.kind {
        UnitKind::Service => "service",
        UnitKind::Target => "target",
        UnitKind::Device => "device",
    };
    if id.name.contains('.') { id.name.clone() } else { format!("{}.{suffix}", id.name) }
}

/// The `systemctl` prefix for a unit's manager.
pub fn systemctl(scope: &Scope) -> Vec<String> {
    match scope {
        Scope::System => vec!["systemctl".into()],
        Scope::User { uid, .. } => vec!["systemctl".into(), "--user".into(), format!("--machine={uid}@.host")],
    }
}

/// Parse `systemctl show` key=value output.
pub fn parse_show(text: &str) -> BTreeMap<String, String> {
    text.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// `Result`, `ExecMainCode` (1 exited, 2 killed, 3 dumped core) and
/// `ExecMainStatus` → how the main process last ended.
pub fn ending_from(props: &BTreeMap<String, String>) -> Option<Ending> {
    let get = |k: &str| props.get(k).map(String::as_str).unwrap_or("");
    let status: i32 = get("ExecMainStatus").parse().ok()?;
    if get("Result") == "oom-kill" {
        return Some(Ending::OomKill);
    }
    match get("ExecMainCode") {
        "1" => Some(Ending::Exited(status)),
        "2" | "3" => Some(Ending::Signal(status)),
        _ => None,
    }
}

/// A unit file that belongs to the generation: in the store (directly or
/// through /etc's links into it), written by a systemd generator, transient,
/// or none at all (scopes, slices, devices, mounts systemd makes up).
pub fn declared(fragment: &str) -> bool {
    // Transient units (`systemd-run`, Planarian's own operations) are made at
    // run time by root over D-Bus and do not persist: not a planted file.
    if fragment.is_empty()
        || fragment.starts_with("/nix/store/")
        || fragment.starts_with("/run/systemd/generator")
        || fragment.starts_with("/run/systemd/transient/")
    {
        return true;
    }
    std::fs::canonicalize(fragment).is_ok_and(|p| p.starts_with("/nix/store/"))
}

pub fn observed_from(props: &BTreeMap<String, String>, now: Timestamp) -> Observed {
    let get = |k: &str| props.get(k).map(String::as_str).unwrap_or("");
    if get("LoadState") == "not-found" {
        return Observed::Absent;
    }
    match get("ActiveState") {
        "active" => Observed::Active,
        "failed" => Observed::Failed(Reason::ExitCode(get("ExecMainStatus").parse().unwrap_or(1))),
        "inactive" | "dead" => Observed::Bound,
        "activating" | "deactivating" | "reloading" | "refreshing" | "maintenance" => {
            Observed::Transitioning { from: Box::new(Observed::Bound), since: now }
        }
        other => Observed::Unknown { since: now, reason: format!("ActiveState={other:?}") },
    }
}

impl Systemd {
    pub fn new(txn_dir: PathBuf) -> Systemd {
        Systemd { txn_dir }
    }

    fn ctl(&self, scope: &Scope, args: &[&str], timeout: Duration) -> crate::cmd::Output {
        let mut argv = systemctl(scope);
        argv.extend(args.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        run(&refs, timeout)
    }

    fn job(&self, verb: &str, id: &UnitId, op: &OpId) -> Outcome {
        if !admitted(&self.txn_dir, op) {
            return Outcome::fenced();
        }
        let o = self.ctl(&id.scope, &[verb, &unit_name(id)], JOB_TIMEOUT);
        if o.timed_out {
            Outcome::Unknown(format!("systemctl {verb} {} did not finish", unit_name(id)))
        } else if o.ok() {
            Outcome::Succeeded
        } else {
            Outcome::Failed(o.tail())
        }
    }
}

/// Admission counts every live launcher-created unit, including an in-flight
/// start. Four of the 32 slots remain reserved for root recovery administration.
/// Missing ownership metadata blocks admission until an administrator stops
/// the old unit; historical units cannot bypass per-caller admission.
fn agent_admission(text: &str, by: u32) -> Result<(), &'static str> {
    let mut total = 0;
    let mut own = 0;
    for block in text.split("\n\n").filter(|s| !s.trim().is_empty()) {
        let p = parse_show(block);
        let state = p.get("ActiveState").map(String::as_str).ok_or("incomplete agent inventory")?;
        if matches!(state, "inactive" | "failed") {
            continue;
        }
        total += 1;
        let owner = p
            .get("Description")
            .and_then(|s| s.strip_prefix("Planarian agent uid="))
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("unknown owner of live agent; administrator must stop it")?;
        if owner == by {
            own += 1;
        }
    }
    if total >= if by == 0 { 32 } else { 28 } {
        return Err("agent launch capacity reached (root recovery slots reserved)");
    }
    if own >= if by == 0 { 8 } else { 4 } {
        return Err("this caller's agent launch capacity reached");
    }
    Ok(())
}

fn agent_argv(name: &str, argv: &[String], by: u32) -> Vec<String> {
    let mut a = vec![
        "systemd-run".into(),
        format!("--unit={}", planarian_schema::backend::agent_unit(name)),
        format!("--description=Planarian agent uid={by}"),
        "--collect".into(),
        "--quiet".into(),
        "--service-type=exec".into(),
        "--property=DynamicUser=yes".into(),
        "--property=NoNewPrivileges=yes".into(),
        "--property=Slice=planarian-agents.slice".into(),
        "--property=BindsTo=planarian-ready.target".into(),
        "--property=After=planarian-ready.target".into(),
        "--property=Requisite=planarian-ready.target".into(),
        "--property=ConditionPathExistsGlob=!/run/planarian/failed-*".into(),
        "--property=TasksMax=64".into(),
        "--property=MemoryMax=256M".into(),
        "--property=CPUQuota=50%".into(),
        "--property=KillMode=control-group".into(),
        "--property=TimeoutStopSec=5s".into(),
        "--".into(),
    ];
    a.extend(argv.iter().cloned());
    a
}

fn now() -> Timestamp {
    Timestamp(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
    )
}

impl UnitBackend for Systemd {
    fn observe(&self, id: &UnitId) -> Result<Observed, Outcome> {
        let name = unit_name(id);
        let o = self.ctl(
            &id.scope,
            &["show", "--property=LoadState,ActiveState,SubState,ExecMainStatus", &name],
            QUERY_TIMEOUT,
        );
        if !o.ok() {
            // A user manager that isn't running means the unit isn't either.
            if matches!(id.scope, Scope::User { .. }) {
                return Ok(Observed::Absent);
            }
            return Err(Outcome::Failed(o.tail()));
        }
        Ok(observed_from(&parse_show(&o.stdout), now()))
    }

    fn foreign_units(&self) -> Vec<String> {
        let o = self.ctl(
            &Scope::System,
            &["list-units", "--state=active", "--no-legend", "--plain", "--all"],
            QUERY_TIMEOUT,
        );
        if !o.ok() {
            return vec![];
        }
        let mut out = vec![];
        for name in o.stdout.lines().filter_map(|l| l.split_whitespace().next()) {
            let s = self.ctl(&Scope::System, &["show", "--property=FragmentPath", "--value", name], QUERY_TIMEOUT);
            let frag = s.stdout.trim();
            if s.ok() && !declared(frag) {
                out.push(format!("{name} ({frag})"));
            }
        }
        out
    }

    fn ended_by(&self, id: &UnitId) -> Option<Ending> {
        let o = self.ctl(
            &id.scope,
            &["show", "--property=Result,ExecMainCode,ExecMainStatus", &unit_name(id)],
            QUERY_TIMEOUT,
        );
        o.ok().then(|| ending_from(&parse_show(&o.stdout))).flatten()
    }

    fn auto_restarts(&self, id: &UnitId) -> Option<u32> {
        let o = self.ctl(&id.scope, &["show", "--property=NRestarts", "--value", &unit_name(id)], QUERY_TIMEOUT);
        o.ok().then(|| o.stdout.trim().parse().ok()).flatten()
    }

    fn list(&self) -> Result<Vec<UnitId>, Outcome> {
        let o = self.ctl(
            &Scope::System,
            &["list-units", "--type=service", "--all", "--plain", "--no-legend"],
            QUERY_TIMEOUT,
        );
        if !o.ok() {
            return Err(Outcome::Failed(o.tail()));
        }
        Ok(o.stdout
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter_map(|n| n.strip_suffix(".service"))
            .map(UnitId::service)
            .collect())
    }

    fn start_agent(
        &self,
        name: &str,
        argv: &[String],
        by: u32,
    ) -> Result<planarian_schema::backend::InstanceId, Outcome> {
        if !planarian_schema::backend::valid_agent_name(name)
            || argv.is_empty()
            || argv.len() > 64
            || argv.iter().map(String::len).sum::<usize>() > 16384
        {
            return Err(Outcome::Failed("invalid or oversized agent command".into()));
        }
        // The same cross-process lock covers admission, start and identity
        // readback; no unbounded launcher wait queue is created.
        if let Err(e) = std::fs::create_dir_all(&self.txn_dir) {
            return Err(Outcome::Failed(format!("agent admission directory: {e}")));
        }
        let lock = match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.txn_dir.join("agent-launch.lock"))
        {
            Ok(f) => f,
            Err(e) => return Err(Outcome::Failed(format!("agent admission lock: {e}"))),
        };
        if lock.try_lock().is_err() {
            return Err(Outcome::Failed("agent admission busy; retry later".into()));
        }
        let ready = self.ctl(&Scope::System, &["is-active", "--quiet", "planarian-ready.target"], QUERY_TIMEOUT);
        if !ready.ok() {
            return Err(Outcome::Failed("Planarian is not ready for agents".into()));
        }
        let live = self.ctl(
            &Scope::System,
            &["show", "--property=Id,Description,ActiveState", "planarian-agent-*.service"],
            QUERY_TIMEOUT,
        );
        if !live.ok() {
            return Err(Outcome::Failed(format!("cannot establish agent admission: {}", live.tail())));
        }
        if let Err(reason) = agent_admission(&live.stdout, by) {
            return Err(Outcome::Failed(reason.into()));
        }
        let a = agent_argv(name, argv, by);
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        let o = run(&refs, QUERY_TIMEOUT);
        if o.timed_out {
            return Err(Outcome::Unknown("agent start was accepted or lost; inspect its systemd unit".into()));
        }
        if !o.ok() {
            return Err(Outcome::Failed(o.tail()));
        }
        let unit = format!("{}.service", planarian_schema::backend::agent_unit(name));
        let id = self.ctl(&Scope::System, &["show", "-p", "InvocationID", "--value", &unit], QUERY_TIMEOUT);
        if !id.ok() {
            return Err(Outcome::Unknown(format!("{unit} started, but its instance query failed")));
        }
        planarian_schema::backend::InstanceId::parse(id.stdout.trim().as_bytes())
            .ok_or_else(|| Outcome::Unknown(format!("{unit} started, but it has no InvocationID")))
    }

    fn agent_running(&self, name: &str) -> bool {
        let unit = format!("{}.service", planarian_schema::backend::agent_unit(name));
        let o = self.ctl(&Scope::System, &["show", "-p", "ActiveState", "--value", &unit], QUERY_TIMEOUT);
        o.ok() && matches!(o.stdout.trim(), "active" | "activating" | "reloading" | "deactivating")
    }

    fn restart(&self, id: &UnitId, op: &OpId) -> Outcome {
        self.job("restart", id, op)
    }

    fn stop(&self, id: &UnitId, op: &OpId) -> Outcome {
        self.job("stop", id, op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_units_are_externally_supervised_and_bounded() {
        let a = agent_argv("helper", &["sleep".into(), "infinity".into()], 1000);
        for property in [
            "BindsTo=planarian-ready.target",
            "After=planarian-ready.target",
            "Requisite=planarian-ready.target",
            "ConditionPathExistsGlob=!/run/planarian/failed-*",
            "Slice=planarian-agents.slice",
            "TasksMax=64",
            "MemoryMax=256M",
            "CPUQuota=50%",
            "KillMode=control-group",
        ] {
            assert!(a.contains(&format!("--property={property}")), "{property}");
        }
        assert!(a.contains(&"--description=Planarian agent uid=1000".into()));
        assert!(a.contains(&"--property=DynamicUser=yes".into()));
    }

    #[test]
    fn admission_counts_starts_and_preserves_root_capacity() {
        let block = |uid, state| {
            format!("Id=planarian-agent-helper.service\nDescription=Planarian agent uid={uid}\nActiveState={state}\n")
        };
        let four =
            [block(1000, "active"), block(1000, "activating"), block(1000, "deactivating"), block(1000, "active")]
                .join("\n");
        assert!(agent_admission(&four, 1000).is_err());
        assert!(agent_admission(&four, 1001).is_ok());
        let full = (1000..1028).map(|uid| block(uid, "active")).collect::<Vec<_>>().join("\n");
        assert!(agent_admission(&full, 2000).is_err());
        assert!(agent_admission(&full, 0).is_ok());
        let all = format!("{full}\n{}", (2000..2004).map(|uid| block(uid, "active")).collect::<Vec<_>>().join("\n"));
        assert!(agent_admission(&all, 0).is_err());
        assert!(agent_admission(&block(1000, "inactive"), 1000).is_ok());
        assert!(agent_admission("Id=planarian-agent-old.service\nActiveState=active\n", 1000).is_err());
        assert!(agent_admission("Id=planarian-agent-broken.service\n", 0).is_err());
    }

    #[test]
    fn mapping() {
        let o = |s: &str| observed_from(&parse_show(s), Timestamp(0));
        assert_eq!(o("LoadState=loaded\nActiveState=active\nSubState=running\nExecMainStatus=0\n"), Observed::Active);
        assert!(
            declared("") && declared("/nix/store/abc-unit/x.service") && declared("/run/systemd/generator/a.mount")
        );
        assert!(!declared("/etc/systemd/system/planted-by-hand-0000.service"));
        assert!(declared("/run/systemd/transient/run-u12.service"));
        let e = |t: &str| ending_from(&parse_show(t));
        assert_eq!(e("Result=signal\nExecMainCode=2\nExecMainStatus=9\n"), Some(Ending::Signal(9)));
        assert_eq!(e("Result=success\nExecMainCode=2\nExecMainStatus=15\n"), Some(Ending::Signal(15)));
        assert_eq!(e("Result=core-dump\nExecMainCode=3\nExecMainStatus=11\n"), Some(Ending::Signal(11)));
        assert_eq!(e("Result=oom-kill\nExecMainCode=2\nExecMainStatus=9\n"), Some(Ending::OomKill));
        assert_eq!(e("Result=exit-code\nExecMainCode=1\nExecMainStatus=3\n"), Some(Ending::Exited(3)));
        assert_eq!(
            o("LoadState=loaded\nActiveState=failed\nExecMainStatus=137\n"),
            Observed::Failed(Reason::ExitCode(137))
        );
        assert_eq!(o("LoadState=loaded\nActiveState=inactive\n"), Observed::Bound);
        assert_eq!(o("LoadState=not-found\nActiveState=inactive\n"), Observed::Absent);
        assert!(matches!(o("LoadState=loaded\nActiveState=activating\n"), Observed::Transitioning { .. }));
        assert_eq!(unit_name(&UnitId::service("sshd")), "sshd.service");
        assert_eq!(unit_name(&UnitId::target("graphical-session")), "graphical-session.target");
        assert_eq!(
            systemctl(&Scope::User { uid: 1000, session: None }),
            ["systemctl", "--user", "--machine=1000@.host"]
        );
    }
}
