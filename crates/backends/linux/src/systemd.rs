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
