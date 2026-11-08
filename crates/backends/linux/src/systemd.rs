//! `UnitBackend` over systemd (§8 systemd mapping).
//!
//! `active` → Active; `failed` → Failed(exit status); `inactive`/`dead` →
//! Bound; `activating`/`deactivating`/`reloading` → Transitioning; not
//! found → Absent; a systemctl error → Err (state reports Unknown).
//! User-scope units go through the user's manager (`--machine=<uid>@.host --user`).

use crate::admitted;
use crate::cmd::run;
use planarian_schema::{
    Ending, JobId, Millis, Observed, OpId, Outcome, Reason, Scope, Timestamp, UnitBackend, UnitId, UnitKind,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
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

/// `systemctl show --property=Id,… a.service b.service`: one block of
/// `Key=value` lines per unit, blocks separated by a blank line, in no
/// promised order, so matched by `Id`. Per requested name: its properties,
/// or why they are not known: absent from the output, named by more than one
/// block, or a block that cannot be read (no `Id`) is an error, never a
/// guess.
pub fn parse_show_many(text: &str, names: &[String]) -> Vec<Result<BTreeMap<String, String>, String>> {
    let mut by_id: BTreeMap<String, Vec<BTreeMap<String, String>>> = BTreeMap::new();
    let mut unreadable = 0;
    for block in text.split("\n\n").map(str::trim).filter(|b| !b.is_empty()) {
        let props = parse_show(block);
        match props.get("Id") {
            Some(id) if !id.is_empty() => by_id.entry(id.clone()).or_default().push(props),
            _ => unreadable += 1,
        }
    }
    names
        .iter()
        .map(|n| match by_id.get(n).map(Vec::as_slice) {
            Some([one]) => Ok(one.clone()),
            Some(_) => Err(format!("{n}: more than one block in systemctl show's output")),
            None if unreadable > 0 => Err(format!("{n}: not in the output (a block had no Id)")),
            None => Err(format!("{n}: not in systemctl show's output")),
        })
        .collect()
}

/// `observe_many` from the command's result: a failed command or a timeout
/// is an error for every unit; otherwise each as `observe` and `ended_by`
/// would give it (how it ended only for a unit that is not running).
pub fn observe_many_from(
    names: &[String],
    ok: bool,
    stdout: &str,
    tail: &str,
    now: Timestamp,
) -> Vec<(Result<Observed, Outcome>, Option<Ending>)> {
    if !ok {
        return names.iter().map(|_| (Err(Outcome::Failed(tail.to_string())), None)).collect();
    }
    parse_show_many(stdout, names)
        .into_iter()
        .map(|r| match r {
            Err(why) => (Err(Outcome::Unknown(why)), None),
            Ok(props) => {
                let observed = observed_from(&props, now);
                let ended = matches!(observed, Observed::Absent | Observed::Bound | Observed::Detected)
                    .then(|| ending_from(&props))
                    .flatten();
                (Ok(observed), ended)
            }
        })
        .collect()
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
    /// §12d: netwatch's footprints in `/run/planarian/footprint`, read with its
    /// own fail-closed rules, at the boot clock's now.
    fn protecting(&self, tools: &[UnitId]) -> Result<BTreeSet<UnitId>, Outcome> {
        let now = planarian_backend_netwatch::host::boottime_secs()
            .ok_or_else(|| Outcome::Unknown("no /proc/uptime".into()))?;
        Ok(planarian_backend_netwatch::read(std::path::Path::new(planarian_backend_netwatch::DIR))
            .protecting(tools, now))
    }
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

    fn observe_many(&self, ids: &[UnitId]) -> Vec<(Result<Observed, Outcome>, Option<Ending>)> {
        // One command for system units; a user manager's units one at a time.
        if ids.is_empty() || ids.iter().any(|u| u.scope != Scope::System) {
            return ids
                .iter()
                .map(|u| {
                    let o = self.observe(u);
                    let ended = matches!(o, Ok(Observed::Absent | Observed::Bound | Observed::Detected))
                        .then(|| self.ended_by(u))
                        .flatten();
                    (o, ended)
                })
                .collect();
        }
        let names: Vec<String> = ids.iter().map(unit_name).collect();
        let mut args: Vec<&str> =
            vec!["show", "--property=Id,LoadState,ActiveState,SubState,ExecMainStatus,Result,ExecMainCode"];
        args.extend(names.iter().map(String::as_str));
        let o = self.ctl(&Scope::System, &args, QUERY_TIMEOUT);
        observe_many_from(&names, o.ok(), &o.stdout, &o.tail(), now())
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

    fn queued_jobs(&self) -> Result<Vec<JobId>, Outcome> {
        let o = self.ctl(&Scope::System, &["list-jobs", "--no-legend", "--plain"], QUERY_TIMEOUT);
        if !o.ok() {
            return Err(Outcome::Unknown(format!("systemctl list-jobs: {}", o.tail())));
        }
        parse_list_jobs(&o.stdout).map_err(|e| Outcome::Unknown(format!("systemctl list-jobs: {e}")))
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
        limits: &planarian_schema::backend::AgentLimits,
    ) -> Result<planarian_schema::backend::InstanceId, Outcome> {
        if !planarian_schema::backend::valid_agent_name(name) {
            return Err(Outcome::Failed(format!("bad agent name {name:?}")));
        }
        // I20: no agent starts while a failure class is raised.
        if posture_failed(Path::new(FAILED_DIR)) {
            return Err(Outcome::Failed("a failure posture is engaged: agents do not start".into()));
        }
        let unit = format!("--unit={}", planarian_schema::backend::agent_unit(name));
        let slice = format!("--slice={}", planarian_schema::backend::AGENTS_SLICE);
        let tasks = format!("--property=TasksMax={}", limits.tasks_max);
        let memory = format!("--property=MemoryMax={}", limits.memory_max);
        // A uid of its own (DynamicUser), so it is never the person who
        // started it (§11); no privilege it could gain by exec. In the
        // agents' slice, which the posture stops as a whole, after and
        // requiring planarian-ready.target, and conditioned on no failure
        // class being raised (§12d, I20, R05).
        let mut a: Vec<&str> = vec![
            "systemd-run",
            &unit,
            &slice,
            "--collect",
            "--quiet",
            "--property=DynamicUser=yes",
            "--property=NoNewPrivileges=yes",
            "--property=Requires=planarian-ready.target",
            "--property=After=planarian-ready.target",
            "--property=ConditionPathExistsGlob=!/run/planarian/failed-*",
            &tasks,
            &memory,
            "--",
        ];
        a.extend(argv.iter().map(String::as_str));
        let o = run(&a, JOB_TIMEOUT);
        if !o.ok() {
            return Err(Outcome::Failed(o.tail()));
        }
        // The instance that started, read back from systemd (I24).
        let unit = format!("{}.service", planarian_schema::backend::agent_unit(name));
        let id = run(&["systemctl", "show", "-p", "InvocationID", "--value", &unit], QUERY_TIMEOUT);
        planarian_schema::backend::InstanceId::parse(id.stdout.trim().as_bytes())
            .ok_or_else(|| Outcome::Unknown(format!("{unit} started, but it has no InvocationID")))
    }

    fn agent_running(&self, name: &str) -> bool {
        let unit = format!("{}.service", planarian_schema::backend::agent_unit(name));
        let o = run(&["systemctl", "show", "-p", "ActiveState", "--value", &unit], QUERY_TIMEOUT);
        matches!(o.stdout.trim(), "active" | "activating" | "reloading" | "deactivating")
    }

    fn restart(&self, id: &UnitId, op: &OpId) -> Outcome {
        self.job("restart", id, op)
    }

    fn stop(&self, id: &UnitId, op: &OpId) -> Outcome {
        self.job("stop", id, op)
    }
    // §12d: the hold, a failure posture response (crate::hold).
    fn hold(&self, unit: &UnitId, wait: Millis) -> Outcome {
        crate::hold::apply(unit, ms(wait))
    }
    fn lift_hold(&self, unit: &UnitId, wait: Millis) -> Outcome {
        crate::hold::lift(unit, ms(wait))
    }
    fn held(&self) -> Result<std::collections::BTreeSet<UnitId>, Outcome> {
        crate::hold::held_in(Path::new(crate::hold::HOLD_DIR))
    }
    fn release_hold(&self, unit: &UnitId, until: Option<Timestamp>, wait: Millis) -> Outcome {
        crate::hold::release_in(Path::new(crate::hold::RELEASED_DIR), unit, until, ms(wait))
    }
    fn timed_release_active(&self, unit: &UnitId, until: Timestamp) -> Result<bool, Outcome> {
        crate::hold::timed_release_active_in(Path::new(crate::hold::RELEASED_DIR), unit, until)
    }
    fn end_release(&self, unit: &UnitId) -> Outcome {
        crate::hold::end_release_in(Path::new(crate::hold::RELEASED_DIR), unit)
    }
    fn hold_table_present(&self, wait: Millis) -> Result<bool, Outcome> {
        crate::hold::table_present(ms(wait))
    }
    fn reapply_hold(&self, unit: &UnitId, wait: Millis) -> Outcome {
        crate::hold::reapply(unit, ms(wait))
    }
}

fn ms(m: Millis) -> std::time::Duration {
    std::time::Duration::from_millis(m.0)
}

/// Where the posture marks a raised failure class (`failed-<class>`).
const FAILED_DIR: &str = "/run/planarian";

/// `systemctl list-jobs --no-legend --plain`: one line per job, `JOB UNIT
/// TYPE STATE` (e.g. `5731 gym-web.service stop running`); nothing at all
/// when the queue is empty. A line that is not that shape is an error, never
/// skipped (an unreadable queue must not read as an empty one).
fn parse_list_jobs(out: &str) -> Result<Vec<JobId>, String> {
    let mut jobs = vec![];
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.as_slice() {
            [id, unit, _type, _state] if id.parse::<u64>().is_ok() && unit.contains('.') => {
                jobs.push(JobId(format!("{id} {unit}")));
            }
            _ => return Err(format!("unreadable line {line:?}")),
        }
    }
    Ok(jobs)
}

/// A failure class is raised: `failed-*` exists in `dir`.
fn posture_failed(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("failed-")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R05, I20: the launcher refuses while a failure class is raised.
    #[test]
    fn no_agent_starts_while_a_failure_class_is_raised() {
        let d = std::env::temp_dir().join(format!("planarian-posture-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(!posture_failed(&d));
        std::fs::write(d.join("alarm"), "").unwrap();
        assert!(!posture_failed(&d), "only failed-<class> counts");
        std::fs::write(d.join("failed-crashed"), "").unwrap();
        assert!(posture_failed(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn list_jobs_output_is_parsed_and_an_unreadable_line_is_an_error() {
        let sample = "  5731 gym-web.service stop running\n  5732 gym-web.service start waiting\n 5733 multi-user.target start waiting\n";
        let jobs = parse_list_jobs(sample).unwrap();
        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[0], JobId("5731 gym-web.service".into()));
        assert_eq!(parse_list_jobs("").unwrap(), vec![], "an empty queue prints nothing");
        assert_eq!(parse_list_jobs("\n\n").unwrap(), vec![]);
        for bad in ["No jobs running.", "3 jobs listed.", "x gym-web.service stop running", "5731 gym-web.service stop"]
        {
            assert!(parse_list_jobs(bad).is_err(), "{bad}");
        }
    }

    mod list_jobs_props {
        use super::super::parse_list_jobs;
        use proptest::prelude::*;

        fn good() -> impl Strategy<Value = String> {
            (
                1u64..1_000_000,
                "[a-z][a-z0-9@-]{0,12}",
                "(service|target|socket|mount)",
                "(start|stop|restart|reload)",
                "(running|waiting)",
            )
                .prop_map(|(id, n, k, t, st)| format!("{id} {n}.{k} {t} {st}"))
        }
        /// Anything `parse_list_jobs` must refuse: wrong field count, a
        /// non-numeric id, a unit without a '.', a legend line.
        fn bad() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("No jobs running.".to_string()),
                (1u32..99).prop_map(|n| format!("{n} jobs listed.")),
                "[a-z]{1,6} [a-z]{1,6}\\.service stop running",
                (1u32..99999).prop_map(|n| format!("{n} gym-web.service stop")),
                (1u32..99999).prop_map(|n| format!("{n} gym-web.service stop running extra")),
                (1u32..99999).prop_map(|n| format!("{n} gymweb stop running")),
            ]
        }
        fn pad() -> impl Strategy<Value = String> {
            "[ \\t]{0,4}"
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 200, failure_persistence: None, ..ProptestConfig::default() })]

            /// Well-formed lines, padded any way, with blank lines between,
            /// parse to exactly that many jobs, in order.
            #[test]
            fn well_formed_lines_parse_to_exactly_that_many_jobs(
                lines in prop::collection::vec((good(), pad(), pad(), 0usize..3), 0..8),
            ) {
                let text: String = lines
                    .iter()
                    .map(|(l, a, b, blank)| format!("{a}{l}{b}\n{}", "\n".repeat(*blank)))
                    .collect();
                let jobs = parse_list_jobs(&text).unwrap();
                prop_assert_eq!(jobs.len(), lines.len());
                for (j, (l, ..)) in jobs.iter().zip(&lines) {
                    let mut f = l.split_whitespace();
                    prop_assert_eq!(&j.0, &format!("{} {}", f.next().unwrap(), f.next().unwrap()));
                }
            }

            /// One unreadable line anywhere makes the whole parse an Err:
            /// an unreadable queue never reads as a shorter or empty one.
            #[test]
            fn one_unreadable_line_makes_the_parse_an_error(
                before in prop::collection::vec(good(), 0..4),
                after in prop::collection::vec(good(), 0..4),
                bad in bad(),
            ) {
                let text = before.iter().chain([&bad]).chain(&after).map(|l| format!("{l}\n")).collect::<String>();
                prop_assert!(parse_list_jobs(&text).is_err(), "{text:?}");
            }
        }
    }

    /// A multi-unit `systemctl show` (three units, properties in systemd's
    /// own order, a blank line between): matched by Id, whatever the order.
    const SHOW_MANY: &str = "Id=sshd.service
LoadState=loaded
ActiveState=active
SubState=running
Result=success
ExecMainCode=0
ExecMainStatus=0

Id=wg-quick-wg0.service
LoadState=loaded
ActiveState=inactive
SubState=dead
Result=success
ExecMainCode=2
ExecMainStatus=15

Id=modprobe@dm_mod.service
LoadState=loaded
ActiveState=inactive
SubState=dead
Result=success
ExecMainCode=1
ExecMainStatus=0
";

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_multi_unit_show_is_matched_by_id_in_any_order() {
        let n = names(&["modprobe@dm_mod.service", "sshd.service", "wg-quick-wg0.service"]);
        let got = observe_many_from(&n, true, SHOW_MANY, "", Timestamp(0));
        assert_eq!(got[0], (Ok(Observed::Bound), Some(Ending::Exited(0))), "a finished oneshot");
        assert_eq!(got[1], (Ok(Observed::Active), None), "running: how it ended is not asked");
        assert_eq!(got[2], (Ok(Observed::Bound), Some(Ending::Signal(15))), "stopped by SIGTERM");
    }

    /// Rule 21: what cannot be matched is an error for that unit, never Absent.
    #[test]
    fn a_missing_duplicate_or_unreadable_block_is_an_error_for_that_unit() {
        let n = names(&["sshd.service", "absent.service"]);
        let got = observe_many_from(&n, true, SHOW_MANY, "", Timestamp(0));
        assert!(matches!(got[0].0, Ok(Observed::Active)));
        assert!(matches!(&got[1].0, Err(Outcome::Unknown(w)) if w.contains("absent.service")), "{:?}", got[1]);
        let dup = format!("{SHOW_MANY}\nId=sshd.service\nLoadState=loaded\nActiveState=failed\n");
        let got = observe_many_from(&names(&["sshd.service", "wg-quick-wg0.service"]), true, &dup, "", Timestamp(0));
        assert!(matches!(&got[0].0, Err(Outcome::Unknown(w)) if w.contains("more than one")), "{:?}", got[0]);
        assert!(got[1].0.is_ok(), "the others are unaffected");
        let junk = format!("{SHOW_MANY}\nLoadState=loaded\nActiveState=active\n");
        let got = observe_many_from(&names(&["sshd.service", "gone.service"]), true, &junk, "", Timestamp(0));
        assert!(got[0].0.is_ok());
        assert!(matches!(&got[1].0, Err(Outcome::Unknown(w)) if w.contains("no Id")), "{:?}", got[1]);
    }

    #[test]
    fn a_failed_command_is_an_error_for_every_unit() {
        let n = names(&["sshd.service", "wg-quick-wg0.service"]);
        let got = observe_many_from(&n, false, "", "Failed to connect to bus", Timestamp(0));
        assert!(got.iter().all(|(o, e)| matches!(o, Err(Outcome::Failed(_))) && e.is_none()), "{got:?}");
        // The same output with an empty stdout and ok is not a pass.
        let got = observe_many_from(&n, true, "", "", Timestamp(0));
        assert!(got.iter().all(|(o, _)| o.is_err()), "{got:?}");
    }

    #[test]
    fn a_not_found_unit_is_absent_only_because_systemd_said_so() {
        let text = "Id=ghost.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n";
        let got = observe_many_from(&names(&["ghost.service"]), true, text, "", Timestamp(0));
        assert_eq!(got[0], (Ok(Observed::Absent), None));
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
