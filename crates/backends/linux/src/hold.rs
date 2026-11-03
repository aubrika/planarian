//! §12d *Network security fails closed*: the hold, as lane-nix's
//! `planarian-hold@<unit>.service` (nix/posture.nix) builds it. This module
//! only starts and stops that unit, reads which holds are in place, and
//! writes the release marker the hold script honours:
//!
//! - apply: `systemctl start planarian-hold@<unit>.service` (idempotent;
//!   systemd's `OnFailure=` starts the same unit on a crash or kill);
//! - lift: `systemctl stop` of it;
//! - reapply: `systemctl reload` of it (`ExecReload`: rebuild the table,
//!   never lift);
//! - state: `/run/planarian/hold/<unit>` exists while a hold is in place;
//! - release: `/run/planarian/hold-released/<unit>` holds `boot` (until the
//!   next boot), or `<unix> <boottime>`: the expiry in Unix seconds and the
//!   same deadline in `CLOCK_BOOTTIME` seconds. The script takes whichever
//!   passes first, so a stepped wall clock cannot lengthen a release; an
//!   unparsable or past one is expired (the script holds).
//!
//! `<unit>` is the systemd unit name without `.service`. A failure posture
//! response, not a transition (docs/bypasses.md): no `Prepared`, no lease,
//! no op tag. It only ever restricts traffic, except `lift`, which the
//! daemon calls only once the unit is Running and its Readiness probes pass,
//! or on an attested release.

use crate::cmd::{Output, run};
use crate::systemd::unit_name;
use planarian_schema::{Outcome, Timestamp, UnitId};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const HOLD_DIR: &str = "/run/planarian/hold";
pub const RELEASED_DIR: &str = "/run/planarian/hold-released";
const TIMEOUT: Duration = Duration::from_secs(30);

/// The hold's instance name: the unit's systemd name without `.service`.
pub fn instance(unit: &UnitId) -> String {
    let n = unit_name(unit);
    n.strip_suffix(".service").map(str::to_string).unwrap_or(n)
}

fn hold_unit(unit: &UnitId) -> String {
    format!("planarian-hold@{}.service", instance(unit))
}

fn outcome(verb: &str, unit: &UnitId, o: Output) -> Outcome {
    if o.timed_out {
        Outcome::Unknown(format!("systemctl {verb} {} did not finish", hold_unit(unit)))
    } else if o.ok() {
        Outcome::Succeeded
    } else {
        Outcome::Failed(o.tail())
    }
}

/// Start the unit's hold, waiting at most `wait` (and never past TIMEOUT).
/// Past it the `systemctl` client is killed and the result is `Unknown`;
/// systemd's start job is the manager's, not the client's, and goes on, so
/// the hold may still land.
pub fn apply(unit: &UnitId, wait: Duration) -> Outcome {
    outcome("start", unit, run(&["systemctl", "start", &hold_unit(unit)], wait.min(TIMEOUT)))
}

/// Rebuild the hold's table in place (`ExecReload` runs the script's
/// `reapply`). A reload never lifts the hold, where a restart would run
/// `ExecStop` (`lift`) first and let traffic through for a moment.
///
/// `systemctl reload` fails on an inactive unit, so one not active (the hold
/// was stopped, or never started on this boot) is started instead.
pub fn reapply(unit: &UnitId, wait: Duration) -> Outcome {
    reapply_with(unit, |argv| run(argv, wait.min(TIMEOUT)))
}

fn reapply_with(unit: &UnitId, run: impl Fn(&[&str]) -> Output) -> Outcome {
    let name = hold_unit(unit);
    let active = run(&["systemctl", "is-active", "--quiet", &name]);
    if active.timed_out {
        return Outcome::Unknown(format!("systemctl is-active {name} did not finish"));
    }
    let verb = if active.ok() { "reload" } else { "start" };
    outcome(verb, unit, run(&["systemctl", verb, &name]))
}

/// The hold script's table (`table inet planarian-hold`).
pub fn table_present(wait: Duration) -> Result<bool, Outcome> {
    let o = run(&["nft", "list", "table", "inet", "planarian-hold"], wait.min(TIMEOUT));
    if o.ok() {
        Ok(true)
    } else if !o.timed_out && o.stderr.contains("No such file or directory") {
        Ok(false)
    } else {
        Err(Outcome::Failed(o.tail()))
    }
}

pub fn lift(unit: &UnitId, wait: Duration) -> Outcome {
    outcome("stop", unit, run(&["systemctl", "stop", &hold_unit(unit)], wait.min(TIMEOUT)))
}

/// The units held now, from the hold script's state directory. A directory
/// that cannot be read (other than absent: no hold was ever applied) is an
/// error, never "none" (rule 21).
pub fn held_in(dir: &Path) -> Result<BTreeSet<UnitId>, Outcome> {
    match std::fs::read_dir(dir) {
        Ok(entries) => Ok(entries
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .map(|n| UnitId::service(&n))
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(Outcome::Failed(format!("{}: {e}", dir.display()))),
    }
}

/// The marker's content: `boot`, or the expiry in Unix seconds and the same
/// deadline on the boot clock, `boottime_now + (until - wall_now)`, both
/// truncated to seconds. A deadline already past saturates to `boottime_now`
/// or below: expired.
pub fn marker(until: Option<Timestamp>, wall_now: Timestamp, boottime_now_s: u64) -> String {
    match until {
        Some(t) => {
            let left = (t.0 / 1000).saturating_sub(wall_now.0 / 1000);
            format!("{} {}\n", t.0 / 1000, boottime_now_s.saturating_add(left))
        }
        None => "boot\n".into(),
    }
}

fn boottime_s() -> u64 {
    rustix::time::clock_gettime(rustix::time::ClockId::Boottime).tv_sec as u64
}

fn wall_now() -> Timestamp {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    Timestamp(d.as_millis() as u64)
}

fn marker_path(dir: &Path, unit: &UnitId) -> PathBuf {
    dir.join(instance(unit))
}

/// Write the release marker, then lift the hold. The marker comes first so
/// that a failure racing the lift does not re-apply the hold.
pub fn release_in(dir: &Path, unit: &UnitId, until: Option<Timestamp>, wait: Duration) -> Outcome {
    if let Err(e) = std::fs::create_dir_all(dir)
        .and_then(|_| std::fs::write(marker_path(dir, unit), marker(until, wall_now(), boottime_s())))
    {
        return Outcome::Failed(format!("{}: {e}", dir.display()));
    }
    lift(unit, wait)
}

pub fn end_release_in(dir: &Path, unit: &UnitId) -> Outcome {
    match std::fs::remove_file(marker_path(dir, unit)) {
        Ok(()) => Outcome::Succeeded,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Succeeded,
        Err(e) => Outcome::Failed(format!("{}: {e}", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_drop_the_service_suffix() {
        assert_eq!(instance(&UnitId::service("wireguard-gym")), "wireguard-gym");
        assert_eq!(hold_unit(&UnitId::service("wg-quick-wg0")), "planarian-hold@wg-quick-wg0.service");
        // A template instance keeps its `@`, as systemd's `%N` gives it to `OnFailure=`.
        assert_eq!(hold_unit(&UnitId::service("wg-quick@wg0")), "planarian-hold@wg-quick@wg0.service");
    }

    #[test]
    fn the_marker_is_boot_or_wall_and_boot_deadlines() {
        let now = Timestamp(1_799_999_000_900);
        // 1000 s from now on both clocks, truncated.
        assert_eq!(marker(Some(Timestamp(1_800_000_000_123)), now, 5_000), "1800000000 6000\n");
        // Already past: the boot deadline is now, so the script holds.
        assert_eq!(marker(Some(Timestamp(1_000)), now, 5_000), "1 5000\n");
        assert_eq!(marker(None, now, 5_000), "boot\n");
    }

    /// §12d: re-applying reloads an active hold unit (never lifting it) and
    /// starts an inactive one, since `systemctl reload` fails on that.
    #[test]
    fn reapply_reloads_an_active_hold_and_starts_an_inactive_one() {
        let u = UnitId::service("wireguard-gym");
        for (active, verb) in [(true, "reload"), (false, "start")] {
            let calls = std::cell::RefCell::new(Vec::new());
            let o = reapply_with(&u, |argv| {
                calls.borrow_mut().push(argv.join(" "));
                let status = if argv[1] == "is-active" && !active { 3 } else { 0 };
                Output {
                    status: Some(status),
                    stdout: String::new(),
                    stderr: String::new(),
                    timed_out: false,
                    truncated: false,
                }
            });
            assert_eq!(o, Outcome::Succeeded);
            assert_eq!(
                calls.into_inner(),
                [
                    "systemctl is-active --quiet planarian-hold@wireguard-gym.service".to_string(),
                    format!("systemctl {verb} planarian-hold@wireguard-gym.service"),
                ]
            );
        }
    }

    #[test]
    fn held_reads_the_state_directory_and_absent_is_none() {
        let d = std::env::temp_dir().join(format!("planarian-hold-{}", std::process::id()));
        assert_eq!(held_in(&d), Ok(BTreeSet::new()), "never applied: none");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("wireguard-gym"), "").unwrap();
        assert_eq!(held_in(&d), Ok([UnitId::service("wireguard-gym")].into()));
        // An unreadable directory is an error, not "none".
        let f = d.join("not-a-dir");
        std::fs::write(&f, "").unwrap();
        assert!(held_in(&f).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_release_writes_its_marker_and_ending_it_removes_it() {
        let d = std::env::temp_dir().join(format!("planarian-hold-released-{}", std::process::id()));
        let u = UnitId::service("wireguard-gym");
        // `lift` runs systemctl, absent here: the marker is written first all the same.
        let _ = release_in(&d, &u, None, Duration::from_secs(1));
        assert_eq!(std::fs::read_to_string(d.join("wireguard-gym")).unwrap(), "boot\n");
        assert_eq!(end_release_in(&d, &u), Outcome::Succeeded);
        assert!(!d.join("wireguard-gym").exists());
        assert_eq!(end_release_in(&d, &u), Outcome::Succeeded, "idempotent");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
