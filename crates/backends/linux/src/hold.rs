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
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReleaseMarker {
    Boot,
    Timed { until: u64, deadline: u64 },
}

fn parse_marker(text: &str) -> Result<ReleaseMarker, Outcome> {
    let fields: Vec<_> = text.split_whitespace().collect();
    match fields.as_slice() {
        ["boot"] => Ok(ReleaseMarker::Boot),
        [until, deadline] => match (until.parse(), deadline.parse()) {
            (Ok(until), Ok(deadline)) => Ok(ReleaseMarker::Timed { until, deadline }),
            _ => Err(Outcome::Failed("invalid hold release marker".into())),
        },
        _ => Err(Outcome::Failed("invalid hold release marker".into())),
    }
}

/// Retrying one timed release never grants it a new boot-clock lifetime.
/// Keep the persisted bound even after daemon restart or clock rollback.
/// Observing expiry on either clock also makes the boot bound expired, so
/// a subsequent wall-clock rollback cannot revive it.
fn stable_marker(
    until: Option<Timestamp>,
    previous: Option<&str>,
    wall_now: Timestamp,
    boot_now: u64,
) -> Result<(String, bool), Outcome> {
    let Some(until) = until else { return Ok(("boot\n".into(), true)) };
    let until = until.0 / 1000;
    let old = previous.map(parse_marker).transpose()?;
    let deadline = match old {
        Some(ReleaseMarker::Timed { until: old_until, deadline }) if old_until == until => deadline,
        _ => boot_now.saturating_add(until.saturating_sub(wall_now.0 / 1000)),
    };
    let active = until > wall_now.0 / 1000 && deadline > boot_now;
    let deadline = if active { deadline } else { deadline.min(boot_now) };
    Ok((format!("{until} {deadline}\n"), active))
}

struct MarkerLock(File);

impl Drop for MarkerLock {
    fn drop(&mut self) {
        // flock belongs to the open file description. A concurrent fork
        // can inherit it until exec closes its CLOEXEC descriptor; merely
        // closing our File could leave the next request spuriously locked.
        // Unlock explicitly even while an inherited descriptor stays open.
        let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
    }
}

fn marker_lock(dir: &Path) -> Result<MarkerLock, Outcome> {
    std::fs::create_dir_all(dir).map_err(|e| Outcome::Failed(format!("{}: {e}", dir.display())))?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .truncate(false)
        .open(dir.join(".lock"))
        .map_err(|e| Outcome::Failed(format!("{}: {e}", dir.display())))?;
    // Never block the daemon behind a stuck marker writer; it will retry.
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|e| Outcome::Unknown(format!("hold release marker lock: {e}")))?;
    Ok(MarkerLock(lock))
}

fn read_marker(path: &Path) -> Result<Option<String>, Outcome> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Outcome::Failed(format!("{}: {e}", path.display()))),
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
    release_with(dir, unit, until, wall_now(), boottime_s(), || lift(unit, wait))
}

fn release_with(
    dir: &Path,
    unit: &UnitId,
    until: Option<Timestamp>,
    wall: Timestamp,
    boot: u64,
    lift: impl FnOnce() -> Outcome,
) -> Outcome {
    let _lock = match marker_lock(dir) {
        Ok(lock) => lock,
        Err(o) => return o,
    };
    let path = marker_path(dir, unit);
    let old = match read_marker(&path) {
        Ok(old) => old,
        Err(o) => return o,
    };
    let (text, active) = match stable_marker(until, old.as_deref(), wall, boot) {
        Ok(marker) => marker,
        Err(o) => return o,
    };
    if let Err(e) = std::fs::write(&path, text) {
        return Outcome::Failed(format!("{}: {e}", path.display()));
    }
    if !active {
        return Outcome::Failed("the timed hold release has expired".into());
    }
    lift()
}

/// A reconciliation may only resume a timed release whose original bound
/// survives. A missing marker cannot be reconstructed from wall time after
/// a daemon restart: that could create a new lifetime after clock rollback.
pub fn timed_release_active_in(dir: &Path, unit: &UnitId, until: Timestamp) -> Result<bool, Outcome> {
    timed_release_active_at(dir, unit, until, wall_now(), boottime_s())
}

fn timed_release_active_at(
    dir: &Path,
    unit: &UnitId,
    until: Timestamp,
    wall: Timestamp,
    boot: u64,
) -> Result<bool, Outcome> {
    let _lock = marker_lock(dir)?;
    let path = marker_path(dir, unit);
    let Some(old) = read_marker(&path)? else { return Ok(false) };
    if !matches!(parse_marker(&old)?, ReleaseMarker::Timed { until: old_until, .. } if old_until == until.0 / 1000) {
        return Ok(false);
    }
    let (text, active) = stable_marker(Some(until), Some(&old), wall, boot)?;
    // Latch an observed wall expiry onto the monotonic bound too.
    if !active && text != old {
        std::fs::write(&path, text).map_err(|e| Outcome::Failed(format!("{}: {e}", path.display())))?;
    }
    Ok(active)
}

pub fn end_release_in(dir: &Path, unit: &UnitId) -> Outcome {
    let _lock = match marker_lock(dir) {
        Ok(lock) => lock,
        Err(o) => return o,
    };
    match std::fs::remove_file(marker_path(dir, unit)) {
        Ok(()) => Outcome::Succeeded,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Succeeded,
        Err(e) => Outcome::Failed(format!("{}: {e}", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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

    proptest! {
        #[test]
        fn retry_schedules_never_extend_or_revive_a_timed_release(
            wall in 10_000..100_000u64,
            boot in 1..10_000u64,
            lifetime in 1..3_600u64,
            schedule in prop::collection::vec((0..1_000u64, -5_000..5_000i64), 1..32),
        ) {
            let until = Timestamp((wall + lifetime) * 1000);
            let mut previous = marker(Some(until), Timestamp(wall * 1000), boot);
            let mut now_wall = wall;
            let mut now_boot = boot;
            let mut bound = boot + lifetime;
            let mut expired = false;
            for (elapsed, adjustment) in schedule {
                now_boot += elapsed;
                now_wall = now_wall.saturating_add(elapsed).saturating_add_signed(adjustment);
                let (next, active) = stable_marker(Some(until), Some(&previous), Timestamp(now_wall * 1000), now_boot).unwrap();
                let ReleaseMarker::Timed { deadline, .. } = parse_marker(&next).unwrap() else { unreachable!() };
                prop_assert!(deadline <= bound, "old={previous:?} new={next:?}, wall={now_wall}, boot={now_boot}");
                prop_assert!(!expired || !active, "an expired release revived: {previous:?} -> {next:?}");
                prop_assert_eq!(active, !expired && now_wall < wall + lifetime && now_boot < bound);
                bound = deadline;
                expired |= !active;
                previous = next;
            }
        }
    }

    #[test]
    fn a_retry_and_restart_keep_the_first_boot_bound_and_an_expired_marker_never_lifts() {
        let dir = tempfile::tempdir().unwrap();
        let unit = UnitId::service("vpn");
        let until = Some(Timestamp(1_600_000));
        let calls = std::cell::Cell::new(0);
        let first = release_with(dir.path(), &unit, until, Timestamp(1_000_000), 100, || {
            calls.set(calls.get() + 1);
            Outcome::Unknown("lift still running".into())
        });
        assert!(matches!(first, Outcome::Unknown(_)));
        let original = std::fs::read_to_string(marker_path(dir.path(), &unit)).unwrap();
        assert_eq!(original, "1600 700\n");
        // Fresh calls have no in-memory state: retry/restart must read the
        // durable marker, even after the wall clock moved backwards.
        for boot in [150, 300, 699] {
            let result = release_with(dir.path(), &unit, until, Timestamp(100_000), boot, || {
                calls.set(calls.get() + 1);
                Outcome::Succeeded
            });
            assert_eq!(result, Outcome::Succeeded);
            assert_eq!(std::fs::read_to_string(marker_path(dir.path(), &unit)).unwrap(), original);
        }
        assert!(!timed_release_active_at(dir.path(), &unit, Timestamp(1_600_000), Timestamp(100_000), 700).unwrap());
        let before = calls.get();
        for boot in [700, 701, 1_000] {
            let result = release_with(dir.path(), &unit, until, Timestamp(1_000), boot, || {
                calls.set(calls.get() + 1);
                Outcome::Succeeded
            });
            assert!(matches!(result, Outcome::Failed(_)));
        }
        assert_eq!(calls.get(), before, "an expired marker reached the lift");
        assert_eq!(std::fs::read_to_string(marker_path(dir.path(), &unit)).unwrap(), original);
    }

    #[test]
    fn observing_wall_expiry_latches_it_and_missing_or_corrupt_bounds_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let unit = UnitId::service("vpn");
        let until = Timestamp(1_600_000);
        assert!(!timed_release_active_at(dir.path(), &unit, until, Timestamp(1_000_000), 100).unwrap());
        let result = release_with(dir.path(), &unit, Some(until), Timestamp(1_000_000), 100, || Outcome::Succeeded);
        assert_eq!(result, Outcome::Succeeded);
        assert!(!timed_release_active_at(dir.path(), &unit, until, Timestamp(1_600_000), 200).unwrap());
        assert!(!timed_release_active_at(dir.path(), &unit, until, Timestamp(100_000), 201).unwrap());
        assert_eq!(std::fs::read_to_string(marker_path(dir.path(), &unit)).unwrap(), "1600 200\n");
        std::fs::write(marker_path(dir.path(), &unit), "1600 700 extra\n").unwrap();
        assert!(timed_release_active_at(dir.path(), &unit, until, Timestamp(100_000), 201).is_err());
        let result =
            release_with(dir.path(), &unit, Some(until), Timestamp(100_000), 201, || panic!("invalid marker lifted"));
        assert!(matches!(result, Outcome::Failed(_)));
    }

    #[test]
    fn marker_writers_and_cleanup_do_not_wait_behind_another_writer() {
        let dir = tempfile::tempdir().unwrap();
        let unit = UnitId::service("vpn");
        let lock = marker_lock(dir.path()).unwrap();
        let result =
            release_with(dir.path(), &unit, None, Timestamp(1_000_000), 100, || panic!("locked marker lifted"));
        assert!(matches!(result, Outcome::Unknown(_)));
        assert!(matches!(end_release_in(dir.path(), &unit), Outcome::Unknown(_)));
        drop(lock);
        let result = release_with(dir.path(), &unit, None, Timestamp(1_000_000), 100, || Outcome::Succeeded);
        assert_eq!(result, Outcome::Succeeded);
        assert_eq!(end_release_in(dir.path(), &unit), Outcome::Succeeded);
    }

    #[test]
    fn dropping_the_marker_guard_unlocks_even_with_an_inherited_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let lock = marker_lock(dir.path()).unwrap();
        // dup and fork share the same open file description. Keeping this
        // duplicate open deterministically models a child paused before exec,
        // without depending on scheduler timing or spawning another process.
        let inherited = lock.0.try_clone().unwrap();
        assert!(matches!(marker_lock(dir.path()), Err(Outcome::Unknown(_))));
        drop(lock);
        let next = marker_lock(dir.path()).expect("a child descriptor must not retain the finished operation's lock");
        assert!(inherited.metadata().is_ok(), "the inherited descriptor must still be open");
        drop(next);
        drop(inherited);
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
