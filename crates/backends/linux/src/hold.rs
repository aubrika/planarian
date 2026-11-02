//! §12d *Network security fails closed*: the hold, as lane-nix's
//! `planarian-hold@<unit>.service` (nix/posture.nix) builds it. This module
//! only starts and stops that unit, reads which holds are in place, and
//! writes the release marker the hold script honours:
//!
//! - apply: `systemctl start planarian-hold@<unit>.service` (idempotent;
//!   systemd's `OnFailure=` starts the same unit on a crash or kill);
//! - lift: `systemctl stop` of it;
//! - state: `/run/planarian/hold/<unit>` exists while a hold is in place;
//! - release: `/run/planarian/hold-released/<unit>` holds the expiry in Unix
//!   seconds, or `boot` for the next boot; an unparsable or past one is
//!   expired (the script holds).
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

pub fn apply(unit: &UnitId) -> Outcome {
    outcome("start", unit, run(&["systemctl", "start", &hold_unit(unit)], TIMEOUT))
}

pub fn lift(unit: &UnitId) -> Outcome {
    outcome("stop", unit, run(&["systemctl", "stop", &hold_unit(unit)], TIMEOUT))
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

/// The marker's content: the expiry in Unix seconds, or `boot`.
pub fn marker(until: Option<Timestamp>) -> String {
    match until {
        Some(t) => format!("{}\n", t.0 / 1000),
        None => "boot\n".into(),
    }
}

fn marker_path(dir: &Path, unit: &UnitId) -> PathBuf {
    dir.join(instance(unit))
}

/// Write the release marker, then lift the hold. The marker comes first so
/// that a failure racing the lift does not re-apply the hold.
pub fn release_in(dir: &Path, unit: &UnitId, until: Option<Timestamp>) -> Outcome {
    if let Err(e) = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(marker_path(dir, unit), marker(until))) {
        return Outcome::Failed(format!("{}: {e}", dir.display()));
    }
    lift(unit)
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
    }

    #[test]
    fn the_marker_is_unix_seconds_or_boot() {
        assert_eq!(marker(Some(Timestamp(1_800_000_000_123))), "1800000000\n");
        assert_eq!(marker(None), "boot\n");
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
        let _ = release_in(&d, &u, None);
        assert_eq!(std::fs::read_to_string(d.join("wireguard-gym")).unwrap(), "boot\n");
        assert_eq!(end_release_in(&d, &u), Outcome::Succeeded);
        assert!(!d.join("wireguard-gym").exists());
        assert_eq!(end_release_in(&d, &u), Outcome::Succeeded, "idempotent");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
