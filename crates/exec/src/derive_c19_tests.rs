//! C19, written from the spec before the change (reviewer's case).
//!
//! §9: a manifest entry (`services.planarian.units.<name>`) is `desired`
//! (status + condition), `edges`, `sensitivity`, `restartDisruption`,
//! `probes` and `synonyms`, and "the manifest … ha[s] `Sensitivity::{Security}`".
//! §11, ApplyChange row: "→ AskFirst when … touches_manifest". So a candidate
//! whose manifest differs from the base in any part of any entry, or that adds
//! or removes an entry, touches the manifest. Issue #10's C19 line also names
//! the fields the module exports beyond §9's list: `systemd_restart`,
//! `startup_grace`, `runtime_repair`, `stops_are_faults`. User-scope entries
//! are manifest entries too (`Manifest::user_units`).

use super::touches_manifest;
use planarian_fake::fixtures;
use planarian_schema::*;

fn base() -> Manifest {
    Manifest { units: fixtures::gym_units(), user_units: fixtures::gym_user_units() }
}

fn touched(edit: impl FnOnce(&mut Manifest)) -> bool {
    let b = base();
    let mut c = b.clone();
    edit(&mut c);
    assert_ne!(b, c, "the edit changes the manifest");
    touches_manifest(&b, &c, &ConfigDiff::default())
}

fn web(m: &mut Manifest) -> &mut UnitDef {
    m.units.get_mut(&UnitId::service("gym-web")).expect("gym-web is a fixture")
}

#[test]
fn an_unchanged_manifest_is_not_touched() {
    assert!(!touches_manifest(&base(), &base(), &ConfigDiff::default()));
}

#[test]
fn desired_status_and_condition_are_the_manifest() {
    assert!(touched(|m| web(m).desired.status = DesiredStatus::Stopped), "desired status");
    assert!(
        touched(|m| web(m).desired.when = Condition::SessionEstablished { uid: None, seated: true }),
        "desired condition"
    );
}

#[test]
fn the_exported_restart_and_grace_fields_are_the_manifest() {
    assert!(
        touched(|m| web(m).systemd_restart =
            Some(SystemdRestartPolicy { restart: true, restart_sec: Millis::secs(5), start_limit_burst: 3 })),
        "systemd_restart"
    );
    assert!(touched(|m| web(m).startup_grace = Some(Millis::secs(90))), "startup_grace");
    assert!(touched(|m| web(m).runtime_repair = Some("wifi.network".into())), "runtime_repair");
    assert!(
        touched(|m| {
            let w = web(m);
            w.stops_are_faults = !w.stops_are_faults;
        }),
        "stops_are_faults"
    );
}

#[test]
fn adding_or_removing_an_entry_is_the_manifest() {
    assert!(
        touched(|m| {
            let mut extra = m.units[&UnitId::service("gym-web")].clone();
            extra.id = UnitId::service("gym-extra");
            m.units.insert(extra.id.clone(), extra);
        }),
        "an added unit"
    );
    assert!(
        touched(|m| {
            m.units.remove(&UnitId::service("gym-metrics"));
        }),
        "a removed unit"
    );
}

fn first(m: &mut Manifest) -> &mut UnitDef {
    m.user_units.first_mut().expect("a user-scope fixture")
}

#[test]
fn user_scope_entries_are_the_manifest() {
    assert!(touched(|m| first(m).restart_disruption = Disruption::SessionLoss), "a user unit's field");
    assert!(
        touched(|m| {
            let mut extra = m.user_units[0].clone();
            extra.id.name = "gym-user-extra".into();
            m.user_units.push(extra);
        }),
        "an added user unit"
    );
    assert!(
        touched(|m| {
            m.user_units.remove(0);
        }),
        "a removed user unit"
    );
}

/// What `touches_manifest` already covers keeps being covered.
#[test]
fn the_fields_already_covered_stay_covered() {
    assert!(touched(|m| web(m).synonyms.push("website".into())), "synonyms");
    assert!(touched(|m| web(m).restart_disruption = Disruption::SessionLoss), "restart_disruption");
    assert!(touched(|m| web(m).sensitivity = Sensitivities::of(&[Sensitivity::Security])), "sensitivity");
}
