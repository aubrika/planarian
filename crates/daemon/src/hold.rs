//! §12d *Network security fails closed*, the daemon's half (#35 part 1).
//!
//! A network-security unit (interim, B-21: the module's exported `holds`)
//! that has failed has its traffic held. systemd's `OnFailure=` holds it on a
//! crash or kill; the daemon holds it for a stop outside Planarian that is not
//! attributed, and journals either one (`HoldApplied`, before its own call).
//! The daemon lifts the hold once the unit is Running and every Readiness
//! probe passes (`HoldLifted`, before the call). If repair fails, the hold
//! stays and administrators are notified. `planarian hold release` is an
//! attested Override on the hold unit, through the executor like any
//! override, so a non-administrator's release asks an administrator.
//!
//! The hold is a failure posture response, not a transaction (docs/bypasses.md).

use planarian_schema::*;

/// The alarm when a held unit goes down (§12d, §11), word for word.
pub fn alarm(unit: &UnitId) -> String {
    format!("ALARM: {unit} stopped unexpectedly. Network traffic is blocked until it is back.")
}

/// The systemd unit that holds `unit`'s traffic (lane-nix's
/// `planarian-hold@<unit>.service`; the instance is the unit's name).
pub fn hold_unit(unit: &UnitId) -> UnitId {
    UnitId::service(&format!("planarian-hold@{}", unit.name))
}

/// The held unit a hold unit stands for, if `u` is one.
pub fn held_by(u: &UnitId) -> Option<UnitId> {
    u.name.strip_prefix("planarian-hold@").map(UnitId::service)
}

/// The hold unit's definition: known, so an override on it derives the held
/// unit's sensitivity (§11: releasing a hold that protects a Security unit
/// needs an administrator), but never expected, so it is never watched,
/// repaired or counted as an incident.
pub fn hold_def(held: &UnitDef) -> UnitDef {
    let mut d = held.clone();
    d.id = hold_unit(&held.id);
    d.desired = Desired { status: DesiredStatus::Stopped, when: Condition::Any(vec![]) };
    d.edges.clear();
    d.probes.clear();
    d.synonyms.clear();
    d.systemd_restart = None;
    d.runtime_repair = None;
    d.restart_disruption = Disruption::None;
    d.holds = false;
    d.hold_allow.clear();
    d.hold_interfaces.clear();
    d
}

/// The network tools: units able to change how traffic leaves the machine
/// (the build-time half; the exported `holds`). Each has a hold unit.
pub fn network_tools(defs: &UnitDefs) -> impl Iterator<Item = &UnitDef> {
    defs.values().filter(|d| d.holds)
}

/// §12d *Which units*: a network-security unit is a network tool that is
/// protecting traffic now (`SystemState::protecting`, from the kernel-
/// attributed footprints; an unreadable watch counts every tool as
/// protecting). Only its failure holds traffic.
pub fn network_security<'a>(s: &'a SystemState, defs: &'a UnitDefs) -> impl Iterator<Item = &'a UnitDef> {
    network_tools(defs).filter(|d| s.protecting.contains(&d.id))
}

/// It has failed in §12d's sense: observed failed, or not running while it
/// is desired running. A stop through an attested override is not a failure
/// (the override makes it not expected).
pub fn failed(s: &SystemState, defs: &UnitDefs, u: &UnitId) -> bool {
    defs.get(u).is_some_and(|d| d.desired.status == DesiredStatus::Running)
        && s.expected(u, defs)
        && matches!(s.status(u, defs), UnitStatus::Failed(_) | UnitStatus::Stopped | UnitStatus::Absent)
}

/// Back: Running, and every Readiness probe has fresh passing evidence.
/// A unit with no Readiness probe is back when it is Running.
pub fn back(s: &SystemState, defs: &UnitDefs, u: &UnitId) -> bool {
    let Some(def) = defs.get(u) else { return false };
    let readiness = def.probes.iter().filter(|p| p.role == ProbeRole::Readiness).count();
    s.status(u, defs) == UnitStatus::Running && s.passing_readiness(u, defs).len() == readiness
}

/// `--until` as the release marker takes it: `None` is the next boot. A
/// release is never forever (§12d), so an explicit, unbounded one ends at
/// the next boot too.
pub fn release_until(u: &Until) -> Option<Timestamp> {
    match u {
        Until::At(t) => Some(*t),
        Until::NextBoot | Until::Explicit => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hold_unit_names_its_unit_and_back() {
        let wg = UnitId::service("wireguard-gym");
        assert_eq!(hold_unit(&wg), UnitId::service("planarian-hold@wireguard-gym"));
        assert_eq!(held_by(&hold_unit(&wg)), Some(wg.clone()));
        assert_eq!(held_by(&wg), None);
        assert_eq!(
            alarm(&wg),
            "ALARM: service:wireguard-gym stopped unexpectedly. Network traffic is blocked until it is back."
        );
    }

    #[test]
    fn the_hold_def_carries_sensitivity_and_is_never_expected() {
        let mut wg = planarian_schema::fixtures::service("wireguard-gym");
        wg.sensitivity = Sensitivities::of(&[Sensitivity::Security, Sensitivity::External]);
        wg.holds = true;
        let d = hold_def(&wg);
        assert_eq!(d.id, UnitId::service("planarian-hold@wireguard-gym"));
        assert_eq!(d.sensitivity, wg.sensitivity);
        assert!(!d.holds);
        let mut defs = UnitDefs::new();
        defs.insert(d.id.clone(), d.clone());
        let s = planarian_schema::fixtures::empty_state(0);
        assert!(!s.expected(&d.id, &defs), "never watched");
    }

    #[test]
    fn a_release_ends_at_the_next_boot_unless_timed() {
        assert_eq!(release_until(&Until::At(Timestamp(5))), Some(Timestamp(5)));
        assert_eq!(release_until(&Until::NextBoot), None);
        assert_eq!(release_until(&Until::Explicit), None);
    }
}
