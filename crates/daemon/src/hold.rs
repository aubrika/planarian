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
    if u.kind != UnitKind::Service || u.scope != Scope::System {
        return None;
    }
    u.name.strip_prefix("planarian-hold@").filter(|name| !name.is_empty()).map(UnitId::service)
}

/// The release operation always needs an administrator (§12d), regardless
/// of the protected tool's tags. The hold table is Core; this explicit,
/// authorized release operation is Security, so it can ask an administrator
/// rather than being rejected as a direct edit to Core. Never expected, it is never watched,
/// repaired or counted as an incident.
pub fn hold_def(held: &UnitDef) -> UnitDef {
    let mut d = held.clone();
    d.id = hold_unit(&held.id);
    d.sensitivity.security = true;
    d.sensitivity.core = false;
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
/// (the build-time half; the exported `holds`). Each has a hold unit. A
/// *network-security* unit (§12d *Which units*) is a tool that is also in
/// `SystemState::protecting`; only its failure holds traffic, which
/// `Core::network_holds` and the residue facts apply.
pub fn network_tools(defs: &UnitDefs) -> impl Iterator<Item = &UnitDef> {
    defs.values().filter(|d| d.holds)
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

/// Only this effect is an authorized release. Merely leaving a hold alone,
/// or an inference about it, must not open traffic.
pub fn released(o: &Override) -> Option<UnitId> {
    if o.attribution == Attribution::Attested && o.desired == OverrideDesired::Stopped {
        held_by(&o.unit)
    } else {
        None
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
        let mut user_hold = hold_unit(&wg);
        user_hold.scope = Scope::User { uid: 1000, session: None };
        assert_eq!(held_by(&user_hold), None);
        assert_eq!(held_by(&UnitId::service("planarian-hold@")), None);
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

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn every_hold_has_an_administrator_floor_independent_of_the_tools_tags(
            security in any::<bool>(), core in any::<bool>(), external in any::<bool>(),
        ) {
            let mut tool = planarian_schema::fixtures::service("tool");
            tool.sensitivity.security = security;
            tool.sensitivity.core = core;
            tool.sensitivity.external = external;
            let hold = hold_def(&tool);
            prop_assert!(hold.sensitivity.security);
            prop_assert!(!hold.sensitivity.core, "the explicit release can ask rather than CoreTarget");
            prop_assert_eq!(hold.sensitivity.external, external);
        }

        #[test]
        fn only_a_system_services_attested_stop_is_a_release(
            name in "[a-z][a-z0-9-]{0,20}",
            system in any::<bool>(), service in any::<bool>(), attested in any::<bool>(), desired in 0..4usize,
        ) {
            let mut unit = hold_unit(&UnitId::service(&name));
            if !system { unit.scope = Scope::User { uid: 1000, session: None }; }
            if !service { unit.kind = UnitKind::Target; }
            let desired = [OverrideDesired::LeaveAlone, OverrideDesired::Stopped,
                OverrideDesired::Absent, OverrideDesired::Detected][desired];
            let mut o = Override::attested(unit, desired, Until::NextBoot, "release".into(), Actor::user(0));
            if !attested { o.attribution = Attribution::Inferred; }
            prop_assert_eq!(released(&o).is_some(), system && service && attested && desired == OverrideDesired::Stopped);
        }
    }
}
