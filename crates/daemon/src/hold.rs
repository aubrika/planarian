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
use std::collections::BTreeSet;

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

/// The unmanaged network tools: the export's `tools` (a template ends in
/// `@`) as units, minus the manifest's units (`defs`) and the hold units
/// themselves. A template is each unit of `listed` whose name extends it (an
/// instance is longer than the template's own name); where the list could not
/// be read (`None`), the instances of the previous tick stand, never dropped.
/// A previous one whose hold stands (`keep`) stays whatever the export says
/// now: a generation that stops exporting it must not strand its hold.
pub fn unmanaged_set(
    tools: &BTreeSet<String>,
    listed: Option<&[UnitId]>,
    previous: &BTreeSet<UnitId>,
    keep: &BTreeSet<UnitId>,
    defs: &UnitDefs,
) -> BTreeSet<UnitId> {
    let mut want: BTreeSet<UnitId> = previous.intersection(keep).cloned().collect();
    let templates: Vec<&String> = tools.iter().filter(|t| t.ends_with('@')).collect();
    for t in tools.iter().filter(|t| !t.ends_with('@')) {
        want.insert(UnitId::service(t.trim_end_matches(".service")));
    }
    if !templates.is_empty() {
        match listed {
            Some(all) => {
                want.extend(
                    all.iter()
                        .filter(|u| templates.iter().any(|t| u.name.starts_with(t.as_str()) && u.name.len() > t.len()))
                        .cloned(),
                );
            }
            None => want.extend(previous.iter().filter(|u| u.name.contains('@')).cloned()),
        }
    }
    want.retain(|u| !defs.contains_key(u) && held_by(u).is_none());
    want
}

/// What the hold code is to read of an unmanaged tool, from what the backend
/// saw. It has no manifest unit, so there is no Running to compare against:
/// only a failure counts as down. Systemd's `Failed` is one; an inactive unit
/// that a signal or the OOM killer ended is one (a `systemctl stop` or a kill:
/// §12d counts it), whether or not it was seen running; one that never ran, or
/// that ended on its own (a oneshot that finished, `modprobe@x`), is not down
/// and reads as up. A unit whose hold stands keeps what was seen: it lifts
/// only when seen running.
pub fn unmanaged_observed(raw: Observed, ended: Option<Ending>, held: bool) -> Observed {
    match raw {
        Observed::Absent | Observed::Bound | Observed::Detected if !held => {
            if matches!(ended, Some(Ending::Signal(_) | Ending::OomKill)) { raw } else { Observed::Active }
        }
        other => other,
    }
}

/// How many unmanaged tools a tick looks at besides those always looked at
/// (one `systemctl show` each), rotating: the ones never seen running and the
/// ones seen protecting nothing. A tool seen running that protected traffic,
/// and the ones held, are looked at every tick.
pub const UNMANAGED_OBSERVE_PER_TICK: usize = 8;

/// More unmanaged tools than this observed every tick is said once: each is
/// a `systemctl show` in the tick.
pub const UNMANAGED_MANY: usize = 32;

/// An unmanaged network tool (no manifest unit; the export's `networkTools`)
/// as the hold code reads a unit: desired Running, a network tool. Never
/// given to the assembler or the incident manager: it is never repaired.
pub fn unmanaged_def(id: &UnitId) -> UnitDef {
    UnitDef {
        id: id.clone(),
        desired: Desired { status: DesiredStatus::Running, when: Condition::Always },
        edges: vec![],
        sensitivity: Sensitivities::default(),
        restart_disruption: Disruption::None,
        probes: vec![],
        synonyms: vec![],
        systemd_restart: None,
        startup_grace: None,
        runtime_repair: None,
        stops_are_faults: false,
        holds: true,
        hold_allow: vec![],
        hold_interfaces: vec![],
    }
}

/// The alarm when an unmanaged network tool stops and its traffic is held.
pub fn unmanaged_alarm(unit: &UnitId) -> String {
    format!(
        "ALARM: {unit} stopped and is not managed by Planarian. Network traffic is blocked until it is back or an administrator releases it."
    )
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

        /// `unmanaged_set` against an independent model, over generated tools
        /// (plain, `.service`-suffixed, templates), lists (readable or not),
        /// previous instances and manifest units, drawn from names that
        /// collide on purpose (a hold unit, the bare template, a template's
        /// prefix of another).
        #[test]
        fn the_unmanaged_set_is_the_exports_tools_less_the_managed_and_the_hold_units(
            tools in prop::collection::btree_set(prop::sample::select(vec![
                "a", "b", "c.service", "t@", "u@", "planarian-hold@",
            ]), 0..5),
            listed in prop::option::of(prop::collection::vec(prop::sample::select(vec![
                "a", "b", "t@", "t@1", "t@2", "u@x", "u@", "ut@z", "planarian-hold@a", "planarian-hold@", "other",
            ]), 0..8)),
            previous in prop::collection::btree_set(prop::sample::select(vec!["t@1", "u@x", "a", "t@old"]), 0..4),
            managed in prop::collection::btree_set(prop::sample::select(vec!["a", "t@2", "c", "u@x"]), 0..4),
            keep in prop::collection::btree_set(prop::sample::select(vec!["t@1", "t@old", "a", "planarian-hold@a", "zz"]), 0..4),
        ) {
            let tools: BTreeSet<String> = tools.into_iter().map(String::from).collect();
            let listed: Option<Vec<UnitId>> = listed.map(|l| l.into_iter().map(UnitId::service).collect());
            let previous: BTreeSet<UnitId> = previous.into_iter().map(UnitId::service).collect();
            let defs: UnitDefs = managed.into_iter().map(|n| (UnitId::service(n), unmanaged_def(&UnitId::service(n)))).collect();
            let keep: BTreeSet<UnitId> = keep.into_iter().map(UnitId::service).collect();
            let got = unmanaged_set(&tools, listed.as_deref(), &previous, &keep, &defs);

            // The model: names, then filter.
            let mut want: BTreeSet<String> = BTreeSet::new();
            for t in &tools {
                if !t.ends_with('@') {
                    want.insert(t.strip_suffix(".service").unwrap_or(t).to_string());
                }
            }
            let templates: Vec<&String> = tools.iter().filter(|t| t.ends_with('@')).collect();
            if !templates.is_empty() {
                let pool: Vec<String> = match &listed {
                    Some(l) => l.iter().map(|u| u.name.clone()).collect(),
                    None => previous.iter().filter(|u| u.name.contains('@')).map(|u| u.name.clone()).collect(),
                };
                for n in pool {
                    if templates.iter().any(|t| n.len() > t.len() && n.starts_with(t.as_str())) || listed.is_none() {
                        want.insert(n);
                    }
                }
            }
            // A previous unit whose hold stands stays, whatever the export says.
            want.extend(previous.iter().filter(|u| keep.contains(*u)).map(|u| u.name.clone()));
            let want: BTreeSet<UnitId> = want
                .into_iter()
                .filter(|n| !(n.starts_with("planarian-hold@") && n.len() > "planarian-hold@".len()))
                .map(|n| UnitId::service(&n))
                .filter(|u| !defs.contains_key(u))
                .collect();
            prop_assert_eq!(got, want);
        }

        /// What an unmanaged tool reads as, against a model: down only when
        /// systemd says failed, or it is inactive and a signal or the OOM
        /// killer ended it, or its hold stands and it is not seen running.
        #[test]
        fn an_unmanaged_tool_is_down_only_when_it_failed_or_was_killed_or_stays_held(
            raw in prop::sample::select(vec![
                Observed::Absent, Observed::Bound, Observed::Detected, Observed::Active,
                Observed::Failed(Reason::ExitCode(1)),
            ]),
            held in any::<bool>(),
            ended in prop::sample::select(vec![
                None, Some(Ending::Exited(0)), Some(Ending::Exited(1)), Some(Ending::Signal(15)), Some(Ending::OomKill),
            ]),
        ) {
            let got = unmanaged_observed(raw.clone(), ended, held);
            let inactive = matches!(raw, Observed::Absent | Observed::Bound | Observed::Detected);
            let killed = matches!(ended, Some(Ending::Signal(_) | Ending::OomKill));
            let down = matches!(raw, Observed::Failed(_)) || (inactive && (held || killed));
            prop_assert_eq!(matches!(got, Observed::Failed(_) | Observed::Absent | Observed::Bound | Observed::Detected), down);
            if !inactive {
                prop_assert_eq!(got, raw);
            }
        }
    }
}
