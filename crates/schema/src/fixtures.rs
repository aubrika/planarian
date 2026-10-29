//! Builders for tests in other crates (feature `fixtures`).

use crate::*;
use std::collections::{BTreeMap, BTreeSet};

pub fn readiness(id: &str) -> ProbeDef {
    ProbeDef {
        id: ProbeId(id.into()),
        kind: ProbeKind::SystemdActive,
        timeout: Millis::secs(10),
        origin: ProbeOrigin::Canonical,
        role: ProbeRole::Readiness,
        cadence: Cadence::EveryTick,
        cost: ProbeCost::Trivial,
        side_effects: SideEffects::None,
        establishes: format!("{id} passes"),
    }
}

/// A unit desired Running whenever, with one Readiness probe named `<name>-ready`.
pub fn service(name: &str) -> UnitDef {
    let id: UnitId = if name.contains(':') { name.parse().expect("unit id") } else { UnitId::service(name) };
    UnitDef {
        id: id.clone(),
        desired: Desired {
            status: if id.kind == UnitKind::Device { DesiredStatus::Bound } else { DesiredStatus::Running },
            when: Condition::Always,
        },
        edges: vec![],
        sensitivity: Sensitivities::of(&[Sensitivity::Routine]),
        restart_disruption: Disruption::Brief,
        probes: vec![readiness(&format!("{}-ready", id.name))],
        synonyms: vec![],
        systemd_restart: None,
        startup_grace: None,
        runtime_repair: None,
        stops_are_faults: false,
    }
}

pub fn edge(def: &mut UnitDef, to: &str, kind: EdgeKind) {
    let to: UnitId = if to.contains(':') { to.parse().expect("unit id") } else { UnitId::service(to) };
    def.edges.push(Edge { from: def.id.clone(), to, kind, origin: EdgeOrigin::Manifest });
}

pub fn defs(units: impl IntoIterator<Item = UnitDef>) -> UnitDefs {
    units.into_iter().map(|d| (d.id.clone(), d)).collect()
}

pub fn empty_state(now: u64) -> SystemState {
    SystemState {
        generation: GenerationId(1),
        known_good: GenerationId(1),
        live_tested: None,
        accepted_baseline: None,
        security_floor: None,
        units: BTreeMap::new(),
        overrides: vec![],
        conditions: BTreeSet::new(),
        resources: Resources::default(),
        core_hash: Hash::ZERO,
        observed_at: Timestamp(now),
    }
}

/// Set a unit's observation with all its Readiness probes reporting `result` now.
pub fn observe(s: &mut SystemState, defs: &UnitDefs, unit: &UnitId, observed: Observed, result: ProbeResult) {
    let evidence = defs[unit]
        .probes
        .iter()
        .map(|p| Evidence {
            probe: p.id.clone(),
            result: result.clone(),
            at: s.observed_at,
            stale_after: Millis::secs(30),
        })
        .collect();
    s.units.insert(unit.clone(), (observed, evidence));
}

pub fn healthy(s: &mut SystemState, defs: &UnitDefs) {
    for id in defs.keys().cloned().collect::<Vec<_>>() {
        observe(s, defs, &id, Observed::Active, ProbeResult::Pass);
    }
}
