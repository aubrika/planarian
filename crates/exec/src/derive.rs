//! Deriving policy facts (I14): from the evaluated generations and the unit
//! definitions, never from a proposal.

use crate::host::changed_units;
use planarian_policy::Tables;
use planarian_schema::spec::dependents;
use planarian_schema::*;
use planarian_state::Canonical;
use std::collections::BTreeSet;

pub const CORE_UNITS: [&str; 2] = ["planariad", "planarian-recovery"];

pub struct DeriveInput<'a> {
    pub transition: &'a Transition,
    pub defs: &'a UnitDefs,
    pub base: &'a EvaluatedGeneration,
    pub candidate: Option<&'a EvaluatedGeneration>,
    pub activation: Option<&'a ActivationPlan>,
    pub base_overrides: &'a OverrideSet,
    pub candidate_overrides: Option<&'a OverrideSet>,
    pub caller: Actor,
    pub tables: &'a Tables,
    pub canonical: &'a Canonical,
}

pub fn manifest_of(e: &EvaluatedGeneration) -> Manifest {
    Manifest { units: e.units.clone(), user_units: e.user_units.clone() }
}

fn unit_facts<'a>(units: impl IntoIterator<Item = &'a UnitId>, defs: &UnitDefs) -> (Sensitivities, Disruption) {
    let mut sens = Sensitivities::default();
    let mut disruption = Disruption::None;
    for u in units {
        if let Some(d) = defs.get(u) {
            sens = sens.union(&d.sensitivity);
            disruption = disruption.max(d.restart_disruption);
        }
        if CORE_UNITS.contains(&u.name.as_str()) {
            sens.insert(Sensitivity::Core);
        }
    }
    (sens, disruption)
}

pub fn diff(base: &OverrideSet, cand: &OverrideSet) -> ConfigDiff {
    let mut d = ConfigDiff::default();
    for (k, v) in &cand.assignments {
        if base.assignments.get(k) != Some(v) {
            d.options.insert(k.clone(), (base.assignments.get(k).cloned(), Some(v.clone())));
        }
    }
    for (k, v) in &base.assignments {
        if !cand.assignments.contains_key(k) {
            d.options.insert(k.clone(), (Some(v.clone()), None));
        }
    }
    d
}

/// A generation tried to define a canonical probe differently from the core
/// package, or dropped one from a unit that is still present (I10).
fn touches_canonical(base: &Manifest, cand: &Manifest, canonical: &Canonical) -> bool {
    for (id, d) in cand.units.iter().chain(cand.user_units.iter().map(|u| (&u.id, u))) {
        let Some(core) = canonical.get(&id.name) else { continue };
        for p in &d.probes {
            if let Some(c) = core.iter().find(|c| c.id == p.id)
                && c != p
            {
                return true;
            }
        }
        // Present in the base with a canonical probe declared, and the candidate
        // drops that declaration while keeping the unit.
        if let Some(b) = base.units.get(id) {
            let declared = |x: &UnitDef| x.probes.iter().filter(|p| core.iter().any(|c| c.id == p.id)).count();
            if declared(b) > declared(d) {
                return true;
            }
        }
    }
    false
}

fn touches_manifest(base: &Manifest, cand: &Manifest, diff: &ConfigDiff) -> bool {
    if diff.options.keys().any(|k| k.starts_with("services.planarian.")) {
        return true;
    }
    base.units.iter().any(|(id, b)| {
        cand.units.get(id).is_some_and(|c| {
            c.edges != b.edges
                || c.sensitivity != b.sensitivity
                || c.restart_disruption != b.restart_disruption
                || c.synonyms != b.synonyms
                || c.probes
                    .iter()
                    .filter(|p| p.origin == ProbeOrigin::User)
                    .ne(b.probes.iter().filter(|p| p.origin == ProbeOrigin::User))
        })
    })
}

fn changes_desired(base: &Manifest, cand: &Manifest) -> bool {
    base.units.keys().ne(cand.units.keys())
        || base.units.iter().any(|(id, b)| cand.units.get(id).is_some_and(|c| c.desired != b.desired))
}

pub fn derive(i: &DeriveInput<'_>) -> DerivedFacts {
    let base_m = manifest_of(i.base);
    let one = |u: &UnitId| {
        let mut s = dependents(u, i.defs);
        s.insert(u.clone());
        s
    };
    let mut f = DerivedFacts {
        affected_units: Vec::new(),
        sensitivity: Sensitivities::of(&[Sensitivity::Routine]),
        disruption: Disruption::None,
        recovery: Recovery::Idempotent,
        touches_manifest: false,
        touches_canonical_probe: false,
        changes_desired: false,
        touches_core: false,
        below_security_floor: false,
        other_sessions_affected: false,
        affected_sessions: Vec::new(),
        caller: i.caller.clone(),
        config_diff: None,
    };
    let unit_op = |f: &mut DerivedFacts, u: &UnitId, recovery: Recovery| {
        f.affected_units = unit_set(one(u));
        let (s, d) = unit_facts(&f.affected_units, i.defs);
        f.sensitivity = s;
        f.disruption = d;
        f.recovery = recovery;
        f.touches_core = f.sensitivity.contains(Sensitivity::Core);
    };
    match i.transition {
        Transition::RestartUnit(u) => unit_op(&mut f, u, Recovery::Idempotent),
        Transition::StopUnit(u) | Transition::StopAndSuppress { unit: u, .. } => {
            unit_op(&mut f, u, Recovery::Revertible)
        }
        Transition::SetOverride(s) => {
            unit_op(&mut f, &s.unit, Recovery::Idempotent);
            f.affected_units = vec![s.unit.clone()];
            f.disruption = Disruption::None;
        }
        Transition::LiftOverride(u) => {
            unit_op(&mut f, u, Recovery::Idempotent);
            f.affected_units = vec![u.clone()];
            f.disruption = Disruption::None;
        }
        Transition::BindDriver { device, .. } => unit_op(&mut f, device, Recovery::Revertible),
        Transition::SetRuntimeOption { path, .. } => {
            f.sensitivity = i.tables.option_sensitivity(&format!("runtime.{path}"));
            f.disruption = if path == "wifi.network" { Disruption::ConnectivityLoss } else { Disruption::None };
            f.recovery = Recovery::Revertible;
        }
        Transition::CollectGarbage { .. } | Transition::Resolve { .. } => {}
        Transition::RestoreSnapshot(_) => {
            f.recovery = Recovery::NonReversible;
            f.sensitivity = Sensitivities::of(&[Sensitivity::UserData]);
        }
        Transition::ApplyChange { .. }
        | Transition::SwitchGeneration(_)
        | Transition::Revert { .. }
        | Transition::Rollback
        | Transition::LoadModel(_) => {
            f.recovery = Recovery::Revertible;
            let Some(cand) = i.candidate else { return f };
            let cand_m = manifest_of(cand);
            let mut affected = changed_units(&base_m, &cand_m);
            if let Some(a) = i.activation {
                affected.extend(a.start.iter().chain(&a.stop).chain(&a.restart).chain(&a.reload).cloned());
            }
            let config = i.candidate_overrides.map(|c| diff(i.base_overrides, c)).unwrap_or_default();
            let mut all_defs = i.defs.clone();
            for (k, v) in &cand.units {
                all_defs.entry(k.clone()).or_insert_with(|| v.clone());
            }
            let (s, d) = unit_facts(&affected, &all_defs);
            f.sensitivity = s.union(&i.tables.diff_sensitivity(&config));
            f.disruption = d;
            f.touches_manifest = touches_manifest(&base_m, &cand_m, &config);
            f.touches_canonical_probe = touches_canonical(&base_m, &cand_m, i.canonical);
            f.changes_desired = changes_desired(&base_m, &cand_m);
            f.touches_core = cand.core_units != i.base.core_units || f.sensitivity.contains(Sensitivity::Core);
            f.affected_units = unit_set(affected);
            f.config_diff = (!config.options.is_empty()).then_some(config);
        }
    }
    f
}

/// §11 session facts, from logind's sessions: which sessions the disruption
/// lands on (sorted), and whether a system-scope session or connectivity loss
/// reaches a session of another uid than the caller's. A user unit lands on
/// its own session, or every session of its uid; a disruptive system unit on
/// every session.
pub fn session_facts(f: &mut DerivedFacts, sessions: &[SessionInfo]) {
    let live: Vec<&SessionInfo> = sessions.iter().filter(|s| s.establishes()).collect();
    let disruptive =
        matches!(f.disruption, Disruption::SessionLoss | Disruption::ConnectivityLoss | Disruption::DataInterruption);
    let mut hit: BTreeSet<String> = BTreeSet::new();
    let mut system = false;
    for u in &f.affected_units {
        match &u.scope {
            Scope::User { uid, session: Some(s) } if live.iter().any(|x| x.uid == *uid && &x.id == s) => {
                hit.insert(s.clone());
            }
            Scope::User { uid, .. } => hit.extend(live.iter().filter(|x| x.uid == *uid).map(|x| x.id.clone())),
            Scope::System => system = true,
        }
    }
    if system && disruptive {
        hit.extend(live.iter().map(|x| x.id.clone()));
    }
    let caller = f.caller.uid();
    f.other_sessions_affected = system
        && matches!(f.disruption, Disruption::SessionLoss | Disruption::ConnectivityLoss)
        && live.iter().any(|x| Some(x.uid) != caller);
    f.affected_sessions = hit.into_iter().collect();
}

/// §12e: whether the generation a transition goes to is below the security
/// floor. Planarian's generation ids grow with time, so "below" is older.
pub fn floor_fact(f: &mut DerivedFacts, t: &Transition, s: &SystemState) {
    let Some(floor) = s.security_floor else { return };
    let target = match t {
        Transition::SwitchGeneration(g) | Transition::Revert { to: g } => Some(*g),
        Transition::Rollback => Some(s.known_good),
        _ => None,
    };
    f.below_security_floor = target.is_some_and(|g| g.0 < floor.0);
}
