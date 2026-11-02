//! Deriving policy facts (I14): from the evaluated generations and the unit
//! definitions, never from a proposal.

use crate::host::changed_units;
use planarian_policy::Tables;
use planarian_schema::spec::dependents;
use planarian_schema::*;
use planarian_state::Canonical;
use std::collections::{BTreeMap, BTreeSet};

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
    /// The observation this derivation is made against: the one passed to
    /// it, current at proposal, approval and before Activating (§9 step 6).
    pub state: &'a SystemState,
}

pub fn manifest_of(e: &EvaluatedGeneration) -> Manifest {
    Manifest { units: e.units.clone(), user_units: e.user_units.clone() }
}

/// §11 as amended in #22 (owner decision, Nov 2): "A unit that has already
/// failed (observed `Failed`, or not running while it is desired running,
/// when the facts are derived) contributes no disruption of its own". Read
/// from `s`, the observation this derivation is made against, never from an
/// incident or from evidence past its `stale_after` (`status` ignores that).
/// `Unknown` counts as running (§10: "`Unknown`, never `Failed`"), so a probe
/// that timed out, errored or was abandoned buys no exemption; so does
/// Degraded, Transitioning, an override, or a unit not desired Running.
fn already_failed(s: &SystemState, defs: &UnitDefs, u: &UnitId) -> bool {
    let Some(d) = defs.get(u) else { return false };
    d.desired.status == DesiredStatus::Running
        && s.expected(u, defs)
        && matches!(s.status(u, defs), UnitStatus::Failed(_) | UnitStatus::Stopped | UnitStatus::Absent)
}

/// §11, §12d: whether `u`'s traffic is held now, in the observation `s`
/// (lane-daemon's ledger `holds`, reconciled with `/run/planarian/hold/`).
/// §11 waives the RestartUnit row's escalations because "its traffic is
/// held", so the waiver reads the hold itself, not the footprint that leads
/// to it: §12d fails closed toward applying a hold, and with this a missing
/// or stale footprint buys a waiver only once traffic is in fact blocked.
/// `SystemState.holds`: the journal's holds and the host's, their union.
fn hold_in_place(s: &SystemState, u: &UnitId) -> bool {
    s.holds.contains(u)
}

fn unit_facts<'a>(
    units: impl IntoIterator<Item = &'a UnitId>,
    defs: &UnitDefs,
    services: &BTreeMap<String, Sensitivities>,
    already_failed: impl Fn(&UnitId) -> bool,
) -> (Sensitivities, Disruptions) {
    let mut sens = Sensitivities::default();
    // C10 (§11): every kind any unit carries, not the `max` of them. The
    // floors are not ordered, so a fold would drop one.
    let mut disruption = Disruptions::default();
    for u in units {
        // Fail closed (§11 sensitivity completeness, B-5): a unit with no
        // sensitivity entry, or none in the manifest at all, is not taken
        // as Routine. External: nothing is known about what it touches.
        let unknown = Sensitivities::of(&[Sensitivity::External]);
        let empty = |s: &Sensitivities| !(s.routine || s.security || s.user_data || s.external || s.core);
        match defs.get(u) {
            Some(d) => {
                sens = sens.union(if empty(&d.sensitivity) { &unknown } else { &d.sensitivity });
                // What an already-failed unit provides is already lost:
                // restarting it restores rather than costs. Its sensitivity
                // still counts.
                if !already_failed(u) {
                    disruption.insert(d.restart_disruption);
                }
            }
            // A user-scope unit runs with that user's rights only; an
            // undeclared one stays Routine (deviations.md).
            None if matches!(u.scope, Scope::User { .. }) => {}
            // A system service NixOS defines but the manifest does not
            // declare has the shipped tables' entry (the export's `services`).
            None => match services.get(&u.name) {
                Some(t) if !empty(t) => sens = sens.union(t),
                _ => sens = sens.union(&unknown),
            },
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

/// The options two evaluated generations set differently (§11, §16).
pub fn option_diff(base: &BTreeMap<String, Value>, cand: &BTreeMap<String, Value>) -> ConfigDiff {
    let mut d = ConfigDiff::default();
    for (k, v) in cand {
        if base.get(k) != Some(v) {
            d.options.insert(k.clone(), (base.get(k).cloned(), Some(v.clone())));
        }
    }
    for (k, v) in base {
        if !cand.contains_key(k) {
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

/// C19 (§9, §11 ApplyChange row): whether the candidate's manifest differs
/// from the base's in any part of any entry (`desired`, `edges`,
/// `sensitivity`, `restart_disruption`, the user probes, `synonyms`, and the
/// exported `systemd_restart`, `startup_grace`, `runtime_repair`,
/// `stops_are_faults`), in user-scope entries as in system ones, or adds or
/// removes an entry. Canonical probes are left out: they come from the core
/// package, and redefining one is `touches_canonical`.
fn touches_manifest(base: &Manifest, cand: &Manifest, diff: &ConfigDiff) -> bool {
    if diff.options.keys().any(|k| k.starts_with("services.planarian.")) {
        return true;
    }
    // An entry as the manifest declares it: every field, the user probes only.
    let entry = |d: &UnitDef| {
        let mut d = d.clone();
        d.probes.retain(|p| p.origin == ProbeOrigin::User);
        d
    };
    let entries = |m: &Manifest| -> (BTreeMap<UnitId, UnitDef>, BTreeMap<UnitId, UnitDef>) {
        (
            m.units.iter().map(|(id, d)| (id.clone(), entry(d))).collect(),
            m.user_units.iter().map(|d| (d.id.clone(), entry(d))).collect(),
        )
    };
    entries(base) != entries(cand)
}

fn changes_desired(base: &Manifest, cand: &Manifest) -> bool {
    base.units.keys().ne(cand.units.keys())
        || base.units.iter().any(|(id, b)| cand.units.get(id).is_some_and(|c| c.desired != b.desired))
}

/// What a generation transition takes away (§11 Rollback row, §16): units
/// present now and absent from the target, and units its activation stops,
/// sorted, with their sensitivity. A removed user template's definition is in
/// the base manifest, not in `defs` (which holds the per-session instances), so
/// it is looked up there: an unknown unit must not count as Routine (§11
/// sensitivity completeness, fail closed).
pub(crate) fn removed_units(
    base_m: &Manifest,
    cand_m: &Manifest,
    activation: Option<&ActivationPlan>,
    defs: &UnitDefs,
    services: &BTreeMap<String, Sensitivities>,
) -> (Vec<UnitId>, Vec<Sensitivities>, Sensitivities) {
    let mut removed: Vec<UnitId> = base_m.units.keys().filter(|u| !cand_m.units.contains_key(*u)).cloned().collect();
    removed.extend(
        base_m.user_units.iter().filter(|b| !cand_m.user_units.iter().any(|c| c.id == b.id)).map(|b| b.id.clone()),
    );
    if let Some(a) = activation {
        removed.extend(a.stop.iter().cloned());
    }
    let mut known = defs.clone();
    for b in &base_m.user_units {
        known.entry(b.id.clone()).or_insert_with(|| b.clone());
    }
    let sens = unit_facts(&removed, &known, services, |_| false).0;
    // Each one's own, from the same lookup as the decision's (§16: what the
    // approval shows is what was decided on).
    let removed = unit_set(removed);
    let each = removed.iter().map(|u| unit_facts(std::iter::once(u), &known, services, |_| false).0).collect();
    (removed, each, sens)
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
        disruption: Disruptions::default(),
        recovery: Recovery::Idempotent,
        touches_manifest: false,
        touches_canonical_probe: false,
        changes_desired: false,
        touches_core: false,
        below_security_floor: false,
        restores_unattributed_stop: false,
        restarts_failed_unit: false,
        removes_sensitivity: Default::default(),
        removes: Default::default(),
        removes_each: Default::default(),
        restarts_held_unit: false,
        other_sessions_affected: false,
        affected_sessions: Vec::new(),
        caller: i.caller.clone(),
        config_diff: None,
    };
    let unit_op = |f: &mut DerivedFacts, u: &UnitId, recovery: Recovery| {
        f.affected_units = unit_set(one(u));
        let (s, d) = unit_facts(&f.affected_units, i.defs, &i.base.services, |u| already_failed(i.state, i.defs, u));
        f.sensitivity = s;
        f.disruption = d;
        f.recovery = recovery;
        f.touches_core = f.sensitivity.contains(Sensitivity::Core);
    };
    match i.transition {
        Transition::RestartUnit(u) => {
            unit_op(&mut f, u, Recovery::Idempotent);
            // §11 (owner decision, Nov 2): restarting an already-failed unit
            // waives the RestartUnit row's External escalation (policy reads
            // this; Security still escalates). The same reading as the
            // disruption rule: current observation, Unknown is not failed.
            f.restarts_failed_unit = already_failed(i.state, i.defs, u);
            // §11, §12d (owner decision, Nov 2): a failed unit whose traffic
            // is held: its restart only ends an outage, and waives both
            // escalations of the RestartUnit row.
            f.restarts_held_unit = f.restarts_failed_unit && hold_in_place(i.state, u);
        }
        Transition::StopUnit(u) | Transition::StopAndSuppress { unit: u, .. } => {
            unit_op(&mut f, u, Recovery::Revertible)
        }
        // Equivalent effects, equivalent facts (§11, rule 20, R03): an
        // override that stops, removes or detaches a unit does what a stop
        // does to it and its dependents, so it carries the same facts as
        // StopAndSuppress. Only LeaveAlone changes nothing on the machine.
        Transition::SetOverride(s) => match s.desired {
            OverrideDesired::LeaveAlone => {
                unit_op(&mut f, &s.unit, Recovery::Idempotent);
                f.affected_units = vec![s.unit.clone()];
                f.disruption = Disruptions::default();
            }
            OverrideDesired::Stopped | OverrideDesired::Absent | OverrideDesired::Detected => {
                unit_op(&mut f, &s.unit, Recovery::Revertible)
            }
        },
        Transition::LiftOverride(u) => {
            unit_op(&mut f, u, Recovery::Idempotent);
            f.affected_units = vec![u.clone()];
            f.disruption = Disruptions::default();
        }
        Transition::BindDriver { device, .. } => unit_op(&mut f, device, Recovery::Revertible),
        Transition::SetRuntimeOption { path, .. } => {
            f.sensitivity = i.tables.option_sensitivity(&format!("runtime.{path}"));
            // §11, §12a (owner decision, Nov 2): Wi-Fi selection's
            // ConnectivityLoss is its providing unit's (NetworkManager's),
            // and none while that unit has already failed. The providing
            // units are those whose manifest entry names this option as its
            // `runtime_repair`; with none declared, the loss stays (fail
            // closed), and every one of them must have failed.
            let providers: Vec<&UnitId> =
                i.defs.values().filter(|d| d.runtime_repair.as_deref() == Some(path.as_str())).map(|d| &d.id).collect();
            let provider_failed = !providers.is_empty() && providers.iter().all(|u| already_failed(i.state, i.defs, u));
            f.disruption = if path == "wifi.network" && !provider_failed {
                Disruptions::of(Disruption::ConnectivityLoss)
            } else {
                Disruptions::default()
            };
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
            let mut config = i.candidate_overrides.map(|c| diff(i.base_overrides, c)).unwrap_or_default();
            // A generation built outside Planarian (known_good often is) has no
            // recorded override, so for a switch, revert or rollback the
            // evaluated option sets are compared too: an option it would
            // restore is in the diff even without an override (§11 Rollback
            // row, I11, §16; owner decision, Nov 2).
            if matches!(
                i.transition,
                Transition::SwitchGeneration(_) | Transition::Revert { .. } | Transition::Rollback
            ) {
                for (k, v) in option_diff(&i.base.options, &cand.options).options {
                    if !config.options.contains_key(&k) {
                        config.options.insert(k, v);
                    }
                }
            }
            let mut all_defs = i.defs.clone();
            for (k, v) in &cand.units {
                all_defs.entry(k.clone()).or_insert_with(|| v.clone());
            }
            let mut services = i.base.services.clone();
            services.extend(cand.services.iter().map(|(k, v)| (k.clone(), *v)));
            // Kinds come from `all_defs` (a unit only the candidate adds has its
            // definition there); the already-failed rule reads `i.defs`, the
            // definitions `i.state` was observed against. A unit only the
            // candidate adds is not in `i.defs` and was never observed, so it
            // is never exempt.
            let (s, d) = unit_facts(&affected, &all_defs, &services, |u| already_failed(i.state, i.defs, u));
            f.sensitivity = s.union(&i.tables.diff_sensitivity(&config));
            f.disruption = d;
            f.touches_manifest = touches_manifest(&base_m, &cand_m, &config);
            f.touches_canonical_probe = touches_canonical(&base_m, &cand_m, i.canonical);
            f.changes_desired = changes_desired(&base_m, &cand_m);
            f.touches_core = cand.core_units != i.base.core_units || f.sensitivity.contains(Sensitivity::Core);
            // A catalog change may bring only what its override explains. The
            // staged tree is the owner's as it is now, so it can carry edits the
            // running generation does not have; those were never classified.
            if let Transition::ApplyChange { change, args } = i.transition
                && unexplained(i.base, cand, change, args)
            {
                f.sensitivity = f.sensitivity.union(&Sensitivities::of(&[Sensitivity::Security]));
                f.touches_manifest = true;
            }
            let (removes, each, removes_sensitivity) =
                removed_units(&base_m, &cand_m, i.activation, &all_defs, &services);
            f.removes_sensitivity = removes_sensitivity;
            f.removes = removes;
            f.removes_each = each;
            f.affected_units = unit_set(affected);
            f.config_diff = (!config.options.is_empty()).then_some(config);
        }
    }
    f
}

/// Whether the candidate differs from the running generation in ways a
/// catalog change's override cannot explain: services declared or removed
/// (other than the one a `service-enable` names), flake inputs, or a package
/// with known vulnerabilities that the running generation does not have.
pub fn unexplained(
    base: &EvaluatedGeneration,
    cand: &EvaluatedGeneration,
    change: &ChangeId,
    args: &BTreeMap<String, Value>,
) -> bool {
    let named = (change.0 == "service-enable").then(|| match args.get("service") {
        Some(Value::Str(s)) => s.clone(),
        _ => String::new(),
    });
    let services = |e: &EvaluatedGeneration| -> BTreeSet<String> {
        e.declarations.keys().filter(|k| Some(*k) != named.as_ref()).cloned().collect()
    };
    // A generation that predates the export has no declarations to compare.
    let declared = !base.declarations.is_empty() && services(base) != services(cand);
    // Packages change with most changes (a service brings its own); a newly
    // insecure one does not come from a catalog change.
    declared || base.inputs != cand.inputs || !cand.insecure.is_subset(&base.insecure)
}

/// §11 session facts, from logind's sessions: which sessions the disruption
/// lands on (sorted), and whether a system-scope session or connectivity loss
/// reaches a session of another uid than the caller's. A user unit lands on
/// its own session, or every session of its uid; a disruptive system unit on
/// every session.
pub fn session_facts(f: &mut DerivedFacts, sessions: &[SessionInfo]) {
    let live: Vec<&SessionInfo> = sessions.iter().filter(|s| s.establishes()).collect();
    let disruptive = f.disruption.session_loss || f.disruption.connectivity_loss || f.disruption.data_interruption;
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
        && (f.disruption.session_loss || f.disruption.connectivity_loss)
        && live.iter().any(|x| Some(x.uid) != caller);
    f.affected_sessions = hit.into_iter().collect();
}

/// §11: whether a RestartUnit restores a unit stopped outside Planarian and
/// not attributed: stopped by `systemctl stop` or a termination signal (not
/// a crash), under no override, and desired Running now. From systemd's state, never
/// from the proposal (I14).
pub fn stop_fact(f: &mut DerivedFacts, t: &Transition, s: &SystemState, defs: &UnitDefs, ended: Option<Ending>) {
    let Transition::RestartUnit(u) = t else { return };
    // Inactive after a `systemctl stop` (an orderly exit or a termination
    // signal), or failed with Result=signal from a termination signal
    // (kill -9). A crash, a non-zero exit or the OOM killer is a fault.
    // (Inactive, not failed, is a stop on request whatever the exit status:
    // sshd, for one, exits 255 on SIGTERM.)
    let stopped = match (s.units.get(u).map(|(o, _)| o), ended) {
        (Some(Observed::Bound), _) => true,
        (Some(Observed::Failed(_)), Some(e)) => e.is_termination(),
        _ => false,
    };
    f.restores_unattributed_stop = stopped
        && s.override_of(u).is_none()
        && s.expected(u, defs)
        && defs.get(u).is_some_and(|d| d.desired.status == DesiredStatus::Running);
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

#[cfg(test)]
mod sensitivity_completeness {
    use super::*;

    /// §11 (B-5): a system unit with no sensitivity entry, or none in the
    /// manifest, is not Routine; a user's own undeclared user unit is.
    #[test]
    fn unknown_units_fail_closed() {
        let mut defs = UnitDefs::new();
        let mut empty = planarian_fake::fixtures::gym_units()[&UnitId::service("gym-web")].clone();
        empty.id = UnitId::service("gym-untagged");
        empty.sensitivity = Sensitivities::default();
        defs.insert(empty.id.clone(), empty.clone());
        let none = BTreeMap::new();
        let (s, _) = unit_facts([&empty.id], &defs, &none, |_| false);
        assert!(s.external && !s.routine, "an empty sensitivity is External: {s:?}");
        let ghost = UnitId::service("not-in-the-manifest");
        let (s, _) = unit_facts([&ghost], &defs, &none, |_| false);
        assert!(s.external && !s.routine, "an undeclared system unit is External: {s:?}");
        // One NixOS defines has the shipped tables' entry instead.
        let tables = BTreeMap::from([
            ("dbus-broker".to_string(), Sensitivities::of(&[Sensitivity::Routine])),
            ("blank".to_string(), Sensitivities::default()),
        ]);
        let (s, _) = unit_facts([&UnitId::service("dbus-broker")], &defs, &tables, |_| false);
        assert!(s.routine && !s.external, "a defined service takes its table entry: {s:?}");
        let (s, _) = unit_facts([&UnitId::service("blank")], &defs, &tables, |_| false);
        assert!(s.external, "an empty table entry still fails closed: {s:?}");
        let own =
            UnitId { kind: UnitKind::Service, name: "notes".into(), scope: Scope::User { uid: 1000, session: None } };
        let (s, _) = unit_facts([&own], &defs, &none, |_| false);
        assert!(!s.external, "an undeclared user unit stays as it was: {s:?}");
    }

    /// §11 Rollback row (owner decision, Nov 2): a removed user template
    /// carries its own sensitivity, read from the base manifest (the per-session
    /// instances alone would miss it), and a removed or stopped system unit
    /// carries its own.
    #[test]
    fn removed_units_carry_their_sensitivity() {
        let mut vpn = planarian_fake::fixtures::gym_user_units()[0].clone();
        vpn.id.name = "user-vpn".into();
        vpn.sensitivity = Sensitivities::of(&[Sensitivity::Security]);
        let base = Manifest { units: planarian_fake::fixtures::gym_units(), user_units: vec![vpn.clone()] };
        let mut cand = base.clone();
        cand.user_units.clear();
        let none = BTreeMap::new();
        let (removed, each, s) = removed_units(&base, &cand, None, &UnitDefs::new(), &none);
        assert_eq!(removed, vec![vpn.id.clone()]);
        assert_eq!(each.len(), removed.len(), "parallel");
        assert!(each[0].security, "each carries its own: {each:?}");
        assert!(s.security, "the removed user template is Security: {s:?}");
        // Nothing removed: nothing carried.
        let (removed, each, s) = removed_units(&base, &base, None, &base.units, &none);
        assert!(removed.is_empty() && each.is_empty() && s == Sensitivities::default(), "{removed:?} {s:?}");
        // A unit the activation stops counts too.
        let web = UnitId::service("gym-web");
        let plan = ActivationPlan { stop: [web.clone()].into(), ..Default::default() };
        let (removed, each, _) = removed_units(&base, &base, Some(&plan), &base.units, &none);
        assert_eq!(removed, vec![web]);
        assert_eq!(each.len(), 1);
    }
}

// C19 (§9 manifest, §11 ApplyChange row): the reviewer's acceptance test.
#[cfg(test)]
#[path = "derive_c19_tests.rs"]
mod c19;
