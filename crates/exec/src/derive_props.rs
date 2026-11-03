//! Property tests for `derive`'s folds (catch-up coverage,
//! `docs/regression-ledger.md`). `PROPTEST_CASES` goes deeper.
//!
//! - C1 (C10, #21/#27): `restart_disruption` was folded with `max` over
//!   `Disruption`'s order, so ConnectivityLoss + DataInterruption kept only
//!   ConnectivityLoss and a seated user escaped the DataInterruption floor
//!   (§11). Stated whole: the disruption is exactly the set of the touched
//!   units' own kinds, less the already-failed units', and the sensitivity
//!   is the union of theirs (failing closed on an empty one).
//! - C3 (R03, `20d4f2c`; rule 20): an override that stops a unit derived
//!   `disruption = None` over the unit alone, so an administrator could dodge
//!   a stop's floor (SessionLoss on the display manager) by asking for an
//!   override instead. Stated whole: for any unit, any observation of it and
//!   any caller, an override that stops it derives the facts a stop of it
//!   derives, one that removes or detaches it at least those (§11), and
//!   only `LeaveAlone` derives no effect.

use super::*;
use proptest::prelude::*;
use proptest::test_runner::Config;

fn config() -> Config {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(256);
    Config { cases, failure_persistence: None, ..Config::default() }
}

fn disruption() -> impl Strategy<Value = Disruption> {
    prop_oneof![
        Just(Disruption::None),
        Just(Disruption::Brief),
        Just(Disruption::SessionLoss),
        Just(Disruption::DataInterruption),
        Just(Disruption::ConnectivityLoss),
    ]
}

fn sensitivities() -> impl Strategy<Value = Sensitivities> {
    any::<[bool; 5]>().prop_map(|[routine, security, user_data, external, core]| Sensitivities {
        routine,
        security,
        user_data,
        external,
        core,
    })
}

/// A declared system unit: its restart disruption, its sensitivity, and
/// whether it has already failed in the observation.
fn unit() -> impl Strategy<Value = (Disruption, Sensitivities, bool)> {
    (disruption(), sensitivities(), any::<bool>())
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn the_disruption_is_every_touched_units_own_kind(units in proptest::collection::vec(unit(), 0..6)) {
        let template = planarian_fake::fixtures::gym_units()[&UnitId::service("gym-web")].clone();
        let mut defs = UnitDefs::new();
        let mut failed = BTreeSet::new();
        let mut ids = Vec::new();
        for (k, (d, s, f)) in units.iter().enumerate() {
            let mut def = template.clone();
            def.id = UnitId::service(&format!("u{k}"));
            def.restart_disruption = *d;
            def.sensitivity = *s;
            if *f {
                failed.insert(def.id.clone());
            }
            ids.push(def.id.clone());
            defs.insert(def.id.clone(), def);
        }
        let none = BTreeMap::new();
        let (sens, got) = unit_facts(ids.iter(), &defs, &none, |u| failed.contains(u));

        let mut expect = Disruptions::default();
        for (d, _, f) in &units {
            if !f {
                expect.insert(*d);
            }
        }
        prop_assert_eq!(&got, &expect, "units {:?}", units);
        // Each kind keeps its own floor: every one a live unit carries is a member.
        for (d, _, f) in &units {
            if !f && *d != Disruption::None {
                prop_assert!(got.members().contains(d), "{:?} lost from {:?}", d, got);
            }
        }

        let empty = |s: &Sensitivities| !(s.routine || s.security || s.user_data || s.external || s.core);
        let external = Sensitivities::of(&[Sensitivity::External]);
        let mut want = Sensitivities::default();
        for (_, s, _) in &units {
            want = want.union(if empty(s) { &external } else { s });
        }
        prop_assert_eq!(sens, want, "sensitivity counts for failed units too: {:?}", units);
    }
}

fn eval(units: UnitDefs) -> EvaluatedGeneration {
    EvaluatedGeneration {
        source: Hash::ZERO,
        options: BTreeMap::new(),
        units,
        user_units: planarian_fake::fixtures::gym_user_units(),
        activation: ActivationPlan::default(),
        locked: BTreeSet::new(),
        core_units: BTreeMap::new(),
        packages: BTreeMap::new(),
        insecure: BTreeSet::new(),
        declarations: BTreeMap::new(),
        inputs: BTreeMap::new(),
        services: BTreeMap::new(),
    }
}

fn facts_of(t: &Transition, defs: &UnitDefs, state: &SystemState, caller: Actor) -> DerivedFacts {
    let base = eval(defs.clone());
    let tables = Tables {
        catalog: Default::default(),
        runtime_allowlist: Default::default(),
        option_sensitivity: Vec::new(),
        model_catalog: Default::default(),
    };
    let canonical = planarian_fake::fixtures::canonical();
    derive(&DeriveInput {
        transition: t,
        defs,
        base: &base,
        candidate: None,
        activation: None,
        base_overrides: &OverrideSet::default(),
        candidate_overrides: None,
        caller,
        tables: &tables,
        canonical: &canonical,
        state,
    })
}

fn observed() -> impl Strategy<Value = Observed> {
    prop_oneof![
        Just(Observed::Active),
        Just(Observed::Bound),
        Just(Observed::Absent),
        (0..3i32).prop_map(|c| Observed::Failed(Reason::ExitCode(c))),
    ]
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn an_override_that_stops_derives_a_stops_facts(
        which in any::<prop::sample::Index>(),
        desired in prop_oneof![Just(OverrideDesired::Stopped), Just(OverrideDesired::Absent), Just(OverrideDesired::Detected)],
        o in observed(),
        uid in prop_oneof![Just(0u32), 1000..1002u32],
        explicit in any::<bool>(),
    ) {
        let defs = planarian_fake::fixtures::gym_units();
        let ids: Vec<UnitId> = defs.keys().cloned().collect();
        let unit = ids[which.index(ids.len())].clone();
        let mut state = planarian_schema::fixtures::empty_state(1_000);
        state.units.insert(unit.clone(), (o, Vec::new()));
        let until = if explicit { Until::Explicit } else { Until::NextBoot };
        let caller = Actor::user(uid);
        let stop = Transition::StopAndSuppress { unit: unit.clone(), until: until.clone(), reason: "r".into() };
        let over = Transition::SetOverride(Override {
            unit: unit.clone(),
            desired,
            until,
            reason: "r".into(),
            by: caller.clone(),
            attribution: Attribution::Attested,
            acknowledged: false,
        });
        let a = facts_of(&stop, &defs, &state, caller.clone());
        let b = facts_of(&over, &defs, &state, caller);
        if desired == OverrideDesired::Stopped {
            // An override that stops is a stop: the same facts (rule 20).
            prop_assert_eq!(&a.affected_units, &b.affected_units, "{:?}", unit);
            prop_assert_eq!(&a.disruption, &b.disruption, "{:?}", unit);
            prop_assert_eq!(&a.sensitivity, &b.sensitivity, "{:?}", unit);
            prop_assert_eq!(&a.recovery, &b.recovery, "{:?}", unit);
            prop_assert_eq!(a.touches_core, b.touches_core);
        } else {
            // §11: Absent and Detected "likewise carry the effects of the
            // disable or unbind they cause": at least a stop's, so a stop's
            // facts bound them from below; more is allowed.
            for u in &a.affected_units {
                prop_assert!(b.affected_units.contains(u), "{desired:?} on {unit:?} lost {u:?}");
            }
            for d in a.disruption.members() {
                prop_assert!(b.disruption.members().contains(&d), "{desired:?} on {unit:?} lost {d:?}");
            }
            prop_assert_eq!(b.sensitivity.union(&a.sensitivity), b.sensitivity, "{:?} on {:?}", desired, unit);
            prop_assert!(b.touches_core || !a.touches_core);
        }
    }

    /// §11: "Only `LeaveAlone` has no effect and no disruption": for any
    /// unit, observation and caller, it touches the unit alone and carries
    /// no disruption.
    #[test]
    fn leave_alone_has_no_effect(
        which in any::<prop::sample::Index>(),
        o in observed(),
        uid in prop_oneof![Just(0u32), 1000..1002u32],
    ) {
        let defs = planarian_fake::fixtures::gym_units();
        let ids: Vec<UnitId> = defs.keys().cloned().collect();
        let unit = ids[which.index(ids.len())].clone();
        let mut state = planarian_schema::fixtures::empty_state(1_000);
        state.units.insert(unit.clone(), (o, Vec::new()));
        let caller = Actor::user(uid);
        let t = Transition::SetOverride(Override {
            unit: unit.clone(),
            desired: OverrideDesired::LeaveAlone,
            until: Until::Explicit,
            reason: "r".into(),
            by: caller.clone(),
            attribution: Attribution::Attested,
            acknowledged: false,
        });
        let f = facts_of(&t, &defs, &state, caller);
        prop_assert_eq!(&f.affected_units, &vec![unit.clone()]);
        prop_assert!(f.disruption.is_none(), "LeaveAlone on {:?} carries {:?}", unit, f.disruption);
    }
}

/// One edit to one manifest entry, as a candidate generation's manifest
/// might differ from the base's: every field a manifest entry has (§9, and
/// the exported fields #10's C19 line names), or the entry added or removed.
fn edit_entry(d: &mut UnitDef, field: u8, k: u8) {
    let next = |n: u8, of: u8| (n + 1 + k % (of - 1)) % of;
    match field {
        0 => {
            let all = [DesiredStatus::Running, DesiredStatus::Stopped, DesiredStatus::Bound, DesiredStatus::Absent];
            let i = all.iter().position(|s| *s == d.desired.status).unwrap_or(0) as u8;
            d.desired.status = all[next(i, 4) as usize];
        }
        1 => {
            d.desired.when = if d.desired.when == Condition::Always {
                Condition::SessionEstablished { uid: Some(1000 + k as u32), seated: k.is_multiple_of(2) }
            } else {
                Condition::Always
            }
        }
        2 => d.edges.push(Edge {
            from: d.id.clone(),
            to: UnitId::service(&format!("dep-{k}")),
            kind: EdgeKind::Requires,
            origin: EdgeOrigin::Manifest,
        }),
        3 => match k % 5 {
            0 => d.sensitivity.routine = !d.sensitivity.routine,
            1 => d.sensitivity.security = !d.sensitivity.security,
            2 => d.sensitivity.user_data = !d.sensitivity.user_data,
            3 => d.sensitivity.external = !d.sensitivity.external,
            _ => d.sensitivity.core = !d.sensitivity.core,
        },
        4 => {
            let all = [
                Disruption::None,
                Disruption::Brief,
                Disruption::SessionLoss,
                Disruption::DataInterruption,
                Disruption::ConnectivityLoss,
            ];
            let i = all.iter().position(|x| *x == d.restart_disruption).unwrap_or(0) as u8;
            d.restart_disruption = all[next(i, 5) as usize];
        }
        5 => {
            // A user probe: one of the fixture's, as the owner's own.
            let mut p = planarian_fake::fixtures::canonical().into_values().flatten().next().expect("a fixture probe");
            p.origin = ProbeOrigin::User;
            p.id = ProbeId(format!("user-{k}"));
            d.probes.push(p);
        }
        6 => d.synonyms.push(format!("also-{k}")),
        7 => {
            d.systemd_restart = match &d.systemd_restart {
                None => Some(SystemdRestartPolicy {
                    restart: true,
                    restart_sec: Millis::secs(1 + k as u64),
                    start_limit_burst: 5,
                }),
                Some(_) => None,
            }
        }
        8 => d.startup_grace = if d.startup_grace.is_some() { None } else { Some(Millis::secs(1 + k as u64)) },
        9 => d.runtime_repair = if d.runtime_repair.is_some() { None } else { Some(format!("opt-{k}")) },
        10 => d.stops_are_faults = !d.stops_are_faults,
        11 => d.holds = !d.holds,
        12 => d.hold_allow.push(HoldEndpoint { address: format!("192.0.2.{k}"), port: 443, protocol: "tcp".into() }),
        _ => d.hold_interfaces.push(format!("wg{k}")),
    }
}

const FIELDS: u8 = 14;

fn manifest() -> Manifest {
    Manifest { units: planarian_fake::fixtures::gym_units(), user_units: planarian_fake::fixtures::gym_user_units() }
}

proptest! {
    #![proptest_config(config())]

    /// C2 (C19, #29): `touches_manifest` compared four fields of entries in
    /// both manifests, so a candidate that changed `desired`, the exported
    /// restart and grace fields, an added or removed entry, or any user-scope
    /// entry did not ask (§11 ApplyChange row). Stated whole: any edit to any
    /// field of any entry, system or user scope, and any added or removed
    /// entry, touches the manifest.
    #[test]
    fn every_edit_to_an_entry_touches_the_manifest(
        user in any::<bool>(),
        which in any::<prop::sample::Index>(),
        how in 0..FIELDS + 2,
        k in any::<u8>(),
    ) {
        let base = manifest();
        let mut cand = base.clone();
        if user {
            let i = which.index(cand.user_units.len());
            match how {
                f if f < FIELDS => edit_entry(&mut cand.user_units[i], f, k),
                f if f == FIELDS => {
                    cand.user_units.remove(i);
                }
                _ => {
                    let mut extra = cand.user_units[i].clone();
                    extra.id.name = format!("{}-extra-{k}", extra.id.name);
                    cand.user_units.push(extra);
                }
            }
        } else {
            let ids: Vec<UnitId> = cand.units.keys().cloned().collect();
            let id = ids[which.index(ids.len())].clone();
            match how {
                f if f < FIELDS => edit_entry(cand.units.get_mut(&id).unwrap(), f, k),
                f if f == FIELDS => {
                    cand.units.remove(&id);
                }
                _ => {
                    let mut extra = cand.units[&id].clone();
                    extra.id.name = format!("{}-extra-{k}", extra.id.name);
                    cand.units.insert(extra.id.clone(), extra);
                }
            }
        }
        prop_assert_ne!(&base, &cand, "the edit changes the manifest");
        prop_assert!(
            touches_manifest(&base, &cand, &ConfigDiff::default()),
            "edit {} ({}) of entry {:?} did not touch the manifest",
            how,
            if user { "user scope" } else { "system scope" },
            which
        );
    }

    /// The other side: a canonical probe's definition is `touches_canonical`'s
    /// (I10), not the manifest's; an edit to canonical probes alone, or no
    /// edit, does not touch the manifest.
    #[test]
    fn canonical_probes_alone_are_not_the_manifest(which in any::<prop::sample::Index>(), k in any::<u8>()) {
        let base = manifest();
        let mut cand = base.clone();
        prop_assert!(!touches_manifest(&base, &cand, &ConfigDiff::default()));
        let ids: Vec<UnitId> = cand.units.keys().cloned().collect();
        let d = cand.units.get_mut(&ids[which.index(ids.len())]).unwrap();
        let mut p = planarian_fake::fixtures::canonical().into_values().flatten().next().expect("a fixture probe");
        p.origin = ProbeOrigin::Canonical;
        p.id = ProbeId(format!("canonical-{k}"));
        d.probes.push(p);
        prop_assert!(!touches_manifest(&base, &cand, &ConfigDiff::default()));
    }
}

fn option_value() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        Just(None),
        Just(Some(Value::Bool(true))),
        Just(Some(Value::Bool(false))),
        "[a-c]{1,2}".prop_map(|s| Some(Value::Str(s))),
    ]
}

/// Option paths: one under a Security-sensitive tree, the rest Routine.
const PATHS: [&str; 4] = ["services.openssh.enable", "services.openssh.ports", "fonts.scale", "time.zone"];

fn options(values: &[Option<Value>]) -> BTreeMap<String, Value> {
    PATHS.iter().zip(values).filter_map(|(k, v)| v.clone().map(|v| (k.to_string(), v))).collect()
}

proptest! {
    #![proptest_config(config())]

    /// C11 (`3f24a2d`): a Rollback to a generation built outside Planarian
    /// (no recorded override) compared only the overrides, so one that only
    /// restored a Security-sensitive option did not ask. Stated whole: for a
    /// switch, revert or rollback with no overrides recorded, and any option
    /// sets on either side, the facts' diff is exactly the options set
    /// differently, and the facts are Security exactly when one of those is.
    #[test]
    fn a_generation_transition_carries_every_option_it_changes(
        before in proptest::collection::vec(option_value(), 4),
        after in proptest::collection::vec(option_value(), 4),
        t in prop_oneof![
            Just(Transition::Rollback),
            Just(Transition::SwitchGeneration(GenerationId(1))),
            Just(Transition::Revert { to: GenerationId(1) }),
        ],
    ) {
        let defs = planarian_fake::fixtures::gym_units();
        let mut base = eval(defs.clone());
        base.options = options(&before);
        let mut cand = eval(defs.clone());
        cand.options = options(&after);
        let tables = Tables {
            catalog: Default::default(),
            runtime_allowlist: Default::default(),
            option_sensitivity: vec![("services.openssh".into(), Sensitivities::of(&[Sensitivity::Security]))],
            model_catalog: Default::default(),
        };
        let canonical = planarian_fake::fixtures::canonical();
        let state = planarian_schema::fixtures::empty_state(1_000);
        let f = derive(&DeriveInput {
            transition: &t,
            defs: &defs,
            base: &base,
            candidate: Some(&cand),
            activation: None,
            base_overrides: &OverrideSet::default(),
            candidate_overrides: None,
            caller: Actor::user(0),
            tables: &tables,
            canonical: &canonical,
            state: &state,
        });
        let changed: Vec<&str> = PATHS
            .iter()
            .zip(before.iter().zip(&after))
            .filter(|(_, (b, a))| b != a)
            .map(|(k, _)| *k)
            .collect();
        let got: Vec<String> = f.config_diff.as_ref().map(|d| d.options.keys().cloned().collect()).unwrap_or_default();
        let mut want: Vec<String> = changed.iter().map(|s| s.to_string()).collect();
        want.sort();
        let mut got_sorted = got.clone();
        got_sorted.sort();
        prop_assert_eq!(got_sorted, want, "{:?}: {:?} → {:?}", t, before, after);
        let security = changed.iter().any(|k| k.starts_with("services.openssh"));
        prop_assert_eq!(f.sensitivity.security, security, "{:?}: {:?} → {:?}", t, before, after);
    }
}
