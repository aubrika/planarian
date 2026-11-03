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
//!   any caller, an override that stops, removes or detaches it derives the
//!   facts a stop of it derives.

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
        prop_assert_eq!(&a.affected_units, &b.affected_units, "{:?}", unit);
        prop_assert_eq!(&a.disruption, &b.disruption, "{:?}", unit);
        prop_assert_eq!(&a.sensitivity, &b.sensitivity, "{:?}", unit);
        prop_assert_eq!(&a.recovery, &b.recovery, "{:?}", unit);
        prop_assert_eq!(a.touches_core, b.touches_core);
    }
}
