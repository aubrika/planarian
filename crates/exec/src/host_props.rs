//! Property tests for the executor's post-check, `ExecHost::violations`
//! (catch-up coverage, `docs/regression-ledger.md` C4 and C5).
//! `PROPTEST_CASES` goes deeper.
//!
//! - C4 (R07, `ff11187`): a unit already Degraded could lose another
//!   Readiness probe and the change still committed: the check compared the
//!   unit's aggregate status only. Stated whole: whatever the unit's status
//!   before and now, a Readiness probe that passed before and fails now is a
//!   violation (outside a revert whose only failing probes are free-space
//!   ones, §12 ENOSPC), and when nothing was lost from a unit that was not
//!   Running before, the unit raises none.
//! - C5 (before the clone's history): a driver that binds but cannot drive
//!   the device passed the check. Stated whole: a device expected Bound has
//!   a violation exactly when one of its Readiness probes fails.

use super::*;
use planarian_schema::fixtures::empty_state;
use proptest::prelude::*;
use proptest::test_runner::Config;
use std::collections::{BTreeMap, BTreeSet};

fn config() -> Config {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(256);
    Config { cases, failure_persistence: None, ..Config::default() }
}

const NOW: u64 = 1_000_000;

fn host() -> ExecHost<planarian_fake::Fake> {
    let store = planarian_fake::MemStore::new(1 << 16);
    ExecHost::new(planarian_fake::gym_world(store), planarian_fake::fixtures::canonical())
}

/// A transaction with nothing to say but what a test puts in `check` and
/// `expected`: no candidate, so no generation is required.
fn txn(check: CheckContext, expected: BTreeMap<UnitId, UnitStatus>) -> Transaction {
    let transition = Transition::RestartUnit(UnitId::service("gym-web"));
    Transaction {
        id: TxnId(1),
        state: TxnState::Checking,
        lease: Lease {
            txn: TxnId(1),
            owner: OwnerId::Daemon { pid: 1, boot_id: Hash::ZERO },
            epoch: 1,
            worker_pid: None,
            renewed: Timestamp(NOW),
            jobs: vec![],
        },
        base_source: None,
        staged_source: None,
        candidate_nar: None,
        base_override: None,
        candidate_override: None,
        gc_root: None,
        recovery: transition.recovery(),
        facts: DerivedFacts {
            affected_units: vec![],
            sensitivity: Sensitivities::default(),
            disruption: Disruptions::default(),
            recovery: Recovery::Idempotent,
            touches_manifest: false,
            touches_canonical_probe: false,
            changes_desired: false,
            touches_core: false,
            below_security_floor: false,
            journal_incompatibility: Vec::new(),
            other_sessions_affected: false,
            affected_sessions: vec![],
            restores_unattributed_stop: false,
            restarts_failed_unit: false,
            removes_sensitivity: Sensitivities::default(),
            removes: vec![],
            removes_each: vec![],
            restarts_held_unit: false,
            caller: Actor::Daemon,
            config_diff: None,
        },
        transition,
        base: GenerationId(1),
        candidate: None,
        policy: PolicyVersion(Hash::ZERO),
        approval: None,
        snapshot: None,
        expected: Expectation {
            units: expected,
            generation: None,
            may_change: BTreeSet::new(),
            others_unchanged: true,
            settle: Settle::Duration(Millis::secs(15)),
        },
        started: Timestamp(NOW),
        deadline: Timestamp(NOW + 900_000),
        revert_to: GenerationId(1),
        prior_driver: None,
        check,
        prepared_again_from: None,
    }
}

/// The fixture's units, and one more whose Readiness includes a free-space
/// probe (`gym-store`: a TCP probe and `gym-store-space`), so the revert's
/// space exception (§12, `space_only`) is reached.
fn with_store(mut defs: UnitDefs) -> UnitDefs {
    let mut store = defs[&UnitId::service("gym-db")].clone();
    store.id = UnitId::service("gym-store");
    let mut space = store.probes[0].clone();
    space.id = ProbeId("gym-store-space".into());
    space.kind = ProbeKind::FreeSpace { path: "/var/lib/gym-store".into(), min_bytes: 1 << 20, min_permille: 50 };
    store.probes.push(space);
    defs.insert(store.id.clone(), store);
    defs
}

/// The fixture's units that have Readiness probes, with them.
fn readiness_units(defs: &UnitDefs, devices: bool) -> Vec<(UnitId, Vec<ProbeId>)> {
    defs.values()
        .filter(|d| (d.id.kind == UnitKind::Device) == devices)
        .map(|d| {
            (
                d.id.clone(),
                d.probes.iter().filter(|p| p.role == ProbeRole::Readiness).map(|p| p.id.clone()).collect::<Vec<_>>(),
            )
        })
        .filter(|(_, ps)| !ps.is_empty())
        .collect()
}

/// The state: `u` observed as `o`, each probe's latest result fresh.
fn state(u: &UnitId, o: Observed, results: &[(ProbeId, bool)]) -> SystemState {
    let mut s = empty_state(NOW);
    let ev = results
        .iter()
        .map(|(p, pass)| Evidence {
            probe: p.clone(),
            result: if *pass { ProbeResult::Pass } else { ProbeResult::Fail("down".into()) },
            at: Timestamp(NOW - 1_000),
            stale_after: Millis::secs(60),
        })
        .collect();
    s.units.insert(u.clone(), (o, ev));
    s
}

fn before() -> impl Strategy<Value = UnitStatus> {
    prop_oneof![
        Just(UnitStatus::Running),
        Just(UnitStatus::Degraded(vec![])),
        Just(UnitStatus::Failed(Reason::ExitCode(1))),
        Just(UnitStatus::Stopped),
    ]
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn a_readiness_probe_lost_is_a_violation(
        which in any::<prop::sample::Index>(),
        // Often the unit with a free-space probe, so the space exception is
        // reached in both phases.
        store in prop::bool::weighted(0.3),
        was in before(),
        passed_before in any::<u8>(),
        passes_now in any::<u8>(),
        phase in prop_oneof![Just(CheckPhase::Candidate), Just(CheckPhase::Revert)],
    ) {
        let defs = with_store(planarian_fake::fixtures::gym_units());
        let units = readiness_units(&defs, false);
        let (u, probes) = if store {
            units.iter().find(|(u, _)| u.name == "gym-store").expect("gym-store").clone()
        } else {
            units[which.index(units.len())].clone()
        };
        let bit = |m: u8, i: usize| m & (1 << (i % 8)) != 0;
        let before: Vec<ProbeId> = probes.iter().enumerate().filter(|(i, _)| bit(passed_before, *i)).map(|(_, p)| p.clone()).collect();
        let now: Vec<(ProbeId, bool)> = probes.iter().enumerate().map(|(i, p)| (p.clone(), bit(passes_now, i))).collect();
        let s = state(&u, Observed::Active, &now);
        let check = CheckContext {
            candidate: None,
            base: Manifest { units: defs.clone(), user_units: vec![] },
            pre: [(u.clone(), was.clone())].into(),
            pre_passing: [(u.clone(), before.clone())].into(),
        };
        let v = host().violations(&txn(check, BTreeMap::new()), phase, &s, &defs);
        let lost: Vec<&ProbeId> = before.iter().filter(|p| now.iter().any(|(q, ok)| q == *p && !ok)).collect();
        // §12 (ENOSPC): a revert neither causes nor cures a full filesystem,
        // so when every failing Readiness probe is a free-space one, a revert
        // reports no probe lost; the storage units' incidents take it.
        let failing: Vec<&ProbeId> = now.iter().filter(|(_, ok)| !ok).map(|(p, _)| p).collect();
        let space_only = !failing.is_empty() && failing.iter().all(|p| p.0.ends_with("-space"));
        if phase == CheckPhase::Revert && space_only {
            prop_assert!(
                !v.iter().any(|m| m.contains("passed before and fails now")),
                "{u}: a revert with only space probes failing reported a lost probe: {v:?}"
            );
        } else if !lost.is_empty() {
            prop_assert!(!v.is_empty(), "{u}, {was:?} before: lost {lost:?} and no violation");
        } else if was != UnitStatus::Running {
            prop_assert!(v.is_empty(), "{u}, {was:?} before, nothing lost: {v:?}");
        }
    }

    #[test]
    fn a_bound_device_whose_readiness_fails_is_a_violation(
        which in any::<prop::sample::Index>(),
        passes_now in any::<u8>(),
    ) {
        let defs = planarian_fake::fixtures::gym_units();
        let devices = readiness_units(&defs, true);
        prop_assume!(!devices.is_empty());
        let (u, probes) = devices[which.index(devices.len())].clone();
        let now: Vec<(ProbeId, bool)> = probes.iter().enumerate().map(|(i, p)| (p.clone(), passes_now & (1 << (i % 8)) != 0)).collect();
        let s = state(&u, Observed::Bound, &now);
        let check = CheckContext { candidate: None, base: Manifest { units: defs.clone(), user_units: vec![] }, pre: BTreeMap::new(), pre_passing: BTreeMap::new() };
        let v = host().violations(&txn(check, [(u.clone(), UnitStatus::Bound)].into()), CheckPhase::Candidate, &s, &defs);
        let failing = now.iter().any(|(_, ok)| !ok);
        prop_assert_eq!(!v.is_empty(), failing, "{} bound, probes {:?}: {:?}", u, now, v);
    }
}
