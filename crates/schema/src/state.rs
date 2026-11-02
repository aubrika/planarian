//! Observed state, derived status, and the state digest (§8).

use crate::ids::{GenerationId, Hash, ProbeId, Timestamp};
use crate::unit::{Condition, Evidence, Override, OverrideDesired, ProbeResult, ProbeRole, UnitDefs, UnitId, UnitKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observed {
    /// Stale evidence, probe timeout, backend error.
    Unknown {
        since: Timestamp,
        reason: String,
    },
    Transitioning {
        from: Box<Observed>,
        since: Timestamp,
    },
    Absent,
    Detected,
    Bound,
    Active,
    Failed(Reason),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    ExitCode(i32),
    DriverError(String),
    Backend(String),
}

/// Derived, never stored as truth on its own.
///
/// `NotExpected` is not in §8. §8 says a unit whose desired condition does not
/// hold reports its observed status and opens no incident. Mapping such a unit
/// onto `Running` would break I4, so it gets a variant of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitStatus {
    Running,
    Degraded(Vec<ProbeId>),
    Stopped,
    Overridden(OverrideDesired),
    Unknown,
    Failed(Reason),
    Absent,
    Detected,
    Bound,
    Transitioning,
    NotExpected,
}

/// Host resources. Excluded from the digest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    pub mem_total_mb: u64,
    pub mem_available_mb: u64,
    /// Free bytes per storage unit (`device:fs-root`, ...).
    pub fs_free_bytes: BTreeMap<UnitId, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemState {
    pub generation: GenerationId,
    /// Boot-confirmed.
    pub known_good: GenerationId,
    /// Passed probes live, not yet rebooted.
    pub live_tested: Option<GenerationId>,
    /// Set by `mark-good --accept-unconfirmed`; never replaces `known_good` in the boot menu (§16, G3).
    pub accepted_baseline: Option<GenerationId>,
    /// §12e: derived when a generation commits, never set by a proposal.
    #[serde(default)]
    pub security_floor: Option<GenerationId>,
    pub units: BTreeMap<UnitId, (Observed, Vec<Evidence>)>,
    pub overrides: Vec<Override>,
    /// Atomic conditions that currently hold.
    pub conditions: BTreeSet<Condition>,
    /// Excluded from the digest.
    pub resources: Resources,
    pub core_hash: Hash,
    /// The reference time for staleness. Excluded from the digest.
    pub observed_at: Timestamp,
}

impl SystemState {
    /// The override holding `id` right now, if any.
    pub fn override_of(&self, id: &UnitId) -> Option<&Override> {
        self.overrides.iter().find(|s| &s.unit == id && s.holds_at(self.observed_at))
    }

    pub fn overridden(&self, id: &UnitId) -> bool {
        self.override_of(id).is_some()
    }

    /// Whether the unit is expected to be in its desired status right now:
    /// it is defined, its desired condition holds, and no override holds it.
    pub fn expected(&self, id: &UnitId, defs: &UnitDefs) -> bool {
        match defs.get(id) {
            Some(def) => !self.overridden(id) && def.desired.when.holds(&self.conditions),
            None => false,
        }
    }

    /// Readiness probes of `id` whose fresh evidence is a failure. For a
    /// device this is what `status` leaves out: §8 derives a bound device's
    /// status from `Observed` alone, so one bound to a driver that cannot
    /// drive it still reads Bound.
    pub fn failing_readiness(&self, id: &UnitId, defs: &UnitDefs) -> Vec<ProbeId> {
        let (Some(def), Some((_, evidence))) = (defs.get(id), self.units.get(id)) else { return vec![] };
        def.probes
            .iter()
            .filter(|p| p.role == ProbeRole::Readiness)
            .filter(|p| {
                evidence
                    .iter()
                    .filter(|e| e.probe == p.id)
                    .max_by_key(|e| e.at)
                    .is_some_and(|e| e.fresh_at(self.observed_at) && matches!(e.result, ProbeResult::Fail(_)))
            })
            .map(|p| p.id.clone())
            .collect()
    }

    /// The applicable Readiness probes whose latest evidence is a fresh pass
    /// (§9: what a change may not take away, whatever the unit's status).
    pub fn passing_readiness(&self, id: &UnitId, defs: &UnitDefs) -> Vec<ProbeId> {
        let (Some(def), Some((_, evidence))) = (defs.get(id), self.units.get(id)) else { return vec![] };
        def.probes
            .iter()
            .filter(|p| p.role == ProbeRole::Readiness)
            .filter(|p| {
                evidence
                    .iter()
                    .filter(|e| e.probe == p.id)
                    .max_by_key(|e| e.at)
                    .is_some_and(|e| e.fresh_at(self.observed_at) && matches!(e.result, ProbeResult::Pass))
            })
            .map(|p| p.id.clone())
            .collect()
    }

    /// Status derivation, in the order §8 gives:
    /// Overridden; not expected; definite Failed; Unknown on stale or timed-out
    /// Readiness evidence; Running / Degraded from Active; otherwise from `Observed`.
    /// Diagnostic probes never affect the result.
    pub fn status(&self, id: &UnitId, defs: &UnitDefs) -> UnitStatus {
        if let Some(o) = self.override_of(id) {
            return UnitStatus::Overridden(o.desired);
        }
        let Some(def) = defs.get(id) else {
            return UnitStatus::NotExpected;
        };
        if !def.desired.when.holds(&self.conditions) {
            return UnitStatus::NotExpected;
        }
        let Some((observed, evidence)) = self.units.get(id) else {
            return UnitStatus::Unknown;
        };
        if let Observed::Failed(r) = observed {
            return UnitStatus::Failed(r.clone());
        }

        let mut failed = Vec::new();
        for probe in def.probes.iter().filter(|p| p.role == ProbeRole::Readiness) {
            let latest = evidence.iter().filter(|e| e.probe == probe.id).max_by_key(|e| e.at);
            match latest {
                Some(e) if e.fresh_at(self.observed_at) => match &e.result {
                    ProbeResult::Pass => {}
                    ProbeResult::Fail(_) => failed.push(probe.id.clone()),
                    ProbeResult::Timeout | ProbeResult::Abandoned | ProbeResult::Error(_) => {
                        return UnitStatus::Unknown;
                    }
                },
                _ => return UnitStatus::Unknown,
            }
        }

        match observed {
            Observed::Active if failed.is_empty() => UnitStatus::Running,
            Observed::Active => UnitStatus::Degraded(failed),
            Observed::Unknown { .. } => UnitStatus::Unknown,
            Observed::Transitioning { .. } => UnitStatus::Transitioning,
            Observed::Absent => UnitStatus::Absent,
            Observed::Detected => UnitStatus::Detected,
            // systemd `inactive` maps to Bound; for anything but a device that is
            // a stopped unit once desired state is considered (§8 systemd mapping).
            Observed::Bound if def.id.kind == UnitKind::Device => UnitStatus::Bound,
            Observed::Bound => UnitStatus::Stopped,
            Observed::Failed(_) => unreachable!("handled above"),
        }
    }

    /// Hash of everything that describes the system's state, excluding
    /// `resources` and all observation timestamps (`observed_at`, `Evidence::at`,
    /// `Unknown::since`, `Transitioning::since`). Two observations of an unchanged
    /// system therefore have the same digest. Override deadlines (`Until::At`)
    /// are desired-state data and are included.
    pub fn digest(&self) -> Hash {
        let view = DigestView {
            generation: self.generation,
            known_good: self.known_good,
            live_tested: self.live_tested,
            accepted_baseline: self.accepted_baseline,
            units: self
                .units
                .iter()
                .map(|(id, (obs, ev))| {
                    let mut results: Vec<(&ProbeId, &ProbeResult)> = ev.iter().map(|e| (&e.probe, &e.result)).collect();
                    results.sort_by(|a, b| a.0.cmp(b.0));
                    (id, ObservedView::of(obs), results)
                })
                .collect(),
            overrides: {
                let mut s: Vec<&Override> = self.overrides.iter().collect();
                s.sort();
                s
            },
            conditions: &self.conditions,
            core_hash: self.core_hash,
        };
        Hash::of(&serde_json::to_vec(&view).expect("digest view serializes"))
    }
}

type UnitView<'a> = (&'a UnitId, ObservedView<'a>, Vec<(&'a ProbeId, &'a ProbeResult)>);

#[derive(Serialize)]
struct DigestView<'a> {
    generation: GenerationId,
    known_good: GenerationId,
    live_tested: Option<GenerationId>,
    accepted_baseline: Option<GenerationId>,
    units: Vec<UnitView<'a>>,
    overrides: Vec<&'a Override>,
    conditions: &'a BTreeSet<Condition>,
    core_hash: Hash,
}

#[derive(Serialize, PartialEq)]
enum ObservedView<'a> {
    Unknown { reason: &'a str },
    Transitioning { from: Box<ObservedView<'a>> },
    Absent,
    Detected,
    Bound,
    Active,
    Failed(&'a Reason),
}

impl<'a> ObservedView<'a> {
    fn of(o: &'a Observed) -> ObservedView<'a> {
        match o {
            Observed::Unknown { reason, .. } => ObservedView::Unknown { reason },
            Observed::Transitioning { from, .. } => {
                ObservedView::Transitioning { from: Box::new(ObservedView::of(from)) }
            }
            Observed::Absent => ObservedView::Absent,
            Observed::Detected => ObservedView::Detected,
            Observed::Bound => ObservedView::Bound,
            Observed::Active => ObservedView::Active,
            Observed::Failed(r) => ObservedView::Failed(r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Millis;
    use crate::unit::*;

    fn probe(id: &str, role: ProbeRole) -> ProbeDef {
        ProbeDef {
            id: ProbeId(id.into()),
            kind: ProbeKind::SystemdActive,
            timeout: Millis::secs(10),
            origin: ProbeOrigin::Canonical,
            role,
            cadence: if role == ProbeRole::Readiness { Cadence::EveryTick } else { Cadence::OnDemand },
            cost: ProbeCost::Trivial,
            side_effects: if role == ProbeRole::Readiness { SideEffects::None } else { SideEffects::Audible },
            establishes: String::new(),
        }
    }

    fn def(id: &UnitId, when: Condition, probes: Vec<ProbeDef>) -> UnitDef {
        UnitDef {
            id: id.clone(),
            desired: Desired { status: DesiredStatus::Running, when },
            edges: vec![],
            sensitivity: Sensitivities::default(),
            restart_disruption: Disruption::Brief,
            probes,
            synonyms: vec![],
            systemd_restart: None,
            startup_grace: None,
            runtime_repair: None,
            stops_are_faults: false,
        }
    }

    fn ev(id: &str, result: ProbeResult, at: u64) -> Evidence {
        Evidence { probe: ProbeId(id.into()), result, at: Timestamp(at), stale_after: Millis(30_000) }
    }

    fn state(now: u64) -> SystemState {
        SystemState {
            generation: GenerationId(2),
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

    fn web() -> (UnitId, UnitDefs) {
        let id = UnitId::service("gym-web");
        let d = def(
            &id,
            Condition::Always,
            vec![probe("http", ProbeRole::Readiness), probe("tone", ProbeRole::Diagnostic)],
        );
        (id.clone(), [(id, d)].into())
    }

    #[test]
    fn running_needs_fresh_readiness_only() {
        let (id, defs) = web();
        let mut s = state(100_000);
        // Diagnostic evidence is long stale; it must not matter (catalog: probe-diagnostic-stale-healthy).
        s.units.insert(
            id.clone(),
            (Observed::Active, vec![ev("http", ProbeResult::Pass, 90_000), ev("tone", ProbeResult::Pass, 1)]),
        );
        assert_eq!(s.status(&id, &defs), UnitStatus::Running);
        s.observed_at = Timestamp(200_000);
        assert_eq!(s.status(&id, &defs), UnitStatus::Unknown);
    }

    #[test]
    fn failed_beats_stale() {
        // Catalog: probe-failed-beats-stale.
        let (id, defs) = web();
        let mut s = state(1_000_000);
        s.units.insert(id.clone(), (Observed::Failed(Reason::ExitCode(137)), vec![ev("http", ProbeResult::Pass, 1)]));
        assert_eq!(s.status(&id, &defs), UnitStatus::Failed(Reason::ExitCode(137)));
    }

    #[test]
    fn timeout_is_unknown_not_failed() {
        let (id, defs) = web();
        let mut s = state(100_000);
        s.units.insert(id.clone(), (Observed::Active, vec![ev("http", ProbeResult::Timeout, 99_000)]));
        assert_eq!(s.status(&id, &defs), UnitStatus::Unknown);
    }

    #[test]
    fn degraded_and_stopped() {
        let (id, defs) = web();
        let mut s = state(100_000);
        s.units.insert(id.clone(), (Observed::Active, vec![ev("http", ProbeResult::Fail("503".into()), 99_000)]));
        assert_eq!(s.status(&id, &defs), UnitStatus::Degraded(vec![ProbeId("http".into())]));
        s.units.insert(id.clone(), (Observed::Bound, vec![ev("http", ProbeResult::Fail("refused".into()), 99_000)]));
        assert_eq!(s.status(&id, &defs), UnitStatus::Stopped);
    }

    #[test]
    fn suppressed_and_not_expected() {
        let id = UnitId::target("graphical-session");
        let defs: UnitDefs =
            [(id.clone(), def(&id, Condition::SessionEstablished { uid: None, seated: false }, vec![]))].into();
        let mut s = state(100_000);
        s.units.insert(id.clone(), (Observed::Bound, vec![]));
        // Idle greeter: nobody logged in (catalog: login-greeter-idle).
        assert_eq!(s.status(&id, &defs), UnitStatus::NotExpected);
        assert!(!s.expected(&id, &defs));
        s.conditions.insert(Condition::SessionEstablished { uid: Some(1000), seated: false });
        assert_eq!(s.status(&id, &defs), UnitStatus::Stopped);
        assert!(s.expected(&id, &defs));
        s.overrides.push(Override {
            unit: id.clone(),
            until: Until::At(Timestamp(200_000)),
            reason: String::new(),
            by: Actor::user(1000),
            desired: OverrideDesired::LeaveAlone,
            attribution: Attribution::Attested,
            acknowledged: false,
        });
        assert_eq!(s.status(&id, &defs), UnitStatus::Overridden(OverrideDesired::LeaveAlone));
        s.observed_at = Timestamp(200_000);
        assert_eq!(s.status(&id, &defs), UnitStatus::Stopped);
    }

    #[test]
    fn digest_ignores_timestamps_and_resources() {
        let (id, _) = web();
        let mut a = state(100_000);
        a.units.insert(id.clone(), (Observed::Active, vec![ev("http", ProbeResult::Pass, 99_000)]));
        let mut b = a.clone();
        b.observed_at = Timestamp(555_555);
        b.resources.mem_available_mb = 7;
        b.units.insert(id.clone(), (Observed::Active, vec![ev("http", ProbeResult::Pass, 1)]));
        assert_eq!(a.digest(), b.digest());
        b.units.insert(id.clone(), (Observed::Active, vec![ev("http", ProbeResult::Fail("x".into()), 1)]));
        assert_ne!(a.digest(), b.digest());
        let mut c = a.clone();
        c.generation = GenerationId(3);
        assert_ne!(a.digest(), c.digest());
    }

    /// §18.4, over random states: perturbing resources or any observation
    /// timestamp never changes the digest; changing what the state says
    /// always does.
    mod digest_props {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::{Config, FailurePersistence};

        fn observed() -> impl Strategy<Value = Observed> {
            prop_oneof![
                Just(Observed::Active),
                Just(Observed::Bound),
                Just(Observed::Absent),
                (0..3i32).prop_map(|c| Observed::Failed(Reason::ExitCode(c))),
                "[a-c]{1,3}".prop_map(|r| Observed::Unknown { since: Timestamp(1), reason: r }),
                Just(Observed::Transitioning { from: Box::new(Observed::Active), since: Timestamp(1) }),
            ]
        }

        fn result() -> impl Strategy<Value = ProbeResult> {
            prop_oneof![Just(ProbeResult::Pass), Just(ProbeResult::Timeout), "[xy]{1,2}".prop_map(ProbeResult::Fail)]
        }

        prop_compose! {
            fn system()(
                generation in 1..4u64,
                units in proptest::collection::btree_map(
                    "[a-d]{1,2}",
                    (observed(), proptest::collection::vec(("[pq]", result()), 0..3)),
                    0..4,
                ),
            ) -> SystemState {
                let mut s = state(1_000);
                s.generation = GenerationId(generation);
                for (name, (o, ev)) in units {
                    let ev = ev.into_iter().map(|(p, r)| super::ev(&p, r, 900)).collect();
                    s.units.insert(UnitId::service(&name), (o, ev));
                }
                s
            }
        }

        /// Every timestamp and resource figure in the state, moved.
        fn perturb(s: &SystemState, by: u64) -> SystemState {
            let mut t = s.clone();
            t.observed_at = Timestamp(t.observed_at.0 + by);
            t.resources.mem_available_mb += by;
            t.resources.mem_total_mb += 2 * by;
            for (o, ev) in t.units.values_mut() {
                match o {
                    Observed::Unknown { since, .. } | Observed::Transitioning { since, .. } => since.0 += by,
                    _ => {}
                }
                for e in ev {
                    e.at.0 += by;
                }
            }
            t
        }

        proptest! {
            #![proptest_config(Config { cases: 256, failure_persistence: None::<Box<dyn FailurePersistence>>, ..Config::default() })]

            #[test]
            fn timestamps_and_resources_do_not_count(s in system(), by in 1..1_000_000u64) {
                prop_assert_eq!(s.digest(), perturb(&s, by).digest());
            }

            #[test]
            fn what_the_state_says_does(s in system(), o in observed()) {
                let mut t = s.clone();
                t.generation = GenerationId(s.generation.0 + 10);
                prop_assert_ne!(s.digest(), t.digest());
                let mut u = s.clone();
                u.overrides.push(Override {
                    unit: UnitId::service("z"),
                    until: Until::Explicit,
                    reason: String::new(),
                    by: Actor::Daemon,
                    desired: OverrideDesired::LeaveAlone,
                    attribution: Attribution::Attested,
                    acknowledged: false,
                });
                prop_assert_ne!(s.digest(), u.digest());
                if let Some((id, (old, ev))) = s.units.iter().next() {
                    let same = ObservedView::of(old) == ObservedView::of(&o);
                    let mut v = s.clone();
                    v.units.insert(id.clone(), (o, ev.clone()));
                    prop_assert_eq!(s.digest() == v.digest(), same);
                }
            }
        }
    }
}
