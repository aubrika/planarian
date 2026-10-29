use super::*;
use planarian_schema::fixtures::*;
use planarian_schema::*;

fn incident(target: &UnitId) -> Incident {
    Incident {
        id: IncidentId(1),
        kind: IncidentKind::Repair,
        target: target.clone(),
        divergence: (DesiredStatus::Running, UnitStatus::Stopped),
        opened: Timestamp(0),
        attempts: vec![],
        budget_left: 3,
        state: IncidentState::Open,
        backoff: Millis::secs(10),
        next_attempt: Timestamp(0),
        regressions: 0,
    }
}

struct World {
    defs: UnitDefs,
    s: SystemState,
    failed_since: BTreeMap<UnitId, Timestamp>,
    drivers: BTreeMap<UnitId, DriverRef>,
    alternatives: BTreeMap<String, Vec<Value>>,
}

impl World {
    fn new(defs: UnitDefs) -> World {
        let mut s = empty_state(1000);
        healthy(&mut s, &defs);
        World { defs, s, failed_since: BTreeMap::new(), drivers: BTreeMap::new(), alternatives: BTreeMap::new() }
    }
    fn fail(&mut self, u: &str, at: u64) {
        let id: UnitId = u.parse().unwrap();
        observe(&mut self.s, &self.defs, &id, Observed::Failed(Reason::ExitCode(1)), ProbeResult::Fail("x".into()));
        self.failed_since.insert(id, Timestamp(at));
    }
    fn inputs(&self) -> Inputs<'_> {
        Inputs {
            state: &self.s,
            defs: &self.defs,
            failed_since: &self.failed_since,
            known_drivers: &self.drivers,
            current_planarian_built: false,
            alternatives: &self.alternatives,
        }
    }
}

fn gym() -> UnitDefs {
    let db = service("gym-db");
    let cache = service("gym-cache");
    let metrics = service("gym-metrics");
    let mut app = service("gym-app");
    edge(&mut app, "gym-db", EdgeKind::Requires);
    edge(&mut app, "gym-cache", EdgeKind::Ordering);
    edge(&mut app, "gym-metrics", EdgeKind::Wants);
    defs([db, cache, metrics, app])
}

#[test]
fn dep_required_stopped_targets_the_dependency() {
    let mut w = World::new(gym());
    w.fail("service:gym-db", 10);
    let id: UnitId = "service:gym-app".parse().unwrap();
    observe(&mut w.s, &w.defs, &id, Observed::Bound, ProbeResult::Fail("refused".into()));
    let c = candidates(&incident(&id), &w.inputs());
    assert_eq!(c[0].transition, Transition::RestartUnit(UnitId::service("gym-db")));
    assert_eq!(c[0].target, UnitId::service("gym-db"));
}

#[test]
fn ordering_and_wants_are_never_followed() {
    let mut w = World::new(gym());
    w.fail("service:gym-cache", 10);
    w.fail("service:gym-metrics", 10);
    let app: UnitId = "service:gym-app".parse().unwrap();
    observe(&mut w.s, &w.defs, &app, Observed::Failed(Reason::ExitCode(1)), ProbeResult::Fail("x".into()));
    assert_eq!(root_cause(&app, &w.inputs()), app, "no false root cause");
}

#[test]
fn cycles_pick_the_earliest_failure() {
    let mut a = service("a");
    let mut b = service("b");
    let mut c = service("c");
    edge(&mut a, "b", EdgeKind::Requires);
    edge(&mut b, "c", EdgeKind::Requires);
    edge(&mut c, "b", EdgeKind::Diagnostic { confidence: Confidence(900) });
    let mut w = World::new(defs([a, b, c]));
    w.fail("service:a", 5);
    w.fail("service:b", 30);
    w.fail("service:c", 20);
    assert_eq!(root_cause(&UnitId::service("a"), &w.inputs()), UnitId::service("c"));
    // A weak diagnostic edge is not walked.
    let mut a = service("a");
    edge(&mut a, "b", EdgeKind::Diagnostic { confidence: Confidence(500) });
    let mut w = World::new(defs([a, service("b")]));
    w.fail("service:a", 5);
    w.fail("service:b", 1);
    assert_eq!(root_cause(&UnitId::service("a"), &w.inputs()), UnitId::service("a"));
}

#[test]
fn driver_unbound_root_is_the_device() {
    let snd: UnitId = "device:snd-hda0".parse().unwrap();
    let mut pw = service("service@1000:pipewire");
    edge(&mut pw, "device:snd-hda0", EdgeKind::Requires);
    let mut w = World::new(defs([service("device:snd-hda0"), pw]));
    w.drivers.insert(snd.clone(), DriverRef { name: "snd_hda_intel".into(), module: None });
    observe(&mut w.s, &w.defs, &snd, Observed::Detected, ProbeResult::Fail("no driver".into()));
    let pwid: UnitId = "service@1000:pipewire".parse().unwrap();
    observe(&mut w.s, &w.defs, &pwid, Observed::Active, ProbeResult::Fail("no sink".into()));
    let c = candidates(&incident(&pwid), &w.inputs());
    assert!(matches!(&c[0].transition, Transition::BindDriver { device, .. } if *device == snd), "{c:?}");
}

#[test]
fn external_dependency_gets_no_local_repair() {
    let ext: UnitId = "service:external:gym-upstream".parse().unwrap();
    let mut client = service("gym-upstream-client");
    edge(&mut client, "service:external:gym-upstream", EdgeKind::Requires);
    let mut w = World::new(defs([service("service:external:gym-upstream"), client]));
    observe(&mut w.s, &w.defs, &ext, Observed::Active, ProbeResult::Fail("connection refused".into()));
    let cl = UnitId::service("gym-upstream-client");
    observe(&mut w.s, &w.defs, &cl, Observed::Active, ProbeResult::Fail("upstream 502".into()));
    assert_eq!(root_cause(&cl, &w.inputs()), ext);
    assert!(candidates(&incident(&cl), &w.inputs()).is_empty(), "exhausted → report, never a local restart");
}

#[test]
fn storage_gc_and_owner_built_never_rolls_back() {
    let fs: UnitId = "device:fs-nix".parse().unwrap();
    let mut w = World::new(defs([service("device:fs-nix"), service("gym-web")]));
    observe(&mut w.s, &w.defs, &fs, Observed::Bound, ProbeResult::Fail("1.2 GB free".into()));
    let c = candidates(&incident(&fs), &w.inputs());
    assert_eq!(c[0].transition, Transition::CollectGarbage { emergency: true });

    w.s.generation = GenerationId(7);
    w.fail("service:gym-web", 1);
    let web = UnitId::service("gym-web");
    let owner_built = candidates(&incident(&web), &w.inputs());
    assert!(owner_built.iter().all(|c| c.transition != Transition::Rollback));
    let mut i = w.inputs();
    i.current_planarian_built = true;
    let ours = candidates(&incident(&web), &i);
    assert_eq!(ours.last().unwrap().transition, Transition::Rollback, "rollback last");
    assert_eq!(ours[0].transition, Transition::RestartUnit(web));
}

#[test]
fn suppressed_root_is_never_a_target() {
    let mut w = World::new(gym());
    w.fail("service:gym-db", 1);
    w.s.overrides.push(Override {
        unit: UnitId::service("gym-db"),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::user(0),
        desired: OverrideDesired::LeaveAlone,
        attribution: Attribution::Attested,
    });
    let app = UnitId::service("gym-app");
    observe(&mut w.s, &w.defs, &app, Observed::Bound, ProbeResult::Fail("x".into()));
    assert!(candidates(&incident(&app), &w.inputs()).iter().all(|c| c.target != UnitId::service("gym-db")));
}
