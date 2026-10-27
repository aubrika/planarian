use super::*;
use planarian_schema::fixtures::*;
use planarian_schema::*;

const T0: u64 = 1_000_000;
const TICK: u64 = 5_000;

struct Sim {
    m: Manager,
    defs: UnitDefs,
    s: SystemState,
}

impl Sim {
    fn new(defs: UnitDefs) -> Sim {
        let mut s = empty_state(T0);
        healthy(&mut s, &defs);
        Sim { m: Manager::default(), defs, s }
    }

    fn now(&self) -> Timestamp {
        self.s.observed_at
    }

    fn set(&mut self, unit: &str, observed: Observed, result: ProbeResult) {
        let id: UnitId = UnitId::service(unit);
        observe(&mut self.s, &self.defs, &id, observed, result);
    }

    /// Advance one tick, refreshing evidence timestamps, and run the manager.
    fn tick(&mut self) -> Vec<Incident> {
        self.s.observed_at = Timestamp(self.s.observed_at.0 + TICK);
        let now = self.s.observed_at;
        for (_, ev) in self.s.units.values_mut() {
            for e in ev.iter_mut() {
                e.at = now;
            }
        }
        let now = self.now();
        self.m.tick(now, &self.s, &self.defs)
    }

    fn ticks(&mut self, n: usize) {
        for _ in 0..n {
            self.tick();
        }
    }

    fn fail(&mut self, unit: &str) {
        self.set(unit, Observed::Failed(Reason::ExitCode(1)), ProbeResult::Fail("down".into()));
    }

    fn heal(&mut self, unit: &str) {
        self.set(unit, Observed::Active, ProbeResult::Pass);
    }

    fn active(&self, unit: &str) -> Option<&Incident> {
        self.m.active_for(&UnitId::service(unit))
    }
}

#[test]
fn opens_after_two_ticks_and_closes_after_stabilization() {
    let mut sim = Sim::new(defs([service("gym-web")]));
    sim.fail("gym-web");
    sim.tick();
    assert!(sim.active("gym-web").is_none(), "one tick is not enough");
    sim.tick();
    let inc = sim.active("gym-web").cloned().expect("opened");
    assert_eq!(sim.m.actionable(sim.now()).len(), 1);
    sim.m.record_attempt(inc.id, TxnId(1), Outcome::Succeeded, sim.now());
    sim.heal("gym-web");
    sim.ticks(59);
    assert!(sim.active("gym-web").is_some(), "still stabilizing");
    sim.ticks(2);
    assert!(sim.active("gym-web").is_none(), "closed after 5 min");
}

#[test]
fn flapping_spends_budget_with_backoff_then_cools_down() {
    let mut sim = Sim::new(defs([service("gym-flap")]));
    sim.fail("gym-flap");
    sim.ticks(2);
    let mut gaps = vec![];
    let mut last = None;
    for txn in 1..=3 {
        let id = sim.active("gym-flap").unwrap().id;
        // Wait until actionable.
        let mut waited = 0;
        while sim.m.actionable(sim.now()).is_empty() {
            sim.tick();
            waited += 1;
            assert!(waited < 200);
        }
        if let Some(l) = last {
            gaps.push(sim.now().0 - l);
        }
        last = Some(sim.now().0);
        sim.m.record_attempt(id, TxnId(txn), Outcome::Succeeded, sim.now());
        // Comes back for 30 s, then fails again.
        sim.heal("gym-flap");
        sim.ticks(6);
        sim.fail("gym-flap");
        sim.tick();
    }
    assert!(gaps[0] >= 10_000 && gaps[1] >= 60_000, "{gaps:?}");
    let inc = sim.active("gym-flap").unwrap();
    assert!(matches!(inc.state, IncidentState::Cooldown { .. }), "{:?}", inc.state);
    assert!(sim.m.actionable(sim.now()).is_empty());
    // After an hour: exactly one more attempt.
    for _ in 0..(3_600_000 / TICK as usize) {
        sim.tick();
    }
    let inc = sim.active("gym-flap").unwrap().clone();
    assert_eq!(inc.state, IncidentState::Open);
    assert_eq!(inc.budget_left, 1);
    sim.m.record_attempt(inc.id, TxnId(4), Outcome::Succeeded, sim.now());
    let inc = sim.active("gym-flap").unwrap();
    assert_eq!(inc.state, IncidentState::Cooldown { until: sim.now().plus(COOLDOWN_LATER) }, "then 6 h");
}

#[test]
fn regressions_escalate() {
    let mut sim = Sim::new(defs([service("gym-flap")]));
    for round in 0..4u8 {
        sim.fail("gym-flap");
        sim.ticks(2);
        let inc = sim.active("gym-flap").unwrap().clone();
        assert_eq!(inc.regressions, round);
        if round == ESCALATE_AT {
            assert!(matches!(inc.state, IncidentState::Escalated { .. }));
            assert!(sim.m.actionable(sim.now()).is_empty(), "no autonomous action while escalated");
            return;
        }
        sim.m.record_attempt(inc.id, TxnId(round as u64), Outcome::Succeeded, sim.now());
        sim.heal("gym-flap");
        sim.ticks(61); // just past stabilization → closed
        assert!(sim.active("gym-flap").is_none());
    }
    panic!("never escalated");
}

#[test]
fn suppression_closes_and_is_never_a_target() {
    let mut sim = Sim::new(defs([service("gym-web")]));
    sim.fail("gym-web");
    sim.ticks(2);
    assert!(sim.active("gym-web").is_some());
    sim.s.suppressions.push(Suppression {
        unit: UnitId::service("gym-web"),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::User { uid: 1000 },
    });
    sim.ticks(3);
    assert!(sim.active("gym-web").is_none());
    assert!(sim.m.actionable(sim.now()).is_empty());
}

#[test]
fn unknown_opens_diagnostic_never_repair() {
    let mut sim = Sim::new(defs([service("gym-web")]));
    sim.set("gym-web", Observed::Active, ProbeResult::Timeout);
    sim.ticks(2);
    assert!(sim.active("gym-web").is_none());
    sim.tick();
    let inc = sim.active("gym-web").unwrap();
    assert_eq!(inc.kind, IncidentKind::Diagnostic);
    assert!(sim.m.actionable(sim.now()).is_empty(), "a diagnostic incident never yields a repair");
    sim.heal("gym-web");
    sim.tick();
    assert!(sim.active("gym-web").is_none(), "closes once the evidence is definite and fine");
}

#[test]
fn defers_to_systemd_restart() {
    let mut d = service("gym-restartful");
    d.systemd_restart =
        Some(SystemdRestartPolicy { restart: true, restart_sec: Millis::secs(5), start_limit_burst: 3 });
    let mut sim = Sim::new(defs([d]));
    sim.fail("gym-restartful");
    sim.ticks(2);
    assert!(sim.m.actionable(sim.now()).is_empty(), "systemd gets its turn first");
    // systemd restarts it within RestartSec: no Planarian attempt ever happened.
    sim.heal("gym-restartful");
    sim.ticks(62);
    assert!(sim.active("gym-restartful").is_none());
}

#[test]
fn not_expected_units_open_nothing() {
    let mut d = service("graphical-session");
    d.desired.when = Condition::SessionEstablished { uid: None };
    let mut sim = Sim::new(defs([d]));
    sim.set("graphical-session", Observed::Bound, ProbeResult::Fail("not reached".into()));
    sim.ticks(10);
    assert!(sim.active("graphical-session").is_none(), "idle greeter: no incident");
}

#[test]
fn stabilizing_incident_is_not_actionable() {
    // Regression (found by the gym): after a successful repair the incident
    // stays open for the stabilization window, but must not be acted on again.
    let mut sim = Sim::new(defs([service("gym-web")]));
    sim.fail("gym-web");
    sim.ticks(2);
    let id = sim.active("gym-web").unwrap().id;
    sim.m.record_attempt(id, TxnId(1), Outcome::Succeeded, sim.now());
    sim.heal("gym-web");
    sim.ticks(10); // past the 10 s backoff, still stabilizing
    assert!(sim.active("gym-web").is_some());
    assert!(sim.m.actionable(sim.now()).is_empty());
}
