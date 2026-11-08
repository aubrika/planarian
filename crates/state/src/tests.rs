use super::*;
use planarian_fake::{Health, MemStore, fixtures, gym_world};
use planarian_schema::*;

fn rig() -> (planarian_fake::Fake, Assembler) {
    let fake = gym_world(MemStore::new(1 << 20));
    let manifest = Manifest { units: fixtures::gym_units(), user_units: fixtures::gym_user_units() };
    (fake, Assembler::new(manifest, fixtures::canonical()))
}

fn tick(fake: &planarian_fake::Fake, a: &mut Assembler) -> (SystemState, UnitDefs) {
    fake.advance(TICK);
    let s = a.observe(fake, &Context { known_good: GenerationId(1), ..Default::default() });
    (s, a.defs())
}

#[test]
fn healthy_machine_is_running_and_idle_greeter_not_expected() {
    let (fake, mut a) = rig();
    let (s, defs) = tick(&fake, &mut a);
    for (id, def) in &defs {
        let st = s.status(id, &defs);
        if id.name == "graphical-session" {
            assert_eq!(st, UnitStatus::NotExpected, "nobody logged in");
        } else if def.desired.status == DesiredStatus::Bound {
            assert_eq!(st, UnitStatus::Bound, "{id}");
        } else {
            assert_eq!(st, UnitStatus::Running, "{id}");
        }
    }
    // sshd got its canonical probe from the core package, not the manifest.
    let sshd = &defs[&UnitId::service("sshd")];
    assert!(sshd.probes.iter().any(|p| p.id.0 == "sshd-tcp" && p.origin == ProbeOrigin::Canonical));
}

#[test]
fn manifest_cannot_redefine_a_canonical_probe() {
    let mut units = fixtures::gym_units();
    let sshd = units.get_mut(&UnitId::service("sshd")).unwrap();
    let mut weak = fixtures::canonical()["sshd"][0].clone();
    weak.timeout = Millis::secs(600);
    weak.role = ProbeRole::Diagnostic;
    sshd.probes.push(weak);
    let a = Assembler::new(Manifest { units, user_units: vec![] }, fixtures::canonical());
    let p = &a.defs()[&UnitId::service("sshd")].probes;
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].timeout, Millis::secs(10));
    assert_eq!(p[0].role, ProbeRole::Readiness);
}

#[test]
fn user_units_follow_sessions_and_desktop_deadline() {
    let (fake, mut a) = rig();
    let created = fake.w().now;
    fake.w().sessions.push(SessionInfo {
        id: "c1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        active: true,
        idle: false,
        created,
    });
    // The compositor never reaches graphical-session.target.
    let (s, defs) = tick(&fake, &mut a);
    let pw: UnitId = "service@1000:pipewire".parse().unwrap();
    assert!(defs.contains_key(&pw), "instantiated for alice's session");
    let gs: UnitId = "target@1000/c1:graphical-session".parse().unwrap();
    assert!(!defs.contains_key(&UnitId::target("graphical-session")), "one instance per session");
    assert_eq!(s.status(&gs, &defs), UnitStatus::Transitioning, "within 60 s");
    for _ in 0..13 {
        tick(&fake, &mut a);
    }
    let (s, defs) = tick(&fake, &mut a);
    assert_eq!(s.status(&gs, &defs), UnitStatus::Stopped, "deadline missed → divergent");
    // It comes up: Running.
    let target = UnitId {
        kind: UnitKind::Target,
        name: "graphical-session".into(),
        scope: Scope::User { uid: 1000, session: None },
    };
    fake.w().units.insert(target, planarian_fake::UnitSim::active(created));
    let (s, defs) = tick(&fake, &mut a);
    assert_eq!(s.status(&gs, &defs), UnitStatus::Running);
    // A greeter session never counts.
    fake.w().sessions = vec![SessionInfo {
        id: "g".into(),
        uid: 990,
        class: "greeter".into(),
        seat: Some("seat0".into()),
        remote: false,
        active: true,
        idle: false,
        created,
    }];
    let (s, defs) = tick(&fake, &mut a);
    assert_eq!(s.status(&gs, &defs), UnitStatus::NotExpected);
    assert!(!defs.contains_key(&pw));
}

#[test]
fn probe_timeout_is_unknown_and_503_is_degraded() {
    let (fake, mut a) = rig();
    let web = UnitId::service("gym-web");
    fake.w().units.get_mut(&web).unwrap().health = Health::Delay(Millis::secs(15));
    let (s, defs) = tick(&fake, &mut a);
    assert_eq!(s.status(&web, &defs), UnitStatus::Unknown);
    fake.w().units.get_mut(&web).unwrap().health = Health::Http503;
    let (s, defs) = tick(&fake, &mut a);
    assert_eq!(s.status(&web, &defs), UnitStatus::Degraded(vec![ProbeId("gym-web-http".into())]));
}

#[test]
fn storage_and_devices() {
    let (fake, mut a) = rig();
    tick(&fake, &mut a); // the driver is seen bound once
    fake.w().fs.insert("/nix".into(), (1_000_000_000, 100_000_000_000));
    fake.w().devices.insert(UnitId::device("snd-hda0"), None);
    let (s, defs) = tick(&fake, &mut a);
    assert!(matches!(s.status(&UnitId::device("fs-nix"), &defs), UnitStatus::Degraded(_)));
    assert_eq!(s.status(&UnitId::device("snd-hda0"), &defs), UnitStatus::Detected);
    assert_eq!(a.known_drivers[&UnitId::device("snd-hda0")].name, "snd_hda_intel", "remembered");
}

#[test]
fn unknown_session_creation_time_counts_from_first_sight() {
    let (fake, mut a) = rig();
    fake.w().sessions.push(SessionInfo {
        id: "c9".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        active: true,
        idle: false,
        created: Timestamp(0),
    });
    let (s, defs) = tick(&fake, &mut a);
    let gs: UnitId = "target@1000/c9:graphical-session".parse().unwrap();
    assert_eq!(s.status(&gs, &defs), UnitStatus::Transitioning, "a fresh 60 s, not a deadline missed since 1970");
}

/// session-second-compositor-fails, at the state level: two graphical
/// sessions of one uid; the compositor in the second never runs. Only the
/// second session's instance diverges, though the user's target is reached.
#[test]
fn second_session_of_one_uid_is_judged_on_its_own() {
    let (fake, mut a) = rig();
    let created = fake.w().now;
    for id in ["s1", "s2"] {
        fake.w().sessions.push(SessionInfo {
            id: id.into(),
            uid: 1000,
            class: "user".into(),
            seat: Some("seat0".into()),
            remote: false,
            active: id == "s2",
            idle: false,
            created,
        });
    }
    fake.w().compositors.insert("s1".into(), true);
    fake.w().compositors.insert("s2".into(), false);
    for _ in 0..14 {
        tick(&fake, &mut a);
    }
    let (s, defs) = tick(&fake, &mut a);
    let s1: UnitId = "target@1000/s1:graphical-session".parse().unwrap();
    let s2: UnitId = "target@1000/s2:graphical-session".parse().unwrap();
    assert_eq!(s.status(&s1, &defs), UnitStatus::Running);
    assert_eq!(s.status(&s2, &defs), UnitStatus::Stopped);
}

/// P10, §10: "`per` enforced by the cadence scheduler". A Measurement probe
/// on `EveryTick`, declared at one run per 30 s, runs on its cadence at most
/// once per 30 s, and the unit stays judged between runs. A run on request
/// (`request`, `reprobe`) is not the cadence and is not held back.
#[test]
fn a_measurement_probe_runs_at_most_once_per_its_per() {
    let web = UnitId::service("gym-web");
    let http = ProbeId("gym-web-http".into());
    let per = Millis::secs(30);
    let mut units = fixtures::gym_units();
    for p in units.get_mut(&web).unwrap().probes.iter_mut().filter(|p| p.id == http) {
        p.side_effects = SideEffects::Measurement { bytes_max: 4096, per };
    }
    let fake = gym_world(MemStore::new(1 << 20));
    let mut a = Assembler::new(Manifest { units, user_units: fixtures::gym_user_units() }, fixtures::canonical());
    let ran_at = |s: &SystemState| s.units[&web].1.iter().find(|e| e.probe == http).map(|e| e.at).unwrap();

    // On its cadence alone.
    let mut runs = vec![ran_at(&tick(&fake, &mut a).0)];
    for n in 0..17 {
        let (s, defs) = tick(&fake, &mut a);
        assert_eq!(s.status(&web, &defs), UnitStatus::Running, "fresh between runs (tick {n})");
        if ran_at(&s) != *runs.last().unwrap() {
            runs.push(ran_at(&s));
        }
    }
    assert!(runs.len() >= 3, "it still runs at its rate: {runs:?}");
    for w in runs.windows(2) {
        assert!(w[1].0 - w[0].0 >= per.0, "two cadence runs {} ms apart: {runs:?}", w[1].0 - w[0].0);
    }
    // The daemon's own re-observe of a diagnostic incident is nobody's
    // request: right after a cadence run it leaves the Measurement probe on
    // its cadence (no run inside `per`).
    while ran_at(&tick(&fake, &mut a).0) != fake.w().now {}
    let last = fake.w().now;
    a.reobserve(&web);
    let s = tick(&fake, &mut a).0;
    assert_eq!(ran_at(&s), last, "an internal re-observe ran a Measurement probe inside its per");
    // On request, or a re-observe, right after a cadence run: it runs on the
    // next tick, well inside the window.
    let asks: [fn(&mut Assembler, &UnitId, &ProbeId); 2] = [|a, u, p| a.request(u, p), |a, u, _| a.reprobe(u)];
    for ask in asks {
        while ran_at(&tick(&fake, &mut a).0) != fake.w().now {}
        let last = fake.w().now;
        ask(&mut a, &web, &http);
        let s = tick(&fake, &mut a).0;
        assert_eq!(ran_at(&s), fake.w().now, "a requested run was held back");
        assert!(ran_at(&s).0 - last.0 < per.0);
    }
}

/// Property test for the cadence scheduler's Measurement rate (catch-up
/// coverage, `docs/regression-ledger.md` C16). P10 (#18): a Measurement
/// probe's `per` was read nowhere, so it could run on every tick. Stated
/// whole: for any `per`, any cadence, and requests or re-observes on any
/// ticks, a run nobody asked for comes at least `per` after the one before
/// it and no later than its interval and a tick, and a run asked for comes
/// on the next tick (§10 binds `per` to the cadence only).
/// `PROPTEST_CASES` goes deeper.
mod rate_props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config;

    fn config() -> Config {
        let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(64);
        Config { cases, failure_persistence: None, ..Config::default() }
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn a_measurement_runs_at_its_rate_unless_asked(
            per_s in 1..90u64,
            every_s in prop_oneof![Just(None), (1..40u64).prop_map(Some)],
            asks in proptest::collection::vec(prop_oneof![8 => Just(0u8), 1 => Just(1), 1 => Just(2), 2 => Just(3)], 40..80),
        ) {
            let web = UnitId::service("gym-web");
            let http = ProbeId("gym-web-http".into());
            let per = Millis::secs(per_s);
            let mut units = fixtures::gym_units();
            let mut base = TICK;
            for p in units.get_mut(&web).unwrap().probes.iter_mut().filter(|p| p.id == http) {
                p.side_effects = SideEffects::Measurement { bytes_max: 4096, per };
                if let Some(e) = every_s {
                    p.cadence = Cadence::Every(Millis::secs(e));
                    base = Millis::secs(e);
                }
                prop_assume!(p.cost != ProbeCost::WakesHardware);
            }
            let interval = base.0.max(per.0);
            let fake = gym_world(MemStore::new(1 << 20));
            let mut a = Assembler::new(Manifest { units, user_units: fixtures::gym_user_units() }, fixtures::canonical());
            let ran_at = |s: &SystemState| s.units[&web].1.iter().find(|e| e.probe == http).map(|e| e.at);
            let mut last = ran_at(&tick(&fake, &mut a).0).expect("it runs at start");
            for ask in asks {
                match ask {
                    1 => a.request(&web, &http),
                    2 => a.reprobe(&web),
                    // The daemon's own re-observe: never a run nobody asked
                    // for inside `per`; the cadence checks below hold.
                    3 => a.reobserve(&web),
                    _ => {}
                }
                let s = tick(&fake, &mut a).0;
                let now = fake.w().now;
                let at = ran_at(&s).expect("evidence");
                if ask == 1 || ask == 2 {
                    prop_assert_eq!(at, now, "a run asked for was held back");
                } else {
                    // Check the gap before updating `last`, including ticks on which the probe ran.
                    prop_assert!(now.0 - last.0 <= interval + TICK.0, "a cadence gap of {} ms exceeds interval {interval} ms plus a tick", now.0 - last.0);
                    if at == now {
                        prop_assert!(at.0 - last.0 >= per.0, "a cadence run {} ms after the last (per {} ms)", at.0 - last.0, per.0);
                    }
                }
                last = at;
            }
        }
    }
}

/// The daemon's own re-observe still re-runs what is not a Measurement: a
/// slow-cadence Readiness probe runs on the next tick (the diagnostic
/// incident's point), while a Measurement probe of the same unit stays on its
/// cadence.
#[test]
fn an_internal_reobserve_reruns_readiness_probes_but_not_measurements() {
    let web = UnitId::service("gym-web");
    let http = ProbeId("gym-web-http".into());
    let tcp = ProbeId("gym-web-tcp".into());
    let mut units = fixtures::gym_units();
    for p in units.get_mut(&web).unwrap().probes.iter_mut() {
        p.cadence = Cadence::Every(Millis::secs(120));
        p.side_effects = if p.id == http {
            SideEffects::Measurement { bytes_max: 4096, per: Millis::secs(30) }
        } else {
            SideEffects::None
        };
    }
    let fake = gym_world(MemStore::new(1 << 20));
    let mut a = Assembler::new(Manifest { units, user_units: fixtures::gym_user_units() }, fixtures::canonical());
    let at = |s: &SystemState, id: &ProbeId| s.units[&web].1.iter().find(|e| e.probe == *id).map(|e| e.at).unwrap();
    let first = tick(&fake, &mut a).0;
    let (h0, t0) = (at(&first, &http), at(&first, &tcp));
    let _ = tick(&fake, &mut a);
    a.reobserve(&web);
    let s = tick(&fake, &mut a).0;
    assert_eq!(at(&s, &http), h0, "the Measurement probe was run by an internal re-observe");
    assert!(
        at(&s, &tcp) > t0,
        "the Readiness probe was not re-run: {:?} vs {:?} now {:?}",
        at(&s, &tcp),
        t0,
        fake.w().now
    );
}
