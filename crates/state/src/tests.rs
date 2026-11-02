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
