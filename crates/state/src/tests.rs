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
/// declared at one run per 30 s runs at most once per 30 s, on its cadence,
/// on request and on a re-observe alike; a request made sooner runs on the
/// first tick allowed, and the evidence stays fresh in between.
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

    let (s, defs) = tick(&fake, &mut a);
    let first = ran_at(&s);
    let mut runs = vec![first];
    for n in 0..17 {
        // Every way of asking for a run, inside the window.
        match n % 3 {
            0 => a.request(&web, &http),
            1 => a.reprobe(&web),
            _ => {}
        }
        let (s, defs) = tick(&fake, &mut a);
        assert_eq!(s.status(&web, &defs), UnitStatus::Running, "fresh between runs (tick {n})");
        let at = ran_at(&s);
        if at != *runs.last().unwrap() {
            runs.push(at);
        }
    }
    assert_eq!(s.status(&web, &defs), UnitStatus::Running);
    assert!(runs.len() >= 3, "it still runs on its rate: {runs:?}");
    for w in runs.windows(2) {
        assert!(w[1].0 - w[0].0 >= per.0, "two runs {} ms apart: {runs:?}", w[1].0 - w[0].0);
    }
    // A request made inside the window runs on the first tick allowed.
    a.request(&web, &http);
    let last = *runs.last().unwrap();
    let mut s = tick(&fake, &mut a).0;
    while ran_at(&s) == last {
        assert!(fake.w().now.0 < last.0 + per.0, "the request was dropped");
        s = tick(&fake, &mut a).0;
    }
    assert!(ran_at(&s).0 - last.0 >= per.0 && ran_at(&s).0 - last.0 < per.0 + TICK.0);
}
