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
        created,
    });
    // The compositor never reaches graphical-session.target.
    let (s, defs) = tick(&fake, &mut a);
    let pw: UnitId = "service@1000:pipewire".parse().unwrap();
    assert!(defs.contains_key(&pw), "instantiated for alice's session");
    let gs = UnitId::target("graphical-session");
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
        created: Timestamp(0),
    });
    let (s, defs) = tick(&fake, &mut a);
    let gs = UnitId::target("graphical-session");
    assert_eq!(s.status(&gs, &defs), UnitStatus::Transitioning, "a fresh 60 s, not a deadline missed since 1970");
}
