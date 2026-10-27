//! The gym's reference units (catalog `[[fixture]]`), as a manifest would
//! declare them. Canonical probes are attached by `state` from `canonical()`.

use planarian_schema::*;
use std::collections::BTreeMap;

fn probe(id: &str, kind: ProbeKind, origin: ProbeOrigin, establishes: &str) -> ProbeDef {
    let measurement = matches!(kind, ProbeKind::Tcp { .. } | ProbeKind::Http { .. });
    ProbeDef {
        id: ProbeId(id.into()),
        kind,
        timeout: Millis::secs(10),
        origin,
        role: ProbeRole::Readiness,
        cadence: Cadence::EveryTick,
        cost: ProbeCost::Cheap,
        side_effects: if measurement {
            SideEffects::Measurement { bytes_max: 4096, per: Millis::secs(5) }
        } else {
            SideEffects::None
        },
        establishes: establishes.into(),
    }
}

fn user_probe(id: &str, kind: ProbeKind) -> ProbeDef {
    probe(id, kind, ProbeOrigin::User, id)
}

pub fn unit(id: &str, sens: &[Sensitivity], disruption: Disruption, probes: Vec<ProbeDef>) -> UnitDef {
    let id: UnitId = id.parse().expect("unit id");
    UnitDef {
        desired: Desired {
            status: if id.kind == UnitKind::Device && !id.name.starts_with("fs-") {
                DesiredStatus::Bound
            } else {
                DesiredStatus::Running
            },
            when: Condition::Always,
        },
        id,
        edges: vec![],
        sensitivity: Sensitivities::of(sens),
        restart_disruption: disruption,
        probes,
        synonyms: vec![],
        systemd_restart: None,
    }
}

fn edge(d: &mut UnitDef, to: &str, kind: EdgeKind, origin: EdgeOrigin) {
    d.edges.push(Edge { from: d.id.clone(), to: to.parse().expect("unit id"), kind, origin });
}

pub fn gym_units() -> UnitDefs {
    use Sensitivity::*;
    let r = &[Routine][..];
    let mut web = unit(
        "service:gym-web",
        r,
        Disruption::Brief,
        vec![
            user_probe("gym-web-http", ProbeKind::Http { url: "http://127.0.0.1:8080/health".into(), status: 200 }),
            user_probe("gym-web-tcp", ProbeKind::Tcp { addr: "127.0.0.1:8080".into() }),
        ],
    );
    web.synonyms = vec!["web server".into(), "web".into()];
    let db = unit(
        "service:gym-db",
        r,
        Disruption::DataInterruption,
        vec![user_probe("gym-db-tcp", ProbeKind::Tcp { addr: "127.0.0.1:5432".into() })],
    );
    let mut app = unit(
        "service:gym-app",
        r,
        Disruption::Brief,
        vec![user_probe("gym-app-tcp", ProbeKind::Tcp { addr: "127.0.0.1:8081".into() })],
    );
    edge(&mut app, "service:gym-db", EdgeKind::Requires, EdgeOrigin::SystemdRequires);
    edge(&mut app, "service:gym-cache", EdgeKind::Ordering, EdgeOrigin::SystemdAfter);
    edge(&mut app, "service:gym-metrics", EdgeKind::Wants, EdgeOrigin::SystemdWants);
    let cache = unit(
        "service:gym-cache",
        r,
        Disruption::Brief,
        vec![user_probe("gym-cache-tcp", ProbeKind::Tcp { addr: "127.0.0.1:6379".into() })],
    );
    let metrics = unit(
        "service:gym-metrics",
        r,
        Disruption::None,
        vec![user_probe("gym-metrics-tcp", ProbeKind::Tcp { addr: "127.0.0.1:9100".into() })],
    );
    let flap =
        unit("service:gym-flap", r, Disruption::Brief, vec![user_probe("gym-flap-active", ProbeKind::SystemdActive)]);
    let mut restartful = unit(
        "service:gym-restartful",
        r,
        Disruption::Brief,
        vec![user_probe("gym-restartful-active", ProbeKind::SystemdActive)],
    );
    restartful.systemd_restart =
        Some(SystemdRestartPolicy { restart: true, restart_sec: Millis::secs(5), start_limit_burst: 3 });
    let mut client = unit(
        "service:gym-upstream-client",
        r,
        Disruption::Brief,
        vec![user_probe(
            "gym-upstream-client-http",
            ProbeKind::Http { url: "http://10.0.2.2:9000/health".into(), status: 200 },
        )],
    );
    edge(&mut client, "service:external:gym-upstream", EdgeKind::Requires, EdgeOrigin::Manifest);
    let upstream = unit(
        "service:external:gym-upstream",
        &[External],
        Disruption::None,
        vec![user_probe("gym-upstream-tcp", ProbeKind::Tcp { addr: "10.0.2.2:9000".into() })],
    );

    let mut sshd = unit("service:sshd", &[Security], Disruption::Brief, vec![]);
    sshd.synonyms = vec!["ssh".into()];
    let mut nm = unit("service:NetworkManager", &[External], Disruption::ConnectivityLoss, vec![]);
    nm.synonyms = vec!["wifi".into(), "wi-fi".into(), "network".into(), "internet".into()];
    let dm = unit("service:display-manager", r, Disruption::SessionLoss, vec![]);
    let mut gs = unit("target:graphical-session", r, Disruption::SessionLoss, vec![]);
    gs.desired.when = Condition::SessionEstablished { uid: None };
    gs.synonyms = vec!["desktop".into()];

    let snd =
        unit("device:snd-hda0", r, Disruption::Brief, vec![user_probe("snd-hda0-bound", ProbeKind::SystemdActive)]);
    let nic = unit(
        "device:net-gym0",
        &[External],
        Disruption::ConnectivityLoss,
        vec![user_probe("net-gym0-bound", ProbeKind::SystemdActive)],
    );
    let gpu = unit("device:gpu0", r, Disruption::SessionLoss, vec![user_probe("gpu0-bound", ProbeKind::SystemdActive)]);

    let fs = |name: &str| unit(&format!("device:{name}"), r, Disruption::None, vec![]);

    [
        web,
        db,
        app,
        cache,
        metrics,
        flap,
        restartful,
        client,
        upstream,
        sshd,
        nm,
        dm,
        gs,
        snd,
        nic,
        gpu,
        fs("fs-root"),
        fs("fs-nix"),
        fs("fs-boot"),
        fs("fs-journal"),
    ]
    .into_iter()
    .map(|d| (d.id.clone(), d))
    .collect()
}

pub fn gym_user_units() -> Vec<UnitDef> {
    let user = |name: &str| UnitId {
        kind: UnitKind::Service,
        name: name.into(),
        scope: Scope::User { uid: 0, session: None },
    };
    let mut pw = unit("service:pipewire", &[Sensitivity::Routine], Disruption::Brief, vec![]);
    pw.id = user("pipewire");
    pw.synonyms = vec!["sound".into(), "audio".into()];
    pw.edges.push(Edge {
        from: pw.id.clone(),
        to: UnitId::device("snd-hda0"),
        kind: EdgeKind::Requires,
        origin: EdgeOrigin::Manifest,
    });
    let mut wp = unit("service:wireplumber", &[Sensitivity::Routine], Disruption::Brief, vec![]);
    wp.id = user("wireplumber");
    vec![pw, wp]
}

/// The canonical probes the core package ships (I10), by unit name.
pub fn canonical() -> BTreeMap<String, Vec<ProbeDef>> {
    let c = |id: &str, kind: ProbeKind, est: &str| probe(id, kind, ProbeOrigin::Canonical, est);
    let free = |id: &str, path: &str, min_bytes: u64, min_permille: u16| {
        c(id, ProbeKind::FreeSpace { path: path.into(), min_bytes, min_permille }, &format!("{path} has room"))
    };
    [
        (
            "sshd",
            vec![c(
                "sshd-tcp",
                ProbeKind::Tcp { addr: "127.0.0.1:22".into() },
                "sshd accepts TCP connections on port 22",
            )],
        ),
        ("NetworkManager", vec![c("networkmanager-active", ProbeKind::SystemdActive, "NetworkManager is running")]),
        ("display-manager", vec![c("display-manager-active", ProbeKind::SystemdActive, "the greeter is running")]),
        (
            "graphical-session",
            vec![c(
                "graphical-session-reached",
                ProbeKind::SessionTarget { target: "graphical-session".into(), within: Millis::secs(60) },
                "graphical-session.target reached within 60 s of the session's creation",
            )],
        ),
        ("pipewire", vec![c("pipewire-active", ProbeKind::SystemdActive, "PipeWire is running in the user session")]),
        ("fs-root", vec![free("fs-root-free", "/", 2_000_000_000, 50)]),
        ("fs-nix", vec![free("fs-nix-free", "/nix", 2_000_000_000, 50)]),
        ("fs-boot", vec![free("fs-boot-free", "/boot", 64_000_000, 0)]),
        ("fs-journal", vec![free("fs-journal-free", "/var/lib/planarian", 128_000_000, 0)]),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}
