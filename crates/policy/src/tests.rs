//! Executable checks alongside the proofs: the proved properties again over a
//! grid of transitions × facts × callers × autonomy settings (~110k inputs),
//! which also exercises the compiled code, plus the catalog's policy cases.

use super::*;
use planarian_schema::*;
use std::collections::BTreeMap;

fn state() -> SystemState {
    SystemState {
        generation: GenerationId(5),
        known_good: GenerationId(4),
        live_tested: Some(GenerationId(5)),
        accepted_baseline: None,
        units: BTreeMap::new(),
        suppressions: vec![],
        conditions: Default::default(),
        resources: Default::default(),
        core_hash: Hash::ZERO,
        observed_at: Timestamp(0),
    }
}

fn tables() -> Tables {
    Tables {
        catalog: ["font-scale", "service-enable", "wifi-select"].map(|s| ChangeId(s.into())).into(),
        runtime_allowlist: ["font.scale", "wifi.network"].map(String::from).into(),
        option_sensitivity: vec![
            ("services.openssh".into(), Sensitivities::of(&[Sensitivity::Security])),
            ("networking".into(), Sensitivities::of(&[Sensitivity::External])),
        ],
        model_catalog: Default::default(),
    }
}

fn facts(
    sens: &[Sensitivity],
    disruption: Disruption,
    recovery: Recovery,
    flags: u8,
    diff: Option<&str>,
) -> DerivedFacts {
    DerivedFacts {
        affected_units: Default::default(),
        sensitivity: Sensitivities::of(sens),
        disruption,
        recovery,
        touches_manifest: flags & 1 != 0,
        touches_canonical_probe: flags & 2 != 0,
        changes_desired: flags & 4 != 0,
        touches_core: flags & 8 != 0,
        caller: Actor::Daemon,
        config_diff: diff.map(|p| ConfigDiff { options: [(p.to_owned(), (None, Some(Value::Bool(true))))].into() }),
    }
}

fn transitions() -> Vec<Transition> {
    let u = UnitId::service("pipewire");
    let sshd = UnitId::service("sshd");
    vec![
        Transition::RestartUnit(u.clone()),
        Transition::StopUnit(sshd.clone()),
        Transition::Suppress(Suppression {
            unit: sshd.clone(),
            until: Until::Explicit,
            reason: String::new(),
            by: Actor::Daemon,
            stopped: false,
        }),
        Transition::Unsuppress(u.clone()),
        Transition::StopAndSuppress { unit: u.clone(), until: Until::NextBoot, reason: String::new() },
        Transition::BindDriver {
            device: UnitId::device("gpu0"),
            driver: DriverRef { name: "virtio_gpu".into(), module: None },
        },
        Transition::ApplyChange { change: ChangeId("font-scale".into()), args: Default::default() },
        Transition::ApplyChange { change: ChangeId("manifest-probe-edit".into()), args: Default::default() },
        Transition::SwitchGeneration(GenerationId(5)),
        Transition::SwitchGeneration(GenerationId(9)),
        Transition::Revert { to: GenerationId(4) },
        Transition::Rollback,
        Transition::LoadModel(ModelId("m".into())),
        Transition::RestoreSnapshot(SnapshotId("s".into())),
        Transition::CollectGarbage { emergency: true },
        Transition::SetRuntimeOption { path: "wifi.network".into(), value: Value::Str("ap".into()) },
        Transition::SetRuntimeOption { path: "kernel.sysctl".into(), value: Value::Int(1) },
        Transition::Resolve { txn: TxnId(1), resolution: Resolution::ManualRepaired },
    ]
}

fn callers() -> Vec<Authorization> {
    let user = |uid, admin, local, own| Authorization {
        caller: Actor::User { uid },
        admin,
        local_session: local,
        owns_affected_session: own,
    };
    vec![
        Authorization::daemon(),
        Authorization { caller: Actor::Model(ModelId("m".into())), ..Authorization::daemon() },
        user(1000, false, true, true),
        user(1000, false, false, false),
        user(0, true, true, false),
        user(0, true, false, true),
    ]
}

/// Every combination; calls `f(input-without-max-tier, decisions by max_tier)`.
fn grid(mut f: impl FnMut(&Transition, &DerivedFacts, &Authorization, &Session, [Decision; 3])) {
    let st = state();
    let tb = tables();
    let locked: Vec<String> = vec!["services.locked".to_string()];
    let sens: [&[Sensitivity]; 5] = [
        &[],
        &[Sensitivity::Routine],
        &[Sensitivity::Security],
        &[Sensitivity::External, Sensitivity::UserData],
        &[Sensitivity::Core],
    ];
    let disruptions = [
        Disruption::None,
        Disruption::Brief,
        Disruption::SessionLoss,
        Disruption::DataInterruption,
        Disruption::ConnectivityLoss,
    ];
    let recoveries = [Recovery::Idempotent, Recovery::Revertible, Recovery::NonReversible];
    let diffs = [None, Some("fonts.scale"), Some("services.openssh.enable"), Some("services.locked")];
    let sessions = [
        Session::default(),
        Session {
            applied: vec![],
            cumulative: ConfigDiff { options: [("networking.wifi".into(), (None, Some(Value::Bool(true))))].into() },
            policy: None,
        },
    ];
    for t in transitions() {
        for s in sens {
            for d in disruptions {
                for r in recoveries {
                    for flags in 0..16u8 {
                        for diff in diffs {
                            let fa = facts(s, d, r, flags, diff);
                            for a in callers() {
                                for session in &sessions {
                                    let decide_at = |max_tier| {
                                        let settings = Settings { max_tier, ..Settings::default() };
                                        decide(&Input {
                                            transition: &t,
                                            facts: &fa,
                                            known_good: st.known_good,
                                            live_tested: st.live_tested,
                                            cumulative: &session.cumulative,
                                            authz: &a,
                                            settings: &settings,
                                            tables: &tb,
                                            locked: &locked,
                                            revert_to: Some(GenerationId(4)),
                                        })
                                    };
                                    f(
                                        &t,
                                        &fa,
                                        &a,
                                        session,
                                        [decide_at(Tier::Observe), decide_at(Tier::Runtime), decide_at(Tier::Tested)],
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn tier(d: &Decision) -> Option<Tier> {
    match d {
        Decision::Allow(t) => Some(*t),
        Decision::Reject(_) => None,
    }
}

/// I5: the autonomy setting never converts a Reject into a tier, nor a tier
/// into a Reject; raising it never makes a decision stricter.
#[test]
fn i5_autonomy_never_touches_reject() {
    let mut n = 0;
    grid(|t, _, _, _, [obs, rt, tested]| {
        n += 1;
        let rejects: Vec<bool> = [&obs, &rt, &tested].iter().map(|d| matches!(d, Decision::Reject(_))).collect();
        assert!(rejects.iter().all(|r| *r == rejects[0]), "{t:?}");
        if let Decision::Reject(r) = &obs {
            assert_eq!(obs, rt);
            assert_eq!(rt, tested, "{r:?}");
        } else {
            assert!(tier(&obs) >= tier(&rt) && tier(&rt) >= tier(&tested), "{t:?}");
            for (d, max) in [(&obs, Tier::Observe), (&rt, Tier::Runtime), (&tested, Tier::Tested)] {
                let got = tier(d).unwrap();
                assert!(got <= max || got == Tier::AskFirst, "{t:?}: {got:?} above {max:?}");
            }
        }
    });
    assert!(n > 100_000, "{n}");
}

/// I11: when the session's cumulative diff (with this change) is non-Routine,
/// the decision is AskFirst or a Reject.
#[test]
fn i11_cumulative_classification() {
    let tb = tables();
    grid(|t, f, _, session, decisions| {
        if let Some(diff) = &f.config_diff {
            let cumulative = session.cumulative.then(diff);
            if !tb.diff_sensitivity(&cumulative).only_routine() {
                for d in &decisions {
                    assert!(matches!(d, Decision::Allow(Tier::AskFirst) | Decision::Reject(_)), "{t:?} {d:?}");
                }
            }
        }
    });
}

/// The floors and the protected oracle hold for every transition kind.
#[test]
fn floors_and_canonical_probes() {
    grid(|t, f, a, _, decisions| {
        let is_user = matches!(a.caller, Actor::User { .. });
        let must_ask = f.recovery == Recovery::NonReversible
            || f.touches_canonical_probe
            || (matches!(f.disruption, Disruption::SessionLoss | Disruption::DataInterruption)
                && !(is_user && a.owns_affected_session))
            || (f.disruption == Disruption::ConnectivityLoss && !(is_user && a.local_session));
        if must_ask {
            for d in &decisions {
                assert!(
                    matches!(d, Decision::Allow(Tier::AskFirst) | Decision::Reject(_)),
                    "{t:?} {f:?} {a:?} → {d:?}"
                );
            }
        }
        if f.touches_core {
            for d in &decisions {
                assert!(matches!(d, Decision::Reject(_)));
            }
        }
    });
}

/// I14 in the sense `decide` can check: the actor written in a Suppress
/// transition (the proposal's claim) does not change the decision.
#[test]
fn i14_actor_field_is_not_authority() {
    let st = state();
    let tb = tables();
    let settings = Settings::default();
    let alice = Authorization {
        caller: Actor::User { uid: 1000 },
        admin: false,
        local_session: true,
        owns_affected_session: true,
    };
    let mut f = facts(&[Sensitivity::Security], Disruption::None, Recovery::Revertible, 0, None);
    f.caller = alice.caller.clone();
    for claimed in [Actor::Daemon, Actor::User { uid: 0 }, Actor::Watchdog] {
        let t = Transition::Suppress(Suppression {
            unit: UnitId::service("sshd"),
            until: Until::Explicit,
            reason: String::new(),
            by: claimed,
            stopped: false,
        });
        let d = decide(&Input {
            transition: &t,
            facts: &f,
            known_good: st.known_good,
            live_tested: st.live_tested,
            cumulative: &ConfigDiff::default(),
            authz: &alice,
            settings: &settings,
            tables: &tb,
            locked: &vec![],
            revert_to: None,
        });
        assert_eq!(d, Decision::Reject(RejectReason::Unauthorized));
    }
}

fn one(t: Transition, f: DerivedFacts, a: Authorization) -> Decision {
    decide(&Input {
        transition: &t,
        facts: &f,
        known_good: state().known_good,
        live_tested: state().live_tested,
        cumulative: &ConfigDiff::default(),
        authz: &a,
        settings: &Settings::default(),
        tables: &tables(),
        locked: &vec!["services.locked".into()],
        revert_to: None,
    })
}

#[test]
fn catalog_policy_cases() {
    let alice = Authorization {
        caller: Actor::User { uid: 1000 },
        admin: false,
        local_session: true,
        owns_affected_session: true,
    };
    let admin =
        Authorization { caller: Actor::User { uid: 0 }, admin: true, local_session: true, owns_affected_session: true };
    let routine = || facts(&[Sensitivity::Routine], Disruption::Brief, Recovery::Idempotent, 0, None);

    // authz-unprivileged-suppress-security
    let sup = Transition::Suppress(Suppression {
        unit: UnitId::service("sshd"),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
        stopped: false,
    });
    assert_eq!(
        one(
            sup.clone(),
            facts(&[Sensitivity::Security], Disruption::None, Recovery::Revertible, 0, None),
            alice.clone()
        ),
        Decision::Reject(RejectReason::Unauthorized)
    );
    // An admin may, but it is Security: AskFirst.
    assert_eq!(
        one(sup, facts(&[Sensitivity::Security], Disruption::None, Recovery::Revertible, 0, None), admin.clone()),
        Decision::Allow(Tier::AskFirst)
    );
    // alice may suppress her own user unit.
    let own = Transition::Suppress(Suppression {
        unit: UnitId {
            kind: UnitKind::Service,
            name: "pipewire".into(),
            scope: Scope::User { uid: 1000, session: None },
        },
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
        stopped: false,
    });
    assert_eq!(one(own, routine(), alice.clone()), Decision::Allow(Tier::Runtime));

    // policy-daemon-session-drop-rebind
    let bind = Transition::BindDriver {
        device: UnitId::device("gpu0"),
        driver: DriverRef { name: "virtio_gpu".into(), module: None },
    };
    assert_eq!(
        one(
            bind,
            facts(&[Sensitivity::Routine], Disruption::SessionLoss, Recovery::Revertible, 0, None),
            Authorization::daemon()
        ),
        Decision::Allow(Tier::AskFirst)
    );
    // policy-daemon-wifi-runtime
    let wifi = Transition::SetRuntimeOption { path: "wifi.network".into(), value: Value::Str("gym-ap-b".into()) };
    assert_eq!(
        one(
            wifi.clone(),
            facts(&[Sensitivity::Routine], Disruption::ConnectivityLoss, Recovery::Revertible, 0, None),
            Authorization::daemon()
        ),
        Decision::Allow(Tier::AskFirst)
    );
    // …but alice at her own laptop may switch her Wi-Fi at Runtime.
    assert_eq!(
        one(
            wifi,
            facts(&[Sensitivity::Routine], Disruption::ConnectivityLoss, Recovery::Revertible, 0, None),
            alice.clone()
        ),
        Decision::Allow(Tier::Runtime)
    );

    // manifest-weaken-via-proposal: no such catalog entry.
    let weaken = Transition::ApplyChange { change: ChangeId("manifest-probe-edit".into()), args: Default::default() };
    assert_eq!(
        one(weaken, facts(&[Sensitivity::Security], Disruption::None, Recovery::Revertible, 3, None), admin.clone()),
        Decision::Reject(RejectReason::NotInCatalog)
    );
    // core-target-rejected, under any caller.
    let font = Transition::ApplyChange { change: ChangeId("font-scale".into()), args: Default::default() };
    assert_eq!(
        one(
            font.clone(),
            facts(&[Sensitivity::Routine], Disruption::None, Recovery::Revertible, 8, None),
            admin.clone()
        ),
        Decision::Reject(RejectReason::CoreTarget)
    );
    // gen-override-only-change: a routine catalog change by alice is Tested.
    assert_eq!(
        one(
            font.clone(),
            facts(&[Sensitivity::Routine], Disruption::None, Recovery::Revertible, 0, Some("fonts.scale")),
            alice.clone()
        ),
        Decision::Allow(Tier::Tested)
    );
    // gen-disable-reenable-canonical: changing desired state is not tampering, but sshd is Security.
    let disable = Transition::ApplyChange { change: ChangeId("service-enable".into()), args: Default::default() };
    assert_eq!(
        one(
            disable.clone(),
            facts(
                &[Sensitivity::Security],
                Disruption::Brief,
                Recovery::Revertible,
                4,
                Some("services.openssh.enable")
            ),
            admin.clone()
        ),
        Decision::Allow(Tier::AskFirst)
    );
    assert_eq!(one(disable, routine(), alice.clone()), Decision::Reject(RejectReason::Unauthorized));
    // Locked option.
    assert_eq!(
        one(
            font,
            facts(&[Sensitivity::Routine], Disruption::None, Recovery::Revertible, 0, Some("services.locked")),
            admin.clone()
        ),
        Decision::Reject(RejectReason::LockedOption)
    );

    // Resolve: administrators only.
    let resolve = Transition::Resolve { txn: TxnId(1), resolution: Resolution::AsReverted };
    assert_eq!(one(resolve.clone(), routine(), Authorization::daemon()), Decision::Reject(RejectReason::Unauthorized));
    assert_eq!(one(resolve.clone(), routine(), alice), Decision::Reject(RejectReason::Unauthorized));
    assert_eq!(one(resolve, routine(), admin.clone()), Decision::Allow(Tier::Runtime));

    // gen-bad-switch: a generation never live-tested asks.
    assert_eq!(
        one(Transition::SwitchGeneration(GenerationId(9)), routine(), admin.clone()),
        Decision::Allow(Tier::AskFirst)
    );
    assert_eq!(one(Transition::SwitchGeneration(GenerationId(5)), routine(), admin), Decision::Allow(Tier::Tested));
}

#[test]
fn policy_version_covers_tables() {
    let a = tables();
    let mut b = tables();
    b.runtime_allowlist.push("display.brightness".into());
    assert_ne!(policy_version(&a), policy_version(&b));
    assert_eq!(policy_version(&a), policy_version(&tables()));
}

#[test]
fn policy_version_ignores_list_order() {
    let a = tables();
    let mut b = tables();
    b.catalog.reverse();
    b.runtime_allowlist.reverse();
    b.runtime_allowlist.push(b.runtime_allowlist[0].clone());
    assert_eq!(policy_version(&a), policy_version(&b));
}
