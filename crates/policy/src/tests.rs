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
        security_floor: None,
        units: BTreeMap::new(),
        overrides: vec![],
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
        below_security_floor: flags & 16 != 0,
        restores_unattributed_stop: flags & 128 != 0,
        other_sessions_affected: flags & 32 != 0,
        affected_sessions: if flags & 64 != 0 { vec!["s1".into()] } else { vec![] },
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
        Transition::SetOverride(Override {
            unit: sshd.clone(),
            until: Until::Explicit,
            reason: String::new(),
            by: Actor::Daemon,
            desired: OverrideDesired::LeaveAlone,
            attribution: Attribution::Attested,
            acknowledged: false,
        }),
        Transition::LiftOverride(u.clone()),
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

/// A user in session `s1` (`local`: with a seat) or outside any session.
fn user(uid: u32, admin: bool, local: bool, in_session: bool) -> Authorization {
    let a = Actor::User {
        uid,
        session: in_session.then(|| "s1".to_string()),
        seat: local.then(|| "seat0".to_string()),
        active: true,
    };
    user_authorization(a, admin)
}

fn callers() -> Vec<Authorization> {
    vec![
        authorization_of(Actor::Daemon),
        authorization_of(Actor::Model(ModelId("m".into()))),
        authorization_of(Actor::Unattributed),
        authorization_of(Actor::Agent(PrincipalId(7))),
        user(1000, false, true, true),
        user(1000, false, false, false),
        user(1000, false, true, false),
        user(0, true, true, false),
        user(0, true, false, true),
    ]
}

fn ask(class: ApproverClass) -> Decision {
    Decision::Allow { tier: Tier::AskFirst, approver: class }
}

fn at(t: Tier) -> Decision {
    Decision::Allow { tier: t, approver: ApproverClass::AnyApprover }
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
                    for flags in 0..=255u8 {
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
        Decision::Allow { tier, .. } => Some(*tier),
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
    assert!(n > 1_000_000, "{n}");
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
                    assert!(
                        matches!(d, Decision::Allow { tier: Tier::AskFirst, .. } | Decision::Reject(_)),
                        "{t:?} {d:?}"
                    );
                }
            }
        }
    });
}

/// The floors and the protected oracle hold for every transition kind.
#[test]
fn floors_and_canonical_probes() {
    grid(|t, f, a, _, decisions| {
        let is_user = matches!(a.actor, Actor::User { .. });
        let admin = is_user && a.capabilities.administrator;
        let (session, seat) = match &a.actor {
            Actor::User { session, seat, .. } => (session.clone(), seat.is_some()),
            _ => (None, false),
        };
        let own = session.is_some_and(|s| f.affected_sessions == vec![s]);
        let must_ask = f.recovery == Recovery::NonReversible
            || f.touches_canonical_probe
            || (matches!(f.disruption, Disruption::SessionLoss | Disruption::DataInterruption) && !(is_user && own))
            || (f.disruption == Disruption::ConnectivityLoss && !seat)
            || (f.other_sessions_affected
                && matches!(f.disruption, Disruption::SessionLoss | Disruption::ConnectivityLoss)
                && !admin);
        for d in &decisions {
            if must_ask {
                assert!(
                    matches!(d, Decision::Allow { tier: Tier::AskFirst, .. } | Decision::Reject(_)),
                    "{t:?} {f:?} {a:?} → {d:?}"
                );
            }
            // I16: below the floor, an administrator approves, or it is refused.
            if f.below_security_floor {
                assert!(
                    matches!(
                        d,
                        Decision::Allow { tier: Tier::AskFirst, approver: ApproverClass::Administrator }
                            | Decision::Reject(_)
                    ),
                    "{t:?} {f:?} {a:?} → {d:?}"
                );
            }
            // An administrator class only comes with AskFirst.
            if let Decision::Allow { tier, approver: ApproverClass::Administrator } = d {
                assert_eq!(*tier, Tier::AskFirst);
            }
            if f.touches_core {
                assert!(matches!(d, Decision::Reject(_)));
            }
            if matches!(a.actor, Actor::Agent(_) | Actor::Unattributed) {
                assert_eq!(*d, Decision::Reject(RejectReason::Unauthorized));
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
    let alice = user(1000, false, true, true);
    let mut f = facts(&[Sensitivity::Security], Disruption::None, Recovery::Revertible, 0, None);
    f.caller = alice.actor.clone();
    for claimed in [Actor::Daemon, Actor::user(0), Actor::Watchdog] {
        let t = Transition::SetOverride(Override {
            unit: UnitId::service("sshd"),
            until: Until::Explicit,
            reason: String::new(),
            by: claimed,
            desired: OverrideDesired::LeaveAlone,
            attribution: Attribution::Attested,
            acknowledged: false,
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
        assert_eq!(d, ask(ApproverClass::Administrator));
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
    let alice = user(1000, false, true, true);
    let admin = user(0, true, true, true);
    let routine = || facts(&[Sensitivity::Routine], Disruption::Brief, Recovery::Idempotent, 0, None);

    // authz-unprivileged-override-security: held for an administrator.
    let sup = Transition::SetOverride(Override {
        unit: UnitId::service("sshd"),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
        desired: OverrideDesired::LeaveAlone,
        attribution: Attribution::Attested,
        acknowledged: false,
    });
    assert_eq!(
        one(
            sup.clone(),
            facts(&[Sensitivity::Security], Disruption::None, Recovery::Revertible, 0, None),
            alice.clone()
        ),
        ask(ApproverClass::Administrator)
    );
    // An administrator may override a Security unit at Runtime (§11 table).
    assert_eq!(
        one(sup, facts(&[Sensitivity::Security], Disruption::None, Recovery::Revertible, 0, None), admin.clone()),
        at(Tier::Runtime)
    );
    // authz-unprivileged-stop-unauthorized: gym-db is neither Security nor user-controllable.
    assert_eq!(
        one(
            Transition::StopAndSuppress {
                unit: UnitId::service("gym-db"),
                until: Until::NextBoot,
                reason: String::new()
            },
            routine(),
            alice.clone()
        ),
        Decision::Reject(RejectReason::Unauthorized)
    );
    // alice may suppress her own user unit.
    let own = Transition::SetOverride(Override {
        unit: UnitId {
            kind: UnitKind::Service,
            name: "pipewire".into(),
            scope: Scope::User { uid: 1000, session: None },
        },
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
        desired: OverrideDesired::LeaveAlone,
        attribution: Attribution::Attested,
        acknowledged: false,
    });
    assert_eq!(one(own, routine(), alice.clone()), at(Tier::Runtime));

    // policy-daemon-session-drop-rebind
    let bind = Transition::BindDriver {
        device: UnitId::device("gpu0"),
        driver: DriverRef { name: "virtio_gpu".into(), module: None },
    };
    assert_eq!(
        one(
            bind,
            facts(&[Sensitivity::Routine], Disruption::SessionLoss, Recovery::Revertible, 0, None),
            authorization_of(Actor::Daemon)
        ),
        ask(ApproverClass::AnyApprover)
    );
    // policy-daemon-wifi-runtime
    let wifi = Transition::SetRuntimeOption { path: "wifi.network".into(), value: Value::Str("gym-ap-b".into()) };
    assert_eq!(
        one(
            wifi.clone(),
            facts(&[Sensitivity::Routine], Disruption::ConnectivityLoss, Recovery::Revertible, 0, None),
            authorization_of(Actor::Daemon)
        ),
        ask(ApproverClass::AnyApprover)
    );
    // …but alice at her own laptop may switch her Wi-Fi at Runtime.
    assert_eq!(
        one(
            wifi,
            facts(&[Sensitivity::Routine], Disruption::ConnectivityLoss, Recovery::Revertible, 0, None),
            alice.clone()
        ),
        at(Tier::Runtime)
    );
    // authz-ssh-not-local: the same from a session without a seat asks.
    assert_eq!(
        one(
            Transition::SetRuntimeOption { path: "wifi.network".into(), value: Value::Str("gym-ap-b".into()) },
            facts(&[Sensitivity::Routine], Disruption::ConnectivityLoss, Recovery::Revertible, 0, None),
            user(1000, false, false, true)
        ),
        ask(ApproverClass::AnyApprover)
    );
    // authz-nonadmin-stops-network-other-session: another uid is online.
    let net = Transition::StopAndSuppress {
        unit: UnitId::service("pipewire"),
        until: Until::NextBoot,
        reason: String::new(),
    };
    assert_eq!(
        one(
            net.clone(),
            facts(&[Sensitivity::Routine], Disruption::ConnectivityLoss, Recovery::Revertible, 32, None),
            alice.clone()
        ),
        ask(ApproverClass::AnyApprover)
    );
    assert_eq!(
        one(
            net,
            facts(&[Sensitivity::Routine], Disruption::ConnectivityLoss, Recovery::Revertible, 32, None),
            admin.clone()
        ),
        at(Tier::Runtime)
    );
    // Own session is per session: alice dropping her own session s1 runs; another of hers asks.
    let mut drop_s1 = facts(&[Sensitivity::Routine], Disruption::SessionLoss, Recovery::Revertible, 64, None);
    let restart_pw = Transition::RestartUnit(UnitId::service("pipewire"));
    assert_eq!(one(restart_pw.clone(), drop_s1.clone(), alice.clone()), at(Tier::Runtime));
    drop_s1.affected_sessions = vec!["s2".into()];
    assert_eq!(one(restart_pw, drop_s1, alice.clone()), ask(ApproverClass::AnyApprover));
    // floor-revert-blocked / floor-manual-rollback-needs-admin: below the floor asks an administrator.
    assert_eq!(
        one(
            Transition::Rollback,
            facts(&[Sensitivity::Routine], Disruption::Brief, Recovery::Revertible, 16, None),
            admin.clone()
        ),
        ask(ApproverClass::Administrator)
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
        at(Tier::Tested)
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
        ask(ApproverClass::AnyApprover)
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
    assert_eq!(
        one(resolve.clone(), routine(), authorization_of(Actor::Daemon)),
        Decision::Reject(RejectReason::Unauthorized)
    );
    assert_eq!(one(resolve.clone(), routine(), alice), Decision::Reject(RejectReason::Unauthorized));
    assert_eq!(one(resolve, routine(), admin.clone()), at(Tier::Runtime));

    // gen-bad-switch: a generation never live-tested asks.
    assert_eq!(
        one(Transition::SwitchGeneration(GenerationId(9)), routine(), admin.clone()),
        ask(ApproverClass::AnyApprover)
    );
    assert_eq!(one(Transition::SwitchGeneration(GenerationId(5)), routine(), admin), at(Tier::Tested));
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

/// I19, executable: never one's own proposal; Administrator class needs one;
/// no self-grant; non-users never approve.
#[test]
fn i19_approval_and_grants() {
    let admin = user(0, true, true, true);
    let other_admin = user(1001, true, true, true);
    let alice = user(1000, false, true, true);
    for class in [ApproverClass::AnyApprover, ApproverClass::Administrator] {
        assert!(!may_approve(&admin, admin.principal, class), "own proposal");
        assert!(may_approve(&admin, alice.principal, class));
        assert!(!may_approve(&alice, admin.principal, class), "alice holds no Approve");
        assert!(!may_approve(&authorization_of(Actor::Daemon), alice.principal, class));
    }
    let g = Grant {
        to: other_admin.principal,
        capability: Capability::Approve,
        approved_by: admin.principal,
        txn: TxnId(1),
    };
    assert!(may_grant(&admin, alice.principal, &g));
    assert!(!may_grant(&other_admin, alice.principal, &g), "self-grant");
    assert!(!may_grant(&admin, admin.principal, &g), "own proposal");
    let merge = Grant { capability: Capability::Merge, ..g };
    assert!(!may_grant(&admin, alice.principal, &merge), "cannot grant what it does not hold");
}
