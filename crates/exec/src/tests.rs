//! The executor over the fake machine. Names follow catalog entries.

use super::*;
use planarian_fake::{Fake, MemStore, fixtures, gym_world};
use planarian_policy::{authorization_of, user_authorization};
use planarian_state::{Assembler, Context, Manifest};
use planarian_txn::kernel::CrashPoint;

const ALICE: u32 = 1000;

struct Rig {
    fake: Fake,
    ex: Executor<Fake, MemStore>,
    asm: Assembler,
}

fn catalog() -> CatalogConfig {
    CatalogConfig {
        services: [("sshd".into(), "services.openssh.enable".into())].into(),
        font_scale_option: "planarian.reference.fontScale".into(),
        font_scales: ["1", "1.25", "1.5"].map(String::from).into(),
        listen_addresses: [(
            "gym-web".into(),
            planarian_changes::ListenAddress {
                option: "services.gym-web.listenAddress".into(),
                permitted: vec!["127.0.0.1".into(), "192.0.2.10".into()],
            },
        )]
        .into(),
        ..Default::default()
    }
}

fn tables() -> Tables {
    Tables {
        catalog: ["service-enable", "font-scale", "listen-address", "repair:reenable-predicted"]
            .map(|s| ChangeId(s.into()))
            .into(),
        runtime_allowlist: ["font.scale", "wifi.network"].map(String::from).into(),
        option_sensitivity: vec![("services.openssh".into(), Sensitivities::of(&[Sensitivity::Security]))],
        model_catalog: Default::default(),
    }
}

fn config() -> Config {
    Config {
        settings: Settings::default(),
        tables: tables(),
        catalog: catalog(),
        owner: PinnedSource { root: "/etc/nixos".into(), kind: SourceKind::Git },
        canonical: fixtures::canonical(),
    }
}

impl Rig {
    fn new() -> Rig {
        let store = MemStore::new(4 << 20);
        let fake = gym_world(store.clone());
        let cfg = config();
        let journal = Journal::open(store).unwrap();
        let ex = Executor::new(journal, fake.clone(), OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO }, cfg);
        ex.adopt_current();
        fake.w().alive.insert(100);
        let asm = Assembler::new(
            Manifest { units: fixtures::gym_units(), user_units: fixtures::gym_user_units() },
            fixtures::canonical(),
        );
        Rig { fake, ex, asm }
    }

    fn observe(&mut self) -> (SystemState, UnitDefs) {
        let l = self.ex.kernel.journal.sync_ledger().unwrap().clone();
        let ctx = Context {
            known_good: GenerationId(1),
            live_tested: l.live_tested,
            accepted_baseline: None,
            security_floor: l.security_floor,
            overrides: l.overrides,
            core_hash: Hash::ZERO,
        };
        self.ex.update_context(ctx.clone(), vec![GenerationId(1)]);
        let s = self.asm.observe(&self.fake, &ctx);
        (s, self.asm.defs())
    }

    fn propose(&mut self, t: Transition, authz: Authorization) -> Submitted {
        let (s, defs) = self.observe();
        let p = Proposal {
            observed: s.digest(),
            expected: predict(&t, &s, &defs),
            transition: t,
            reason: "test".into(),
            source: Source::User,
        };
        self.ex.submit(p, authz, &s, &defs)
    }

    fn approve(&mut self, h: Hash) -> Submitted {
        let (s, defs) = self.observe();
        self.ex.approve(&h, &root(), &s, &defs)
    }

    /// The status on the daemon's next tick.
    fn status(&mut self, u: &UnitId) -> UnitStatus {
        self.fake.advance(planarian_state::TICK);
        let (s, defs) = self.observe();
        s.status(u, &defs)
    }
}

/// An administrator (in `planarian-admin`) who proposes changes.
fn admin() -> Authorization {
    user_authorization(Actor::local(1001, "1"), true)
}

/// Root at a terminal: the Phase A approver (§16), a different principal (I19).
fn root() -> Authorization {
    user_authorization(Actor::user(0), true)
}

fn alice() -> Authorization {
    user_authorization(Actor::local(ALICE, "2"), false)
}

fn change(id: &str, args: &[(&str, Value)]) -> Transition {
    Transition::ApplyChange {
        change: ChangeId(id.into()),
        args: args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
    }
}

fn finished(s: &Submitted) -> TxnState {
    match s {
        Submitted::Finished { state, .. } => state.clone(),
        other => panic!("not finished: {other:?}"),
    }
}

#[test]
fn svc_killed_restart_commits() {
    let mut r = Rig::new();
    let web = UnitId::service("gym-web");
    r.fake.w().units.get_mut(&web).unwrap().observed = Observed::Failed(Reason::ExitCode(137));
    assert!(matches!(r.status(&web), UnitStatus::Failed(_)));
    let s = r.propose(Transition::RestartUnit(web.clone()), authorization_of(Actor::Daemon));
    assert_eq!(finished(&s), TxnState::Committed);
    assert_eq!(r.status(&web), UnitStatus::Running);
}

#[test]
fn gen_override_only_change_commits() {
    let mut r = Rig::new();
    let s = r.propose(change("font-scale", &[("scale", Value::Str("1.25".into()))]), alice());
    assert_eq!(finished(&s), TxnState::Committed);
    let w = r.fake.w();
    assert_eq!(w.overrides.assignments["planarian.reference.fontScale"], Value::Str("1.25".into()));
    assert_ne!(w.current, GenerationId(1));
    assert_eq!(w.boot_default, w.current);
}

#[test]
fn svc_misconfig_listen_address_reverts() {
    let mut r = Rig::new();
    let s = r.propose(
        change(
            "listen-address",
            &[("service", Value::Str("gym-web".into())), ("addr", Value::Str("192.0.2.10".into()))],
        ),
        admin(),
    );
    assert_eq!(finished(&s), TxnState::Reverted, "{s:?}");
    let w = r.fake.w();
    assert_eq!(w.current, GenerationId(1));
    assert_eq!(w.boot_default, GenerationId(1));
    assert!(w.overrides.assignments.is_empty(), "override source restored");
    drop(w);
    assert_eq!(r.status(&UnitId::service("gym-web")), UnitStatus::Running);
}

#[test]
fn gen_disable_reenable_canonical_asks_and_is_not_reverted() {
    let mut r = Rig::new();
    let off = change("service-enable", &[("service", Value::Str("sshd".into())), ("enabled", Value::Bool(false))]);
    let Submitted::Parked { approve, facts, .. } = r.propose(off, admin()) else { panic!("Security change must ask") };
    assert!(!facts.touches_canonical_probe && facts.changes_desired);
    assert_eq!(finished(&r.approve(approve)), TxnState::Committed, "disabling makes the probe inapplicable; no revert");
    assert_eq!(r.fake.w().units[&UnitId::service("sshd")].observed, Observed::Absent);
    // Replay of the same approval is refused.
    assert!(matches!(r.approve(approve), Submitted::Rejected { .. }));
    let on = change("service-enable", &[("service", Value::Str("sshd".into())), ("enabled", Value::Bool(true))]);
    let Submitted::Parked { approve, .. } = r.propose(on, admin()) else { panic!() };
    assert_eq!(finished(&r.approve(approve)), TxnState::Committed);
    assert_eq!(r.status(&UnitId::service("sshd")), UnitStatus::Running);
}

#[test]
fn stale_owner_edit_after_staging_rejects() {
    let mut r = Rig::new();
    let off = change("service-enable", &[("service", Value::Str("sshd".into())), ("enabled", Value::Bool(false))]);
    let Submitted::Parked { approve, txn, .. } = r.propose(off, admin()) else { panic!() };
    r.fake.w().owner_files.insert("configuration.nix".into(), "{ edited = true; }".into());
    match r.approve(approve) {
        Submitted::Rejected { reason: RejectReason::Stale, .. } => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(r.ex.kernel.journal.sync_ledger().unwrap().state(txn), Some(TxnState::Rejected(RejectReason::Stale)));
    assert_eq!(r.fake.w().current, GenerationId(1));
}

#[test]
fn untracked_files_do_not_make_it_stale() {
    let mut r = Rig::new();
    r.fake.w().untracked.insert("scratch.nix".into());
    let s = r.propose(change("font-scale", &[("scale", Value::Str("1.5".into()))]), alice());
    assert_eq!(finished(&s), TxnState::Committed);
}

#[test]
fn authz_and_refinement_and_digest() {
    let mut r = Rig::new();
    let sup = Transition::SetOverride(Override {
        unit: UnitId::service("sshd"),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
        desired: OverrideDesired::LeaveAlone,
        attribution: Attribution::Attested,
    });
    // Held for an administrator (§11), not refused; alice can't approve it.
    let Submitted::Parked { approve, .. } = r.propose(sup, alice()) else { panic!("not parked") };
    let (s, defs) = r.observe();
    assert!(matches!(
        r.ex.approve(&approve, &alice(), &s, &defs),
        Submitted::Rejected { reason: RejectReason::Unauthorized, .. }
    ));
    // Nor can an administrator who is not an approver of this class: the daemon.
    assert!(matches!(
        r.ex.approve(&approve, &authorization_of(Actor::Daemon), &s, &defs),
        Submitted::Rejected { reason: RejectReason::Unauthorized, .. }
    ));
    assert!(matches!(r.ex.approve(&approve, &root(), &s, &defs), Submitted::Finished { .. }));

    let (s, defs) = r.observe();
    let t = Transition::RestartUnit(UnitId::service("gym-web"));
    let mut expected = predict(&t, &s, &defs);
    expected.may_change.insert(UnitId::service("sshd"));
    let p =
        Proposal { observed: s.digest(), transition: t.clone(), expected, reason: String::new(), source: Source::User };
    assert!(matches!(r.ex.submit(p, admin(), &s, &defs), Submitted::Rejected { reason: RejectReason::Refinement, .. }));

    let p = Proposal {
        observed: Hash::ZERO,
        expected: predict(&t, &s, &defs),
        transition: t,
        reason: String::new(),
        source: Source::User,
    };
    match r.ex.submit(p, admin(), &s, &defs) {
        Submitted::Rejected { reason: RejectReason::Stale, digest: Some(d), .. } => assert_eq!(d, s.digest()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn forged_actor_is_overwritten() {
    let mut r = Rig::new();
    let pw =
        UnitId { kind: UnitKind::Service, name: "pipewire".into(), scope: Scope::User { uid: ALICE, session: None } };
    let sup = Transition::SetOverride(Override {
        unit: pw.clone(),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
        desired: OverrideDesired::LeaveAlone,
        attribution: Attribution::Attested,
    });
    assert_eq!(finished(&r.propose(sup, alice())), TxnState::Committed);
    let l = r.ex.kernel.journal.sync_ledger().unwrap();
    assert_eq!(l.overrides[0].by.uid(), Some(ALICE));
    assert_eq!(l.overrides[0].attribution, Attribution::Attested);
}

#[test]
fn watchdog_verifies_from_the_journal_alone() {
    // Kill the daemon at Checking; a fresh watchdog with no executor state
    // re-runs the probes from the journaled CheckContext and decides.
    for (bad, expect) in [(false, TxnState::Committed), (true, TxnState::Reverted)] {
        let mut r = Rig::new();
        r.ex.kernel.crash_at = Some(CrashPoint::State("Checking"));
        let t = if bad {
            change(
                "listen-address",
                &[("service", Value::Str("gym-web".into())), ("addr", Value::Str("192.0.2.10".into()))],
            )
        } else {
            change("font-scale", &[("scale", Value::Str("1.25".into()))])
        };
        let s = r.propose(t, admin());
        assert!(matches!(s, Submitted::Error(_)), "crashed: {s:?}");
        r.fake.w().alive.remove(&100);

        let journal = Journal::open(r.fake.store.clone()).unwrap();
        let host = ExecHost::new(r.fake.clone(), fixtures::canonical());
        let mut wd = Kernel::new(journal, host, OwnerId::Watchdog { pid: 200, boot_id: Hash::ZERO });
        let txn = wd.journal.ledger().live.values().next().unwrap().txn.clone();
        assert!(wd.watchdog_should_take_over(&txn));
        assert_eq!(wd.recover(txn.id, txn.lease.epoch).unwrap(), expect, "bad={bad}");
        let w = r.fake.w();
        assert_eq!(w.boot_default, w.current);
        assert_eq!(w.current == GenerationId(1), bad);
    }
}

#[test]
fn rollback_restores_known_good_and_its_overrides() {
    let mut r = Rig::new();
    assert_eq!(
        finished(&r.propose(change("font-scale", &[("scale", Value::Str("1.5".into()))]), alice())),
        TxnState::Committed
    );
    let s = r.propose(Transition::Rollback, admin());
    assert_eq!(finished(&s), TxnState::Committed, "{s:?}");
    let w = r.fake.w();
    assert_eq!(w.current, GenerationId(1));
    assert!(w.overrides.assignments.is_empty());
}

#[test]
fn approval_expires() {
    let mut r = Rig::new();
    let off = change("service-enable", &[("service", Value::Str("sshd".into())), ("enabled", Value::Bool(false))]);
    let Submitted::Parked { txn, .. } = r.propose(off, admin()) else { panic!() };
    r.fake.advance(Millis(TOKEN_LIFETIME.0 + 60_000));
    assert_eq!(r.ex.expire(), vec![txn]);
    assert_eq!(
        r.ex.kernel.journal.sync_ledger().unwrap().state(txn),
        Some(TxnState::Rejected(RejectReason::ApprovalExpired))
    );
}

#[test]
fn runtime_option_then_writeback() {
    let mut r = Rig::new();
    let t = Transition::SetRuntimeOption { path: "font.scale".into(), value: Value::Str("1.25".into()) };
    let Submitted::Finished { state, followup: Some(wb), .. } = r.propose(t, alice()) else { panic!() };
    assert_eq!(state, TxnState::Committed);
    let mut wb = wb;
    let (s, defs) = r.observe();
    wb.observed = s.digest();
    assert_eq!(finished(&r.ex.submit(wb, alice(), &s, &defs)), TxnState::Committed);
    assert_eq!(r.fake.w().overrides.assignments["planarian.reference.fontScale"], Value::Str("1.25".into()));
}

/// Property tests (§17a: proptest for `exec` in Phase A). Random histories of
/// proposals, faults and crashes at every kernel crash point, each crash
/// followed by watchdog and/or daemon-restart recovery; after every step the
/// journal-level invariants must hold.
mod props {
    use super::*;
    use planarian_txn::kernel::Kernel;
    use proptest::prelude::*;
    use proptest::test_runner::{Config as PConfig, FailurePersistence};

    const POINTS: [CrashPoint; 15] = [
        CrashPoint::State("Staged"),
        CrashPoint::State("Built"),
        CrashPoint::State("Activating"),
        CrashPoint::State("Checking"),
        CrashPoint::State("Published"),
        CrashPoint::State("Promoted"),
        CrashPoint::State("Reverting"),
        CrashPoint::OpBegun("activate_live"),
        CrashPoint::OpCalled("activate_live"),
        CrashPoint::OpBegun("publish_boot"),
        CrashPoint::OpCalled("publish_boot"),
        CrashPoint::OpBegun("swap_override"),
        CrashPoint::OpCalled("swap_override"),
        CrashPoint::OpBegun("runtime"),
        CrashPoint::OpCalled("runtime"),
    ];

    #[derive(Clone, Debug)]
    enum Step {
        Submit(u8),
        /// Submit, crash at a point, recover (by the watchdog first, or not).
        Crash(u8, u8, bool),
        KillWeb,
        Wait(u8),
    }

    fn proposal(k: u8) -> (Transition, Authorization) {
        let web = UnitId::service("gym-web");
        let addr = |a: &str| {
            change("listen-address", &[("service", Value::Str("gym-web".into())), ("addr", Value::Str(a.into()))])
        };
        match k % 10 {
            0 => (Transition::RestartUnit(web), admin()),
            1 => (change("font-scale", &[("scale", Value::Str("1.25".into()))]), alice()),
            2 => (change("font-scale", &[("scale", Value::Str("1.5".into()))]), alice()),
            3 => (addr("192.0.2.10"), admin()),
            4 => (addr("127.0.0.1"), admin()),
            5 => (Transition::Rollback, admin()),
            6 => (Transition::StopAndSuppress { unit: web, until: Until::Explicit, reason: "test".into() }, admin()),
            7 => (Transition::LiftOverride(web), admin()),
            8 => (Transition::CollectGarbage { emergency: false }, admin()),
            _ => (Transition::SwitchGeneration(GenerationId(1)), admin()),
        }
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            4 => any::<u8>().prop_map(Step::Submit),
            3 => (any::<u8>(), 0..POINTS.len() as u8, any::<bool>()).prop_map(|(k, p, w)| Step::Crash(k, p, w)),
            1 => Just(Step::KillWeb),
            1 => (1..30u8).prop_map(Step::Wait),
        ]
    }

    impl Rig {
        /// The daemon dies mid-transaction; the watchdog may take over what is
        /// in its window; a new daemon starts and reconciles the rest.
        fn crash_and_recover(&mut self, watchdog_first: bool, next_pid: &mut u32) {
            let dead = match &self.ex.kernel.me {
                OwnerId::Daemon { pid, .. } => *pid,
                OwnerId::Watchdog { pid, .. } => *pid,
            };
            self.fake.w().alive.remove(&dead);
            if watchdog_first {
                let journal = Journal::open(self.fake.store.clone()).unwrap();
                let host = ExecHost::new(self.fake.clone(), fixtures::canonical());
                let mut wd = Kernel::new(journal, host, OwnerId::Watchdog { pid: 200, boot_id: Hash::ZERO });
                let live: Vec<_> = wd.journal.ledger().live.values().map(|l| l.txn.clone()).collect();
                for t in live {
                    if wd.watchdog_should_take_over(&t) {
                        wd.recover(t.id, t.lease.epoch).expect("watchdog recovery");
                    }
                }
            }
            *next_pid += 1;
            let me = OwnerId::Daemon { pid: *next_pid, boot_id: Hash::ZERO };
            self.fake.w().alive.insert(*next_pid);
            let journal = Journal::open(self.fake.store.clone()).unwrap();
            self.ex = Executor::new(journal, self.fake.clone(), me, config());
            self.ex.kernel.reconcile().expect("daemon reconciliation");
            self.ex.adopt_current();
        }
    }

    fn check(r: &mut Rig) -> Result<(), TestCaseError> {
        let l = r.ex.kernel.journal.sync_ledger().unwrap().clone();
        // The proved ledger invariant, on the ledger the run produced.
        prop_assert!(l.well_formed());
        // Replaying the journal from scratch gives the same ledger.
        let replay = Journal::open(r.fake.store.clone()).unwrap().ledger().clone();
        prop_assert_eq!(&replay, &l);
        // I12: nothing is left part-way through a mutation.
        for t in l.live.values() {
            prop_assert!(t.txn.state.is_pre_mutation(), "{:?} left in {:?}", t.txn.id, t.txn.state);
        }
        // A committed generation change was published and promoted first.
        for t in l.terminal.values() {
            if t.state == TxnState::Committed && t.transition.changes_generation() {
                prop_assert!(t.path.iter().any(|p| p == "Published"), "{:?}", t.path);
                prop_assert!(t.path.iter().any(|p| p == "Promoted"), "{:?}", t.path);
            }
        }
        // The running generation is the one that boots, and no protected
        // generation was collected.
        let w = r.fake.w();
        prop_assert_eq!(w.boot_default, w.current);
        prop_assert!(!w.collected.contains(&w.current));
        prop_assert!(!w.collected.contains(&GenerationId(1)), "known-good collected");
        Ok(())
    }

    proptest! {
        #![proptest_config(PConfig {
            cases: 96,
            failure_persistence: None::<Box<dyn FailurePersistence>>,
            ..PConfig::default()
        })]

        #[test]
        fn histories_keep_the_invariants(steps in proptest::collection::vec(step(), 1..10)) {
            let mut r = Rig::new();
            let mut next_pid = 100;
            for s in steps {
                match s {
                    Step::Submit(k) => {
                        let (t, a) = proposal(k);
                        let _ = r.propose(t, a);
                    }
                    Step::Crash(k, p, watchdog_first) => {
                        let (t, a) = proposal(k);
                        r.ex.kernel.crash_at = Some(POINTS[p as usize].clone());
                        let res = r.propose(t, a);
                        r.ex.kernel.crash_at = None;
                        if matches!(res, Submitted::Error(_)) {
                            r.crash_and_recover(watchdog_first, &mut next_pid);
                        }
                    }
                    Step::KillWeb => r.fake.w().kill(&UnitId::service("gym-web")),
                    Step::Wait(n) => {
                        for _ in 0..n {
                            r.fake.advance(planarian_state::TICK);
                        }
                    }
                }
                check(&mut r)?;
            }
        }
    }
}
