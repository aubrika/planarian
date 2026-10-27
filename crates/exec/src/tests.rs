//! The executor over the fake machine. Names follow catalog entries.

use super::*;
use planarian_fake::{Fake, MemStore, fixtures, gym_world};
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

impl Rig {
    fn new() -> Rig {
        let store = MemStore::new(4 << 20);
        let fake = gym_world(store.clone());
        let cfg = Config {
            settings: Settings::default(),
            tables: tables(),
            catalog: catalog(),
            owner: PinnedSource { root: "/etc/nixos".into(), kind: SourceKind::Git },
            canonical: fixtures::canonical(),
        };
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
            suppressions: l.suppressions,
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
        self.ex.approve(&h, &s, &defs)
    }

    /// The status on the daemon's next tick.
    fn status(&mut self, u: &UnitId) -> UnitStatus {
        self.fake.advance(planarian_state::TICK);
        let (s, defs) = self.observe();
        s.status(u, &defs)
    }
}

fn admin() -> Authorization {
    Authorization { caller: Actor::User { uid: 0 }, admin: true, local_session: true, owns_affected_session: true }
}

fn alice() -> Authorization {
    Authorization { caller: Actor::User { uid: ALICE }, admin: false, local_session: true, owns_affected_session: true }
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
    let s = r.propose(Transition::RestartUnit(web.clone()), Authorization::daemon());
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
    let sup = Transition::Suppress(Suppression {
        unit: UnitId::service("sshd"),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
    });
    assert!(matches!(r.propose(sup, alice()), Submitted::Rejected { reason: RejectReason::Unauthorized, .. }));

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
    let sup = Transition::Suppress(Suppression {
        unit: pw.clone(),
        until: Until::Explicit,
        reason: String::new(),
        by: Actor::Daemon,
    });
    assert_eq!(finished(&r.propose(sup, alice())), TxnState::Committed);
    let l = r.ex.kernel.journal.sync_ledger().unwrap();
    assert_eq!(l.suppressions[0].by, Actor::User { uid: ALICE });
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
