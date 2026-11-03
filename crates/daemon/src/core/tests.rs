//! The daemon loop on the fake machine, end to end. Names follow the catalog.

use super::*;
use planarian_changes::CatalogConfig;
use planarian_exec::Config;
use planarian_fake::{Fake, MemStore, fixtures, gym_world};
use planarian_policy::{Settings, Tables};

const ADMIN: Peer = Peer::new(0, true);
const ALICE: Peer = Peer::new(1000, false);

fn config() -> CoreConfig {
    CoreConfig {
        exec: Config {
            settings: Settings::default(),
            tables: Tables {
                catalog: [
                    "service-enable",
                    "font-scale",
                    "listen-address",
                    "repair:reenable-predicted",
                    "repair:reapply",
                ]
                .map(|s| ChangeId(s.into()))
                .into(),
                runtime_allowlist: ["font.scale", "wifi.network"].map(String::from).into(),
                option_sensitivity: vec![("services.openssh".into(), Sensitivities::of(&[Sensitivity::Security]))],
                model_catalog: Default::default(),
            },
            catalog: CatalogConfig {
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
            },
            owner: PinnedSource { root: "/etc/nixos".into(), kind: SourceKind::Git },
            canonical: fixtures::canonical(),
        },
        runtime_options: vec![],
        fresh_boot: true,
        startup_grace: planarian_incident::STARTUP_GRACE,
        posture: planarian_schema::Posture::Standard,
        posture_decl: Default::default(),
        agent_limits: Default::default(),
        defer_recovery: false,
    }
}

struct Rig {
    fake: Fake,
    core: Core<Fake, MemStore>,
}

impl Rig {
    /// A machine past initial enrollment (generation 1 is known-good).
    fn new() -> Rig {
        Rig::with(config())
    }

    fn with(cfg: CoreConfig) -> Rig {
        let store = MemStore::new(8 << 20);
        let fake = gym_world(store.clone());
        fake.w().alive.insert(100);
        let mut j = Journal::open(store).unwrap();
        j.append(fake.w().now, Record::KnownGood(GenerationId(1))).unwrap();
        let core = Core::start(j, fake.clone(), OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO }, cfg);
        Rig { fake, core }
    }

    fn ticks(&mut self, n: usize) {
        for _ in 0..n {
            self.fake.advance(planarian_state::TICK);
            self.core.tick();
        }
    }

    fn status(&mut self, u: &str) -> UnitStatus {
        let id: UnitId = u.parse().unwrap();
        let (s, defs) = self.core.observe();
        s.status(&id, &defs)
    }

    fn calls(&self, prefix: &str) -> usize {
        self.fake.w().calls.iter().filter(|c| c.call.starts_with(prefix) && !c.fenced).count()
    }
}

#[test]
fn svc_killed_is_repaired_once_and_closes() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().signal(&UnitId::service("gym-web"), 11);
    r.ticks(4);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running);
    assert_eq!(r.calls("restart(service:gym-web)"), 1);
    r.ticks(70);
    assert!(r.core.incidents.active_for(&UnitId::service("gym-web")).is_none(), "closed after stabilization");
}

#[test]
fn svc_killed_defer_to_systemd() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().kill(&UnitId::service("gym-restartful"));
    r.ticks(30);
    assert_eq!(r.status("service:gym-restartful"), UnitStatus::Running);
    assert_eq!(r.calls("restart(service:gym-restartful)"), 0, "systemd did it");
}

/// dep-required-stopped under v4.4 (owner decision Q5): root's `systemctl
/// stop gym-db` outside Planarian is the unattributed residue. Under
/// Standard it is taken as intended until the next boot, with gym-app (which
/// systemd stopped with it) linked to it; nothing is restarted; one release
/// undoes both.
#[test]
fn out_of_band_stop_is_an_inferred_override_with_an_undo() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().stop_out_of_band(&UnitId::service("gym-db"));
    r.ticks(40);
    assert_eq!(r.status("service:gym-db"), UnitStatus::Overridden(OverrideDesired::Stopped));
    assert_eq!(r.status("service:gym-app"), UnitStatus::Overridden(OverrideDesired::Stopped));
    assert_eq!(r.calls("restart"), 0, "not fought");
    let l = r.core.ledger();
    for o in &l.overrides {
        assert_eq!(
            (o.by.clone(), o.attribution, o.until.clone()),
            (Actor::Unattributed, Attribution::Inferred, Until::NextBoot)
        );
    }
    assert!(r.core.notices.iter().any(|n| n.contains("planarian release service:gym-db")), "{:?}", r.core.notices);
    let resp = r.core.handle(ADMIN, Request::LiftOverride { unit: UnitId::service("gym-db") });
    assert!(matches!(resp, Response::Done { .. }), "{resp:?}");
    r.ticks(40);
    assert_eq!(r.status("service:gym-db"), UnitStatus::Running);
    assert_eq!(r.status("service:gym-app"), UnitStatus::Running);
}

/// residue-kill9-security: a Security-sensitive unit stopped outside
/// Planarian is a fault under every posture: alarmed, never inferred, and
/// restored on its own (§11; catalog-review G16, decided 2026-10-29).
#[test]
fn security_unit_stop_is_a_fault_and_alarmed() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().kill(&UnitId::service("sshd"));
    r.ticks(10);
    assert!(r.core.notices.iter().any(|n| n.starts_with("ALARM: service:sshd")), "{:?}", r.core.notices);
    assert!(r.core.ledger().overrides.is_empty());
    assert!(r.core.ex.parked.is_empty(), "restored without asking");
    assert_eq!(r.status("service:sshd"), UnitStatus::Running);
}

/// residue-oom-kill: the OOM killer's SIGKILL is a fault, not a person.
#[test]
fn oom_kill_is_repaired() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().oom(&UnitId::service("gym-web"));
    r.ticks(6);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running);
    assert!(r.core.ledger().overrides.is_empty());
}

/// residue-kill9-service under Guarded: no inference; repaired.
#[test]
fn guarded_posture_does_not_infer() {
    let mut cfg = config();
    cfg.posture = Posture::Guarded;
    let mut r = Rig::with(cfg);
    r.ticks(2);
    r.fake.w().kill(&UnitId::service("gym-web"));
    r.ticks(6);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running);
}

#[test]
fn ordering_only_predecessor_is_not_blamed() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().signal(&UnitId::service("gym-cache"), 11);
    r.ticks(10);
    assert_eq!(r.calls("restart(service:gym-app)"), 0);
    assert_eq!(r.status("service:gym-cache"), UnitStatus::Running);
}

#[test]
fn intent_user_stops_service_and_it_stays_stopped() {
    let mut r = Rig::new();
    r.ticks(2);
    let resp = r.core.handle(ADMIN, Request::Ask { phrase: "stop gym-web until I say".into(), choice: None });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    r.ticks(60);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Overridden(OverrideDesired::Stopped));
    assert_eq!(r.calls("restart(service:gym-web)"), 0, "no repair race");
    let resp = r.core.handle(ADMIN, Request::Ask { phrase: "start gym-web again".into(), choice: None });
    assert!(matches!(resp, Response::Done { .. }), "{resp:?}");
    r.ticks(6);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running, "desired again, so repaired");
}

#[test]
fn unprivileged_override_of_a_security_unit_is_held_for_an_administrator() {
    let mut r = Rig::new();
    r.ticks(2);
    let sshd = UnitId::service("sshd");
    let req = Request::SetOverride { unit: sshd.clone(), until: Until::Explicit, desired: OverrideDesired::Stopped };
    let resp = r.core.handle(ALICE, req);
    let Response::NeedsApproval { approve, .. } = resp else { panic!("{resp:?}") };
    r.ticks(2);
    assert_eq!(r.status("service:sshd"), UnitStatus::Running, "stays up while held");
    // I19: never the proposer; Phase A approval is root at a terminal.
    let resp = r.core.handle(ALICE.at_terminal(), Request::Approve { hash: approve });
    assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
    let resp = r.core.handle(ADMIN.at_terminal(), Request::Approve { hash: approve });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    r.ticks(2);
    assert_eq!(r.status("service:sshd"), UnitStatus::Overridden(OverrideDesired::Stopped));
    let l = r.core.ledger();
    assert_eq!(l.overrides[0].by.uid(), Some(1000), "attributed to alice, not the approver");
}

/// §11 (owner decision, 2026-10-30): an agent has the permissions of the
/// user who started it, bound to the instance that start journaled (I24),
/// and is attributed to itself in the log. One with no journaled start, or
/// in an instance no start names, holds nothing.
#[test]
fn an_agent_has_its_users_permissions() {
    let mut r = Rig::new();
    r.ticks(2);
    let stop_web = || Request::Stop { unit: UnitId::service("gym-web") };
    let instance = |r: &Rig, name: &str| r.fake.w().agent_instances.get(name).copied();
    // Never started through `agent run`: nothing.
    let stray = Peer::agent(61185, "stray", None);
    let resp = r.core.handle(stray, stop_web());
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // Started by alice: alice's permissions, which do not reach gym-web.
    let resp = r.core.handle(ALICE, Request::AgentRun { name: "helper".into(), argv: vec!["true".into()] });
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let helper = Peer::agent(61186, "helper", instance(&r, "helper"));
    let resp = r.core.handle(helper.clone(), stop_web());
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // An agent cannot start agents.
    let resp = r.core.handle(helper.clone(), Request::AgentRun { name: "more".into(), argv: vec!["true".into()] });
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // B-20: an administrator re-running `agent run helper` is refused while
    // alice's agent runs, naming its owner, and her agent gains nothing.
    let resp = r.core.handle(ADMIN, Request::AgentRun { name: "helper".into(), argv: vec!["true".into()] });
    assert!(
        matches!(&resp, Response::Rejected { message, .. } if message.contains("uid 1000")),
        "a name in use is refused: {resp:?}"
    );
    let resp = r.core.handle(helper, stop_web());
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // A process claiming the name in another instance holds nothing.
    let forged = Peer::agent(61186, "helper", Some(planarian_schema::InstanceId([7; 16])));
    let resp = r.core.handle(forged, stop_web());
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // Started by an administrator: an administrator's permissions.
    let resp = r.core.handle(ADMIN, Request::AgentRun { name: "coder".into(), argv: vec!["true".into()] });
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    r.ticks(1);
    // Planarian does not manage the agent's unit: it is not in the manifest.
    assert_eq!(r.status("service:planarian-agent-coder"), UnitStatus::NotExpected);
    let coder = Peer::agent(61184, "coder", instance(&r, "coder"));
    let resp = r.core.handle(coder, stop_web());
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    // A finished transaction's record is logged at the next observation.
    r.ticks(1);
    let rec = r.core.log.iter().rev().find(|l| matches!(l.proposal.transition, Transition::StopAndSuppress { .. }));
    let rec = rec.expect("logged");
    assert_eq!(rec.agent.as_deref(), Some("coder"), "attributed to the agent");
    assert_eq!(rec.caller.uid(), Some(0), "acting for the administrator who started it");
    // Who it acts for is in the journal, by instance, so it survives a restart.
    let l = r.core.ledger();
    assert_eq!(l.agent_for("coder", instance(&r, "coder").unwrap().0), Some(0));
    assert_eq!(l.agent_for("helper", instance(&r, "helper").unwrap().0), Some(1000));
    assert_eq!(l.agent_for("helper", [7; 16]), None);
}

#[test]
fn cli_stop_is_rewritten() {
    let mut r = Rig::new();
    let resp = r.core.handle(ADMIN, Request::Stop { unit: UnitId::service("gym-web") });
    let Response::Done { message, .. } = resp else { panic!("{resp:?}") };
    assert!(message.contains("until the next boot"));
    let l = r.core.ledger();
    assert_eq!(l.overrides[0].until, Until::NextBoot);
}

#[test]
fn flapping_is_bounded() {
    let mut r = Rig::new();
    r.ticks(2);
    {
        let mut w = r.fake.w();
        let now = w.now;
        let sim = w.units.get_mut(&UnitId::service("gym-flap")).unwrap();
        sim.fail_after = Some(Millis::secs(30));
        sim.started_at = now;
    }
    r.ticks(20 * 12); // 20 minutes
    let restarts = r.calls("restart(service:gym-flap)");
    assert!(restarts <= 3, "{restarts} restarts in 20 minutes");
    let inc = r.core.incidents.active_for(&UnitId::service("gym-flap")).unwrap();
    assert!(matches!(inc.state, IncidentState::Cooldown { .. }), "{:?}", inc.state);
}

#[test]
fn bad_config_reverts_and_good_config_commits() {
    let mut r = Rig::new();
    r.ticks(2);
    let mut args = BTreeMap::new();
    args.insert("service".to_string(), Value::Str("gym-web".into()));
    args.insert("addr".to_string(), Value::Str("192.0.2.10".into()));
    let resp = r.core.handle(ADMIN, Request::Apply { change: ChangeId("listen-address".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Reverted, .. }), "{resp:?}");
    assert_eq!(r.fake.w().current, GenerationId(1));
    r.ticks(2);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running);
    let resp = r.core.handle(ALICE, Request::Ask { phrase: "make text bigger".into(), choice: None });
    // No runtime options configured in this rig: it is not understood as a setting.
    assert!(matches!(resp, Response::Unmatched { .. } | Response::Confirm { .. }), "{resp:?}");
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let resp = r.core.handle(ALICE, Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
}

#[test]
fn initial_enrollment_then_tested_tier() {
    let store = MemStore::new(8 << 20);
    let fake = gym_world(store.clone());
    let mut core = Core::start(
        Journal::open(store).unwrap(),
        fake.clone(),
        OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO },
        config(),
    );
    // No baseline yet: a Tested change asks.
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let resp = core.handle(ALICE, Request::Apply { change: ChangeId("font-scale".into()), args: args.clone() });
    assert!(matches!(resp, Response::NeedsApproval { .. }), "{resp:?}");
    let Response::Status(st) = core.handle(ALICE, Request::Status) else { panic!() };
    assert!(st.baseline_note.is_some());
    for _ in 0..125 {
        fake.advance(planarian_state::TICK);
        core.tick();
    }
    assert_eq!(core.ledger().known_good, Some(GenerationId(1)));
}

#[test]
fn ga_demo_crash_watchdog_then_reconcile() {
    use planarian_exec::host::ExecHost;
    use planarian_txn::kernel::{CrashPoint, Kernel};
    let mut r = Rig::new();
    r.ticks(2);
    r.core.ex.kernel.crash_at = Some(CrashPoint::State("Activating"));
    let mut args = BTreeMap::new();
    args.insert("service".to_string(), Value::Str("gym-web".into()));
    args.insert("addr".to_string(), Value::Str("192.0.2.10".into()));
    let resp = r.core.handle(ADMIN, Request::Apply { change: ChangeId("listen-address".into()), args });
    assert!(matches!(resp, Response::Error { .. }), "killed mid-activation: {resp:?}");
    r.fake.w().alive.remove(&100);

    // The watchdog, from the journal alone.
    let mut wd = Kernel::new(
        Journal::open(r.fake.store.clone()).unwrap(),
        ExecHost::new(r.fake.clone(), fixtures::canonical()),
        OwnerId::Watchdog { pid: 200, boot_id: Hash::ZERO },
    );
    let txn = wd.journal.ledger().live.values().next().unwrap().txn.clone();
    assert!(wd.watchdog_should_take_over(&txn));
    assert_eq!(wd.recover(txn.id, txn.lease.epoch).unwrap(), TxnState::Reverted);

    // The daemon restarts and explains.
    r.fake.w().alive.insert(101);
    let mut core = Core::start(
        Journal::open(r.fake.store.clone()).unwrap(),
        r.fake.clone(),
        OwnerId::Daemon { pid: 101, boot_id: Hash::ZERO },
        config(),
    );
    let Response::Status(st) = core.handle(ADMIN, Request::Status) else { panic!() };
    let rec = st.reconciliation.unwrap().join("\n");
    assert!(rec.contains("the watchdog took over and finished it: Reverted"), "{rec}");
    assert_eq!(r.fake.w().current, GenerationId(1));
}

/// #9: the daemon restarted with `defer_recovery` reaches ready before it
/// reverts an interrupted activation; `finish_recovery` then reverts it.
#[test]
fn restart_reverts_an_interrupted_activation_after_ready() {
    use planarian_txn::kernel::CrashPoint;
    let mut r = Rig::new();
    r.ticks(2);
    r.core.ex.kernel.crash_at = Some(CrashPoint::State("Activating"));
    let mut args = BTreeMap::new();
    args.insert("service".to_string(), Value::Str("gym-web".into()));
    args.insert("addr".to_string(), Value::Str("192.0.2.10".into()));
    let resp = r.core.handle(ADMIN, Request::Apply { change: ChangeId("listen-address".into()), args });
    assert!(matches!(resp, Response::Error { .. }), "killed mid-activation: {resp:?}");
    r.fake.w().alive.remove(&100);
    let calls = r.fake.w().calls.len();

    r.fake.w().alive.insert(101);
    let mut cfg = config();
    cfg.defer_recovery = true;
    let mut core = Core::start(
        Journal::open(r.fake.store.clone()).unwrap(),
        r.fake.clone(),
        OwnerId::Daemon { pid: 101, boot_id: Hash::ZERO },
        cfg,
    );
    // Started (ready): nothing activated yet, the change still Activating.
    assert_eq!(r.fake.w().calls.len(), calls, "no backend call before ready");
    assert!(core.ledger().live.values().any(|l| l.txn.state == TxnState::Activating));
    assert_eq!(core.pending_recovery().as_deref(), Some("recovering transaction 1 after the restart"));

    core.finish_recovery();
    assert_eq!(core.pending_recovery(), None);
    assert!(core.ledger().live.is_empty());
    assert!(core.ledger().terminal.values().any(|t| t.state == TxnState::Reverted));
    assert_eq!(r.fake.w().current, GenerationId(1));
}

#[test]
fn shared_root_cause_parks_one_approval() {
    // A sensitive dependency (sshd is Security): restarting it asks first.
    // Two incidents leading to it must share one approval.
    let mut r = Rig::new();
    let mut client = fixtures::gym_units()[&UnitId::service("gym-app")].clone();
    client.id = UnitId::service("ssh-tunnel");
    client.edges = vec![Edge {
        from: client.id.clone(),
        to: UnitId::service("sshd"),
        kind: EdgeKind::Requires,
        origin: EdgeOrigin::Manifest,
    }];
    let mut m = r.core.asm.manifest().clone();
    m.units.insert(client.id.clone(), client.clone());
    r.core.asm.set_manifest(m);
    r.fake.w().base_units.insert(client.id.clone(), client);
    r.fake.w().units.insert(UnitId::service("ssh-tunnel"), planarian_fake::UnitSim::active(Timestamp(0)));
    r.ticks(2);
    // A crash: restoring a Security unit after a crash still asks (only an
    // unattributed stop is restored on its own).
    r.fake.w().signal(&UnitId::service("sshd"), 11);
    r.ticks(8);
    assert_eq!(r.core.ex.parked.len(), 1, "{:?}", r.core.notices);
}

/// §12b: over the count bound, the daemon collects the oldest unprotected
/// generations itself (Runtime), at most once an hour, and never the
/// protected ones.
#[test]
fn generations_over_the_bound_are_collected_by_maintenance() {
    let mut r = Rig::new();
    {
        let mut w = r.fake.w();
        for _ in 0..13 {
            let g = w.add_generation(&OverrideSet::default());
            w.boot_entries.insert(g);
        }
    }
    r.ticks(1);
    let collected = r.fake.w().collected.clone();
    assert_eq!(collected, vec![GenerationId(2), GenerationId(3), GenerationId(4), GenerationId(5)]);
    assert!(!collected.contains(&GenerationId(1)), "known-good is protected");
    // The log record is completed with the post-state at the next observation.
    r.ticks(1);
    let record = r.core.log.iter().find(|l| l.proposal.source == Source::Maintenance).expect("logged");
    assert!(record.post_digest.is_some() && record.facts.is_some() && record.decision.is_some(), "I7: {record:?}");
    assert!(r.core.log.iter().any(|l| l.proposal.source == Source::Maintenance
        && matches!(l.result, Submitted::Finished { state: TxnState::Committed, .. })));
    let report = r.fake.w().space_report.clone().expect("a report");
    assert_eq!((report.generations, report.shortfall), (10, None));
    // Nothing more to collect: no further collection within the hour or after.
    let before = r.core.log.len();
    r.ticks(800);
    assert!(r.core.log[before..].iter().all(|l| l.proposal.source != Source::Maintenance));
}

/// Activating a generation restarts every active target, which starts the
/// services they want, including one the user stopped. Planarian's own
/// activations (a change, and a revert) stop it again (principle 9).
#[test]
fn a_users_stop_survives_generation_changes() {
    let mut r = Rig::new();
    r.ticks(2);
    let cache = UnitId::service("gym-cache");
    let resp = r.core.handle(ADMIN, Request::Stop { unit: cache.clone() });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    let stopped = |r: &Rig| r.fake.w().units[&cache].observed != Observed::Active;
    assert!(stopped(&r));

    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let resp = r.core.handle(ADMIN, Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert!(stopped(&r), "a committed change left the user's stop in place");

    let mut args = BTreeMap::new();
    args.insert("service".to_string(), Value::Str("gym-web".into()));
    args.insert("addr".to_string(), Value::Str("192.0.2.10".into()));
    let resp = r.core.handle(ADMIN, Request::Apply { change: ChangeId("listen-address".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Reverted, .. }), "{resp:?}");
    assert!(stopped(&r), "a revert left the user's stop in place");
    r.ticks(20);
    assert!(stopped(&r));
    assert_eq!(r.status("service:gym-cache"), UnitStatus::Overridden(OverrideDesired::Stopped));
}

#[test]
fn reads_are_answered_from_a_snapshot_while_busy() {
    use crate::snapshot::{self, Busy, Snapshot};
    let mut r = Rig::new();
    r.ticks(2);
    let apply = Request::Apply { change: ChangeId("service-enable".into()), args: Default::default() };
    assert!(!snapshot::read_only(&apply) && snapshot::read_only(&Request::Log { limit: 5 }));
    let snap = Snapshot::take(&mut r.core).expect("snapshot");
    let busy = Busy { with: snapshot::describe(&apply), since: std::time::Instant::now() };
    let Some(Response::Status(s)) = snap.answer(&Request::Status, &busy) else { panic!("status") };
    assert!(s.notices[0].starts_with("busy with the change service-enable for under a minute"), "{:?}", s.notices);
    assert!(s.units.iter().any(|u| u.unit == UnitId::service("gym-web")));
    let Some(Response::Console(c)) = snap.answer(&Request::Console, &busy) else { panic!("console") };
    assert!(c.status.notices[0].starts_with("busy with"));
    let Some(Response::Log { lines }) = snap.answer(&Request::Log { limit: 1 }, &busy) else { panic!("log") };
    assert_eq!(lines.len(), 1);
    assert!(snap.answer(&apply, &busy).is_none());
}

#[test]
fn a_change_builds_elsewhere_while_repairs_go_on() {
    let mut r = Rig::new();
    r.core.defer = true;
    r.ticks(2);
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let placeholder = r.core.handle(ALICE, Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(placeholder, Response::Ok { .. }), "{placeholder:?}");
    let (job, resume) = r.core.take_deferred().expect("deferred");
    assert_eq!(resume.describe(), "apply font-scale scale=1.25");
    // The build runs on another thread; meanwhile a service dies and the tick repairs it.
    let worker = std::thread::spawn(move || job.run());
    r.core.building = Some((resume.describe(), Timestamp(0)));
    r.fake.w().signal(&UnitId::service("gym-web"), 11);
    r.ticks(4);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running);
    assert_eq!(r.calls("restart(service:gym-web)"), 1);
    let Response::Status(s) = r.core.handle(ALICE, Request::Status) else { panic!() };
    assert!(s.notices[0].starts_with("building apply font-scale scale=1.25 ("), "{:?}", s.notices);
    r.core.building = None;
    let resp = r.core.resume(resume, worker.join().unwrap());
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    // Built once, on the worker: resuming did not build again.
    assert_eq!(r.fake.w().builds, 1);
}

#[test]
fn a_prebuilt_candidate_from_an_older_override_file_is_not_used() {
    let mut r = Rig::new();
    r.core.defer = true;
    r.ticks(2);
    let apply = |scale: &str| {
        let mut args = BTreeMap::new();
        args.insert("scale".to_string(), Value::Str(scale.into()));
        Request::Apply { change: ChangeId("font-scale".into()), args }
    };
    r.core.handle(ALICE, apply("1.25"));
    let (job, resume) = r.core.take_deferred().expect("deferred");
    let pre = job.run();
    // Another change commits first and rewrites the override file.
    r.core.defer = false;
    let resp = r.core.handle(ALICE, apply("1.5"));
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    r.core.defer = true;
    let resp = r.core.resume(resume, pre);
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    // The stale candidate was rebuilt against the new file.
    assert_eq!(r.fake.w().builds, 3);
}

#[test]
fn notices_keep_reaching_the_journal_once_the_deque_is_full() {
    let mut r = Rig::new();
    let mut printed = r.core.notices_total;
    let mut seen = vec![];
    for i in 0..(super::NOTICES_KEPT * 3) {
        r.core.notice(format!("n{i}"));
        if i % 7 == 0 {
            seen.extend(r.core.notices_since(printed).cloned());
            printed = r.core.notices_total;
        }
    }
    seen.extend(r.core.notices_since(printed).cloned());
    let want: Vec<String> = (0..super::NOTICES_KEPT * 3).map(|i| format!("n{i}")).collect();
    assert_eq!(seen, want, "each notice once, in order, also after the first {}", super::NOTICES_KEPT);
}

#[test]
fn an_untracked_file_added_during_the_build_is_reported_not_stale() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().untracked_on_stage = Some("scratch.nix".into());
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let resp = r.core.handle(ALICE, Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert!(
        r.core.notices.iter().any(|n| n.contains("left out of the build") && n.contains("scratch.nix")),
        "{:?}",
        r.core.notices
    );
}

#[test]
fn a_deferred_change_reaches_the_executor_log() {
    let mut r = Rig::new();
    r.ticks(2);
    r.core.log.clear();
    r.core.defer = true;
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let placeholder = r.core.handle(ALICE, Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(placeholder, Response::Ok { .. }), "{placeholder:?}");
    let (job, resume) = r.core.take_deferred().expect("deferred");
    let resp = r.core.resume(resume, job.run());
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    r.ticks(1);
    assert!(
        r.core.log.iter().any(|l| matches!(l.proposal.transition, Transition::ApplyChange { .. })),
        "{:?}",
        r.core.log
    );
}

#[test]
fn executor_log_records_serialize() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().signal(&UnitId::service("gym-web"), 11);
    r.ticks(4);
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    r.core.handle(ALICE, Request::Apply { change: ChangeId("font-scale".into()), args });
    r.ticks(1);
    assert!(r.core.log.len() >= 2, "{:?}", r.core.log);
    for l in &r.core.log {
        let j = serde_json::to_string(l).unwrap_or_else(|e| panic!("{e}: {l:?}"));
        let back: LogRecord = serde_json::from_str(&j).unwrap_or_else(|e| panic!("{e}: {j}"));
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
    }
}

#[test]
fn an_unreachable_external_dependency_is_said_not_repaired() {
    // Traffic to the gateway is dropped: every probe on the way times out.
    let mut r = Rig::new();
    r.ticks(2);
    let client = UnitId::service("gym-upstream-client");
    r.fake.w().external_unreachable.insert("gym-upstream".into());
    r.ticks(12);
    assert!(!r.core.notices.iter().any(|n| n.contains("can't reach")), "not before it has lasted");
    r.ticks(24);
    let said: Vec<&String> = r.core.notices.iter().filter(|n| n.contains("can't reach")).collect();
    assert_eq!(said.len(), 1, "{:?}", r.core.notices);
    assert!(said[0].starts_with("service:external:gym-upstream:"), "{said:?}");
    assert_eq!(r.status("service:gym-upstream-client"), UnitStatus::Unknown);
    // Unknown opens a diagnostic incident (re-observe, no budget), never a repair.
    assert!(
        r.core.incidents.active_for(&client).is_none_or(|i| i.kind == IncidentKind::Diagnostic),
        "{:?}",
        r.core.incidents.active_for(&client)
    );
    assert_eq!(r.calls("restart("), 0, "nothing local is restarted");
    r.fake.w().external_unreachable.clear();
    r.ticks(4);
    assert!(r.core.notices.iter().any(|n| n == "service:external:gym-upstream: answers again"), "{:?}", r.core.notices);
}

#[test]
fn a_definite_failure_is_repaired_promptly_while_probes_time_out() {
    // probe-failed-beats-stale: gym-web's HTTP answer is slow (Unknown,
    // re-observed), then the process is killed: Failed, and repaired
    // within a tick or two plus the first backoff, not after the
    // re-observation's backoff.
    let mut r = Rig::new();
    r.ticks(2);
    let web = UnitId::service("gym-web");
    r.fake.w().units.get_mut(&web).unwrap().health = planarian_fake::Health::Delay(Millis::secs(60));
    r.ticks(12);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Unknown);
    r.fake.w().signal(&web, 11);
    let mut n = 0;
    while r.calls("restart(service:gym-web)") == 0 && n < 60 {
        r.ticks(1);
        n += 1;
    }
    assert!(n <= 6, "restarted after {n} ticks ({} s): {:?}", n * 5, r.core.notices);
}

#[test]
fn status_requests_do_not_run_the_probes() {
    // Readers (the tray, the console, the gym's sampler) ask often; each
    // probe run can take a probe timeout, which held the core for minutes.
    let mut r = Rig::new();
    r.ticks(2);
    let before = r.fake.w().probe_batches;
    for _ in 0..5 {
        // Time passes (the probes fall due) but no tick runs.
        r.fake.advance(planarian_state::TICK);
        assert!(matches!(r.core.handle(ALICE, Request::Status), Response::Status(_)));
        assert!(matches!(r.core.handle(ALICE, Request::Console), Response::Console(_)));
    }
    assert_eq!(r.fake.w().probe_batches, before);
}

#[test]
fn a_repaired_root_cause_is_named_for_its_dependents() {
    // drv-unbound-audio: alice's pipewire degrades because the sound card's
    // driver is unbound; the card is rebound, and pipewire is told why.
    let mut r = Rig::new();
    let now = r.fake.w().now;
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1000".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        active: true,
        idle: false,
        created: now,
    });
    for name in ["pipewire", "wireplumber"] {
        r.fake.w().units.insert(
            UnitId { kind: UnitKind::Service, name: name.into(), scope: Scope::User { uid: 1000, session: None } },
            planarian_fake::UnitSim::active(now),
        );
    }
    r.ticks(30);
    r.fake.w().devices.insert(UnitId::device("snd-hda0"), None);
    r.ticks(20);
    assert!(
        r.core
            .notices
            .iter()
            .any(|n| n.starts_with("service@1000:pipewire:") && n.contains("(root cause: device:snd-hda0)")),
        "{:#?}",
        r.core.notices
    );
}

/// journal-record-edited (I18): a retained record edited on disk while the
/// daemon runs is caught at the next chain check; the daemon reports an
/// Integrity failure instead of acting on the edited history.
#[test]
fn edited_journal_record_is_an_integrity_failure() {
    let mut r = Rig::new();
    let resp = r.core.handle(ADMIN, Request::Restart { unit: UnitId::service("gym-web") });
    assert!(matches!(resp, Response::Done { .. }), "{resp:?}");
    r.ticks(2);
    assert!(r.core.integrity.is_none());
    let store = r.fake.store.clone();
    assert!(
        planarian_txn::journal::tamper(&store, 1, |p| {
            let i = p.iter().position(|b| b.is_ascii_digit()).unwrap();
            p[i] = if p[i] == b'9' { b'1' } else { p[i] + 1 };
        })
        .unwrap()
    );
    r.fake.advance(CHAIN_CHECK_EVERY);
    r.core.tick();
    assert!(
        r.core.integrity.as_deref().is_some_and(|w| w.contains("hash chain") || w.contains("no longer")),
        "{:?}",
        r.core.integrity
    );
}

/// quiet-staged-update-foreground across a restart (§12f): a generation
/// waiting in Built is Rejected(Interrupted) when the daemon restarts, and
/// prepared again; with Foreground still holding, it waits again.
#[test]
fn waiting_generation_is_prepared_again_after_a_restart() {
    let mut r = Rig::new();
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        created: Timestamp(0),
        active: true,
        idle: false,
    });
    r.fake.w().foreground.insert("s1".into());
    r.ticks(2);
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let resp = r.core.handle(ALICE.in_session("s1"), Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Built, .. }), "{resp:?}");

    // The daemon restarts.
    let store = r.fake.store.clone();
    r.fake.w().alive.insert(101);
    r.core = Core::start(
        Journal::open(store).unwrap(),
        r.fake.clone(),
        OwnerId::Daemon { pid: 101, boot_id: Hash::ZERO },
        config(),
    );
    r.ticks(2);
    let l = r.core.ledger();
    assert!(l.terminal.values().any(|t| t.state == TxnState::Rejected(RejectReason::Interrupted)));
    assert!(l.live.values().any(|t| t.txn.state == TxnState::Built), "prepared again, waiting again");

    // Foreground ends: it activates in that window.
    r.fake.w().foreground.clear();
    r.ticks(4);
    let l = r.core.ledger();
    assert!(l.live.is_empty());
    assert!(
        l.terminal
            .values()
            .any(|t| t.state == TxnState::Committed && matches!(t.transition, Transition::ApplyChange { .. }))
    );
}

/// §9 hook: a verified external document's units join the generation's;
/// a failure of one says where its declaration came from (future-work T5);
/// a unit the generation declares stays the generation's.
#[test]
fn external_desired_state_joins_with_provenance() {
    let mut r = Rig::new();
    r.ticks(2);
    let web = UnitId::service("gym-web");
    let ext = UnitId::service("gym-ext");
    let mut def = r.core.asm.manifest().units[&web].clone();
    def.id = ext.clone();
    def.probes.clear();
    let mut shadow = def.clone();
    shadow.id = web.clone();
    shadow.synonyms = vec!["from outside".into()];
    let doc = crate::hooks::DesiredDoc {
        seq: 7,
        issued: Timestamp(1),
        issuer: "fleet-test".into(),
        units: [(ext.clone(), def), (web.clone(), shadow)].into(),
    };
    r.core.set_external(Some(doc));
    assert!(
        r.core.notices.iter().any(|n| n.contains("sequence 7") && n.contains("fleet-test")),
        "{:?}",
        r.core.notices
    );
    assert!(r.core.notices.iter().any(|n| n.contains("the generation's declaration stands")));
    assert!(r.core.asm.manifest().units.contains_key(&ext));
    assert!(r.core.asm.manifest().units[&web].synonyms.iter().all(|s| s != "from outside"));
    // The document's unit is taken for its desired state only: no edges it
    // drew, and Security-sensitive, so acting on it asks first.
    let taken = &r.core.asm.manifest().units[&ext];
    assert!(taken.edges.is_empty());
    assert!(taken.sensitivity.contains(Sensitivity::Security));
    assert!(!taken.probes.iter().any(|p| matches!(p.kind, ProbeKind::Exec { .. })));
    assert!(r.core.origin_of(&web).is_none());
    r.ticks(6);
    assert!(
        r.core
            .notices
            .iter()
            .any(|n| n.starts_with("service:gym-ext") && n.contains("declared by the external desired-state source")),
        "{:?}",
        r.core.notices
    );
    // Dropped: the unit is no longer desired.
    r.core.set_external(None);
    assert!(!r.core.asm.manifest().units.contains_key(&ext));
}

/// §12f, I12 (S03): a repair that has to wait in Built for an activation
/// window (its activation would restart a busy session's audio) is not an
/// attempt: the incident waits with it, and when the wait expires the change
/// is Cancelled(Daemon) and the incident reopens with its budget intact.
/// (Under Foreground the same repair would be deferred before it is
/// proposed, P8.)
#[test]
fn an_expired_wait_reopens_its_incident() {
    let mut cfg = config();
    cfg.exec.catalog.services.insert("gym-web".into(), "services.gym-web.enable".into());
    let mut r = Rig::with(cfg);
    r.ticks(2);
    let now = r.fake.w().now;
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        active: true,
        idle: false,
        created: now,
    });
    r.fake.w().activation_restarts.insert(UnitId {
        kind: UnitKind::Service,
        name: "pipewire".into(),
        scope: Scope::User { uid: 1000, session: None },
    });
    r.fake.w().units.get_mut(&UnitId::service("gym-web")).unwrap().observed = Observed::Absent;
    r.ticks(20);
    let waiting = |r: &mut Rig| {
        r.core.ledger().live.values().filter(|t| t.txn.state == TxnState::Built).map(|t| t.txn.id).collect::<Vec<_>>()
    };
    let first = waiting(&mut r);
    assert_eq!(first.len(), 1, "the repair waits in Built: {:?}", r.core.notices);
    let budget = |r: &Rig| r.core.incidents.active_for(&UnitId::service("gym-web")).map(|i| i.budget_left);
    assert_eq!(budget(&r), Some(planarian_incident::BUDGET), "waiting spends no budget");
    r.ticks(10);
    assert_eq!(waiting(&mut r), first, "the incident is not retried while its repair waits");

    r.fake.advance(Millis::secs(25 * 3600));
    r.ticks(20);
    let l = r.core.ledger();
    assert!(matches!(l.terminal.get(&first[0]).map(|t| &t.state), Some(TxnState::Cancelled(Actor::Daemon))));
    let again = waiting(&mut r);
    assert!(again.len() == 1 && again != first, "the reopened incident proposes the repair again: {again:?}");
    assert_eq!(budget(&r), Some(planarian_incident::BUDGET));
}

/// §12d (R05): one uid may have only so many agents running at once; a
/// launch over the limit is refused, and one that has stopped frees its slot.
#[test]
fn agents_per_uid_are_limited() {
    let mut cfg = config();
    cfg.agent_limits.per_uid = 2;
    let mut r = Rig::with(cfg);
    r.ticks(2);
    let run = |r: &mut Rig, peer: Peer, name: &str| {
        r.core.handle(peer, Request::AgentRun { name: name.into(), argv: vec!["true".into()] })
    };
    assert!(matches!(run(&mut r, ALICE, "one"), Response::Ok { .. }));
    assert!(matches!(run(&mut r, ALICE, "two"), Response::Ok { .. }));
    let over = run(&mut r, ALICE, "three");
    assert!(
        matches!(&over, Response::Rejected { message, .. } if message.contains("limit")),
        "a third launch is refused: {over:?}"
    );
    // Another uid has its own count.
    assert!(matches!(run(&mut r, ADMIN, "theirs"), Response::Ok { .. }));
    // One of alice's stops: she may start another.
    r.fake.w().units.get_mut(&UnitId::service("planarian-agent-one")).unwrap().observed =
        Observed::Failed(planarian_schema::Reason::ExitCode(0));
    assert!(matches!(run(&mut r, ALICE, "three"), Response::Ok { .. }), "a stopped agent frees its slot");
}

/// P7 (§12a): a write-back issued while a generation transaction is active
/// (here one waiting in Built while Foreground holds) is queued, not
/// refused; it is submitted, with the same caller, once that transaction is
/// terminal, and commits. Nothing says it failed.
#[test]
fn a_write_back_queues_behind_a_generation_transaction() {
    let mut r = Rig::new();
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        created: Timestamp(0),
        active: true,
        idle: false,
    });
    r.fake.w().foreground.insert("s1".into());
    r.ticks(2);
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let resp = r.core.handle(ALICE.in_session("s1"), Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Built, .. }), "{resp:?}");

    let authz = r.core.authz(&ALICE.in_session("s1"));
    let (s, defs) = r.core.observe();
    let t = Transition::SetRuntimeOption { path: "font.scale".into(), value: Value::Str("1.5".into()) };
    let p = r.core.proposal(t, &s, &defs, Source::User, "bigger".into());
    let res = r.core.submit(p, authz, &s, &defs);
    assert!(matches!(res, Submitted::Finished { state: TxnState::Committed, .. }), "{res:?}");
    assert_eq!(r.core.writebacks.len(), 1, "queued behind the waiting generation");

    r.fake.w().foreground.clear();
    r.ticks(6);
    assert!(r.core.writebacks.is_empty());
    let l = r.core.ledger();
    assert!(!l.live.values().any(|t| t.txn.transition.changes_generation()));
    let applied: Vec<_> = l
        .terminal
        .values()
        .filter(|t| matches!(t.transition, Transition::ApplyChange { .. }))
        .map(|t| t.state.clone())
        .collect();
    assert_eq!(applied, vec![TxnState::Committed, TxnState::Committed], "the change, then the write-back");
    assert!(!r.core.notices.iter().any(|n| n.contains("will not survive")), "{:?}", r.core.notices);
}

/// P8 (§12f): while Foreground holds, a repair the foreground work does not
/// depend on is deferred in fact: never attempted, no budget or backoff
/// spent. It runs once quiet mode ends.
#[test]
fn a_deferred_repair_is_deferred_in_fact() {
    let mut r = Rig::new();
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        created: Timestamp(0),
        active: true,
        idle: false,
    });
    r.fake.w().foreground.insert("s1".into());
    r.ticks(2);
    let web = UnitId::service("gym-web");
    r.fake.w().signal(&web, 11);
    r.ticks(30);
    assert_eq!(r.calls("restart(service:gym-web)"), 0, "deferred while the game runs");
    let i = r.core.incidents.active_for(&web).expect("an incident is open").clone();
    assert!(i.attempts.is_empty(), "no budget spent: {:?}", i.attempts);

    r.fake.w().foreground.clear();
    r.ticks(4);
    assert_eq!(r.calls("restart(service:gym-web)"), 1);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running);
}

/// K10 (§16): mark-good needs root at an interactive terminal, the
/// terminal established by the daemon from the peer; an administrator
/// without one, or a non-root administrator, is refused.
#[test]
fn mark_good_needs_root_at_a_terminal() {
    let mut r = Rig::new();
    r.ticks(2);
    let refused =
        |resp: &Response| matches!(resp, Response::Error { message } if message.contains("interactive terminal"));
    let resp = r.core.handle(ADMIN, Request::MarkGood { accept_unconfirmed: false });
    assert!(refused(&resp), "{resp:?}");
    let resp = r.core.handle(Peer::new(1001, true).at_terminal(), Request::MarkGood { accept_unconfirmed: false });
    assert!(refused(&resp), "{resp:?}");
    let resp = r.core.handle(ADMIN.at_terminal(), Request::MarkGood { accept_unconfirmed: false });
    assert!(!refused(&resp), "{resp:?}");
}

/// P17 (§16): `report boot` prints the last boot report; `posture` prints
/// the posture and timeout in force and says when a weaker declaration
/// waits for the next boot (P16).
#[test]
fn report_boot_and_posture_answer() {
    let mut cfg = config();
    cfg.posture_decl = crate::config::PostureDecl {
        declared: planarian_schema::Posture::Relaxed,
        declared_timeout_secs: 600,
        booted: Some((planarian_schema::Posture::Standard, 120)),
    };
    cfg.posture = cfg.posture_decl.in_force();
    let mut r = Rig::with(cfg);
    r.ticks(2);
    let text = |resp: Response| match resp {
        Response::Ok { message } => message,
        other => panic!("{other:?}"),
    };
    let boot = text(r.core.handle(ALICE, Request::ReportBoot));
    assert!(boot.contains("clean"), "{boot}");
    let p = text(r.core.handle(ALICE, Request::Posture));
    assert!(p.starts_with("posture: Standard, boot-ready timeout 120 s"), "{p}");
    assert!(p.contains("declares Relaxed, 600 s") && p.contains("next boot"), "{p}");
}

/// P22: the daemon finds the change committed for a unit that the override
/// file no longer carries (a hand edit took it out), for `repair:reapply`.
#[test]
fn a_committed_change_missing_from_the_overrides_is_lost() {
    let mut r = Rig::new();
    r.ticks(2);
    let args: BTreeMap<String, Value> =
        [("service".to_string(), Value::Str("gym-web".into())), ("addr".to_string(), Value::Str("127.0.0.1".into()))]
            .into();
    let resp = r.core.handle(ADMIN, Request::Apply { change: ChangeId("listen-address".into()), args: args.clone() });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    let l = r.core.ledger();
    assert!(r.core.lost_changes(&l).is_empty(), "carried");
    r.fake.w().overrides.assignments.remove("services.gym-web.listenAddress");
    let lost = r.core.lost_changes(&l);
    assert_eq!(lost.get(&UnitId::service("gym-web")), Some(&(ChangeId("listen-address".into()), args)));
}

/// C2 (§9 step 6, I8): the owner edits their configuration while a change
/// waits in Built for Foreground to end. When the window opens the change
/// is checked again on its way into Activating: it is Stale, never
/// activated, and a notice says to ask again.
#[test]
fn an_owner_edit_while_waiting_is_stale_when_the_window_opens() {
    let mut r = Rig::new();
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        created: Timestamp(0),
        active: true,
        idle: false,
    });
    r.fake.w().foreground.insert("s1".into());
    r.ticks(2);
    let mut args = BTreeMap::new();
    args.insert("scale".to_string(), Value::Str("1.25".into()));
    let resp = r.core.handle(ALICE.in_session("s1"), Request::Apply { change: ChangeId("font-scale".into()), args });
    assert!(matches!(resp, Response::Done { state: TxnState::Built, .. }), "{resp:?}");

    r.fake.w().owner_files.insert("configuration.nix".into(), "edited while it waited".into());
    r.fake.w().foreground.clear();
    r.ticks(4);
    let l = r.core.ledger();
    assert!(
        l.terminal.values().any(|t| t.state == TxnState::Rejected(RejectReason::Stale)
            && matches!(t.transition, Transition::ApplyChange { .. })),
        "{:?}",
        l.terminal
    );
    assert_eq!(r.calls("activate_live"), 0, "never activated");
    assert!(r.core.notices.iter().any(|n| n.contains("not activated")), "{:?}", r.core.notices);
}

/// P9: a tick over the 500 ms budget is warned, naming the probes that ran,
/// at most once a minute; a tick within it is not.
#[test]
fn a_slow_tick_is_warned() {
    let mut r = Rig::new();
    r.ticks(2);
    assert_eq!(r.core.slow_tick_warnings, 0);
    r.fake.w().probe_batch_ms = 800;
    r.ticks(1);
    assert_eq!(r.core.slow_tick_warnings, 1);
    // Every tick slow for half a minute: no second warning yet.
    r.ticks(5);
    assert_eq!(r.core.slow_tick_warnings, 1, "at most one a minute");
    r.ticks(10);
    assert_eq!(r.core.slow_tick_warnings, 2);
    r.fake.w().probe_batch_ms = 0;
    r.ticks(20);
    assert_eq!(r.core.slow_tick_warnings, 2);
}

/// P19: `SystemState.core_hash` is the recorded core hash, not zero, so
/// `digest()` covers it: a proposal observed under one record is stale
/// under another. The record is read again when the running generation
/// changes; only a missing record is zero, and an unreadable one keeps the
/// last value read and says so (rule 21).
#[test]
fn the_state_carries_the_recorded_core_hash() {
    let dir = std::env::temp_dir().join(format!("planarian-core-hash-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let record = dir.join("core.sha256");
    std::fs::write(&record, "00ab /run/current-system/sw/bin/planariad\n").unwrap();
    let recorded = Hash::of(&std::fs::read(&record).unwrap());
    assert_eq!(crate::config::core_hash(&record), Ok(recorded));
    assert_eq!(crate::config::core_hash(&dir.join("absent")), Ok(Hash::ZERO), "no record: zero");
    assert!(crate::config::core_hash(&dir).is_err(), "unreadable (a directory): an error, not zero");

    let mut r = Rig::new();
    r.ticks(2);
    let (before, _) = r.core.observe();
    assert_eq!(before.core_hash, Hash::ZERO);
    r.core.set_core_hash_record(record.clone());
    let (s, defs) = r.core.observe();
    assert_eq!(s.core_hash, recorded, "the state carries the record's hash");
    assert_ne!(s.digest(), before.digest(), "the digest covers it");

    // Observed before the core hash changed: refused as Stale (§12 step 1).
    let mut p =
        r.core.proposal(Transition::RestartUnit(UnitId::service("gym-web")), &s, &defs, Source::User, "restart".into());
    p.observed = before.digest();
    let got = r.core.ex.submit(p, authorization_of(Actor::Daemon), &s, &defs);
    assert!(matches!(got, Submitted::Rejected { reason: RejectReason::Stale, .. }), "{got:?}");

    // A switch outside Planarian installs another record: read again.
    std::fs::write(&record, "00cd /run/current-system/sw/bin/planariad\n").unwrap();
    let (same_gen, _) = r.core.observe();
    assert_eq!(same_gen.core_hash, recorded, "not re-read without a generation change");
    let running = r.fake.w().current;
    r.fake.w().current = GenerationId(running.0 + 1);
    let (switched, _) = r.core.observe();
    assert_eq!(switched.core_hash, Hash::of(&std::fs::read(&record).unwrap()), "re-read on the switch");

    // Unreadable: the last value read stays, with a notice.
    r.core.set_core_hash_record(dir.clone());
    assert_eq!(r.core.core_hash(), switched.core_hash);
    assert!(r.core.notices.iter().any(|n| n.contains("core hash record could not be read")), "{:?}", r.core.notices);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// C18 (§12 step 6): a transaction touching user data, with no snapshot
/// backend (Phase A), logs `NoSnapshot` and continues: on the approval path
/// (a UserData change is AskFirst in A) and on the submission path (a
/// Runtime restart of a UserData unit); one that does not touch user data
/// does not. The approved execution's record names the approver, the
/// token's `bound_to` and the decision (I7).
#[test]
fn user_data_without_a_snapshot_backend_logs_no_snapshot() {
    let mut cfg = config();
    cfg.exec
        .tables
        .option_sensitivity
        .push(("planarian.reference.fontScale".into(), Sensitivities::of(&[Sensitivity::UserData])));
    // gym-web holds user data, in every generation the fake knows.
    let store = MemStore::new(8 << 20);
    let fake = gym_world(store.clone());
    let web = UnitId::service("gym-web");
    {
        let mut w = fake.w();
        let user_data = Sensitivities::of(&[Sensitivity::UserData]);
        for g in w.gens.values_mut() {
            if let Some(d) = g.eval.units.get_mut(&web) {
                d.sensitivity = user_data;
            }
        }
        // And in generations built from here on.
        if let Some(d) = w.base_units.get_mut(&web) {
            d.sensitivity = user_data;
        }
    }
    fake.w().alive.insert(100);
    let mut j = Journal::open(store).unwrap();
    j.append(fake.w().now, Record::KnownGood(GenerationId(1))).unwrap();
    let core = Core::start(j, fake.clone(), OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO }, cfg);
    let mut r = Rig { fake, core };
    r.ticks(2);
    let font = |scale: &str| Request::Apply {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str(scale.into()))].into(),
    };
    let flagged = |r: &Rig| r.core.log.iter().filter(|x| x.no_snapshot).cloned().collect::<Vec<LogRecord>>();

    // Approval path: alice asks; user data makes it AskFirst.
    let Response::NeedsApproval { approve, .. } = r.core.handle(ALICE, font("1.25")) else {
        panic!("a UserData change asks in Phase A")
    };
    r.ticks(1);
    assert!(flagged(&r).is_empty(), "not past step 5 while it waits for approval");
    let resp = r.core.handle(ADMIN.at_terminal(), Request::Approve { hash: approve });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "continued: {resp:?}");
    r.ticks(2);
    let f = flagged(&r);
    assert_eq!(f.len(), 1, "{:#?}", r.core.log);
    assert!(matches!(f[0].result, Submitted::Finished { state: TxnState::Committed, .. }));
    assert_eq!(f[0].caller, Actor::user(1000), "the proposer");
    assert_eq!(f[0].approver, Some(Actor::user(0)), "I7: the approver");
    assert_eq!(f[0].bound_to, Some(approve), "I7: the token's bound_to");
    assert!(
        matches!(f[0].decision, Some(Decision::Allow { tier: Tier::AskFirst, .. })),
        "the decision: {:?}",
        f[0].decision
    );

    // Submission path: a Runtime restart of a unit holding user data.
    let (s, defs) = r.core.observe();
    let p = r.core.proposal(Transition::RestartUnit(web.clone()), &s, &defs, Source::User, "restart".into());
    let got = r.core.submit(p, user_authorization(Actor::user(0), true), &s, &defs);
    assert!(matches!(got, Submitted::Finished { .. }), "Runtime, runs at once: {got:?}");
    r.ticks(2);
    let f = flagged(&r);
    assert_eq!(f.len(), 2, "{:#?}", r.core.log);
    assert!(matches!(f[1].proposal.transition, Transition::RestartUnit(_)));
    assert_eq!(f[1].approver, None, "no approval on this path");

    // Not user data: nothing to snapshot, nothing logged.
    let (s, defs) = r.core.observe();
    let p =
        r.core.proposal(Transition::RestartUnit(UnitId::service("sshd")), &s, &defs, Source::User, "restart".into());
    let got = r.core.submit(p, user_authorization(Actor::user(0), true), &s, &defs);
    assert!(matches!(got, Submitted::Finished { .. } | Submitted::Parked { .. }), "{got:?}");
    r.ticks(2);
    assert!(
        r.core
            .log
            .iter()
            .filter(|x| !x.facts.as_ref().is_some_and(|f| f.sensitivity.contains(Sensitivity::UserData)))
            .all(|x| !x.no_snapshot),
        "{:#?}",
        r.core.log
    );
    assert_eq!(flagged(&r).len(), 2);
}

/// #24 review: the agent kept for a parked change's approval record
/// (I7) is dropped once the change is no longer parked, whether it is
/// approved or withdrawn, so the map does not grow for the daemon's life.
#[test]
fn a_withdrawn_parked_change_forgets_its_agent() {
    let mut cfg = config();
    cfg.exec
        .tables
        .option_sensitivity
        .push(("planarian.reference.fontScale".into(), Sensitivities::of(&[Sensitivity::UserData])));
    let mut r = Rig::with(cfg);
    r.ticks(2);
    let font = |scale: &str| Request::Apply {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str(scale.into()))].into(),
    };
    let resp = r.core.handle(ALICE, font("1.25"));
    let Response::NeedsApproval { txn, .. } = resp else { panic!("{resp:?}") };
    assert!(r.core.parked_agents.contains_key(&txn), "kept while parked");
    let resp = r.core.handle(ALICE, Request::Cancel { txn });
    assert!(matches!(resp, Response::Done { .. }), "{resp:?}");
    r.ticks(1);
    assert!(r.core.parked_agents.is_empty(), "{:?}", r.core.parked_agents);
}

/// #24 review: an approved change that cannot run on the same tick (here it
/// waits in Built while Foreground holds) still has its proposer's agent in
/// its approval record: the record is written in the approval's own call,
/// before any tick prunes.
#[test]
fn an_approved_change_that_waits_keeps_its_agent() {
    let mut cfg = config();
    cfg.exec
        .tables
        .option_sensitivity
        .push(("planarian.reference.fontScale".into(), Sensitivities::of(&[Sensitivity::UserData])));
    let mut r = Rig::with(cfg);
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        created: Timestamp(0),
        active: true,
        idle: false,
    });
    r.ticks(2);
    let font = Request::Apply {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.25".into()))].into(),
    };
    let resp = r.core.handle(ALICE, font);
    let Response::NeedsApproval { txn, approve, .. } = resp else { panic!("{resp:?}") };
    // As if an agent of alice's had asked (the agent path sets this entry).
    r.core.parked_agents.insert(txn, Some("helper".into()));
    r.fake.w().foreground.insert("s1".into());
    r.ticks(2);
    let resp = r.core.handle(ADMIN.at_terminal(), Request::Approve { hash: approve });
    assert!(matches!(resp, Response::Done { state: TxnState::Built, .. }), "waits for its window: {resp:?}");
    r.ticks(3);
    let rec = r
        .core
        .log
        .iter()
        .find(|x| x.approver.is_some() && matches!(x.result, Submitted::Finished { txn: t, .. } if t == txn))
        .expect("the approved execution's record");
    assert_eq!(rec.agent.as_deref(), Some("helper"));
    assert!(r.core.parked_agents.is_empty());
}

/// #24 review (I7): an approval that re-binds, whose fresh decision no
/// longer asks, runs as an ordinary submission under a new id. Its record
/// names no approver and no `bound_to`, carries the fresh decision, and
/// keeps the proposer's agent.
#[test]
fn a_rebound_approval_that_no_longer_asks_is_logged_as_a_submission() {
    let mut cfg = config();
    cfg.exec
        .tables
        .option_sensitivity
        .push(("planarian.reference.fontScale".into(), Sensitivities::of(&[Sensitivity::UserData])));
    let mut r = Rig::with(cfg);
    r.ticks(2);
    let font = Request::Apply {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.25".into()))].into(),
    };
    let resp = r.core.handle(ALICE, font);
    let Response::NeedsApproval { txn: first, approve, .. } = resp else { panic!("{resp:?}") };
    r.core.parked_agents.insert(first, Some("helper".into()));
    // What the change touches is no longer user data: re-derived at
    // approval, the facts differ, and the fresh decision does not ask.
    r.core.ex.cfg.tables.option_sensitivity.retain(|(o, _)| o != "planarian.reference.fontScale");
    let resp = r.core.handle(ADMIN.at_terminal(), Request::Approve { hash: approve });
    let Response::Done { txn: ran, .. } = resp else { panic!("ran without asking: {resp:?}") };
    assert_ne!(ran, first, "under a new id");
    r.ticks(2);
    let rec = r
        .core
        .log
        .iter()
        .find(|x| matches!(x.result, Submitted::Finished { txn, .. } if txn == ran))
        .expect("the resubmission's record");
    assert_eq!(rec.approver, None, "nobody approved what ran");
    assert_eq!(rec.bound_to, None);
    assert!(
        matches!(rec.decision, Some(Decision::Allow { tier, .. }) if tier != Tier::AskFirst),
        "the fresh decision: {:?}",
        rec.decision
    );
    assert_eq!(rec.agent.as_deref(), Some("helper"), "the proposer's agent");
    assert!(!r.core.log.iter().any(|x| x.approver.is_some()), "no approval record: {:#?}", r.core.log);
    assert!(r.core.parked_agents.is_empty());
}

// ---------- §12d network security fails closed (#35 part 1) ----------

/// sshd as a network-security unit (interim: the module's `holds`), with the
/// fake's OnFailure= stand-in holding it when it fails.
fn rig_with_held_sshd(holds: bool) -> Rig {
    let store = MemStore::new(8 << 20);
    let fake = gym_world(store.clone());
    let sshd = UnitId::service("sshd");
    {
        let mut w = fake.w();
        for g in w.gens.values_mut() {
            if let Some(d) = g.eval.units.get_mut(&sshd) {
                d.holds = holds;
            }
        }
        if let Some(d) = w.base_units.get_mut(&sshd) {
            d.holds = holds;
        }
        if holds {
            w.hold_on_failure.insert(sshd);
        }
        w.alive.insert(100);
    }
    let mut j = Journal::open(store).unwrap();
    j.append(fake.w().now, Record::KnownGood(GenerationId(1))).unwrap();
    let core = Core::start(j, fake.clone(), OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO }, config());
    let mut r = Rig { fake, core };
    r.ticks(2);
    r
}

fn alarms(r: &Rig) -> usize {
    r.core
        .notices
        .iter()
        .filter(|n| n.contains("stopped unexpectedly. Network traffic is blocked until it is back."))
        .count()
}

/// §12d: a crash holds traffic (OnFailure=), the daemon journals it, alarms
/// once and restarts the unit at once (`restarts_held_unit`, §11), and lifts
/// the hold once it is Running and its Readiness probes pass. Without the
/// hold, the same crash of a Security unit asks.
#[test]
fn a_held_unit_crash_holds_restarts_at_once_and_lifts() {
    let sshd = UnitId::service("sshd");
    let mut r = rig_with_held_sshd(true);
    r.fake.w().signal(&sshd, 11);
    assert!(r.fake.w().held.contains(&sshd), "OnFailure= held it");
    r.ticks(1);
    assert!(r.core.ledger().holds().contains(&sshd), "journaled");
    assert!(r.core.observe().0.holds.contains(&sshd), "in the observed state, for derive");
    assert_eq!(alarms(&r), 1, "{:?}", r.core.notices);
    r.ticks(10);
    assert!(r.core.ex.parked.is_empty(), "restarted without asking: {:?}", r.core.notices);
    assert_eq!(r.status("service:sshd"), UnitStatus::Running);
    assert!(!r.fake.w().held.contains(&sshd), "lifted once back");
    assert!(!r.core.ledger().holds().contains(&sshd));
    assert_eq!(alarms(&r), 1, "one alarm: {:?}", r.core.notices);

    // Not a network-security unit: the same crash of a Security unit asks.
    let mut r = rig_with_held_sshd(false);
    r.fake.w().signal(&sshd, 11);
    r.ticks(10);
    assert!(
        r.core.ex.parked.values().any(|p| p.proposal.transition == Transition::RestartUnit(sshd.clone())),
        "asks: {:?}",
        r.core.notices
    );
    assert!(r.core.ledger().holds().is_empty() && alarms(&r) == 0);
}

/// §12d: a stop outside Planarian that is not attributed is the daemon's to
/// hold (systemd's OnFailure= does not fire on a clean stop); `planarian
/// stop`, an attested override, holds nothing.
#[test]
fn an_unattributed_stop_is_held_by_the_daemon_and_an_attested_one_is_not() {
    let sshd = UnitId::service("sshd");
    let mut r = rig_with_held_sshd(true);
    r.fake.w().stop_out_of_band(&sshd);
    assert!(!r.fake.w().held.contains(&sshd), "OnFailure= does not fire");
    r.ticks(1);
    assert!(r.fake.w().calls.iter().any(|c| c.call == "hold(service:sshd)"), "the daemon held it");
    assert!(r.core.ledger().holds().contains(&sshd));
    r.ticks(10);
    assert_eq!(r.status("service:sshd"), UnitStatus::Running);
    assert!(!r.fake.w().held.contains(&sshd) && r.core.ledger().holds().is_empty(), "lifted");

    let mut r = rig_with_held_sshd(true);
    let resp = r.core.handle(ADMIN, Request::Stop { unit: sshd.clone() });
    assert!(matches!(resp, Response::Done { .. }), "{resp:?}");
    r.ticks(5);
    assert!(r.fake.w().held.is_empty() && r.core.ledger().holds().is_empty(), "an attested stop holds nothing");
    assert_eq!(alarms(&r), 0);
}

/// §12d: repair fails every attempt: the hold stays, administrators are
/// notified once, and a restart of planariad keeps it (the journal's holds
/// are the source of truth; a disagreement with the host fails closed).
#[test]
fn a_failed_repair_keeps_the_hold_and_notifies_across_a_restart() {
    let sshd = UnitId::service("sshd");
    let mut r = rig_with_held_sshd(true);
    r.fake.w().units.get_mut(&sshd).unwrap().fail_on_start = true;
    r.fake.w().signal(&sshd, 11);
    r.ticks(200);
    assert!(r.fake.w().held.contains(&sshd), "the hold stays");
    let told: Vec<&String> =
        r.core.notices.iter().filter(|n| n.contains("service:sshd") && n.contains("needs a person")).collect();
    assert!(!told.is_empty(), "{:?}", r.core.notices);
    assert!(r.core.notices.iter().any(|n| n.contains("administrator") && n.contains("hold release")));

    // The host loses its hold state (as if /run were cleared); the daemon
    // restarts; the journal's hold puts it back.
    r.fake.w().held.clear();
    let store = r.fake.store.clone();
    r.fake.w().alive.insert(101);
    r.core = Core::start(
        Journal::open(store).unwrap(),
        r.fake.clone(),
        OwnerId::Daemon { pid: 101, boot_id: Hash::ZERO },
        config(),
    );
    r.ticks(2);
    assert!(r.fake.w().held.contains(&sshd), "held again: fail closed");
    assert_eq!(alarms(&r), 0, "no new alarm for the same hold");
}

/// §12d: `planarian hold release` is an attested override on the hold
/// unit. A non-administrator's release asks for an administrator and holds;
/// an administrator's lifts it and marks the release (until the next boot
/// by default).
#[test]
fn hold_release_needs_an_administrator() {
    let sshd = UnitId::service("sshd");
    let mut r = rig_with_held_sshd(true);
    r.fake.w().units.get_mut(&sshd).unwrap().fail_on_start = true;
    r.fake.w().signal(&sshd, 11);
    r.ticks(2);
    assert!(r.fake.w().held.contains(&sshd));

    let release = || Request::HoldRelease { unit: UnitId::service("sshd"), until: Until::NextBoot };
    let resp = r.core.handle(ALICE, release());
    let Response::NeedsApproval { why, .. } = &resp else { panic!("asks: {resp:?}") };
    let text = format!("{resp:?} {why}").to_lowercase();
    assert!(text.contains("administrator"), "{text}");
    r.ticks(2);
    assert!(r.fake.w().held.contains(&sshd), "still held while it asks");

    let resp = r.core.handle(ADMIN, release());
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert!(!r.fake.w().held.contains(&sshd), "lifted");
    assert_eq!(r.fake.w().hold_released.get(&sshd), Some(&None), "released until the next boot");
    r.ticks(5);
    assert!(!r.fake.w().held.contains(&sshd), "not held again while released, though still failed");

    let resp = r.core.handle(ADMIN, Request::HoldRelease { unit: UnitId::service("gym-web"), until: Until::NextBoot });
    assert!(matches!(resp, Response::Error { .. }), "no hold to release: {resp:?}");
}

/// §12d (#36 review): anything else flushing the ruleset removes the hold's
/// table and would fail open. While a hold is active the daemon checks the
/// table each tick and, if it is gone, journals, alarms and re-applies it.
#[test]
fn a_flushed_hold_table_is_put_back() {
    let sshd = UnitId::service("sshd");
    let mut r = rig_with_held_sshd(true);
    r.fake.w().units.get_mut(&sshd).unwrap().fail_on_start = true;
    r.fake.w().signal(&sshd, 11);
    r.ticks(2);
    let applied = |r: &mut Rig| {
        r.core
            .ex
            .kernel
            .journal
            .segment()
            .unwrap()
            .into_iter()
            .filter(|e| matches!(&e.record, Record::HoldApplied { unit, .. } if *unit == UnitId::service("sshd")))
            .count()
    };
    let before = applied(&mut r);
    assert!(before >= 1);
    r.fake.w().hold_table_flushed = true;
    r.ticks(1);
    assert!(r.fake.w().calls.iter().any(|c| c.call == "reapply_hold(service:sshd)"), "re-applied");
    assert!(!r.fake.w().hold_table_flushed);
    assert_eq!(applied(&mut r), before + 1, "journaled");
    assert!(r.core.notices.iter().any(|n| n.contains("removed from the firewall")), "{:?}", r.core.notices);
    r.ticks(2);
    assert_eq!(applied(&mut r), before + 1, "once, while the table stays");
}

/// §12d: a hold table that cannot be checked (planariad has no `nft`, say)
/// alarms once and is checked again each tick; nothing is re-applied blind.
#[test]
fn an_uncheckable_hold_table_alarms_once_and_is_checked_again() {
    let sshd = UnitId::service("sshd");
    let mut r = rig_with_held_sshd(true);
    r.fake.w().units.get_mut(&sshd).unwrap().fail_on_start = true;
    r.fake.w().signal(&sshd, 11);
    r.ticks(2);
    r.fake.w().hold_table_unreadable = true;
    r.ticks(5);
    let reapplied = |r: &Rig| r.fake.w().calls.iter().filter(|c| c.call == "reapply_hold(service:sshd)").count();
    assert_eq!(reapplied(&r), 0, "not re-applied blind");
    let alarms = r.core.notices.iter().filter(|n| n.contains("could not be checked")).count();
    assert_eq!(alarms, 1, "{:?}", r.core.notices);
    // Checkable again and missing: re-applied, with its own alarm and
    // `HoldApplied` (review of #40 at d147ec6).
    let applied = |r: &mut Rig| {
        let seg = r.core.ex.kernel.journal.segment().unwrap();
        seg.iter().filter(|e| matches!(&e.record, Record::HoldApplied { unit, .. } if *unit == sshd)).count()
    };
    let before = applied(&mut r);
    r.fake.w().hold_table_unreadable = false;
    r.fake.w().hold_table_flushed = true;
    r.ticks(1);
    assert_eq!(reapplied(&r), 1);
    assert!(!r.fake.w().hold_table_flushed);
    assert_eq!(applied(&mut r), before + 1, "journaled");
    assert!(r.core.notices.iter().any(|n| n.contains("removed from the firewall")), "{:?}", r.core.notices);
}

/// §12d: a re-apply that fails is retried with backoff while the hold stands
/// and the table is missing; the alarm and `HoldApplied` come once.
#[test]
fn a_failed_reapply_is_retried_with_backoff() {
    let sshd = UnitId::service("sshd");
    let mut r = rig_with_held_sshd(true);
    r.fake.w().units.get_mut(&sshd).unwrap().fail_on_start = true;
    r.fake.w().signal(&sshd, 11);
    r.ticks(2);
    r.fake.w().hold_reapply_fails = true;
    r.fake.w().hold_table_flushed = true;
    r.ticks(1);
    let reapplied = |r: &Rig| r.fake.w().calls.iter().filter(|c| c.call == "reapply_hold(service:sshd)").count();
    assert_eq!(reapplied(&r), 1);
    // Retried, but not every tick: the waits double from 10 s.
    for _ in 0..(120_000 / planarian_state::TICK.0) {
        r.ticks(1);
    }
    let tries = reapplied(&r);
    assert!(tries > 1, "retried: {tries}");
    assert!(tries < 2 + (120_000 / planarian_state::TICK.0) as usize / 2, "with backoff: {tries}");
    let alarms = r.core.notices.iter().filter(|n| n.contains("removed from the firewall")).count();
    assert_eq!(alarms, 1, "one alarm: {:?}", r.core.notices);
    // It loads: held again, and no more retries.
    r.fake.w().hold_reapply_fails = false;
    for _ in 0..(300_000 / planarian_state::TICK.0) {
        r.ticks(1);
    }
    assert!(!r.fake.w().hold_table_flushed, "held again");
    let after = reapplied(&r);
    r.ticks(20);
    assert_eq!(reapplied(&r), after, "no retry once the table is back");
}

/// §16 *Approvals show the change*: a pending generation change carries the
/// diff the core computed (option, old, new, sensitivity), and its response
/// says what it changes. The diff is base override → candidate override,
/// both fixed by hash at Prepared, so it can differ at approval only if the
/// override file changed: then the approval does not apply (Stale, §12
/// step 4) and nothing runs. Any other change in the re-derived facts
/// re-binds and asks again (`a_rebound_approval_that_no_longer_asks_…`
/// covers a re-bind; the binding hashes the facts, `config_diff` included).
#[test]
fn an_approval_shows_its_diff_and_a_changed_diff_does_not_apply() {
    let mut cfg = config();
    cfg.exec
        .tables
        .option_sensitivity
        .push(("planarian.reference.fontScale".into(), Sensitivities::of(&[Sensitivity::UserData])));
    let mut r = Rig::with(cfg);
    r.ticks(2);
    let font = Request::Apply {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.25".into()))].into(),
    };
    let resp = r.core.handle(ALICE, font);
    let Response::NeedsApproval { approve, why, .. } = resp else { panic!("{resp:?}") };
    assert!(why.contains("changes 1 option"), "the response says what it changes: {why}");
    let Response::Status(st) = r.core.handle(ALICE, Request::Status) else { panic!() };
    let p = st.pending.iter().find(|p| p.approve == approve).expect("pending");
    assert_eq!(p.diff.options.len(), 1);
    let o = &p.diff.options[0];
    assert_eq!(o.path, "planarian.reference.fontScale");
    assert_eq!(o.new, Some(Value::Str("1.25".into())));
    assert!(o.sensitivity.contains(Sensitivity::UserData));
    assert!(p.diff.lines()[0].starts_with("planarian.reference.fontScale"), "{:?}", p.diff.lines());

    // The live override file now holds another value for that option: the
    // diff re-derived at approval would differ from the one shown.
    r.fake.w().overrides.assignments.insert("planarian.reference.fontScale".into(), Value::Str("1.1".into()));
    let before = r.fake.w().current;
    let resp = r.core.handle(ADMIN.at_terminal(), Request::Approve { hash: approve });
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Stale"), "does not apply: {resp:?}");
    assert_eq!(r.fake.w().current, before, "nothing ran");
    let Response::Status(st) = r.core.handle(ALICE, Request::Status) else { panic!() };
    assert!(st.pending.iter().all(|p| p.approve != approve), "the old approval is gone");
}

/// #35, §16 *Approvals show the change* and §11's Rollback row (owner
/// decisions, Nov 2), written from the spec before the change (reviewer's
/// case). The known-good generation lacks sshd (`services.openssh.enable =
/// false`); the running one has it. A Rollback to known-good would remove a
/// Security-sensitive unit, so it asks; and what is asked shows the change:
/// "each option added, removed or changed, with its old and new value and its
/// sensitivity … and the units it would remove or stop", in the text the
/// caller and the notice get, and as structured data on the pending approval
/// (`PendingApproval.diff`, what `planarian approve --json` prints).
#[test]
fn a_rollback_that_removes_a_security_unit_asks_and_shows_the_change() {
    let store = MemStore::new(8 << 20);
    let fake = gym_world(store.clone());
    fake.w().alive.insert(100);
    let without_ssh = OverrideSet { assignments: [("services.openssh.enable".to_string(), Value::Bool(false))].into() };
    let known_good = {
        let mut w = fake.w();
        let g = w.add_generation(&without_ssh);
        w.boot_entries.insert(g);
        w.override_store.insert(planarian_fake::World::override_hash_of(&without_ssh), without_ssh.clone());
        g
    };
    assert_ne!(known_good, fake.w().current);
    let mut j = Journal::open(store).unwrap();
    j.append(fake.w().now, Record::KnownGood(known_good)).unwrap();
    let mut r =
        Rig { core: Core::start(j, fake.clone(), OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO }, config()), fake };
    r.ticks(2);
    assert_eq!(r.status("service:sshd"), UnitStatus::Running, "sshd runs now");

    let resp = r.core.user_submit(Transition::Rollback, ADMIN, Source::User, "roll back".into());
    let Response::NeedsApproval { approve, what, why, .. } = resp else {
        panic!("a rollback that removes sshd (Security) asks: {resp:?}");
    };
    assert_eq!(r.status("service:sshd"), UnitStatus::Running, "nothing ran before approval");

    // The text the caller gets, and the notice.
    let text = format!("{what}\n{why}");
    for (needle, what_for) in [
        ("sshd", "the unit it would remove"),
        ("services.openssh.enable", "the option it would change"),
        ("Security", "the option's sensitivity"),
    ] {
        assert!(text.contains(needle), "the approval text names {what_for} ({needle}): {text}");
    }
    assert!(text.contains("true") && text.contains("false"), "old and new value: {text}");
    let notice = r.core.notices.iter().rev().find(|n| n.contains("services.openssh.enable"));
    assert!(notice.is_some_and(|n| n.contains("sshd")), "the notice shows the change: {:?}", r.core.notices);

    // The structured diff on the pending approval.
    let Response::Status(st) = r.core.handle(ADMIN, Request::Status) else { panic!("status") };
    let pending = st.pending.iter().find(|p| p.approve == approve).expect("the pending approval");
    assert!(pending.facts.removes_sensitivity.security, "derived: it removes a Security unit");
    let json = serde_json::to_value(pending).unwrap();
    let diff =
        json.get("diff").filter(|d| !d.is_null()).unwrap_or_else(|| panic!("a `diff` on the pending approval: {json}"));
    let diff_text = diff.to_string();
    for needle in ["services.openssh.enable", "sshd", "Security"] {
        assert!(diff_text.contains(needle), "the structured diff carries {needle}: {diff_text}");
    }
}

fn seated_session(r: &mut Rig, idle: bool) {
    r.fake.w().sessions.push(planarian_schema::SessionInfo {
        id: "s1".into(),
        uid: 1000,
        class: "user".into(),
        seat: Some("seat0".into()),
        remote: false,
        created: Timestamp(0),
        active: true,
        idle,
    });
}

fn font(scale: &str) -> Request {
    Request::Apply {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str(scale.into()))].into(),
    }
}

/// §12f *Rollbacks* (owner decisions, Oct 31 and Nov 2): a `Rollback` is
/// never parked in `Built` for a window. The user's runs at once, also under
/// `Foreground`; the diagnoser's is a repair and runs at once too (the
/// repair loop decides whether to submit it under quiet mode).
#[test]
fn a_rollback_never_waits_for_a_window() {
    let mut r = Rig::new();
    seated_session(&mut r, false);
    r.ticks(2);
    let resp = r.core.handle(ALICE.in_session("s1"), font("1.25"));
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert_eq!(r.fake.w().current, GenerationId(2));

    r.fake.w().foreground.insert("s1".into());
    r.ticks(2);
    // The user's rollback runs now, Foreground or not.
    let (s, defs) = r.core.observe();
    let p = r.core.proposal(Transition::Rollback, &s, &defs, Source::User, "planarian undo".into());
    let got = r.core.submit(p, user_authorization(Actor::user(0), true), &s, &defs);
    assert!(matches!(got, Submitted::Finished { state: TxnState::Committed, .. }), "{got:?}");
    assert_eq!(r.fake.w().current, GenerationId(1));

    // Forward again, then the diagnoser's rollback under Foreground: a
    // repair, not parked.
    r.fake.w().foreground.clear();
    r.ticks(2);
    let resp = r.core.handle(ALICE.in_session("s1"), font("1.25"));
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    r.fake.w().foreground.insert("s1".into());
    r.ticks(2);
    let (s, defs) = r.core.observe();
    let p = r.core.proposal(
        Transition::Rollback,
        &s,
        &defs,
        Source::Diagnoser { incident: IncidentId(99) },
        "repair".into(),
    );
    let got = r.core.submit(p, authorization_of(Actor::Daemon), &s, &defs);
    assert!(matches!(got, Submitted::Finished { state: TxnState::Committed, .. }), "{got:?}");
    let l = r.core.ledger();
    let rollbacks: Vec<_> = l.terminal.values().filter(|t| t.transition == Transition::Rollback).collect();
    assert_eq!(rollbacks.len(), 2);
    assert!(rollbacks.iter().all(|t| t.state == TxnState::Committed), "{rollbacks:?}");
}

/// Commit alice's font scale (generation 2), then make a further update that
/// restarts the display manager wait in `Built` while her session is in use
/// (asked by maintenance, so not its own window). Returns its txn.
fn an_update_waiting_in_built(r: &mut Rig) -> TxnId {
    seated_session(r, false);
    r.ticks(2);
    let resp = r.core.handle(ALICE.in_session("s1"), font("1.25"));
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert_eq!(r.fake.w().current, GenerationId(2));
    r.fake.w().activation_restarts.insert(UnitId::service("display-manager"));
    let (s, defs) = r.core.observe();
    let t = Transition::ApplyChange {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.5".into()))].into(),
    };
    let p = r.core.proposal(t, &s, &defs, Source::Maintenance, "update".into());
    let alice = r.core.authz(&ALICE.in_session("s1"));
    let got = r.core.submit(p, alice, &s, &defs);
    let Submitted::Finished { txn, state: TxnState::Built, .. } = got else { panic!("{got:?}") };
    txn
}

/// Tick until the diagnoser's Rollback is parked for approval; its hash.
fn until_rollback_asks(r: &mut Rig) -> Hash {
    for _ in 0..200 {
        r.ticks(1);
        if let Some(p) = r.core.ex.parked.values().find(|p| p.proposal.transition == Transition::Rollback) {
            return p.bound_to;
        }
    }
    panic!("the repair rollback was not proposed: {:?}", r.core.notices)
}

/// §12f, I6 (owner decisions, Nov 2): a rollback that must ask withdraws
/// nothing while it waits for approval; once approved, at the moment it is
/// about to run, it withdraws the update waiting in `Built`
/// (`Rejected(Interrupted)`), which is prepared again, with its caller and
/// its original parking start (I12), once the rollback is terminal.
#[test]
fn a_parked_rollback_withdraws_nothing_until_approved() {
    let mut r = Rig::new();
    let waiting = an_update_waiting_in_built(&mut r);
    let since = r.core.ex.waiting_since(waiting).expect("waiting");
    // The committed update's flaw shows; restarts cannot fix it, so the
    // diagnoser reaches its rollback, which restarts the display manager too
    // and so asks.
    r.fake.w().break_in(GenerationId(2), &UnitId::service("gym-printer"));
    let approve = until_rollback_asks(&mut r);
    r.ticks(3);
    let l = r.core.ledger();
    assert_eq!(l.live.get(&waiting).map(|t| t.txn.state.clone()), Some(TxnState::Built), "untouched while it asks");
    assert!(!r.core.notices.iter().any(|n| n.contains("set aside for a rollback")), "{:?}", r.core.notices);

    r.fake.advance(Millis::secs(600));
    let resp = r.core.handle(ADMIN.at_terminal(), Request::Approve { hash: approve });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert_eq!(r.fake.w().current, GenerationId(1));
    let l = r.core.ledger();
    assert_eq!(
        l.terminal.get(&waiting).map(|t| t.state.clone()),
        Some(TxnState::Rejected(RejectReason::Interrupted)),
        "withdrawn when the rollback ran"
    );
    assert!(r.core.notices.iter().any(|n| n.contains("set aside for a rollback")), "{:?}", r.core.notices);
    r.ticks(2);
    let l = r.core.ledger();
    let again = l
        .live
        .values()
        .find(|t| matches!(t.txn.transition, Transition::ApplyChange { .. }))
        .expect("prepared again once the rollback is terminal");
    assert_eq!(again.txn.state, TxnState::Built, "and waits for its window again");
    assert_eq!(r.core.ex.waiting_since(again.txn.id), Some(since), "its parking limit is not extended");
    assert!(r.core.notices.iter().any(|n| n.contains("prepared again after the rollback")));
}

/// §12f (owner decision, Nov 2): `planarian undo` with an update waiting in
/// `Built` withdraws it and runs, rather than being refused under I6.
#[test]
fn undo_withdraws_a_waiting_update_and_runs() {
    let mut r = Rig::new();
    let waiting = an_update_waiting_in_built(&mut r);
    // Going back restarts nothing in the session: no floor asks.
    r.fake.w().activation_restarts.clear();
    let resp = r.core.handle(ADMIN, Request::Undo);
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert_eq!(r.fake.w().current, GenerationId(1));
    let l = r.core.ledger();
    assert_eq!(l.terminal.get(&waiting).map(|t| t.state.clone()), Some(TxnState::Rejected(RejectReason::Interrupted)));
    r.ticks(2);
    // Prepared again once the undo is terminal; nothing in the session is
    // disturbed now, so it runs.
    assert!(r.core.notices.iter().any(|n| n.contains("prepared again after the rollback")), "{:?}", r.core.notices);
    let l = r.core.ledger();
    assert!(
        l.terminal.iter().any(|(id, t)| *id > waiting
            && matches!(t.transition, Transition::ApplyChange { .. })
            && t.state == TxnState::Committed),
        "{:?}",
        l.terminal
    );
}

/// §12f, I6 (coordinator, Nov 2): an update parked for approval in
/// `Prepared` is not active for I6, so a repair rollback leaves it alone:
/// nobody is asked to approve it twice.
#[test]
fn a_repair_rollback_leaves_a_parked_update_alone() {
    let mut r = Rig::new();
    seated_session(&mut r, false);
    r.ticks(2);
    let resp = r.core.handle(ALICE.in_session("s1"), font("1.25"));
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    let broken = GenerationId(2);
    // An update that would end alice's session, asked for outside it: the
    // §11 floor parks it for approval.
    r.fake.w().activation_restarts.insert(UnitId::service("display-manager"));
    let (s, defs) = r.core.observe();
    let t = Transition::ApplyChange {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.5".into()))].into(),
    };
    let p = r.core.proposal(t, &s, &defs, Source::Maintenance, "update".into());
    let got = r.core.submit(p, user_authorization(Actor::user(1000), false), &s, &defs);
    let Submitted::Parked { txn: parked, .. } = got else { panic!("{got:?}") };

    let printer = UnitId::service("gym-printer");
    r.fake.w().break_in(broken, &printer);
    let mut proposed = false;
    for _ in 0..200 {
        r.ticks(1);
        let l = r.core.ledger();
        if l.live.values().any(|t| t.txn.transition == Transition::Rollback)
            || l.terminal.values().any(|t| t.transition == Transition::Rollback)
        {
            proposed = true;
            break;
        }
    }
    assert!(proposed, "the repair rollback was proposed");
    let l = r.core.ledger();
    assert_eq!(l.live.get(&parked).map(|t| t.txn.state.clone()), Some(TxnState::Prepared), "left alone");
    assert!(r.core.ex.parked.contains_key(&parked), "still waiting for its approval");
    assert!(!r.core.notices.iter().any(|n| n.contains("set aside for a rollback")), "{:?}", r.core.notices);
}

/// #26 review (1): a rollback withdraws only when it is about to run: one
/// refused before it gets a transaction (here its dry activation fails,
/// R10) withdraws nothing.
#[test]
fn a_refused_repair_rollback_withdraws_nothing() {
    let mut r = Rig::new();
    let waiting = an_update_waiting_in_built(&mut r);
    r.fake.w().break_in(GenerationId(2), &UnitId::service("gym-printer"));
    // The rollback's dry activation will fail (the restart does not use one).
    r.fake.w().dry_activate_fails = Some("dry-activate: exit 1".into());
    let refused = |r: &Rig| {
        r.core
            .log
            .iter()
            .any(|x| x.proposal.transition == Transition::Rollback && matches!(x.result, Submitted::Rejected { .. }))
    };
    for _ in 0..200 {
        r.ticks(1);
        if refused(&r) {
            break;
        }
    }
    assert!(refused(&r), "the repair rollback was refused: {:#?}", r.core.log);
    let l = r.core.ledger();
    assert_eq!(l.live.get(&waiting).map(|t| t.txn.state.clone()), Some(TxnState::Built), "still waiting");
    assert!(!r.core.notices.iter().any(|n| n.contains("set aside")), "{:?}", r.core.notices);
}

/// #26 review (4): a diagnoser's repair prepared again (after a restart or
/// a withdrawal; both use `prepare_again`) that waits again is linked back
/// to its incident.
#[test]
fn a_repair_prepared_again_keeps_its_incident() {
    let mut r = Rig::new();
    seated_session(&mut r, false);
    r.ticks(2);
    r.fake.w().activation_restarts.insert(UnitId::service("display-manager"));
    let t = Transition::ApplyChange {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.25".into()))].into(),
    };
    let incident = IncidentId(7);
    let (s, defs) = r.core.observe();
    let earlier = r.core.proposal(t.clone(), &s, &defs, Source::Diagnoser { incident }, "repair".into());
    r.core.earlier.insert(TxnId(40), (earlier, Actor::Daemon));
    r.core.prepare_again(vec![(TxnId(40), t, None)], "after a restart", &s, &defs);
    let l = r.core.ledger();
    let again = l
        .live
        .values()
        .find(|t| matches!(t.txn.transition, Transition::ApplyChange { .. }))
        .expect("prepared again, and waiting");
    assert_eq!(r.core.incident_parked.get(&incident), Some(&again.txn.id), "linked to its incident");
}

/// §12f *Rollbacks*: a change withdrawn for a rollback is "prepared again
/// once the rollback is terminal". That promise must survive the daemon
/// restarting in between (a rollback to an older generation may itself
/// restart planariad): after the restart, the withdrawn update is prepared
/// again, not lost behind its "set aside" notice. (Reviewer's case.)
#[test]
fn a_withdrawn_update_is_prepared_again_after_a_restart() {
    let mut r = Rig::new();
    let waiting = an_update_waiting_in_built(&mut r);
    r.fake.w().activation_restarts.clear();
    let resp = r.core.handle(ADMIN, Request::Undo);
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert!(r.core.notices.iter().any(|n| n.contains("set aside for a rollback")), "{:?}", r.core.notices);
    let l = r.core.ledger();
    assert_eq!(l.terminal.get(&waiting).map(|t| t.state.clone()), Some(TxnState::Rejected(RejectReason::Interrupted)));

    // The daemon restarts before its next tick: a new process on the same
    // journal, with the executor log of the earlier run (as `main` passes it).
    let log = r.core.log.clone();
    r.fake.w().alive.remove(&100);
    r.fake.w().alive.insert(101);
    let mut core = Core::start(
        Journal::open(r.fake.store.clone()).unwrap(),
        r.fake.clone(),
        OwnerId::Daemon { pid: 101, boot_id: Hash::ZERO },
        config(),
    );
    core.remember(log);
    r.core = core;
    r.ticks(3);

    let l = r.core.ledger();
    let again = l
        .terminal
        .iter()
        .map(|(id, t)| (*id, t.transition.clone(), t.state.clone()))
        .chain(l.live.values().map(|t| (t.txn.id, t.txn.transition.clone(), t.txn.state.clone())))
        .any(|(id, t, _)| id > waiting && matches!(t, Transition::ApplyChange { .. }));
    assert!(again, "the withdrawn update was not prepared again after the restart; notices: {:?}", r.core.notices);
}

/// §12f, the other half of the reviewer's case: once a withdrawn update has
/// been prepared again, a later restart does not prepare it a second time
/// (the new transaction names it in `prepared_again_from`).
#[test]
fn a_withdrawn_update_prepared_again_is_not_prepared_twice_after_a_restart() {
    let mut r = Rig::new();
    let waiting = an_update_waiting_in_built(&mut r);
    r.fake.w().activation_restarts.clear();
    let resp = r.core.handle(ADMIN, Request::Undo);
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    r.ticks(3);
    let again_of = |l: &planarian_txn::ledger::Ledger| {
        l.terminal
            .values()
            .filter_map(|t| t.prepared_again_from)
            .chain(l.live.values().filter_map(|t| t.txn.prepared_again_from))
            .filter(|f| *f == waiting)
            .count()
    };
    assert_eq!(again_of(&r.core.ledger()), 1, "prepared again once before the restart: {:?}", r.core.notices);
    let terminal_withdrawal = r.core.ledger().terminal.get(&waiting).cloned().expect("terminal");
    assert!(terminal_withdrawal.withdrawn_for.is_some(), "the withdrawal names its rollback");

    let log = r.core.log.clone();
    r.fake.w().alive.remove(&100);
    r.fake.w().alive.insert(101);
    let mut core = Core::start(
        Journal::open(r.fake.store.clone()).unwrap(),
        r.fake.clone(),
        OwnerId::Daemon { pid: 101, boot_id: Hash::ZERO },
        config(),
    );
    core.remember(log);
    r.core = core;
    r.ticks(3);
    assert_eq!(again_of(&r.core.ledger()), 1, "not prepared a second time: {:?}", r.core.notices);
}

/// Records as main journals them, before `withdrawn_for` and
/// `prepared_again_from` (§12c: a retained record that does not parse is
/// truncated, or Integrity). Literals, not round-trips.
#[test]
fn records_journaled_before_the_withdrawal_fields_decode() {
    let advance =
        r#"{"Advance":{"txn":3,"epoch":1,"to":{"Rejected":"Interrupted"},"note":"rejected before mutation"}}"#;
    let r: Record = serde_json::from_str(advance).expect("main's Advance decodes");
    assert_eq!(
        r,
        Record::Advance {
            txn: TxnId(3),
            epoch: 1,
            to: TxnState::Rejected(RejectReason::Interrupted),
            note: "rejected before mutation".into(),
            withdrawn_for: None,
        }
    );
    let prepared = include_str!("../fixtures/prepared-before-removes-each.json");
    assert!(!prepared.contains("prepared_again_from"), "the fixture is main's form");
    let Record::Prepared(t) = serde_json::from_str::<Record>(prepared).expect("main's Prepared decodes") else {
        panic!("a Prepared record")
    };
    assert_eq!(t.prepared_again_from, None);
    // And a terminal ledger entry from a checkpoint before them.
    let terminal = r#"{"state":{"Rejected":"Interrupted"},"epoch":1,"owner":{"Daemon":{"pid":100,"boot_id":"0000000000000000000000000000000000000000000000000000000000000000"}},"path":["Prepared","Built","Rejected"],"transition":"Rollback","why":""}"#;
    let t: planarian_txn::ledger::TerminalTxn = serde_json::from_str(terminal).expect("main's TerminalTxn decodes");
    assert_eq!((t.withdrawn_for, t.prepared_again_from), (None, None));
}

/// §12f: only `prepare_again` links a transaction to a withdrawn one; an
/// ordinary submission journals no link.
#[test]
fn an_ordinary_submission_prepares_nothing_again() {
    let mut r = Rig::new();
    let waiting = an_update_waiting_in_built(&mut r);
    let l = r.core.ledger();
    let t = &l.live.values().find(|t| t.txn.id == waiting).expect("live").txn;
    assert_eq!(t.prepared_again_from, None);
}

/// §13 backoff floor: an incident's attempts are at least the backoff
/// apart by their own times (the log record's `at`, which the gym's
/// `attempt_gaps_min` reads), not by the observations that found them
/// actionable. A slow observation before one attempt and a quick one
/// before the next must not bring them closer (catalog run 41535954746,
/// flap-30s: 59 967 ms for a 60 s minimum).
#[test]
fn backoff_is_kept_between_attempts_even_after_a_slow_observation() {
    let mut r = Rig::new();
    r.ticks(2);
    let flap = UnitId::service("gym-flap");
    {
        let mut w = r.fake.w();
        let now = w.now;
        let sim = w.units.get_mut(&flap).unwrap();
        sim.fail_after = Some(Millis::secs(30));
        sim.started_at = now;
    }
    let restarts = |r: &Rig| -> Vec<u64> {
        r.core
            .log
            .iter()
            .chain(r.core.awaiting_post.iter())
            .filter(|x| {
                matches!(&x.proposal.transition, Transition::RestartUnit(u) if *u == flap)
                    && matches!(x.result, Submitted::Finished { .. })
            })
            .map(|x| x.at.0)
            .collect()
    };
    // Observations are slow until the second attempt has run, then quick.
    r.fake.w().probe_batch_ms = 7_000;
    let mut n = 0;
    while restarts(&r).len() < 2 {
        r.ticks(1);
        n += 1;
        assert!(n < 200, "no second attempt");
    }
    r.fake.w().probe_batch_ms = 0;
    while restarts(&r).len() < 3 {
        r.ticks(1);
        n += 1;
        assert!(n < 400, "no third attempt");
    }
    let at = restarts(&r);
    for (k, (w, min)) in at.windows(2).zip([10_000u64, 60_000]).enumerate() {
        assert!(w[1] - w[0] >= min, "attempts {} and {} {} ms apart (min {min} ms): {at:?}", k + 1, k + 2, w[1] - w[0]);
    }
}

/// §13: a cooldown runs from the decision that set it, like an attempt's
/// backoff, not from the start of the observation before it. The
/// diagnoser has nothing for a device whose driver was never known, so the
/// incident cools down for 1 h, counted from after the slow probes.
#[test]
fn an_exhausted_cooldown_runs_from_the_decision() {
    let mut r = Rig::new();
    r.ticks(2);
    let dev = UnitId::device("snd-hda0");
    r.fake.w().probe_batch_ms = 7_000;
    r.fake.w().devices.insert(dev.clone(), None);
    r.core.asm.known_drivers.clear();
    for _ in 0..200 {
        r.fake.advance(planarian_state::TICK);
        let observed = r.fake.now();
        r.core.tick();
        r.core.asm.known_drivers.clear();
        if let Some(IncidentState::Cooldown { until }) = r.core.incidents.active_for(&dev).map(|i| i.state.clone()) {
            assert!(
                until.0 >= observed.0 + 7_000 + planarian_incident::COOLDOWN_FIRST.0,
                "cooldown until {} from an observation at {observed:?}",
                until.0
            );
            return;
        }
    }
    panic!("no cooldown: {:#?}", r.core.notices);
}

/// Property tests for the repair loop's timing anchors (#44; the ledger's D2
/// and D3). Each attempt's backoff is timed from the clock read after the
/// attempt ran, and each cooldown or hold from the clock read at its
/// decision, never from the start of the observation before it, so a slow
/// observation can never bring two attempts closer than the floor, or end a
/// cooldown early. `PROPTEST_CASES` goes deeper.
mod timing_props {
    use super::*;
    use planarian_incident::{COOLDOWN_FIRST, COOLDOWN_LATER};
    use proptest::prelude::*;
    use proptest::test_runner::{Config as PConfig, FailurePersistence};

    fn pconfig() -> PConfig {
        let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(64);
        PConfig { cases, failure_persistence: None::<Box<dyn FailurePersistence>>, ..PConfig::default() }
    }

    /// A probe batch's length on each tick, cycled: quick, or slow enough to
    /// matter against a 10 s floor.
    fn batches() -> impl Strategy<Value = Vec<u64>> {
        proptest::collection::vec(prop_oneof![Just(0u64), 500..9_000u64], 1..8)
    }

    /// The fault: a unit that fails some seconds after each start (attempts,
    /// then a cooldown when the budget is spent), or a device whose driver
    /// was never known (the diagnoser has nothing: `exhausted`).
    /// Or, for the hold (`escalate`, RevertBlockedByFloor): a committed
    /// change raises the security floor above known_good, then a unit fails
    /// every start, so the diagnoser's only candidate is a Rollback below
    /// the floor (§12e, I16; the catalog's `floor-revert-blocked`).
    #[derive(Clone, Debug)]
    enum Fault {
        Flap(u64),
        /// A unit that stays up past the stabilization window after each
        /// start, then fails inside the regression window: Regressed.
        Relapse(u64),
        UnknownDriver,
        FloorBlocksRollback,
    }

    fn fault() -> impl Strategy<Value = Fault> {
        prop_oneof![
            3 => (5..40u64).prop_map(Fault::Flap),
            2 => (330..1_200u64).prop_map(Fault::Relapse),
            1 => Just(Fault::UnknownDriver),
            1 => Just(Fault::FloorBlocksRollback),
        ]
    }

    /// The target's repair attempts, by their log records' times (what the
    /// gym's `attempt_gaps_min` reads).
    fn attempts(r: &Rig, target: &UnitId) -> Vec<u64> {
        r.core
            .log
            .iter()
            .chain(r.core.awaiting_post.iter())
            .filter(|x| {
                matches!(&x.proposal.transition, Transition::RestartUnit(u) if u == target)
                    && matches!(x.result, Submitted::Finished { .. })
            })
            .map(|x| x.at.0)
            .collect()
    }

    /// What the tick's clock bounds: the decision came after the tick's
    /// first probe batch ran and before the tick ended.
    fn decided_within(until: Timestamp, durations: &[Millis], earliest: u64, latest: u64) -> bool {
        durations.iter().any(|d| until.0 >= earliest + d.0 && until.0 <= latest + d.0)
    }

    proptest! {
        #![proptest_config(pconfig())]

        #[test]
        fn slow_observations_never_shorten_a_backoff_or_a_cooldown(f in fault(), batch in batches()) {
            let mut r = Rig::new();
            r.ticks(2);
            let target = match f {
                Fault::Flap(secs) | Fault::Relapse(secs) => {
                    let flap = UnitId::service("gym-flap");
                    let mut w = r.fake.w();
                    let now = w.now;
                    let sim = w.units.get_mut(&flap).unwrap();
                    sim.fail_after = Some(Millis::secs(secs));
                    sim.started_at = now;
                    drop(w);
                    flap
                }
                Fault::UnknownDriver => {
                    let dev = UnitId::device("snd-hda0");
                    r.fake.w().devices.insert(dev.clone(), None);
                    r.core.asm.known_drivers.clear();
                    dev
                }
                Fault::FloorBlocksRollback => {
                    let args = [("scale".to_string(), Value::Str("1.25".into()))].into();
                    let resp = r.core.handle(ADMIN, Request::Apply { change: ChangeId("font-scale".into()), args });
                    prop_assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
                    let floor = r.fake.w().current;
                    let now = r.fake.now();
                    r.core.ex.kernel.journal.append(now, Record::SecurityFloor(Some(floor))).unwrap();
                    let web = UnitId::service("gym-web");
                    r.fake.w().units.get_mut(&web).unwrap().fail_on_start = true;
                    r.fake.w().signal(&web, 11);
                    web
                }
            };
            let mut held = false;
            let mut seen: Option<IncidentState> = None;
            // Each attempt: its time, its incident, and the backoff that
            // attempt set (read after the tick that made it).
            let mut made: Vec<(u64, IncidentId, Millis, u8)> = Vec::new();
            let ticks = if matches!(f, Fault::Relapse(_)) { 720 } else { 240 };
            for k in 0..ticks {
                let before = attempts(&r, &target).len();
                let slow = batch[k % batch.len()];
                r.fake.w().probe_batch_ms = slow;
                r.fake.advance(planarian_state::TICK);
                let start = r.fake.now().0;
                r.core.tick();
                let end = r.fake.now().0;
                if matches!(f, Fault::UnknownDriver) {
                    r.core.asm.known_drivers.clear();
                }
                let inc = r.core.incidents.active_for(&target).cloned();
                for t in attempts(&r, &target).into_iter().skip(before) {
                    if let Some(i) = &inc {
                        made.push((t, i.id, i.backoff, i.regressions));
                    }
                }
                let state = inc.as_ref().map(|i| i.state.clone());
                if state != seen {
                    // D3: a cooldown or hold set on this tick runs from its
                    // decision: after the tick's probes, before its end.
                    match &state {
                        Some(IncidentState::Cooldown { until }) => prop_assert!(
                            decided_within(*until, &[COOLDOWN_FIRST, COOLDOWN_LATER], start + slow, end),
                            "cooldown until {} set on a tick from {start} (+{slow} ms of probes) to {end}",
                            until.0
                        ),
                        // A regression's hold, set when the observation
                        // reopens the incident, is still anchored at the
                        // observation's start: the strict form waits on
                        // lane-daemon's escalation-anchor fix (ledger D3).
                        // Until then, at least an hour from the tick.
                        Some(IncidentState::Escalated { until, reason: EscalationReason::Regressed }) => {
                            held = true;
                            prop_assert!(
                                until.0 >= start + COOLDOWN_FIRST.0 && until.0 <= end + COOLDOWN_FIRST.0,
                                "regression hold until {} set on a tick from {start} to {end}",
                                until.0
                            )
                        }
                        Some(IncidentState::Escalated { until, .. }) => {
                            held = true;
                            prop_assert!(
                                // The anchor, not the length: 1 h after a
                                // regression, 6 h for a floor (§13).
                                decided_within(*until, &[COOLDOWN_FIRST, COOLDOWN_LATER], start + slow, end),
                                "hold until {} set on a tick from {start} (+{slow} ms of probes) to {end}",
                                until.0
                            )
                        }
                        _ => {}
                    }
                    if let Some(s) = &state {
                        seen = Some(s.clone());
                    }
                }
            }
            // D2: within each incident, consecutive attempts (by their log
            // records' times) are at least the backoff the earlier one set
            // apart: BACKOFF[k] at first, longer after a regression (§13).
            for w in made.windows(2) {
                let ((t0, i0, backoff, regressions), (t1, i1, _, _)) = (w[0], w[1]);
                // §13: a regression only lengthens the backoff.
                let floor = planarian_incident::BACKOFF[(regressions as usize).min(planarian_incident::BACKOFF.len() - 1)];
                prop_assert!(backoff.0 >= floor.0, "{i0:?} after {regressions} regression(s) set a {} ms backoff", backoff.0);
                if i0 == i1 {
                    prop_assert!(
                        t1 - t0 >= backoff.0,
                        "attempts of {i0:?} {} ms apart (backoff {} ms): {made:?}",
                        t1 - t0,
                        backoff.0
                    );
                }
            }
            let at: Vec<u64> = made.iter().map(|(t, _, _, _)| *t).collect();
            if let Fault::Flap(_) = f {
                prop_assert!(at.len() >= 2, "the flap was never repaired twice: {at:?}");
            }
            if let Fault::FloorBlocksRollback = f {
                prop_assert!(held, "the rollback below the floor never escalated: {:#?}", r.core.notices);
            }
        }
    }
}

/// Property tests for the daemon's rate limits and its notice cursor
/// (catch-up coverage, `docs/regression-ledger.md` D4 and D5).
/// `PROPTEST_CASES` goes deeper.
mod limit_props {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as PConfig;

    fn pconfig(cases: u32) -> PConfig {
        let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(cases);
        PConfig { cases, failure_persistence: None, ..PConfig::default() }
    }

    proptest! {
        #![proptest_config(pconfig(48))]

        /// D4 (P9, `6ad8521`): the slow-tick warning fired on nearly every VM
        /// tick. For any run of quick and slow ticks: two warnings are at
        /// least `SLOW_TICK_WARN_EVERY` apart; a slow tick that late after
        /// the last warning (or with none before) is warned at once; and the
        /// count carried to the next warning is exactly the slow ticks since
        /// the last one, so none goes uncounted.
        #[test]
        fn slow_ticks_are_warned_at_most_once_a_minute_and_all_counted(
            batches in proptest::collection::vec(prop_oneof![2 => Just(0u64), 3 => 600..3_000u64], 1..60),
        ) {
            let mut r = Rig::new();
            r.ticks(2);
            let mut last: Option<u64> = None;
            let mut since = 0u64;
            for b in batches {
                r.fake.w().probe_batch_ms = b;
                r.fake.advance(planarian_state::TICK);
                let at = r.fake.now().0;
                let warned = r.core.slow_tick_warnings;
                r.core.tick();
                let now_warned = r.core.slow_tick_warnings > warned;
                // Slow by the tick's own length on the fake clock, not by
                // the counters under test.
                let slow = r.fake.now().0 - at > planarian_state::TICK_BUDGET.0;
                prop_assert!(!now_warned || slow, "a quick tick at {at} was warned");
                if slow {
                    since += 1;
                }
                let due = last.is_none_or(|t| at >= t + SLOW_TICK_WARN_EVERY.0);
                if now_warned {
                    prop_assert!(due, "a warning at {at}, {} ms after the last", at - last.unwrap());
                    last = Some(at);
                    since = 0;
                } else if slow {
                    prop_assert!(!due, "a slow tick at {at} was due a warning (last {last:?}) and got none");
                }
                prop_assert_eq!(r.core.slow_ticks_unwarned, since);
            }
        }

        /// D5 (before the clone's history): notices stopped reaching the
        /// journal once 64 had accumulated. For any interleaving of notices
        /// and drains (the binary journals `notices_since(printed)`, then
        /// moves `printed` to `notices_total`), each drain returns exactly
        /// the notices made since the last one, oldest first, or the newest
        /// `NOTICES_KEPT` of them when more were made in between.
        #[test]
        fn each_notice_is_drained_once_in_order(
            steps in proptest::collection::vec(prop_oneof![3 => (1..90usize).prop_map(Some), 1 => Just(None)], 1..30),
        ) {
            let mut r = Rig::new();
            let base = r.core.notices_total;
            let mut printed = base;
            let mut made: Vec<String> = Vec::new();
            for s in steps {
                match s {
                    Some(k) => {
                        for _ in 0..k {
                            let n = format!("notice {}", made.len());
                            r.core.say(n.clone());
                            made.push(n);
                        }
                    }
                    None => {
                        let got: Vec<String> = r.core.notices_since(printed).cloned().collect();
                        let new = (r.core.notices_total - printed) as usize;
                        let from = made.len() - new.min(NOTICES_KEPT).min(made.len());
                        prop_assert_eq!(&got, &made[from..].to_vec(), "drain after {} made, {} printed", made.len(), printed - base);
                        printed = r.core.notices_total;
                    }
                }
                prop_assert_eq!(r.core.notices_total - base, made.len() as u64);
            }
        }
    }
}
