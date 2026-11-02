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

/// §12f, I6 (owner decision, Nov 2): a repair rollback withdraws a
/// generation transaction still waiting in `Built` (`Rejected(Interrupted)`)
/// and it is prepared again, with its caller, once the repair is terminal.
#[test]
fn a_repair_rollback_withdraws_a_waiting_update() {
    let mut r = Rig::new();
    seated_session(&mut r, false);
    r.ticks(2);
    let resp = r.core.handle(ALICE.in_session("s1"), font("1.25"));
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    let broken = GenerationId(2);
    assert_eq!(r.fake.w().current, broken);
    // A further update that restarts the display manager waits while the
    // session is in use.
    r.fake.w().activation_restarts.insert(UnitId::service("display-manager"));
    // Not asked for by the user (so not its own window); alice's change.
    let (s, defs) = r.core.observe();
    let t = Transition::ApplyChange {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.5".into()))].into(),
    };
    let p = r.core.proposal(t, &s, &defs, Source::Maintenance, "update".into());
    let alice = r.core.authz(&ALICE.in_session("s1"));
    let got = r.core.submit(p, alice, &s, &defs);
    let Submitted::Finished { txn: waiting, state: TxnState::Built, .. } = got else { panic!("{got:?}") };

    // The committed update's flaw shows: restarts cannot fix it, so the
    // diagnoser reaches its rollback (which restarts the display manager
    // too, so it asks).
    let printer = UnitId::service("gym-printer");
    r.fake.w().break_in(broken, &printer);
    let mut asked = None;
    for _ in 0..200 {
        r.ticks(1);
        if let Some(p) = r.core.ex.parked.values().find(|p| p.proposal.transition == Transition::Rollback) {
            asked = Some(p.bound_to);
            break;
        }
    }
    let approve = asked.expect("the repair rollback was proposed");
    let l = r.core.ledger();
    assert_eq!(
        l.terminal.get(&waiting).map(|t| t.state.clone()),
        Some(TxnState::Rejected(RejectReason::Interrupted)),
        "withdrawn before it mutated"
    );
    assert!(r.core.notices.iter().any(|n| n.contains("set aside for a repair rollback")), "{:?}", r.core.notices);
    r.ticks(2);
    assert!(
        !r.core.ledger().live.values().any(|t| matches!(t.txn.transition, Transition::ApplyChange { .. })),
        "not prepared again while the repair is active"
    );

    let resp = r.core.handle(ADMIN.at_terminal(), Request::Approve { hash: approve });
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    assert_eq!(r.fake.w().current, GenerationId(1));
    r.ticks(2);
    let l = r.core.ledger();
    let again = l
        .live
        .values()
        .find(|t| matches!(t.txn.transition, Transition::ApplyChange { .. }))
        .expect("prepared again once the repair is terminal");
    assert_eq!(again.txn.state, TxnState::Built, "and waits for its window again");
    assert!(r.core.notices.iter().any(|n| n.contains("prepared again after the repair rollback")));
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
    assert!(!r.core.notices.iter().any(|n| n.contains("set aside for a repair rollback")), "{:?}", r.core.notices);
}

/// #26 review (1): a repair rollback refused before it gets a transaction
/// (here its dry activation fails, R10) gives nothing the withdrawn change
/// made way for: it is prepared again in the same tick.
#[test]
fn a_refused_repair_rollback_gives_the_withdrawn_change_back() {
    let mut r = Rig::new();
    seated_session(&mut r, false);
    r.ticks(2);
    let resp = r.core.handle(ALICE.in_session("s1"), font("1.25"));
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    let broken = GenerationId(2);
    r.fake.w().activation_restarts.insert(UnitId::service("display-manager"));
    let (s, defs) = r.core.observe();
    let t = Transition::ApplyChange {
        change: ChangeId("font-scale".into()),
        args: [("scale".to_string(), Value::Str("1.5".into()))].into(),
    };
    let p = r.core.proposal(t, &s, &defs, Source::Maintenance, "update".into());
    let alice = r.core.authz(&ALICE.in_session("s1"));
    let got = r.core.submit(p, alice, &s, &defs);
    let Submitted::Finished { txn: waiting, state: TxnState::Built, .. } = got else { panic!("{got:?}") };

    r.fake.w().break_in(broken, &UnitId::service("gym-printer"));
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
    assert_eq!(
        l.terminal.get(&waiting).map(|t| t.state.clone()),
        Some(TxnState::Rejected(RejectReason::Interrupted)),
        "it was withdrawn for the attempt"
    );
    let again = l
        .live
        .values()
        .find(|t| matches!(t.txn.transition, Transition::ApplyChange { .. }))
        .expect("prepared again in the same tick");
    assert_eq!(again.txn.state, TxnState::Built);
    assert!(r.core.notices.iter().any(|n| n.contains("prepared again after a refused repair rollback")));
    assert!(r.core.withdrawn.is_empty(), "nothing left waiting for a repair that never ran");
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
    r.core.prepare_again(vec![(TxnId(40), t)], "after a restart", &s, &defs);
    let l = r.core.ledger();
    let again = l
        .live
        .values()
        .find(|t| matches!(t.txn.transition, Transition::ApplyChange { .. }))
        .expect("prepared again, and waiting");
    assert_eq!(r.core.incident_parked.get(&incident), Some(&again.txn.id), "linked to its incident");
}
