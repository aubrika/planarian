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
                catalog: ["service-enable", "font-scale", "listen-address", "repair:reenable-predicted"]
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
fn health_reporting_only_reads_the_cached_state_and_journal_cut() {
    let mut r = Rig::new();
    assert!(r.core.health_report().is_none(), "no invented initial snapshot");
    r.core.observe();
    let before = r.core.health_report().unwrap();
    let crate::hooks::JournalEvidence::Verified(prefix) = &before.journal else { panic!("verified context") };
    assert_eq!(prefix.sequence, r.core.ex.kernel.journal.ledger().last_seq);
    assert_eq!(prefix.head, r.core.ex.kernel.journal.head());
    let calls = r.fake.w().calls.len();
    let now = r.fake.w().now;
    r.fake.w().kill(&UnitId::service("gym-web"));
    for _ in 0..3 {
        assert_eq!(r.core.health_report().unwrap(), before);
    }
    assert_eq!(r.fake.w().calls.len(), calls, "reporting starts no backend operations");
    assert_eq!(r.fake.w().now, now, "reporting runs no probes or sleeps");
    assert_eq!(r.core.ex.kernel.journal.ledger().last_seq, prefix.sequence, "reporting appends no records");
    r.core.observe();
    assert_ne!(r.core.health_report().unwrap().units, before.units, "the next collection sees the failure");
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
/// user who started it, as journaled when it started, and is attributed to
/// itself in the log. One the journal has no start for holds nothing.
#[test]
fn an_agent_has_its_users_permissions() {
    let mut r = Rig::new();
    r.ticks(2);
    let stop_web = || Request::Stop { unit: UnitId::service("gym-web") };
    // Never started through `agent run`: nothing.
    let stray = Peer::agent(61185, "stray");
    let resp = r.core.handle(stray, stop_web());
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // Started by alice: alice's permissions, which do not reach gym-web.
    let resp = r.core.handle(ALICE, Request::AgentRun { name: "helper".into(), argv: vec!["true".into()] });
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let helper = Peer::agent(61186, "helper");
    let resp = r.core.handle(helper.clone(), stop_web());
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // An agent cannot start agents.
    let resp = r.core.handle(helper, Request::AgentRun { name: "more".into(), argv: vec!["true".into()] });
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
    // Started by an administrator: an administrator's permissions.
    let resp = r.core.handle(ADMIN, Request::AgentRun { name: "coder".into(), argv: vec!["true".into()] });
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    r.ticks(1);
    // Planarian does not manage the agent's unit: it is not in the manifest.
    assert_eq!(r.status("service:planarian-agent-coder"), UnitStatus::NotExpected);
    let coder = Peer::agent(61184, "coder");
    let resp = r.core.handle(coder, stop_web());
    assert!(matches!(resp, Response::Done { state: TxnState::Committed, .. }), "{resp:?}");
    // A finished transaction's record is logged at the next observation.
    r.ticks(1);
    let rec = r.core.log.iter().rev().find(|l| matches!(l.proposal.transition, Transition::StopAndSuppress { .. }));
    let rec = rec.expect("logged");
    assert_eq!(rec.agent.as_deref(), Some("coder"), "attributed to the agent");
    assert_eq!(rec.caller.uid(), Some(0), "acting for the administrator who started it");
    // Who it acts for is in the journal, so it survives a restart.
    assert_eq!(r.core.ledger().agent_for("coder"), Some(0));
    assert_eq!(r.core.ledger().agent_for("helper"), Some(1000));
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
        graphical: true,
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
        graphical: true,
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


/// A failed same-name request cannot transfer a running agent's authority.
#[test]
fn agent_name_cannot_be_reattributed_by_another_launcher() {
    let mut r = Rig::new();
    r.ticks(2);
    let launch = || Request::AgentRun { name: "owned-helper".into(), argv: vec!["true".into()] };
    assert!(matches!(r.core.handle(ALICE, launch()), Response::Ok { .. }));
    assert!(matches!(r.core.handle(ADMIN, launch()), Response::Rejected { .. }));
    assert_eq!(r.core.ledger().agent_for("owned-helper"), Some(1000));
    let resp = r.core.handle(Peer::agent(61186, "owned-helper"), Request::Stop { unit: UnitId::service("gym-web") });
    assert!(matches!(resp, Response::Rejected { .. }), "{resp:?}");
}

#[test]
fn oversized_agent_commands_do_not_get_authority() {
    let mut r = Rig::new();
    let resp = r.core.handle(ALICE, Request::AgentRun { name: "too-big".into(), argv: vec!["x".repeat(16385)] });
    assert!(matches!(resp, Response::Error { .. }));
    assert_eq!(r.core.ledger().agent_for("too-big"), None);
}

/// R05: completed/failed unit lifetimes cannot evade durable name admission.
/// The proposed contract permits 32 names per ordinary uid, 224 ordinary
/// names overall and 32 reserved root names (256 total), independent of how
/// many systemd units remain active. Every reuse still journals its start.
#[test]
fn short_lived_agent_names_are_bounded_and_preserve_root_reserve() {
    let mut r = Rig::new();
    let launch = |name: String| Request::AgentRun { name, argv: vec!["true".into()] };
    for caller in 0..7 {
        let peer = Peer::new(1000 + caller, false);
        for slot in 0..32 {
            let name = format!("finished-{caller}-{slot}");
            let response = r.core.handle(peer.clone(), launch(name.clone()));
            assert!(matches!(response, Response::Ok { .. }), "{response:?}");
            // Model a command that has already exited and been collected.
            // No live-unit count can bound this durable ownership history.
            r.fake.w().units.remove(&UnitId::service(&format!("planarian-agent-{name}")));
        }
        let seq = r.core.ledger().last_seq;
        let response = r.core.handle(peer, launch(format!("caller-overflow-{caller}")));
        assert!(matches!(response, Response::Error { .. }), "{response:?}");
        assert_eq!(r.core.ledger().last_seq, seq, "denied name is not journaled");
    }
    let seq = r.core.ledger().last_seq;
    let response = r.core.handle(Peer::new(2000, false), launch("ordinary-global-overflow".into()));
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(r.core.ledger().last_seq, seq);
    assert_eq!(r.core.ledger().agent_for("ordinary-global-overflow"), None);

    // A full caller/global budget must still permit an owned name's reuse.
    // Repeated launch events must not grow the checkpoint's owner registry.
    for _ in 0..4 {
        let seq = r.core.ledger().last_seq;
        let response = r.core.handle(ALICE, launch("finished-0-0".into()));
        assert!(matches!(response, Response::Ok { .. }), "{response:?}");
        assert!(r.core.ledger().last_seq > seq, "journal the new start before launching");
        r.fake.w().units.remove(&UnitId::service("planarian-agent-finished-0-0"));
        assert_eq!(r.core.ledger().agents.len(), 224, "reuse does not accumulate owner rows");
    }
    for slot in 0..32 {
        let name = format!("root-reserve-{slot}");
        let response = r.core.handle(ADMIN, launch(name.clone()));
        assert!(matches!(response, Response::Ok { .. }), "{response:?}");
        r.fake.w().units.remove(&UnitId::service(&format!("planarian-agent-{name}")));
    }
    let seq = r.core.ledger().last_seq;
    let response = r.core.handle(ADMIN, launch("root-total-overflow".into()));
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(r.core.ledger().last_seq, seq);
    r.core.ex.kernel.journal.compact().unwrap();
    let replay = Journal::open(r.fake.store.clone()).unwrap();
    assert_eq!(replay.ledger().agents.len(), 256);
    assert_eq!(replay.ledger().agent_for("finished-0-0"), Some(ALICE.uid));
    let mut cfg = config();
    cfg.fresh_boot = false;
    let mut restarted = Core::start(replay, r.fake.clone(), OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO }, cfg);
    assert!(matches!(restarted.handle(ADMIN, launch("still-full".into())), Response::Error { .. }));
    assert!(matches!(restarted.handle(ADMIN, launch("root-reserve-0".into())), Response::Ok { .. }));
    assert_eq!(restarted.ledger().agents.len(), 256);
}

/// A durable start whose backend launch failed still owns its name. Such
/// historical records have no live unit to count, but consume name capacity.
#[test]
fn failed_agent_start_history_cannot_bypass_name_limits() {
    let mut r = Rig::new();
    for slot in 0..32 {
        r.core.journal(Record::AgentStarted { name: format!("failed-{slot}"), by: ALICE.uid });
    }
    let seq = r.core.ledger().last_seq;
    let response = r.core.handle(ALICE, Request::AgentRun {
        name: "failed-history-overflow".into(), argv: vec!["true".into()],
    });
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(r.core.ledger().last_seq, seq);
    assert_eq!(r.core.ledger().agent_for("failed-history-overflow"), None);
    assert!(matches!(r.core.handle(ADMIN, Request::AgentRun {
        name: "recovery-after-failed-starts".into(), argv: vec!["true".into()],
    }), Response::Ok { .. }));
    assert!(matches!(r.core.handle(ALICE, Request::AgentRun {
        name: "failed-0".into(), argv: vec!["true".into()],
    }), Response::Ok { .. }));
    assert_eq!(r.core.ledger().agents.len(), 33);
}

#[test]
fn root_agent_name_limit_still_allows_owned_name_reuse() {
    let mut r = Rig::new();
    for slot in 0..64 {
        r.core.journal(Record::AgentStarted { name: format!("root-history-{slot}"), by: 0 });
    }
    let seq = r.core.ledger().last_seq;
    let response = r.core.handle(ADMIN, Request::AgentRun {
        name: "root-caller-overflow".into(), argv: vec!["true".into()],
    });
    assert!(matches!(response, Response::Error { .. }), "{response:?}");
    assert_eq!(r.core.ledger().last_seq, seq);
    assert!(matches!(r.core.handle(ADMIN, Request::AgentRun {
        name: "root-history-0".into(), argv: vec!["true".into()],
    }), Response::Ok { .. }));
    assert_eq!(r.core.ledger().agents.len(), 64);
}

/// R08: a denied release cannot replenish retry budgets, clear a hold, or
/// fan out releases to linked inferred stops.
#[test]
fn denied_release_preserves_incident_and_linked_overrides() {
    let mut r = Rig::new();
    let target = UnitId::service("gym-db");
    let linked = UnitId::service("gym-app");
    let now = r.fake.clock().now();
    for (unit, reason) in [(target.clone(), "outside stop".to_string()),
                           (linked, format!("stopped together with {target}"))] {
        let mut o = Override::attested(unit, OverrideDesired::Stopped, Until::NextBoot, reason, Actor::Unattributed);
        o.attribution = Attribution::Inferred;
        r.core.journal(Record::OverrideSet(o));
    }
    let incident = Incident {
        id: IncidentId(91), kind: IncidentKind::Repair, target: target.clone(),
        divergence: (DesiredStatus::Running, UnitStatus::Stopped), opened: now,
        attempts: vec![], budget_left: 0,
        state: IncidentState::Cooldown { until: now.plus(Millis::secs(3600)) },
        backoff: Millis::secs(300), next_attempt: now.plus(Millis::secs(300)), regressions: 2,
    };
    r.core.incidents.incidents.insert(incident.id, incident.clone());
    let before = r.core.ledger().overrides;
    let denied = r.core.handle(ALICE, Request::LiftOverride { unit: target.clone() });
    assert!(matches!(denied, Response::Rejected { .. }), "{denied:?}");
    assert_eq!(r.core.incidents.incidents[&incident.id], incident);
    assert_eq!(r.core.ledger().overrides, before);
    let allowed = r.core.handle(ADMIN, Request::LiftOverride { unit: target });
    assert!(matches!(allowed, Response::Done { state: TxnState::Committed, .. }), "{allowed:?}");
    let after = &r.core.incidents.incidents[&incident.id];
    assert_eq!(after.state, IncidentState::Open);
    assert_eq!(after.budget_left, 1);
    assert!(r.core.ledger().overrides.is_empty());
}

/// R09: admission happens before a job is handed to the build queue, while
/// a valid administrator request that will require AskFirst remains valid.
#[test]
fn deferred_catalog_work_authenticates_before_staging() {
    let mut r = Rig::new();
    r.core.defer = true;
    let args = [("service".into(), Value::Str("sshd".into())), ("enabled".into(), Value::Bool(false))].into();
    let req = Request::Apply { change: ChangeId("service-enable".into()), args };
    let denied = r.core.handle(ALICE, req.clone());
    assert!(matches!(denied, Response::Rejected { .. }), "{denied:?}");
    assert!(r.core.take_deferred().is_none());
    assert!(r.fake.w().staged.is_empty());
    assert_eq!(r.fake.w().builds, 0);
    let accepted = r.core.handle(Peer::new(1001, true), req);
    assert!(matches!(accepted, Response::Ok { .. }));
    let (job, resume) = r.core.take_deferred().expect("authorized AskFirst candidate may be built");
    assert_eq!(resume.principal(), Actor::user(1001).principal());
    let response = r.core.resume(resume, job.run());
    assert!(matches!(response, Response::NeedsApproval { .. }), "{response:?}");
}

#[test]
fn deferred_agent_work_keeps_launching_principal_limits_and_attribution() {
    let mut r = Rig::new();
    r.ticks(2);
    r.core.log.clear();
    r.core.journal(Record::AgentStarted { name: "coder".into(), by: ALICE.uid });
    r.core.defer = true;
    let request = Request::Apply {
        change: ChangeId("font-scale".into()),
        args: [("scale".into(), Value::Str("1.25".into()))].into(),
    };
    let placeholder = r.core.handle(Peer::agent(61184, "coder"), request);
    assert!(matches!(placeholder, Response::Ok { .. }));
    let (job, resume) = r.core.take_deferred().unwrap();
    assert_eq!(resume.principal(), Actor::user(ALICE.uid).principal());
    assert!(!resume.administrator());
    let response = r.core.resume(resume, job.run());
    assert!(matches!(response, Response::Done { state: TxnState::Committed, .. }), "{response:?}");
    r.ticks(1);
    let entry = r.core.log.iter().find(|l| matches!(l.proposal.transition, Transition::ApplyChange { .. })).unwrap();
    assert_eq!(entry.agent.as_deref(), Some("coder"));
    assert_eq!(entry.facts.as_ref().unwrap().caller, Actor::user(ALICE.uid));
}

/// D03: runtime lifecycle completion cannot manufacture backend success or
/// healthy post-state. Failure remains durable after compaction/restart.
#[test]
fn committed_runtime_failure_is_not_a_repaired_incident() {
    let mut r = Rig::new();
    let unit = UnitId::service("gym-web");
    r.ticks(2);
    r.fake.w().units.get_mut(&unit).unwrap().fail_on_start = true;
    r.fake.w().signal(&unit, 11);
    r.ticks(4);
    r.core.observe();
    let incident = r.core.incidents.active_for(&unit).expect("still failed");
    assert!(!incident.attempts.is_empty());
    for (txn, outcome) in &incident.attempts {
        assert_eq!(r.core.ledger().state(*txn), Some(TxnState::Committed), "runtime lifecycle completes");
        assert!(matches!(outcome, Outcome::Failed(_)), "backend failure is not success: {outcome:?}");
    }
    let record = r.core.log.iter().find(|record| {
        matches!(&record.proposal.source, Source::Diagnoser { .. })
            && record.proposal.transition == Transition::RestartUnit(unit.clone())
    }).expect("attempt log");
    assert_eq!(record.format, 2);
    assert!(matches!(record.operation, Some(Outcome::Failed(_))));
    assert!(matches!(record.expectation, Some(Outcome::Partial(_))));
    assert!(matches!(record.post_status.get(&unit), Some(UnitStatus::Failed(_))));
    assert!(!r.core.notices.iter().any(|line| line.contains("repaired with")));
    let txn = incident.attempts[0].0;
    r.core.ex.kernel.journal.compact().unwrap();
    let replay = Journal::open(r.fake.store.clone()).unwrap();
    assert_eq!(replay.ledger().state(txn), Some(TxnState::Committed));
    assert!(matches!(replay.ledger().operation_outcome(txn), Outcome::Failed(_)));
}

#[test]
fn operation_expectation_and_health_are_independent_results() {
    for injected in [planarian_fake::Injected::Partial, planarian_fake::Injected::Unknown] {
        let mut r = Rig::new();
        let unit = UnitId::service("gym-web");
        r.ticks(2);
        r.fake.w().inject.insert("restart".into(), injected);
        let response = r.core.handle(ADMIN, Request::Restart { unit: unit.clone() });
        let Response::Done { state: TxnState::Committed, message, .. } = response else { panic!("{response:?}") };
        assert!(!message.starts_with("operation succeeded"), "{message}");
        r.core.observe();
        let record = r.core.log.last().expect("post-observed log");
        match injected {
            planarian_fake::Injected::Partial => assert!(matches!(record.operation, Some(Outcome::Partial(_)))),
            planarian_fake::Injected::Unknown => assert!(matches!(record.operation, Some(Outcome::Unknown(_)))),
            planarian_fake::Injected::Fenced => unreachable!(),
        }
        assert_eq!(record.expectation, Some(Outcome::Succeeded), "effect may land despite failed/lost reply");
        assert_eq!(record.post_status.get(&unit), Some(&UnitStatus::Running));
    }
}

#[test]
fn recovery_interlock_keeps_its_candidate_and_fallback_protected() {
    let r = Rig::new();
    let mut ledger = r.core.ledger();
    ledger.add_interlock(planarian_txn::ledger::InterlockEntry {
        txn: TxnId(20),
        transition: Transition::Rollback,
        failed_from: "PublishingBoot".into(),
        base_override: None,
        candidate_override: None,
        revert_to: GenerationId(7),
        note: "selection unknown".into(),
        evidence_version: 1,
        candidate: Some((GenerationId(9), StorePath("/nix/store/candidate".into()))),
        gc_root: Some("/nix/var/nix/gcroots/planarian/builds/pending".into()),
    });
    let protected = r.core.protect(&ledger, GenerationId(1));
    assert!(protected.contains(&GenerationId(7)), "fallback stays protected");
    assert!(protected.contains(&GenerationId(9)), "selected candidate stays protected after RecoveryFailed");
}
