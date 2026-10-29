//! The daemon loop on the fake machine, end to end. Names follow the catalog.

use super::*;
use planarian_changes::CatalogConfig;
use planarian_exec::Config;
use planarian_fake::{Fake, MemStore, fixtures, gym_world};
use planarian_policy::{Settings, Tables};

const ADMIN: Peer = Peer { uid: 0, admin: true };
const ALICE: Peer = Peer { uid: 1000, admin: false };

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
    }
}

struct Rig {
    fake: Fake,
    core: Core<Fake, MemStore>,
}

impl Rig {
    /// A machine past initial enrollment (generation 1 is known-good).
    fn new() -> Rig {
        let store = MemStore::new(8 << 20);
        let fake = gym_world(store.clone());
        fake.w().alive.insert(100);
        let mut j = Journal::open(store).unwrap();
        j.append(fake.w().now, Record::KnownGood(GenerationId(1))).unwrap();
        let core = Core::start(j, fake.clone(), OwnerId::Daemon { pid: 100, boot_id: Hash::ZERO }, config());
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
    r.fake.w().kill(&UnitId::service("gym-web"));
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

#[test]
fn dep_required_stopped_repairs_the_dependency_first() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().stop_out_of_band(&UnitId::service("gym-db"));
    r.ticks(40);

    assert_eq!(r.status("service:gym-db"), UnitStatus::Running);
    assert_eq!(r.status("service:gym-app"), UnitStatus::Running);
    let calls: Vec<String> =
        r.fake.w().calls.iter().filter(|c| c.call.starts_with("restart")).map(|c| c.call.clone()).collect();
    assert_eq!(calls.first().map(String::as_str), Some("restart(service:gym-db)"), "{calls:?}");
}

#[test]
fn ordering_only_predecessor_is_not_blamed() {
    let mut r = Rig::new();
    r.ticks(2);
    r.fake.w().kill(&UnitId::service("gym-cache"));
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
    assert_eq!(r.status("service:gym-web"), UnitStatus::Suppressed);
    assert_eq!(r.calls("restart(service:gym-web)"), 0, "no repair race");
    let resp = r.core.handle(ADMIN, Request::Ask { phrase: "start gym-web again".into(), choice: None });
    assert!(matches!(resp, Response::Done { .. }), "{resp:?}");
    r.ticks(6);
    assert_eq!(r.status("service:gym-web"), UnitStatus::Running, "desired again, so repaired");
}

#[test]
fn unprivileged_user_cannot_suppress_sshd() {
    let mut r = Rig::new();
    let resp = r.core.handle(ALICE, Request::Suppress { unit: UnitId::service("sshd"), until: Until::Explicit });
    assert!(matches!(&resp, Response::Rejected { reason, .. } if reason == "Unauthorized"), "{resp:?}");
}

#[test]
fn cli_stop_is_rewritten() {
    let mut r = Rig::new();
    let resp = r.core.handle(ADMIN, Request::Stop { unit: UnitId::service("gym-web") });
    let Response::Done { message, .. } = resp else { panic!("{resp:?}") };
    assert!(message.contains("until the next boot"));
    let l = r.core.ledger();
    assert_eq!(l.suppressions[0].until, Until::NextBoot);
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
    r.fake.w().stop_out_of_band(&UnitId::service("sshd"));
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
    assert_eq!(r.status("service:gym-cache"), UnitStatus::Suppressed);
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
    r.fake.w().kill(&UnitId::service("gym-web"));
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
    r.fake.w().kill(&UnitId::service("gym-web"));
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
