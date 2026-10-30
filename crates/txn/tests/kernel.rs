//! Kernel behaviour on the fake harness. Test names follow the
//! `crates/gym/catalog/phase-a.toml` entries they exercise.

mod common;

use common::*;
use planarian_schema::*;
use planarian_txn::journal::JournalError;
use planarian_txn::kernel::{CrashPoint, KernelError};
use planarian_txn::ledger::LedgerError;

fn lost_or_crashed(r: Result<TxnState, KernelError>) {
    assert!(matches!(r, Err(KernelError::Crashed)), "expected an injected crash, got {r:?}");
}

#[test]
fn gen_override_only_change_commits() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    assert_eq!(d.run(id).unwrap(), TxnState::Committed);
    assert_eq!(
        path_of(&mut d, id),
        strs(&["Prepared", "Activating", "Checking", "Published", "Promoted", "Committed"])
    );
    rig.assert_agrees(G2, cand_override());
    assert_eq!(d.journal.ledger().live_tested, Some(G2));
    // Committed keeps its GC root; the generation's profile link takes over.
    assert!(rig.w().gc_roots.contains("/nix/var/nix/gcroots/planarian/builds/cand"));
}

#[test]
fn svc_misconfig_listen_address_reverts() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(bad_change(&rig)).unwrap();
    assert_eq!(d.run(id).unwrap(), TxnState::Reverted);
    assert_eq!(path_of(&mut d, id), strs(&["Prepared", "Activating", "Checking", "Reverting", "Reverted"]));
    rig.assert_agrees(G1, base_override());
    assert!(rig.w().gc_roots.is_empty(), "the GC root is released at a non-Committed terminal state");
    assert!(!d.journal.ledger().interlocked());
}

#[test]
fn storage_boot_full_publish_reverts() {
    let rig = Rig::new();
    rig.w().fail_publish = true;
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    // The revert's own publish_boot also hits the full /boot, so this ends in
    // RecoveryFailed unless /boot frees up; free it once the candidate failed.
    d.crash_at = Some(CrashPoint::State("Reverting"));
    lost_or_crashed(d.run(id));
    rig.w().fail_publish = false;
    rig.kill(DAEMON);
    let mut wd = rig.watchdog();
    assert_eq!(wd.recover(id, 1).unwrap(), TxnState::Reverted);
    let w = rig.w();
    assert_eq!(w.boot_default, G1, "the candidate never became the boot default");
    assert!(!w.boot_entries.contains(&G2), "the candidate is never left as the only boot entry");
}

/// Crash at each journaled state, with the daemon held down; the watchdog
/// recovers (catalog: crash-activating-bad/-good, crash-checking,
/// crash-published, crash-promoted, crash-reverting).
#[test]
fn crash_at_each_state_watchdog_recovers() {
    let cases: [(&str, bool, TxnState); 6] = [
        ("Activating", true, TxnState::Reverted),
        ("Activating", false, TxnState::Reverted),
        ("Checking", false, TxnState::Committed),
        ("Published", false, TxnState::Committed),
        ("Promoted", false, TxnState::Committed),
        ("Reverting", true, TxnState::Reverted),
    ];
    for (at, bad, expect) in cases {
        let rig = Rig::new();
        let mut d = rig.daemon();
        let t = if bad { bad_change(&rig) } else { good_change() };
        let id = d.prepare(t).unwrap();
        d.crash_at = Some(CrashPoint::State(at));
        lost_or_crashed(d.run(id));
        rig.kill(DAEMON);

        let mut wd = rig.watchdog();
        let txn = wd.journal.sync_ledger().unwrap().live[&id].txn.clone();
        assert!(wd.watchdog_should_take_over(&txn), "{at}: the owner is dead");
        assert_eq!(wd.recover(id, txn.lease.epoch).unwrap(), expect, "{at} (bad={bad})");
        let t = wd.journal.ledger().terminal[&id].clone();
        assert!(t.owner.is_watchdog(), "{at}: the watchdog finished it");
        assert_eq!(t.epoch, 2, "{at}: one takeover");
        match expect {
            TxnState::Committed => rig.assert_agrees(G2, cand_override()),
            _ => rig.assert_agrees(G1, base_override()),
        }
    }
}

/// A crash at Activating before the call: the candidate never activated, so
/// recovery reverts (the crash table: candidate not active → Reverting).
#[test]
fn crash_after_activation_accepted_good_commits() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::OpCalled("activate_live"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);
    let mut wd = rig.watchdog();
    assert_eq!(wd.recover(id, 1).unwrap(), TxnState::Committed, "candidate active → Checking → full commit path");
    rig.assert_agrees(G2, cand_override());
}

#[test]
fn watchdog_leaves_a_live_renewing_daemon_alone() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::State("Checking"));
    lost_or_crashed(d.run(id));
    // The daemon process is still alive and within its deadline.
    let mut wd = rig.watchdog();
    let txn = wd.journal.sync_ledger().unwrap().live[&id].txn.clone();
    assert!(!wd.watchdog_should_take_over(&txn));
    // Past the deadline and unrenewed: take over even though the pid lives.
    rig.w().now = Timestamp(txn.deadline.0 + 60_000);
    assert!(wd.watchdog_should_take_over(&txn));
}

/// §12h: leases are on the boot clock, so after a reboot an owner from the
/// earlier boot must read as gone even if its pid now belongs to a live
/// process; otherwise its stale boot-clock deadline could look current.
#[test]
fn an_owner_from_an_earlier_boot_is_gone_whatever_holds_its_pid() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::State("Checking"));
    lost_or_crashed(d.run(id));
    let mut wd = rig.watchdog();
    let mut txn = wd.journal.sync_ledger().unwrap().live[&id].txn.clone();
    assert!(!wd.watchdog_should_take_over(&txn), "same boot, live pid, within deadline");
    txn.lease.owner = OwnerId::Daemon { pid: txn.lease.owner.pid(), boot_id: Hash::of(b"an earlier boot") };
    assert!(wd.watchdog_should_take_over(&txn));
}

/// GA demo tail: the watchdog reverted while the daemon was down; the
/// restarted daemon writes a reconciliation record that says so.
#[test]
fn crash_daemon_restart_reconciles() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(bad_change(&rig)).unwrap();
    d.crash_at = Some(CrashPoint::State("Activating"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);
    assert_eq!(rig.watchdog().recover(id, 1).unwrap(), TxnState::Reverted);

    let mut d2 = rig.daemon2();
    assert!(d2.reconcile().unwrap().is_empty());
    let r = d2.journal.ledger().last_reconciliation.clone().expect("reconciliation record");
    let text = r.actions.join("\n");
    assert!(text.contains("the watchdog took over and finished it: Reverted"), "{text}");
    assert!(text.contains("Activating → Reverting → Reverted"), "{text}");
    assert!(r.found.contains(&(id, TxnState::Reverted)));
}

#[test]
fn daemon_waits_for_a_live_watchdog() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(bad_change(&rig)).unwrap();
    d.crash_at = Some(CrashPoint::State("Activating"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);
    // The watchdog takes over and is itself mid-revert when the daemon restarts.
    let mut wd = rig.watchdog();
    wd.crash_at = Some(CrashPoint::State("Reverting"));
    lost_or_crashed(wd.recover(id, 1));
    let mut d2 = rig.daemon2();
    assert_eq!(d2.reconcile().unwrap(), vec![id], "the daemon does not compete with a live watchdog");
    assert_eq!(state_of(&mut d2, id), TxnState::Reverting);
}

/// Kill and immediately restart the daemon while a slow activation worker
/// survives. The new owner fences it, cancels its tagged job before reverting,
/// and the old owner's later calls are refused.
#[test]
fn crash_slow_worker_overlap() {
    let rig = Rig::new();
    rig.w().slow_activation = Some((Millis::secs(120), true));
    let mut d = rig.daemon();
    d.worker_pid = Some(WORKER);
    let id = d.prepare(bad_change(&rig)).unwrap();
    d.crash_at = Some(CrashPoint::OpCalled("activate_live"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);
    let stale_op = rig.w().calls.last().unwrap().op;

    let mut d2 = rig.daemon2();
    d2.reconcile().unwrap();
    assert_eq!(state_of(&mut d2, id), TxnState::Reverted);
    assert!(!rig.w().alive.contains(&WORKER), "the old worker was killed");

    // The old worker wakes up and tries to finish its activation.
    let host = rig.host();
    use planarian_schema::GenerationBackend;
    assert!(host.activate_live(G2, &stale_op).is_fenced());
    // And the old owner cannot advance the journal.
    assert!(matches!(d.run(id), Err(KernelError::NotLive(_)) | Err(KernelError::LostLease(_))));

    let w = rig.w();
    let revert = w.calls.iter().find(|c| c.call == "activate_live(1)" && !c.fenced).expect("revert activation");
    assert_eq!(revert.pending, 0, "no activation job was pending when the revert started");
    assert_eq!(w.current, G1);
}

/// The activation job was accepted, its reply withheld, and the owner killed
/// before the OpAck. Recovery discovers the job by its OpId and waits for it
/// before deciding (catalog: crash-withheld-job-reply).
#[test]
fn crash_withheld_job_reply() {
    let rig = Rig::new();
    rig.w().slow_activation = Some((Millis::secs(30), false));
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::OpCalled("activate_live"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);

    let mut wd = rig.watchdog();
    assert_eq!(wd.recover(id, 1).unwrap(), TxnState::Committed);
    let w = rig.w();
    assert!(w.calls.iter().all(|c| c.call != "activate_live(1)"), "no conflicting mutation");
    assert_eq!(w.current, G2);
}

#[test]
fn crash_job_outlives_drain() {
    let rig = Rig::new();
    rig.w().slow_activation = Some((Millis::secs(600), false));
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::OpCalled("activate_live"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);

    let mut wd = rig.watchdog();
    assert_eq!(wd.recover(id, 1).unwrap(), TxnState::RecoveryFailed);
    assert!(wd.journal.ledger().interlocked());
    assert!(rig.w().calls.iter().all(|c| c.call != "activate_live(1)"), "never an overlapping revert");
}

#[test]
fn own_slow_activation_drains_before_deciding() {
    // No crash: the owner's own activation returns without a reply; the kernel
    // waits for the job rather than reverting over it.
    let rig = Rig::new();
    rig.w().slow_activation = Some((Millis::secs(20), false));
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    assert_eq!(d.run(id).unwrap(), TxnState::Committed);
    rig.assert_agrees(G2, cand_override());
}

#[test]
fn crash_jobs_tagged_unknown() {
    let rig = Rig::new();
    {
        let mut w = rig.w();
        w.slow_activation = Some((Millis::secs(30), true));
        w.jobs_tagged_unknown = true;
    }
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::OpCalled("activate_live"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);
    assert_eq!(rig.watchdog().recover(id, 1).unwrap(), TxnState::RecoveryFailed);
}

#[test]
fn crash_simultaneous_takeover() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::State("Checking"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = [rig.daemon2(), rig.watchdog()]
        .into_iter()
        .map(|mut k| {
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                k.take_over(id, 1).map(|l| l.map(|l| l.epoch))
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let won = results.iter().filter(|r| matches!(r, Ok(Some(2)))).count();
    let lost = results.iter().filter(|r| matches!(r, Err(KernelError::LostLease(_)))).count();
    assert_eq!((won, lost), (1, 1), "{results:?}");
}

#[test]
fn crash_runtime_rollback_recovers_as_generation_op() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let first = d.prepare(good_change()).unwrap();
    d.run(first).unwrap();
    // Rollback to known_good (G1): restores the override recorded for G1.
    let mut t = txn(Transition::Rollback, Actor::user(ADMIN));
    t.base = G2;
    t.candidate = Some((G1, path(G1)));
    t.revert_to = G2;
    t.base_override = Some(cand_override());
    t.candidate_override = Some(base_override());
    assert_eq!(t.recovery, RecoveryStrategy::RevertGeneration);
    let id = d.prepare(t).unwrap();
    d.crash_at = Some(CrashPoint::State("Checking"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);
    assert_eq!(rig.watchdog().recover(id, 1).unwrap(), TxnState::Committed);
    rig.assert_agrees(G1, base_override());
}

/// The suppression is durable before the stop; a crash after it recovers as a
/// unit operation, never a generation rollback (catalog: crash-stop-and-suppress).
#[test]
fn crash_stop_and_suppress() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let t = txn(
        Transition::StopAndSuppress { unit: web(), until: Until::Explicit, reason: "user asked".into() },
        Actor::user(ADMIN),
    );
    let id = d.prepare(t).unwrap();
    d.crash_at = Some(CrashPoint::OpBegun("stop"));
    lost_or_crashed(d.run(id));
    rig.kill(DAEMON);

    let mut wd = rig.watchdog();
    assert_eq!(wd.recover(id, 1).unwrap(), TxnState::Committed);
    let l = wd.journal.ledger();
    assert_eq!(l.overrides.len(), 1);
    assert_eq!(l.overrides[0].by, Actor::user(ADMIN));
    let w = rig.w();
    assert!(w.calls.iter().all(|c| !c.call.starts_with("activate_live") && !c.call.starts_with("restart")));
}

#[test]
fn stop_and_suppress_journals_suppression_before_stop() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let t = txn(
        Transition::StopAndSuppress { unit: web(), until: Until::Explicit, reason: String::new() },
        Actor::user(ADMIN),
    );
    let id = d.prepare(t).unwrap();
    assert_eq!(d.run(id).unwrap(), TxnState::Committed);
    let entries = d.journal.segment().unwrap();
    let suppressed =
        entries.iter().position(|e| matches!(e.record, planarian_txn::ledger::Record::OverrideSet(_))).unwrap();
    let stop = entries
        .iter()
        .position(|e| matches!(&e.record, planarian_txn::ledger::Record::OpBegin { call, .. } if call == "stop"))
        .unwrap();
    assert!(suppressed < stop);
    assert_eq!(rig.w().units[&web()], Observed::Bound);
}

#[test]
fn drv_bind_fails_restores_previous() {
    let rig = Rig::new();
    rig.w().bad_drivers.insert("vfio-pci".into());
    let mut d = rig.daemon();
    let mut t = txn(
        Transition::BindDriver { device: snd(), driver: DriverRef { name: "vfio-pci".into(), module: None } },
        Actor::user(ADMIN),
    );
    t.prior_driver = Some(hda());
    let id = d.prepare(t).unwrap();
    assert_eq!(d.run(id).unwrap(), TxnState::Reverted);
    let w = rig.w();
    assert_eq!(w.devices[&snd()], Some(hda()));
    assert!(w.calls.iter().all(|c| !c.call.starts_with("activate_live") && !c.call.starts_with("publish_boot")));
}

/// Revert probes also fail (an environmental fault): RecoveryFailed, interlock
/// set, autonomous work refused until an administrator resolves it.
#[test]
fn revert_fails_sets_interlock_until_resolved() {
    let rig = Rig::new();
    rig.w().env_fault = true;
    let mut d = rig.daemon();
    let id = d.prepare(bad_change(&rig)).unwrap();
    assert_eq!(d.run(id).unwrap(), TxnState::RecoveryFailed);
    assert!(d.journal.ledger().interlocked());

    let restart = txn(Transition::RestartUnit(UnitId::service("gym-cache")), Actor::Daemon);
    assert!(matches!(
        d.prepare(restart.clone()),
        Err(KernelError::Journal(JournalError::Ledger(LedgerError::Interlocked { .. })))
    ));

    rig.w().env_fault = false;
    let resolve = txn(Transition::Resolve { txn: id, resolution: Resolution::ManualRepaired }, Actor::user(ADMIN));
    let r = d.prepare(resolve).unwrap();
    assert_eq!(d.run(r).unwrap(), TxnState::Committed);
    assert!(!d.journal.ledger().interlocked());
    let again = d.prepare(restart).unwrap();
    assert_eq!(d.run(again).unwrap(), TxnState::Committed);
}

#[test]
fn revert_fails_interlock_survives_compaction_and_restart() {
    let rig = Rig::new();
    rig.w().env_fault = true;
    let mut d = rig.daemon();
    let id = d.prepare(bad_change(&rig)).unwrap();
    assert_eq!(d.run(id).unwrap(), TxnState::RecoveryFailed);
    d.journal.compact().unwrap();
    drop(d);

    for mut k in [rig.daemon2(), rig.watchdog()] {
        assert!(k.journal.ledger().interlocked());
        let restart = txn(Transition::RestartUnit(web()), Actor::Daemon);
        assert!(k.prepare(restart).is_err());
    }
}

#[test]
fn i6_generation_transactions_are_exclusive() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let a = d.prepare(good_change()).unwrap();
    let b = d.prepare(good_change()).unwrap();
    let r = d.prepare(txn(Transition::RestartUnit(web()), Actor::Daemon)).unwrap();
    d.crash_at = Some(CrashPoint::State("Checking"));
    lost_or_crashed(d.run(a));

    d.crash_at = None;
    let blocked = |res: Result<TxnState, KernelError>| {
        matches!(res, Err(KernelError::Journal(JournalError::Ledger(LedgerError::Exclusive { .. }))))
    };
    assert!(blocked(d.run(b)), "a second generation change while one is in flight");
    assert!(blocked(d.run(r)), "a runtime transition while a generation change is in flight");
}

#[test]
fn runtime_transitions_may_overlap_each_other() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let a = d.prepare(txn(Transition::RestartUnit(web()), Actor::Daemon)).unwrap();
    let b = d.prepare(txn(Transition::RestartUnit(UnitId::service("gym-db")), Actor::Daemon)).unwrap();
    d.crash_at = Some(CrashPoint::State("Checking"));
    lost_or_crashed(d.run(a));
    d.crash_at = None;
    assert_eq!(d.run(b).unwrap(), TxnState::Committed);
}

#[test]
fn i15_stale_owner_cannot_advance() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    d.crash_at = Some(CrashPoint::State("Checking"));
    lost_or_crashed(d.run(id));
    // The daemon is wedged, not dead; the watchdog takes over past the deadline.
    let mut wd = rig.watchdog();
    wd.take_over(id, 1).unwrap().unwrap();
    d.crash_at = None;
    assert!(matches!(d.run(id), Err(KernelError::LostLease(_))));
    assert_eq!(wd.recover(id, 2).unwrap(), TxnState::Committed);
}

#[test]
fn prepared_found_after_crash_is_rejected_interrupted() {
    let rig = Rig::new();
    let mut d = rig.daemon();
    let id = d.prepare(good_change()).unwrap();
    rig.kill(DAEMON);
    let mut d2 = rig.daemon2();
    d2.reconcile().unwrap();
    assert_eq!(state_of(&mut d2, id), TxnState::Rejected(RejectReason::Interrupted));
    assert!(rig.w().gc_roots.is_empty(), "GC root released");
}

#[test]
fn journal_full_mid_transaction_writes_the_sentinel() {
    // Find capacities at which the journal fills after the transaction began
    // mutating; each must leave the interlock set via the sentinel.
    let mut seen = 0;
    for capacity in (1_500..6_000).step_by(20) {
        let rig = Rig::with_capacity(capacity);
        let mut d = rig.daemon();
        let Ok(id) = d.prepare(bad_change(&rig)) else { continue };
        if let Err(KernelError::Journal(JournalError::Full)) = d.run(id) {
            let reopened = rig.daemon2();
            let l = reopened.journal.ledger();
            if l.live.get(&id).is_some_and(|l| !l.txn.state.is_pre_mutation()) {
                assert!(l.interlocked(), "capacity {capacity}: sentinel sets the interlock on reopen");
                seen += 1;
            }
        }
    }
    assert!(seen > 0, "no capacity filled the journal mid-transaction");
}


/// Publication must be durably recoverable before any boot selection effect,
/// including an accepted call whose acknowledgment and reply were lost.
#[test]
fn boot_publication_crash_boundaries_remain_tracked_for_both_owners() {
    for watchdog in [false, true] {
        for point in [
            CrashPoint::State("Built"),
            CrashPoint::State("PublishingBoot"),
            CrashPoint::OpBegun("publish_boot_once"),
            CrashPoint::OpCalled("publish_boot_once"),
            CrashPoint::OpAcked("publish_boot_once"),
            CrashPoint::State("AwaitingBoot"),
        ] {
            let rig = Rig::new();
            let mut daemon = rig.daemon();
            let id = daemon.prepare(good_change()).unwrap();
            daemon.crash_at = Some(point.clone());
            lost_or_crashed(daemon.run_boot_only(id));
            rig.kill(DAEMON);
            let mut owner = if watchdog { rig.watchdog() } else { rig.daemon2() };
            let before = owner.journal.sync_ledger().unwrap().live[&id].txn.clone();
            if before.state == TxnState::PublishingBoot {
                assert!(owner.watchdog_should_take_over(&before));
            }
            let end = owner.recover(id, before.lease.epoch).unwrap();
            let published = matches!(point, CrashPoint::OpCalled(_) | CrashPoint::OpAcked(_) | CrashPoint::State("AwaitingBoot"));
            if published {
                assert_eq!(end, TxnState::AwaitingBoot, "{point:?}, watchdog={watchdog}");
                let live = &owner.journal.ledger().live[&id].txn;
                assert_eq!(live.candidate.as_ref().unwrap().0, G2);
                assert_eq!(live.revert_to, G1);
                assert_eq!(rig.w().one_shot, Some(G2));
                assert!(rig.w().gc_roots.contains(live.gc_root.as_ref().unwrap()));
            } else {
                assert!(matches!(end, TxnState::Reverted | TxnState::Rejected(_)), "{end:?}");
                assert_eq!(rig.w().one_shot, None);
            }
            assert_eq!(rig.w().boot_default, G1);
            assert_eq!(rig.w().override_hash, base_override());
            assert_eq!(rig.w().current, G1, "publishing never live-activates");
        }
    }
}

#[test]
fn partial_unknown_and_failed_boot_publication_reconcile_actual_effects() {
    for reply in [
        Outcome::Partial("selection written but metadata incomplete".into()),
        Outcome::Unknown("accepted, reply lost".into()),
        Outcome::Failed("error returned after selection".into()),
    ] {
        let rig = Rig::new();
        rig.w().boot_once_reply = Some(reply);
        let mut daemon = rig.daemon();
        let id = daemon.prepare(good_change()).unwrap();
        assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::AwaitingBoot);
        assert_eq!(rig.w().one_shot, Some(G2));
        assert!(daemon.journal.ledger().live.contains_key(&id));
    }
    let rig = Rig::new();
    rig.w().fail_publish = true;
    let mut daemon = rig.daemon();
    let id = daemon.prepare(good_change()).unwrap();
    assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::Reverted);
    assert_eq!(rig.w().one_shot, None);
}

#[test]
fn unknown_boot_selection_interlocks_and_keeps_the_candidate_root() {
    let rig = Rig::new();
    rig.w().boot_once_reply = Some(Outcome::Unknown("accepted".into()));
    rig.w().boot_selection_unknown = true;
    let mut daemon = rig.daemon();
    let id = daemon.prepare(good_change()).unwrap();
    assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::RecoveryFailed);
    assert!(daemon.journal.ledger().interlocked());
    assert_eq!(rig.w().one_shot, Some(G2));
    assert!(rig.w().gc_roots.contains("/nix/var/nix/gcroots/planarian/builds/cand"));
}

/// No bootloader reply may turn a possibly running candidate into an
/// untracked Reverted transaction. These are evidence failures, not proof
/// that publication or boot did not happen.
#[test]
fn unknown_boot_identity_or_unrelated_selection_preserves_the_obligation() {
    for watchdog in [false, true] {
        for publishing in [false, true] {
            for unknown_identity in [false, true] {
                let rig = Rig::new();
                let mut daemon = rig.daemon();
                let id = daemon.prepare(good_change()).unwrap();
                if publishing {
                    daemon.crash_at = Some(CrashPoint::OpCalled("publish_boot_once"));
                    lost_or_crashed(daemon.run_boot_only(id));
                } else {
                    assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::AwaitingBoot);
                }
                {
                    let mut w = rig.w();
                    // The candidate may already have booted while the daemon
                    // was gone; a missing identity must never be read as G1.
                    w.current = G2;
                    w.last_booted = Some(G2);
                    w.one_shot = if unknown_identity { None } else { Some(GenerationId(3)) };
                    w.boot_identity_unknown = unknown_identity;
                }
                rig.kill(DAEMON);
                let mut owner = if watchdog { rig.watchdog() } else { rig.daemon2() };
                assert_eq!(owner.recover(id, 1).unwrap(), TxnState::RecoveryFailed);
                assert!(owner.journal.ledger().interlocked());
                let w = rig.w();
                assert_eq!(w.current, G2);
                assert_eq!(w.boot_default, G1);
                assert!(w.gc_roots.contains("/nix/var/nix/gcroots/planarian/builds/cand"));
                assert!(w.calls.iter().all(|c| c.call != "withdraw_boot_once"));
            }
        }
    }
}

#[test]
fn interrupted_withdrawal_never_claims_the_boot_candidate_untracked() {
    let rig = Rig::new();
    let mut daemon = rig.daemon();
    let id = daemon.prepare(good_change()).unwrap();
    daemon.crash_at = Some(CrashPoint::State("PublishingBoot"));
    lost_or_crashed(daemon.run_boot_only(id));
    rig.kill(DAEMON);
    rig.w().fail_withdraw = true;
    let mut watchdog = rig.watchdog();
    assert_eq!(watchdog.recover(id, 1).unwrap(), TxnState::RecoveryFailed);
    assert!(watchdog.journal.ledger().interlocked());
    assert!(!rig.w().gc_roots.is_empty());
}

#[test]
fn withdrawal_effects_with_failed_partial_or_lost_replies_remain_interlocked() {
    for watchdog in [false, true] {
        for reply in [
            Outcome::Failed("reply lost after withdrawal".into()),
            Outcome::Partial("selection cleared before partial reply".into()),
            Outcome::Unknown("accepted withdrawal without acknowledgment".into()),
        ] {
            let rig = Rig::new();
            let mut daemon = rig.daemon();
            let id = daemon.prepare(good_change()).unwrap();
            assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::AwaitingBoot);
            {
                let mut w = rig.w();
                w.one_shot = None;
                w.boot_default = G2;
                w.withdraw_reply = Some(reply.clone());
            }
            rig.kill(DAEMON);
            let mut owner = if watchdog { rig.watchdog() } else { rig.daemon2() };
            assert_eq!(owner.recover(id, 1).unwrap(), TxnState::RecoveryFailed);
            let w = rig.w();
            assert_eq!(w.boot_default, G1, "the withdrawal actually landed despite its reply");
            assert_eq!(w.one_shot, None);
            assert!(!w.gc_roots.is_empty());
            assert!(owner.journal.ledger().interlocked());
            assert!(owner.journal.ledger().operations(id).unwrap().iter().any(|operation| {
                operation.call == "withdraw_boot_once" && operation.ack.as_ref() == Some(&reply)
            }));
        }
    }
}

#[test]
fn every_generation_completion_establishes_the_same_floor() {
    for boot_only in [false, true] {
        for watchdog in [false, true] {
            let rig = Rig::new();
            let mut txn = good_change();
            txn.check.required_floor = Some(G2);
            txn.check.floor_fixes = vec!["inspected-package-fix".into()];
            let mut daemon = rig.daemon();
            let id = daemon.prepare(txn).unwrap();
            if boot_only {
                assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::AwaitingBoot);
                {
                    let mut w = rig.w();
                    w.one_shot = None;
                    w.last_booted = Some(G2);
                    w.current = G2;
                }
                if watchdog {
                    rig.kill(DAEMON);
                    assert_eq!(rig.watchdog().recover(id, 1).unwrap(), TxnState::Committed);
                } else {
                    assert_eq!(daemon.run(id).unwrap(), TxnState::Committed);
                }
            } else if watchdog {
                daemon.crash_at = Some(CrashPoint::State("Promoted"));
                lost_or_crashed(daemon.run(id));
                rig.kill(DAEMON);
                assert_eq!(rig.watchdog().recover(id, 1).unwrap(), TxnState::Committed);
            } else {
                assert_eq!(daemon.run(id).unwrap(), TxnState::Committed);
            }
            let journal = planarian_txn::journal::Journal::open(rig.store.clone()).unwrap();
            assert_eq!(journal.ledger().security_floor, Some(G2));
            assert_eq!(journal.ledger().terminal[&id].state, TxnState::Committed);
        }
    }
}

#[test]
fn watchdog_admits_boot_completion_only_after_the_publishing_boot() {
    let rig = Rig::new();
    let mut txn = good_change();
    txn.check.required_floor = Some(G2);
    txn.check.floor_fixes = vec!["inspected-package-fix".into()];
    let mut daemon = rig.daemon();
    let id = daemon.prepare(txn).unwrap();
    assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::AwaitingBoot);
    rig.kill(DAEMON);
    let parked = daemon.journal.ledger().live[&id].txn.clone();
    assert!(!rig.watchdog().watchdog_should_take_over(&parked), "same-boot parking does not expire");
    {
        let mut w = rig.w();
        w.one_shot = None;
        w.last_booted = Some(G2);
        w.current = G2;
    }
    let mut watchdog = planarian_txn::kernel::Kernel::new(
        planarian_txn::journal::Journal::open(rig.store.clone()).unwrap(),
        rig.host(),
        OwnerId::Watchdog { pid: WATCHDOG, boot_id: Hash::of(b"the candidate boot") },
    );
    assert!(watchdog.watchdog_should_take_over(&parked), "new-boot completion is watchdog-owned if needed");
    assert_eq!(watchdog.recover(id, 1).unwrap(), TxnState::Committed);
    assert_eq!(watchdog.journal.ledger().security_floor, Some(G2));
}

#[test]
fn completion_crashes_and_torn_floor_or_commit_writes_preserve_the_obligation() {
    for boundary in ["floor-write", "after-floor", "commit-write", "after-commit"] {
        let rig = Rig::new();
        let mut daemon = rig.daemon();
        let mut txn = good_change();
        txn.check.required_floor = Some(G2);
        txn.check.floor_fixes = vec!["inspected-package-fix".into()];
        let id = daemon.prepare(txn).unwrap();
        match boundary {
            "floor-write" => rig.store.tear_write_containing("SecurityFloor"),
            "commit-write" => rig.store.tear_write_containing("Committed"),
            "after-floor" => daemon.crash_at = Some(CrashPoint::FloorEstablished),
            "after-commit" => daemon.crash_at = Some(CrashPoint::State("Committed")),
            _ => unreachable!(),
        }
        assert!(daemon.run(id).is_err(), "{boundary}");
        rig.kill(DAEMON);
        let mut restarted = rig.daemon2();
        restarted.reconcile().unwrap();
        assert_eq!(restarted.journal.ledger().security_floor, Some(G2), "{boundary}");
        assert_eq!(restarted.journal.ledger().terminal[&id].state, TxnState::Committed, "{boundary}");
    }
}

#[test]
fn completion_never_lowers_an_existing_floor() {
    let rig = Rig::new();
    let mut daemon = rig.daemon();
    daemon.journal.append(Timestamp(1), planarian_txn::ledger::Record::SecurityFloor(Some(GenerationId(3)))).unwrap();
    let mut txn = good_change();
    txn.check.required_floor = Some(G2);
    txn.check.floor_fixes = vec!["inspected-package-fix".into()];
    let id = daemon.prepare(txn).unwrap();
    assert_eq!(daemon.run(id).unwrap(), TxnState::Committed);
    assert_eq!(daemon.journal.ledger().security_floor, Some(GenerationId(3)));
}

#[test]
fn historical_completion_without_floor_intent_is_interlocked() {
    let rig = Rig::new();
    let mut daemon = rig.daemon();
    let mut txn = good_change();
    txn.check.version = 0;
    txn.check.passing_readiness = None;
    let id = daemon.prepare(txn).unwrap();
    assert_eq!(daemon.run(id).unwrap(), TxnState::RecoveryFailed);
    assert!(daemon.journal.ledger().interlocked());
}

#[test]
fn legacy_built_publication_is_taken_over_as_a_mutation_obligation() {
    let rig = Rig::new();
    let mut daemon = rig.daemon();
    let id = daemon.prepare(good_change()).unwrap();
    daemon.wait_built(id, "old format").unwrap();
    let op = OpId { txn: id, epoch: 1, seq: 1 };
    daemon.journal.append(Timestamp(2), planarian_txn::ledger::Record::OpBegin { op, call: "publish_boot_once".into() }).unwrap();
    assert!(rig.host().publish_boot_once(G2, G1, &op).is_success());
    rig.kill(DAEMON);
    let mut watchdog = rig.watchdog();
    let txn = watchdog.journal.ledger().live[&id].txn.clone();
    assert!(watchdog.watchdog_should_take_over(&txn));
    assert_eq!(watchdog.recover(id, 1).unwrap(), TxnState::AwaitingBoot);
    assert_eq!(rig.w().one_shot, Some(G2));
}

#[test]
fn failed_boot_only_generation_uses_floor_eligible_fallback_not_old_known_good() {
    let rig = Rig::new();
    let g3 = GenerationId(3);
    {
        let mut w = rig.w();
        w.current = G2;
        w.boot_default = G2;
        w.last_booted = Some(G2);
        w.generations.insert(g3, path(g3));
    }
    let mut daemon = rig.daemon();
    daemon.journal.append(Timestamp(1), planarian_txn::ledger::Record::KnownGood(G1)).unwrap();
    daemon.journal.append(Timestamp(2), planarian_txn::ledger::Record::SecurityFloor(Some(G2))).unwrap();
    let mut txn = good_change();
    txn.base = G2;
    txn.revert_to = G2;
    txn.candidate = Some((g3, path(g3)));
    let id = daemon.prepare(txn).unwrap();
    assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::AwaitingBoot);
    assert_eq!(rig.w().boot_default, G2);
    rig.w().one_shot = None; // candidate failed; installed loader chose its default
    rig.kill(DAEMON);
    let mut watchdog = rig.watchdog();
    assert_eq!(watchdog.recover(id, 1).unwrap(), TxnState::Reverted);
    assert_eq!(rig.w().boot_default, G2);
    assert!(rig.w().boot_entries.contains(&G1), "manual boot-confirmed fallback stays available");
}

#[test]
fn no_floor_eligible_automatic_boot_target_refuses_before_publication() {
    let rig = Rig::new();
    let mut daemon = rig.daemon();
    daemon.journal.append(Timestamp(1), planarian_txn::ledger::Record::SecurityFloor(Some(G2))).unwrap();
    let id = daemon.prepare(good_change()).unwrap();
    assert!(matches!(daemon.run_boot_only(id).unwrap(), TxnState::Rejected(_)));
    assert_eq!(rig.w().one_shot, None);
    assert!(rig.w().calls.is_empty());
}

#[test]
fn a_fence_ahead_of_the_journal_blocks_override_and_publication_intents() {
    use planarian_txn::store::Store;
    for boot_only in [false, true] {
        let rig = Rig::new();
        let mut daemon = rig.daemon();
        let transaction = if boot_only {
            good_change()
        } else {
            txn(
                Transition::StopAndSuppress { unit: web(), until: Until::Explicit, reason: "maintenance".into() },
                Actor::user(ADMIN),
            )
        };
        let id = daemon.prepare(transaction).unwrap();
        let before = daemon.journal.ledger().clone();
        // Another owner fenced us but died before appending Takeover.
        rig.store.set_fence(id, 2).unwrap();
        let result = if boot_only { daemon.run_boot_only(id) } else { daemon.run(id) };
        assert!(matches!(result, Err(KernelError::LostLease(t)) if t == id));
        assert_eq!(daemon.journal.sync_ledger().unwrap(), &before);
        assert!(rig.w().calls.is_empty());
        assert_eq!(rig.w().one_shot, None);
    }
}

#[test]
fn watchdog_recovers_a_physically_fenced_owner_even_if_its_pid_is_alive() {
    use planarian_txn::store::Store;
    let rig = Rig::new();
    let mut daemon = rig.daemon();
    let mut transaction = good_change();
    transaction.check.required_floor = Some(G2);
    transaction.check.floor_fixes = vec!["inspected-fix".into()];
    let id = daemon.prepare(transaction).unwrap();
    daemon.crash_at = Some(CrashPoint::State("Promoted"));
    lost_or_crashed(daemon.run(id));
    // The process remains alive and its ledger lease is recent, but the
    // physical fence establishes that it can no longer mutate or complete.
    rig.store.set_fence(id, 2).unwrap();
    let mut watchdog = rig.watchdog();
    let transaction = watchdog.journal.ledger().live[&id].txn.clone();
    assert!(watchdog.watchdog_should_take_over(&transaction));
    assert_eq!(watchdog.recover(id, 1).unwrap(), TxnState::Committed);
    assert_eq!(watchdog.journal.ledger().terminal[&id].epoch, 3);
    assert_eq!(watchdog.journal.ledger().security_floor, Some(G2));
}

#[test]
fn intentional_boot_parking_has_no_forced_reboot_or_untracked_cancellation() {
    let rig = Rig::new();
    let mut daemon = rig.daemon();
    let id = daemon.prepare(good_change()).unwrap();
    assert_eq!(daemon.run_boot_only(id).unwrap(), TxnState::AwaitingBoot);
    rig.w().now = Timestamp(30 * 24 * 3600 * 1000);
    let parked = daemon.journal.ledger().live[&id].txn.clone();
    assert!(!rig.watchdog().watchdog_should_take_over(&parked), "parking waits for an operator-selected reboot");
    assert_eq!(daemon.run(id).unwrap(), TxnState::AwaitingBoot);
    assert!(daemon.cancel(id, Actor::user(ADMIN)).is_err(), "generic pre-mutation cancellation cannot withdraw a published candidate");
    assert_eq!(state_of(&mut daemon, id), TxnState::AwaitingBoot);
    assert_eq!(rig.w().one_shot, Some(G2));
    assert!(rig.w().calls.iter().all(|c| !c.call.starts_with("activate_live")));
    assert!(!rig.w().gc_roots.is_empty());
}
