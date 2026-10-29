//! The judge can fail: each test runs a real catalog entry on the fake
//! harness, checks it passes, then changes the evidence the way a bug would
//! and checks the judge catches it. A check that cannot fail proves nothing.

use crate::check::judge;
use crate::evidence::Evidence;
use crate::sim::unit;
use crate::{Result_, load, run_entry};
use planarian_exec::Submitted;
use planarian_schema::*;
use planarian_txn::ledger::{Entry, Record};
use toml::Value as T;

fn catalog() -> Vec<T> {
    load(concat!(env!("CARGO_MANIFEST_DIR"), "/catalog/phase-a.toml"))
}

/// Run `id`, require PASS, and return its evidence and required_post.
fn passing(id: &str) -> (Evidence, T) {
    let entries = catalog();
    let entry = entries.iter().find(|e| e.get("id").and_then(T::as_str) == Some(id)).expect("entry");
    let r = run_entry(entry);
    assert_eq!(r.result, Result_::Pass, "{id}: {:?}", r.notes);
    let e = r.sim.expect("fake run").evidence();
    let post = entry.get("required_post").cloned().expect("required_post");
    assert!(judge(&e, &post).failures.is_empty());
    (e, post)
}

fn fails(e: &Evidence, post: &T, key: &str) {
    let v = judge(e, post);
    assert!(v.failures.iter().any(|f| f.contains(key)), "expected a {key} failure, got {:?}", v.failures);
}

fn entries(e: &mut Evidence) -> &mut Vec<Entry> {
    e.entries.as_mut().expect("entries")
}

#[test]
fn restart_while_interlocked() {
    let (mut e, post) = passing("revert-fails");
    // The admin's resolution comes after the diagnoser's restart instead.
    let restart = e
        .log
        .iter()
        .find(|r| {
            matches!(r.proposal.transition, Transition::RestartUnit(_))
                && matches!(r.result, Submitted::Finished { .. })
        })
        .expect("the later repair")
        .at;
    for x in entries(&mut e) {
        if matches!(x.record, Record::Resolved { .. }) {
            x.at = Timestamp(restart.0 + 1);
        }
    }
    fails(&e, &post, "while the condition held");
}

#[test]
fn repair_while_escalated() {
    let (mut e, post) = passing("flap-regression-escalates");
    let escalated = entries(&mut e)
        .iter()
        .find(|x| matches!(&x.record, Record::Incident(i) if matches!(i.state, IncidentState::Escalated { .. })))
        .expect("escalation")
        .at;
    let r = e.log.iter_mut().find(|r| matches!(r.proposal.source, Source::Diagnoser { .. })).expect("a repair");
    r.at = Timestamp(escalated.0 + 1);
    fails(&e, &post, "while the condition held");
}

#[test]
fn restart_before_dependency_runs() {
    let (mut e, post) = passing("dep-required-stopped");
    let line = e.status_timeline.as_mut().expect("timeline").get_mut(&unit("service:gym-db")).expect("gym-db");
    line.retain(|(t, _)| t.0 <= e.start.0);
    line.push((e.start, "Stopped".into()));
    fails(&e, &post, "while service:gym-db was Stopped");
}

#[test]
fn root_cause_named_and_not_named() {
    let (mut e, post) = passing("dep-ordering-only-stopped");
    e.notices.push(
        "service:gym-app: Stopped (root cause: service:gym-cache) and nothing I know how to do would fix it".into(),
    );
    fails(&e, &post, "named as the root cause of service:gym-app");

    let (mut e, post) = passing("dep-required-stopped");
    for r in &mut e.log {
        r.proposal.source = Source::User;
    }
    e.notices.retain(|n| !n.contains("root cause"));
    fails(&e, &post, "never named as the root cause of service:gym-app");
}

#[test]
fn restart_instead_of_reobserving() {
    let (mut e, post) = passing("probe-delayed-healthy");
    e.notices.retain(|n| !n.contains("re-observing"));
    fails(&e, &post, "did not re-observe through gym-web-tcp");
}

#[test]
fn derived_facts_and_args() {
    let (mut e, post) = passing("gen-disable-reenable-canonical");
    for r in &mut e.log {
        if let Some(f) = r.facts.as_mut() {
            f.touches_canonical_probe = true;
        }
    }
    fails(&e, &post, "facts.touches_canonical_probe");

    // Without the disabling transaction, `args` finds nothing to judge.
    let (mut e, post) = passing("gen-disable-reenable-canonical");
    e.ledger.terminal.retain(|_, t| {
        !matches!(&t.transition, Transition::ApplyChange { args, .. } if args.get("enabled") == Some(&Value::Bool(false)))
    });
    e.log.clear();
    fails(&e, &post, "no such transaction or refusal");
}

#[test]
fn two_owners_one_epoch() {
    let (mut e, post) = passing("crash-simultaneous-takeover");
    let en = entries(&mut e);
    let (i, mut dup) = en
        .iter()
        .enumerate()
        .find_map(|(i, x)| matches!(x.record, Record::Takeover { .. }).then(|| (i, x.clone())))
        .expect("a takeover");
    if let Record::Takeover { lease, .. } = &mut dup.record {
        lease.owner = OwnerId::Daemon { pid: 999, boot_id: Hash::ZERO };
    }
    en.insert(i + 1, dup);
    fails(&e, &post, "owners_per_epoch_max");
    fails(&e, &post, "lease_epochs_strictly_increasing");
}

#[test]
fn watchdog_committed_without_probing() {
    let (mut e, post) = passing("crash-checking");
    for x in entries(&mut e) {
        if let Record::Advance { note, to: TxnState::Published, .. } = &mut x.record {
            note.clear();
        }
    }
    fails(&e, &post, "did not probe before publishing");
}

#[test]
fn compaction_lost_state() {
    let (mut e, post) = passing("journal-compaction-preserves-state");
    e.full_replay.as_mut().expect("compacted").overrides.clear();
    fails(&e, &post, "overrides");
}

#[test]
fn snapshot_checks() {
    let (mut e, post) = passing("stale-owner-edit-during-build");
    e.gc_roots.as_mut().expect("roots").1.insert("/nix/var/nix/gcroots/planarian/builds/leaked".into());
    fails(&e, &post, "build roots left behind");

    let (mut e, post) = passing("manifest-weaken-via-proposal");
    e.probe_defs.as_mut().expect("defs").1.push(' ');
    fails(&e, &post, "probe definitions changed");

    let (mut e, post) = passing("drv-bind-fails-restores-previous");
    e.drivers.as_mut().expect("drivers").insert(unit("device:snd-hda0"), "vfio-pci".into());
    fails(&e, &post, "bound to vfio-pci");

    let (mut e, post) = passing("gen-override-only-change");
    e.options.as_mut().expect("options").insert("planarian.reference.fontScale".into(), Value::Str("1".into()));
    fails(&e, &post, "planarian.reference.fontScale");
}

#[test]
fn hints_in_notices() {
    let (mut e, post) = passing("dep-required-stopped");
    e.notices.retain(|n| !n.contains("planarian override"));
    fails(&e, &post, "OutOfBandStopHint");

    let (mut e, post) = passing("policy-daemon-session-drop-rebind");
    e.notices.retain(|n| !n.contains("graphical session"));
    fails(&e, &post, "DisruptionSessionLoss");
}

#[test]
fn torn_record_really_tears() {
    let entries = catalog();
    let entry = entries.iter().find(|e| e.get("id").and_then(T::as_str) == Some("journal-torn-write")).expect("entry");
    let r = run_entry(entry);
    assert_eq!(r.result, Result_::Pass, "{:?}", r.notes);
    let sim = r.sim.expect("fake run");
    assert!(sim.fake.store.torn(), "the Checking record's write was not torn");
    // The torn record was never read as a transition: recovery found the
    // transaction still Activating.
    assert!(sim.notices.iter().any(|n| n.contains("found Activating")), "{:?}", sim.notices);
}

#[test]
fn emergency_selects_among_collections() {
    // A routine collection (the entry's own) and an emergency one beside it:
    // the spec asks for the emergency one, wherever it falls.
    let (mut e, _) = passing("storage-budget-unsatisfiable");
    let post: T =
        toml::from_str("[[txn]]\ntransition = \"CollectGarbage\"\nemergency = true\nterminal = \"Committed\"\n")
            .unwrap();
    assert!(!judge(&e, &post).failures.is_empty(), "no emergency collection yet");
    let (id, routine) = e
        .ledger
        .terminal
        .iter()
        .find(|(_, t)| matches!(t.transition, Transition::CollectGarbage { emergency: false }))
        .map(|(id, t)| (*id, t.clone()))
        .expect("a routine collection");
    let mut urgent = routine;
    urgent.transition = Transition::CollectGarbage { emergency: true };
    e.ledger.terminal.insert(TxnId(id.0 + 1000), urgent);
    let v = judge(&e, &post);
    assert!(v.failures.is_empty(), "{:?}", v.failures);
}

#[test]
fn vm_plan_refuses_what_the_gym_vm_cannot_be() {
    let entries = catalog();
    let get = |id: &str| entries.iter().find(|e| e.get("id").and_then(T::as_str) == Some(id)).expect("entry").clone();
    let unsupported = |id: &str| crate::live::plan(&get(id)).steps.iter().any(|s| s.starts_with("unsupported"));
    // A btrfs journal: the gym VM's is ext4, so the entry would pass on the wrong filesystem.
    assert!(unsupported("storage-journal-btrfs-reuse"));
    // ext4 is one of its layouts.
    assert!(!unsupported("storage-journal-fs-full"));
    // The VM's Nix store is the host's: it cannot really fill or be collected.
    assert!(unsupported("storage-enospc-during-build"));
    assert!(unsupported("storage-nix-full-gc"));
    assert!(!unsupported("storage-boot-full-publish"));
    // `internal wifi-connect` is the harness's own; the others do not exist.
    assert!(!unsupported("policy-daemon-wifi-runtime"));
}
