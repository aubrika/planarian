//! `fake-assumptions-conformance` (SPEC §17a, §18.12): the fake backend as a
//! second implementation of every docs/assumptions.md entry.
//!
//! Two halves. The contracts: one check per assumption the fake can hold,
//! against a fresh fake machine. The matrix: each mutating backend call,
//! with each outcome a real backend may give besides success (Partial: the
//! effect landed but the call failed; Unknown: no answer; Fenced: refused
//! before any effect), injected into a catalog entry that makes that call.
//! Every transaction must still end in a terminal state (I12), and the
//! journal must replay (I15; I6 is the ledger's own guard on replay).

use crate::sim::Sim;
use planarian_fake::{Fake, Injected, MemStore, gym_world};
use planarian_schema::*;
use planarian_txn::journal::{Journal, JournalError};
use planarian_txn::ledger::Record;
use planarian_txn::store::Store;
use toml::Value as T;

/// The mutating calls, and the catalog entry whose run makes each one.
/// (`protect`, `cancel`, `unbind` and the runtime `set` are not made by any
/// fake-harness entry: `protect` by no caller at all.)
pub const MATRIX: &[(&str, &str)] = &[
    ("restart", "svc-killed"),
    ("stop", "intent-user-stops-service"),
    ("activate_live", "gen-override-only-change"),
    ("publish_boot", "gen-override-only-change"),
    ("swap_override", "gen-override-only-change"),
    ("bind", "drv-unbound-audio"),
    ("collect_garbage", "storage-budget-unsatisfiable"),
    ("publish_boot_once", "boot-only-kernel-confirmed"),
];

pub const OUTCOMES: &[Injected] = &[Injected::Partial, Injected::Unknown, Injected::Fenced];

fn fresh() -> Fake {
    gym_world(MemStore::new(8 << 20))
}

fn op(txn: u64, epoch: u64) -> OpId {
    OpId { txn: TxnId(txn), epoch, seq: 1 }
}

/// A fence at `epoch` for `txn`, as a lease holder would write it.
fn fenced_at(f: &Fake, txn: u64, epoch: u64) {
    f.store.set_fence(TxnId(txn), epoch).expect("fence");
}

/// One check per docs/assumptions.md row the fake can hold. Rows about the
/// world outside the process (the kernel and systemd are correct) have no
/// fake counterpart and are listed as such.
pub fn contracts() -> Vec<(&'static str, Result<(), String>)> {
    let web = UnitId::service("gym-web");
    let mut out: Vec<(&'static str, Result<(), String>)> = vec![];

    // Outcome is honest: Succeeded means applied.
    out.push(("Backend Outcome is honest", {
        let f = fresh();
        fenced_at(&f, 1, 1);
        f.w().units.get_mut(&web).expect("gym-web").observed = Observed::Failed(Reason::ExitCode(1));
        let r = f.units().restart(&web, &op(1, 1));
        let o = f.units().observe(&web);
        let s = f.units().stop(&web, &op(1, 1));
        let after_stop = f.units().observe(&web);
        if r != Outcome::Succeeded || o != Ok(Observed::Active) {
            Err(format!("restart said {r:?}, then observed {o:?}"))
        } else if s != Outcome::Succeeded || after_stop == Ok(Observed::Active) {
            Err(format!("stop said {s:?}, then observed {after_stop:?}"))
        } else {
            Ok(())
        }
    }));

    // A withdrawal can have effects without a successful acknowledgment.
    // Exercise the real fake adapter, including fencing before any mutation.
    out.push(("Boot withdrawal preserves Partial/Unknown and fencing", (|| {
        for injected in OUTCOMES {
            let f = fresh();
            fenced_at(&f, 1, 1);
            let keep = f.w().current;
            {
                let mut w = f.w();
                w.one_shot = Some(GenerationId(99));
                w.boot_default = GenerationId(99);
                w.inject.insert("withdraw_boot_once".into(), *injected);
            }
            let result = f.generations().withdraw_boot_once(keep, &op(1, 1));
            let w = f.w();
            let correct = match (injected, &result) {
                (Injected::Fenced, _) => result.is_fenced() && w.one_shot == Some(GenerationId(99)),
                (Injected::Partial, Outcome::Partial(_)) | (Injected::Unknown, Outcome::Unknown(_)) => {
                    w.one_shot.is_none() && w.boot_default == keep
                }
                _ => false,
            };
            if !correct {
                return Err(format!("withdrawal {injected:?}: {result:?}, selection {:?}", w.one_shot));
            }
        }
        Ok(())
    })()));

    // activate_live(revert_to) restores revert_to's activation state.
    out.push(("activate_live(revert_to) restores revert_to", {
        let f = fresh();
        fenced_at(&f, 1, 1);
        let (base, bad) = {
            let mut w = f.w();
            let base = w.current;
            let mut o = OverrideSet::default();
            o.assignments.insert("services.gym-web.listenAddress".into(), Value::Str("192.0.2.10".into()));
            (base, w.add_generation(&o))
        };
        let a = f.generations().activate_live(bad, &op(1, 1));
        let broke = f.units().observe(&web);
        let b = f.generations().activate_live(base, &op(1, 1));
        let back = f.units().observe(&web);
        if a != Outcome::Succeeded || !matches!(broke, Ok(Observed::Failed(_))) {
            Err(format!("the bad candidate did not take effect: {a:?}, {broke:?}"))
        } else if b != Outcome::Succeeded || back != Ok(Observed::Active) || f.w().current != base {
            Err(format!("revert left {back:?} on generation {}", f.w().current.0))
        } else {
            Ok(())
        }
    }));

    // publish_boot and the override promotion are idempotent.
    out.push(("publish_boot and the override promotion are idempotent", {
        let f = fresh();
        fenced_at(&f, 1, 1);
        let g = f.w().current;
        let r1 = f.generations().publish_boot(g, &op(1, 1));
        let entries = f.w().boot_entries.clone();
        let r2 = f.generations().publish_boot(g, &op(1, 1));
        let (set, from) = f.generations().read_overrides().expect("overrides");
        let mut next = set.clone();
        next.assignments.insert("planarian.reference.fontScale".into(), Value::Str("1.25".into()));
        let to = f.generations().remember_override(&next).expect("candidate");
        let s1 = f.generations().swap_override(&from, &to, &op(1, 1));
        let s2 = f.generations().swap_override(&from, &to, &op(1, 1));
        if (r1.clone(), r2.clone()) != (Outcome::Succeeded, Outcome::Succeeded) || f.w().boot_entries != entries {
            Err(format!("publish_boot twice: {r1:?}, {r2:?}"))
        } else if (s1.clone(), s2.clone()) != (Outcome::Succeeded, Outcome::Succeeded)
            || f.generations().override_hash() != Ok(to)
        {
            Err(format!("promotion twice: {s1:?}, {s2:?}"))
        } else {
            Ok(())
        }
    }));

    // Journal fsync is durable: what a sync covered survives a crash.
    out.push(("Journal fsync is durable", {
        let store = MemStore::new(1 << 20);
        let mut j = Journal::open(store.clone()).expect("open");
        j.append(Timestamp(1), Record::KnownGood(GenerationId(7))).expect("append");
        drop(j);
        match Journal::open(store) {
            Ok(j) if j.ledger().known_good == Some(GenerationId(7)) => Ok(()),
            Ok(_) => Err("the synced record is gone".into()),
            Err(e) => Err(format!("{e:?}")),
        }
    }));

    // SHA-256 (I18): an edited retained record breaks the chain.
    out.push(("SHA-256 is collision-resistant (I18)", {
        let store = MemStore::new(1 << 20);
        let mut j = Journal::open(store.clone()).expect("open");
        for g in 1..=4 {
            j.append(Timestamp(g), Record::KnownGood(GenerationId(g))).expect("append");
        }
        drop(j);
        let _ = planarian_txn::journal::tamper(&store, 1, |p| {
            if let Some(b) = p.iter_mut().find(|b| b.is_ascii_digit()) {
                *b = if *b == b'9' { b'1' } else { *b + 1 };
            }
        });
        match Journal::open(store) {
            Err(JournalError::Integrity(_)) => Ok(()),
            other => Err(format!("an edited record opened as {:?}", other.map(|_| ()))),
        }
    }));

    // systemd reports state truthfully and honors X-RestartIfChanged: an
    // activation that changes planariad's unit does not restart the daemon.
    out.push(("systemd reports unit state truthfully; X-RestartIfChanged honored", {
        let f = fresh();
        fenced_at(&f, 1, 1);
        f.w().alive.insert(4242);
        f.w().units.get_mut(&web).expect("gym-web").observed = Observed::Bound;
        let seen = f.units().observe(&web);
        let g = {
            let mut w = f.w();
            let mut core = w.core_units.clone();
            core.insert("planariad.service".into(), Hash::of(b"changed"));
            w.core_units = core;
            w.add_generation(&OverrideSet::default())
        };
        let r = f.generations().activate_live(g, &op(1, 1));
        if seen != Ok(Observed::Bound) {
            Err(format!("a stopped unit observed as {seen:?}"))
        } else if r != Outcome::Succeeded || !f.w().alive.contains(&4242) {
            Err("activation restarted the daemon".into())
        } else {
            Ok(())
        }
    }));

    // Fencing: a stale epoch is refused before any effect.
    out.push(("Fencing is effective", {
        let f = fresh();
        fenced_at(&f, 1, 2);
        f.w().units.get_mut(&web).expect("gym-web").observed = Observed::Failed(Reason::ExitCode(1));
        let r = f.units().restart(&web, &op(1, 1));
        let o = f.units().observe(&web);
        let logged = f.w().calls.last().is_some_and(|c| c.fenced);
        if r.is_fenced() && matches!(o, Ok(Observed::Failed(_))) && logged {
            Ok(())
        } else {
            Err(format!("stale epoch: {r:?}, unit {o:?}"))
        }
    }));

    // The kernel and systemd are correct: the world outside the process.
    out.push(("The kernel and systemd are correct", Ok(())));

    // Progress (I12): backend calls terminate; jobs_tagged finds every job.
    out.push(("Backend calls terminate; jobs_tagged finds every job an op started", {
        let f = fresh();
        fenced_at(&f, 1, 1);
        f.w().slow_activation = Some((Millis::secs(60), true));
        let g = f.w().add_generation(&OverrideSet::default());
        let r = f.generations().activate_live(g, &op(1, 1));
        let jobs = f.generations().jobs_tagged(&op(1, 1));
        if !matches!(r, Outcome::Unknown(_)) {
            Err(format!("a slow activation answered {r:?}"))
        } else if !matches!(&jobs, Ok(Some(j)) if j.len() == 1) {
            Err(format!("jobs_tagged: {jobs:?}"))
        } else {
            Ok(())
        }
    }));

    // swap_override is a compare-and-swap.
    out.push(("swap_override is a compare-and-swap", {
        let f = fresh();
        fenced_at(&f, 1, 1);
        let (set, from) = f.generations().read_overrides().expect("overrides");
        let mut next = set.clone();
        next.assignments.insert("planarian.reference.fontScale".into(), Value::Str("1.5".into()));
        let to = f.generations().remember_override(&next).expect("candidate");
        let stale = Hash::of(b"someone else's file");
        let r = f.generations().swap_override(&stale, &to, &op(1, 1));
        if matches!(r, Outcome::Failed(_)) && f.generations().override_hash() == Ok(from) {
            Ok(())
        } else {
            Err(format!("a swap from a stale hash: {r:?}"))
        }
    }));
    out
}

/// Run `entry` with `outcome` injected into its first `call`; Ok if every
/// transaction ends terminal, the journal replays, and the call was made.
pub fn injected(entry: &T, call: &str, outcome: Injected) -> Result<(), String> {
    let steps = |k: &str| match entry.get(k) {
        Some(T::Array(a)) => a.clone(),
        Some(t @ T::Table(_)) => vec![t.clone()],
        _ => vec![],
    };
    let (setup, inject, after) = (steps("setup"), steps("inject"), steps("after"));
    let mut sim = Sim::new();
    for _ in 0..3 {
        sim.tick();
    }
    sim.begin();
    // Armed before the first step: the entry's first such call gets it.
    sim.fake.w().inject.insert(call.into(), outcome);
    for s in setup.iter().chain(inject.iter()).chain(after.iter()) {
        sim.step(s).map_err(|u| format!("step: {}", u.0))?;
    }
    sim.run_window(crate::window(entry));
    // Time for the watchdog and the incident manager to finish what is left.
    sim.run_window(Millis::secs(3600));
    if sim.fake.w().inject.contains_key(call) {
        return Err(format!("{} never called {call}", entry.get("id").and_then(T::as_str).unwrap_or("?")));
    }
    let l = sim.ledger();
    let open: Vec<String> = l
        .live
        .values()
        .filter(|t| !matches!(t.txn.state, TxnState::AwaitingBoot | TxnState::Built))
        .map(|t| format!("txn {} in {:?}", t.txn.id.0, t.txn.state))
        .collect();
    if !open.is_empty() {
        return Err(format!("not terminal after an hour (I12): {}", open.join(", ")));
    }
    Journal::open(sim.fake.store.clone()).map(|_| ()).map_err(|e| format!("the journal does not replay (I15): {e:?}"))
}

/// The whole entry: contracts, then the matrix.
pub fn run(catalog: &[T]) -> (bool, Vec<String>) {
    let mut notes = vec![];
    let mut ok = true;
    for (name, r) in contracts() {
        match r {
            Ok(()) => notes.push(format!("AssumptionHeld({name})")),
            Err(e) => {
                ok = false;
                notes.push(format!("assumption {name}: {e}"));
            }
        }
    }
    for (call, id) in MATRIX {
        let Some(entry) = catalog.iter().find(|e| e.get("id").and_then(T::as_str) == Some(id)) else {
            ok = false;
            notes.push(format!("{call}: no catalog entry {id}"));
            continue;
        };
        for o in OUTCOMES {
            match injected(entry, call, *o) {
                Ok(()) => notes.push(format!("{call} × {o:?} ({id}): terminal, journal replays")),
                Err(e) => {
                    ok = false;
                    notes.push(format!("{call} × {o:?} ({id}): {e}"));
                }
            }
        }
    }
    (ok, notes)
}
