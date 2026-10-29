//! The real `txn::Host`: the kernel's view of the backends, plus the probe
//! check and re-observation the protocol needs (§9 executor-owned
//! requirements, §12 step 7). The daemon and the watchdog both use it, so
//! the watchdog can verify a candidate on its own from the journaled
//! `CheckContext`.

use planarian_schema::spec::DEFAULT_SETTLE;
use planarian_schema::*;
use planarian_state::{Assembler, Canonical, Context};
use planarian_txn::kernel::{CheckPhase, Host, Verdict};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// How long a check keeps re-observing before a non-Running unit counts as a failure.
pub const CHECK_PATIENCE: Millis = Millis::secs(30);
pub const CHECK_POLL: Millis = Millis::secs(2);

/// Generations that garbage collection must keep, maintained by the executor (I3).
pub type Protect = Arc<Mutex<Vec<GenerationId>>>;

pub struct ExecHost<B: Backends> {
    pub b: B,
    pub canonical: Canonical,
    pub protect: Protect,
    /// Baselines for the probe runs' state assembly.
    pub ctx: Arc<Mutex<Context>>,
}

impl<B: Backends + Clone> Clone for ExecHost<B> {
    fn clone(&self) -> Self {
        ExecHost {
            b: self.b.clone(),
            canonical: self.canonical.clone(),
            protect: self.protect.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

impl<B: Backends> ExecHost<B> {
    pub fn new(b: B, canonical: Canonical) -> Self {
        ExecHost { b, canonical, protect: Arc::new(Mutex::new(vec![])), ctx: Arc::new(Mutex::new(Context::default())) }
    }

    fn ctx(&self) -> Context {
        self.ctx.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn settle(&self, settle: &Settle) {
        match settle {
            Settle::Duration(d) => self.b.clock().sleep(*d),
            Settle::Ready { unit, timeout } => {
                let deadline = self.b.clock().now().plus(*timeout);
                while self.b.clock().now() < deadline {
                    if matches!(self.b.units().observe(unit), Ok(Observed::Active)) {
                        break;
                    }
                    self.b.clock().sleep(Millis::secs(1));
                }
            }
        }
    }

    /// Observe once with a fresh assembler over `manifest` (every probe due).
    fn observe(&self, manifest: &Manifest) -> (SystemState, UnitDefs) {
        let mut a = Assembler::new(manifest.clone(), self.canonical.clone());
        let s = a.observe(&self.b, &self.ctx());
        (s, a.defs())
    }

    /// The requirements a check enforces; returns what failed.
    fn violations(&self, txn: &Transaction, phase: CheckPhase, s: &SystemState, defs: &UnitDefs) -> Vec<String> {
        let mut out = vec![];
        let want_gen = match phase {
            CheckPhase::Candidate => txn.candidate.as_ref().map(|(g, _)| *g),
            CheckPhase::Revert => txn.candidate.as_ref().map(|_| txn.revert_to),
        };
        if let Some(g) = want_gen
            && s.generation != g
        {
            out.push(format!("running generation is {} (expected {})", s.generation.0, g.0));
        }
        if phase == CheckPhase::Candidate {
            for (u, want) in &txn.expected.units {
                // A unit the candidate no longer defines can't be held to a status.
                if !defs.contains_key(u) {
                    continue;
                }
                let got = s.status(u, defs);
                if &got != want {
                    out.push(format!("{u}: expected {want:?}, observed {got:?}"));
                } else if *want == UnitStatus::Bound {
                    // Bound to a driver that cannot drive it (§12 DeviceOp
                    // gym case): the device's own checks say so.
                    let failing = s.failing_readiness(u, defs);
                    if !failing.is_empty() {
                        out.push(format!(
                            "{u}: bound, but {} failing",
                            failing.iter().map(|p| p.0.as_str()).collect::<Vec<_>>().join(", ")
                        ));
                    }
                }
            }
        }
        // Executor-owned (§9): every unit that is desired-present under these
        // defs and was Running before is Running now. This covers both "no
        // unit outside may_change leaves Running" and "no applicable Readiness
        // probe that passed before fails after" (Running needs every applicable
        // Readiness probe passing, I4).
        for (u, before) in &txn.check.pre {
            if *before != UnitStatus::Running || !defs.contains_key(u) || !s.expected(u, defs) {
                continue;
            }
            let now = s.status(u, defs);
            if now != UnitStatus::Running {
                out.push(format!("{u} was Running before and is now {now:?}"));
            }
        }
        out
    }
}

impl<B: Backends> Host for ExecHost<B> {
    type Gen = B::Gens;
    type Inv = B::Inv;

    fn generations(&self) -> &B::Gens {
        self.b.generations()
    }

    fn inventory(&self) -> &B::Inv {
        self.b.inventory()
    }

    fn execute_runtime(&self, t: &Transition, op: &OpId) -> Outcome {
        match t {
            Transition::RestartUnit(u) => self.b.units().restart(u, op),
            Transition::StopUnit(u) => self.b.units().stop(u, op),
            Transition::CollectGarbage { emergency } => {
                let protect = self.protect.lock().unwrap_or_else(|e| e.into_inner()).clone();
                self.b.generations().collect_garbage(&protect, *emergency, op)
            }
            Transition::SetRuntimeOption { path, value } => self.b.runtime().set(path, value, op),
            other => Outcome::Failed(format!("not a runtime operation: {other:?}")),
        }
    }

    fn reobserve(&self, txn: &Transaction) -> Outcome {
        self.settle(&txn.expected.settle);
        let manifest = txn.check.candidate.clone().unwrap_or_else(|| txn.check.base.clone());
        let (s, defs) = self.observe(&manifest);
        let missed: Vec<String> = txn
            .expected
            .units
            .iter()
            .filter(|(u, want)| defs.contains_key(*u) && &s.status(u, &defs) != *want)
            .map(|(u, want)| format!("{u}: expected {want:?}, observed {:?}", s.status(u, &defs)))
            .collect();
        if missed.is_empty() { Outcome::Succeeded } else { Outcome::Partial(missed.join("; ")) }
    }

    fn check(&self, txn: &Transaction, phase: CheckPhase) -> Verdict {
        let settle = match phase {
            CheckPhase::Candidate => txn.expected.settle.clone(),
            CheckPhase::Revert => Settle::Duration(DEFAULT_SETTLE),
        };
        self.settle(&settle);
        let manifest = match phase {
            CheckPhase::Candidate => txn.check.candidate.clone().unwrap_or_else(|| txn.check.base.clone()),
            CheckPhase::Revert => txn.check.base.clone(),
        };
        // Re-observe for a while: units the activation restarted may still be
        // coming up. A definite failure that persists past the patience window fails.
        let deadline = self.b.clock().now().plus(CHECK_PATIENCE);
        loop {
            let (s, defs) = self.observe(&manifest);
            let v = self.violations(txn, phase, &s, &defs);
            if v.is_empty() {
                return Verdict::Pass;
            }
            if self.b.clock().now() >= deadline {
                return Verdict::Fail(v.join("; "));
            }
            self.b.clock().sleep(CHECK_POLL);
        }
    }

    fn release_gc_root(&self, path: &str) -> bool {
        self.b.generations().release_root(path)
    }

    fn now(&self) -> Timestamp {
        self.b.clock().now()
    }

    fn sleep(&self, d: Millis) {
        self.b.clock().sleep(d)
    }

    fn kill_worker(&self, pid: u32) -> bool {
        self.b.processes().kill_group(pid)
    }

    fn pid_alive(&self, pid: u32) -> bool {
        self.b.processes().alive(pid)
    }
}

/// Units that differ between two manifests, or exist in only one.
pub fn changed_units(a: &Manifest, b: &Manifest) -> BTreeSet<UnitId> {
    let mut out = BTreeSet::new();
    for (id, d) in &a.units {
        if b.units.get(id) != Some(d) {
            out.insert(id.clone());
        }
    }
    for id in b.units.keys() {
        if !a.units.contains_key(id) {
            out.insert(id.clone());
        }
    }
    out
}
