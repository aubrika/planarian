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
        out.extend(preservation_violations(&txn.check, txn.started, phase, s, defs));
        // Preserve aggregate Running separately from individual probe evidence:
        // an already Degraded/Unknown unit can still have required passing probes.
        for (u, before) in &txn.check.pre {
            if *before != UnitStatus::Running || !defs.contains_key(u) || !s.expected(u, defs) {
                continue;
            }
            let now = s.status(u, defs);
            if now == UnitStatus::Running {
                continue;
            }
            // A revert neither causes nor cures a full filesystem (§12c: /boot
            // full at publish is a Checking failure and the change reverts);
            // the storage units' own incidents take it from there. Anything
            // else that did not come back fails the revert.
            if phase == CheckPhase::Revert && matches!(now, UnitStatus::Degraded(_)) && space_only(u, s, defs) {
                continue;
            }
            out.push(format!("{u} was Running before and is now {now:?}"));
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

    fn check_boot_confirmation(&self, txn: &Transaction) -> Verdict {
        let manifest = txn.check.candidate.as_ref().unwrap_or(&txn.check.base);
        let (s, defs) = self.observe(manifest);
        if txn.candidate.as_ref().is_none_or(|(g, _)| *g != s.generation) {
            return Verdict::Fail("the admitted generation is no longer running".into());
        }
        let failed: Vec<String> = defs
            .iter()
            .filter_map(|(id, def)| {
                let canonical =
                    def.probes.iter().any(|p| p.origin == ProbeOrigin::Canonical && p.role == ProbeRole::Readiness);
                (canonical && s.expected(id, &defs) && s.status(id, &defs) != UnitStatus::Running)
                    .then(|| format!("{id}: canonical readiness did not pass"))
            })
            .collect();
        if failed.is_empty() { Verdict::Pass } else { Verdict::Fail(failed.join("; ")) }
    }

    fn release_gc_root(&self, path: &str) -> bool {
        self.b.generations().release_root(path)
    }

    fn now(&self) -> Timestamp {
        self.b.clock().now()
    }

    fn boot_now(&self) -> Timestamp {
        self.b.clock().boot_now()
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

/// `u` fails only free-space probes.
fn space_only(u: &UnitId, s: &SystemState, defs: &UnitDefs) -> bool {
    let failing = s.failing_readiness(u, defs);
    !failing.is_empty()
        && defs.get(u).is_some_and(|d| {
            failing.iter().all(|f| d.probes.iter().any(|p| &p.id == f && matches!(p.kind, ProbeKind::FreeSpace { .. })))
        })
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

/// Capture the independently passing applicable probes before policy-approved
/// activation. This evidence is stored in Prepared, so recovery has the same
/// obligation even if the daemon and its volatile state are gone.
pub fn passing_readiness(state: &SystemState, defs: &UnitDefs) -> Vec<(UnitId, ProbeDef)> {
    let mut passed = Vec::new();
    for (unit, def) in defs {
        if !state.expected(unit, defs) {
            continue;
        }
        let Some((_, evidence)) = state.units.get(unit) else { continue };
        for probe in def.probes.iter().filter(|p| p.role == ProbeRole::Readiness) {
            let latest = evidence.iter().filter(|e| e.probe == probe.id).max_by_key(|e| e.at);
            if latest.is_some_and(|e| {
                e.at <= state.observed_at && e.fresh_at(state.observed_at) && e.result == ProbeResult::Pass
            }) {
                passed.push((unit.clone(), probe.clone()));
            }
        }
    }
    passed
}

fn preservation_violations(
    check: &CheckContext,
    started: Timestamp,
    phase: CheckPhase,
    state: &SystemState,
    defs: &UnitDefs,
) -> Vec<String> {
    if check.version != CHECK_CONTEXT_VERSION {
        return vec!["individual pre-change probe evidence unavailable in historical/unsupported check context".into()];
    }
    let Some(passing) = &check.passing_readiness else {
        return vec!["individual pre-change probe evidence unavailable".into()];
    };
    let mut out = Vec::new();
    for (unit, before) in passing {
        // Desired-state changes may remove applicability. Definition weakening
        // cannot manufacture a pass: an applicable preserved probe must still
        // have the same definition and fresh, newly observed passing evidence.
        if !state.expected(unit, defs) {
            continue;
        }
        if !defs.get(unit).is_some_and(|d| d.probes.iter().any(|p| p == before)) {
            out.push(format!("{unit}: previously passing Readiness probe {} changed or disappeared", before.id.0));
            continue;
        }
        let latest =
            state.units.get(unit).and_then(|(_, ev)| ev.iter().filter(|e| e.probe == before.id).max_by_key(|e| e.at));
        let fresh =
            latest.is_some_and(|e| e.at >= started && e.at <= state.observed_at && e.fresh_at(state.observed_at));
        // §12c: rollback cannot cure unrelated filesystem fullness. Preserve
        // the existing revert-only exception for a newly observed FreeSpace
        // failure; missing/Unknown evidence and every other probe still fail.
        if phase == CheckPhase::Revert
            && matches!(before.kind, ProbeKind::FreeSpace { .. })
            && fresh
            && latest.is_some_and(|e| matches!(&e.result, ProbeResult::Fail(_)))
        {
            continue;
        }
        if !fresh || !latest.is_some_and(|e| e.result == ProbeResult::Pass) {
            out.push(format!(
                "{unit}: previously passing Readiness probe {} has no fresh post-change pass",
                before.id.0
            ));
        }
    }
    out
}

#[cfg(test)]
mod preservation_tests {
    use super::*;
    use planarian_schema::fixtures;

    fn candidate_violations(
        check: &CheckContext,
        started: Timestamp,
        state: &SystemState,
        defs: &UnitDefs,
    ) -> Vec<String> {
        preservation_violations(check, started, CheckPhase::Candidate, state, defs)
    }

    fn baseline(a: ProbeResult) -> (CheckContext, SystemState, UnitDefs, UnitId) {
        let mut d = fixtures::service("mixed");
        d.probes = vec![fixtures::readiness("A"), fixtures::readiness("B")];
        let unit = d.id.clone();
        let defs = fixtures::defs([d]);
        let mut state = fixtures::empty_state(1000);
        fixtures::observe(&mut state, &defs, &unit, Observed::Active, ProbeResult::Pass);
        state.units.get_mut(&unit).unwrap().1[0].result = a;
        let check = CheckContext { passing_readiness: Some(passing_readiness(&state, &defs)), ..Default::default() };
        (check, state, defs, unit)
    }

    #[test]
    fn mixed_baselines_preserve_each_passing_probe_through_replay() {
        for a in [ProbeResult::Fail("A down".into()), ProbeResult::Timeout, ProbeResult::Error("A unknown".into())] {
            let (check, mut state, defs, unit) = baseline(a);
            assert_eq!(check.passing_readiness.as_ref().unwrap().len(), 1);
            // The exact context reconstructed from Prepared/checkpoint must
            // carry the obligation used by daemon and watchdog checking alike.
            let restored: CheckContext = serde_json::from_slice(&serde_json::to_vec(&check).unwrap()).unwrap();
            assert!(candidate_violations(&restored, Timestamp(1000), &state, &defs).is_empty());
            state.units.get_mut(&unit).unwrap().1[1].result = ProbeResult::Fail("B regressed".into());
            assert_eq!(candidate_violations(&restored, Timestamp(1000), &state, &defs).len(), 1);
        }
    }

    #[test]
    fn missing_stale_timeout_error_and_old_pass_are_not_preservation_evidence() {
        let (check, state, defs, unit) = baseline(ProbeResult::Fail("A".into()));
        for result in [ProbeResult::Timeout, ProbeResult::Error("lost".into())] {
            let mut after = state.clone();
            after.units.get_mut(&unit).unwrap().1[1].result = result;
            assert!(!candidate_violations(&check, Timestamp(1000), &after, &defs).is_empty());
        }
        let mut missing = state.clone();
        missing.units.get_mut(&unit).unwrap().1.pop();
        assert!(!candidate_violations(&check, Timestamp(1000), &missing, &defs).is_empty());
        let mut stale = state.clone();
        stale.observed_at = Timestamp(100_000);
        assert!(!candidate_violations(&check, Timestamp(1000), &stale, &defs).is_empty());
        assert!(!candidate_violations(&check, Timestamp(1001), &state, &defs).is_empty());
    }

    #[test]
    fn authorized_removal_changes_applicability_but_probe_removal_does_not() {
        let (check, state, mut defs, unit) = baseline(ProbeResult::Fail("A".into()));
        defs.get_mut(&unit).unwrap().probes.pop();
        assert!(!candidate_violations(&check, Timestamp(1000), &state, &defs).is_empty());
        defs.remove(&unit);
        assert!(candidate_violations(&check, Timestamp(1000), &state, &defs).is_empty());
    }

    #[test]
    fn only_fresh_filesystem_failure_is_exempt_during_revert() {
        let (_, mut state, mut defs, unit) = baseline(ProbeResult::Pass);
        defs.get_mut(&unit).unwrap().probes[0].kind = ProbeKind::FreeSpace {
            path: "/boot".into(),
            min_bytes: 1,
            min_permille: 1,
        };
        let check = CheckContext { passing_readiness: Some(passing_readiness(&state, &defs)), ..Default::default() };
        let errors = |phase, state: &SystemState| preservation_violations(&check, Timestamp(1000), phase, state, &defs);
        state.units.get_mut(&unit).unwrap().1[0].result = ProbeResult::Fail("disk full".into());
        assert!(!errors(CheckPhase::Candidate, &state).is_empty());
        assert!(errors(CheckPhase::Revert, &state).is_empty());
        // The storage exception cannot hide a second, unrelated regression.
        state.units.get_mut(&unit).unwrap().1[1].result = ProbeResult::Fail("B regressed".into());
        assert!(!errors(CheckPhase::Revert, &state).is_empty());
        state.units.get_mut(&unit).unwrap().1[1].result = ProbeResult::Pass;
        for result in [ProbeResult::Timeout, ProbeResult::Error("unavailable".into())] {
            state.units.get_mut(&unit).unwrap().1[0].result = result;
            assert!(!errors(CheckPhase::Revert, &state).is_empty());
        }
        state.units.get_mut(&unit).unwrap().1[0].result = ProbeResult::Fail("disk full".into());
        state.observed_at = Timestamp(100_000);
        assert!(!errors(CheckPhase::Revert, &state).is_empty());
        state.observed_at = Timestamp(1000);
        state.units.get_mut(&unit).unwrap().1.remove(0);
        assert!(!errors(CheckPhase::Revert, &state).is_empty());
    }

    #[test]
    fn old_context_does_not_invent_an_empty_probe_obligation() {
        let old = r#"{"candidate":null,"base":{"units":{},"user_units":[]},"pre":{}}"#;
        let ctx: CheckContext = serde_json::from_str(old).unwrap();
        assert_eq!(ctx.version, 0);
        assert!(ctx.passing_readiness.is_none());
        assert_eq!(serde_json::to_string(&ctx).unwrap(), old);
        assert!(!candidate_violations(&ctx, Timestamp(0), &fixtures::empty_state(0), &UnitDefs::new()).is_empty());
    }
}
