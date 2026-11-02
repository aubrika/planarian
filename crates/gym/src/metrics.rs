//! The metrics §15 asks the gym to report, over a run of the catalog: repair
//! rate, unnecessary interventions, disruption incurred, time to repair,
//! restarts per target, and RecoveryFailed count.

use crate::sim::Sim;
use planarian_exec::Submitted;
use planarian_schema::{Actor, Disruption, Transition, TxnState};
use std::collections::BTreeMap;
use std::fmt;
use toml::Value as T;

#[derive(Default)]
pub struct Metrics {
    runnable: usize,
    passed: usize,
    partial: usize,
    repair_entries: usize,
    repaired: usize,
    intent_entries: usize,
    unnecessary: usize,
    disruption: BTreeMap<&'static str, usize>,
    /// Seconds from injection to the last committed autonomous transaction,
    /// for each repair entry that was cleared.
    time_to_repair: Vec<u64>,
    restarts: BTreeMap<String, usize>,
    recovery_failed: usize,
    recovery_failed_injected: usize,
    recovery_failed_in: Vec<String>,
}

fn disruption_name(d: Disruption) -> &'static str {
    match d {
        Disruption::None => "none",
        Disruption::Brief => "brief",
        Disruption::SessionLoss => "session loss",
        Disruption::DataInterruption => "data interruption",
        Disruption::ConnectivityLoss => "connectivity loss",
    }
}

impl Metrics {
    pub fn add(&mut self, entry: &T, pass: bool, partial: bool, sim: Option<&Sim>) {
        let Some(sim) = sim else { return };
        self.runnable += 1;
        self.passed += pass as usize;
        self.partial += partial as usize;
        let scoring = entry.get("scoring").and_then(T::as_str).unwrap_or("");
        let cleared = pass || partial;
        let autonomous = |r: &&planarian_daemon::LogRecord| !matches!(r.caller, Actor::User { .. });
        let executed = |r: &&planarian_daemon::LogRecord| matches!(&r.result, Submitted::Finished { state, .. } if !matches!(state, TxnState::Rejected(_) | TxnState::Cancelled(_)));
        if scoring == "repair" {
            self.repair_entries += 1;
            if cleared {
                self.repaired += 1;
                let last = sim
                    .log
                    .iter()
                    .filter(autonomous)
                    .filter(|r| matches!(r.result, Submitted::Finished { state: TxnState::Committed, .. }))
                    .map(|r| r.at.0)
                    .max();
                if let Some(t) = last {
                    self.time_to_repair.push(t.saturating_sub(sim.start.0) / 1000);
                }
            }
        }
        if scoring == "intent" {
            self.intent_entries += 1;
            // The user's own setup is not an intervention; anything the
            // daemon did after it is.
            self.unnecessary += sim.log.iter().filter(autonomous).filter(executed).count();
        }
        for r in sim.log.iter().filter(executed) {
            if let Some(f) = &r.facts {
                // Once per kind the change carries (C10), or as none.
                let kinds = f.disruption.members();
                if kinds.is_empty() {
                    *self.disruption.entry(disruption_name(Disruption::None)).or_default() += 1;
                }
                for d in kinds {
                    *self.disruption.entry(disruption_name(d)).or_default() += 1;
                }
            }
            if let Transition::RestartUnit(u) = &r.proposal.transition {
                *self.restarts.entry(u.to_string()).or_default() += 1;
            }
        }
        let failed = sim.ledger().terminal.values().filter(|t| t.state == TxnState::RecoveryFailed).count();
        // Expected where the entry itself names it (its setup waits for it,
        // or its required_post asks for it).
        let injected = entry.to_string().contains("RecoveryFailed");
        if injected {
            self.recovery_failed_injected += failed;
        } else if failed > 0 {
            self.recovery_failed += failed;
            self.recovery_failed_in.push(entry.get("id").and_then(T::as_str).unwrap_or("?").to_string());
        }
    }
}

impl fmt::Display for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "metrics (fake harness, {} runnable entries):", self.runnable)?;
        writeln!(
            f,
            "  cleared: {} fully checked, {} with every fake-checkable key holding ({:.0}% of runnable)",
            self.passed,
            self.partial,
            100.0 * (self.passed + self.partial) as f64 / self.runnable.max(1) as f64
        )?;
        writeln!(f, "  repair rate: {}/{} repair entries cleared", self.repaired, self.repair_entries)?;
        writeln!(
            f,
            "  unnecessary interventions: {} on {} intent entries (must be 0)",
            self.unnecessary, self.intent_entries
        )?;
        let total: usize = self.disruption.values().sum();
        let by: Vec<String> = self.disruption.iter().map(|(k, n)| format!("{k} {n}")).collect();
        writeln!(f, "  disruption incurred: {total} executed transactions ({})", by.join(", "))?;
        let mut t = self.time_to_repair.clone();
        t.sort();
        if !t.is_empty() {
            writeln!(f, "  time to repair: median {} s, max {} s (simulated time)", t[t.len() / 2], t[t.len() - 1])?;
        }
        let max = self.restarts.iter().max_by_key(|(_, n)| **n);
        if let Some((u, n)) = max {
            writeln!(
                f,
                "  restarts: {} in total, at most {n} of {u} in one run set",
                self.restarts.values().sum::<usize>()
            )?;
        }
        write!(
            f,
            "  RecoveryFailed: {} unexpected (must be 0){}, {} where the entry injects it",
            self.recovery_failed,
            if self.recovery_failed_in.is_empty() {
                String::new()
            } else {
                format!(" in {}", self.recovery_failed_in.join(", "))
            },
            self.recovery_failed_injected
        )
    }
}
