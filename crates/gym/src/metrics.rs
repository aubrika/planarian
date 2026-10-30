//! The metrics §15 asks the gym to report, over a run of the catalog: repair
//! rate, unnecessary interventions, disruption incurred, time to repair,
//! restarts per target, and RecoveryFailed count.

use crate::sim::Sim;
use planarian_exec::Submitted;
use planarian_schema::{Actor, Disruption, Outcome, Timestamp, Transition, TxnState, UnitId};
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
    /// Seconds from injection to sampled satisfaction of the required unit
    /// predicates. Transaction completion is never a health timestamp.
    time_to_repair: Vec<u64>,
    repair_time_unmeasured: usize,
    operation_outcomes: BTreeMap<&'static str, usize>,
    restarts: BTreeMap<String, usize>,
    recovery_failed: usize,
    recovery_failed_injected: usize,
    recovery_failed_in: Vec<String>,
}

fn health_satisfied_at(entry: &T, timeline: &BTreeMap<UnitId, Vec<(Timestamp, String)>>) -> Option<Timestamp> {
    let units = entry.get("required_post")?.get("units")?.as_table()?;
    if units.is_empty() {
        return None;
    }
    let mut last = Timestamp(0);
    for (name, value) in units {
        let wanted = value.as_str()?;
        let named = crate::sim::unit(name);
        let lines: Vec<_> = timeline.iter().filter(|(u, _)| crate::check::same_unit(&named, u)).collect();
        if lines.is_empty() {
            return None;
        }
        for (_, line) in lines {
            let (at, _) = line.iter().rev().take_while(|(_, status)| status == wanted).last()?;
            last = last.max(*at);
        }
    }
    Some(last)
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
        let cleared = pass;
        let autonomous = |r: &&planarian_daemon::LogRecord| !matches!(r.caller, Actor::User { .. });
        let executed = |r: &&planarian_daemon::LogRecord| matches!(&r.result, Submitted::Finished { state, .. } if !matches!(state, TxnState::Rejected(_) | TxnState::Cancelled(_)));
        if scoring == "repair" {
            self.repair_entries += 1;
            if cleared {
                self.repaired += 1;
                if let Some(t) = health_satisfied_at(entry, sim.status_timeline()) {
                    self.time_to_repair.push(t.0.saturating_sub(sim.start.0) / 1000);
                } else {
                    self.repair_time_unmeasured += 1;
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
            if let Submitted::Finished { txn, .. } = &r.result {
                let operation = r.operation.clone().unwrap_or_else(|| sim.ledger().operation_outcome(*txn));
                let key = match operation {
                    Outcome::Succeeded => "succeeded",
                    Outcome::Failed(_) => "failed",
                    Outcome::Partial(_) => "partial",
                    Outcome::Unknown(_) => "unknown",
                };
                *self.operation_outcomes.entry(key).or_default() += 1;
            }
            if let Some(f) = &r.facts {
                *self.disruption.entry(disruption_name(f.disruption)).or_default() += 1;
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
            "  evidence: {} fully checked passes ({:.0}% of runnable); {} partial verdicts",
            self.passed,
            100.0 * self.passed as f64 / self.runnable.max(1) as f64,
            self.partial
        )?;
        writeln!(f, "  repair rate: {}/{} repair entries with verified required postconditions", self.repaired, self.repair_entries)?;
        writeln!(f, "  operation outcomes (independent of lifecycle/health): {:?}", self.operation_outcomes)?;
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
            writeln!(f, "  time to sampled health satisfaction: median {} s, max {} s (simulated time)", t[t.len() / 2], t[t.len() - 1])?;
        }
        writeln!(f, "  repair latency unmeasured: {} passing repair entries without required-unit timeline evidence", self.repair_time_unmeasured)?;
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_coverage_does_not_count_as_a_verified_repair() {
        let sim = Sim::new();
        let entry: T = "scoring = 'repair'".parse().unwrap();
        let mut metrics = Metrics::default();
        metrics.add(&entry, false, true, Some(&sim));
        assert_eq!(metrics.repair_entries, 1);
        assert_eq!(metrics.repaired, 0);
        assert_eq!(metrics.partial, 1);
    }

    #[test]
    fn repair_time_comes_from_health_samples_and_rejects_missing_or_failed_samples() {
        let entry: T = "[required_post.units]\n'service:gym-web' = 'Running'".parse().unwrap();
        let unit = UnitId::service("gym-web");
        let mut timeline = BTreeMap::from([(unit.clone(), vec![
            (Timestamp(0), "Running".into()),
            (Timestamp(1000), "Failed".into()),
            (Timestamp(19_000), "Running".into()),
        ])]);
        assert_eq!(health_satisfied_at(&entry, &timeline), Some(Timestamp(19_000)));
        timeline.get_mut(&unit).unwrap().push((Timestamp(20_000), "Unknown".into()));
        assert_eq!(health_satisfied_at(&entry, &timeline), None);
        assert_eq!(health_satisfied_at(&entry, &BTreeMap::new()), None);
    }
}
