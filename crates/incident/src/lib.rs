//! Incident lifecycle (SPEC §13): open, defer to systemd, attempts with
//! budget and backoff, close on a stabilized desired predicate, regression,
//! escalation, cooldown. Pure: time comes in as an argument, and every
//! incident that changes is returned so the daemon can journal it.

use planarian_schema::{
    DesiredStatus, Incident, IncidentId, IncidentKind, IncidentState, Millis, Outcome, SystemState, Timestamp, TxnId,
    UnitDefs, UnitId, UnitStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const BUDGET: u8 = 3;
pub const BACKOFF: [Millis; 3] = [Millis::secs(10), Millis::secs(60), Millis::secs(300)];
pub const STABILIZATION: Millis = Millis::secs(5 * 60);
pub const REGRESSION_WINDOW: Millis = Millis::secs(30 * 60);
pub const ESCALATE_AT: u8 = 3;
pub const COOLDOWN_FIRST: Millis = Millis::secs(3600);
pub const COOLDOWN_LATER: Millis = Millis::secs(6 * 3600);
pub const SETTLE: Millis = Millis::secs(15);
/// Consecutive ticks of divergence before an incident opens.
pub const OPEN_AFTER: u8 = 2;
/// Consecutive Unknown ticks before a diagnostic incident opens (§10).
pub const UNKNOWN_LIMIT: u8 = 3;
/// How far back failures count toward systemd's own start limit.
pub const FAILURE_WINDOW: Millis = Millis::secs(10 * 60);

/// §13 "Open when …": the divergences that open an incident.
pub fn divergent(desired: DesiredStatus, status: &UnitStatus) -> bool {
    use UnitStatus as S;
    match desired {
        DesiredStatus::Running => {
            matches!(status, S::Failed(_) | S::Degraded(_) | S::Stopped | S::Absent | S::Detected)
        }
        DesiredStatus::Bound => matches!(status, S::Detected | S::Absent | S::Failed(_)),
        DesiredStatus::Stopped => matches!(status, S::Failed(_)),
        DesiredStatus::Absent => false,
    }
}

/// The desired predicate (§13 "Closed when").
pub fn satisfied(desired: DesiredStatus, status: &UnitStatus) -> bool {
    use UnitStatus as S;
    match desired {
        DesiredStatus::Running => matches!(status, S::Running),
        DesiredStatus::Bound => matches!(status, S::Bound | S::Running),
        DesiredStatus::Stopped => matches!(status, S::Stopped | S::Absent),
        DesiredStatus::Absent => matches!(status, S::Absent),
    }
}

/// Per-unit observation history. Not journaled: after a restart it is
/// re-learned within a few ticks, while the incidents themselves (budgets,
/// backoff, holds) come back from the journal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Track {
    divergent_ticks: u8,
    unknown_ticks: u8,
    satisfied_since: Option<Timestamp>,
    /// When the last incident on this target closed, and its regression count.
    last_closed: Option<(Timestamp, u8)>,
    /// When the unit went from fine to divergent, recently.
    failures: Vec<Timestamp>,
    was_divergent: bool,
    /// When the unit last came up (Running or Degraded: its process is active),
    /// or when Planarian started or restarted it; first sight counts as coming up.
    up_since: Option<Timestamp>,
    /// Degraded within its startup grace: not yet a fault.
    in_grace: bool,
}

#[derive(Clone, Debug)]
pub struct Manager {
    pub incidents: BTreeMap<IncidentId, Incident>,
    tracks: BTreeMap<UnitId, Track>,
    next_id: u64,
    /// How long after coming up a failing health probe is not yet a fault,
    /// for units that do not set their own (`UnitDef::startup_grace`).
    pub startup_grace: Millis,
}

/// The default startup grace (`services.planarian.startupGrace`).
pub const STARTUP_GRACE: Millis = Millis::secs(90);

impl Default for Manager {
    fn default() -> Manager {
        Manager::restore([])
    }
}

impl Manager {
    /// Rebuild from the incidents the journal holds (open and cooling ones).
    pub fn restore(incidents: impl IntoIterator<Item = Incident>) -> Manager {
        let incidents: BTreeMap<IncidentId, Incident> = incidents.into_iter().map(|i| (i.id, i)).collect();
        let next_id = incidents.keys().map(|i| i.0).max().unwrap_or(0);
        Manager { incidents, tracks: BTreeMap::new(), next_id, startup_grace: STARTUP_GRACE }
    }

    /// Planarian (or a user through it) just started or restarted `unit`:
    /// its startup grace begins again.
    pub fn started(&mut self, unit: &UnitId, now: Timestamp) {
        self.tracks.entry(unit.clone()).or_default().up_since = Some(now);
    }

    pub fn active_for(&self, unit: &UnitId) -> Option<&Incident> {
        self.incidents.values().find(|i| &i.target == unit && i.state != IncidentState::Closed)
    }

    fn active_id(&self, unit: &UnitId) -> Option<IncidentId> {
        self.active_for(unit).map(|i| i.id)
    }

    fn close(&mut self, id: IncidentId, now: Timestamp, changed: &mut Vec<Incident>) {
        if let Some(mut i) = self.incidents.remove(&id) {
            if i.kind == IncidentKind::Repair {
                self.tracks.entry(i.target.clone()).or_default().last_closed = Some((now, i.regressions));
            }
            i.state = IncidentState::Closed;
            changed.push(i);
        }
    }

    /// Observe one tick. Returns every incident that opened, changed or closed.
    pub fn tick(&mut self, now: Timestamp, state: &SystemState, defs: &UnitDefs) -> Vec<Incident> {
        let mut changed = vec![];

        // Targets that left the definitions close.
        let gone: Vec<IncidentId> =
            self.incidents.values().filter(|i| !defs.contains_key(&i.target)).map(|i| i.id).collect();
        for id in gone {
            self.close(id, now, &mut changed);
        }

        // Holds that ended.
        for i in self.incidents.values_mut() {
            match i.state {
                IncidentState::Cooldown { until } | IncidentState::Escalated { until } if now >= until => {
                    i.state = IncidentState::Open;
                    i.budget_left = 1;
                    i.next_attempt = now;
                    changed.push(i.clone());
                }
                _ => {}
            }
        }

        for (id, def) in defs {
            let status = state.status(id, defs);
            let desired = def.desired.status;
            let active = self.active_id(id);

            if status == UnitStatus::Suppressed || status == UnitStatus::NotExpected {
                // A suppression closes the incident (I13); so does a condition
                // that stopped holding (logout, unplug).
                if let Some(a) = active {
                    self.close(a, now, &mut changed);
                }
                let t = self.tracks.entry(id.clone()).or_default();
                (t.divergent_ticks, t.unknown_ticks, t.satisfied_since, t.was_divergent) = (0, 0, None, false);
                continue;
            }

            if status == UnitStatus::Unknown {
                let t = self.tracks.entry(id.clone()).or_default();
                t.unknown_ticks = t.unknown_ticks.saturating_add(1);
                t.divergent_ticks = 0;
                t.satisfied_since = None;
                if t.unknown_ticks >= UNKNOWN_LIMIT && active.is_none() {
                    let inc = self.open(id, IncidentKind::Diagnostic, (desired, status), now, now, 0);
                    changed.push(inc);
                }
                continue;
            }

            // Startup grace: a unit whose process is up but whose health probe
            // fails may still be starting. A crash (Failed) gets no grace.
            {
                let t = self.tracks.entry(id.clone()).or_default();
                if matches!(status, UnitStatus::Running | UnitStatus::Degraded(_)) {
                    t.up_since.get_or_insert(now);
                } else {
                    t.up_since = None;
                }
                let grace = def.startup_grace.unwrap_or(self.startup_grace);
                t.in_grace = matches!(status, UnitStatus::Degraded(_))
                    && t.up_since.is_some_and(|since| now.0.saturating_sub(since.0) < grace.0);
                if t.in_grace {
                    (t.divergent_ticks, t.unknown_ticks, t.satisfied_since) = (0, 0, None);
                    continue;
                }
            }

            if divergent(desired, &status) {
                let t = self.tracks.entry(id.clone()).or_default();
                t.unknown_ticks = 0;
                t.satisfied_since = None;
                t.divergent_ticks = t.divergent_ticks.saturating_add(1);
                if !t.was_divergent {
                    t.was_divergent = true;
                    t.failures.push(now);
                }
                t.failures.retain(|f| now.0.saturating_sub(f.0) <= FAILURE_WINDOW.0);
                let ready = t.divergent_ticks >= OPEN_AFTER;
                let recent_failures = t.failures.len() as u32;
                let last_closed = t.last_closed;

                if let Some(a) = active {
                    let inc = self.incidents.get_mut(&a).expect("active");
                    if inc.kind == IncidentKind::Diagnostic {
                        // The evidence turned definite: this is a repair incident now.
                        inc.kind = IncidentKind::Repair;
                        inc.budget_left = BUDGET;
                        inc.next_attempt = now;
                    }
                    if inc.divergence.1 != status {
                        inc.divergence = (desired, status.clone());
                        changed.push(inc.clone());
                    }
                    continue;
                }
                if !ready {
                    continue;
                }
                // Defer to systemd while it is within its own start limit (§13).
                let next_attempt = match &def.systemd_restart {
                    Some(p) if p.restart && recent_failures <= p.start_limit_burst => {
                        now.plus(Millis(p.restart_sec.0 + SETTLE.0))
                    }
                    _ => now,
                };
                let regressions = match last_closed {
                    Some((closed, n)) if now.0.saturating_sub(closed.0) <= REGRESSION_WINDOW.0 => n + 1,
                    _ => 0,
                };
                let mut inc = self.open(id, IncidentKind::Repair, (desired, status), now, next_attempt, regressions);
                if regressions >= ESCALATE_AT {
                    inc.state = IncidentState::Escalated { until: now.plus(COOLDOWN_FIRST) };
                } else if regressions > 0 {
                    inc.state = IncidentState::Regressed { count: regressions };
                }
                self.incidents.insert(inc.id, inc.clone());
                changed.push(inc);
                continue;
            }

            let t = self.tracks.entry(id.clone()).or_default();
            t.divergent_ticks = 0;
            t.unknown_ticks = 0;
            t.was_divergent = false;
            if satisfied(desired, &status) {
                let since = *t.satisfied_since.get_or_insert(now);
                if let Some(a) = active {
                    let kind = self.incidents[&a].kind;
                    if kind == IncidentKind::Diagnostic || now.0.saturating_sub(since.0) >= STABILIZATION.0 {
                        self.close(a, now, &mut changed);
                    }
                }
            } else {
                t.satisfied_since = None;
            }
        }
        changed
    }

    fn open(
        &mut self,
        target: &UnitId,
        kind: IncidentKind,
        divergence: (DesiredStatus, UnitStatus),
        now: Timestamp,
        next_attempt: Timestamp,
        regressions: u8,
    ) -> Incident {
        self.next_id += 1;
        let inc = Incident {
            id: IncidentId(self.next_id),
            kind,
            target: target.clone(),
            divergence,
            opened: now,
            attempts: vec![],
            budget_left: if kind == IncidentKind::Repair { BUDGET } else { 0 },
            state: IncidentState::Open,
            backoff: BACKOFF[0],
            next_attempt,
            regressions,
        };
        self.incidents.insert(inc.id, inc.clone());
        inc
    }

    /// Repair incidents the diagnoser may act on now. An incident whose target
    /// currently meets its desired state is stabilizing, not actionable: acting
    /// on it would find nothing to do and wrongly exhaust it.
    pub fn actionable(&self, now: Timestamp) -> Vec<&Incident> {
        self.incidents
            .values()
            .filter(|i| {
                i.kind == IncidentKind::Repair
                    && matches!(i.state, IncidentState::Open | IncidentState::Regressed { .. })
                    && i.budget_left > 0
                    && now >= i.next_attempt
                    && self.tracks.get(&i.target).is_none_or(|t| t.satisfied_since.is_none() && !t.in_grace)
            })
            .collect()
    }

    /// Diagnostic incidents (re-observe through another Readiness probe).
    pub fn diagnostic(&self) -> Vec<&Incident> {
        self.incidents.values().filter(|i| i.kind == IncidentKind::Diagnostic).collect()
    }

    /// Record an attempt's transaction. Spends budget, sets the next backoff
    /// (longer after regressions), and enters cooldown when the budget is gone.
    pub fn record_attempt(&mut self, id: IncidentId, txn: TxnId, outcome: Outcome, now: Timestamp) -> Option<Incident> {
        let i = self.incidents.get_mut(&id)?;
        i.attempts.push((txn, outcome));
        i.budget_left = i.budget_left.saturating_sub(1);
        let step = (BUDGET - i.budget_left - 1) as usize + i.regressions as usize;
        i.backoff = BACKOFF[step.min(BACKOFF.len() - 1)];
        i.next_attempt = now.plus(i.backoff);
        if i.budget_left == 0 {
            Self::cool(i, now);
        }
        Some(i.clone())
    }

    fn cool(i: &mut Incident, now: Timestamp) {
        // The first cooldown is 1 h; once the budget has been spent before
        // (the post-cooldown attempt failed too, or the diagnoser exhausted
        // again), 6 h.
        let cooled_before = i.attempts.len() > BUDGET as usize || i.backoff.0 >= COOLDOWN_FIRST.0;
        let d = if cooled_before { COOLDOWN_LATER } else { COOLDOWN_FIRST };
        i.backoff = d;
        i.state = IncidentState::Cooldown { until: now.plus(d) };
    }

    /// The diagnoser found nothing (A: report to the user). The incident goes
    /// quiet with a cooldown rather than retrying forever (§1 step 4).
    pub fn exhausted(&mut self, id: IncidentId, now: Timestamp) -> Option<Incident> {
        let i = self.incidents.get_mut(&id)?;
        Self::cool(i, now);
        Some(i.clone())
    }

    /// A human acted on the target (unsuppress, explicit request): lift any hold.
    pub fn human_acted(&mut self, target: &UnitId, now: Timestamp) -> Option<Incident> {
        let i = self.incidents.values_mut().find(|i| &i.target == target)?;
        i.state = IncidentState::Open;
        i.budget_left = i.budget_left.max(1);
        i.next_attempt = now;
        Some(i.clone())
    }
}

#[cfg(test)]
mod tests;
