//! What the indicator shows: one level and one line, from the daemon's
//! console report. "Needs attention" is `ConsoleReport::needs_attention`,
//! the same condition that makes the console start visible.

use planarian_ipc::{ConsoleReport, status_words};
use planarian_schema::IncidentState;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing needs you.
    Ok,
    /// A change is being built or applied.
    Working,
    /// Something needs a look: an incident being repaired, an approval, a reverted change.
    Attention,
    /// Something needs a person: escalated, cooling down after failed repairs,
    /// the recovery interlock, or the daemon cannot be reached.
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub level: Level,
    /// One line for the tooltip and the menu.
    pub line: String,
}

/// The indicator's state from the last answer (or the error reaching the daemon).
pub fn classify(report: Result<&ConsoleReport, &str>) -> Summary {
    let r = match report {
        Ok(r) => r,
        Err(e) => return Summary { level: Level::Fault, line: format!("can't reach planariad ({e})") },
    };
    let s = &r.status;
    if let Some((t, why)) = s.interlock.first() {
        return Summary {
            level: Level::Fault,
            line: format!("recovery failed (transaction {}): {why}; automatic repair is stopped", t.0),
        };
    }
    let held = s
        .incidents
        .iter()
        .find(|i| matches!(i.state, IncidentState::Escalated { .. } | IncidentState::Cooldown { .. }));
    if let Some(i) = held {
        return Summary {
            level: Level::Fault,
            line: format!("{} needs a person: {}", i.target, status_words(&i.divergence.1)),
        };
    }
    if r.needs_attention() {
        let line = if let Some(p) = s.pending.first() {
            format!("waiting for your approval: {}", p.what)
        } else if let Some(i) = s.incidents.iter().find(|i| i.state != IncidentState::Closed) {
            format!("{}: {}; repairing", i.target, status_words(&i.divergence.1))
        } else if r.last_change_reverted {
            "the last configuration change was reverted".into()
        } else if let Some(rec) = s.reconciliation.as_ref().filter(|a| !a.is_empty()) {
            format!("after the last restart: {}", rec.join("; "))
        } else {
            "something needs a look".into()
        };
        return Summary { level: Level::Attention, line };
    }
    let busy = s.notices.iter().find(|n| n.starts_with("building ") || n.starts_with("busy with "));
    if let Some(n) = busy {
        // "busy with … for 3 min: this is how things stood …" → the part before the colon.
        let line = if n.starts_with("busy with ") { n.split(':').next().unwrap_or(n) } else { n };
        return Summary { level: Level::Working, line: line.to_string() };
    }
    if let Some((t, _, what)) = s.in_flight.first() {
        return Summary { level: Level::Working, line: format!("working on #{}: {what}", t.0) };
    }
    let line = match &s.baseline_note {
        Some(_) => "all healthy (no baseline yet)".to_string(),
        None => "all healthy".to_string(),
    };
    Summary { level: Level::Ok, line }
}

#[cfg(test)]
mod tests {
    use super::*;
    use planarian_ipc::{Pending, StatusReport};
    use planarian_schema::*;

    fn report() -> ConsoleReport {
        let status: StatusReport = serde_json::from_value(serde_json::json!({
            "generation": 1, "known_good": 1, "live_tested": null, "accepted_baseline": null,
            "boot_default": 1, "baseline_note": null, "units": [], "incidents": [], "pending": [],
            "in_flight": [], "interlock": [], "reconciliation": null, "notices": []
        }))
        .unwrap();
        ConsoleReport {
            status,
            nodes: vec![],
            edges: vec![],
            timeline: vec![],
            previous: None,
            last_booted: Some(GenerationId(1)),
            candidates: vec![],
            last_change_reverted: false,
            now: Timestamp(0),
        }
    }

    fn incident(state: IncidentState) -> Incident {
        Incident {
            id: IncidentId(1),
            kind: IncidentKind::Repair,
            target: UnitId::service("gym-state"),
            divergence: (DesiredStatus::Running, UnitStatus::Failed(Reason::ExitCode(1))),
            opened: Timestamp(0),
            attempts: vec![],
            budget_left: 3,
            state,
            backoff: Millis::secs(10),
            next_attempt: Timestamp(0),
            regressions: 0,
        }
    }

    #[test]
    fn healthy_is_ok_and_says_so() {
        let r = report();
        assert_eq!(classify(Ok(&r)), Summary { level: Level::Ok, line: "all healthy".into() });
        let mut r = report();
        r.status.baseline_note = Some("no baseline yet: …".into());
        let s = classify(Ok(&r));
        assert_eq!(s.level, Level::Ok, "the first 10 minutes are not a problem");
        assert!(s.line.contains("no baseline yet"));
    }

    #[test]
    fn an_incident_being_repaired_is_attention_and_a_held_one_is_a_fault() {
        let mut r = report();
        r.status.incidents.push(incident(IncidentState::Open));
        let s = classify(Ok(&r));
        assert_eq!(s.level, Level::Attention);
        assert_eq!(s.line, "service:gym-state: failed (exit code 1); repairing");
        r.status.incidents[0].state = IncidentState::Cooldown { until: Timestamp(60_000) };
        let s = classify(Ok(&r));
        assert_eq!(s.level, Level::Fault);
        assert_eq!(s.line, "service:gym-state needs a person: failed (exit code 1)");
    }

    #[test]
    fn approvals_reverts_and_the_interlock() {
        let mut r = report();
        r.status.pending.push(Pending {
            txn: TxnId(4),
            approve: Hash::ZERO,
            what: "apply service-enable service=sshd enabled=false".into(),
            facts: DerivedFacts {
                affected_units: vec![],
                sensitivity: Sensitivities::default(),
                disruption: Disruption::Brief,
                recovery: Recovery::Revertible,
                touches_manifest: false,
                touches_canonical_probe: false,
                changes_desired: true,
                below_security_floor: false,
                restores_unattributed_stop: false,
                other_sessions_affected: false,
                affected_sessions: Vec::new(),
                touches_core: false,
                caller: Actor::user(1000),
                config_diff: None,
            },
            issued: Timestamp(0),
        });
        assert_eq!(classify(Ok(&r)).line, "waiting for your approval: apply service-enable service=sshd enabled=false");
        let mut r = report();
        r.last_change_reverted = true;
        assert_eq!(classify(Ok(&r)).level, Level::Attention);
        r.status.interlock.push((TxnId(7), "revert failed".into()));
        assert_eq!(classify(Ok(&r)).level, Level::Fault);
    }

    #[test]
    fn building_is_working_and_an_unreachable_daemon_is_a_fault() {
        let mut r = report();
        r.status.notices.push("building apply font-scale scale=1.25 (3 min so far); repairs go on meanwhile".into());
        let s = classify(Ok(&r));
        assert_eq!(s.level, Level::Working);
        assert_eq!(s.line, "building apply font-scale scale=1.25 (3 min so far); repairs go on meanwhile");
        r.status.notices[0] =
            "busy with the change font-scale for 3 min: this is how things stood when it started".into();
        assert_eq!(classify(Ok(&r)).line, "busy with the change font-scale for 3 min");
        assert_eq!(classify(Err("connection refused")).level, Level::Fault);
    }

    #[test]
    fn the_tray_and_the_console_agree() {
        // Attention or Fault exactly when the console would start visible.
        let changes: [fn(&mut ConsoleReport); 3] = [
            |r| r.last_change_reverted = true,
            |r| r.status.reconciliation = Some(vec!["finished it: Committed".into()]),
            |r| r.status.incidents.push(incident(IncidentState::Open)),
        ];
        for f in changes {
            let mut r = report();
            assert!(classify(Ok(&r)).level < Level::Attention && !r.needs_attention());
            f(&mut r);
            assert!(classify(Ok(&r)).level >= Level::Attention && r.needs_attention());
        }
    }
}
