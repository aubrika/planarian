//! Judging an entry's `required_post` (SPEC §15: on required_post and intent
//! cases, never on the absence of errors). Keys the fake harness cannot judge
//! are reported, and make the result PARTIAL rather than PASS.

use crate::evidence::Evidence;
use crate::sim::{dur, unit};
use planarian_exec::Submitted;
use planarian_ipc::Response;
use planarian_schema::*;
use planarian_txn::machine::tag;
use std::collections::BTreeMap;
use toml::Value as T;

#[derive(Debug, Default)]
pub struct Verdict {
    pub failures: Vec<String>,
    pub unchecked: Vec<String>,
}

fn transition_name(t: &Transition) -> &'static str {
    match t {
        Transition::RestartUnit(_) => "RestartUnit",
        Transition::StopUnit(_) => "StopUnit",
        Transition::BindDriver { .. } => "BindDriver",
        Transition::ApplyChange { .. } => "ApplyChange",
        Transition::SwitchGeneration(_) => "SwitchGeneration",
        Transition::Revert { .. } => "Revert",
        Transition::Rollback => "Rollback",
        Transition::LoadModel(_) => "LoadModel",
        Transition::RestoreSnapshot(_) => "RestoreSnapshot",
        Transition::CollectGarbage { .. } => "CollectGarbage",
        Transition::SetRuntimeOption { .. } => "SetRuntimeOption",
        Transition::Suppress(_) => "Suppress",
        Transition::Unsuppress(_) => "Unsuppress",
        Transition::StopAndSuppress { .. } => "StopAndSuppress",
        Transition::Resolve { .. } => "Resolve",
    }
}

fn target_of(t: &Transition) -> Option<UnitId> {
    match t {
        Transition::RestartUnit(u) | Transition::StopUnit(u) | Transition::Unsuppress(u) => Some(u.clone()),
        Transition::BindDriver { device, .. } => Some(device.clone()),
        Transition::StopAndSuppress { unit, .. } => Some(unit.clone()),
        Transition::Suppress(s) => Some(s.unit.clone()),
        _ => None,
    }
}

fn state_name(s: &TxnState) -> String {
    match s {
        TxnState::Rejected(r) => format!("Rejected({r:?})"),
        s => tag(s).to_string(),
    }
}

struct TxnView {
    transition: Transition,
    path: Vec<String>,
    state: TxnState,
    watchdog: bool,
    epoch: u64,
}

fn txns(e: &Evidence) -> Vec<TxnView> {
    let l = &e.ledger;
    l.terminal
        .values()
        .map(|t| TxnView {
            transition: t.transition.clone(),
            path: t.path.clone(),
            state: t.state.clone(),
            watchdog: t.owner.is_watchdog(),
            epoch: t.epoch,
        })
        .chain(l.live.values().map(|t| TxnView {
            transition: t.txn.transition.clone(),
            path: t.path.clone(),
            state: t.txn.state.clone(),
            watchdog: t.txn.lease.owner.is_watchdog(),
            epoch: t.txn.lease.epoch,
        }))
        .collect()
}

fn gen_named(e: &Evidence, name: &str) -> Option<GenerationId> {
    match name {
        "base" | "known_good" | "unchanged" => Some(e.base),
        "candidate" => e.candidate,
        "owner-built" => None,
        _ => None,
    }
}

fn subsequence(path: &[String], want: &[String]) -> bool {
    let mut it = path.iter();
    want.iter().all(|w| it.any(|p| p == w))
}

pub fn judge(e: &Evidence, post: &T) -> Verdict {
    let mut v = Verdict::default();
    let Some(post) = post.as_table() else { return v };
    let current = e.current;
    let boot = e.boot_default;
    let overrides_empty = e.overrides_empty;
    let ledger = &e.ledger;
    let all = txns(e);
    let finals = &e.finals;
    let may_change: Vec<UnitId> =
        post.get("may_change").and_then(T::as_array).into_iter().flatten().filter_map(T::as_str).map(unit).collect();

    for (key, val) in post {
        let fail = |v: &mut Verdict, m: String| v.failures.push(format!("{key}: {m}"));
        match key.as_str() {
            "units" => {
                for (u, want) in val.as_table().into_iter().flatten() {
                    let got = finals.get(&unit(u)).cloned().unwrap_or_else(|| "undefined".into());
                    if got != want.as_str().unwrap_or("") {
                        fail(&mut v, format!("{u} is {got}, want {want}"));
                    }
                }
            }
            // Bounds for others_unchanged; settle is timing only.
            "may_change" | "settle" => {}
            "others_unchanged" if val.as_bool() == Some(true) => {
                let named: Vec<UnitId> =
                    post.get("units").and_then(T::as_table).into_iter().flatten().map(|(k, _)| unit(k)).collect();
                for (u, before) in &e.pre_status {
                    if before != "Running" || may_change.contains(u) || named.contains(u) || e.touched.contains(u) {
                        continue;
                    }
                    let after = finals.get(u).cloned().unwrap_or_default();
                    if after != "Running" {
                        fail(&mut v, format!("{u} was Running and is now {after}"));
                    }
                }
            }
            "others_unchanged" => {}
            // The ledger refuses any record that would break I6, I12's paths or
            // I15, so a journal that replays cleanly is the check.
            "invariants" => {
                if !e.journal_replays {
                    fail(&mut v, "the journal does not replay".into());
                }
            }
            "generation" | "boot_default" => {
                let have = if key == "generation" { current } else { boot };
                match val.as_str() {
                    Some("owner-built") => {
                        if have == e.base {
                            fail(&mut v, "expected the owner's own generation".into());
                        }
                    }
                    Some(name) => match gen_named(e, name) {
                        Some(g) if g == have => {}
                        Some(g) => fail(&mut v, format!("is {}, want {name} ({})", have.0, g.0)),
                        None => fail(&mut v, format!("no {name} generation")),
                    },
                    None => v.unchecked.push(key.clone()),
                }
            }
            "override_source" => {
                let want_empty = matches!(val.as_str(), Some("base" | "known_good"));
                if overrides_empty != want_empty {
                    fail(
                        &mut v,
                        format!("override file is {}", if overrides_empty { "the base" } else { "the candidate" }),
                    );
                }
            }
            "known_good" => {
                if ledger.known_good != Some(e.base) {
                    fail(&mut v, format!("{:?}", ledger.known_good));
                }
            }
            "live_tested" => {
                if ledger.live_tested.is_none() || ledger.live_tested != e.candidate {
                    fail(&mut v, format!("{:?} vs candidate {:?}", ledger.live_tested, e.candidate));
                }
            }
            "journal_agrees" => {
                if current != boot {
                    fail(&mut v, format!("running {} but boot default {}", current.0, boot.0));
                }
                if ledger.live.values().any(|t| !t.txn.state.is_pre_mutation()) {
                    fail(&mut v, "a transaction is still in flight".into());
                }
            }
            "interlock" => {
                let set = ledger.interlocked();
                if set != (val.as_str() == Some("set")) {
                    fail(&mut v, format!("interlock is {}", if set { "set" } else { "clear" }));
                }
            }
            "suppressions" => {
                let want: Vec<(String, String)> = val
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|s| {
                        (
                            s.get("unit").and_then(T::as_str).unwrap_or("").to_string(),
                            s.get("until").and_then(T::as_str).unwrap_or("").to_string(),
                        )
                    })
                    .collect();
                let have: Vec<(String, String)> = ledger
                    .suppressions
                    .iter()
                    .map(|s| {
                        (
                            s.unit.to_string(),
                            match s.until {
                                Until::Explicit => "Explicit".into(),
                                Until::NextBoot => "NextBoot".into(),
                                Until::At(_) => "At".into(),
                            },
                        )
                    })
                    .collect();
                if want != have {
                    fail(&mut v, format!("have {have:?}, want {want:?}"));
                }
                for (s, w) in ledger.suppressions.iter().zip(val.as_array().into_iter().flatten()) {
                    if let Some(by) = w.get("by").and_then(T::as_str) {
                        let ok = matches!(&s.by, Actor::User { uid } if format!("user:{uid}") == by);
                        if !ok {
                            fail(&mut v, format!("{} suppressed by {:?}, want {by}", s.unit, s.by));
                        }
                    }
                }
            }
            "no_txn_on" => {
                for u in val.as_array().into_iter().flatten().filter_map(T::as_str) {
                    let id = unit(u);
                    if all.iter().any(|t| target_of(&t.transition).as_ref() == Some(&id)) {
                        fail(&mut v, format!("a transaction targeted {u}"));
                    }
                }
            }
            "no_autonomous_txn" => {
                let auto = e
                    .log
                    .iter()
                    .filter(|r| !matches!(r.caller, Actor::User { .. }))
                    .filter(|r| matches!(r.result, Submitted::Finished { .. } | Submitted::Parked { .. }))
                    .count();
                if auto > 0 {
                    fail(&mut v, format!("{auto} autonomous transaction(s)"));
                }
            }
            "no_incident_on" => {
                for u in val.as_array().into_iter().flatten().filter_map(T::as_str) {
                    let id = unit(u);
                    if e.seen_incidents.values().any(|i| i.target == id && i.kind == IncidentKind::Repair) {
                        fail(&mut v, format!("an incident opened on {u}"));
                    }
                }
            }
            "gc_protected" => {
                // I3: none of the named generations was collected.
                let previous = e.boot_entries.iter().copied().filter(|g| *g < current).max();
                for name in val.as_array().into_iter().flatten().filter_map(T::as_str) {
                    let gens: Vec<GenerationId> = match name {
                        "known_good" => ledger.known_good.into_iter().chain([e.boot_default]).collect(),
                        "base" => vec![current],
                        "previous" => previous.into_iter().collect(),
                        "candidate" => {
                            ledger.live.values().filter_map(|t| t.txn.candidate.as_ref().map(|(g, _)| *g)).collect()
                        }
                        other => {
                            v.unchecked.push(format!("gc_protected.{other}"));
                            continue;
                        }
                    };
                    if let Some(g) = gens.iter().find(|g| e.collected.contains(g)) {
                        fail(&mut v, format!("{name} generation {} was collected", g.0));
                    }
                }
            }
            "status_seen" | "status_never" => {
                for (u, names) in val.as_table().into_iter().flatten() {
                    let seen = e.seen_status.get(&unit(u)).cloned().unwrap_or_default();
                    for n in names.as_array().into_iter().flatten().filter_map(T::as_str) {
                        let has = seen.contains(n);
                        if key == "status_seen" && !has {
                            fail(&mut v, format!("{u} never showed {n} (saw {seen:?})"));
                        }
                        if key == "status_never" && has {
                            fail(&mut v, format!("{u} showed {n}"));
                        }
                    }
                }
            }
            "metrics" => {
                for (m, spec) in val.as_table().into_iter().flatten() {
                    match m.as_str() {
                        "restarts_max" => {
                            for (u, n) in spec.as_table().into_iter().flatten() {
                                let id = unit(u);
                                let count = e.restarts.get(&id).copied().unwrap_or(0);
                                if count > n.as_integer().unwrap_or(0) {
                                    fail(&mut v, format!("{u} restarted {count} times (max {n})"));
                                }
                            }
                        }
                        "incidents_max" => {
                            let n = e.seen_incidents.values().filter(|i| i.kind == IncidentKind::Repair).count() as i64;
                            if n > spec.as_integer().unwrap_or(0) {
                                fail(&mut v, format!("{n} incidents"));
                            }
                        }
                        "attempt_gaps_min" => {
                            // Backoff: the k-th gap between a repair incident's
                            // attempts is at least the k-th minimum.
                            let mins: Vec<Millis> = spec.as_array().into_iter().flatten().filter_map(dur).collect();
                            let at: BTreeMap<TxnId, Timestamp> = e
                                .log
                                .iter()
                                .filter_map(|r| match &r.result {
                                    Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } => {
                                        Some((*txn, r.at))
                                    }
                                    _ => None,
                                })
                                .collect();
                            for i in e.seen_incidents.values().filter(|i| i.kind == IncidentKind::Repair) {
                                let times: Vec<Timestamp> =
                                    i.attempts.iter().filter_map(|(t, _)| at.get(t).copied()).collect();
                                if times.len() < i.attempts.len() {
                                    v.unchecked.push(format!("metrics.attempt_gaps_min ({}: attempt times)", i.target));
                                    continue;
                                }
                                for (k, w) in times.windows(2).enumerate() {
                                    let gap = w[1].0.saturating_sub(w[0].0);
                                    if let Some(min) = mins.get(k).filter(|m| gap < m.0) {
                                        fail(
                                            &mut v,
                                            format!(
                                                "{}: attempts {} and {} {gap} ms apart (min {} ms)",
                                                i.target,
                                                k + 1,
                                                k + 2,
                                                min.0
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                        other => v.unchecked.push(format!("metrics.{other}")),
                    }
                }
            }
            "reports" => {
                for r in val.as_array().into_iter().flatten().filter_map(T::as_str) {
                    let notices = e.notices.join("\n");
                    let ok = match r {
                        "DiagnoserExhausted" => notices.contains("needs a person"),
                        "Flapping" | "Escalated" => {
                            notices.contains("needs a person") || notices.contains("keeps failing")
                        }
                        "Unauthorized" => e
                            .responses
                            .iter()
                            .any(|x| matches!(x, Response::Rejected { reason, .. } if reason == "Unauthorized")),
                        "RecoveryFailed" | "alert" => {
                            ledger.terminal.values().any(|t| t.state == TxnState::RecoveryFailed)
                        }
                        "NoSpace" => e
                            .responses
                            .iter()
                            .any(|x| matches!(x, Response::Rejected { reason, .. } if reason == "NoSpace")),
                        "StopRewrittenNotice" => e.responses.iter().any(
                            |x| matches!(x, Response::Done { message, .. } if message.contains("until the next boot")),
                        ),
                        "AwaitingApproval" => notices.contains("needs approval"),
                        "BudgetUnsatisfiable" => notices.contains("BudgetUnsatisfiable"),
                        _ => {
                            v.unchecked.push(format!("reports.{r}"));
                            continue;
                        }
                    };
                    if !ok {
                        fail(&mut v, format!("{r} was not reported"));
                    }
                }
            }
            "reconciliation" => {
                let text = ledger.last_reconciliation.as_ref().map(|r| r.actions.join("\n")).unwrap_or_default();
                if let Some(found) = val.get("found").and_then(T::as_str)
                    && !text.contains(&format!("finished it: {found}"))
                {
                    fail(&mut v, format!("record does not say the watchdog finished it as {found}: {text:?}"));
                }
                for token in val.get("explains").and_then(T::as_array).into_iter().flatten().filter_map(T::as_str) {
                    let ok = if let Some(state) = token.strip_prefix("killed-during-") {
                        text.contains(state)
                    } else if token == "watchdog-reverted" {
                        text.contains("watchdog") && text.contains("Reverted")
                    } else if let Some(u) = token.strip_prefix("probe-failed:") {
                        text.contains(u)
                    } else if let Some(w) = token.strip_prefix("why:") {
                        text.contains(&format!("because recovery: {w}")) || text.contains(&format!("because {w}"))
                    } else {
                        v.unchecked.push(format!("reconciliation.explains {token}"));
                        continue;
                    };
                    if !ok {
                        fail(&mut v, format!("the record does not explain {token}: {text:?}"));
                    }
                }
            }
            "txn" => {
                for spec in val.as_array().into_iter().flatten() {
                    check_txn(e, &all, spec, &mut v);
                }
            }
            "incident" => {
                for spec in val.as_array().into_iter().flatten() {
                    check_incident(e, spec, &mut v);
                }
            }
            other => v.unchecked.push(other.to_string()),
        }
    }
    v
}

fn check_txn(e: &Evidence, all: &[TxnView], spec: &T, v: &mut Verdict) {
    let s = |k: &str| spec.get(k).and_then(T::as_str);
    let mut matching: Vec<&TxnView> = all.iter().collect();
    if let Some(t) = s("transition") {
        matching.retain(|x| transition_name(&x.transition) == t);
    }
    if let Some(u) = s("target") {
        let id = unit(u);
        matching.retain(|x| target_of(&x.transition).as_ref() == Some(&id));
    }
    if let Some(c) = s("change") {
        matching.retain(|x| matches!(&x.transition, Transition::ApplyChange { change, .. } if change.0 == c));
    }
    let label = format!(
        "txn {}",
        spec.as_table()
            .map(|t| t.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
    );
    let count = spec.get("count").and_then(T::as_integer);
    if count == Some(0) {
        if spec.get("before_unit_running").is_some()
            || spec.get("while_interlock").is_some()
            || spec.get("while_incident").is_some()
        {
            v.unchecked.push(format!("{label} (conditional count)"));
        } else if !matching.is_empty() {
            v.failures.push(format!("{label}: expected none, found {}", matching.len()));
        }
        return;
    }
    if matching.is_empty() {
        // Refused before a transaction existed (authorization, catalog,
        // refinement, digest, stale source, no space): judged from the
        // executor log (I7), which records every proposal and its result.
        let wanted: Vec<String> = s("terminal")
            .map(|t| vec![t.to_string()])
            .or_else(|| {
                s("decision").filter(|d| d.starts_with("Reject")).map(|d| vec![d.replace("Reject(", "Rejected(")])
            })
            .or_else(|| {
                spec.get("decision_in")
                    .and_then(T::as_array)
                    .map(|a| a.iter().filter_map(T::as_str).map(|d| d.replace("Reject(", "Rejected(")).collect())
            })
            .unwrap_or_default();
        let refused = e.log.iter().any(|r| {
            s("transition").is_none_or(|t| transition_name(&r.proposal.transition) == t)
                && match &r.result {
                    Submitted::Rejected { reason, .. } => wanted.iter().any(|w| *w == format!("Rejected({reason:?})")),
                    _ => false,
                }
        });
        if !refused {
            v.failures.push(format!("{label}: no such transaction or refusal"));
        }
        return;
    }
    // Judge the most recent match.
    let t = matching.last().expect("non-empty");
    if let Some(want) = s("terminal") {
        let got = state_name(&t.state);
        if got != want {
            v.failures.push(format!("{label}: ended {got}"));
        }
    }
    if let Some(want) = s("terminal_prefix")
        && !state_name(&t.state).starts_with(want)
    {
        v.failures.push(format!("{label}: ended {}", state_name(&t.state)));
    }
    if let Some(path) = spec.get("path").and_then(T::as_array) {
        let want: Vec<String> = path.iter().filter_map(T::as_str).map(String::from).collect();
        if !subsequence(&t.path, &want) {
            v.failures.push(format!("{label}: path {:?} lacks {want:?}", t.path));
        }
    }
    if let Some(never) = spec.get("never").and_then(T::as_array) {
        for n in never.iter().filter_map(T::as_str) {
            if t.path.iter().any(|p| p == n) || state_name(&t.state) == n {
                v.failures.push(format!("{label}: went through {n}"));
            }
        }
    }
    if let Some(min) = spec.get("lease_epoch_min").and_then(T::as_integer)
        && (t.epoch as i64) < min
    {
        v.failures.push(format!("{label}: epoch {} < {min}", t.epoch));
    }
    if let Some(src) = s("source") {
        let target = target_of(&t.transition);
        let found = e.log.iter().any(|r| {
            transition_name(&r.proposal.transition) == transition_name(&t.transition)
                && target_of(&r.proposal.transition) == target
                && match &r.proposal.source {
                    Source::Diagnoser { .. } => src == "diagnoser",
                    Source::User => src == "user",
                    Source::Intent { .. } => src == "intent",
                    Source::Model(_) => src == "model",
                    Source::Maintenance => src == "maintenance",
                }
        });
        if !found {
            v.failures.push(format!("{label}: not proposed by {src}"));
        }
    }
    if s("owner") == Some("watchdog") && !t.watchdog {
        v.failures.push(format!("{label}: not finished by the watchdog"));
    }
    if let Some(r) = s("recovery")
        && format!("{:?}", t.transition.recovery()) != r
    {
        v.failures.push(format!("{label}: recovery {:?}", t.transition.recovery()));
    }
    match s("decision") {
        Some("Allow(AskFirst)") => {
            let parked = e.log.iter().any(|r| {
                transition_name(&r.proposal.transition) == transition_name(&t.transition)
                    && matches!(r.result, Submitted::Parked { .. })
            });
            if !parked {
                v.failures.push(format!("{label}: never asked for approval"));
            }
        }
        Some(d) if d.starts_with("Allow(") => {
            let parked = e.log.iter().any(|r| {
                transition_name(&r.proposal.transition) == transition_name(&t.transition)
                    && matches!(r.result, Submitted::Parked { .. })
            });
            if parked {
                v.failures.push(format!("{label}: asked for approval, want {d}"));
            }
        }
        Some(d) => v.unchecked.push(format!("{label}: decision {d}")),
        None => {}
    }
    for k in [
        "facts",
        "args",
        "not_activated_before",
        "path_option",
        "returns_current_digest",
        "reject_detail",
        "decision_in",
        "decision_not_below",
        "emergency",
    ] {
        if spec.get(k).is_some() {
            v.unchecked.push(format!("{label}: {k}"));
        }
    }
}

fn check_incident(e: &Evidence, spec: &T, v: &mut Verdict) {
    let Some(target) = spec.get("target").and_then(T::as_str) else { return };
    let id = unit(target);
    let label = format!("incident on {target}");
    let found: Vec<&Incident> = e.seen_incidents.values().filter(|i| i.target == id).collect();
    let Some(last) = found.last() else {
        v.failures.push(format!("{label}: none opened"));
        return;
    };
    if let Some(state) = spec.get("state").and_then(T::as_str) {
        let current = e.open_incidents.get(&id).cloned();
        let got = match &current {
            None => "Closed".to_string(),
            Some(i) => format!("{:?}", i.state).split([' ', '{', '(']).next().unwrap_or("").to_string(),
        };
        if got != state {
            v.failures.push(format!("{label}: is {got}, want {state}"));
        }
    }
    if let Some(n) = spec.get("regressed_count").and_then(T::as_integer)
        && found.iter().map(|i| i.regressions as i64).max().unwrap_or(0) < n
    {
        v.failures.push(format!("{label}: regressions below {n}"));
    }
    if let Some(n) = spec.get("budget_left").and_then(T::as_integer)
        && last.budget_left as i64 != n
    {
        v.failures.push(format!("{label}: budget {}", last.budget_left));
    }
    if let Some(k) = spec.get("kind").and_then(T::as_str) {
        let want = if k == "diagnostic" { IncidentKind::Diagnostic } else { IncidentKind::Repair };
        if !found.iter().any(|i| i.kind == want) {
            v.failures.push(format!("{label}: no {k} incident"));
        }
    }
    if let Some(w) = spec.get("opened_within").and_then(T::as_str) {
        let limit = w.trim_end_matches('s').parse::<u64>().unwrap_or(0) * 1000;
        let at = e.first_incident_at.get(&id).copied().unwrap_or(Timestamp(u64::MAX));
        if at.0.saturating_sub(e.start.0) > limit + 60_000 {
            v.unchecked.push(format!("{label}: opened_within (relative to inject)"));
        }
    }
    for k in ["root_of", "first_candidate", "session_bound"] {
        if spec.get(k).is_some() {
            v.unchecked.push(format!("{label}: {k}"));
        }
    }
}
