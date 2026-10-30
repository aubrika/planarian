//! Judging an entry's `required_post` (SPEC §15: on required_post and intent
//! cases, never on the absence of errors). Keys the fake harness cannot judge
//! are reported, and make the result PARTIAL rather than PASS.

use crate::evidence::{Effect, Evidence};
use crate::sim::{dur, unit};
use planarian_exec::Submitted;
use planarian_ipc::Response;
use planarian_schema::*;
use planarian_txn::ledger::{Entry, Record};
use planarian_txn::machine::tag;
use std::collections::{BTreeMap, BTreeSet};
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
        Transition::SetOverride(_) => "SetOverride",
        Transition::LiftOverride(_) => "LiftOverride",
        Transition::StopAndSuppress { .. } => "StopAndSuppress",
        Transition::Resolve { .. } => "Resolve",
    }
}

fn target_of(t: &Transition) -> Option<UnitId> {
    match t {
        Transition::RestartUnit(u) | Transition::StopUnit(u) | Transition::LiftOverride(u) => Some(u.clone()),
        Transition::BindDriver { device, .. } => Some(device.clone()),
        Transition::StopAndSuppress { unit, .. } => Some(unit.clone()),
        Transition::SetOverride(s) => Some(s.unit.clone()),
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
    id: TxnId,
    transition: Transition,
    path: Vec<String>,
    state: TxnState,
    watchdog: bool,
    epoch: u64,
}

fn txns(e: &Evidence) -> Vec<TxnView> {
    let l = &e.ledger;
    l.terminal
        .iter()
        .map(|(id, t)| TxnView {
            id: *id,
            transition: t.transition.clone(),
            path: t.path.clone(),
            state: t.state.clone(),
            watchdog: t.owner.is_watchdog(),
            epoch: t.epoch,
        })
        .chain(l.live.values().map(|t| TxnView {
            id: t.txn.id,
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

/// A catalog unit name matches a unit the run saw: the same unit, or, for a
/// system-scope name of a session-bound unit (`target:graphical-session`),
/// any session's instance of it (§9).
pub fn same_unit(spec: &UnitId, seen: &UnitId) -> bool {
    spec == seen
        || (spec.scope == Scope::System
            && spec.kind == seen.kind
            && spec.name == seen.name
            && matches!(seen.scope, Scope::User { session: Some(_), .. }))
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

    // Every unit the machine showed. A key naming any other unit would hold
    // vacuously, so naming one is a failure of the entry itself.
    let known: BTreeSet<&UnitId> = e.pre_status.keys().chain(e.finals.keys()).chain(e.seen_status.keys()).collect();
    let unknown = |u: &str| !known.is_empty() && !known.iter().any(|k| same_unit(&unit(u), k));
    // Gamed success (§15): an override set by the daemon, the watchdog, the
    // model or an agent; an Unattributed (inferred) one only where the entry
    // declares it.
    let declares_inferred = post
        .get("overrides")
        .and_then(T::as_array)
        .is_some_and(|a| a.iter().any(|o| o.get("by").and_then(T::as_str) == Some("Unattributed")));
    for o in &ledger.overrides {
        let ok = match &o.by {
            Actor::User { .. } => o.attribution == Attribution::Attested,
            Actor::Unattributed => o.attribution == Attribution::Inferred && declares_inferred,
            _ => false,
        };
        if !ok {
            v.failures.push(format!("gamed success: {} overridden by {:?} ({:?})", o.unit, o.by, o.attribution));
        }
    }
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
            // I18 entries edit the journal on purpose: there the check is that
            // the chain refuses to open, not that it replays.
            "invariants" | "journal_readable" => {
                let i18 = val.as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some("I18")));
                if i18 && e.posture.chain_broken {
                    if !e.posture.finding.as_deref().is_some_and(|f| f.contains("journal")) {
                        fail(&mut v, "the chain is broken but planariad did not report it".into());
                    }
                } else if !e.journal_replays {
                    fail(&mut v, "the journal does not replay".into());
                }
            }
            // §15: the incident report names where a declaration came from:
            // who, through what, in which file, and when.
            "declaration_origin" => {
                let name = unit(val.get("unit").and_then(T::as_str).unwrap_or("")).name;
                let target = post
                    .get("incident")
                    .and_then(T::as_array)
                    .and_then(|a| a.first())
                    .and_then(|i| i.get("target"))
                    .and_then(T::as_str)
                    .unwrap_or("");
                let decl = format!("service:{name} is new in generation");
                let report = e.notices.iter().find(|n| n.starts_with(target) && n.contains(&decl));
                let Some(report) = report else {
                    fail(&mut v, format!("no incident report on {target} names service:{name}'s declaration"));
                    continue;
                };
                let mut want: Vec<String> = vec![];
                match val.get("who").and_then(T::as_str) {
                    Some("root") => want.push("by root".into()),
                    Some(u) => want.push(format!("by uid {}", u.trim_start_matches("user:"))),
                    None => {}
                }
                match val.get("path").and_then(T::as_str) {
                    Some(p) if p.starts_with("ApplyChange ") => {
                        want.push(format!("through apply {}", p.trim_start_matches("ApplyChange ")))
                    }
                    Some(p) => want.push(p.to_string()),
                    None => {}
                }
                match val.get("file").and_then(T::as_str) {
                    // The owner's own file: whatever NixOS records as its definition.
                    Some(f) if f.starts_with("owner:") => want.push("defined in /".into()),
                    Some(f) => want.push(f.to_string()),
                    None => {}
                }
                match val.get("when").and_then(T::as_str) {
                    Some("generation-created") => want.push("generation created at".into()),
                    Some("txn") => want.push("(transaction ".into()),
                    _ => {}
                }
                // The input's lock change: its previous and new revision.
                if val.get("lock_change").and_then(T::as_bool) == Some(true) && !report.contains(" → ") {
                    fail(&mut v, format!("the report does not give the input's lock change: {report}"));
                }
                for w in want.iter().filter(|w| !report.contains(w.as_str())) {
                    fail(&mut v, format!("the report does not say {w:?}: {report}"));
                }
            }
            // I20: these agents never ran while a failure class was raised
            // (the posture samples; VM only), and were stopped by it.
            "not_started" | "unit_after_failure" => match &e.posture.responses {
                None => v.unchecked.push(format!("{key} (systemd's; the VM harness observes it)")),
                Some(seen) => {
                    if key == "not_started" && seen.contains("agents_running") {
                        fail(&mut v, "an agent ran while Planarian was failed".into());
                    }
                    if key == "unit_after_failure" && !seen.contains("disable_agents") {
                        fail(&mut v, "the agents were not stopped".into());
                    }
                }
            },
            // §12d: the failure class reached, the posture target, and (VM only)
            // the responses systemd applied.
            "posture" => {
                let class = val.get("class").and_then(T::as_str).unwrap_or("").to_lowercase();
                if !e.posture.classes.contains(&class) {
                    fail(&mut v, format!("class {class} not reached (reached: {:?})", e.posture.classes));
                }
                if let Some(t) = val.get("target_reached").and_then(T::as_str)
                    && t.to_lowercase() != format!("planarian-failed@{class}.target")
                {
                    fail(&mut v, format!("{t} is not the target for class {class}"));
                }
                let want: Vec<&str> =
                    val.get("responses").and_then(T::as_array).into_iter().flatten().filter_map(T::as_str).collect();
                let not: Vec<&str> =
                    val.get("not").and_then(T::as_array).into_iter().flatten().filter_map(T::as_str).collect();
                match &e.posture.responses {
                    None if want.is_empty() && not.is_empty() => {}
                    None => v.unchecked.push("posture.responses (systemd's; the VM harness observes them)".into()),
                    Some(seen) => {
                        for r in want.iter().filter(|r| !seen.contains(**r)) {
                            fail(&mut v, format!("response {r} not applied"));
                        }
                        for r in not.iter().filter(|r| seen.contains(**r)) {
                            fail(&mut v, format!("response {r} applied, must not be"));
                        }
                    }
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
            // §12e: the floor names this generation ("none" if unset).
            "security_floor" => {
                let want = match val.as_str() {
                    Some("none" | "unchanged") => None,
                    Some(name) => gen_named(e, name),
                    None => None,
                };
                if ledger.security_floor != want {
                    fail(&mut v, format!("is {:?}, want {want:?}", ledger.security_floor));
                }
            }
            // §11: every one of these sessions was told about an action reaching it.
            "notified_sessions" => {
                for sid in val.as_array().into_iter().flatten().filter_map(T::as_str) {
                    let told = e
                        .notices
                        .iter()
                        .any(|n| n.contains("other people's sessions") && n.contains(&format!("{sid} (uid")));
                    if !told {
                        fail(&mut v, format!("session {sid} was not notified"));
                    }
                }
            }
            // Exactly this many notices mention `match` (§12f: one notice per repair).
            "notices_count" => {
                let m = val.get("match").and_then(T::as_str).unwrap_or("");
                let want = val.get("count").and_then(T::as_integer).unwrap_or(0) as usize;
                let got = e.notices.iter().filter(|n| n.contains(m)).count();
                if got != want {
                    fail(&mut v, format!("{got} notices mention {m}, want {want}: {:?}", e.notices));
                }
            }
            // An incident escalated with this reason during the run.
            "escalation" => {
                let want = val.as_str().unwrap_or("");
                let found = e.seen_incidents.values().any(
                    |i| matches!(&i.state, IncidentState::Escalated { reason, .. } if format!("{reason:?}") == want),
                );
                if !found {
                    fail(&mut v, format!("no incident escalated with {want}"));
                }
            }
            "interlock" => {
                let set = ledger.interlocked();
                if set != (val.as_str() == Some("set")) {
                    fail(&mut v, format!("interlock is {}", if set { "set" } else { "clear" }));
                }
            }
            // §11 (B-11): the inferred overrides still listed (not yet
            // acknowledged) at the end.
            "inferred_listed" => {
                let want: BTreeSet<String> =
                    val.as_array().into_iter().flatten().filter_map(T::as_str).map(String::from).collect();
                let got: BTreeSet<String> = ledger
                    .overrides
                    .iter()
                    .filter(|o| o.attribution == Attribution::Inferred && !o.acknowledged)
                    .map(|o| o.unit.to_string())
                    .collect();
                if got != want {
                    fail(&mut v, format!("inferred overrides listed: {got:?}, want {want:?}"));
                }
            }
            "overrides" => {
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
                    .overrides
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
                for (s, w) in ledger.overrides.iter().zip(val.as_array().into_iter().flatten()) {
                    if let Some(by) = w.get("by").and_then(T::as_str) {
                        let ok = match &s.by {
                            Actor::User { uid, session, .. } => {
                                format!("user:{uid}") == by
                                    || session.as_ref().is_some_and(|x| format!("user:{uid}@{x}") == by)
                            }
                            Actor::Unattributed => by == "Unattributed",
                            _ => false,
                        };
                        if !ok {
                            fail(&mut v, format!("{} overridden by {:?}, want {by}", s.unit, s.by));
                        }
                    }
                    if let Some(a) = w.get("attribution").and_then(T::as_str)
                        && format!("{:?}", s.attribution) != a
                    {
                        fail(&mut v, format!("{} attribution {:?}, want {a}", s.unit, s.attribution));
                    }
                }
            }
            // Nothing the entry asked for ran: no transaction committed, and
            // no backend mutation went through.
            "no_txn_executed" if val.as_bool() == Some(true) => {
                for t in &all {
                    if state_name(&t.state) == "Committed" {
                        fail(&mut v, format!("txn {} ({}) committed", t.id.0, transition_name(&t.transition)));
                    }
                }
                match &e.effects {
                    None => v.unchecked.push(format!("{key} (backend effects)")),
                    Some(fx) => {
                        for f in fx {
                            fail(&mut v, format!("{} went through", describe(f)));
                        }
                    }
                }
            }
            // I23: the override file at the end is the third party's, as it
            // wrote it (never replaced by Planarian), or Planarian's own.
            "override_file" => match (val.as_str(), &e.third_party_override) {
                (Some("third-party"), Some(h)) => {
                    if e.override_hash != Some(*h) {
                        fail(&mut v, "the third party's override file was replaced".into());
                    }
                }
                (Some("third-party"), None) => fail(&mut v, "no third-party edit happened".into()),
                _ => v.unchecked.push(key.clone()),
            },
            // I12: no transaction is left open at the end of the window.
            "nothing_left_open" if val.as_bool() == Some(true) => {
                for t in e.ledger.live.values() {
                    fail(&mut v, format!("txn {} left in {}", t.txn.id.0, state_name(&t.txn.state)));
                }
            }
            "no_txn_on" => {
                for u in val.as_array().into_iter().flatten().filter_map(T::as_str) {
                    if unknown(u) {
                        fail(&mut v, format!("{u} is not a unit on this machine"));
                    }
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
                    // A per-session unit (§9) has no instance while nobody is
                    // logged in: then it trivially had no incident.
                    let per_session = id.kind == UnitKind::Target && id.name == "graphical-session";
                    if unknown(u) && !per_session {
                        fail(&mut v, format!("{u} is not a unit on this machine"));
                    }
                    if e.seen_incidents.values().any(|i| same_unit(&id, &i.target) && i.kind == IncidentKind::Repair) {
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
                        "Unauthorized" => {
                            e.responses
                                .iter()
                                .any(|x| matches!(x, Response::Rejected { reason, .. } if reason == "Unauthorized"))
                                || !e.posture.refused_acks.is_empty()
                        }
                        "JournalChainBroken" | "BootReport(JournalChainBroken)" => {
                            e.posture.finding.as_deref().is_some_and(|f| f.contains("journal"))
                        }
                        "PostureLifted" => e.posture.lifted,
                        r if r.starts_with("BootReport(UndeclaredEarly: ") => {
                            let u = r.trim_start_matches("BootReport(UndeclaredEarly: ").trim_end_matches(')');
                            let name = unit(u).name;
                            e.posture.finding.as_deref().is_some_and(|f| f.contains("undeclared") && f.contains(&name))
                        }
                        r if r.starts_with("AlarmAcknowledged(") => {
                            let who = r.trim_start_matches("AlarmAcknowledged(").trim_end_matches(')');
                            e.posture.acks.iter().any(|a| a == who)
                        }
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
                        // The request itself was answered "approve first".
                        "NeedsApproval" => e.responses.iter().any(|x| matches!(x, Response::NeedsApproval { .. })),
                        "ApprovalInvalidated" => ledger.terminal.values().any(|t| {
                            matches!(&t.state, TxnState::Rejected(RejectReason::Other(w)) if w == "approval invalidated")
                        }),
                        "TokenReplayRefused" => e.responses.iter().any(|x| {
                            matches!(x, Response::Rejected { message, .. }
                                if message.contains("no pending change with that hash") || message.contains("already used"))
                        }),
                        "UntrackedExcluded" => notices.contains("git does not track them"),
                        // The incident is the external dependency's, and says nothing local fixes it.
                        "ExternalDependencyDown" => e.notices.iter().any(|n| {
                            n.starts_with("service:external:") && n.contains("nothing I know how to do would fix it")
                        }),
                        // Dropped traffic: said, not an incident (§10: a timeout is Unknown).
                        "ExternalDependencyUnreachable" => e.notices.iter().any(|n| {
                            n.starts_with("service:external:") && n.contains("can't reach it")
                        }),
                        "OutOfBandStopHint" => {
                            notices.contains("stopped, not crashed") && notices.contains("planarian override")
                        }
                        "DisruptionSessionLoss" => notices.contains("end your graphical session"),
                        "RestartToFinish" => notices.contains("restart to finish"),
                        "WaitsForWindow" => notices.contains("waits for a quiet moment"),
                        "InferredOverride" => notices.contains("stopped outside Planarian")
                            && notices.contains("take that as intended"),
                        "Undo" => notices.contains("To start it again: planarian release"),
                        "alarm" => e.notices.iter().any(|n| n.starts_with("ALARM: ")),
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
                let specs: Vec<&T> = match val {
                    T::Array(a) => a.iter().collect(),
                    one => vec![one],
                };
                for spec in specs {
                    check_txn(e, &all, spec, &mut v);
                }
            }
            // Any one alternative holding in full is enough.
            "one_of" => {
                let alts: Vec<Verdict> = val.as_array().into_iter().flatten().map(|alt| judge(e, alt)).collect();
                if !alts.iter().any(|a| a.failures.is_empty() && a.unchecked.is_empty()) {
                    if alts.iter().any(|a| a.failures.is_empty()) {
                        v.unchecked.push(format!("{key} (an alternative with unchecked keys)"));
                    } else {
                        let why: Vec<String> = alts.iter().map(|a| a.failures.join("; ")).collect();
                        fail(&mut v, format!("no alternative holds: {}", why.join(" | ")));
                    }
                }
            }
            // The canonical probe from the core package, not the owner's
            // weakened one, is what saw the failure.
            "canonical_probe_source" if val.as_str() == Some("core") => {
                let canonical: BTreeMap<String, Vec<ProbeDef>> =
                    serde_json::from_str(include_str!("../../../share/canonical.json")).unwrap_or_default();
                let ids: BTreeSet<String> = canonical.values().flatten().map(|p| p.id.0.clone()).collect();
                let seen = e
                    .notices
                    .iter()
                    .any(|n| n.contains(": Degraded") && ids.iter().any(|id| n.contains(&format!("{id}: "))));
                if !seen {
                    fail(&mut v, "no failure was reported by a canonical probe".into());
                }
            }
            "incident" => {
                for spec in val.as_array().into_iter().flatten() {
                    check_incident(e, spec, &mut v);
                }
            }
            "bound_driver" => match &e.drivers {
                None => v.unchecked.push(key.clone()),
                Some(d) => {
                    for (dev, want) in val.as_table().into_iter().flatten() {
                        let got = d.get(&unit(dev)).map(String::as_str).unwrap_or("none");
                        if got != want.as_str().unwrap_or("") {
                            fail(&mut v, format!("{dev} is bound to {got}, want {want}"));
                        }
                    }
                }
            },
            "evaluated_option" => match &e.options {
                None => v.unchecked.push(key.clone()),
                Some(o) => {
                    for (opt, want) in val.as_table().into_iter().flatten() {
                        let got = o.get(opt).map(value_str);
                        if got.as_deref() != Some(toml_str(want).as_str()) {
                            fail(&mut v, format!("{opt} is {got:?}, want {}", toml_str(want)));
                        }
                    }
                }
            },
            "probe_definitions_unchanged" if val.as_bool() == Some(true) => match &e.probe_defs {
                None => v.unchecked.push(key.clone()),
                Some((before, after)) if before != after => fail(&mut v, "probe definitions changed".into()),
                Some(_) => {}
            },
            "gc_root_released" if val.as_bool() == Some(true) => match &e.gc_roots {
                None => v.unchecked.push(key.clone()),
                Some((before, after)) => {
                    let left: Vec<&String> = after.difference(before).collect();
                    if !left.is_empty() {
                        fail(&mut v, format!("build roots left behind: {left:?}"));
                    }
                }
            },
            "replay_equivalent" if val.as_bool() == Some(true) => match &e.full_replay {
                None => v.unchecked.push(format!("{key} (no compaction seen)")),
                Some(full) if full != ledger => {
                    let a = serde_json::to_value(full).unwrap_or_default();
                    let b = serde_json::to_value(ledger).unwrap_or_default();
                    let differ: Vec<&String> = a
                        .as_object()
                        .into_iter()
                        .flatten()
                        .filter(|(k, x)| b.get(k.as_str()) != Some(x))
                        .map(|(k, _)| k)
                        .collect();
                    fail(&mut v, format!("checkpoint + tail differs from the full history in {differ:?}"));
                }
                Some(_) => {}
            },
            "no_overlap" => match &e.effects {
                None => v.unchecked.push(key.clone()),
                Some(fx) => {
                    let names: Vec<&str> = val.as_array().into_iter().flatten().filter_map(T::as_str).collect();
                    let named: Vec<&Effect> = fx.iter().filter(|f| names.contains(&f.call.as_str())).collect();
                    for (i, a) in named.iter().enumerate() {
                        for b in &named[i + 1..] {
                            if a.call != b.call && overlap(a, b) {
                                fail(&mut v, format!("{} and {} overlapped", describe(a), describe(b)));
                            }
                        }
                    }
                }
            },
            "quiescence_includes_tagged_jobs" if val.as_bool() == Some(true) => match &e.effects {
                None => v.unchecked.push(key.clone()),
                Some(fx) => {
                    // A later owner of a transaction never mutates while an
                    // earlier owner's job for it is still running.
                    let muts: Vec<&Effect> =
                        fx.iter().filter(|f| !f.call.starts_with("cancel") && !f.call.starts_with("protect")).collect();
                    for a in &muts {
                        for b in &muts {
                            if a.txn == b.txn && a.epoch < b.epoch && overlap(a, b) {
                                fail(&mut v, format!("{} ran during {}", describe(b), describe(a)));
                            }
                        }
                    }
                }
            },
            "stale_owner_commit" if val.as_bool() == Some(false) => match &e.entries {
                None => v.unchecked.push(key.clone()),
                Some(en) => {
                    let mut epoch: BTreeMap<TxnId, u64> = BTreeMap::new();
                    for x in en {
                        match &x.record {
                            Record::Prepared(t) => {
                                epoch.insert(t.id, t.lease.epoch);
                            }
                            Record::Takeover { txn, lease, .. } => {
                                epoch.insert(*txn, lease.epoch);
                            }
                            Record::Advance { txn, epoch: by, to, .. }
                                if matches!(to, TxnState::Published | TxnState::Promoted | TxnState::Committed)
                                    && epoch.get(txn).is_some_and(|cur| by < cur) =>
                            {
                                fail(&mut v, format!("txn {} advanced to {} by stale epoch {by}", txn.0, tag(to)));
                            }
                            _ => {}
                        }
                    }
                    // A call journaled after a takeover past its epoch must
                    // have been fenced; one that took effect is a stale write.
                    if let Some(fx) = &e.effects {
                        for f in fx {
                            let begun = en.iter().position(|x| {
                                matches!(&x.record, Record::OpBegin { op, .. }
                                    if op.txn == f.txn && op.epoch == f.epoch && op.seq == f.seq)
                            });
                            let stale = begun.is_some_and(|b| {
                                en[..b].iter().any(|x| {
                                    matches!(&x.record, Record::Takeover { txn, lease, .. }
                                        if *txn == f.txn && lease.epoch > f.epoch)
                                })
                            });
                            if stale {
                                fail(&mut v, format!("{} by a fenced owner went through", describe(f)));
                            }
                        }
                    }
                }
            },
            "lease_epochs_strictly_increasing" | "owners_per_epoch_max" => match &e.entries {
                None => v.unchecked.push(key.clone()),
                Some(en) => {
                    let mut seq: BTreeMap<TxnId, Vec<u64>> = BTreeMap::new();
                    let mut owners: BTreeMap<(TxnId, u64), BTreeSet<String>> = BTreeMap::new();
                    for x in en {
                        let claim = match &x.record {
                            Record::Prepared(t) => Some(&t.lease),
                            Record::Takeover { lease, .. } => Some(lease),
                            _ => None,
                        };
                        if let Some(l) = claim {
                            seq.entry(l.txn).or_default().push(l.epoch);
                            owners.entry((l.txn, l.epoch)).or_default().insert(format!("{:?}", l.owner));
                        }
                    }
                    if key == "lease_epochs_strictly_increasing" && val.as_bool() == Some(true) {
                        for (t, s) in &seq {
                            if s.windows(2).any(|w| w[1] <= w[0]) {
                                fail(&mut v, format!("txn {} epochs {s:?}", t.0));
                            }
                        }
                    }
                    if key == "owners_per_epoch_max" {
                        let max = val.as_integer().unwrap_or(1) as usize;
                        for ((t, ep), o) in &owners {
                            if o.len() > max {
                                fail(&mut v, format!("txn {} epoch {ep} had {} owners", t.0, o.len()));
                            }
                        }
                    }
                }
            },
            // I15: once a transaction is taken over, only the new lease
            // holder advances it, and the takeover is the named owner's.
            "journal_owner_after_takeover" => match &e.entries {
                None => v.unchecked.push(key.clone()),
                Some(en) => {
                    let want = val.as_str().unwrap_or("");
                    let mut held: BTreeMap<TxnId, u64> = BTreeMap::new();
                    let mut took = false;
                    for x in en {
                        match &x.record {
                            Record::Takeover { txn, lease, .. } => {
                                took = true;
                                if (want == "watchdog") != lease.owner.is_watchdog() {
                                    fail(&mut v, format!("txn {} taken over by {:?}", txn.0, lease.owner));
                                }
                                held.insert(*txn, lease.epoch);
                            }
                            Record::Advance { txn, epoch, to, .. } => {
                                if let Some(&ep) = held.get(txn)
                                    && *epoch != ep
                                {
                                    fail(
                                        &mut v,
                                        format!(
                                            "txn {} advanced to {to:?} at epoch {epoch} after takeover {ep}",
                                            txn.0
                                        ),
                                    );
                                }
                            }
                            Record::OpBegin { op, call } => {
                                if let Some(&ep) = held.get(&op.txn)
                                    && op.epoch != ep
                                {
                                    fail(&mut v, format!("{call} journaled at epoch {} after takeover {ep}", op.epoch));
                                }
                            }
                            _ => {}
                        }
                    }
                    if !took {
                        fail(&mut v, "no takeover in the journal".into());
                    }
                }
            },
            "journal_order" => match &e.entries {
                None => v.unchecked.push(key.clone()),
                Some(en) => {
                    let mut last = None;
                    for token in val.as_array().into_iter().flatten().filter_map(T::as_str) {
                        match position(en, token) {
                            None => fail(&mut v, format!("no {token} in the journal")),
                            Some(p) if last.is_some_and(|l| p <= l) => {
                                fail(&mut v, format!("{token} is out of order"));
                            }
                            Some(p) => last = Some(p),
                        }
                    }
                }
            },
            "watchdog_probed_before_commit" if val.as_bool() == Some(true) => match &e.entries {
                None => v.unchecked.push(key.clone()),
                Some(en) => {
                    // Published is written only once the writer's own probes
                    // passed; it must be the watchdog's.
                    let mut watchdog: BTreeSet<(TxnId, u64)> = BTreeSet::new();
                    let mut ok = false;
                    for x in en {
                        match &x.record {
                            Record::Takeover { txn, lease, .. } if lease.owner.is_watchdog() => {
                                watchdog.insert((*txn, lease.epoch));
                            }
                            Record::Advance { txn, epoch, to: TxnState::Published, note }
                                if watchdog.contains(&(*txn, *epoch)) && note == "probes passed" =>
                            {
                                ok = true;
                            }
                            _ => {}
                        }
                    }
                    if !ok {
                        fail(&mut v, "the watchdog did not probe before publishing".into());
                    }
                }
            },
            other => v.unchecked.push(other.to_string()),
        }
    }
    v
}

fn value_str(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        Value::List(l) => format!("[{}]", l.iter().map(value_str).collect::<Vec<_>>().join(", ")),
    }
}

fn toml_str(t: &T) -> String {
    match t {
        T::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Two effects overlapped: one began strictly inside the other's run. Two
/// instants never overlap (the backend serves calls one at a time).
fn overlap(a: &Effect, b: &Effect) -> bool {
    let end = |f: &Effect| f.end.unwrap_or(Timestamp(u64::MAX));
    a.start < end(b) && b.start < end(a)
}

fn describe(f: &Effect) -> String {
    format!("{} (txn {} epoch {}, {}–{:?} ms)", f.call, f.txn.0, f.epoch, f.start.0, f.end.map(|t| t.0))
}

/// The journal position of `Override(<unit>)` or `<call>(<unit>)` (an
/// OpBegin whose call starts with `<call>` in a transaction on that unit).
fn position(en: &[Entry], token: &str) -> Option<usize> {
    let (what, u) = token.strip_suffix(')')?.split_once('(')?;
    let id = unit(u);
    let mut on: BTreeMap<TxnId, Option<UnitId>> = BTreeMap::new();
    en.iter().position(|x| match &x.record {
        Record::Prepared(t) => {
            on.insert(t.id, target_of(&t.transition));
            false
        }
        Record::OverrideSet(s) => what == "Override" && s.unit == id,
        Record::OpBegin { op, call } => {
            what != "Override" && call.starts_with(what) && on.get(&op.txn).cloned().flatten() == Some(id.clone())
        }
        _ => false,
    })
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
    if let Some(want) = s("path_option") {
        matching.retain(|x| matches!(&x.transition, Transition::SetRuntimeOption { path, .. } if path == want));
    }
    // `args` picks the transaction (the same change can run twice with
    // different arguments).
    if let Some(want) = spec.get("args").and_then(T::as_table) {
        matching.retain(|x| match &x.transition {
            Transition::ApplyChange { args, .. } => {
                want.iter().all(|(k, w)| args.get(k).map(value_str).as_deref() == Some(toml_str(w).as_str()))
            }
            _ => false,
        });
    }
    // So does `emergency`: a run can collect both ways (an emergency on a
    // full journal filesystem, a routine one on another).
    if let Some(want) = spec.get("emergency").and_then(T::as_bool) {
        matching.retain(|x| matches!(x.transition, Transition::CollectGarbage { emergency } if emergency == want));
    }
    let label = format!(
        "txn {}",
        spec.as_table()
            .map(|t| t.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
    );
    // I6: none of the matching transactions was prepared while another
    // transaction was in a state (none at all passes).
    if let Some(during) = spec.get("not_during").and_then(T::as_table) {
        match &e.entries {
            None => v.unchecked.push(format!("{label}: not_during (journal history)")),
            Some(en) => {
                let other = during.get("transition").and_then(T::as_str).unwrap_or("");
                let state = during.get("state").and_then(T::as_str).unwrap_or("");
                let others: BTreeSet<TxnId> =
                    all.iter().filter(|x| transition_name(&x.transition) == other).map(|x| x.id).collect();
                let mine: BTreeSet<TxnId> = matching.iter().map(|x| x.id).collect();
                let mut inside: BTreeSet<TxnId> = BTreeSet::new();
                let mut saw_state = false;
                for x in en {
                    match &x.record {
                        Record::Advance { txn, to, .. } if others.contains(txn) => {
                            if state_name(to) == state {
                                inside.insert(*txn);
                                saw_state = true;
                            } else {
                                inside.remove(txn);
                            }
                        }
                        Record::Prepared(p) if mine.contains(&p.id) && !inside.is_empty() => {
                            v.failures.push(format!("{label}: txn {} prepared while {other} was {state}", p.id.0));
                        }
                        _ => {}
                    }
                }
                if !saw_state {
                    v.failures.push(format!("{label}: no {other} was ever {state}"));
                }
            }
        }
        if spec.get("terminal").is_none() {
            return;
        }
    }
    // A refusal for this reason (I5: never converted to a tier), from the
    // executor log; and no matching transaction ran.
    if let Some(why) = s("refused_with") {
        let refused = e.log.iter().any(|r| {
            s("transition").is_none_or(|t| transition_name(&r.proposal.transition) == t)
                && s("caller").is_none_or(|c| caller_is(&r.caller, c))
                && (matches!(&r.result, Submitted::Rejected { reason, .. } if format!("{reason:?}") == why)
                    || matches!(&r.decision, Some(Decision::Reject(reason)) if format!("{reason:?}") == why))
        });
        if !refused {
            v.failures.push(format!("{label}: not refused with {why}"));
        }
        for t in &matching {
            if t.path.iter().any(|p| p == "Activating") {
                v.failures.push(format!("{label}: txn {} ran", t.id.0));
            }
        }
        return;
    }
    let count = spec.get("count").and_then(T::as_integer);
    if count == Some(0) {
        if spec.get("before_unit_running").is_some()
            || spec.get("while_interlock").is_some()
            || spec.get("while_incident").is_some()
        {
            conditional_none(e, spec, &label, v);
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
                && s("caller").is_none_or(|c| caller_is(&r.caller, c))
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
    if let Some(c) = s("caller") {
        let by = e.log.iter().any(|r| {
            matches!(&r.result, Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } if *txn == t.id)
                && caller_is(&r.caller, c)
        });
        if !by {
            v.failures.push(format!("{label}: not submitted by {c}"));
        }
    }
    if let Some(want) = s("terminal") {
        let got = state_name(&t.state);
        // "pending": still waiting for an approval at the end of the window.
        let pending = want == "pending" && got == "Prepared";
        if got != want && !pending {
            v.failures.push(format!("{label}: ended {got}"));
        }
    }
    if let Some(want) = s("approver_class") {
        let class = e.log.iter().find_map(|r| match (&r.result, &r.decision) {
            (Submitted::Parked { txn, .. }, Some(Decision::Allow { approver, .. })) if *txn == t.id => Some(*approver),
            _ => None,
        });
        match class {
            Some(c) if format!("{c:?}") == want => {}
            Some(c) => v.failures.push(format!("{label}: approver class {c:?}")),
            None => v.failures.push(format!("{label}: never asked for approval")),
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
    if let Some(want) = spec.get("facts").and_then(T::as_table) {
        let facts = e.log.iter().find_map(|r| match &r.result {
            Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } if *txn == t.id => r.facts.clone(),
            _ => None,
        });
        match facts.map(|f| serde_json::to_value(f).unwrap_or_default()) {
            None => v.failures.push(format!("{label}: no derived facts in the executor log")),
            Some(got) => {
                for (k, w) in want {
                    let w = serde_json::to_value(w).unwrap_or_default();
                    if got.get(k) != Some(&w) {
                        v.failures.push(format!("{label}: facts.{k} is {:?}, want {w}", got.get(k)));
                    }
                }
            }
        }
    }
    // The derived affected units include these (others may come with the
    // real activation, as dbus-broker does).
    if let Some(want) = spec.get("affected_includes").and_then(T::as_array) {
        let facts = e.log.iter().find_map(|r| match &r.result {
            Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } if *txn == t.id => r.facts.clone(),
            _ => None,
        });
        match facts {
            None => v.failures.push(format!("{label}: no derived facts in the executor log")),
            Some(f) => {
                for u in want.iter().filter_map(T::as_str) {
                    if !f.affected_units.contains(&unit(u)) {
                        v.failures.push(format!("{label}: {u} not among the affected units {:?}", f.affected_units));
                    }
                }
            }
        }
    }
    // Parked for approval, and activated only once approved.
    if s("not_activated_before") == Some("approval") {
        let parked = e.log.iter().any(|r| matches!(&r.result, Submitted::Parked { txn, .. } if *txn == t.id));
        if !parked {
            v.failures.push(format!("{label}: never waited for approval"));
        }
    }
    // The tier it was decided at: AskFirst is the one that waits for an
    // approval; the others are read from the logged decision.
    if let Some(want) = s("tier") {
        let rec = e.log.iter().find(
            |r| matches!(&r.result, Submitted::Finished { txn, .. } | Submitted::Parked { txn, .. } if *txn == t.id),
        );
        let got = match rec {
            Some(r) if matches!(r.result, Submitted::Parked { .. }) => Some("AskFirst".to_string()),
            Some(r) => match &r.decision {
                Some(Decision::Allow { tier, .. }) => Some(format!("{tier:?}")),
                _ => None,
            },
            None => None,
        };
        if got.as_deref() != Some(want) {
            v.failures.push(format!("{label}: decided at {got:?}"));
        }
    }
    if let Some(after) = spec.get("started_after").and_then(T::as_table) {
        match &e.entries {
            None => v.unchecked.push(format!("{label}: started_after (journal history)")),
            Some(en) => {
                let other = after.get("transition").and_then(T::as_str).unwrap_or("");
                let left = after.get("left").and_then(T::as_str).unwrap_or("");
                let others: BTreeSet<TxnId> =
                    all.iter().filter(|x| transition_name(&x.transition) == other).map(|x| x.id).collect();
                // Where the other transaction first advanced out of `left`.
                let mut inside = BTreeSet::new();
                let mut out = None;
                for (i, x) in en.iter().enumerate() {
                    if let Record::Advance { txn, to, .. } = &x.record
                        && others.contains(txn)
                    {
                        if state_name(to) == left {
                            inside.insert(*txn);
                        } else if inside.contains(txn) && out.is_none() {
                            out = Some(i);
                        }
                    }
                }
                let began = en.iter().position(|x| matches!(&x.record, Record::Prepared(p) if p.id == t.id));
                match (out, began) {
                    (None, _) => v.failures.push(format!("{label}: no {other} left {left}")),
                    (_, None) => v.failures.push(format!("{label}: not in the journal")),
                    (Some(o), Some(b)) if b < o => {
                        v.failures.push(format!("{label}: prepared while {other} was still in {left}"))
                    }
                    _ => {}
                }
            }
        }
    }
    // A runtime transaction writes no boot entry (I23).
    if spec.get("boot_entries_unchanged").and_then(T::as_bool) == Some(true) {
        match &e.entries {
            None => v.unchecked.push(format!("{label}: boot_entries_unchanged (journal history)")),
            Some(en) => {
                if en.iter().any(|x| {
                    matches!(&x.record, Record::OpBegin { op, call } if op.txn == t.id && call.starts_with("publish_boot"))
                }) {
                    v.failures.push(format!("{label}: wrote a boot entry"));
                }
            }
        }
    }
    for k in ["returns_current_digest", "reject_detail", "decision_in", "decision_not_below"] {
        if spec.get(k).is_some() {
            v.unchecked.push(format!("{label}: {k}"));
        }
    }
    // A key nobody reads is never taken as holding.
    for k in spec.as_table().into_iter().flat_map(|t| t.keys()) {
        if !TXN_KEYS.contains(&k.as_str()) {
            v.unchecked.push(format!("{label}: {k}"));
        }
    }
}

const TXN_KEYS: &[&str] = &[
    "not_during",
    "affected_includes",
    "transition",
    "target",
    "change",
    "path_option",
    "args",
    "emergency",
    "count",
    "before_unit_running",
    "while_interlock",
    "while_incident",
    "terminal",
    "decision",
    "decision_in",
    "caller",
    "approver_class",
    "terminal_prefix",
    "path",
    "never",
    "lease_epoch_min",
    "source",
    "owner",
    "recovery",
    "facts",
    "not_activated_before",
    "returns_current_digest",
    "reject_detail",
    "decision_not_below",
    "refused_with",
    "tier",
    "started_after",
    "boot_entries_unchanged",
];

/// `count = 0` under a condition: no proposal matching the spec went
/// through (finished or parked) while the condition held.
fn conditional_none(e: &Evidence, spec: &T, label: &str, v: &mut Verdict) {
    let s = |k: &str| spec.get(k).and_then(T::as_str);
    let incident_target: BTreeMap<IncidentId, UnitId> =
        e.seen_incidents.values().map(|i| (i.id, i.target.clone())).collect();
    let went: Vec<&planarian_daemon::LogRecord> = e
        .log
        .iter()
        .filter(|r| matches!(r.result, Submitted::Finished { .. } | Submitted::Parked { .. }))
        .filter(|r| s("transition").is_none_or(|t| transition_name(&r.proposal.transition) == t))
        .filter(|r| s("target").is_none_or(|u| target_of(&r.proposal.transition) == Some(unit(u))))
        .filter(|r| {
            s("source").is_none_or(|src| match &r.proposal.source {
                Source::Diagnoser { .. } => src == "diagnoser",
                Source::User => src == "user",
                Source::Intent { .. } => src == "intent",
                Source::Model(_) => src == "model",
                Source::Maintenance => src == "maintenance",
            })
        })
        .collect();
    if let Some(u) = s("before_unit_running") {
        let Some(line) = e.status_timeline.as_ref() else {
            v.unchecked.push(format!("{label} (status timeline)"));
            return;
        };
        let line = line.get(&unit(u)).cloned().unwrap_or_default();
        for r in &went {
            let at = line.iter().rev().find(|(t, _)| *t <= r.at).map(|(_, st)| st.as_str()).unwrap_or("unknown");
            if at != "Running" {
                v.failures.push(format!("{label}: proposed at {} ms while {u} was {at}", r.at.0));
            }
        }
    }
    if s("while_interlock") == Some("set") || s("while_incident").is_some() {
        let Some(en) = e.entries.as_ref() else {
            v.unchecked.push(format!("{label} (journal history)"));
            return;
        };
        // Spans when the condition held, from the journal.
        let mut spans: Vec<(Timestamp, Timestamp)> = vec![];
        let mut since: Option<Timestamp> = None;
        let target = s("target").map(unit);
        for x in en {
            let holds = match (&x.record, s("while_incident")) {
                (Record::Advance { to: TxnState::RecoveryFailed, .. }, None) => Some(true),
                (Record::Resolved { .. }, None) => Some(false),
                (Record::Incident(i), Some(state)) if Some(&i.target) == target.as_ref() => {
                    Some(format!("{:?}", i.state).starts_with(state))
                }
                _ => None,
            };
            match (holds, since) {
                (Some(true), None) => since = Some(x.at),
                (Some(false), Some(t0)) => {
                    spans.push((t0, x.at));
                    since = None;
                }
                _ => {}
            }
        }
        if let Some(t0) = since {
            spans.push((t0, Timestamp(u64::MAX)));
        }
        for r in &went {
            if spans.iter().any(|(a, b)| *a <= r.at && r.at < *b) {
                let inc = match &r.proposal.source {
                    Source::Diagnoser { incident } => incident_target.get(incident).map(|u| u.to_string()),
                    _ => None,
                };
                v.failures.push(format!(
                    "{label}: proposed at {} ms while the condition held{}",
                    r.at.0,
                    inc.map(|u| format!(" (incident on {u})")).unwrap_or_default()
                ));
            }
        }
    }
}

fn check_incident(e: &Evidence, spec: &T, v: &mut Verdict) {
    let Some(target) = spec.get("target").and_then(T::as_str) else { return };
    let id = unit(target);
    let label = format!("incident on {target}");
    let found: Vec<&Incident> = e.seen_incidents.values().filter(|i| same_unit(&id, &i.target)).collect();
    let Some(last) = found.last() else {
        v.failures.push(format!("{label}: none opened"));
        return;
    };
    if let Some(state) = spec.get("state").and_then(T::as_str) {
        let current = e.open_incidents.iter().find(|(k, _)| same_unit(&id, k)).map(|(_, i)| i.clone());
        let got = match &current {
            None => "Closed".to_string(),
            Some(i) => format!("{:?}", i.state).split([' ', '{', '(']).next().unwrap_or("").to_string(),
        };
        if got != state {
            v.failures.push(format!("{label}: is {got}, want {state}"));
        }
    }
    if let Some(want) = spec.get("escalation").and_then(T::as_str) {
        let ok = found
            .iter()
            .any(|i| matches!(&i.state, IncidentState::Escalated { reason, .. } if format!("{reason:?}") == want));
        if !ok {
            v.failures.push(format!("{label}: not escalated with {want}"));
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
        let at = e
            .first_incident_at
            .iter()
            .filter(|(k, _)| same_unit(&id, k))
            .map(|(_, t)| *t)
            .min()
            .unwrap_or(Timestamp(u64::MAX));
        if at.0.saturating_sub(e.start.0) > limit + 60_000 {
            v.unchecked.push(format!("{label}: opened_within (relative to inject)"));
        }
    }
    if let Some(of) = spec.get("root_of").and_then(T::as_array) {
        // Where the daemon attributes a unit's divergence to another: a
        // repair proposal's reason, or an "it needs a person" notice.
        let by_incident: BTreeMap<IncidentId, UnitId> =
            e.seen_incidents.values().map(|i| (i.id, i.target.clone())).collect();
        let mut attributed: BTreeSet<UnitId> = BTreeSet::new();
        for r in &e.log {
            if let Source::Diagnoser { incident } = &r.proposal.source
                && let Some(t) = by_incident.get(incident)
                && *t != id
                && target_of(&r.proposal.transition).as_ref() == Some(&id)
            {
                attributed.insert(t.clone());
            }
        }
        let marker = format!("(root cause: {id})");
        for n in e.notices.iter().filter(|n| n.contains(&marker)) {
            if let Some((t, _)) = n.split_once(": ") {
                attributed.insert(unit(t));
            }
        }
        let want: BTreeSet<UnitId> = of.iter().filter_map(T::as_str).map(unit).collect();
        for u in want.difference(&attributed) {
            // Whether the dependent ever diverged says which side to look at.
            let seen =
                e.seen_status.get(u).map(|s| s.iter().cloned().collect::<Vec<_>>().join(", ")).unwrap_or_default();
            v.failures.push(format!("{label}: never named as the root cause of {u} (it was seen {seen})"));
        }
        for u in attributed.difference(&want) {
            v.failures.push(format!("{label}: named as the root cause of {u}, which it isn't"));
        }
    }
    if let Some(first) = spec.get("first_candidate").and_then(T::as_str) {
        match first.strip_prefix("reobserve:") {
            Some(probe) => {
                let said = e.notices.iter().any(|n| {
                    n.starts_with(&format!("{id}: ")) && n.contains("re-observing through") && n.contains(probe)
                });
                let acted = e.log.iter().any(|r| {
                    matches!(&r.proposal.source, Source::Diagnoser { incident } if found.iter().any(|i| i.id == *incident))
                });
                if !said {
                    v.failures.push(format!("{label}: did not re-observe through {probe}"));
                }
                if acted {
                    v.failures.push(format!("{label}: proposed a transition instead of re-observing"));
                }
            }
            None => v.unchecked.push(format!("{label}: first_candidate {first}")),
        }
    }
    // The incident is about that user's session: the daemon's account of it
    // names the session's uid.
    if let Some(uid) = spec.get("session_bound").and_then(T::as_integer)
        && !e.notices.iter().any(|n| {
            found.iter().any(|i| n.starts_with(&format!("{}: ", i.target))) && n.contains(&format!("(uid {uid})"))
        })
    {
        v.failures.push(format!("{label}: not tied to the session of uid {uid}"));
    }
}

/// The executor log's caller is the catalog's principal: `root`,
/// `user:<uid>`, `user:<uid>@<session>` or `user:<uid>@-` (no session), or
/// `agent:<name>` (an agent's own principal, §11).
fn caller_is(a: &Actor, want: &str) -> bool {
    match (a, want.split_once(':')) {
        (Actor::User { uid, .. }, None) => want == "root" && *uid == 0,
        (Actor::User { uid, session, .. }, Some(("user", n))) => match n.split_once('@') {
            Some((n, "-")) => n.parse() == Ok(*uid) && session.is_none(),
            Some((n, s)) => n.parse() == Ok(*uid) && session.as_deref() == Some(s),
            None => n.parse() == Ok(*uid),
        },
        (Actor::Agent(p), Some(("agent", name))) => *p == planarian_daemon::core::agent_principal(name),
        _ => false,
    }
}
