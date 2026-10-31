//! Deterministic diagnoser (SPEC §13): root-cause over the typed graph, then
//! enumerate the known transitions that could close the divergence, safest
//! and least disruptive first. Pure.
//!
//! Only `Requires` edges, and `Diagnostic` edges with confidence ≥ 0.7, are
//! walked. `Ordering` and `Wants` never are, so a failed wanted or ordered-
//! before unit is never blamed for another unit's failure. Cycles are
//! collapsed into strongly connected components first.

use planarian_incident::divergent;
use planarian_schema::spec::{precondition, predict};
use planarian_schema::{
    ChangeId, Confidence, DriverRef, EdgeKind, Expectation, Incident, ProbeResult, ProbeRole, SystemState, Timestamp,
    Transition, UnitDefs, UnitId, UnitKind, UnitStatus, Value,
};
use std::collections::{BTreeMap, BTreeSet};

pub const DIAGNOSTIC_EDGE_MIN: Confidence = Confidence(700);

pub struct Inputs<'a> {
    pub state: &'a SystemState,
    pub defs: &'a UnitDefs,
    /// When each unit was first observed definitely Failed (tie-break in a cycle).
    pub failed_since: &'a BTreeMap<UnitId, Timestamp>,
    /// The driver each device was last seen bound to.
    pub known_drivers: &'a BTreeMap<UnitId, DriverRef>,
    /// The running generation was built by a Planarian transaction. Owner-built
    /// generations are never rolled back autonomously (owner decision Q3).
    pub current_planarian_built: bool,
    /// For each runtime option a unit names as its repair (`runtime_repair`),
    /// the other values available now (for Wi-Fi: known networks in range).
    pub alternatives: &'a BTreeMap<String, Vec<Value>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub target: UnitId,
    pub transition: Transition,
    pub expected: Expectation,
    pub reason: String,
}

fn diverges(u: &UnitId, i: &Inputs<'_>) -> bool {
    let Some(def) = i.defs.get(u) else { return false };
    i.state.expected(u, i.defs) && divergent(def.desired.status, &i.state.status(u, i.defs))
}

fn walkable(kind: &EdgeKind) -> bool {
    match kind {
        EdgeKind::Requires => true,
        EdgeKind::Diagnostic { confidence } => *confidence >= DIAGNOSTIC_EDGE_MIN,
        EdgeKind::Ordering | EdgeKind::Wants => false,
    }
}

/// A declared external dependency can rule out a local repair even when its
/// Diagnostic confidence is too low to select it as a root cause. This is a
/// negative safety check, not a new functional edge: Wants and Ordering never
/// participate, and weak Diagnostic edges between local units stay unwalkable.
/// Missing/Unknown evidence cannot establish that a local restart is useful.
fn external_dependency_obstructs(target: &UnitId, i: &Inputs<'_>) -> bool {
    let mut pending = vec![target.clone()];
    let mut seen = BTreeSet::new();
    while let Some(unit) = pending.pop() {
        if !seen.insert(unit.clone()) {
            continue;
        }
        let Some(def) = i.defs.get(&unit) else { continue };
        for edge in &def.edges {
            if edge.to.name.starts_with("external:")
                && matches!(edge.kind, EdgeKind::Requires | EdgeKind::Diagnostic { .. })
            {
                let has_readiness =
                    i.defs.get(&edge.to).is_some_and(|d| d.probes.iter().any(|p| p.role == ProbeRole::Readiness));
                if !has_readiness
                    || !matches!(i.state.status(&edge.to, i.defs), UnitStatus::Running | UnitStatus::Bound)
                {
                    return true;
                }
            }
            if walkable(&edge.kind) && diverges(&edge.to, i) {
                pending.push(edge.to.clone());
            }
        }
    }
    false
}

/// The divergent units reachable from `target` through walkable edges, with
/// their walkable edges among themselves.
fn subgraph(target: &UnitId, i: &Inputs<'_>) -> BTreeMap<UnitId, Vec<UnitId>> {
    let mut g: BTreeMap<UnitId, Vec<UnitId>> = BTreeMap::new();
    let mut frontier = vec![target.clone()];
    while let Some(u) = frontier.pop() {
        if g.contains_key(&u) {
            continue;
        }
        let next: Vec<UnitId> = i
            .defs
            .get(&u)
            .map(|d| d.edges.iter().filter(|e| walkable(&e.kind) && diverges(&e.to, i)).map(|e| e.to.clone()).collect())
            .unwrap_or_default();
        frontier.extend(next.iter().cloned());
        g.insert(u, next);
    }
    g
}

/// Tarjan's algorithm. Returns the components and each node's component index.
fn sccs(g: &BTreeMap<UnitId, Vec<UnitId>>) -> (Vec<Vec<UnitId>>, BTreeMap<UnitId, usize>) {
    struct T<'g> {
        g: &'g BTreeMap<UnitId, Vec<UnitId>>,
        index: BTreeMap<UnitId, usize>,
        low: BTreeMap<UnitId, usize>,
        on: BTreeSet<UnitId>,
        stack: Vec<UnitId>,
        comps: Vec<Vec<UnitId>>,
        n: usize,
    }
    fn visit(t: &mut T<'_>, v: &UnitId) {
        t.index.insert(v.clone(), t.n);
        t.low.insert(v.clone(), t.n);
        t.n += 1;
        t.stack.push(v.clone());
        t.on.insert(v.clone());
        for w in t.g.get(v).cloned().unwrap_or_default() {
            if !t.index.contains_key(&w) {
                visit(t, &w);
                let lw = t.low[&w];
                let lv = t.low.get_mut(v).expect("visited");
                *lv = (*lv).min(lw);
            } else if t.on.contains(&w) {
                let iw = t.index[&w];
                let lv = t.low.get_mut(v).expect("visited");
                *lv = (*lv).min(iw);
            }
        }
        if t.low[v] == t.index[v] {
            let mut comp = vec![];
            while let Some(w) = t.stack.pop() {
                t.on.remove(&w);
                comp.push(w.clone());
                if &w == v {
                    break;
                }
            }
            comp.sort();
            t.comps.push(comp);
        }
    }
    let mut t =
        T { g, index: BTreeMap::new(), low: BTreeMap::new(), on: BTreeSet::new(), stack: vec![], comps: vec![], n: 0 };
    for v in g.keys() {
        if !t.index.contains_key(v) {
            visit(&mut t, v);
        }
    }
    let mut of = BTreeMap::new();
    for (ci, c) in t.comps.iter().enumerate() {
        for u in c {
            of.insert(u.clone(), ci);
        }
    }
    (t.comps, of)
}

/// Tie-break (§13): earliest definite Failed, then most failed Readiness
/// probes, then lexical order. Smaller key wins.
fn rank(u: &UnitId, i: &Inputs<'_>) -> (u64, std::cmp::Reverse<usize>, UnitId) {
    let failed_at = i.failed_since.get(u).map(|t| t.0).unwrap_or(u64::MAX);
    let failed_probes = match (i.defs.get(u), i.state.units.get(u)) {
        (Some(d), Some((_, ev))) => d
            .probes
            .iter()
            .filter(|p| p.role == ProbeRole::Readiness)
            .filter(|p| ev.iter().any(|e| e.probe == p.id && matches!(e.result, ProbeResult::Fail(_))))
            .count(),
        _ => 0,
    };
    (failed_at, std::cmp::Reverse(failed_probes), u.clone())
}

/// The deepest divergent unit below `target` (§13 step 1).
pub fn root_cause(target: &UnitId, i: &Inputs<'_>) -> UnitId {
    let g = subgraph(target, i);
    let (comps, of) = sccs(&g);
    // Sinks of the condensation: components with no edge to another component.
    let sinks: Vec<usize> =
        (0..comps.len()).filter(|ci| comps[*ci].iter().all(|u| g[u].iter().all(|w| of[w] == *ci))).collect();
    sinks.iter().flat_map(|ci| comps[*ci].iter()).min_by_key(|u| rank(u, i)).cloned().unwrap_or_else(|| target.clone())
}

/// Coarse ordering key standing in for the policy tier (§13 step 3); the
/// executor's policy decision remains authoritative.
fn est_tier(t: &Transition) -> u8 {
    match t {
        Transition::RestartUnit(_) | Transition::CollectGarbage { .. } | Transition::SetRuntimeOption { .. } => 1,
        Transition::BindDriver { .. } | Transition::ApplyChange { .. } => 2,
        _ => 3,
    }
}

/// Candidate transitions for an incident, in the order to try them (§13 steps 2–3).
pub fn candidates(incident: &Incident, i: &Inputs<'_>) -> Vec<Candidate> {
    let root = root_cause(&incident.target, i);
    // An external outage cannot be repaired by restarting a client, changing
    // its runtime options, or rolling back this node. Preserve Unknown rather
    // than inventing a definite failure for a timed-out dependency.
    if root.name.starts_with("external:") || external_dependency_obstructs(&incident.target, i) {
        return vec![];
    }
    if i.state.overridden(&root) {
        return vec![]; // I13
    }
    let Some(def) = i.defs.get(&root) else { return vec![] };
    let status = i.state.status(&root, i.defs);
    let mut out: Vec<(Transition, String)> = vec![];
    let via = if root == incident.target { String::new() } else { format!(" (root cause of {})", incident.target) };

    // A unit restored by choosing another value of a runtime option (§12a):
    // Wi-Fi to another known network in range. The unit says its health
    // depends on that value, so when another is available it comes before a
    // restart (which cannot bring a network back). It drops connectivity, so
    // the policy floors make it AskFirst.
    if let Some(opt) = &def.runtime_repair
        && divergent(def.desired.status, &status)
        && let Some(v) = i.alternatives.get(opt).and_then(|a| a.first())
    {
        let shown = match v {
            Value::Str(s) => s.clone(),
            other => format!("{other:?}"),
        };
        out.push((
            Transition::SetRuntimeOption { path: opt.clone(), value: v.clone() },
            format!("{root} is {status:?}; switch {opt} to {shown}{via}"),
        ));
    }

    match def.id.kind {
        UnitKind::Device if root.name.starts_with("fs-") => {
            let emergency = root.name == "fs-journal" || root.name == "fs-nix";
            out.push((Transition::CollectGarbage { emergency }, format!("{root} is low on space{via}")));
        }
        UnitKind::Device => {
            if let Some(driver) = i.known_drivers.get(&root)
                && matches!(status, UnitStatus::Detected | UnitStatus::Failed(_))
            {
                out.push((
                    Transition::BindDriver { device: root.clone(), driver: driver.clone() },
                    format!("{root} lost its driver {}{via}", driver.name),
                ));
            }
        }
        _ if root.name.starts_with("external:") => {
            // Nothing local repairs an external dependency; report it.
        }
        _ => match status {
            UnitStatus::Failed(_) | UnitStatus::Stopped | UnitStatus::Degraded(_) => {
                out.push((Transition::RestartUnit(root.clone()), format!("{root} is {status:?}{via}")));
            }
            UnitStatus::Absent => out.push((
                Transition::ApplyChange {
                    change: ChangeId("repair:reenable-predicted".into()),
                    args: [("service".to_string(), Value::Str(root.name.clone()))].into(),
                },
                format!("{root} is missing though the manifest predicts it{via}"),
            )),
            _ => {}
        },
    }

    if i.current_planarian_built && i.state.generation != i.state.known_good {
        out.push((Transition::Rollback, format!("roll back to the known-good generation{via}")));
    }

    out.retain(|(t, _)| precondition(t, i.state, i.defs));
    out.sort_by_key(|(t, _)| {
        let rollback = matches!(t, Transition::Rollback);
        (rollback, est_tier(t), def.restart_disruption)
    });
    out.into_iter()
        .map(|(t, reason)| Candidate {
            target: root.clone(),
            expected: predict(&t, i.state, i.defs),
            transition: t,
            reason,
        })
        .collect()
}

/// The candidate for this attempt: candidates are tried in order across the
/// incident's attempts, wrapping around (so a lone restart is retried until the
/// budget is spent). `None`: the diagnoser is exhausted.
pub fn next(incident: &Incident, i: &Inputs<'_>) -> Option<Candidate> {
    let c = candidates(incident, i);
    if c.is_empty() {
        return None;
    }
    let n = incident.attempts.len() % c.len();
    c.into_iter().nth(n)
}

#[cfg(test)]
mod tests;
