//! Per-transition preconditions and predictions (§8 `TransitionSpec`, the
//! pure half). Shared by the diagnoser, which builds proposals, and the
//! executor, which checks that a proposal's `expected` refines `predict`
//! (§12 step 3). Derivation of facts needs the evaluated generation and lives
//! in `exec`.

use crate::ids::Millis;
use crate::state::{SystemState, UnitStatus};
use crate::transition::{Expectation, Settle, Transition};
use crate::unit::{Attribution, EdgeKind, OverrideDesired, UnitDefs, UnitId, UnitKind};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_SETTLE: Millis = Millis::secs(15);
pub const READY_TIMEOUT: Millis = Millis::secs(60);

/// Units with a `Requires` edge to `unit`, transitively: systemd stops or
/// restarts them along with it.
pub fn dependents(unit: &UnitId, defs: &UnitDefs) -> BTreeSet<UnitId> {
    let mut out = BTreeSet::new();
    let mut frontier = vec![unit.clone()];
    while let Some(u) = frontier.pop() {
        for d in defs.values() {
            if d.edges.iter().any(|e| e.to == u && e.kind == EdgeKind::Requires) && out.insert(d.id.clone()) {
                frontier.push(d.id.clone());
            }
        }
    }
    out
}

pub fn precondition(t: &Transition, s: &SystemState, defs: &UnitDefs) -> bool {
    match t {
        Transition::RestartUnit(u) => {
            defs.get(u).is_some_and(|d| d.id.kind != UnitKind::Device && !u.name.starts_with("external:"))
                && !s.overridden(u)
        }
        Transition::StopUnit(u) | Transition::StopAndSuppress { unit: u, .. } => defs.contains_key(u),
        // An inferred override is replaced only by an authorized principal setting a new one (§11).
        Transition::SetOverride(sup) => s.override_of(&sup.unit).is_none_or(|o| o.attribution == Attribution::Inferred),
        Transition::LiftOverride(u) => s.overridden(u),
        Transition::BindDriver { device, .. } => {
            defs.get(device).is_some_and(|d| d.id.kind == UnitKind::Device) && !s.overridden(device)
        }
        Transition::Rollback => s.generation != s.known_good,
        Transition::SwitchGeneration(g) => *g != s.generation,
        Transition::Revert { to } => *to != s.generation,
        _ => true,
    }
}

/// What the transition is expected to achieve. For generation operations the
/// set of units that may change is only known after evaluation; `predict`
/// leaves `may_change` empty with `others_unchanged = false`, and the executor
/// bounds it by the derived `affected_units` instead.
pub fn predict(t: &Transition, s: &SystemState, defs: &UnitDefs) -> Expectation {
    let unit = |u: &UnitId, status: UnitStatus, settle: Settle| {
        let mut may: BTreeSet<UnitId> = dependents(u, defs);
        may.insert(u.clone());
        Expectation {
            units: BTreeMap::from([(u.clone(), status)]),
            generation: None,
            may_change: may,
            others_unchanged: true,
            settle,
        }
    };
    let ready = |u: &UnitId| Settle::Ready { unit: u.clone(), timeout: READY_TIMEOUT };
    let none = || Expectation {
        units: BTreeMap::new(),
        generation: None,
        may_change: BTreeSet::new(),
        others_unchanged: true,
        settle: Settle::Duration(DEFAULT_SETTLE),
    };
    match t {
        Transition::RestartUnit(u) => unit(u, UnitStatus::Running, ready(u)),
        Transition::StopUnit(u) => unit(u, UnitStatus::Stopped, Settle::Duration(DEFAULT_SETTLE)),
        Transition::StopAndSuppress { unit: u, .. } => {
            unit(u, UnitStatus::Overridden(OverrideDesired::Stopped), Settle::Duration(DEFAULT_SETTLE))
        }
        Transition::SetOverride(sup) => Expectation {
            units: BTreeMap::from([(sup.unit.clone(), UnitStatus::Overridden(sup.desired))]),
            may_change: BTreeSet::from([sup.unit.clone()]),
            ..none()
        },
        Transition::LiftOverride(u) => Expectation { may_change: BTreeSet::from([u.clone()]), ..none() },
        Transition::BindDriver { device, .. } => unit(device, UnitStatus::Bound, Settle::Duration(DEFAULT_SETTLE)),
        Transition::SwitchGeneration(g) | Transition::Revert { to: g } => {
            Expectation { generation: Some(*g), others_unchanged: false, ..none() }
        }
        Transition::Rollback => Expectation { generation: Some(s.known_good), others_unchanged: false, ..none() },
        Transition::ApplyChange { .. } | Transition::LoadModel(_) | Transition::RestoreSnapshot(_) => {
            Expectation { others_unchanged: false, ..none() }
        }
        Transition::CollectGarbage { .. } | Transition::SetRuntimeOption { .. } | Transition::Resolve { .. } => none(),
    }
}

/// §12 step 3: `claimed` must agree with `predicted` on every unit the
/// prediction names, must not broaden `may_change`, and must not relax
/// `others_unchanged`. For generation operations (`others_unchanged = false`
/// in the prediction) `bound` limits `may_change` instead.
pub fn refines(claimed: &Expectation, predicted: &Expectation, bound: Option<&[UnitId]>) -> Result<(), String> {
    for (u, st) in &predicted.units {
        if claimed.units.get(u) != Some(st) {
            return Err(format!("expected status of {u} disagrees with the prediction"));
        }
    }
    if predicted.generation.is_some() && claimed.generation != predicted.generation {
        return Err("expected generation disagrees with the prediction".into());
    }
    if predicted.others_unchanged && !claimed.others_unchanged {
        return Err("claims others may change where the prediction says they don't".into());
    }
    let allowed = |u: &UnitId| match (predicted.others_unchanged, bound) {
        (true, _) => predicted.may_change.contains(u),
        (false, Some(b)) => b.contains(u),
        (false, None) => true,
    };
    if let Some(u) = claimed.may_change.iter().find(|u| !allowed(u)) {
        return Err(format!("may_change broadened with {u}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::*;

    #[test]
    fn restart_prediction_includes_dependents_and_refinement() {
        let db = service("gym-db");
        let mut app = service("gym-app");
        edge(&mut app, "gym-db", EdgeKind::Requires);
        let mut cache_user = service("gym-cache-user");
        edge(&mut cache_user, "gym-app", EdgeKind::Ordering);
        let defs = defs([db, app, cache_user]);
        let s = empty_state(0);
        let t = Transition::RestartUnit(UnitId::service("gym-db"));
        let p = predict(&t, &s, &defs);
        assert_eq!(p.may_change, [UnitId::service("gym-db"), UnitId::service("gym-app")].into());
        assert!(refines(&p, &p, None).is_ok());
        let mut broad = p.clone();
        broad.may_change.insert(UnitId::service("sshd"));
        assert!(refines(&broad, &p, None).is_err(), "policy-refinement-violation");
        let mut lax = p.clone();
        lax.others_unchanged = false;
        assert!(refines(&lax, &p, None).is_err());
        let mut narrower = p.clone();
        narrower.may_change.remove(&UnitId::service("gym-app"));
        assert!(refines(&narrower, &p, None).is_ok(), "a proposer may only add claims");
    }
}
