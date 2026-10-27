//! Transitions, decisions, derived facts and proposals (§8).

use crate::ids::{ChangeId, GenerationId, Hash, IncidentId, Millis, ModelId, SnapshotId, StorePath, TxnId};
use crate::state::{SystemState, UnitStatus};
use crate::unit::{Actor, Disruption, Recovery, Sensitivities, Suppression, UnitDefs, UnitId, Until};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// An option value in the override file or a catalog argument. There is no
/// float variant: fractional settings (font scale) are carried as strings
/// from the catalog's permitted set.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<Value>),
}

/// Option path → (before, after). `None` means unset.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiff {
    pub options: BTreeMap<String, (Option<Value>, Option<Value>)>,
}

impl ConfigDiff {
    /// Compose `self` then `next`: keep the earliest `before` and the latest `after`;
    /// drop entries that end where they began.
    pub fn then(&self, next: &ConfigDiff) -> ConfigDiff {
        let mut out = self.options.clone();
        for (path, (before, after)) in &next.options {
            let first = match out.get(path) {
                Some((b, _)) => b.clone(),
                None => before.clone(),
            };
            out.insert(path.clone(), (first, after.clone()));
        }
        out.retain(|_, (b, a)| b != a);
        ConfigDiff { options: out }
    }

    pub fn hash(&self) -> Hash {
        Hash::of(&serde_json::to_vec(self).expect("diff serializes"))
    }
}

/// An in-tree driver is named (`snd_hda_intel`); an out-of-tree one also names
/// the module's store path. Replaces §8's bare `StorePath` (G6).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DriverRef {
    pub name: String,
    pub module: Option<StorePath>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Resolution {
    AsCommitted,
    AsReverted,
    ManualRepaired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transition {
    RestartUnit(UnitId),
    StopUnit(UnitId),
    BindDriver {
        device: UnitId,
        driver: DriverRef,
    },
    /// Cataloged (§9); the executor computes the diff.
    ApplyChange {
        change: ChangeId,
        args: BTreeMap<String, Value>,
    },
    SwitchGeneration(GenerationId),
    Revert {
        to: GenerationId,
    },
    /// To `known_good` (or `accepted_baseline`).
    Rollback,
    /// Phase B.
    LoadModel(ModelId),
    /// Phase C.
    RestoreSnapshot(SnapshotId),
    CollectGarbage {
        emergency: bool,
    },
    SetRuntimeOption {
        path: String,
        value: Value,
    },
    /// Leave-alone only; does not stop anything.
    Suppress(Suppression),
    Unsuppress(UnitId),
    /// The user's "stop X": suppression journaled, then stop.
    StopAndSuppress {
        unit: UnitId,
        until: Until,
        reason: String,
    },
    /// `planarian resolve <txn>`: the only way to clear the recovery interlock (§12c).
    /// Administrator-only; not in §8's list but §12c calls it a transition.
    Resolve {
        txn: TxnId,
        resolution: Resolution,
    },
}

/// Per-transition recovery strategy, fixed by the spec, not the proposer (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    ReobserveOnly,
    RevertGeneration,
    UnbindDevice,
    RestoreSnapshotThenRevert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Handler {
    UnitOp,
    GenerationOp,
    DeviceOp,
    SnapshotOp,
    GcOp,
    IntentOp,
}

impl Transition {
    /// The §12 execution table. Independent of tier.
    pub fn handler(&self) -> Handler {
        match self {
            Transition::RestartUnit(_) | Transition::StopUnit(_) | Transition::SetRuntimeOption { .. } => {
                Handler::UnitOp
            }
            Transition::Suppress(_)
            | Transition::Unsuppress(_)
            | Transition::StopAndSuppress { .. }
            | Transition::Resolve { .. } => Handler::IntentOp,
            Transition::CollectGarbage { .. } => Handler::GcOp,
            Transition::ApplyChange { .. }
            | Transition::SwitchGeneration(_)
            | Transition::Revert { .. }
            | Transition::Rollback
            | Transition::LoadModel(_) => Handler::GenerationOp,
            Transition::BindDriver { .. } => Handler::DeviceOp,
            Transition::RestoreSnapshot(_) => Handler::SnapshotOp,
        }
    }

    pub fn recovery(&self) -> RecoveryStrategy {
        match self.handler() {
            Handler::UnitOp | Handler::IntentOp | Handler::GcOp => RecoveryStrategy::ReobserveOnly,
            Handler::GenerationOp => RecoveryStrategy::RevertGeneration,
            Handler::DeviceOp => RecoveryStrategy::UnbindDevice,
            Handler::SnapshotOp => RecoveryStrategy::RestoreSnapshotThenRevert,
        }
    }

    /// Generation-changing transactions are serialized (I6).
    pub fn changes_generation(&self) -> bool {
        matches!(self.recovery(), RecoveryStrategy::RevertGeneration | RecoveryStrategy::RestoreSnapshotThenRevert)
    }
}

/// Ordered; the autonomy setting compares with `>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Tier {
    Observe,
    Runtime,
    Tested,
    AskFirst,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow(Tier),
    Reject(RejectReason),
}

/// `Unauthorized`, `Interrupted` and `NoSpace` are used by §11, §12 and §12c
/// but were missing from §8 (G1). `Refinement` names the §12 step 3 rejection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RejectReason {
    Forbidden,
    CoreTarget,
    ProbeTamper,
    NotInCatalog,
    LockedOption,
    Stale,
    Unauthorized,
    Interrupted,
    NoSpace,
    Refinement,
    ApprovalExpired,
    Other(String),
}

/// Derived by the executor from the evaluated generation, never from the
/// proposal (I14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedFacts {
    pub affected_units: BTreeSet<UnitId>,
    pub sensitivity: Sensitivities,
    pub disruption: Disruption,
    pub recovery: Recovery,
    pub touches_manifest: bool,
    /// A canonical probe's *definition* changed (protected by I10).
    pub touches_canonical_probe: bool,
    /// Which units are desired-present changed; makes probes (in)applicable.
    /// Not tampering (§9; missing from §8, G2).
    pub changes_desired: bool,
    pub touches_core: bool,
    pub caller: Actor,
    pub config_diff: Option<ConfigDiff>,
}

/// What evaluating a staged source yields (§9 step 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedGeneration {
    pub source: Hash,
    pub options: BTreeMap<String, Value>,
    pub units: UnitDefs,
    /// Units instantiated once per logged-in user (`Scope::User { uid: 0 }` as
    /// a placeholder); `state` expands them per session (§10).
    pub user_units: Vec<crate::unit::UnitDef>,
    /// Filled in by `build` (dry-activate); empty after evaluation alone.
    pub activation: ActivationPlan,
    /// Option paths whose highest-priority definition beats Planarian's
    /// `mkOverride 90` (the owner used `mkForce`): `locked` (§9).
    pub locked: BTreeSet<String>,
    /// Content hashes of the evaluated unit files for `planariad` and
    /// `planarian-recovery`; a difference from the running ones is `touches_core`.
    pub core_units: BTreeMap<String, Hash>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationPlan {
    pub start: BTreeSet<UnitId>,
    pub stop: BTreeSet<UnitId>,
    pub restart: BTreeSet<UnitId>,
    pub reload: BTreeSet<UnitId>,
    /// Kernel, initrd, bootloader or filesystem options changed: can become
    /// `live_tested` but not `known_good` until a reboot confirms it (§10).
    pub needs_reboot_to_confirm: bool,
}

pub trait TransitionSpec {
    fn precondition(&self, s: &SystemState, defs: &UnitDefs) -> bool;
    fn predict(&self, s: &SystemState, defs: &UnitDefs) -> Expectation;
    fn derive(&self, s: &SystemState, defs: &UnitDefs, generation: &EvaluatedGeneration, caller: Actor)
    -> DerivedFacts;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expectation {
    pub units: BTreeMap<UnitId, UnitStatus>,
    pub generation: Option<GenerationId>,
    pub may_change: BTreeSet<UnitId>,
    pub others_unchanged: bool,
    pub settle: Settle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Settle {
    Duration(Millis),
    Ready { unit: UnitId, timeout: Millis },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub observed: Hash,
    pub transition: Transition,
    /// MUST refine `spec.predict()`; checked in §12 step 3.
    pub expected: Expectation,
    pub reason: String,
    pub source: Source,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    Diagnoser {
        incident: IncidentId,
    },
    Model(ModelId),
    User,
    /// Confidence in per-mille, as `Confidence`.
    Intent {
        phrase: String,
        confidence: crate::unit::Confidence,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_table() {
        let u = UnitId::service("x");
        assert_eq!(Transition::RestartUnit(u.clone()).recovery(), RecoveryStrategy::ReobserveOnly);
        assert_eq!(
            Transition::StopAndSuppress { unit: u.clone(), until: Until::Explicit, reason: String::new() }.recovery(),
            RecoveryStrategy::ReobserveOnly
        );
        // Rollback is a generation operation even though its tier may be Runtime.
        assert_eq!(Transition::Rollback.recovery(), RecoveryStrategy::RevertGeneration);
        assert!(Transition::Rollback.changes_generation());
        let bind = Transition::BindDriver {
            device: UnitId::device("d"),
            driver: DriverRef { name: "snd_hda_intel".into(), module: None },
        };
        assert_eq!(bind.recovery(), RecoveryStrategy::UnbindDevice);
        assert!(!bind.changes_generation());
        assert!(!Transition::CollectGarbage { emergency: true }.changes_generation());
    }

    #[test]
    fn diff_composition() {
        let d = |p: &str, b: Option<i64>, a: Option<i64>| ConfigDiff {
            options: [(p.to_owned(), (b.map(Value::Int), a.map(Value::Int)))].into(),
        };
        let both = d("x", Some(1), Some(2)).then(&d("x", Some(2), Some(3)));
        assert_eq!(both, d("x", Some(1), Some(3)));
        let undone = d("x", Some(1), Some(2)).then(&d("x", Some(2), Some(1)));
        assert!(undone.options.is_empty());
    }
}
