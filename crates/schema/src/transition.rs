//! Transitions, decisions, derived facts and proposals (§8).

use crate::ids::{ChangeId, GenerationId, Hash, IncidentId, Millis, ModelId, SnapshotId, StorePath, TxnId};
use crate::pathmap::PathMap;
use crate::state::{SystemState, UnitStatus};
use crate::unit::{Actor, Disruption, Override, Recovery, Sensitivities, UnitDefs, UnitId, Until};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use vstd::prelude::*;

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

// The types `policy::decide` reads, visible to its proofs. `Value` stays
// opaque to them: the proofs never look inside an option value.
verus! {

#[verifier::external_type_specification]
#[verifier::external_body]
#[allow(dead_code)]
pub struct ExValue(Value);

/// Option path → (before, after). `None` means unset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub struct ConfigDiff {
    pub options: PathMap<(Option<Value>, Option<Value>)>,
}

/// An in-tree driver is named (`snd_hda_intel`); an out-of-tree one also names
/// the module's store path. Replaces §8's bare `StorePath` (G6).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub struct DriverRef {
    pub name: String,
    pub module: Option<StorePath>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Resolution {
    AsCommitted,
    AsReverted,
    ManualRepaired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
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
    /// LeaveAlone records intent only; Stopped records intent and stops the
    /// unit with the same affected-unit and disruption floors as StopUnit.
    SetOverride(Override),
    LiftOverride(UnitId),
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

/// Ordered; the autonomy setting compares with `>` (`rank` in proofs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Tier {
    Observe,
    Runtime,
    Tested,
    AskFirst,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Decision {
    Allow { tier: Tier, approver: ApproverClass },
    Reject(RejectReason),
}

/// Who may approve an AskFirst decision. The class is the maximum over every
/// floor and table row that raised the decision; it is ignored below AskFirst.
/// `Administrator` requires the approver to hold `Capability::Administrator`
/// as well as `Capability::Approve`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum ApproverClass {
    AnyApprover,
    Administrator,
}

/// `Unauthorized`, `Interrupted` and `NoSpace` are used by §11, §12 and §12c
/// but were missing from §8 (G1). `Refinement` names the §12 step 3 rejection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub struct DerivedFacts {
    /// Sorted and unique (`unit_set`).
    pub affected_units: Vec<UnitId>,
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
    /// The target generation (revert, rollback, switch) is below the security floor (§12e).
    #[serde(default)]
    pub below_security_floor: bool,
    /// A system-scope effect reaches another uid's online or active session (§11).
    #[serde(default)]
    pub other_sessions_affected: bool,
    /// Logind sessions the transition's disruption lands on, sorted. The
    /// "own session" floor (§11) holds only when this is exactly the caller's
    /// session; empty means not known, which never counts as own. Not in §8.
    #[serde(default)]
    pub affected_sessions: Vec<String>,
    /// A RestartUnit that restores a unit stopped outside Planarian and not
    /// attributed (§11 residue): stopped, not failed, under no override.
    /// Derived from systemd's state, never from a proposal.
    #[serde(default)]
    pub restores_unattributed_stop: bool,
    pub caller: Actor,
    pub config_diff: Option<ConfigDiff>,
}

impl Tier {
    /// Observe 0, Runtime 1, Tested 2, AskFirst 3: the derived `Ord`.
    pub open spec fn rank(self) -> u8 {
        match self {
            Tier::Observe => 0,
            Tier::Runtime => 1,
            Tier::Tested => 2,
            Tier::AskFirst => 3,
        }
    }

    pub fn rank_of(&self) -> (r: u8)
        ensures r == self.rank(),
    {
        match self {
            Tier::Observe => 0,
            Tier::Runtime => 1,
            Tier::Tested => 2,
            Tier::AskFirst => 3,
        }
    }
}

/// Per-transition recovery strategy, fixed by the spec, not the proposer (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[verifier::external_derive]
pub enum RecoveryStrategy {
    ReobserveOnly,
    RevertGeneration,
    UnbindDevice,
    RestoreSnapshotThenRevert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[verifier::external_derive]
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
    pub open spec fn handler_spec(self) -> Handler {
        match self {
            Transition::RestartUnit(_) | Transition::StopUnit(_) | Transition::SetRuntimeOption { .. } => {
                Handler::UnitOp
            },
            Transition::SetOverride(_) | Transition::LiftOverride(_) | Transition::StopAndSuppress { .. }
            | Transition::Resolve { .. } => Handler::IntentOp,
            Transition::CollectGarbage { .. } => Handler::GcOp,
            Transition::ApplyChange { .. } | Transition::SwitchGeneration(_) | Transition::Revert { .. }
            | Transition::Rollback | Transition::LoadModel(_) => Handler::GenerationOp,
            Transition::BindDriver { .. } => Handler::DeviceOp,
            Transition::RestoreSnapshot(_) => Handler::SnapshotOp,
        }
    }

    pub open spec fn recovery_spec(self) -> RecoveryStrategy {
        match self.handler_spec() {
            Handler::UnitOp | Handler::IntentOp | Handler::GcOp => RecoveryStrategy::ReobserveOnly,
            Handler::GenerationOp => RecoveryStrategy::RevertGeneration,
            Handler::DeviceOp => RecoveryStrategy::UnbindDevice,
            Handler::SnapshotOp => RecoveryStrategy::RestoreSnapshotThenRevert,
        }
    }

    /// Generation-changing transactions are serialized (I6).
    pub open spec fn changes_generation_spec(self) -> bool {
        self.recovery_spec().reverts_generation()
    }

    pub fn handler(&self) -> (r: Handler)
        ensures
            r == self.handler_spec(),
    {
        match self {
            Transition::RestartUnit(_) | Transition::StopUnit(_) | Transition::SetRuntimeOption { .. } => {
                Handler::UnitOp
            },
            Transition::SetOverride(_) | Transition::LiftOverride(_) | Transition::StopAndSuppress { .. }
            | Transition::Resolve { .. } => Handler::IntentOp,
            Transition::CollectGarbage { .. } => Handler::GcOp,
            Transition::ApplyChange { .. } | Transition::SwitchGeneration(_) | Transition::Revert { .. }
            | Transition::Rollback | Transition::LoadModel(_) => Handler::GenerationOp,
            Transition::BindDriver { .. } => Handler::DeviceOp,
            Transition::RestoreSnapshot(_) => Handler::SnapshotOp,
        }
    }

    pub fn recovery(&self) -> (r: RecoveryStrategy)
        ensures
            r == self.recovery_spec(),
    {
        match self.handler() {
            Handler::UnitOp | Handler::IntentOp | Handler::GcOp => RecoveryStrategy::ReobserveOnly,
            Handler::GenerationOp => RecoveryStrategy::RevertGeneration,
            Handler::DeviceOp => RecoveryStrategy::UnbindDevice,
            Handler::SnapshotOp => RecoveryStrategy::RestoreSnapshotThenRevert,
        }
    }

    pub fn changes_generation(&self) -> (r: bool)
        ensures
            r == self.changes_generation_spec(),
    {
        match self.recovery() {
            RecoveryStrategy::RevertGeneration | RecoveryStrategy::RestoreSnapshotThenRevert => true,
            _ => false,
        }
    }
}

impl RecoveryStrategy {
    /// Recovery reverts the generation (generation and snapshot operations).
    pub open spec fn reverts_generation(self) -> bool {
        match self {
            RecoveryStrategy::RevertGeneration | RecoveryStrategy::RestoreSnapshotThenRevert => true,
            _ => false,
        }
    }
}

} // verus!

/// Sorted, without duplicates: the form of `DerivedFacts::affected_units`.
pub fn unit_set(units: impl IntoIterator<Item = UnitId>) -> Vec<UnitId> {
    let set: BTreeSet<UnitId> = units.into_iter().collect();
    set.into_iter().collect()
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
    /// The system's packages, pname → version (§12e).
    #[serde(default)]
    pub packages: BTreeMap<String, String>,
    /// Those whose nixpkgs `meta.knownVulnerabilities` is not empty (§12e).
    #[serde(default)]
    pub insecure: BTreeSet<String>,
    /// Every system service the generation declares, watched or not, with
    /// the files that define it (NixOS's definition locations): the
    /// provenance a malicious declaration leaves (§15).
    #[serde(default)]
    pub declarations: BTreeMap<String, Vec<String>>,
    /// The flake inputs the generation was built from, name → (revision,
    /// store path), when the owner's flake passes them
    /// (`services.planarian.flakeInputs`): a declaration from an input is
    /// reported with the input's lock change (§15).
    #[serde(default)]
    pub inputs: BTreeMap<String, (String, String)>,
    /// The shipped tables' sensitivity for every system service NixOS
    /// defines that the manifest does not declare (§11 sensitivity
    /// completeness): a unit in neither has no entry, and fails closed.
    #[serde(default)]
    pub services: BTreeMap<String, Sensitivities>,
}

impl EvaluatedGeneration {
    /// §12e: packages this generation fixes relative to `base`: insecure in
    /// `base`, still present here, and no longer insecure.
    pub fn security_fixes(&self, base: &EvaluatedGeneration) -> Vec<String> {
        base.insecure
            .iter()
            .filter(|p| self.packages.contains_key(*p) && !self.insecure.contains(*p))
            .cloned()
            .collect()
    }
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

impl ActivationPlan {
    /// Takes effect only at boot (kernel, initrd, drivers): nothing to start,
    /// stop, restart or reload now (§12f boot-only path).
    pub fn boot_only(&self) -> bool {
        self.needs_reboot_to_confirm
            && self.start.is_empty()
            && self.stop.is_empty()
            && self.restart.is_empty()
            && self.reload.is_empty()
    }
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
    /// The daemon's own housekeeping: collection under the §12b bounds.
    Maintenance,
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
