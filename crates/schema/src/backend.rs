//! Backend contracts (§8). Generic parameters only; no `dyn` (§6).
//!
//! Every mutating call takes the `OpId` that was durably journaled before it
//! (§12). The OpId carries `(txn, epoch)`: the backend refuses the call with
//! `Outcome::fenced()` if that epoch is not the journal's current epoch for the
//! transaction, and tags the work it starts with the OpId so `jobs_tagged` can
//! find it later. This replaces the `&Lease` parameter in §8.

use crate::ids::{GenerationId, Hash, JobId, OpId, SnapshotId, StorePath};
use crate::state::{Observed, Resources};
use crate::transition::{DriverRef, EvaluatedGeneration, Value};
use crate::txn::Outcome;
use crate::unit::UnitId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceKind {
    Git,
    Directory,
}

/// The owner's configuration as Nix will see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedSource {
    pub root: String,
    pub kind: SourceKind,
}

/// Flat option assignments for `planarian/overrides.nix` (wrapped in `lib.mkOverride 90`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideSet {
    pub assignments: BTreeMap<String, Value>,
}

/// An immutable staged copy (§9 step 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedSource {
    pub dir: String,
    pub base_source: Hash,
    pub staged_source: Hash,
    pub base_override: Hash,
    pub candidate_override: Hash,
    /// Untracked files that were excluded (reported, §9 step 1).
    pub excluded: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: UnitId,
    pub driver: Option<DriverRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Built {
    pub generation: GenerationId,
    pub path: StorePath,
    /// The GC root `build` created for its own output (§9 step 5).
    pub root: String,
}

pub trait UnitBackend {
    fn observe(&self, id: &UnitId) -> Result<Observed, Outcome>;
    fn list(&self) -> Result<Vec<UnitId>, Outcome>;
    fn restart(&self, id: &UnitId, op: &OpId) -> Outcome;
    fn stop(&self, id: &UnitId, op: &OpId) -> Outcome;
}

pub trait GenerationBackend {
    // Read-only; allowed before Prepared.
    fn current(&self) -> Result<GenerationId, Outcome>;
    fn boot_entries(&self) -> Result<Vec<GenerationId>, Outcome>;
    fn boot_default(&self) -> Result<GenerationId, Outcome>;
    fn last_booted(&self) -> Result<GenerationId, Outcome>;
    fn stage(&self, owner: &PinnedSource, overrides: &OverrideSet) -> Result<StagedSource, Outcome>;
    /// Recompute the NAR hash of the owner's Nix-visible source now (stale check, §9 step 6).
    fn source_hash(&self, owner: &PinnedSource) -> Result<Hash, Outcome>;
    fn evaluate(&self, src: &StagedSource) -> Result<EvaluatedGeneration, Outcome>;
    /// Store-only; roots its own output.
    fn build(&self, eval: &EvaluatedGeneration) -> Result<Built, Outcome>;
    fn verify_candidate(&self, path: &StorePath, expected: &Hash) -> Result<bool, Outcome>;
    fn pending_jobs(&self) -> Result<Vec<JobId>, Outcome>;
    /// `None`: the backend cannot say whether work tagged with `op` exists.
    fn jobs_tagged(&self, op: &OpId) -> Result<Option<Vec<JobId>>, Outcome>;
    /// The override file's current content hash (promotion compares against it, §9 step 4).
    fn override_hash(&self) -> Result<Hash, Outcome>;

    // Mutating; require a durable Prepared and a current epoch.
    /// `switch-to-configuration test`.
    fn activate_live(&self, g: GenerationId, op: &OpId) -> Outcome;
    /// Boot entry only; no re-activation.
    fn publish_boot(&self, g: GenerationId, op: &OpId) -> Outcome;
    fn protect(&self, g: GenerationId, op: &OpId) -> Outcome;
    fn cancel(&self, job: &JobId, op: &OpId) -> Outcome;
    /// Atomically replace the live override file with the content whose hash is
    /// `to`, but only if its current hash is `from`. Idempotent: if it already
    /// hashes to `to`, succeed without writing.
    fn swap_override(&self, from: &Hash, to: &Hash, op: &OpId) -> Outcome;
}

pub trait SnapshotBackend {
    fn supported(&self) -> bool;
    fn snapshot(&self, label: &str, op: &OpId) -> Result<SnapshotId, Outcome>;
    fn restore(&self, id: &SnapshotId, op: &OpId) -> Outcome;
    fn usage_bytes(&self) -> u64;
}

pub trait InventoryBackend {
    fn devices(&self) -> Result<Vec<DeviceInfo>, Outcome>;
    fn resources(&self) -> Result<Resources, Outcome>;
    fn bound_driver(&self, device: &UnitId) -> Result<Option<DriverRef>, Outcome>;
    fn bind(&self, device: &UnitId, driver: &DriverRef, op: &OpId) -> Outcome;
    fn unbind(&self, device: &UnitId, op: &OpId) -> Outcome;
}
