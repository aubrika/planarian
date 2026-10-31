//! Backend contracts (§8). Generic parameters only; no `dyn` (§6).
//!
//! Every mutating call takes the `OpId` that was durably journaled before it
//! (§12). The OpId carries `(txn, epoch)`: the backend refuses the call with
//! `Outcome::fenced()` if that epoch is not the journal's current epoch for the
//! transaction, and tags the work it starts with the OpId so `jobs_tagged` can
//! find it later. This replaces the `&Lease` parameter in §8.

use crate::ids::{GenerationId, Hash, JobId, Millis, OpId, SnapshotId, StorePath, Timestamp};
use crate::state::{Observed, Resources};
use crate::transition::ActivationPlan;
use crate::transition::{DriverRef, EvaluatedGeneration, Value};
use crate::txn::Outcome;
use crate::unit::{ProbeDef, ProbeResult, UnitId};
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
    /// What switching to it would start, stop, restart and reload (dry-activate).
    pub activation: ActivationPlan,
}

/// How a unit's main process last ended, as the supervisor reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ending {
    /// It exited with this status.
    Exited(i32),
    /// A signal ended it (`systemctl stop` sends SIGTERM).
    Signal(i32),
    /// The kernel's OOM killer ended it (`Result=oom-kill`).
    OomKill,
}

impl Ending {
    /// §11 residue: a termination signal, which a person (or a stop job) sends,
    /// as opposed to a crash signal or an exit status. Owner decision Q5.
    pub fn is_termination(&self) -> bool {
        matches!(self, Ending::Signal(1 | 2 | 9 | 15))
    }
}

pub trait UnitBackend {
    fn observe(&self, id: &UnitId) -> Result<Observed, Outcome>;
    /// How the unit's main process last ended; None if the backend cannot say.
    fn ended_by(&self, _id: &UnitId) -> Option<Ending> {
        None
    }
    /// How many times systemd itself restarted the unit (`NRestarts`); None
    /// if the backend cannot say.
    fn auto_restarts(&self, _id: &UnitId) -> Option<u32> {
        None
    }
    /// The boot report's unit check (§10): active units whose definition does
    /// not come from the running generation (a file outside the store that is
    /// not a generator's).
    fn foreign_units(&self) -> Vec<String> {
        vec![]
    }
    fn list(&self) -> Result<Vec<UnitId>, Outcome>;
    /// Start an agent in a transient dynamic-uid unit (§11, §16). `by` is
    /// authenticated launcher metadata for admission/resource attribution.
    /// Authority is bound only after successful start to the returned unit
    /// instance, read back from the supervisor (I24).
    fn start_agent(&self, _name: &str, _argv: &[String], _by: u32) -> Result<InstanceId, Outcome> {
        Err(Outcome::Failed("this backend cannot start agents".into()))
    }
    /// Whether the named agent is still running; a name in use is refused.
    fn agent_running(&self, _name: &str) -> bool {
        false
    }
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
    /// The owner's files Nix cannot see now (untracked in a git flake), to
    /// report with the stale check: one added during the build was not
    /// there at staging (§9 step 1).
    fn untracked(&self, _owner: &PinnedSource) -> Vec<String> {
        vec![]
    }
    fn evaluate(&self, src: &StagedSource) -> Result<EvaluatedGeneration, Outcome>;
    /// Store-only; roots its own output.
    fn build(&self, eval: &EvaluatedGeneration) -> Result<Built, Outcome>;
    /// Derive activation consequences relative to the running generation and
    /// retain the exact selected store path through preparation and approval.
    /// A prior health verdict or equal manifests do not replace this evidence.
    fn preflight_existing(&self, _g: GenerationId, _path: &StorePath) -> Result<Built, Outcome> {
        Err(Outcome::Unknown("existing-generation activation evidence unavailable".into()))
    }
    /// Read and validate a remembered override's exact content for risk
    /// derivation; absence is unknown, never an empty configuration diff.
    fn read_override(&self, _hash: &Hash) -> Result<OverrideSet, Outcome> {
        Err(Outcome::Unknown("generation override evidence unavailable".into()))
    }

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
    /// The boot-only path (§12 step 7, §12f): `g` boots once, at the next
    /// boot; `keep` stays the default. Non-success may still have effects;
    /// callers must reconcile under their durable publication intent.
    fn publish_boot_once(&self, _g: GenerationId, _keep: GenerationId, _op: &OpId) -> Outcome {
        Outcome::Failed("this boot loader cannot boot a generation once".into())
    }
    /// Withdraw any one-shot selection and restore the eligible default.
    /// Success proves both effects; non-success leaves a recovery obligation.
    fn withdraw_boot_once(&self, _keep: GenerationId, _op: &OpId) -> Outcome {
        Outcome::Unknown("this boot loader cannot prove one-shot withdrawal".into())
    }
    /// Who created generation `g` and when (its profile link's owner and
    /// time): the provenance of a rebuild made outside Planarian (§15).
    fn created_by(&self, _g: GenerationId) -> Option<(u32, Timestamp)> {
        None
    }
    /// The generation a one-shot entry will boot next, if one is pending.
    fn one_shot_pending(&self) -> Result<Option<GenerationId>, Outcome> {
        Err(Outcome::Unknown("this boot loader has no one-shot entries".into()))
    }
    fn protect(&self, g: GenerationId, op: &OpId) -> Outcome;
    fn cancel(&self, job: &JobId, op: &OpId) -> Outcome;
    /// Atomically replace the live override file with the content whose hash is
    /// `to`, but only if its current hash is `from`. Idempotent: if it already
    /// hashes to `to`, succeed without writing.
    fn swap_override(&self, from: &Hash, to: &Hash, op: &OpId) -> Outcome;

    // Bookkeeping beyond §8 that the protocol needs.
    /// The system store path of a known generation.
    fn path_of(&self, g: GenerationId) -> Result<StorePath, Outcome>;
    /// Evaluate an already-built generation from its store path (its exported
    /// manifest), for SwitchGeneration / Revert / Rollback.
    fn evaluate_built(&self, path: &StorePath) -> Result<EvaluatedGeneration, Outcome>;
    /// The live override set and its content hash.
    fn read_overrides(&self) -> Result<(OverrideSet, Hash), Outcome>;
    /// Keep override content addressable by hash, so `swap_override` can write it.
    fn remember_override(&self, set: &OverrideSet) -> Result<Hash, Outcome>;
    /// The override content recorded for a generation when it was committed.
    fn override_for(&self, g: GenerationId) -> Result<Option<Hash>, Outcome>;
    fn record_override(&self, g: GenerationId, hash: &Hash) -> Result<(), Outcome>;
    /// Remove a GC root symlink this backend created.
    fn release_root(&self, root: &str) -> bool;
    /// Collect generations under the §12b bounds (`gc::plan`), never touching
    /// `protect` (I3), then collect store garbage. Mutating.
    fn collect_garbage(&self, protect: &[GenerationId], emergency: bool, op: &OpId) -> Outcome;
    /// What `collect_garbage` would delete now. Read-only.
    fn gc_plan(&self, protect: &[GenerationId], emergency: bool) -> Result<crate::gc::GcPlan, Outcome>;
    /// The last collection's result.
    fn space_report(&self) -> Option<crate::gc::SpaceReport>;
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

pub trait ProbeBackend {
    /// Run probes concurrently, each in its sandbox, each killed at its timeout
    /// (§10). One result per job, in order. `FreeSpace` probes are answered
    /// here too; `SystemdActive` and `SessionTarget` are evaluated by `state`.
    fn run_batch(&self, jobs: &[(UnitId, ProbeDef)]) -> Vec<ProbeResult>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub uid: u32,
    /// logind class: `user`, `greeter`, `lock-screen`, `background`, `manager`, …
    pub class: String,
    pub seat: Option<String>,
    pub remote: bool,
    /// The backend identified an eligible graphical session (logind Type=x11
    /// or wayland, State=active or online). Missing historical evidence is
    /// false: an authenticated login alone never implies a compositor.
    #[serde(default)]
    pub graphical: bool,
    pub created: Timestamp,
    /// logind `State=active`: the session in the foreground of its seat.
    #[serde(default)]
    pub active: bool,
    /// logind `IdleHint`: nobody has used it for a while.
    #[serde(default)]
    pub idle: bool,
}

impl SessionInfo {
    /// §10: only `user`-class sessions with a seat, or remote user sessions, count.
    pub fn establishes(&self) -> bool {
        self.class == "user" && (self.seat.is_some() || self.remote)
    }

    /// Graphical readiness is expected for a local seated user desktop. Locked
    /// and backgrounded desktops remain eligible; greeters, SSH/TTY-only and
    /// closing sessions do not create a compositor expectation.
    pub fn graphical_establishes(&self) -> bool {
        self.establishes() && self.graphical && self.seat.is_some() && !self.remote
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerSource {
    Ac,
    Battery,
}

pub trait SessionBackend {
    fn sessions(&self) -> Result<Vec<SessionInfo>, Outcome>;
    fn power(&self) -> Option<PowerSource>;
    /// Whether a compositor runs in this session's own cgroup (§9); None if
    /// the backend cannot see.
    fn compositor_running(&self, _s: &SessionInfo) -> Option<bool> {
        None
    }
    /// Sessions in which foreground work holds (§10: a GameMode client, a
    /// gamescope session, …): `Condition::Foreground`.
    fn foreground(&self) -> Vec<String> {
        vec![]
    }
}

/// The core-owned runtime-settable options (§12a).
pub trait RuntimeOptionBackend {
    fn get(&self, path: &str) -> Option<crate::transition::Value>;
    /// `Outcome::Failed("no live mechanism")` when the option can only be
    /// changed through its write-back.
    fn set(&self, path: &str, value: &crate::transition::Value, op: &OpId) -> Outcome;
    /// Other values the option could take right now (for `wifi.network`:
    /// known networks in range, besides the current one).
    fn alternatives(&self, path: &str) -> Vec<crate::transition::Value> {
        let _ = path;
        vec![]
    }
}

pub trait ProcessBackend {
    /// SIGTERM, then SIGKILL, the process group via pidfd; true once confirmed gone.
    fn kill_group(&self, pid: u32) -> bool;
    fn alive(&self, pid: u32) -> bool;
}

pub trait Clock {
    /// Wall-clock time: for what people see and records compared across boots.
    fn now(&self) -> Timestamp;
    /// Milliseconds on `CLOCK_BOOTTIME`: for everything that does not survive
    /// a reboot (approval tokens, leases, cooldowns, windows; §12h). Moving
    /// the wall clock never moves it.
    fn boot_now(&self) -> Timestamp;
    fn sleep(&self, d: Millis);
}

/// Every backend the system needs, as one generic parameter (§6: generics, no
/// `dyn`). The daemon and the watchdog instantiate it with the real backends;
/// the gym, with fakes.
pub trait Backends {
    type Units: UnitBackend;
    /// Cloned onto a worker thread for the slow part of planning a change.
    type Gens: GenerationBackend + Clone + Send + 'static;
    type Inv: InventoryBackend;
    type Probes: ProbeBackend;
    type Sessions: SessionBackend;
    type Runtime: RuntimeOptionBackend;
    type Procs: ProcessBackend;
    type Clock: Clock;

    fn units(&self) -> &Self::Units;
    fn generations(&self) -> &Self::Gens;
    fn inventory(&self) -> &Self::Inv;
    fn probes(&self) -> &Self::Probes;
    fn sessions(&self) -> &Self::Sessions;
    fn runtime(&self) -> &Self::Runtime;
    fn processes(&self) -> &Self::Procs;
    fn clock(&self) -> &Self::Clock;
}

/// An agent's name: 1-32 of `a-z`, `0-9` and `-`, not starting with `-`.
pub fn valid_agent_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One start of an agent's unit: its systemd InvocationID (I24). The name
/// alone never identifies an agent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InstanceId(pub [u8; 16]);

impl InstanceId {
    /// From systemd's form (32 hex digits, as `InvocationID` and the
    /// cgroup's `trusted.invocation_id` carry it) or the 16 raw bytes.
    pub fn parse(b: &[u8]) -> Option<InstanceId> {
        if b.len() == 16 {
            let raw: [u8; 16] = b.try_into().ok()?;
            return (raw != [0; 16]).then_some(InstanceId(raw));
        }
        let b = b.strip_suffix(b"\n").unwrap_or(b);
        let s = std::str::from_utf8(b).ok()?.trim();
        if s.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        (out != [0; 16]).then_some(InstanceId(out))
    }
}

/// The unit an agent runs in (§11, §16).
pub fn agent_unit(name: &str) -> String {
    format!("planarian-agent-{name}")
}

#[cfg(test)]
mod instance_tests {
    use super::InstanceId;

    #[test]
    fn instance_evidence_rejects_zero_and_preserves_raw_newline_bytes() {
        assert_eq!(InstanceId::parse(&[0; 16]), None);
        assert_eq!(InstanceId::parse(b"00000000000000000000000000000000"), None);
        let mut raw = [1; 16];
        raw[15] = b'\n';
        assert_eq!(InstanceId::parse(&raw), Some(InstanceId(raw)));
        assert_eq!(InstanceId::parse(b"0101010101010101010101010101010a\n"), Some(InstanceId(raw)));
    }
}
