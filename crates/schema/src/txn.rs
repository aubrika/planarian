//! Transactions, leases, approvals and incidents (§8).

use crate::ids::{
    GenerationId, Hash, IncidentId, JobId, Millis, PolicyVersion, SnapshotId, StorePath, Timestamp, TxnId,
};
use crate::state::UnitStatus;
use crate::transition::{ConfigDiff, DerivedFacts, DriverRef, Expectation, RecoveryStrategy, RejectReason, Transition};
use crate::unit::{Actor, DesiredStatus, UnitId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxnState {
    Prepared,
    Staged,
    Built,
    Activating,
    Checking,
    /// Boot entry written.
    Published,
    /// Override source promoted.
    Promoted,
    Committed,
    Reverting,
    Reverted,
    RecoveryFailed,
    /// Refused after Prepared (precondition, expired or invalidated approval, policy).
    Rejected(RejectReason),
    /// Withdrawn before any mutation.
    Cancelled(Actor),
}

impl TxnState {
    /// I12's terminal set.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TxnState::Committed
                | TxnState::Reverted
                | TxnState::RecoveryFailed
                | TxnState::Rejected(_)
                | TxnState::Cancelled(_)
        )
    }

    /// States in which no other transition may execute (I6).
    pub fn is_exclusive(&self) -> bool {
        matches!(self, TxnState::Activating | TxnState::Published | TxnState::Promoted | TxnState::Reverting)
    }

    /// Nothing has been mutated yet.
    pub fn is_pre_mutation(&self) -> bool {
        matches!(self, TxnState::Prepared | TxnState::Staged | TxnState::Built)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OwnerId {
    Daemon { pid: u32, boot_id: Hash },
    Watchdog { pid: u32, boot_id: Hash },
}

impl OwnerId {
    pub fn pid(&self) -> u32 {
        match self {
            OwnerId::Daemon { pid, .. } | OwnerId::Watchdog { pid, .. } => *pid,
        }
    }

    pub fn is_watchdog(&self) -> bool {
        matches!(self, OwnerId::Watchdog { .. })
    }
}

/// Exclusive ownership of a transaction (§12). `txn` is not in §8; the
/// backend fences on (txn, epoch), so the lease has to name its transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub txn: TxnId,
    pub owner: OwnerId,
    pub epoch: u64,
    pub worker_pid: Option<u32>,
    pub renewed: Timestamp,
    /// Supervisor jobs this owner submitted.
    pub jobs: Vec<JobId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxnId,
    pub state: TxnState,
    pub lease: Lease,
    /// NAR hash of the owner's source with the BASE override, at Prepared (§9).
    pub base_source: Option<Hash>,
    /// NAR hash of the candidate tree actually evaluated and built (§9).
    pub staged_source: Option<Hash>,
    pub base_override: Option<Hash>,
    pub candidate_override: Option<Hash>,
    /// `/nix/var/nix/gcroots/planarian/builds/<staged_source>`, adopted at Prepared (I3).
    pub gc_root: Option<String>,
    pub recovery: RecoveryStrategy,
    pub transition: Transition,
    pub facts: DerivedFacts,
    pub base: GenerationId,
    pub candidate: Option<(GenerationId, StorePath)>,
    pub policy: PolicyVersion,
    pub approval: Option<ApprovalToken>,
    pub snapshot: Option<SnapshotId>,
    pub expected: Expectation,
    pub started: Timestamp,
    /// The watchdog acts after this.
    pub deadline: Timestamp,
    /// Fixed at Prepared; authorized with the transaction.
    pub revert_to: GenerationId,
    /// For `BindDriver`: the driver bound at Prepared, rebound on revert (§12
    /// execution table). Not in §8 (G12).
    pub prior_driver: Option<DriverRef>,
    /// What the probe check needs, journaled so the watchdog can run it alone.
    pub check: CheckContext,
}

/// The manifest part of an evaluated generation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub units: crate::unit::UnitDefs,
    /// Per-user templates (`Scope::User { uid: 0 }`), instantiated per session.
    pub user_units: Vec<crate::unit::UnitDef>,
}

/// Recorded at Prepared (§12 step 4) for the Checking and revert probe runs:
/// the candidate's and the base's manifests, and every unit's status before.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckContext {
    pub candidate: Option<Manifest>,
    pub base: Manifest,
    pub pre: std::collections::BTreeMap<UnitId, UnitStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Succeeded,
    Failed(String),
    Partial(String),
    Unknown(String),
}

impl Outcome {
    /// `Partial` and `Unknown` are never success (§12 step 8).
    pub fn is_success(&self) -> bool {
        matches!(self, Outcome::Succeeded)
    }

    pub fn fenced() -> Outcome {
        Outcome::Failed("fenced".into())
    }

    pub fn is_fenced(&self) -> bool {
        matches!(self, Outcome::Failed(m) if m == "fenced")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// hash(transition, staged_source, candidate store path, base generation,
    /// policy version, cumulative-diff hash, derived facts, expected, revert_to,
    /// recovery strategy).
    pub bound_to: Hash,
    pub issued: Timestamp,
    pub expires: Timestamp,
    pub nonce: [u8; 16],
    pub used: bool,
}

pub const TOKEN_LIFETIME: Millis = Millis(24 * 3600 * 1000);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub applied: Vec<TxnId>,
    pub cumulative: ConfigDiff,
    pub policy: Option<PolicyVersion>,
}

// ---------- Incidents ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentState {
    Open,
    Cooldown {
        until: Timestamp,
    },
    /// Reported to the user; no autonomous action until `until` or a human acts.
    /// `until` is not in §8; without it the hold could not survive a restart.
    Escalated {
        until: Timestamp,
    },
    Closed,
    Regressed {
        count: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentKind {
    /// A divergence to repair.
    Repair,
    /// Three consecutive Unknowns (§10): re-observe through another Readiness
    /// probe; never a restart.
    Diagnostic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub id: IncidentId,
    pub kind: IncidentKind,
    pub target: UnitId,
    pub divergence: (DesiredStatus, UnitStatus),
    pub opened: Timestamp,
    pub attempts: Vec<(TxnId, Outcome)>,
    /// Persisted; survives daemon restart.
    pub budget_left: u8,
    pub state: IncidentState,
    pub backoff: Millis,
    /// Earliest time of the next attempt (backoff and defer-to-systemd).
    /// Not in §8; persisted so a restart does not reset the backoff.
    pub next_attempt: Timestamp,
    /// How often this target regressed within the window (§13).
    pub regressions: u8,
}
