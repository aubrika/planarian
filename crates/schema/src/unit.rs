//! Units, desired state, the graph, risk metadata and probes (§8).

use crate::ids::{Millis, ProbeId, Timestamp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// Written `<kind>:<name>` for system scope and `<kind>@<uid>[/<session>]:<name>`
/// for user scope, e.g. `service:sshd`, `service@1000:pipewire`,
/// `service:external:gym-upstream`. Serialized in that form so it can key JSON maps.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitId {
    pub kind: UnitKind,
    pub name: String,
    pub scope: Scope,
}

/// `Target` is not in §8; added for units such as `graphical-session` (G4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum UnitKind {
    Service,
    Device,
    Target,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Scope {
    System,
    User { uid: u32, session: Option<String> },
}

impl UnitId {
    pub fn system(kind: UnitKind, name: &str) -> UnitId {
        UnitId { kind, name: name.to_owned(), scope: Scope::System }
    }

    pub fn service(name: &str) -> UnitId {
        UnitId::system(UnitKind::Service, name)
    }

    pub fn device(name: &str) -> UnitId {
        UnitId::system(UnitKind::Device, name)
    }

    pub fn target(name: &str) -> UnitId {
        UnitId::system(UnitKind::Target, name)
    }
}

impl fmt::Display for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            UnitKind::Service => "service",
            UnitKind::Device => "device",
            UnitKind::Target => "target",
        };
        match &self.scope {
            Scope::System => write!(f, "{kind}:{}", self.name),
            Scope::User { uid, session: None } => write!(f, "{kind}@{uid}:{}", self.name),
            Scope::User { uid, session: Some(s) } => write!(f, "{kind}@{uid}/{s}:{}", self.name),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseUnitIdError(pub String);

impl FromStr for UnitId {
    type Err = ParseUnitIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseUnitIdError(s.to_owned());
        let (head, name) = s.split_once(':').ok_or_else(err)?;
        if name.is_empty() {
            return Err(err());
        }
        let (kind, scope) = match head.split_once('@') {
            None => (head, Scope::System),
            Some((kind, user)) => {
                let (uid, session) = match user.split_once('/') {
                    None => (user, None),
                    Some((uid, session)) => (uid, Some(session.to_owned())),
                };
                (kind, Scope::User { uid: uid.parse().map_err(|_| err())?, session })
            }
        };
        let kind = match kind {
            "service" => UnitKind::Service,
            "device" => UnitKind::Device,
            "target" => UnitKind::Target,
            _ => return Err(err()),
        };
        Ok(UnitId { kind, name: name.to_owned(), scope })
    }
}

impl Serialize for UnitId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for UnitId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(|e: ParseUnitIdError| serde::de::Error::custom(format!("bad unit id {:?}", e.0)))
    }
}

// ---------- Actors ----------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Actor {
    Daemon,
    Watchdog,
    User { uid: u32 },
    Model(crate::ids::ModelId),
}

// ---------- Desired ----------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Condition {
    Always,
    /// logind reports a session of class `user` with a seat, or a remote user
    /// session; greeter, `manager` and background sessions never count (§10).
    SessionEstablished {
        uid: Option<u32>,
    },
    DeviceConnected(UnitId),
    OnAcPower,
    OnBattery,
    All(Vec<Condition>),
    Any(Vec<Condition>),
}

impl Condition {
    /// `atoms` is the set of atomic conditions that hold right now.
    pub fn holds(&self, atoms: &BTreeSet<Condition>) -> bool {
        match self {
            Condition::Always => true,
            Condition::All(cs) => cs.iter().all(|c| c.holds(atoms)),
            Condition::Any(cs) => cs.iter().any(|c| c.holds(atoms)),
            Condition::SessionEstablished { uid: None } => {
                atoms.iter().any(|a| matches!(a, Condition::SessionEstablished { .. }))
            }
            atom => atoms.contains(atom),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DesiredStatus {
    Running,
    Stopped,
    Bound,
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Desired {
    pub status: DesiredStatus,
    pub when: Condition,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Suppression {
    pub unit: UnitId,
    pub until: Until,
    pub reason: String,
    /// Always overwritten by the daemon from the caller's credentials (§11).
    pub by: Actor,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Until {
    At(Timestamp),
    NextBoot,
    Explicit,
}

impl Suppression {
    /// `NextBoot` suppressions are dropped by state assembly on boot, so here they hold.
    pub fn holds_at(&self, now: Timestamp) -> bool {
        match self.until {
            Until::At(t) => now < t,
            Until::NextBoot | Until::Explicit => true,
        }
    }
}

// ---------- Graph ----------

/// Confidence in per-mille (0..=1000). Used instead of `f32` to stay in the
/// Verus subset and keep comparisons exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// After=/Before=: never followed in diagnosis.
    Ordering,
    /// Wants=: weak; never a root cause for the wanting unit.
    Wants,
    /// Requires=/BindsTo=/Requisite= or manifest: functional prerequisite.
    Requires,
    /// Manifest or learned; may form cycles (§13).
    Diagnostic { confidence: Confidence },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge {
    pub from: UnitId,
    pub to: UnitId,
    pub kind: EdgeKind,
    pub origin: EdgeOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EdgeOrigin {
    SystemdRequires,
    SystemdWants,
    SystemdAfter,
    Manifest,
    Learned,
}

// ---------- Risk metadata ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Sensitivity {
    Routine,
    Security,
    UserData,
    External,
    Core,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sensitivities(pub BTreeSet<Sensitivity>);

impl Sensitivities {
    pub fn of(items: &[Sensitivity]) -> Sensitivities {
        Sensitivities(items.iter().copied().collect())
    }

    pub fn contains(&self, s: Sensitivity) -> bool {
        self.0.contains(&s)
    }

    /// True when nothing but `Routine` is present (an empty set counts as Routine).
    pub fn only_routine(&self) -> bool {
        self.0.iter().all(|s| *s == Sensitivity::Routine)
    }

    pub fn union(&self, other: &Sensitivities) -> Sensitivities {
        Sensitivities(self.0.union(&other.0).copied().collect())
    }
}

/// Ordered by how much it costs the user; §11 compares with `>=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Disruption {
    None,
    Brief,
    SessionLoss,
    DataInterruption,
    ConnectivityLoss,
}

/// Ordered from most to least reversible (§13 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Recovery {
    Idempotent,
    Revertible,
    NonReversible,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemdRestartPolicy {
    pub restart: bool,
    pub restart_sec: Millis,
    pub start_limit_burst: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitDef {
    pub id: UnitId,
    pub desired: Desired,
    pub edges: Vec<Edge>,
    pub sensitivity: Sensitivities,
    pub restart_disruption: Disruption,
    pub probes: Vec<ProbeDef>,
    pub synonyms: Vec<String>,
    pub systemd_restart: Option<SystemdRestartPolicy>,
}

pub type UnitDefs = BTreeMap<UnitId, UnitDef>;

// ---------- Health ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeDef {
    pub id: ProbeId,
    pub kind: ProbeKind,
    pub timeout: Millis,
    pub origin: ProbeOrigin,
    /// Readiness feeds Running/Unknown; Diagnostic never does.
    pub role: ProbeRole,
    pub cadence: Cadence,
    pub cost: ProbeCost,
    pub side_effects: SideEffects,
    /// What a pass actually shows, in plain words.
    pub establishes: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProbeOrigin {
    Canonical,
    User,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeKind {
    SystemdActive,
    Tcp {
        addr: String,
    },
    Http {
        url: String,
        status: u16,
    },
    Exec {
        argv: Vec<String>,
        sandbox: ProbeSandbox,
    },
    /// Free space on the filesystem holding `path`: at least `min_bytes` and at
    /// least `min_permille` of its size (§10 storage units). Not in §8.
    FreeSpace {
        path: String,
        min_bytes: u64,
        min_permille: u16,
    },
    /// A systemd target in the user's session reached within `within` of that
    /// session's creation (§9 graphical-session). Evaluated by `state` from logind
    /// and systemd together; bound to one session id (§10). Not in §8.
    SessionTarget {
        target: String,
        within: Millis,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSandbox {
    pub uid: u32,
    pub caps: Vec<String>,
    pub max_output: u32,
    pub cpu_ms: u32,
    pub network: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProbeRole {
    Readiness,
    Diagnostic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cadence {
    EveryTick,
    Every(Millis),
    OnEvent,
    OnDemand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProbeCost {
    Trivial,
    Cheap,
    WakesHardware,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SideEffects {
    None,
    /// Bounded read-only I/O, permitted for Readiness probes at the declared rate.
    Measurement {
        bytes_max: u32,
        per: Millis,
    },
    Audible,
    Visible,
    RemoteStateChange,
    Disk,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeContractError {
    /// A Readiness probe with side effects other than None or Measurement.
    ReadinessWithSideEffects(ProbeId),
    /// A side-effecting probe that is not OnDemand (§18.4).
    SideEffectsOnCadence(ProbeId),
}

impl ProbeDef {
    /// The parts of the probe contract (§10) that are decidable from the definition.
    pub fn check_contract(&self) -> Result<(), ProbeContractError> {
        let benign = matches!(self.side_effects, SideEffects::None | SideEffects::Measurement { .. });
        if !benign && self.role == ProbeRole::Readiness {
            return Err(ProbeContractError::ReadinessWithSideEffects(self.id.clone()));
        }
        if !benign && self.cadence != Cadence::OnDemand {
            return Err(ProbeContractError::SideEffectsOnCadence(self.id.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeResult {
    Pass,
    Fail(String),
    Timeout,
    Error(String),
}

/// `probe` is not in §8; status derivation cannot match evidence to probes without it (G11).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub probe: ProbeId,
    pub result: ProbeResult,
    pub at: Timestamp,
    pub stale_after: Millis,
}

impl Evidence {
    pub fn fresh_at(&self, now: Timestamp) -> bool {
        now <= self.at.plus(self.stale_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_id_roundtrip() {
        for s in [
            "service:sshd",
            "device:fs-root",
            "target:graphical-session",
            "service@1000:pipewire",
            "service@1000/c2:pipewire",
            "service:external:gym-upstream",
        ] {
            let id: UnitId = s.parse().unwrap();
            assert_eq!(id.to_string(), s);
        }
        let ext: UnitId = "service:external:gym-upstream".parse().unwrap();
        assert_eq!(ext.name, "external:gym-upstream");
        assert!("bogus:x".parse::<UnitId>().is_err());
        assert!("service:".parse::<UnitId>().is_err());
        assert!("service@x:y".parse::<UnitId>().is_err());
    }

    #[test]
    fn unit_id_keys_json_maps() {
        let mut m = BTreeMap::new();
        m.insert(UnitId::service("sshd"), 1);
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"service:sshd":1}"#);
        assert_eq!(serde_json::from_str::<BTreeMap<UnitId, i32>>(&json).unwrap(), m);
    }

    #[test]
    fn conditions() {
        let mut atoms = BTreeSet::new();
        assert!(Condition::Always.holds(&atoms));
        assert!(!Condition::SessionEstablished { uid: None }.holds(&atoms));
        atoms.insert(Condition::SessionEstablished { uid: Some(1000) });
        assert!(Condition::SessionEstablished { uid: None }.holds(&atoms));
        assert!(Condition::SessionEstablished { uid: Some(1000) }.holds(&atoms));
        assert!(!Condition::SessionEstablished { uid: Some(1001) }.holds(&atoms));
        let any = Condition::Any(vec![Condition::OnBattery, Condition::SessionEstablished { uid: Some(1000) }]);
        assert!(any.holds(&atoms));
        assert!(!Condition::All(vec![Condition::OnBattery, Condition::Always]).holds(&atoms));
    }

    fn probe(role: ProbeRole, side_effects: SideEffects, cadence: Cadence) -> ProbeDef {
        ProbeDef {
            id: ProbeId("p".into()),
            kind: ProbeKind::SystemdActive,
            timeout: Millis::secs(10),
            origin: ProbeOrigin::Canonical,
            role,
            cadence,
            cost: ProbeCost::Trivial,
            side_effects,
            establishes: String::new(),
        }
    }

    #[test]
    fn probe_contract() {
        let m = SideEffects::Measurement { bytes_max: 4096, per: Millis::secs(5) };
        assert!(probe(ProbeRole::Readiness, m, Cadence::EveryTick).check_contract().is_ok());
        assert!(probe(ProbeRole::Readiness, SideEffects::Audible, Cadence::OnDemand).check_contract().is_err());
        assert!(probe(ProbeRole::Diagnostic, SideEffects::Audible, Cadence::EveryTick).check_contract().is_err());
        assert!(probe(ProbeRole::Diagnostic, SideEffects::Audible, Cadence::OnDemand).check_contract().is_ok());
    }
}
