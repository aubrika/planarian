//! Units, desired state, the graph, risk metadata and probes (§8).

use crate::ids::{Millis, ProbeId, Timestamp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use vstd::prelude::*;

// The unit and risk types `policy` reads, visible to its proofs.
verus! {

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum UnitKind {
    Service,
    Device,
    Target,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Scope {
    System,
    User { uid: u32, session: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Actor {
    Daemon,
    Watchdog,
    /// Filled from `SO_PEERCRED` → pid → logind (§10). `session` is None only
    /// for callers outside any logind session (a root timer), which never
    /// satisfy an "own session" floor; `seat` is None for SSH and other remote
    /// sessions, which are never local.
    User { uid: u32, session: Option<String>, seat: Option<String>, active: bool },
    Model(crate::ids::ModelId),
    /// Reserved: remote principals via a relay; in Phase A, only a local agent
    /// the journal has no start for (it holds nothing; §11).
    Agent(crate::ids::PrincipalId),
    /// The actor of an `Inferred` override (§11): never a caller, never authorized.
    Unattributed,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Override {
    pub unit: UnitId,
    pub desired: OverrideDesired,
    pub until: Until,
    pub reason: String,
    /// Always overwritten by the daemon from the caller's credentials (§11).
    /// `Actor::Unattributed` exactly when `attribution == Inferred`.
    pub by: Actor,
    pub attribution: Attribution,
    /// An `Inferred` override a user has acknowledged: the console stops
    /// listing it; it still holds until it ends (§11, B-11).
    #[serde(default)]
    pub acknowledged: bool,
}

/// What the override holds the unit to (§8). A `Stopped` override also undoes
/// a generation activation that starts the unit again (principle 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum OverrideDesired {
    /// Do not repair; take no action.
    LeaveAlone,
    /// Stop or kill a service.
    Stopped,
    /// Disable or mask.
    Absent,
    /// Unmount, eject or unbind a device.
    Detected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Attribution {
    /// Reached Planarian with the actor's identity before it took effect.
    Attested,
    /// The unattributed residue (§11): recorded as an inference, never as fact.
    Inferred,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Until {
    At(Timestamp),
    NextBoot,
    Explicit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Sensitivity {
    Routine,
    Security,
    UserData,
    External,
    Core,
}

/// Ordered by how much it costs the user; §11 compares with `>=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Disruption {
    None,
    Brief,
    SessionLoss,
    DataInterruption,
    ConnectivityLoss,
}

/// Ordered from most to least reversible (§13 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Recovery {
    Idempotent,
    Revertible,
    NonReversible,
}

/// A set of `Sensitivity` values, as flags so the proofs can read it.
/// Serialized as the list of members in declaration order, as the
/// `BTreeSet` it replaces was.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sensitivities {
    pub routine: bool,
    pub security: bool,
    pub user_data: bool,
    pub external: bool,
    pub core: bool,
}

impl Sensitivities {
    pub open spec fn has(self, s: Sensitivity) -> bool {
        match s {
            Sensitivity::Routine => self.routine,
            Sensitivity::Security => self.security,
            Sensitivity::UserData => self.user_data,
            Sensitivity::External => self.external,
            Sensitivity::Core => self.core,
        }
    }

    /// Nothing but `Routine` is present (an empty set counts as Routine).
    pub open spec fn routine_only(self) -> bool {
        !self.security && !self.user_data && !self.external && !self.core
    }

    pub fn contains(&self, s: Sensitivity) -> (r: bool)
        ensures r == self.has(s),
    {
        match s {
            Sensitivity::Routine => self.routine,
            Sensitivity::Security => self.security,
            Sensitivity::UserData => self.user_data,
            Sensitivity::External => self.external,
            Sensitivity::Core => self.core,
        }
    }

    pub fn only_routine(&self) -> (r: bool)
        ensures r == self.routine_only(),
    {
        !self.security && !self.user_data && !self.external && !self.core
    }

    pub fn union(&self, other: &Sensitivities) -> (r: Sensitivities)
        ensures forall|s: Sensitivity| #[trigger] r.has(s) == (self.has(s) || other.has(s)),
    {
        Sensitivities {
            routine: self.routine || other.routine,
            security: self.security || other.security,
            user_data: self.user_data || other.user_data,
            external: self.external || other.external,
            core: self.core || other.core,
        }
    }

    pub fn insert(&mut self, s: Sensitivity)
        ensures forall|t: Sensitivity| #[trigger] final(self).has(t) == (old(self).has(t) || t == s),
    {
        match s {
            Sensitivity::Routine => self.routine = true,
            Sensitivity::Security => self.security = true,
            Sensitivity::UserData => self.user_data = true,
            Sensitivity::External => self.external = true,
            Sensitivity::Core => self.core = true,
        }
    }
}

} // verus!

impl Actor {
    /// A user outside any logind session (a root timer, a test). Never local,
    /// never "own session".
    pub fn user(uid: u32) -> Actor {
        Actor::User { uid, session: None, seat: None, active: false }
    }

    /// A user in the active local session `session` on `seat0`.
    pub fn local(uid: u32, session: &str) -> Actor {
        Actor::User { uid, session: Some(session.into()), seat: Some("seat0".into()), active: true }
    }

    /// The principal behind this actor (§11). A human is their uid; the
    /// non-human actors of Phase A have fixed ids above every uid.
    pub fn principal(&self) -> crate::ids::PrincipalId {
        use crate::ids::PrincipalId;
        const BASE: u64 = 1 << 32;
        match self {
            Actor::User { uid, .. } => PrincipalId(*uid as u64),
            Actor::Daemon => PrincipalId(BASE),
            Actor::Watchdog => PrincipalId(BASE + 1),
            Actor::Model(_) => PrincipalId(BASE + 2),
            Actor::Unattributed => PrincipalId(BASE + 3),
            Actor::Agent(p) => *p,
        }
    }

    pub fn uid(&self) -> Option<u32> {
        match self {
            Actor::User { uid, .. } => Some(*uid),
            _ => None,
        }
    }
}

impl Override {
    /// An attested override: the action reached Planarian with `by`'s identity first.
    pub fn attested(unit: UnitId, desired: OverrideDesired, until: Until, reason: String, by: Actor) -> Override {
        Override { unit, desired, until, reason, by, attribution: Attribution::Attested, acknowledged: false }
    }
}

impl Sensitivities {
    pub const ALL: [Sensitivity; 5] =
        [Sensitivity::Routine, Sensitivity::Security, Sensitivity::UserData, Sensitivity::External, Sensitivity::Core];

    pub fn of(items: &[Sensitivity]) -> Sensitivities {
        let mut out = Sensitivities::default();
        for s in items {
            out.insert(*s);
        }
        out
    }

    /// Members in declaration order.
    pub fn members(&self) -> Vec<Sensitivity> {
        Self::ALL.into_iter().filter(|s| self.contains(*s)).collect()
    }
}

impl Serialize for Sensitivities {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.members().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Sensitivities {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Sensitivities::of(&Vec::<Sensitivity>::deserialize(d)?))
    }
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

// ---------- Desired ----------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Condition {
    Always,
    /// logind reports a session of class `user` with a seat, or a remote user
    /// session; greeter, `manager` and background sessions never count (§10).
    /// `seated` asks for a session at a seat: the graphical expectation
    /// (S05), which an SSH-only login never carries. As an atom (what holds
    /// now), it says whether that session has a seat.
    SessionEstablished {
        uid: Option<u32>,
        #[serde(default)]
        seated: bool,
    },
    DeviceConnected(UnitId),
    OnAcPower,
    OnBattery,
    /// Quiet mode (§12f; signals in §10): a GameMode client, a gamescope
    /// session, a fullscreen surface holding an idle-inhibitor, or Do Not Disturb.
    Foreground {
        session: String,
    },
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
            Condition::SessionEstablished { uid, seated } => atoms.iter().any(|a| {
                matches!(a, Condition::SessionEstablished { uid: u, seated: s }
                    if (uid.is_none() || u == uid) && (*s || !*seated))
            }),
            atom => atoms.contains(atom),
        }
    }

    /// The condition asks for a seated session somewhere (S05).
    pub fn needs_seat(&self) -> bool {
        match self {
            Condition::SessionEstablished { seated, .. } => *seated,
            Condition::All(cs) | Condition::Any(cs) => cs.iter().any(Condition::needs_seat),
            _ => false,
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

impl Override {
    /// `NextBoot` overrides are dropped by state assembly on boot, so here they hold.
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
    /// How long after the unit comes up a failing health probe is not yet a
    /// fault (it may still be starting). `None`: the daemon's default.
    #[serde(default)]
    pub startup_grace: Option<Millis>,
    /// A runtime-settable option (§12a) whose other values can restore this
    /// unit: `wifi.network` for a Wi-Fi interface. When it diverges, the
    /// diagnoser may propose another value the backend says is available.
    #[serde(default)]
    pub runtime_repair: Option<String>,
    /// The manifest's `inferStops = false` (§11, B-11): a stop outside
    /// Planarian is a fault (restarted and alarmed), never inferred as a
    /// person's intent. Backup, sync and the desktop's own units.
    #[serde(default)]
    pub stops_are_faults: bool,
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
    DBus {
        service: String,
        path: String,
        method: String,
    },
    FilePresent {
        path: String,
    },
    /// Administrator-authored manifest entries only; flagged in the console and journal (§9).
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
        assert!(!Condition::SessionEstablished { uid: None, seated: false }.holds(&atoms));
        atoms.insert(Condition::SessionEstablished { uid: Some(1000), seated: false });
        assert!(Condition::SessionEstablished { uid: None, seated: false }.holds(&atoms));
        assert!(Condition::SessionEstablished { uid: Some(1000), seated: false }.holds(&atoms));
        assert!(!Condition::SessionEstablished { uid: Some(1001), seated: false }.holds(&atoms));
        let any = Condition::Any(vec![
            Condition::OnBattery,
            Condition::SessionEstablished { uid: Some(1000), seated: false },
        ]);
        assert!(any.holds(&atoms));
        assert!(!Condition::All(vec![Condition::OnBattery, Condition::Always]).holds(&atoms));
    }

    /// S05: an SSH-only session satisfies `SessionEstablished` but not the
    /// graphical expectation; a seated one satisfies both.
    #[test]
    fn only_a_seated_session_expects_a_desktop() {
        let seat = Condition::SessionEstablished { uid: None, seated: true };
        let mut atoms: BTreeSet<Condition> = [Condition::SessionEstablished { uid: Some(1000), seated: false }].into();
        assert!(!seat.holds(&atoms));
        assert!(Condition::SessionEstablished { uid: None, seated: false }.holds(&atoms));
        atoms.insert(Condition::SessionEstablished { uid: Some(1002), seated: true });
        assert!(seat.holds(&atoms));
        assert!(!Condition::SessionEstablished { uid: Some(1000), seated: true }.holds(&atoms));
        assert!(Condition::SessionEstablished { uid: Some(1002), seated: true }.holds(&atoms));
        assert!(Condition::All(vec![Condition::Always, seat]).needs_seat());
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
