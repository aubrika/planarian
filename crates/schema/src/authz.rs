//! Principals, capabilities and failure posture (§8, §11, §12d).

use crate::ids::{PrincipalId, TxnId};
use crate::unit::Actor;
use serde::{Deserialize, Serialize};
use vstd::prelude::*;

// The authorization types `policy` reads, visible to its proofs.
verus! {

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub enum Capability {
    /// Act on units in one's own `Scope::User`.
    OwnScope,
    /// Act on units in `services.planarian.userControllable`.
    UserControllable,
    Administrator,
    /// Approve others' AskFirst proposals within one's other capabilities (I19).
    Approve,
    /// Propose catalog / model-catalog entries (the only non-human grants in B).
    Catalog,
    ModelCatalog,
    /// Human-only through B; `Merge` needs two distinct approvers.
    Manifest,
    Merge,
}

/// A set of `Capability` values, as flags so the proofs can read it (as
/// `Sensitivities`). Serialized as the list of members in declaration order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capabilities {
    pub own_scope: bool,
    pub user_controllable: bool,
    pub administrator: bool,
    pub approve: bool,
    pub catalog: bool,
    pub model_catalog: bool,
    pub manifest: bool,
    pub merge: bool,
}

impl Capabilities {
    pub open spec fn has(self, c: Capability) -> bool {
        match c {
            Capability::OwnScope => self.own_scope,
            Capability::UserControllable => self.user_controllable,
            Capability::Administrator => self.administrator,
            Capability::Approve => self.approve,
            Capability::Catalog => self.catalog,
            Capability::ModelCatalog => self.model_catalog,
            Capability::Manifest => self.manifest,
            Capability::Merge => self.merge,
        }
    }

    pub fn contains(&self, c: Capability) -> (r: bool)
        ensures r == self.has(c),
    {
        match c {
            Capability::OwnScope => self.own_scope,
            Capability::UserControllable => self.user_controllable,
            Capability::Administrator => self.administrator,
            Capability::Approve => self.approve,
            Capability::Catalog => self.catalog,
            Capability::ModelCatalog => self.model_catalog,
            Capability::Manifest => self.manifest,
            Capability::Merge => self.merge,
        }
    }
}

/// Computed by the daemon for each call from `SO_PEERCRED`, logind, group
/// membership and journaled grants. Never read from a proposal (I14).
#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Authorization {
    pub principal: PrincipalId,
    pub actor: Actor,
    pub capabilities: Capabilities,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
#[verifier::external_derive]
pub struct Grant {
    pub to: PrincipalId,
    pub capability: Capability,
    pub approved_by: PrincipalId,
    pub txn: TxnId,
}

} // verus!

/// The failure posture, declared in the generation (§12d). Phase A ships Standard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Posture {
    Relaxed,
    #[default]
    Standard,
    Guarded,
    Sealed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailureClass {
    /// `planariad` did not reach ready within the boot-ready timeout, or was masked or stopped.
    Absent,
    /// Reached ready, then died and exhausted its restart budget.
    Crashed,
    /// Core hash, journal chain, boot report or signature check failed.
    Integrity,
}

impl Capabilities {
    pub fn of(items: &[Capability]) -> Capabilities {
        let mut c = Capabilities::default();
        for i in items {
            match i {
                Capability::OwnScope => c.own_scope = true,
                Capability::UserControllable => c.user_controllable = true,
                Capability::Administrator => c.administrator = true,
                Capability::Approve => c.approve = true,
                Capability::Catalog => c.catalog = true,
                Capability::ModelCatalog => c.model_catalog = true,
                Capability::Manifest => c.manifest = true,
                Capability::Merge => c.merge = true,
            }
        }
        c
    }

    pub fn members(&self) -> Vec<Capability> {
        use Capability::*;
        [OwnScope, UserControllable, Administrator, Approve, Catalog, ModelCatalog, Manifest, Merge]
            .into_iter()
            .filter(|c| self.contains(*c))
            .collect()
    }
}

impl Serialize for Capabilities {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.members().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Capabilities::of(&Vec::<Capability>::deserialize(d)?))
    }
}
