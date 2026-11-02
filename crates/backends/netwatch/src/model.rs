//! What the kernel attributed to whom, and what it means (§12d).

use crate::contract::FRESH_SECS;
use planarian_schema::UnitId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Who made a change: a unit (its cgroup), or nobody the kernel could name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Owner {
    Unit(UnitId),
    Unattributed,
}

/// The kind of object a netlink message touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ChangeKind {
    Interface,
    Route,
    Rule,
    Dns,
    Proxy,
    Firewall,
}

/// One attributed change: `object` names what was touched (an interface, a
/// route prefix, a rule, an nft table or chain), so a later removal of the
/// same object undoes it. `steers` is whether it currently steers traffic
/// (§12d: a default or all-covering route, a catch-all rule, DNS on the
/// unit's interface, the system proxy, a dropping or redirecting firewall
/// rule); an interface by itself steers nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub owner: Owner,
    pub kind: ChangeKind,
    pub object: String,
    /// The interface the object belongs to or routes out of, if any.
    pub iface: Option<String>,
    pub steers: bool,
    /// The object was deleted (a route or rule removed, an interface gone).
    pub removed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
}

/// A unit's footprint as the files carry it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Footprint {
    /// When it was last confirmed, in [`crate::CLOCK`] seconds.
    pub at: u64,
    pub protecting: bool,
    pub ifaces: BTreeSet<String>,
    pub endpoints: BTreeSet<Endpoint>,
    /// A lost event may have touched this unit.
    pub unattributed: bool,
}

/// The watch's state, as `.watch` carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchState {
    /// All probes attached and events flowing, confirmed at this time.
    Attached { at: u64 },
    /// A probe failed to attach, or the watch stopped, at this time.
    AttachFailed { at: u64 },
    /// No `.watch`, or one this crate cannot read: not known to be healthy.
    Unknown,
}

/// Everything the hold needs, read back from the files (or scripted by the
/// fake): the watch, the global unattributed marker, and the footprint of
/// each network tool, keyed by its file name ([`crate::file_name`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FootprintView {
    pub watch: WatchState,
    pub unattributed: bool,
    pub units: BTreeMap<String, Footprint>,
}

impl Default for FootprintView {
    fn default() -> Self {
        FootprintView { watch: WatchState::Unknown, unattributed: false, units: BTreeMap::new() }
    }
}

fn fresh(at: u64, now: u64) -> bool {
    now.saturating_sub(at) <= FRESH_SECS
}

impl FootprintView {
    /// §12d, fail closed: whether a failed network tool `unit` (its file
    /// name) counts as protecting traffic at `now`. True unless the watch is
    /// attached and fresh, no unattributed change stands, and the unit's
    /// footprint exists, is fresh, is not protecting and is not marked
    /// unattributed. The hold's script applies the same rules to the files.
    pub fn protecting_now(&self, unit: &str, now: u64) -> bool {
        let healthy = matches!(self.watch, WatchState::Attached { at } if fresh(at, now));
        if !healthy || self.unattributed {
            return true;
        }
        match self.units.get(unit) {
            None => true,
            Some(f) => !fresh(f.at, now) || f.protecting || f.unattributed,
        }
    }
}

/// The objects a unit has changed that still stand, and whether each one
/// steers traffic.
#[derive(Clone, Debug, Default)]
struct Standing {
    objects: BTreeMap<(ChangeKind, String), (Option<String>, bool)>,
    endpoints: BTreeSet<Endpoint>,
    unattributed: bool,
}

/// Each unit's current footprint, kept from the kernel's reports (or the
/// fake's script). `apply` takes one attributed change; `lost` records an
/// event the ring buffer dropped; `view` renders what the files carry.
#[derive(Clone, Debug, Default)]
pub struct Tracker {
    units: BTreeMap<UnitId, Standing>,
    /// Steering changes that stand, attributed to nobody.
    unattributed: BTreeSet<(ChangeKind, String)>,
    /// A lost event could not be placed: everything counts as unattributed
    /// until the watch restarts (which re-reads the kernel's state).
    lost_unplaced: bool,
}

impl Tracker {
    pub fn apply(&mut self, c: &Change) {
        let key = (c.kind, c.object.clone());
        match &c.owner {
            Owner::Unattributed => {
                if c.removed || !c.steers {
                    self.unattributed.remove(&key);
                } else {
                    self.unattributed.insert(key);
                }
            }
            Owner::Unit(u) => {
                let s = self.units.entry(u.clone()).or_default();
                if c.removed {
                    s.objects.remove(&key);
                } else {
                    s.objects.insert(key, (c.iface.clone(), c.steers));
                }
            }
        }
    }

    pub fn add_endpoint(&mut self, unit: &UnitId, e: Endpoint) {
        self.units.entry(unit.clone()).or_default().endpoints.insert(e);
    }

    /// An event was lost. With the unit known, its footprint is marked
    /// unattributed; without, the global marker stands.
    pub fn lost(&mut self, unit: Option<&UnitId>) {
        match unit {
            Some(u) => self.units.entry(u.clone()).or_default().unattributed = true,
            None => self.lost_unplaced = true,
        }
    }

    /// The footprint of `unit` now, confirmed at `at`.
    pub fn footprint(&self, unit: &UnitId, at: u64) -> Footprint {
        let Some(s) = self.units.get(unit) else { return Footprint { at, ..Default::default() } };
        let ifaces: BTreeSet<String> = s
            .objects
            .iter()
            .filter(|((k, _), _)| *k == ChangeKind::Interface)
            .map(|((_, name), _)| name.clone())
            .collect();
        // §12d: an interface the unit created that carries a default or
        // all-covering route protects, whoever added the route; its own
        // steering changes (rules, DNS, proxy, firewall) protect too.
        let routed_through_own = self.steering_ifaces().iter().any(|i| ifaces.contains(i));
        Footprint {
            at,
            protecting: routed_through_own
                || s.objects.iter().any(|((k, _), (_, steers))| *steers && *k != ChangeKind::Interface),
            ifaces,
            endpoints: s.endpoints.clone(),
            unattributed: s.unattributed,
        }
    }

    /// Interfaces some standing steering route goes out of, whoever made it.
    fn steering_ifaces(&self) -> BTreeSet<String> {
        self.units
            .values()
            .flat_map(|s| s.objects.iter())
            .filter(|((k, _), (_, steers))| *k == ChangeKind::Route && *steers)
            .filter_map(|(_, (iface, _))| iface.clone())
            .collect()
    }

    /// What the files carry: a footprint for every network tool in `tools`
    /// (absent from the tracker: `protecting no`), confirmed at `now`.
    pub fn view(&self, watch: WatchState, tools: &[UnitId], now: u64) -> FootprintView {
        let units = tools.iter().map(|u| (crate::file_name(u), self.footprint(u, now))).collect();
        FootprintView { watch, unattributed: self.lost_unplaced || !self.unattributed.is_empty(), units }
    }
}
