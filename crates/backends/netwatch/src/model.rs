//! What the kernel attributed to whom, and what it means (§12d).

use crate::contract::{AHEAD_SECS, FRESH_SECS};
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
    /// The unit's latest systemd InvocationID netwatch has seen (32
    /// lowercase hex), from its cgroup's `trusted.invocation_id`.
    #[serde(default)]
    pub invocation: Option<String>,
}

/// The watch's state, as `.watch` carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchState {
    /// All probes attached and events flowing, confirmed at this time.
    Attached { at: u64 },
    /// A probe failed to attach, or the watch was lost; why, on one line.
    Failed { reason: String },
    /// No `.watch`, or one this crate cannot read: not known to be healthy.
    Unknown,
}

/// Everything the hold needs, read back from the files (or scripted by the
/// fake): the watch, why `.unattributed` stands (empty: it is absent), and
/// the footprint of each network tool, keyed by its file name
/// ([`crate::file_name`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FootprintView {
    pub watch: WatchState,
    pub unattributed: Vec<String>,
    pub units: BTreeMap<String, Footprint>,
}

impl Default for FootprintView {
    fn default() -> Self {
        FootprintView { watch: WatchState::Unknown, unattributed: vec![], units: BTreeMap::new() }
    }
}

/// Fresh: at most [`FRESH_SECS`] old and at most [`AHEAD_SECS`] ahead.
pub(crate) fn fresh(at: u64, now: u64) -> bool {
    let age = now as i128 - at as i128;
    age <= FRESH_SECS as i128 && age >= -(AHEAD_SECS as i128)
}

impl FootprintView {
    /// §12d, fail closed: whether a failed network tool `unit` (its file
    /// name) counts as protecting traffic at `now`. True unless the watch is
    /// attached and fresh, no unattributed change stands, and the unit's
    /// footprint exists, is fresh, is not protecting and is not marked
    /// unattributed. The hold's script applies the same rules to the files.
    pub fn protecting_now(&self, unit: &str, now: u64) -> bool {
        let healthy = matches!(self.watch, WatchState::Attached { at } if fresh(at, now));
        if !healthy || !self.unattributed.is_empty() {
            return true;
        }
        match self.units.get(unit) {
            None => true,
            Some(f) => !fresh(f.at, now) || f.protecting || f.unattributed,
        }
    }
}

impl FootprintView {
    /// Which of `tools` count as protecting traffic at `now` (§12d, fail
    /// closed): what the daemon carries in its observation.
    pub fn protecting(&self, tools: &[UnitId], now: u64) -> BTreeSet<UnitId> {
        tools.iter().filter(|u| self.protecting_now(&crate::file_name(u), now)).cloned().collect()
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
    /// Steering changes that stand, attributed to nobody, with the interface
    /// a route goes out of.
    unattributed: BTreeMap<(ChangeKind, String), Option<String>>,
    /// Links that something created (a link kind; or created through
    /// netlink while watched, which a physical NIC never is). §12d's
    /// steering route is one over "an interface it created": a default route
    /// over the machine's own NIC is not one, watched or found at attach.
    virtual_ifaces: BTreeSet<String>,
    /// Each unit's latest InvocationID seen (not kept across restarts: the
    /// cgroups are read again on attach).
    invocations: BTreeMap<UnitId, String>,
    /// A lost event could not be placed: everything counts as unattributed
    /// until the watch restarts (which re-reads the kernel's state).
    lost_unplaced: bool,
    /// Steering objects found standing on attach that no footprint claimed:
    /// made while nobody watched (§12d, fail closed). Each clears when its
    /// object is removed.
    pre_attach: BTreeMap<(ChangeKind, String), Option<String>>,
    /// Steering routes found standing on attach over an interface a unit
    /// claims (object → interface): they protect through that interface.
    route_through: BTreeMap<String, String>,
}

/// The tracker's claims, as `.state` keeps them across a restart of the
/// watch (a dot-file the hold does not read).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// (unit, kind, object, iface, steers)
    pub objects: Vec<(UnitId, ChangeKind, String, Option<String>, bool)>,
    pub endpoints: Vec<(UnitId, Endpoint)>,
    pub unattributed_units: Vec<UnitId>,
}

impl Claims {
    /// Every unit claimed for: an object, an endpoint, or an unattributed
    /// mark.
    pub fn units(&self) -> BTreeSet<UnitId> {
        let objects = self.objects.iter().map(|o| o.0.clone());
        let endpoints = self.endpoints.iter().map(|e| e.0.clone());
        objects.chain(endpoints).chain(self.unattributed_units.iter().cloned()).collect()
    }
}

impl Tracker {
    pub fn apply(&mut self, c: &Change) {
        let key = (c.kind, c.object.clone());
        if c.removed {
            // An object gone is gone for everyone who claimed it, whoever
            // removed it (and a pre-attach one clears with it).
            for s in self.units.values_mut() {
                s.objects.remove(&key);
            }
            self.unattributed.remove(&key);
            self.pre_attach.remove(&key);
            if c.kind == ChangeKind::Interface {
                self.virtual_ifaces.remove(&c.object);
            }
            if c.kind == ChangeKind::Route {
                self.route_through.remove(&c.object);
            }
            if c.kind == ChangeKind::Interface {
                // The kernel drops an interface's routes with it, without a
                // message for each: drop every claim on a route through it.
                let gone = Some(c.object.clone());
                for s in self.units.values_mut() {
                    s.objects.retain(|(k, _), (i, _)| !(*k == ChangeKind::Route && *i == gone));
                }
                self.route_through.retain(|_, i| Some(i.clone()) != gone);
                self.unattributed.retain(|(k, _), i| !(*k == ChangeKind::Route && *i == gone));
                self.pre_attach.retain(|(k, _), i| !(*k == ChangeKind::Route && *i == gone));
            }
            return;
        }
        if c.kind == ChangeKind::Interface {
            // Created through netlink: a virtual link (dummy, wireguard, tun).
            self.virtual_ifaces.insert(c.object.clone());
        }
        match &c.owner {
            Owner::Unattributed => {
                if !c.steers {
                    self.unattributed.remove(&key);
                } else {
                    self.unattributed.insert(key, c.iface.clone());
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

    /// What `.state` keeps.
    pub fn claims(&self) -> Claims {
        let mut c = Claims::default();
        for (u, s) in &self.units {
            for ((k, o), (i, steers)) in &s.objects {
                c.objects.push((u.clone(), *k, o.clone(), i.clone(), *steers));
            }
            c.endpoints.extend(s.endpoints.iter().map(|e| (u.clone(), *e)));
            if s.unattributed {
                c.unattributed_units.push(u.clone());
            }
        }
        c
    }

    /// §12d, on every attach (boot or restart): start from the claims kept
    /// before (`.state`, or the footprint files' `iface` lines when it is
    /// gone), keep each claim whose object still stands in `standing` (a
    /// snapshot of the kernel's steering state, as changes), drop the rest,
    /// and record every standing steering object nobody claims as
    /// pre-attach: it was made while nobody watched. A restart therefore
    /// never downgrades a footprint, and a change made in the gap fails
    /// closed until its object is gone.
    ///
    /// `virtual_ifaces` are the standing links that something created (they
    /// have a link kind: dummy, wireguard, tun, …). An unclaimed steering
    /// route counts as pre-attach only over one of those, or over no
    /// interface: a default route over a physical NIC no unit created (the
    /// machine's own uplink) is not "an interface it created" (§12d).
    pub fn attach(previous: &Claims, standing: &[Change], virtual_ifaces: &BTreeSet<String>) -> Tracker {
        let present: BTreeMap<(ChangeKind, String), &Change> =
            standing.iter().map(|c| ((c.kind, c.object.clone()), c)).collect();
        let mut t = Tracker { virtual_ifaces: virtual_ifaces.clone(), ..Default::default() };
        for (u, k, o, i, steers) in &previous.objects {
            if present.contains_key(&(*k, o.clone())) {
                t.apply(&Change {
                    owner: Owner::Unit(u.clone()),
                    kind: *k,
                    object: o.clone(),
                    iface: i.clone(),
                    steers: *steers,
                    removed: false,
                });
            }
        }
        for (u, e) in &previous.endpoints {
            t.add_endpoint(u, *e);
        }
        for u in &previous.unattributed_units {
            t.lost(Some(u));
        }
        let claimed: BTreeSet<(ChangeKind, String)> =
            t.units.values().flat_map(|s| s.objects.keys().cloned()).collect();
        for (key, c) in &present {
            if c.steers && !claimed.contains(key) {
                t.pre_attach.insert(key.clone(), c.iface.clone());
            }
        }
        // An unclaimed steering route over an interface a unit claims is
        // that unit's (it carries the unit's traffic), not pre-attach.
        let claimed_ifaces: BTreeSet<String> = t
            .units
            .values()
            .flat_map(|s| s.objects.iter())
            .filter(|((k, _), _)| *k == ChangeKind::Interface)
            .map(|((_, n), _)| n.clone())
            .collect();
        t.pre_attach.retain(|key, _| {
            let iface = present[key].iface.as_ref();
            !(key.0 == ChangeKind::Route
                && iface.is_some_and(|i| claimed_ifaces.contains(i) || !virtual_ifaces.contains(i)))
        });
        // Routes over a claimed interface still steer through it.
        for c in standing {
            if c.kind == ChangeKind::Route
                && c.steers
                && !claimed.contains(&(c.kind, c.object.clone()))
                && let Some(i) = &c.iface
                && claimed_ifaces.contains(i)
            {
                t.route_through.insert(c.object.clone(), i.clone());
            }
        }
        t
    }

    /// The claims the footprint files carry (each `iface` line), for an
    /// attach when `.state` is gone.
    pub fn claims_from_files(view: &FootprintView) -> Claims {
        let mut c = Claims::default();
        for (name, f) in &view.units {
            let u = UnitId::service(name);
            for i in &f.ifaces {
                c.objects.push((u.clone(), ChangeKind::Interface, i.clone(), Some(i.clone()), false));
            }
            c.endpoints.extend(f.endpoints.iter().map(|e| (u.clone(), *e)));
            if f.unattributed {
                c.unattributed_units.push(u);
            }
        }
        c
    }

    pub fn add_endpoint(&mut self, unit: &UnitId, e: Endpoint) {
        self.units.entry(unit.clone()).or_default().endpoints.insert(e);
    }

    /// An event was lost. With the unit known, its footprint is marked
    /// unattributed; without, the global marker stands.
    /// The unit's InvocationID as its cgroup carries it; whether it changed.
    pub fn set_invocation(&mut self, unit: &UnitId, id: &str) -> bool {
        if self.invocations.get(unit).is_some_and(|i| i == id) {
            return false;
        }
        self.invocations.insert(unit.clone(), id.to_string());
        true
    }

    /// The virtual links standing now (`host::read_virtual_ifaces`): read
    /// live each tick, so a tun made by ioctl or a link moved in from
    /// another netns is never taken for a physical NIC.
    pub fn set_virtual(&mut self, live: BTreeSet<String>) {
        self.virtual_ifaces = live;
    }

    pub fn lost(&mut self, unit: Option<&UnitId>) {
        match unit {
            Some(u) => self.units.entry(u.clone()).or_default().unattributed = true,
            None => self.lost_unplaced = true,
        }
    }

    /// The footprint of `unit` now, confirmed at `at`.
    pub fn footprint(&self, unit: &UnitId, at: u64) -> Footprint {
        let invocation = self.invocations.get(unit).cloned();
        let Some(s) = self.units.get(unit) else { return Footprint { at, invocation, ..Default::default() } };
        // Only a virtual link can be one a tool created; a physical NIC is
        // registered by its driver, whoever's context that runs in.
        let created: BTreeSet<String> = s
            .objects
            .iter()
            .filter(|((k, name), _)| *k == ChangeKind::Interface && self.virtual_ifaces.contains(name))
            .map(|((_, name), _)| name.clone())
            .collect();
        // §12d: an interface the unit created that carries a default or
        // all-covering route protects, whoever added the route; so do its own
        // catch-all rules, DNS, proxy and firewall changes. A route alone
        // does not: a default route over an interface the unit did not create
        // (NetworkManager's DHCP route over wlan0) steers nothing of its own,
        // watched or found at attach (coordinator, Nov 2). `iface` lines name
        // the created interfaces that steer: what the hold passes.
        let mut ifaces: BTreeSet<String> = self.steering_ifaces().intersection(&created).cloned().collect();
        // (coordinator, Nov 2 and 3; the spec reads "...over a virtual
        // interface it did not create...") A default or all-covering route
        // the unit added over a *virtual* link it did not create makes it
        // protecting too: one another unit made (OpenVPN on a persistent tun
        // a setup unit made: both hold), one moved in from another netns, one
        // made before the watch attached. Virtual is the live sysfs check, so
        // a route over a physical NIC (NetworkManager's DHCP default over
        // wlan0) still steers nothing of the unit's own. Leans fail-closed.
        for ((k, _), (i, steers)) in &s.objects {
            if *k == ChangeKind::Route
                && *steers
                && let Some(i) = i
                && self.virtual_ifaces.contains(i)
            {
                ifaces.insert(i.clone());
            }
        }
        let own = |k: &ChangeKind| !matches!(k, ChangeKind::Interface | ChangeKind::Route);
        Footprint {
            at,
            // A change charged here that could not be fully attributed counts
            // as protecting (fail closed), and the file says so: `protecting
            // yes` with its `unattributed` line, as the hold reads it anyway.
            protecting: s.unattributed
                || !ifaces.is_empty()
                || s.objects.iter().any(|((k, _), (_, steers))| *steers && own(k)),
            ifaces,
            endpoints: s.endpoints.clone(),
            unattributed: s.unattributed,
            invocation,
        }
    }

    /// Interfaces some standing steering route goes out of, whoever made it.
    fn steering_ifaces(&self) -> BTreeSet<String> {
        self.units
            .values()
            .flat_map(|s| s.objects.iter())
            .filter(|((k, _), (_, steers))| *k == ChangeKind::Route && *steers)
            .filter_map(|(_, (iface, _))| iface.clone())
            .chain(self.route_through.values().cloned())
            .chain(
                self.unattributed.iter().filter(|((k, _), _)| *k == ChangeKind::Route).filter_map(|(_, i)| i.clone()),
            )
            .collect()
    }

    /// What the files carry: a footprint for every network tool in `tools`
    /// (absent from the tracker: `protecting no`), confirmed at `now`.
    pub fn view(&self, watch: WatchState, tools: &[UnitId], now: u64) -> FootprintView {
        let units = tools.iter().map(|u| (crate::file_name(u), self.footprint(u, now))).collect();
        // An unattributed route over a physical NIC steers nothing (the same
        // rule as at attach); over a virtual link, or none, it fails closed.
        let mut why: Vec<String> = self
            .unattributed
            .iter()
            .filter(|((k, _), i)| {
                !(*k == ChangeKind::Route && i.as_ref().is_some_and(|i| !self.virtual_ifaces.contains(i)))
            })
            .map(|((k, o), _)| format!("{k:?} {o}: no unit made it"))
            .collect();
        why.extend(self.pre_attach.keys().map(|(k, o)| format!("pre-attach {k:?} {o}")));
        if self.lost_unplaced {
            why.push("an event was lost and could not be placed".into());
        }
        FootprintView { watch, unattributed: why, units }
    }
}
