//! From a captured netlink message to the changes it makes (§12d). Read-only
//! requests (`RTM_GET*`, dumps) change nothing. A message this module cannot
//! fully read but that may change how traffic leaves is not guessed at: it
//! is reported as [`Parsed::Unreadable`], which marks the sender's
//! footprint `unattributed` (fail closed).

use crate::ebpf::{
    Event, HOOK_GENL, HOOK_NETDEV, HOOK_NETMOVE, HOOK_NETRENAME, HOOK_NFBATCH, HOOK_NFNETLINK, HOOK_RTNETLINK,
    HOOK_SOCKOPT,
};
use crate::model::{Change, ChangeKind, Owner};

const NLM_F_CREATE: u16 = 0x400;
const NLMSG_HDRLEN: usize = 16;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

const IFLA_IFNAME: u16 = 3;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;
const FRA_PRIORITY: u16 = 6;
const FRA_TABLE: u16 = 15;
const FR_ACT_TO_TBL: u8 = 1;

/// nfnetlink's nftables subsystem (`NFNL_SUBSYS_NFTABLES`).
const NFNL_SUBSYS_NFTABLES: u16 = 10;

/// The nftables messages that only read (`enum nf_tables_msg_types`):
/// GETTABLE 1, GETCHAIN 4, GETRULE 7, GETSET 10, GETSETELEM 13, GETGEN 16,
/// GETOBJ 19, GETFLOWTABLE 23. Listed, not computed: the numbering stopped
/// following a pattern at NFT_MSG_GETOBJ_RESET. Any other type, a later
/// kernel's included, is a change (fail closed). The resets (GETOBJ_RESET
/// 21, GETRULE_RESET 25, GETSETELEM_RESET 33) are changes too: zeroing a
/// quota or limit can flip a verdict (reviewer, coordinator, Nov 3).
/// vm-netwatch (n) found GETFLOWTABLE read as a change: `nft list` made its
/// caller protecting.
const NFT_READS: [u16; 8] = [1, 4, 7, 10, 13, 16, 19, 23];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// Nothing that can change how traffic leaves (a read, an address).
    Nothing,
    Changes(Vec<Change>),
    /// The same interface, with every maker and route preserved.
    Renamed {
        was: String,
        now: String,
    },
    /// May change how traffic leaves, but could not be read in full.
    Unreadable(String),
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|x| u16::from_ne_bytes([x[0], x[1]]))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|x| u32::from_ne_bytes([x[0], x[1], x[2], x[3]]))
}

/// The attributes after a fixed header, as (type, payload); `None` if one
/// runs past the captured bytes.
pub(crate) fn attrs(b: &[u8], from: usize) -> Option<Vec<(u16, &[u8])>> {
    let mut out = vec![];
    let mut o = from;
    while o + 4 <= b.len() {
        let len = u16_at(b, o)? as usize;
        let ty = u16_at(b, o + 2)? & 0x3fff;
        if len < 4 || o + len > b.len() {
            return None;
        }
        out.push((ty, &b[o + 4..o + len]));
        o += (len + 3) & !3;
    }
    Some(out)
}

pub(crate) fn cstr(b: &[u8]) -> String {
    String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or(&[])).into_owned()
}

/// Deliberate bugs in the move rules, for the tests that show the move
/// property catches them (rule 23).
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MoveMutant {
    None,
    /// A move into the host makes no claim.
    DropArrival,
    /// A move out of the host removes nothing.
    DropDeparture,
    /// A move out removes the name it has now, not the one it had.
    DepartureByNewName,
    /// Only the target's namespace is looked at: a move out is never seen.
    TargetOnly,
    /// Any move to another namespace removes the claim, whichever it left.
    AnyDeparture,
}

#[cfg(test)]
thread_local! {
    pub(crate) static MOVE_MUTANT: std::cell::Cell<MoveMutant> = const { std::cell::Cell::new(MoveMutant::None) };
}

#[cfg(test)]
fn mutant(m: MoveMutant) -> bool {
    MOVE_MUTANT.with(std::cell::Cell::get) == m
}

/// Which network namespace a request acts on, against netwatch's own
/// (crate docs, "Namespaces").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// This one: the host's.
    Host,
    /// Another (a container's, a `PrivateNetwork=` service's): how traffic
    /// leaves the machine is not changed there. Ignored.
    Elsewhere,
    /// The probe could not read the netns: a loss nothing can place
    /// (`.unattributed`, fail closed).
    Unknown,
}

pub fn scope(ev: &Event, own: u32) -> Scope {
    if ev.hook == HOOK_NETMOVE {
        // A move concerns the host if it arrives there or leaves from there.
        return match (ev.netns, move_source(ev)) {
            (0, _) | (_, None) => Scope::Unknown,
            (target, _) if target == own => Scope::Host,
            #[cfg(test)]
            _ if mutant(MoveMutant::TargetOnly) => Scope::Elsewhere,
            (_, Some((source, _))) if source == own => Scope::Host,
            #[cfg(test)]
            _ if mutant(MoveMutant::AnyDeparture) => Scope::Host,
            _ => Scope::Elsewhere,
        };
    }
    if ev.netns == 0 {
        return Scope::Unknown;
    }
    if ev.netns == own {
        return Scope::Host;
    }
    // A link moved into the host by a request made elsewhere (`IFLA_NET_NS_*`,
    // `IFLA_TARGET_NETNSID`) is seen as the move itself (HOOK_NETMOVE), in the
    // mover's context, and one created there as its registration (HOOK_NETDEV).
    Scope::Elsewhere
}

/// Where a moved interface came from: the source netns inode and the name it
/// had there (`None`: the probe did not see the call begin, or could not
/// read them).
fn move_source(ev: &Event) -> Option<(u32, String)> {
    let inum = u32::from_ne_bytes(ev.data.get(16..20)?.try_into().ok()?);
    let name = cstr(ev.data.get(20..36)?);
    (inum != 0).then_some((inum, name))
}

/// The loader's event path, including observed interface-index names. Route
/// changes resolve against live names, never a stale cached index. Retain
/// observed names for queued index-only deletions after the device is gone;
/// a rename rewrites them and a departure/deletion removes them afterward.
pub fn take_cached(
    t: &mut crate::Tracker,
    ev: &Event,
    own_netns: u32,
    unit: impl FnOnce() -> Option<planarian_schema::UnitId>,
    names: &mut std::collections::BTreeMap<u32, String>,
    read_names: &mut dyn FnMut() -> std::collections::BTreeMap<u32, String>,
) {
    let host = scope(ev, own_netns) == Scope::Host;
    let route = host && ev.hook == HOOK_RTNETLINK && matches!(ev.nlmsg_type(), Some(RTM_NEWROUTE | RTM_DELROUTE));
    let live = if route { Some(read_names()) } else { None };
    if let Some(live) = &live {
        names.extend(live.clone());
    }
    take(t, ev, own_netns, unit, &mut |i| {
        if let Some(live) = &live {
            return live.get(&i).cloned();
        }
        if !names.contains_key(&i) {
            names.extend(read_names());
        }
        names.get(&i).cloned()
    });
    if !host {
        return;
    }
    let identity = if ev.hook == HOOK_NETMOVE {
        parse_move(ev, own_netns, &Owner::Unattributed)
    } else if matches!(ev.hook, HOOK_NETDEV | HOOK_NETRENAME)
        || (ev.hook == HOOK_RTNETLINK && matches!(ev.nlmsg_type(), Some(16 | 17 | 19)))
    {
        parse(ev, &Owner::Unattributed, &mut |i| names.get(&i).cloned())
    } else {
        return;
    };
    match identity {
        Parsed::Renamed { was, now } => {
            for name in names.values_mut() {
                if name.as_str() == was {
                    *name = now.clone();
                }
            }
        }
        Parsed::Changes(cs) => {
            for c in cs.iter().filter(|c| c.kind == ChangeKind::Interface && c.removed) {
                names.retain(|_, name| name.as_str() != c.object.as_str());
            }
        }
        _ => {}
    }
}

/// One event as the loop takes it: ignored if it acts in another netns, a
/// loss nothing can place if the netns is unknown, else parsed and applied
/// to `t` for the unit `unit()` finds (unattributed if none).
pub fn take(
    t: &mut crate::Tracker,
    ev: &Event,
    own_netns: u32,
    unit: impl FnOnce() -> Option<planarian_schema::UnitId>,
    ifname: &mut dyn FnMut(u32) -> Option<String>,
) {
    match scope(ev, own_netns) {
        Scope::Elsewhere => return,
        Scope::Unknown => return t.lost(None),
        Scope::Host => {}
    }
    // The tracker's keys (interface names, `oif` resolved through the
    // host's /sys/class/net) are implicitly the host's: nothing from
    // another netns may reach it.
    debug_assert!(ev.hook == HOOK_NETMOVE || ev.netns == own_netns, "a non-host event reached the tracker");
    let unit = unit();
    let owner = unit.clone().map(Owner::Unit).unwrap_or(Owner::Unattributed);
    let parsed = if ev.hook == HOOK_NETMOVE { parse_move(ev, own_netns, &owner) } else { parse(ev, &owner, ifname) };
    match parsed {
        Parsed::Nothing => {}
        Parsed::Changes(cs) => cs.iter().for_each(|c| t.apply(c)),
        Parsed::Renamed { was, now } => t.rename_interface(&was, &now),
        Parsed::Unreadable(reason) => {
            // Bounded diagnostics: at most eight per process, even under a
            // stream of malformed requests. Every event still fails closed.
            use std::sync::atomic::{AtomicUsize, Ordering};
            static LOGGED: AtomicUsize = AtomicUsize::new(0);
            if LOGGED.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| (n < 8).then_some(n + 1)).is_ok() {
                eprintln!(
                    "netwatch: unreadable event (hook {}, type {:?}, netns {}, unit {:?}): {reason}",
                    ev.hook,
                    ev.nlmsg_type(),
                    ev.netns,
                    unit,
                );
            }
            t.lost(unit.as_ref());
        }
    }
}

/// An interface moved between network namespaces (`HOOK_NETMOVE`), made by
/// `owner`. Arriving in the host's (`own`): a claim on the name it has now,
/// like any interface the mover brought. Leaving the host's: the interface
/// is gone from it, under the name it had there (the kernel may have renamed
/// it on the way). Between two others, or into the one it was in: nothing of
/// the host's. A name it cannot read, where one matters, is unreadable.
pub fn parse_move(ev: &Event, own: u32, owner: &Owner) -> Parsed {
    let Some((source, was)) = move_source(ev) else {
        return Parsed::Unreadable("a namespace move whose source was not seen".into());
    };
    let target = ev.netns;
    if target == 0 {
        return Parsed::Unreadable("a namespace move whose target was not read".into());
    }
    let now = cstr(ev.data.get(..16).unwrap_or(&[]));
    let change = |name: String, removed| {
        Parsed::Changes(vec![Change {
            owner: owner.clone(),
            kind: ChangeKind::Interface,
            object: name.clone(),
            iface: Some(name),
            steers: false,
            removed,
        }])
    };
    #[cfg(test)]
    let (arrives, leaves) = (
        target == own && source != own && !mutant(MoveMutant::DropArrival),
        (if mutant(MoveMutant::AnyDeparture) { target != own } else { source == own && target != own })
            && !mutant(MoveMutant::DropDeparture),
    );
    #[cfg(not(test))]
    let (arrives, leaves) = (target == own && source != own, source == own && target != own);
    if arrives {
        return if now.is_empty() {
            Parsed::Unreadable("an interface moved in without a readable name".into())
        } else {
            change(now, false)
        };
    }
    if leaves {
        #[cfg(test)]
        let was = if mutant(MoveMutant::DepartureByNewName) { now } else { was };
        return if was.is_empty() {
            Parsed::Unreadable("an interface moved out without a readable name".into())
        } else {
            change(was, true)
        };
    }
    Parsed::Nothing
}

/// The changes in `ev`, made by `owner`. `ifname` names an interface index.
pub fn parse(ev: &Event, owner: &Owner, ifname: &mut dyn FnMut(u32) -> Option<String>) -> Parsed {
    let b = &ev.data;
    if ev.hook == HOOK_NETRENAME {
        let names = b.get(..32).map(|b| (cstr(&b[..16]), cstr(&b[16..32])));
        return match names {
            Some((was, now)) if !was.is_empty() && !now.is_empty() => Parsed::Renamed { was, now },
            _ => Parsed::Unreadable("an interface rename without both readable names".into()),
        };
    }
    if ev.hook == HOOK_NETMOVE {
        // Which way it went depends on the host's netns, which `parse` is
        // not given: `take` calls `parse_move`. Anyone else must not read
        // a move as nothing.
        return Parsed::Unreadable("a namespace move is read by parse_move".into());
    }
    if ev.hook == HOOK_NETDEV {
        // An interface registered in its creator's context: how a tun made
        // by ioctl is seen at all (no netlink message announces it).
        let name = cstr(b);
        if name.is_empty() {
            return Parsed::Unreadable("an interface registered without a readable name".into());
        }
        return Parsed::Changes(vec![Change {
            owner: owner.clone(),
            kind: ChangeKind::Interface,
            object: name.clone(),
            iface: Some(name),
            steers: false,
            removed: false,
        }]);
    }
    if ev.hook == HOOK_SOCKOPT {
        // A legacy table replaced (or its counters set) through setsockopt:
        // fail closed, like an nftables batch. The object names the family.
        let pf = b.first().copied().unwrap_or(0);
        return Parsed::Changes(vec![Change {
            owner: owner.clone(),
            kind: ChangeKind::Firewall,
            object: format!("legacy tables pf {pf}"),
            iface: None,
            steers: true,
            removed: false,
        }]);
    }
    let (Some(ty), Some(flags)) = (u16_at(b, 4), u16_at(b, 6)) else {
        return Parsed::Unreadable("no netlink header".into());
    };
    let change = |kind, object: String, iface: Option<String>, steers, removed| Change {
        owner: owner.clone(),
        kind,
        object,
        iface,
        steers,
        removed,
    };
    match ev.hook {
        HOOK_RTNETLINK => match ty {
            RTM_NEWLINK | RTM_DELLINK => {
                if ty == RTM_NEWLINK && flags & NLM_F_CREATE == 0 {
                    // Changing an existing link (up, mtu, master) makes nothing new.
                    return Parsed::Nothing;
                }
                let index = u32_at(b, NLMSG_HDRLEN + 4);
                let name = attrs(b, NLMSG_HDRLEN + 16)
                    .and_then(|a| a.iter().find(|(t, _)| *t == IFLA_IFNAME).map(|(_, v)| cstr(v)))
                    .or_else(|| index.filter(|i| *i != 0).and_then(ifname));
                match name {
                    Some(n) => Parsed::Changes(vec![change(
                        ChangeKind::Interface,
                        n.clone(),
                        Some(n),
                        false,
                        ty == RTM_DELLINK,
                    )]),
                    None => Parsed::Unreadable("a link change without a name".into()),
                }
            }
            RTM_NEWROUTE | RTM_DELROUTE => {
                let (Some(&family), Some(&dst_len), Some(&table)) =
                    (b.get(NLMSG_HDRLEN), b.get(NLMSG_HDRLEN + 1), b.get(NLMSG_HDRLEN + 4))
                else {
                    return Parsed::Unreadable("a short route message".into());
                };
                let Some(a) = attrs(b, NLMSG_HDRLEN + 12) else {
                    return Parsed::Unreadable("a route message past the capture".into());
                };
                let get = |t: u16| a.iter().find(|(x, _)| *x == t).map(|(_, v)| *v);
                let table = get(RTA_TABLE).and_then(|v| u32_at(v, 0)).unwrap_or(table as u32);
                let dst = get(RTA_DST).map(hex).unwrap_or_default();
                let oif = get(RTA_OIF).and_then(|v| u32_at(v, 0));
                let metric = get(RTA_PRIORITY).and_then(|v| u32_at(v, 0)).unwrap_or(0);
                let iface = oif.and_then(ifname);
                // §12d: a default or all-covering route (a /0, or the two /1
                // halves OpenVPN's redirect-gateway uses), in any table.
                let steers = dst_len <= 1;
                if ty == RTM_NEWROUTE && steers && oif.is_some() && iface.is_none() {
                    return Parsed::Unreadable("a steering route whose output interface was not read".into());
                }
                // Two default routes (the uplink's, a tunnel's) differ by their
                // output interface and metric: the key carries both.
                let object = format!("route {family} {table} {dst}/{dst_len} oif {} metric {metric}", oif.unwrap_or(0));
                Parsed::Changes(vec![change(ChangeKind::Route, object, iface, steers, ty == RTM_DELROUTE)])
            }
            RTM_NEWRULE | RTM_DELRULE => {
                let (Some(&family), Some(&dst_len), Some(&src_len), Some(&action)) =
                    (b.get(NLMSG_HDRLEN), b.get(NLMSG_HDRLEN + 1), b.get(NLMSG_HDRLEN + 2), b.get(NLMSG_HDRLEN + 7))
                else {
                    return Parsed::Unreadable("a short rule message".into());
                };
                let Some(a) = attrs(b, NLMSG_HDRLEN + 12) else {
                    return Parsed::Unreadable("a rule message past the capture".into());
                };
                let get = |t: u16| a.iter().find(|(x, _)| *x == t).and_then(|(_, v)| u32_at(v, 0));
                // A rule that sends all traffic (no source or destination
                // selector) to another table catches all of it (wg-quick's
                // `not fwmark … lookup …`). Sending it to the kernel's own
                // tables (local 255, main 254, default 253: the rules every
                // system starts with) redirects nothing.
                let table = get(FRA_TABLE).unwrap_or(b.get(NLMSG_HDRLEN + 4).copied().unwrap_or(0) as u32);
                let steers = dst_len == 0 && src_len == 0 && action == FR_ACT_TO_TBL && !matches!(table, 253..=255);
                let object = format!("rule {family} {} {table}", get(FRA_PRIORITY).unwrap_or(0));
                Parsed::Changes(vec![change(ChangeKind::Rule, object, None, steers, ty == RTM_DELRULE)])
            }
            // GET requests, addresses, neighbours, qdiscs: nothing that steers.
            _ => Parsed::Nothing,
        },
        // A single nftables message outside a batch, or an nftables batch: any
        // change to the ruleset by a unit counts as a firewall change that
        // steers (fail closed: the batch's rules are not read).
        HOOK_NFNETLINK | HOOK_NFBATCH => {
            if ev.hook == HOOK_NFNETLINK && ty >> 8 != NFNL_SUBSYS_NFTABLES {
                return Parsed::Nothing;
            }
            if ev.hook == HOOK_NFNETLINK && NFT_READS.contains(&(ty & 0xff)) {
                // NFT_MSG_GET*: a read (as `nft list` sends to fill its cache).
                return Parsed::Nothing;
            }
            Parsed::Changes(vec![change(ChangeKind::Firewall, "nftables".into(), None, true, false)])
        }
        // Generic netlink (WireGuard's configuration among others): read by
        // the family-aware layer; unknown here.
        HOOK_GENL => Parsed::Nothing,
        h => Parsed::Unreadable(format!("unknown hook {h}")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
