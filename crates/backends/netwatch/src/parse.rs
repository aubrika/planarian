//! From a captured netlink message to the changes it makes (§12d). Read-only
//! requests (`RTM_GET*`, dumps) change nothing. A message this module cannot
//! fully read but that may change how traffic leaves is not guessed at: it
//! is reported as [`Parsed::Unreadable`], which marks the sender's
//! footprint `unattributed` (fail closed).

use crate::ebpf::{Event, HOOK_GENL, HOOK_NETDEV, HOOK_NFBATCH, HOOK_NFNETLINK, HOOK_RTNETLINK, HOOK_SOCKOPT};
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
/// GETOBJ 19, GETOBJ_RESET 21, GETFLOWTABLE 23, GETRULE_RESET 25,
/// GETSETELEM_RESET 33 (the resets zero counters; they do not change where
/// traffic goes). Listed, not computed: the numbering stopped following a
/// pattern at NFT_MSG_GETOBJ_RESET. Any other type, a later kernel's
/// included, is a change (fail closed). vm-netwatch (n) found GETFLOWTABLE
/// read as a change: `nft list` made its caller protecting.
const NFT_READS: [u16; 11] = [1, 4, 7, 10, 13, 16, 19, 21, 23, 25, 33];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// Nothing that can change how traffic leaves (a read, an address).
    Nothing,
    Changes(Vec<Change>),
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
fn attrs(b: &[u8], from: usize) -> Option<Vec<(u16, &[u8])>> {
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

fn cstr(b: &[u8]) -> String {
    String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or(&[])).into_owned()
}

const RTM_SETLINK: u16 = 19;
const IFINFOMSG_LEN: usize = 16;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_TARGET_NETNSID: u16 = 46;

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
    /// A request elsewhere that may reach into this one (a link moved by
    /// netns pid or fd, or aimed at a netns id; the kernel makes no request
    /// here for the device arriving): charged to the mover as unattributed,
    /// or to nobody if its unit is not known (fail closed either way).
    Reaches,
}

pub fn scope(ev: &Event, own: u32) -> Scope {
    if ev.netns == 0 {
        return Scope::Unknown;
    }
    if ev.netns == own {
        return Scope::Host;
    }
    if ev.hook == HOOK_RTNETLINK && matches!(ev.nlmsg_type(), Some(RTM_NEWLINK | RTM_SETLINK)) {
        let reaches = |a: &[(u16, &[u8])]| {
            a.iter().any(|(t, _)| matches!(*t, IFLA_NET_NS_PID | IFLA_NET_NS_FD | IFLA_TARGET_NETNSID))
        };
        match attrs(&ev.data, NLMSG_HDRLEN + IFINFOMSG_LEN) {
            Some(a) if !reaches(&a) && !ev.truncated() => {}
            _ => return Scope::Reaches,
        }
    }
    Scope::Elsewhere
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
        Scope::Reaches => return t.lost(unit().as_ref()),
        Scope::Host => {}
    }
    // The tracker's keys (interface names, `oif` resolved through the
    // host's /sys/class/net) are implicitly the host's: nothing from
    // another netns may reach it.
    debug_assert_eq!(ev.netns, own_netns, "a non-host event reached the tracker");
    let unit = unit();
    let owner = unit.clone().map(Owner::Unit).unwrap_or(Owner::Unattributed);
    match parse(ev, &owner, ifname) {
        Parsed::Nothing => {}
        Parsed::Changes(cs) => cs.iter().for_each(|c| t.apply(c)),
        Parsed::Unreadable(_) => t.lost(unit.as_ref()),
    }
}

/// The changes in `ev`, made by `owner`. `ifname` names an interface index.
pub fn parse(ev: &Event, owner: &Owner, ifname: &mut dyn FnMut(u32) -> Option<String>) -> Parsed {
    let b = &ev.data;
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
