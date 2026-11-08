//! The kernel's steering state now, read through netlink dumps (feature
//! `loader`): what `Tracker::attach` reconciles the kept claims against.
//! Dump replies are the same messages as changes (`RTM_NEWROUTE` and so
//! on), so they go through [`crate::parse::parse`], owned by nobody.

use crate::ebpf::{Event, HOOK_NFNETLINK, HOOK_RTNETLINK};
use crate::model::{Change, ChangeKind, Owner};
use crate::parse::{Parsed, parse};
use rustix::net::netlink::{self, SocketAddrNetlink};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType};

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const RTM_GETROUTE: u16 = 26;
const RTM_GETRULE: u16 = 34;
/// nfnetlink: NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETTABLE.
const NFT_GETTABLE: u16 = (10 << 8) | 1;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// How long a netlink read waits for the kernel's reply.
pub(crate) const RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Why a netlink request failed: the kernel's errno, or the socket/reply.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NlError {
    Errno(i32),
    Other(String),
}

impl std::fmt::Display for NlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlError::Errno(e) => write!(f, "error {e}"),
            NlError::Other(s) => f.write_str(s),
        }
    }
}

/// Send one request (`flags` besides `NLM_F_REQUEST`) and collect every
/// reply message's bytes. `protocol`: `None` is `NETLINK_ROUTE`.
fn request(protocol: Option<rustix::net::Protocol>, ty: u16, flags: u16, body: &[u8]) -> Result<Vec<Vec<u8>>, NlError> {
    let other = |what: &str, e: rustix::io::Errno| NlError::Other(format!("{what}: {e}"));
    let fd = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, protocol)
        .map_err(|e| other("netlink socket", e))?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|e| other("netlink bind", e))?;
    // Every read is bounded: whatever the kernel does, a lookup returns, so
    // netwatch signals ready and stops on SIGTERM. A reply that does not come
    // is an error (the caller fails closed), never a wait.
    rustix::net::sockopt::set_socket_timeout(&fd, rustix::net::sockopt::Timeout::Recv, Some(RECV_TIMEOUT))
        .map_err(|e| other("netlink receive timeout", e))?;
    let mut req = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
    req.extend(ty.to_ne_bytes());
    req.extend((NLM_F_REQUEST | flags).to_ne_bytes());
    req.extend(1u32.to_ne_bytes());
    req.extend(0u32.to_ne_bytes());
    req.extend(body);
    rustix::net::sendto(&fd, &req, SendFlags::empty(), &SocketAddrNetlink::new(0, 0))
        .map_err(|e| other("netlink send", e))?;
    let mut out = vec![];
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let (n, received) = rustix::net::recv(&fd, &mut buf[..], RecvFlags::TRUNC).map_err(|e| {
            if e == rustix::io::Errno::AGAIN {
                NlError::Other(format!("netlink reply not received within {} s", RECV_TIMEOUT.as_secs()))
            } else {
                other("netlink recv", e)
            }
        })?;
        if received > n {
            return Err(NlError::Other("a truncated netlink datagram".into()));
        }
        if collect_reply(&buf[..n], &mut out)? {
            return Ok(out);
        }
    }
}

/// Collect a complete datagram, returning true only at a successful
/// terminator. An interrupted or failed dump is never a smaller snapshot.
pub(crate) fn collect_reply(bytes: &[u8], out: &mut Vec<Vec<u8>>) -> Result<bool, NlError> {
    const NLM_F_DUMP_INTR: u16 = 0x10;
    if bytes.is_empty() {
        return Err(NlError::Other("an empty netlink datagram".into()));
    }
    let mut offset = 0;
    while offset + 16 <= bytes.len() {
        let len = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
        let flags = u16::from_ne_bytes(bytes[offset + 6..offset + 8].try_into().unwrap());
        if len < 16 || offset + len > bytes.len() {
            return Err(NlError::Other("a malformed netlink reply".into()));
        }
        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(NlError::Other("an interrupted netlink dump".into()));
        }
        if ty == NLMSG_DONE || ty == NLMSG_ERROR {
            let code = match len {
                16 if ty == NLMSG_DONE => 0,
                20.. => i32::from_ne_bytes(bytes[offset + 16..offset + 20].try_into().unwrap()),
                _ => return Err(NlError::Other("a short netlink terminator".into())),
            };
            return if code == 0 { Ok(true) } else { Err(NlError::Errno(code)) };
        }
        out.push(bytes[offset..offset + len].to_vec());
        offset += (len + 3) & !3;
    }
    if offset < bytes.len() && (bytes.len() - offset > 3 || bytes[offset..].iter().any(|b| *b != 0)) {
        return Err(NlError::Other("a cut netlink header".into()));
    }
    Ok(false)
}

/// Send one dump request and collect every reply message's bytes.
fn dump(protocol: Option<rustix::net::Protocol>, ty: u16, body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    request(protocol, ty, NLM_F_DUMP, body).map_err(|e| format!("netlink dump {ty}: {e}"))
}

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
#[cfg(test)]
const ENOENT: i32 = -2;

/// A generic netlink family's id, by name, if it is registered (the id is
/// assigned at registration, for a module when it loads). Not registered is
/// `None`; any other failure is an error, and the caller fails closed.
///
/// This asks by *name*, as `CTRL_CMD_GETFAMILY` with `CTRL_ATTR_FAMILY_NAME`
/// as a plain request, which the kernel answers with one message and no
/// terminator; `request` reads until a terminator and so would wait for a
/// reply that never comes (this hung netwatch's start on a machine with the
/// family, #71's gate). The kernel also *loads the module* of a family it
/// does not have, when asked by name: asking must not change the machine.
pub fn family_id(name: &str) -> Result<Option<u16>, String> {
    family_id_in_dump(name)
}

/// The families the controller lists, and the id of the one named `name`: a
/// dump, which ends with a terminator and loads no module.
fn family_id_in_dump(name: &str) -> Result<Option<u16>, String> {
    let body = [CTRL_CMD_GETFAMILY, 1, 0, 0];
    let reply = request(Some(netlink::GENERIC), GENL_ID_CTRL, NLM_F_DUMP, &body)
        .map_err(|e| format!("generic netlink family list: {e}"))?;
    Ok(family_in(&reply, name))
}

/// The id of family `name` among the controller's `NEWFAMILY` messages.
pub fn family_in(msgs: &[Vec<u8>], name: &str) -> Option<u16> {
    msgs.iter().find_map(|m| {
        let attrs = crate::parse::attrs(m, 16 + 4)?;
        let named = attrs.iter().find(|(t, _)| *t == CTRL_ATTR_FAMILY_NAME)?;
        if crate::parse::cstr(named.1) != name {
            return None;
        }
        let (_, id) = attrs.iter().find(|(t, _)| *t == CTRL_ATTR_FAMILY_ID)?;
        id.get(0..2).map(|b| u16::from_ne_bytes([b[0], b[1]]))
    })
}

/// The old way (by name, a plain request), kept only so the regression test
/// can show it hangs; never called outside tests.
#[cfg(test)]
pub(crate) fn family_id_by_name(name: &str) -> Result<Option<u16>, String> {
    let mut body = vec![CTRL_CMD_GETFAMILY, 1, 0, 0];
    body.extend((4u16 + name.len() as u16 + 1).to_ne_bytes());
    body.extend(CTRL_ATTR_FAMILY_NAME.to_ne_bytes());
    body.extend(name.as_bytes());
    body.push(0);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    match request(Some(netlink::GENERIC), GENL_ID_CTRL, 0, &body) {
        Ok(r) => Ok(family_in(&r, name)),
        Err(NlError::Errno(ENOENT)) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Every family the controller lists, as (name, id): one dump, loading no
/// module (see [`family_id`]).
pub fn families() -> Result<Vec<(String, u16)>, String> {
    let body = [CTRL_CMD_GETFAMILY, 1, 0, 0];
    let reply = request(Some(netlink::GENERIC), GENL_ID_CTRL, NLM_F_DUMP, &body)
        .map_err(|e| format!("generic netlink family list: {e}"))?;
    Ok(families_in(&reply))
}

/// The (name, id) of each family among the controller's `NEWFAMILY` messages.
pub fn families_in(msgs: &[Vec<u8>]) -> Vec<(String, u16)> {
    msgs.iter()
        .filter_map(|m| {
            let attrs = crate::parse::attrs(m, 16 + 4)?;
            let name = attrs.iter().find(|(t, _)| *t == CTRL_ATTR_FAMILY_NAME)?;
            let (_, id) = attrs.iter().find(|(t, _)| *t == CTRL_ATTR_FAMILY_ID)?;
            let id = id.get(0..2).map(|b| u16::from_ne_bytes([b[0], b[1]]))?;
            Some((crate::parse::cstr(name.1), id))
        })
        .collect()
}

/// WireGuard's generic netlink family id, if the module is loaded.
pub fn wireguard_family() -> Result<Option<u16>, String> {
    family_id("wireguard")
}

/// The WireGuard devices as the kernel has them, with their peers'
/// endpoints (B-22 b), given WireGuard's family id (`None`: the module is
/// not loaded, so no devices; the id comes from [`GenlIds`], not a lookup
/// here). The reply carries keys; [`crate::wg::devices`] reads none.
pub fn wireguard(family: Option<u16>) -> Result<Vec<crate::wg::Device>, String> {
    let Some(family) = family else { return Ok(vec![]) };
    let links = dump(None, RTM_GETLINK, &[0u8; 16])?;
    let mut devices = vec![];
    for index in crate::wg::link_indices(&links)? {
        let body = crate::wg::get_device_request(index);
        let msgs = request(Some(netlink::GENERIC), family, NLM_F_DUMP, &body)
            .map_err(|e| format!("wireguard device {index} dump: {e}"))?;
        devices.extend(crate::wg::devices(&msgs)?);
    }
    Ok(devices)
}

fn changes(hook: u32, msgs: Vec<Vec<u8>>, ifname: &mut dyn FnMut(u32) -> Option<String>) -> Vec<Change> {
    let mut out = vec![];
    for mut m in msgs {
        // A dumped link exists: read it as one being created.
        if hook == HOOK_RTNETLINK && u16::from_ne_bytes([m[4], m[5]]) == RTM_NEWLINK {
            let f = u16::from_ne_bytes([m[6], m[7]]) | NLM_F_CREATE;
            m[6..8].copy_from_slice(&f.to_ne_bytes());
        }
        // Dumped from netwatch's own netns: parsed directly, never scoped.
        let ev = Event { cgroup: 0, tgid: 0, hook, len: m.len() as u32, netns: 0, cgpath: None, data: m };
        match parse(&ev, &Owner::Unattributed, ifname) {
            Parsed::Changes(c) => out.extend(c),
            Parsed::Nothing => {}
            // Only state-dump hooks reach here, never a rename event. If
            // that contract changes, do not silently drop an identity move.
            Parsed::Renamed { .. } => out.push(Change {
                owner: Owner::Unattributed,
                kind: ChangeKind::Route,
                object: "unreadable: a rename in a state snapshot".into(),
                iface: None,
                steers: true,
                removed: false,
            }),
            // Something standing it cannot read: fail closed.
            Parsed::Unreadable(why) => out.push(Change {
                owner: Owner::Unattributed,
                kind: ChangeKind::Route,
                object: format!("unreadable: {why}"),
                iface: None,
                steers: true,
                removed: false,
            }),
        }
    }
    out
}

/// The links that something created: those with a link kind
/// (`IFLA_LINKINFO`/`IFLA_INFO_KIND`: dummy, wireguard, tun, veth, …). A
/// physical NIC has none.
fn virtual_links(msgs: &[Vec<u8>]) -> std::collections::BTreeSet<String> {
    const IFLA_IFNAME: u16 = 3;
    const IFLA_LINKINFO: u16 = 18;
    let attr_list = |b: &[u8], mut o: usize| {
        let mut out = vec![];
        while o + 4 <= b.len() {
            let len = u16::from_ne_bytes([b[o], b[o + 1]]) as usize;
            let ty = u16::from_ne_bytes([b[o + 2], b[o + 3]]) & 0x3fff;
            if len < 4 || o + len > b.len() {
                break;
            }
            out.push((ty, b[o + 4..o + len].to_vec()));
            o += (len + 3) & !3;
        }
        out
    };
    let mut out = std::collections::BTreeSet::new();
    for m in msgs {
        let a = attr_list(m, 16 + 16);
        let name = a
            .iter()
            .find(|(t, _)| *t == IFLA_IFNAME)
            .map(|(_, v)| String::from_utf8_lossy(v.split(|c| *c == 0).next().unwrap_or(&[])).into_owned());
        let kind = a.iter().any(|(t, v)| *t == IFLA_LINKINFO && attr_list(v, 0).iter().any(|(k, _)| *k == 1));
        if let (Some(n), true) = (name, kind) {
            out.insert(n);
        }
    }
    out
}

/// Everything standing now that `parse` names: links, routes and rules (IPv4
/// and IPv6), nftables tables, and legacy tables (`/proc/net/*_tables_names`);
/// and which links something created. Any failure is an error: the watch
/// then does not report itself attached.
pub fn standing(
    ifname: &mut dyn FnMut(u32) -> Option<String>,
) -> Result<(Vec<Change>, std::collections::BTreeSet<String>), String> {
    let links = dump(None, RTM_GETLINK, &[0u8; 16])?;
    let virtual_ifaces = virtual_links(&links);
    let mut out = changes(HOOK_RTNETLINK, links, ifname);
    for family in [AF_INET, AF_INET6] {
        let mut rt = vec![0u8; 12];
        rt[0] = family;
        out.extend(changes(HOOK_RTNETLINK, dump(None, RTM_GETROUTE, &rt)?, ifname));
        out.extend(changes(HOOK_RTNETLINK, dump(None, RTM_GETRULE, &rt)?, ifname));
    }
    // nftables may be absent from the kernel: no tables, nothing standing.
    match dump(Some(netlink::NETFILTER), NFT_GETTABLE, &[0u8; 4]) {
        Ok(m) => out.extend(changes(HOOK_NFNETLINK, m, ifname)),
        Err(e) if e.contains("error -2") || e.contains("error -93") => {}
        Err(e) => return Err(e),
    }
    for (file, pf) in [("ip_tables_names", 2), ("ip6_tables_names", 10), ("arp_tables_names", 3)] {
        out.extend(legacy_tables(std::fs::read_to_string(format!("/proc/net/{file}")).ok().as_deref(), pf));
    }
    Ok((out, virtual_ifaces))
}

/// What stands of a family's legacy tables, from its `/proc/net/*_names`
/// file (`None`: no such file). Tables listed: they stand, and steer. No
/// file at all: this kernel cannot show legacy tables for the family
/// (`CONFIG_NETFILTER_XTABLES_LEGACY` unset), so a claim on them cannot be
/// shown gone. It is reported as standing but not steering, so a claim
/// made while watched (any `nf_setsockopt`, fail closed, even one the kernel
/// refused) survives a restart, as it read before it (a restart never
/// downgrades), and nothing unclaimed becomes `pre-attach`. An empty file:
/// none stand, and a claim goes.
pub fn legacy_tables(names: Option<&str>, pf: u8) -> Option<Change> {
    let steers = match names {
        Some(s) if s.trim().is_empty() => return None,
        Some(_) => true,
        None => false,
    };
    Some(Change {
        owner: Owner::Unattributed,
        kind: ChangeKind::Firewall,
        object: format!("legacy tables pf {pf}"),
        iface: None,
        steers,
        removed: false,
    })
}
