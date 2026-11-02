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

/// Send one dump request and collect every reply message's bytes.
/// `protocol`: `None` is `NETLINK_ROUTE`.
fn dump(protocol: Option<rustix::net::Protocol>, ty: u16, body: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let fd = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, protocol)
        .map_err(|e| format!("netlink socket: {e}"))?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|e| format!("netlink bind: {e}"))?;
    let mut req = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
    req.extend(ty.to_ne_bytes());
    req.extend((NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req.extend(1u32.to_ne_bytes());
    req.extend(0u32.to_ne_bytes());
    req.extend(body);
    rustix::net::sendto(&fd, &req, SendFlags::empty(), &SocketAddrNetlink::new(0, 0))
        .map_err(|e| format!("netlink send: {e}"))?;
    let mut out = vec![];
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let (n, _) =
            rustix::net::recv(&fd, &mut buf[..], RecvFlags::empty()).map_err(|e| format!("netlink recv: {e}"))?;
        let mut o = 0;
        while o + 16 <= n {
            let len = u32::from_ne_bytes(buf[o..o + 4].try_into().unwrap()) as usize;
            let t = u16::from_ne_bytes(buf[o + 4..o + 6].try_into().unwrap());
            if len < 16 || o + len > n {
                return Err("a malformed netlink reply".into());
            }
            match t {
                NLMSG_DONE => return Ok(out),
                NLMSG_ERROR => {
                    let code = buf.get(o + 16..o + 20).map(|b| i32::from_ne_bytes(b.try_into().unwrap())).unwrap_or(0);
                    return if code == 0 { Ok(out) } else { Err(format!("netlink dump {ty}: error {code}")) };
                }
                _ => out.push(buf[o..o + len].to_vec()),
            }
            o += (len + 3) & !3;
        }
        if n == 0 {
            return Ok(out);
        }
    }
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
        if std::fs::read_to_string(format!("/proc/net/{file}")).is_ok_and(|s| !s.trim().is_empty()) {
            out.push(Change {
                owner: Owner::Unattributed,
                kind: ChangeKind::Firewall,
                object: format!("legacy tables pf {pf}"),
                iface: None,
                steers: true,
                removed: false,
            });
        }
    }
    Ok((out, virtual_ifaces))
}
