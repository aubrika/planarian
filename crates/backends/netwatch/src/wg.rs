//! WireGuard peers' endpoints (B-22 b): the `endpoint` lines of a tunnel's
//! footprint, which the hold passes so a failed tunnel can reach its peer
//! and re-handshake (SPEC §12d). Peers are configured over generic
//! netlink, whose 512-byte capture in the probe cannot hold a configuration
//! with several peers; so a generic-netlink event, and every tick, is a
//! trigger to read the devices as the kernel now has them (`WG_CMD_GET_
//! DEVICE`, a dump) and take each peer's endpoint from that.
//!
//! This module is the pure half: the attribute walk and the endpoint
//! extraction, over the reply messages (`snapshot::wireguard` does the
//! dump). A reply carries the device's private and preshared keys when read
//! as root; nothing here copies, keeps or prints them, and only an
//! endpoint, a name and an index leave the walk.

use crate::model::{Endpoint, Proto};
use crate::parse::{attrs, cstr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NLMSG_HDRLEN: usize = 16;
const GENL_HDRLEN: usize = 4;

// include/uapi/linux/wireguard.h
const WGDEVICE_A_IFINDEX: u16 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PEERS: u16 = 8;
const WGPEER_A_ENDPOINT: u16 = 4;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Deliberate bugs, for the tests that show the endpoint property catches
/// them (rule 23).
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mutant {
    None,
    /// IPv6 endpoints are not read.
    NoV6,
    /// The port is read in host byte order.
    PortHostOrder,
    /// Only the first peer is read.
    FirstPeerOnly,
    /// The device's attributes after the peers (a second dump message) are lost:
    /// only the first message of a reply is read.
    FirstMessageOnly,
    /// Any command of the family is taken for a configuration (a read too).
    SetIsAnyCommand,
    /// Only the request's first attribute can name the device.
    NameMustBeFirst,
    /// A request in another network namespace is taken for the host's.
    IgnoreNetns,
    /// A kernel continuation must repeat the device identity.
    ContinuationNeedsIdentity,
    /// A GET_DEVICE request omits its required interface selector.
    NoSelector,
}

#[cfg(test)]
thread_local! {
    pub(crate) static MUTANT: std::cell::Cell<Mutant> = const { std::cell::Cell::new(Mutant::None) };
}

#[cfg(test)]
fn mutant(m: Mutant) -> bool {
    MUTANT.with(std::cell::Cell::get) == m
}

/// One WireGuard device as the kernel reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub ifindex: u32,
    /// Each peer's endpoint, if it has one (a peer that has never been
    /// contacted and has none configured has none).
    pub endpoints: Vec<Endpoint>,
}

/// A GET_DEVICE dump selects exactly one interface. WireGuard has no
/// all-devices dump: its kernel lookup rejects a request without IFINDEX or
/// IFNAME with EBADR. Enumerate links first, then ask by index, one at a time.
pub fn get_device_request(ifindex: u32) -> Vec<u8> {
    let mut body = vec![0, 1, 0, 0]; // WG_CMD_GET_DEVICE, version, reserved
    #[cfg(test)]
    if mutant(Mutant::NoSelector) {
        return body;
    }
    body.extend(8u16.to_ne_bytes());
    body.extend(WGDEVICE_A_IFINDEX.to_ne_bytes());
    body.extend(ifindex.to_ne_bytes());
    body
}

/// WireGuard interface indices from an RTM_GETLINK dump. The oracle for
/// this parser is the kernel's rtnetlink schema, not the interface's name:
/// IFLA_LINKINFO / IFLA_INFO_KIND must say `wireguard`. An unreadable link
/// cannot silently turn the list into a smaller one.
pub fn link_indices(msgs: &[Vec<u8>]) -> Result<Vec<u32>, String> {
    let mut out = std::collections::BTreeSet::new();
    for m in msgs {
        if m.len() < NLMSG_HDRLEN + 16 || u16::from_ne_bytes([m[4], m[5]]) != 16 {
            return Err("an unreadable link in the WireGuard interface list".into());
        }
        let a = attrs(m, NLMSG_HDRLEN + 16).ok_or("a link with a malformed attribute")?;
        for (_, info) in a.iter().filter(|(ty, _)| *ty == 18) {
            let info = attrs(info, 0).ok_or("a link with malformed linkinfo")?;
            if info.iter().any(|(ty, kind)| *ty == 1 && cstr(kind) == "wireguard") {
                let index = u32::from_ne_bytes(m[20..24].try_into().unwrap());
                if index == 0 {
                    return Err("a WireGuard link with no interface index".into());
                }
                out.insert(index);
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// An endpoint from a `sockaddr_in` or `sockaddr_in6` as the kernel writes
/// it (port in network byte order). `None` for any other length or family.
pub fn endpoint(sa: &[u8]) -> Option<Endpoint> {
    let family = u16::from_ne_bytes(sa.get(0..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(sa.get(2..4)?.try_into().ok()?);
    #[cfg(test)]
    let port = if mutant(Mutant::PortHostOrder) { port.swap_bytes() } else { port };
    let addr = match (family, sa.len()) {
        (AF_INET, 16) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(sa.get(4..8)?).ok()?)),
        #[cfg(test)]
        (AF_INET6, 28) if mutant(Mutant::NoV6) => return None,
        (AF_INET6, 28) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(sa.get(8..24)?).ok()?)),
        _ => return None,
    };
    Some(Endpoint { proto: Proto::Udp, addr, port })
}

/// The devices in a `WG_CMD_GET_DEVICE` dump reply (each message: netlink
/// header, generic netlink header, attributes). A message that is not a
/// readable device is an error: the caller fails closed.
pub fn devices(msgs: &[Vec<u8>]) -> Result<Vec<Device>, String> {
    let mut out: Vec<Device> = vec![];
    let mut current: Option<usize> = None;
    for (i, m) in msgs.iter().enumerate() {
        #[cfg(test)]
        if i > 0 && mutant(Mutant::FirstMessageOnly) {
            break;
        }
        let _ = i;
        if m.len() < NLMSG_HDRLEN + GENL_HDRLEN {
            return Err("a wireguard reply with a short header".into());
        }
        let a = attrs(m, NLMSG_HDRLEN + GENL_HDRLEN).ok_or("a wireguard reply with a malformed attribute")?;
        // Linux emits the device's identity only in the first chunk. Later
        // chunks can contain peers alone, belonging to that same device.
        let mut dev = Device::default();
        for (ty, v) in &a {
            match *ty {
                WGDEVICE_A_IFINDEX => {
                    dev.ifindex = u32::from_ne_bytes(v.get(0..4).ok_or("short ifindex")?.try_into().unwrap())
                }
                WGDEVICE_A_IFNAME => dev.name = cstr(v),
                WGDEVICE_A_PEERS => {
                    let peers = attrs(v, 0).ok_or("a wireguard peer list with a malformed attribute")?;
                    for (_, peer) in peers {
                        #[cfg(test)]
                        if !dev.endpoints.is_empty() && mutant(Mutant::FirstPeerOnly) {
                            break;
                        }
                        let fields = attrs(peer, 0).ok_or("a wireguard peer with a malformed attribute")?;
                        if let Some((_, sa)) = fields.iter().find(|(t, _)| *t == WGPEER_A_ENDPOINT) {
                            dev.endpoints.push(endpoint(sa).ok_or("a wireguard peer endpoint that is not an address")?);
                        }
                    }
                }
                _ => {}
            }
        }
        if dev.name.is_empty() && dev.ifindex == 0 {
            #[cfg(test)]
            if mutant(Mutant::ContinuationNeedsIdentity) {
                return Err("a wireguard reply naming no device".into());
            }
            let Some(index) = current else { return Err("a wireguard reply naming no device".into()) };
            out[index].endpoints.extend(dev.endpoints);
            continue;
        }
        match out.iter().position(|d| d.ifindex == dev.ifindex && d.name == dev.name) {
            Some(index) => {
                out[index].endpoints.extend(dev.endpoints);
                current = Some(index);
            }
            None => {
                current = Some(out.len());
                out.push(dev);
            }
        }
    }
    Ok(out)
}

/// WG_CMD_SET_DEVICE (include/uapi/linux/wireguard.h).
const WG_CMD_SET_DEVICE: u8 = 1;

/// What a generic netlink request is to WireGuard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Genl {
    /// Another family, or a read (`WG_CMD_GET_DEVICE`): no configuration.
    Other,
    /// A configuration of this device (named in the request).
    Set(String),
    /// A configuration of a device the request names by index only, or by
    /// a name the capture cut off: the caller resolves the index, or fails
    /// closed.
    SetIndex(u32),
    SetUnnamed,
}

/// What a request is to the *host's* WireGuard: [`classify`], but only for a
/// request that acts in the host's network namespace (`own`). A container's
/// `wg set` on a device of the same name configures its own, not the host's,
/// and an index there is not the host's index. A request in another
/// namespace is `Other`; one whose namespace was not read is left to the
/// caller's loss handling (`parse::take` marks it), so it is `Other` here too.
pub fn host_request(ev: &crate::ebpf::Event, family: u16, own: u32) -> Genl {
    #[cfg(test)]
    let host = ev.netns == own || mutant(Mutant::IgnoreNetns);
    #[cfg(not(test))]
    let host = ev.netns == own;
    if !host {
        return Genl::Other;
    }
    classify(ev, family)
}

/// Classify a generic netlink request captured by the probe, given
/// WireGuard's family id (`nlmsg_type`, assigned at module load). The
/// device is named by `WGDEVICE_A_IFNAME` (or `_IFINDEX`) among the first
/// attributes; the capture may cut the rest off, so attributes are read up
/// to the cut.
pub fn classify(ev: &crate::ebpf::Event, family: u16) -> Genl {
    if ev.hook != crate::ebpf::HOOK_GENL || ev.nlmsg_type() != Some(family) {
        return Genl::Other;
    }
    #[cfg(test)]
    let reads_only = mutant(Mutant::SetIsAnyCommand);
    #[cfg(not(test))]
    let reads_only = false;
    if ev.data.get(NLMSG_HDRLEN).copied() != Some(WG_CMD_SET_DEVICE) && !reads_only {
        return Genl::Other;
    }
    let (b, mut o) = (&ev.data, NLMSG_HDRLEN + GENL_HDRLEN);
    let (mut name, mut index) = (None, None);
    while o + 4 <= b.len() {
        let len = u16::from_ne_bytes([b[o], b[o + 1]]) as usize;
        let ty = u16::from_ne_bytes([b[o + 2], b[o + 3]]) & 0x3fff;
        if len < 4 || o + len > b.len() {
            break;
        }
        let v = &b[o + 4..o + len];
        match ty {
            WGDEVICE_A_IFNAME => name = Some(cstr(v)),
            WGDEVICE_A_IFINDEX if v.len() >= 4 => index = Some(u32::from_ne_bytes([v[0], v[1], v[2], v[3]])),
            _ => {}
        }
        #[cfg(test)]
        if mutant(Mutant::NameMustBeFirst) {
            break;
        }
        o += (len + 3) & !3;
    }
    match (name, index) {
        (Some(n), _) if !n.is_empty() => Genl::Set(n),
        (_, Some(i)) => Genl::SetIndex(i),
        _ => Genl::SetUnnamed,
    }
}
