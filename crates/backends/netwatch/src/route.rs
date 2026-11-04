//! `ip route get` over netlink (B-22 a, feature `loader`): which interface
//! the kernel sends traffic to an address out of, policy rules and fwmark
//! tables (wg-quick's) honoured, because `RTM_GETROUTE` for one destination
//! runs the full lookup. `dns::charges` takes the answer as [`Lookup`].

use crate::dns::Lookup;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType};
use std::net::IpAddr;

const NLM_F_REQUEST: u16 = 0x1;
const NLMSG_ERROR: u16 = 2;
const RTM_GETROUTE: u16 = 26;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const ENETUNREACH: i32 = -101;
const EHOSTUNREACH: i32 = -113;
const NLMSG_HDRLEN: usize = 16;
const RTMSG_LEN: usize = 12;

/// The request for `addr`: `struct rtmsg` and `RTA_DST`.
fn request(addr: &IpAddr) -> Vec<u8> {
    let (family, bits, octets): (u8, u8, Vec<u8>) = match addr {
        IpAddr::V4(a) => (AF_INET, 32, a.octets().to_vec()),
        IpAddr::V6(a) => (AF_INET6, 128, a.octets().to_vec()),
    };
    // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags.
    let mut body = vec![family, bits, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    body.extend(((4 + octets.len()) as u16).to_ne_bytes());
    body.extend(RTA_DST.to_ne_bytes());
    body.extend(&octets);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let mut req = ((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes().to_vec();
    req.extend(RTM_GETROUTE.to_ne_bytes());
    req.extend(NLM_F_REQUEST.to_ne_bytes());
    req.extend(1u32.to_ne_bytes());
    req.extend(0u32.to_ne_bytes());
    req.extend(body);
    req
}

const RTN_LOCAL: u8 = 2;

/// The answer in a reply: the output interface's index and the route type
/// (`rtm_type`), or the kernel's error code. `Err(0)` is a reply with
/// neither (a malformed one).
fn answer(reply: &[u8]) -> Result<(u32, u8), i32> {
    let mut o = 0;
    while o + NLMSG_HDRLEN <= reply.len() {
        let len = u32::from_ne_bytes(reply[o..o + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(reply[o + 4..o + 6].try_into().unwrap());
        if len < NLMSG_HDRLEN || o + len > reply.len() {
            return Err(0);
        }
        if ty == NLMSG_ERROR {
            let code = reply.get(o + 16..o + 20).map_or(0, |b| i32::from_ne_bytes(b.try_into().unwrap()));
            return Err(code);
        }
        if let Some(attrs) = crate::parse::attrs(&reply[o..o + len], NLMSG_HDRLEN + RTMSG_LEN)
            && let Some((_, v)) = attrs.into_iter().find(|(t, _)| *t == RTA_OIF)
            && let Some(b) = v.get(0..4)
        {
            return Ok((u32::from_ne_bytes([b[0], b[1], b[2], b[3]]), reply[o + NLMSG_HDRLEN + 7]));
        }
        o += (len + 3) & !3;
    }
    Err(0)
}

/// Which interface reaches `addr`; `ifname` names an index.
pub fn get(addr: &IpAddr, ifname: &mut dyn FnMut(u32) -> Option<String>) -> Lookup {
    let Ok(fd) = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None) else { return Lookup::Failed };
    if rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0)).is_err() {
        return Lookup::Failed;
    }
    if rustix::net::sendto(&fd, &request(addr), SendFlags::empty(), &SocketAddrNetlink::new(0, 0)).is_err() {
        return Lookup::Failed;
    }
    let mut buf = vec![0u8; 1 << 14];
    let Ok((n, _)) = rustix::net::recv(&fd, &mut buf[..], RecvFlags::empty()) else { return Lookup::Failed };
    classify(&buf[..n], ifname)
}

/// A reply as a [`Lookup`]: the interface, no route (the kernel's "network
/// unreachable"), or failed. Separate from the socket so it can be tested.
pub fn classify(reply: &[u8], ifname: &mut dyn FnMut(u32) -> Option<String>) -> Lookup {
    match answer(reply) {
        // The machine's own address routes `local ... dev lo`: not a path out.
        Ok((_, RTN_LOCAL)) => Lookup::Local,
        Ok((index, _)) => ifname(index).map_or(Lookup::Failed, Lookup::Via),
        Err(ENETUNREACH | EHOSTUNREACH) => Lookup::NoRoute,
        Err(_) => Lookup::Failed,
    }
}
