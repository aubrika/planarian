//! DNS and proxy steering (B-22 a): the pure half. A unit that points the
//! machine's resolver at its own servers, or sets the system proxy, steers
//! traffic as surely as a default route, but through files, not netlink.
//!
//! **The rule** (SPEC §12d: "DNS servers on *its* interface"; coordinator,
//! Nov 3). A name server or proxy host steers for the unit(s) whose
//! interface *carries* it, not for whoever wrote the setting. Each pass,
//! nothing remembered:
//! 1. read the settings ([`resolv_servers`], [`netif_servers`],
//!    [`proxy_hosts`]): every address they name; a loopback address steers
//!    nothing (the machine's own stub: a dead one fails DNS closed rather
//!    than leaking);
//! 2. ask the kernel which interface reaches each ([`Lookup`], the `ip route
//!    get` equivalent, policy rules and fwmark tables such as wg-quick's
//!    honoured); an address with a zone (`fe80::1%tun0`) and a resolved
//!    link's own servers name their interface themselves;
//! 3. charge the owners of that interface ([`charges`]): for a *virtual*
//!    interface, the units with a claim on it (its creator) and those that
//!    added a steering route over it; a *physical* interface (the uplink,
//!    DHCP-learned DNS) steers for nobody and is charged to nobody;
//! 4. *unknown* fails closed: a lookup that failed, an address that cannot
//!    be read, or a virtual interface nobody is known to own. The setting is
//!    then an object-bound unattributed mark that clears as soon as the
//!    lookup succeeds or the setting changes, never a global one.
//!
//! A route change moves the charge with it, because it is recomputed.

use crate::model::ChangeKind;
use planarian_schema::UnitId;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

/// Deliberate bugs, for the tests that show the properties catch them (rule 23).
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mutant {
    None,
    /// A loopback name server counts as steering.
    LoopbackSteers,
    /// A commented-out line counts.
    CommentCounts,
    /// Only the first name server of a file is looked at.
    FirstServerOnly,
    /// A zone suffix (`fe80::1%eth0`) is not stripped.
    NoZoneStrip,
    /// Proxy variable names are matched in lower case only.
    ProxyLowerOnly,
    /// The interface the lookup picks is ignored: every virtual interface's
    /// owners are charged.
    ChargeEveryOwner,
    /// A physical interface's route adder is charged (DHCP clients count).
    PhysicalCounts,
    /// A failed lookup charges nobody (fails open).
    FailedIsNobody,
    /// An unowned virtual interface charges nobody.
    UnownedIsNobody,
    /// Only the interface's creator is charged, not the unit that added the route.
    CreatorOnly,
    /// A local address is taken for a route over `lo` (a virtual link
    /// nobody owns: unknown, which holds every tool).
    LocalIsUnknown,
    /// A resolved link's own servers are looked up like any address (so a
    /// loopback-routed lookup could pick another interface).
    LinkLooksUp,
}

#[cfg(test)]
thread_local! {
    pub(crate) static MUTANT: std::cell::Cell<Mutant> = const { std::cell::Cell::new(Mutant::None) };
}

#[cfg(test)]
fn mutant(m: Mutant) -> bool {
    MUTANT.with(std::cell::Cell::get) == m
}

/// One address a setting names, and the interface it names itself, if any.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// A non-loopback address, with the interface its zone names.
    Addr { addr: IpAddr, zone: Option<String> },
    /// Something in an address position that cannot be read (fail closed).
    Unreadable,
}

/// An address in a name server position: `1.2.3.4`, `1.2.3.4:53`, `::1`,
/// `[::1]:53`, `fe80::1%eth0`, `1.1.1.1#cloudflare-dns.com`. `None` is a
/// loopback address (steers nothing).
fn target(tok: &str) -> Option<Target> {
    let tok = tok.split('#').next().unwrap_or("");
    let tok = if let Some(rest) = tok.strip_prefix('[') { rest.split(']').next().unwrap_or("") } else { tok };
    #[cfg(test)]
    let strip = !mutant(Mutant::NoZoneStrip);
    #[cfg(not(test))]
    let strip = true;
    let (host, zone) = match tok.split_once('%') {
        Some((h, z)) if strip => (h, Some(z.to_string())),
        _ => (tok, None),
    };
    let addr = host.parse::<IpAddr>().ok().or_else(|| {
        // `1.2.3.4:53`
        let (h, port) = host.rsplit_once(':')?;
        port.parse::<u16>().ok()?;
        h.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
    });
    match addr {
        Some(a) if loopback(a) => None,
        Some(addr) => Some(Target::Addr { addr, zone }),
        None => Some(Target::Unreadable),
    }
}

fn loopback(a: IpAddr) -> bool {
    #[cfg(test)]
    if mutant(Mutant::LoopbackSteers) {
        return false;
    }
    match a {
        IpAddr::V4(v) => v.octets()[0] == 127,
        IpAddr::V6(v) => v == Ipv6Addr::LOCALHOST || v.to_ipv4_mapped().is_some_and(|m| m.octets()[0] == 127),
    }
}

fn targets<'a>(toks: impl Iterator<Item = &'a str>) -> Vec<Target> {
    #[cfg(test)]
    let toks: Box<dyn Iterator<Item = &'a str>> =
        if mutant(Mutant::FirstServerOnly) { Box::new(toks.take(1)) } else { Box::new(toks) };
    let mut out: Vec<Target> = toks.filter_map(target).collect();
    out.sort();
    out.dedup();
    out
}

/// `/etc/resolv.conf`: the non-loopback servers its `nameserver` lines name.
pub fn resolv_servers(content: &str) -> Vec<Target> {
    let line = |l: &str| -> Option<String> {
        let l = l.trim();
        #[cfg(test)]
        let l = if mutant(Mutant::CommentCounts) { l.trim_start_matches(['#', ';']).trim() } else { l };
        #[cfg(test)]
        let skip = !mutant(Mutant::CommentCounts) && (l.starts_with('#') || l.starts_with(';'));
        #[cfg(not(test))]
        let skip = l.starts_with('#') || l.starts_with(';');
        if skip {
            return None;
        }
        let mut it = l.split_whitespace();
        (it.next() == Some("nameserver")).then(|| it.next().unwrap_or("").to_string()).filter(|s| !s.is_empty())
    };
    let servers: Vec<String> = content.lines().filter_map(line).collect();
    targets(servers.iter().map(String::as_str))
}

/// A resolved link's (or the global) state file: its `DNS=` and `DNS_EX=` lines.
pub fn netif_servers(content: &str) -> Vec<Target> {
    let toks: Vec<&str> = content
        .lines()
        .filter_map(|l| l.trim().strip_prefix("DNS=").or_else(|| l.trim().strip_prefix("DNS_EX=")))
        .flat_map(str::split_whitespace)
        .collect();
    targets(toks.into_iter())
}

/// A file that sets environment variables (`/etc/environment`, a profile
/// script, NixOS's `/etc/set-environment`): the hosts of the proxy
/// variables it sets to a value. An IP literal is a [`Target`]; a host *name*
/// is left uncovered (resolving it would be a DNS query netwatch must not
/// make; named in B-22).
pub fn proxy_hosts(content: &str) -> Vec<Target> {
    const VARS: [&str; 4] = ["http_proxy", "https_proxy", "all_proxy", "ftp_proxy"];
    let mut toks = vec![];
    for l in content.lines() {
        let l = l.trim();
        if l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").or_else(|| l.strip_prefix("declare -x ")).unwrap_or(l).trim_start();
        let Some((k, v)) = l.split_once('=') else { continue };
        let k = k.trim();
        #[cfg(test)]
        let named = if mutant(Mutant::ProxyLowerOnly) {
            VARS.contains(&k)
        } else {
            VARS.iter().any(|n| n.eq_ignore_ascii_case(k))
        };
        #[cfg(not(test))]
        let named = VARS.iter().any(|n| n.eq_ignore_ascii_case(k));
        if !named {
            continue;
        }
        let v = v.trim().trim_matches(['"', '\'']).trim();
        if v.is_empty() {
            continue;
        }
        // `scheme://[user[:pass]@]host[:port][/path]`
        let rest = v.split_once("://").map_or(v, |(_, r)| r);
        let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
        let host = rest.split('/').next().unwrap_or("");
        toks.push(host.to_string());
    }
    // A name (not an IP literal) is not covered; only literals become targets.
    let literals: Vec<&str> = toks
        .iter()
        .map(String::as_str)
        .filter(|h| {
            let bare = h.trim_start_matches('[');
            bare.chars().next().is_some_and(|c| c.is_ascii_hexdigit() || c == ':')
                && (h.parse::<IpAddr>().is_ok()
                    || bare.split(']').next().is_some_and(|b| b.parse::<IpAddr>().is_ok())
                    || h.rsplit_once(':').is_some_and(|(a, p)| a.parse::<IpAddr>().is_ok() && p.parse::<u16>().is_ok()))
        })
        .collect();
    targets(literals.into_iter())
}

/// What the kernel says about reaching an address (`ip route get`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Out through this interface.
    Via(String),
    /// No route (the kernel's `ENETUNREACH`): no interface carries it.
    NoRoute,
    /// One of the machine's own addresses (`local ... dev lo`, route type
    /// `RTN_LOCAL`): a server on this machine (dnsmasq, a Pi-hole on the
    /// host's LAN address, libvirt's virbr0), not a path out. Charges
    /// nobody, as loopback does.
    Local,
    /// The lookup itself failed.
    Failed,
}

/// A setting's object: `(Dns, "resolv.conf")`, `(Dns, "link <name>")`,
/// `(Proxy, "<file>")`.
pub type Key = (ChangeKind, String);

/// What one setting's addresses come to.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Charge {
    /// The units that own the interface(s) carrying it.
    pub owners: BTreeSet<UnitId>,
    /// Something could not be placed (fail closed): an object-bound
    /// unattributed mark.
    pub unknown: bool,
}

/// The units that own an interface, by how.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Owners {
    /// Those with a claim on the interface (it made it, or brought it in).
    pub creators: BTreeSet<UnitId>,
    /// Those that added a steering route over it.
    pub routers: BTreeSet<UnitId>,
}

/// What the footprints say about an interface.
pub struct World<'a> {
    /// A virtual link (something created it): only these have owners.
    pub virtual_ifaces: &'a BTreeSet<String>,
    /// Who owns an interface.
    pub owners: &'a dyn Fn(&str) -> Owners,
    /// The kernel's answer for an address.
    pub lookup: &'a dyn Fn(&IpAddr) -> Lookup,
}

/// An interface carries the setting: its owners (its creator and the units
/// that routed over it), or unknown if it is virtual and nobody is known to
/// own it. A physical one steers for nobody.
fn carried(iface: &str, w: &World<'_>, c: &mut Charge) {
    let o = (w.owners)(iface);
    if !w.virtual_ifaces.contains(iface) {
        #[cfg(test)]
        if mutant(Mutant::PhysicalCounts) {
            c.owners.extend(o.creators.into_iter().chain(o.routers));
        }
        return; // the uplink: steers for nobody
    }
    let mut owners = o.creators;
    #[cfg(test)]
    let routers = !mutant(Mutant::CreatorOnly);
    #[cfg(not(test))]
    let routers = true;
    if routers {
        owners.extend(o.routers);
    }
    if owners.is_empty() {
        #[cfg(test)]
        if mutant(Mutant::UnownedIsNobody) {
            return;
        }
        c.unknown = true;
    }
    c.owners.extend(owners);
}

/// Who a setting (the addresses it names) steers for. `link`: the interface
/// a resolved link's own servers belong to.
pub fn charges(targets: &[Target], link: Option<&str>, w: &World<'_>) -> Charge {
    let mut c = Charge::default();
    for t in targets {
        match t {
            Target::Unreadable => c.unknown = true,
            Target::Addr { addr, zone } => {
                #[cfg(test)]
                let link_lookup = mutant(Mutant::LinkLooksUp);
                #[cfg(not(test))]
                let link_lookup = false;
                if let Some(l) = link.filter(|_| !link_lookup) {
                    carried(l, w, &mut c);
                } else if let Some(z) = zone {
                    carried(z, w, &mut c);
                } else {
                    match (w.lookup)(addr) {
                        Lookup::Via(i) => {
                            #[cfg(test)]
                            if mutant(Mutant::ChargeEveryOwner) {
                                for v in w.virtual_ifaces {
                                    carried(v, w, &mut c);
                                }
                                continue;
                            }
                            carried(&i, w, &mut c);
                        }
                        Lookup::NoRoute => {}
                        #[cfg(test)]
                        Lookup::Local if mutant(Mutant::LocalIsUnknown) => c.unknown = true,
                        Lookup::Local => {}
                        Lookup::Failed => {
                            #[cfg(test)]
                            if mutant(Mutant::FailedIsNobody) {
                                continue;
                            }
                            c.unknown = true;
                        }
                    }
                }
            }
        }
    }
    c
}

/// Every setting's charge: the whole answer for one pass.
pub fn all(settings: &BTreeMap<Key, (Vec<Target>, Option<String>)>, w: &World<'_>) -> BTreeMap<Key, Charge> {
    settings
        .iter()
        .map(|(k, (t, link))| (k.clone(), charges(t, link.as_deref(), w)))
        .filter(|(_, c)| !c.owners.is_empty() || c.unknown)
        .collect()
}
