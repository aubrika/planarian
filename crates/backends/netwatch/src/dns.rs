//! DNS and proxy steering (B-22 a): the pure half. A unit that points the
//! machine's resolver at its own servers, or sets the system proxy, steers
//! traffic as surely as a default route (SPEC §12d "...DNS servers on its
//! interface; the system proxy"), but through files, not netlink.
//!
//! **State model** (coordinator, Nov 3). Each setting is one *object*: `(Dns,
//! "resolv.conf")`, `(Dns, "link <ifname>")` for a resolved link, `(Proxy,
//! "<file>")`. Whether it steers is computed from its *current content* on
//! every read and never remembered: a name server that is not the machine's
//! own loopback stub, or a proxy variable with a value. Content that stops
//! steering, or a file or link that goes, clears the object for *everyone*
//! ([`Action::Clear`]), so a charge cannot stick (B-24's shape). The objects
//! are singletons: a new claimant replaces the old ([`Action::Claim`]).
//! [`reconcile`] decides, from what is observed, who claims what.

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
    /// A zone suffix (`fe80::1%eth0`) makes an address unreadable... and a
    /// loopback with one steers.
    NoZoneStrip,
    /// Proxy variable names are matched in lower case only.
    ProxyLowerOnly,
    /// A charge for a write by an unknown process goes to every network tool,
    /// running or not.
    ChargeAllTools,
    /// Content that stops steering does not clear its claimants.
    NeverClear,
    /// An attributed write adds its unit to the claimants instead of replacing them.
    AttributedAdds,
    /// A link's DNS goes to the running tools even when the interface has an owner.
    IgnoreLinkOwner,
}

#[cfg(test)]
thread_local! {
    pub(crate) static MUTANT: std::cell::Cell<Mutant> = const { std::cell::Cell::new(Mutant::None) };
}

#[cfg(test)]
fn mutant(m: Mutant) -> bool {
    MUTANT.with(std::cell::Cell::get) == m
}

/// An address in a name server position: `1.2.3.4`, `1.2.3.4:53`, `::1`,
/// `[::1]:53`, `fe80::1%eth0`, `1.1.1.1#cloudflare-dns.com`. `None` if it is
/// none of those (the caller fails closed: an unreadable server steers).
fn server(tok: &str) -> Option<IpAddr> {
    let tok = tok.split('#').next().unwrap_or("");
    let tok = if let Some(rest) = tok.strip_prefix('[') { rest.split(']').next().unwrap_or("") } else { tok };
    #[cfg(test)]
    let zone = !mutant(Mutant::NoZoneStrip);
    #[cfg(not(test))]
    let zone = true;
    let tok = if zone { tok.split('%').next().unwrap_or("") } else { tok };
    if let Ok(a) = tok.parse::<IpAddr>() {
        return Some(a);
    }
    // `1.2.3.4:53`
    let (host, port) = tok.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
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

/// Whether any of `servers` steers: one that is not a loopback address (the
/// machine's own stub: a dead stub fails DNS closed rather than leaking),
/// or that cannot be read.
fn any_steers<'a>(servers: impl Iterator<Item = &'a str>) -> bool {
    #[cfg(test)]
    let servers: Box<dyn Iterator<Item = &'a str>> =
        if mutant(Mutant::FirstServerOnly) { Box::new(servers.take(1)) } else { Box::new(servers) };
    let mut servers = servers;
    servers.any(|t| server(t).is_none_or(|a| !loopback(a)))
}

/// `/etc/resolv.conf`: does a `nameserver` line name a server that is not loopback?
pub fn resolv_steers(content: &str) -> bool {
    let line = |l: &'_ str| -> Option<String> {
        let l = l.trim();
        #[cfg(test)]
        let comment = !mutant(Mutant::CommentCounts);
        #[cfg(not(test))]
        let comment = true;
        let l = if comment { l } else { l.trim_start_matches(['#', ';']).trim() };
        if comment && (l.starts_with('#') || l.starts_with(';')) {
            return None;
        }
        let mut it = l.split_whitespace();
        (it.next() == Some("nameserver")).then(|| it.next().unwrap_or("").to_string()).filter(|s| !s.is_empty())
    };
    let servers: Vec<String> = content.lines().filter_map(line).collect();
    any_steers(servers.iter().map(String::as_str))
}

/// A resolved link's state file (`/run/systemd/resolve/netif/<ifindex>`): its
/// `DNS=` (and `DNS_EX=`) lines.
pub fn netif_steers(content: &str) -> bool {
    let toks: Vec<&str> = content
        .lines()
        .filter_map(|l| l.trim().strip_prefix("DNS=").or_else(|| l.trim().strip_prefix("DNS_EX=")))
        .flat_map(str::split_whitespace)
        .collect();
    any_steers(toks.into_iter())
}

/// A file that sets environment variables (`/etc/environment`, a profile
/// script, NixOS's `/etc/set-environment`): does it set a proxy variable to a value?
pub fn proxy_steers(content: &str) -> bool {
    const VARS: [&str; 4] = ["http_proxy", "https_proxy", "all_proxy", "ftp_proxy"];
    content.lines().any(|l| {
        let l = l.trim();
        if l.starts_with('#') {
            return false;
        }
        let l = l.strip_prefix("export ").or_else(|| l.strip_prefix("declare -x ")).unwrap_or(l).trim_start();
        let Some((k, v)) = l.split_once('=') else { return false };
        let k = k.trim();
        #[cfg(test)]
        let named = if mutant(Mutant::ProxyLowerOnly) {
            VARS.contains(&k)
        } else {
            VARS.iter().any(|n| n.eq_ignore_ascii_case(k))
        };
        #[cfg(not(test))]
        let named = VARS.iter().any(|n| n.eq_ignore_ascii_case(k));
        named && !v.trim().trim_matches(['"', '\'']).trim().is_empty()
    })
}

/// An object and what is observed of it now.
pub type Key = (ChangeKind, String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obs {
    /// It names something that steers, now.
    pub steers: bool,
    /// The interface it is for (a resolved link), if any.
    pub iface: Option<String>,
}

/// Who wrote an object since the last pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Writer {
    /// A write whose process was seen and is in this unit's cgroup.
    Unit(UnitId),
    /// A write whose process is gone or in no unit, or a change with no write
    /// seen at all (an event missed).
    Unknown,
    /// Nothing was written to it.
    NoWrite,
}

/// What the tracker should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Exactly these units claim the object, which steers (replacing any other claimant).
    Claim { key: Key, owners: BTreeSet<UnitId>, iface: Option<String> },
    /// The object no longer steers or exists: nobody claims it.
    Clear { key: Key },
}

/// Decide, from what is observed, who claims each object (coordinator, Nov 3).
///
/// - An object that no longer steers (or is gone) and has claimants is cleared, for everyone.
/// - A steering object written by a known unit is that unit's alone (replacing).
/// - One written by an unknown process, or that steers with no claimant (found
///   at attach, or its event missed), is charged to the network tools *running
///   now* (`running`): the only ones that could have written it. With none
///   running it is the machine's baseline, uncovered (B-22): no claim, and
///   any old claimant is cleared (the content is no longer theirs).
/// - A resolved link's DNS is its interface's owner's whoever wrote it
///   (`link_owner`), else the running tools'.
pub fn reconcile(
    observed: &BTreeMap<Key, Obs>,
    claimed: &BTreeMap<Key, BTreeSet<UnitId>>,
    writers: &BTreeMap<Key, Writer>,
    running: &BTreeSet<UnitId>,
    link_owner: &dyn Fn(&str) -> Option<UnitId>,
    all_tools: &BTreeSet<UnitId>,
) -> Vec<Action> {
    let mut out = vec![];
    for (key, who) in claimed {
        let steers = observed.get(key).is_some_and(|o| o.steers);
        #[cfg(test)]
        let steers = steers || mutant(Mutant::NeverClear);
        if !steers && !who.is_empty() {
            out.push(Action::Clear { key: key.clone() });
        }
    }
    let none = BTreeSet::new();
    for (key, obs) in observed.iter().filter(|(_, o)| o.steers) {
        let cur = claimed.get(key).unwrap_or(&none);
        let writer = writers.get(key).unwrap_or(&Writer::NoWrite);
        #[cfg(test)]
        let ignore_link = mutant(Mutant::IgnoreLinkOwner);
        #[cfg(not(test))]
        let ignore_link = false;
        let link = if ignore_link { None } else { obs.iface.as_deref().and_then(link_owner) };
        let charged = || {
            #[cfg(test)]
            if mutant(Mutant::ChargeAllTools) {
                return all_tools.clone();
            }
            let _ = all_tools;
            running.clone()
        };
        let want: Option<BTreeSet<UnitId>> = if let Some(o) = link {
            Some([o].into())
        } else {
            match writer {
                Writer::Unit(u) => {
                    #[cfg(test)]
                    if mutant(Mutant::AttributedAdds) {
                        let mut s = cur.clone();
                        s.insert(u.clone());
                        out.push(Action::Claim { key: key.clone(), owners: s, iface: obs.iface.clone() });
                        continue;
                    }
                    Some([u.clone()].into())
                }
                Writer::Unknown => Some(charged()),
                Writer::NoWrite if cur.is_empty() => Some(charged()),
                Writer::NoWrite => None,
            }
        };
        match want {
            Some(set) if set.is_empty() && !cur.is_empty() => out.push(Action::Clear { key: key.clone() }),
            Some(set) if set.is_empty() => {}
            Some(set) if set != *cur => {
                out.push(Action::Claim { key: key.clone(), owners: set, iface: obs.iface.clone() });
            }
            _ => {}
        }
    }
    out
}
