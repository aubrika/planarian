//! Properties for the pure parts of netwatch (ledger rows N1-N9, docs/
//! regression-ledger.md): each states the invariant a fix established, with
//! an oracle written from the spec (§12d) or the kernel's own numbering
//! rather than from the code under test, and a frame condition where the
//! fix must change nothing else. The ledger says which mutant each one
//! catches. `PROPTEST_CASES` overrides the case counts.

use crate::ebpf::{Event, HOOK_NETDEV, HOOK_NETMOVE, HOOK_NFBATCH, HOOK_NFNETLINK, HOOK_RTNETLINK, HOOK_SOCKOPT};
use crate::host::unit_of_cgroup;
use crate::model::{Change, ChangeKind, Claims, Owner, Tracker, WatchState};
use crate::parse::{Parsed, parse, take};
use planarian_schema::UnitId;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

fn cfg(default: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default);
    ProptestConfig { cases, ..ProptestConfig::default() }
}

const OWN_NETNS: u32 = 4_026_531_840;
const NOW: u64 = 1_000;

fn event(hook: u32, netns: u32, ty: u16, flags: u16, body: &[u8]) -> Event {
    let mut data = vec![0u8; 16];
    data[4..6].copy_from_slice(&ty.to_ne_bytes());
    data[6..8].copy_from_slice(&flags.to_ne_bytes());
    data.extend_from_slice(body);
    Event { cgroup: 1, tgid: 2, hook, len: data.len() as u32, netns, cgpath: None, data }
}

fn no_names(_: u32) -> Option<String> {
    None
}

// The reader is read-only, but the kernel probes observe its requests too.
// Appending any number of those must leave the external work unchanged.
proptest! {
    #![proptest_config(cfg(256))]
    #[test]
    fn the_readers_requests_never_become_external_work(
        reader in 1u32..u32::MAX,
        rows in prop::collection::vec((any::<bool>(), any::<u32>(), any::<u32>(), any::<u32>()), 0..128),
    ) {
        let expected = rows.iter().filter(|(own, _, _, _)| !own).count();
        let events: Vec<_> = rows.iter().map(|(own, hook, netns, noise)| {
            let mut ev = event(*hook, *netns, *noise as u16, 0, &noise.to_ne_bytes());
            ev.tgid = if *own { reader } else { reader.wrapping_add(1) };
            ev
        }).collect();
        let work = events.iter().filter(|ev| !ev.is_own_request(reader)).count();
        prop_assert_eq!(work, expected);
        // An empty external input stays idle after the kernel reports the
        // reads the previous scan made, whatever protocol they used.
        prop_assert!(events.iter().filter(|ev| ev.tgid == reader).all(|ev| ev.is_own_request(reader)));
    }
}

mod wgqueries {
    use super::*;
    use crate::wg;

    fn link(index: u32, kind: &str) -> Vec<u8> {
        let mut body = vec![0u8; 16]; // ifinfomsg
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body.extend(nl_attr(3, format!("link{index}\0").as_bytes()));
        body.extend(nl_attr(18, &nl_attr(1, format!("{kind}\0").as_bytes())));
        let mut msg = vec![0u8; 16];
        msg[4..6].copy_from_slice(&16u16.to_ne_bytes()); // RTM_NEWLINK
        msg.extend(body);
        let len = msg.len() as u32;
        msg[..4].copy_from_slice(&len.to_ne_bytes());
        msg
    }

    proptest! {
        #![proptest_config(cfg(256))]
        #[test]
        fn every_wireguard_link_gets_its_own_selected_dump(
            links in prop::collection::btree_map(1u32..u32::MAX, any::<bool>(), 0..32),
        ) {
            let msgs: Vec<_> = links.iter().map(|(index, wg)| link(*index, if *wg { "wireguard" } else { "dummy" })).collect();
            let wanted: Vec<_> = links.iter().filter_map(|(index, wg)| wg.then_some(*index)).collect();
            let got = wg::link_indices(&msgs).unwrap();
            prop_assert_eq!(&got, &wanted);
            for index in got {
                let body = wg::get_device_request(index);
                // Independent reading of wireguard.h: command 0, version 1,
                // one NLA_U32 attribute (type 1, length 8) naming the index.
                let mut expected = vec![0, 1, 0, 0];
                expected.extend(8u16.to_ne_bytes());
                expected.extend(1u16.to_ne_bytes());
                expected.extend(index.to_ne_bytes());
                prop_assert_eq!(body, expected);
            }
        }
    }

    #[test]
    fn the_missing_selector_mutant_is_caught() {
        let full = wg::get_device_request(7);
        wg::MUTANT.with(|m| m.set(wg::Mutant::NoSelector));
        let missing = wg::get_device_request(7);
        wg::MUTANT.with(|m| m.set(wg::Mutant::None));
        assert_eq!(full.len(), 12);
        assert_eq!(missing, vec![0, 1, 0, 0]);
        assert_ne!(missing, full, "the old request omits the required selector");
    }

    #[test]
    fn an_unreadable_link_list_cannot_become_an_empty_dump() {
        let good = link(7, "wireguard");
        assert_eq!(wg::link_indices(std::slice::from_ref(&good)).unwrap(), vec![7]);
        assert!(wg::link_indices(&[good[..good.len() - 5].to_vec()]).is_err());
        assert!(wg::link_indices(&[link(0, "wireguard")]).is_err());
        assert!(wg::link_indices(&[vec![0; 8]]).is_err());
    }
}

mod wgcontinuations {
    use super::*;
    use crate::{Endpoint, Proto, wg};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn message(index: Option<u32>, endpoints: &[Endpoint]) -> Vec<u8> {
        let mut body = vec![0, 1, 0, 0];
        if let Some(index) = index {
            body.extend(nl_attr(1, &index.to_ne_bytes()));
            body.extend(nl_attr(2, b"wg0\0"));
        }
        let mut peers = vec![];
        for endpoint in endpoints {
            let address = match endpoint.addr {
                IpAddr::V4(a) => {
                    let mut bytes = 2u16.to_ne_bytes().to_vec();
                    bytes.extend(endpoint.port.to_be_bytes());
                    bytes.extend(a.octets());
                    bytes.extend([0; 8]);
                    bytes
                }
                IpAddr::V6(a) => {
                    let mut bytes = 10u16.to_ne_bytes().to_vec();
                    bytes.extend(endpoint.port.to_be_bytes());
                    bytes.extend([0; 4]);
                    bytes.extend(a.octets());
                    bytes.extend([0; 4]);
                    bytes
                }
            };
            // Keys and allowed IPs are independent of the endpoint.
            let mut peer = nl_attr(1, &[0x5a; 32]);
            peer.extend(nl_attr(4, &address));
            peers.extend(nl_attr(0, &peer));
        }
        body.extend(nl_attr(8, &peers));
        let mut msg = vec![0; 16];
        msg.extend(body);
        let len = msg.len() as u32;
        msg[..4].copy_from_slice(&len.to_ne_bytes());
        msg
    }

    proptest! {
        #![proptest_config(cfg(256))]
        #[test]
        fn peer_only_chunks_keep_the_selected_devices_identity(
            chunks in prop::collection::vec(prop::collection::vec((any::<bool>(), 1u16..u16::MAX), 0..8), 2..8),
        ) {
            let endpoints: Vec<Vec<_>> = chunks.iter().map(|chunk| chunk.iter().map(|(v6, port)| Endpoint {
                proto: Proto::Udp,
                addr: if *v6 { IpAddr::V6(Ipv6Addr::LOCALHOST) } else { IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)) },
                port: *port,
            }).collect()).collect();
            let messages: Vec<_> = endpoints.iter().enumerate().map(|(i, e)| message((i == 0).then_some(7), e)).collect();
            let got = wg::devices(&messages).unwrap();
            prop_assert_eq!(got.len(), 1);
            prop_assert_eq!(&got[0].name, "wg0");
            prop_assert_eq!(got[0].ifindex, 7);
            prop_assert_eq!(&got[0].endpoints, &endpoints.concat());
            prop_assert!(wg::devices(&messages[1..]).is_err(), "a continuation cannot invent its device");
        }
    }
}

#[cfg(feature = "loader")]
mod netlink_completion {
    use super::*;
    use crate::snapshot;

    fn message(ty: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut msg = ((16 + payload.len()) as u32).to_ne_bytes().to_vec();
        msg.extend(ty.to_ne_bytes());
        msg.extend(flags.to_ne_bytes());
        msg.extend([0; 8]);
        msg.extend(payload);
        msg
    }

    proptest! {
        #![proptest_config(cfg(256))]
        #[test]
        fn a_failed_or_interrupted_dump_never_becomes_a_snapshot(
            payload in prop::collection::vec(any::<u8>(), 0..128),
            interrupted in any::<bool>(),
            errno in -4095i32..=0,
            error_message in any::<bool>(),
        ) {
            let mut collected = vec![];
            let data = message(16, 2, &payload);
            prop_assert_eq!(snapshot::collect_reply(&data, &mut collected), Ok(false));
            let terminator = message(if error_message { 2 } else { 3 }, if interrupted { 0x10 } else { 0 }, &errno.to_ne_bytes());
            let result = snapshot::collect_reply(&terminator, &mut collected);
            prop_assert_eq!(result.is_ok(), !interrupted && errno == 0);
            if result.is_ok() {
                prop_assert_eq!(result.unwrap(), true);
                prop_assert_eq!(collected, vec![data]);
            }
        }

        #[test]
        fn a_cut_datagram_is_an_error(
            payload in prop::collection::vec(any::<u8>(), 1..128),
            cut in 1usize..16,
        ) {
            let msg = message(16, 2, &payload);
            let end = msg.len().saturating_sub(cut);
            prop_assert!(snapshot::collect_reply(&msg[..end], &mut vec![]).is_err());
        }
    }
}

// ---- N7: which nftables messages are changes (8311802, c3a7f8d) ----------

/// Every nftables message type, by the kernel's `enum nf_tables_msg_types`
/// numbering written out here (not the parser's list): the reads are the
/// GET messages that only list. The resets (GETOBJ_RESET 21, GETRULE_RESET
/// 25, GETSETELEM_RESET 33) zero counters and so are changes.
const GETTABLE: u8 = 1;
const GETCHAIN: u8 = 4;
const GETRULE: u8 = 7;
const GETSET: u8 = 10;
const GETSETELEM: u8 = 13;
const GETGEN: u8 = 16;
const GETOBJ: u8 = 19;
const GETFLOWTABLE: u8 = 23;
const READS: [u8; 8] = [GETTABLE, GETCHAIN, GETRULE, GETSET, GETSETELEM, GETGEN, GETOBJ, GETFLOWTABLE];
const NFTABLES: u16 = 10;

fn nft(hook: u32, subsys: u16, msg: u8) -> Parsed {
    let ev = event(hook, OWN_NETNS, (subsys << 8) | msg as u16, 0, &[]);
    parse(&ev, &Owner::Unit(UnitId::service("u")), &mut no_names)
}

fn is_firewall_change(p: &Parsed) -> bool {
    matches!(p, Parsed::Changes(cs) if cs.len() == 1 && cs[0].kind == ChangeKind::Firewall && cs[0].steers && !cs[0].removed)
}

/// Over every type: a single nftables message is nothing exactly when it
/// only reads, a message of another subsystem is nothing, and a batch is a
/// change whatever its first message says. A later kernel's new type (any
/// number not listed) is a change: fail closed.
#[test]
fn nftables_reads_are_exactly_the_listed_gets() {
    for msg in 0..=255u8 {
        let p = nft(HOOK_NFNETLINK, NFTABLES, msg);
        if READS.contains(&msg) {
            assert_eq!(p, Parsed::Nothing, "type {msg} only reads");
        } else {
            assert!(is_firewall_change(&p), "type {msg} is a change: {p:?}");
        }
        assert!(is_firewall_change(&nft(HOOK_NFBATCH, NFTABLES, msg)), "a batch is a change (type {msg})");
        for other in [0u16, 9, 11, 255] {
            assert_eq!(nft(HOOK_NFNETLINK, other, msg), Parsed::Nothing, "subsystem {other} is not nftables");
        }
    }
}

// ---- N2: a unit from its cgroup path (1039fee) ---------------------------

fn seg() -> impl Strategy<Value = String> {
    "[a-z0-9@._-]{1,10}"
        .prop_filter("not a slice or service suffix", |s| !s.ends_with(".slice") && !s.ends_with(".service"))
}

proptest! {
    #![proptest_config(cfg(512))]

    /// A service's cgroup, however many template slices sit above it and
    /// whatever sub-cgroups sit below, belongs to that service; nothing
    /// outside `system.slice`, and no slice itself, belongs to a unit.
    #[test]
    fn a_cgroup_belongs_to_the_first_service_below_system_slice(
        slices in proptest::collection::vec(seg(), 0..4),
        svc in seg(),
        below in proptest::collection::vec(seg(), 0..3),
        lead in any::<bool>(),
        other_root in "[a-z]{1,8}\\.slice",
    ) {
        let mut parts = vec!["system.slice".to_string()];
        parts.extend(slices.iter().map(|s| format!("{s}.slice")));
        let slices_only = parts.join("/");
        parts.push(format!("{svc}.service"));
        parts.extend(below.iter().map(|b| format!("{b}.service")));
        let path = format!("{}{}", if lead { "/" } else { "" }, parts.join("/"));
        prop_assert_eq!(unit_of_cgroup(&path), Some(UnitId::service(&svc)), "{}", path);
        prop_assert_eq!(unit_of_cgroup(&slices_only), None, "a slice is no unit: {}", slices_only);
        if other_root != "system.slice" {
            let elsewhere = parts.join("/").replacen("system.slice", &other_root, 1);
            prop_assert_eq!(unit_of_cgroup(&elsewhere), None, "{}", elsewhere);
        }
    }
}

// ---- N4: only the host's netns counts (307b412, b321007) -----------------

fn baseline() -> Tracker {
    let wg = UnitId::service("wg");
    let mut t = Tracker::default();
    let ch = |kind, object: &str, iface: Option<&str>, steers| Change {
        owner: Owner::Unit(wg.clone()),
        kind,
        object: object.into(),
        iface: iface.map(Into::into),
        steers,
        removed: false,
    };
    t.apply(&ch(ChangeKind::Interface, "wg0", Some("wg0"), false));
    t.apply(&ch(ChangeKind::Route, "route-wg0-0", Some("wg0"), true));
    t
}

fn rendered(t: &Tracker) -> String {
    let tools = [UnitId::service("wg"), UnitId::service("other")];
    format!("{:?} {:?}", t.view(WatchState::Attached { at: NOW }, &tools, NOW), t.claims())
}

fn any_event(netns: u32) -> impl Strategy<Value = Event> {
    let hooks = prop_oneof![
        Just(HOOK_RTNETLINK),
        Just(HOOK_NFNETLINK),
        Just(HOOK_NFBATCH),
        Just(HOOK_SOCKOPT),
        Just(HOOK_NETDEV),
        // Not a move: which way one went depends on the host's netns, and
        // `tests::moves` has its own exhaustive property for them.
        (0u32..9).prop_filter("a move is read by parse_move", |h| *h != HOOK_NETMOVE)
    ];
    // A header with a type that matters (link/route/rule messages, with and
    // without NLM_F_CREATE) followed by arbitrary bytes.
    let ty = prop_oneof![Just(16u16), Just(17), Just(19), Just(24), Just(25), Just(32), Just(33), any::<u16>()];
    (hooks, ty, any::<u16>(), proptest::collection::vec(any::<u8>(), 0..80))
        .prop_map(move |(hook, ty, flags, body)| event(hook, netns, ty, flags, &body))
}

proptest! {
    #![proptest_config(cfg(512))]

    /// An event acting in another network namespace changes nothing here:
    /// every footprint and claim is as it was, whatever the event is, a link
    /// request that names a namespace in this machine's reach included (a
    /// move into the host is seen as the move, `tests::moves`).
    #[test]
    fn events_in_other_namespaces_change_nothing_here(
        other in (1u32..).prop_filter("not ours", |n| *n != OWN_NETNS),
        ev in any_event(0),
    ) {
        let ev = Event { netns: other, ..ev };
        let mut t = baseline();
        let before = rendered(&t);
        take(&mut t, &ev, OWN_NETNS, || Some(UnitId::service("other")), &mut no_names);
        prop_assert_eq!(rendered(&t), before, "{:?}", ev);
    }

    /// A netns the probe could not read is a loss nothing can place: the
    /// global unattributed marker stands, whatever the event is.
    #[test]
    fn an_unknown_namespace_fails_closed(ev in any_event(0)) {
        let mut t = baseline();
        take(&mut t, &ev, OWN_NETNS, || None, &mut no_names);
        let v = t.view(WatchState::Attached { at: NOW }, &[UnitId::service("wg")], NOW);
        prop_assert!(!v.unattributed.is_empty(), "{:?}", ev);
    }

    /// In the host's namespace `take` is exactly parse-then-apply.
    #[test]
    fn host_events_are_parsed_and_applied(ev in any_event(OWN_NETNS)) {
        let owner = Owner::Unit(UnitId::service("other"));
        let mut direct = baseline();
        match parse(&ev, &owner, &mut no_names) {
            Parsed::Nothing => {}
            Parsed::Changes(cs) => cs.iter().for_each(|c| direct.apply(c)),
            Parsed::Renamed { was, now } => direct.rename_interface(&was, &now),
            Parsed::Unreadable(_) => direct.lost(Some(&UnitId::service("other"))),
        }
        let mut via_take = baseline();
        take(&mut via_take, &ev, OWN_NETNS, || Some(UnitId::service("other")), &mut no_names);
        prop_assert_eq!(rendered(&via_take), rendered(&direct), "{:?}", ev);
    }
}

fn nl_attr(ty: u16, v: &[u8]) -> Vec<u8> {
    let mut a = ((4 + v.len()) as u16).to_ne_bytes().to_vec();
    a.extend(ty.to_ne_bytes());
    a.extend(v);
    while !a.len().is_multiple_of(4) {
        a.push(0);
    }
    a
}

proptest! {
    #![proptest_config(cfg(512))]

    /// A link request acting elsewhere changes nothing of the host's by
    /// itself, whatever it asks for: even one that names a namespace in this
    /// machine's reach (IFLA_NET_NS_PID 19, IFLA_NET_NS_FD 28,
    /// IFLA_TARGET_NETNSID 46) and may move a device into the host's. A
    /// move that happens is seen as the move (`__dev_change_net_namespace`,
    /// `tests::moves`: arrival, departure, unreadable ends all decided there),
    /// and a link created in the host as its registration; a request that
    /// moves nothing leaves nothing behind. (Before B-24 was closed this
    /// charged the mover as unattributed, for good, with no object to clear
    /// it by.) Over RTM_NEWLINK and RTM_SETLINK, with other attributes
    /// before and after.
    #[test]
    fn a_link_request_elsewhere_changes_nothing_by_itself(
        ty in prop_oneof![Just(16u16), Just(19)],
        before in proptest::collection::vec(prop_oneof![Just(3u16), Just(4), Just(10), Just(13)], 0..3),
        reach in proptest::option::of(prop_oneof![Just(19u16), Just(28), Just(46)]),
        after in proptest::collection::vec(prop_oneof![Just(3u16), Just(4), Just(10)], 0..3),
        known in any::<bool>(),
        other in (1u32..).prop_filter("not ours", |n| *n != OWN_NETNS),
    ) {
        let mut body = vec![0u8; 16];
        for a in &before { body.extend(nl_attr(*a, &[1, 2, 3, 4])); }
        if let Some(r) = reach { body.extend(nl_attr(r, &[7, 0, 0, 0])); }
        for a in &after { body.extend(nl_attr(*a, &[1, 2, 3, 4])); }
        let ev = event(HOOK_RTNETLINK, other, ty, 0, &body);
        let mut t = baseline();
        let before_state = rendered(&t);
        let mover = UnitId::service("other");
        take(&mut t, &ev, OWN_NETNS, || known.then(|| mover.clone()), &mut no_names);
        prop_assert_eq!(rendered(&t), before_state, "{} the host's state", if reach.is_some() { "a reaching request changed" } else { "a request changed" });
    }
}

// ---- N8, N9, N6: the tracker -----------------------------------------------

fn u(n: &str) -> UnitId {
    UnitId::service(n)
}

fn owner() -> impl Strategy<Value = Owner> {
    prop_oneof![Just(Owner::Unit(u("a"))), Just(Owner::Unit(u("b"))), Just(Owner::Unattributed)]
}

fn iface() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("v0"), Just("v1"), Just("p0")]
}

/// Virtual by this world's convention: the name starts with `v`.
fn is_virtual(i: &str) -> bool {
    i.starts_with('v')
}

fn change() -> impl Strategy<Value = Change> {
    let mk = |owner, kind, object: String, iface: Option<String>, steers, removed| Change {
        owner,
        kind,
        object,
        iface,
        steers,
        removed,
    };
    prop_oneof![
        (owner(), iface(), any::<bool>()).prop_map(move |(o, i, r)| mk(
            o,
            ChangeKind::Interface,
            i.into(),
            Some(i.into()),
            false,
            r
        )),
        // Whether an object steers is a function of the object (a route's
        // prefix length is in its key): route 0 is a default route, route 1
        // a host route; rule 0 a catch-all, rule 1 a selector rule.
        (owner(), iface(), 0u8..2, any::<bool>()).prop_map(move |(o, i, k, r)| {
            mk(o, ChangeKind::Route, format!("route-{i}-{k}"), Some(i.into()), k == 0, r)
        }),
        (owner(), 0u8..2, any::<bool>()).prop_map(move |(o, k, r)| mk(
            o,
            ChangeKind::Rule,
            format!("rule{k}"),
            None,
            k == 0,
            r
        )),
        (owner(), any::<bool>()).prop_map(move |(o, r)| mk(o, ChangeKind::Firewall, "nft".into(), None, true, r)),
    ]
}

#[derive(Clone, Debug)]
enum Op {
    Chg(Change),
    Lost(Option<&'static str>),
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    let lost = prop_oneof![Just(None), Just(Some("a")), Just(Some("b"))];
    proptest::collection::vec(prop_oneof![8 => change().prop_map(Op::Chg), 1 => lost.prop_map(Op::Lost)], 0..24)
}

/// What the kernel holds, by replaying the ops independently of the
/// tracker: the latest non-removed change per (kind, object); a removed
/// interface takes its routes with it.
fn kernel_of(ops: &[Op]) -> BTreeMap<(ChangeKind, String), Change> {
    let mut k: BTreeMap<(ChangeKind, String), Change> = BTreeMap::new();
    for op in ops {
        if let Op::Chg(c) = op {
            let key = (c.kind, c.object.clone());
            if c.removed {
                k.remove(&key);
                if c.kind == ChangeKind::Interface {
                    k.retain(|_, r| !(r.kind == ChangeKind::Route && r.iface.as_deref() == Some(c.object.as_str())));
                }
            } else {
                k.insert(key, c.clone());
            }
        }
    }
    k
}

fn tracker_of(ops: &[Op]) -> Tracker {
    let mut t = Tracker::default();
    for op in ops {
        match op {
            Op::Chg(c) => t.apply(c),
            Op::Lost(Some(n)) => t.lost(Some(&u(n))),
            Op::Lost(None) => t.lost(None),
        }
    }
    let live: BTreeSet<String> = kernel_of(ops)
        .into_iter()
        .filter(|((k, o), _)| *k == ChangeKind::Interface && is_virtual(o))
        .map(|((_, o), _)| o)
        .collect();
    t.set_virtual(live);
    t
}

proptest! {
    #![proptest_config(cfg(512))]

    /// N8 (d1a4334 a): a footprint marked unattributed is protecting, so
    /// the file says `protecting yes` with its `unattributed` line, for any
    /// history; and the text reads back the same.
    #[test]
    fn unattributed_implies_protecting(ops in ops()) {
        let t = tracker_of(&ops);
        for n in ["a", "b", "never-seen"] {
            let f = t.footprint(&u(n), NOW);
            if f.unattributed {
                prop_assert!(f.protecting, "{n}: {f:?}");
            }
            let text = crate::contract::render(&f);
            let back = crate::contract::parse_footprint(&text).expect("it reads back");
            prop_assert_eq!((back.protecting, back.unattributed), (f.protecting, f.unattributed), "{}", text);
            if f.unattributed {
                prop_assert!(text.lines().any(|l| l == "protecting yes"), "{}", text);
            }
        }
    }
}

proptest! {
    #![proptest_config(cfg(1024))]

    /// N9 (d1a4334 b, 939819f): a steering route standing over an interface
    /// protects the unit that added it if the interface is virtual (made by
    /// anyone, or before the watch, or moved in), and the unit that created
    /// the interface; never when the interface is a physical NIC. A route
    /// that is removed, or taken with its interface, protects nobody. Both
    /// directions are checked, for each unit.
    #[test]
    fn a_route_over_a_virtual_link_protects_exactly_its_adder_and_the_links_creator(
        creator in prop_oneof![Just(None), Just(Some("a")), Just(Some("b"))],
        adder in prop_oneof![Just("a"), Just("b")],
        virt in any::<bool>(),
        steers in any::<bool>(),
        route_removed in any::<bool>(),
        link_deleted in any::<bool>(),
    ) {
        let link = "x0";
        let mut t = Tracker::default();
        if let Some(c) = creator {
            t.apply(&Change { owner: Owner::Unit(u(c)), kind: ChangeKind::Interface, object: link.into(), iface: Some(link.into()), steers: false, removed: false });
        }
        let route = |removed| Change { owner: Owner::Unit(u(adder)), kind: ChangeKind::Route, object: format!("route-{link}-0"), iface: Some(link.into()), steers, removed };
        t.apply(&route(false));
        if route_removed {
            t.apply(&route(true));
        }
        if link_deleted {
            t.apply(&Change { owner: Owner::Unattributed, kind: ChangeKind::Interface, object: link.into(), iface: Some(link.into()), steers: false, removed: true });
        }
        t.set_virtual(if virt && !link_deleted { [link.to_string()].into() } else { BTreeSet::new() });
        let standing = steers && !route_removed && !link_deleted && virt;
        for n in ["a", "b"] {
            let want = standing && (adder == n || creator == Some(n));
            let f = t.footprint(&u(n), NOW);
            prop_assert_eq!(f.protecting, want, "{} {:?}", n, f);
            if want {
                prop_assert!(f.ifaces.contains(link), "the hold passes the interface: {:?}", f);
            }
        }
    }

    /// N6 (838ccc0, 5a929a7), across a restart: the claims kept and the
    /// kernel's state at attach give back a footprint at least as
    /// protecting for every unit (a restart never downgrades), and every
    /// steering object made while nobody watched, unclaimed, reads
    /// `pre-attach` (a route over a physical NIC is exempt).
    #[test]
    fn a_restart_never_downgrades_and_the_gap_fails_closed(ops in ops(), gap_fw in any::<bool>(), gap_rule in any::<bool>(), gap_virtual_route in any::<bool>(), gap_physical_route in any::<bool>()) {
        let before = tracker_of(&ops);
        let kernel = kernel_of(&ops);
        let mut standing: Vec<Change> = kernel.values().cloned().collect();
        let mut virt: BTreeSet<String> = kernel.keys().filter(|(k, o)| *k == ChangeKind::Interface && is_virtual(o)).map(|(_, o)| o.clone()).collect();
        let mk = |kind, object: &str, iface: Option<&str>| Change { owner: Owner::Unattributed, kind, object: object.into(), iface: iface.map(Into::into), steers: true, removed: false };
        let mut expect_gap = vec![];
        if gap_fw {
            standing.push(mk(ChangeKind::Firewall, "gapfw", None));
            expect_gap.push("gapfw");
        }
        if gap_rule {
            standing.push(mk(ChangeKind::Rule, "gaprule", None));
            expect_gap.push("gaprule");
        }
        if gap_virtual_route {
            standing.push(mk(ChangeKind::Route, "route-vgap-0", Some("vgap")));
            virt.insert("vgap".into());
            expect_gap.push("route-vgap-0");
        }
        if gap_physical_route {
            standing.push(mk(ChangeKind::Route, "route-pgap-0", Some("pgap")));
        }
        let claims: Claims = before.claims();
        let after = Tracker::attach(&claims, &standing, &virt);
        for n in ["a", "b"] {
            let was = before.footprint(&u(n), NOW);
            let now = after.footprint(&u(n), NOW);
            if was.protecting {
                prop_assert!(now.protecting, "{n} downgraded by a restart: {was:?} -> {now:?}");
            }
        }
        let v = after.view(WatchState::Attached { at: NOW }, &[u("a"), u("b")], NOW);
        let why = v.unattributed.join("\n");
        for o in &expect_gap {
            prop_assert!(why.lines().any(|l| l.starts_with("pre-attach") && l.contains(o)), "{o} not pre-attach: {why}");
        }
        prop_assert!(!why.contains("route-pgap-0"), "a route over a physical NIC is not pre-attach: {why}");
    }

    /// N6, the other half: a claim whose object no longer stands is dropped
    /// at attach (a deleted table, a removed rule), and one that stands is
    /// kept. Two-sided on a single claimed firewall change.
    #[test]
    fn a_claim_survives_a_restart_exactly_while_its_object_stands(stands in any::<bool>(), steers in any::<bool>()) {
        let c = Change { owner: Owner::Unit(u("a")), kind: ChangeKind::Firewall, object: "nft".into(), iface: None, steers, removed: false };
        let mut t = Tracker::default();
        t.apply(&c);
        let standing: Vec<Change> = if stands { vec![c.clone()] } else { vec![] };
        let after = Tracker::attach(&t.claims(), &standing, &BTreeSet::new());
        prop_assert_eq!(after.footprint(&u("a"), NOW).protecting, stands && steers);
    }
}

// ---- N6 (5a929a7), legacy tables: the three cases the kernel can show ----

#[cfg(feature = "loader")]
mod legacy {
    use super::*;
    use crate::snapshot::legacy_tables;

    proptest! {
        #![proptest_config(cfg(256))]

        /// A claim made by `nf_setsockopt` (any, even one the kernel
        /// refused: fail closed) survives a restart exactly when the kernel
        /// either lists tables or cannot list them at all (no
        /// `ip_tables_names`); it goes when the file lists none.
        #[test]
        fn a_legacy_claim_survives_unless_the_kernel_shows_no_tables(names in proptest::option::of("[ \\n]{0,3}([a-z]{1,6}\\n){0,2}"), pf in any::<u8>()) {
            let ev = Event { cgroup: 1, tgid: 2, hook: HOOK_SOCKOPT, len: 2, netns: OWN_NETNS, cgpath: None, data: vec![pf, 0] };
            let Parsed::Changes(cs) = parse(&ev, &Owner::Unit(u("a")), &mut no_names) else { panic!("a sockopt is a change") };
            let mut t = Tracker::default();
            cs.iter().for_each(|c| t.apply(c));
            prop_assert!(t.footprint(&u("a"), NOW).protecting, "watched, it is protecting");
            let standing: Vec<Change> = legacy_tables(names.as_deref(), pf).into_iter().collect();
            let after = Tracker::attach(&t.claims(), &standing, &BTreeSet::new());
            let shows_none = names.as_deref().is_some_and(|s| s.trim().is_empty());
            prop_assert_eq!(after.footprint(&u("a"), NOW).protecting, !shows_none, "{:?}", names);
            // And the snapshot alone never makes an unclaimed table pre-attach
            // when the kernel cannot show tables.
            let fresh = Tracker::attach(&Claims::default(), &standing, &BTreeSet::new());
            let v = fresh.view(WatchState::Attached { at: NOW }, &[u("a")], NOW);
            prop_assert_eq!(v.unattributed.is_empty(), names.is_none() || shows_none, "{:?}", names);
        }
    }
}

// ---- N1, N3: the cgroup map merges, and prunes after two walks (87d61fe) --

#[cfg(feature = "loader")]
mod cg {
    use super::*;
    use crate::cgroups::Cgroups;
    use std::os::unix::fs::MetadataExt;

    #[derive(Clone, Debug)]
    enum Step {
        Create(usize),
        Remove(usize),
        /// The loop's drain: IN_CREATE records are read.
        Drain,
        /// A tick's walk, with the units that claim something (a mask).
        Walk(u8),
    }

    const UNITS: usize = 4;

    fn steps() -> impl Strategy<Value = Vec<Step>> {
        proptest::collection::vec(
            prop_oneof![
                3 => (0..UNITS).prop_map(Step::Create),
                3 => (0..UNITS).prop_map(Step::Remove),
                2 => Just(Step::Drain),
                4 => (0u8..(1 << UNITS)).prop_map(Step::Walk),
            ],
            0..24,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig { max_global_rejects: 1_000_000, ..cfg(64) })]

        /// Against a model written from the doc comment, not the code: a
        /// cgroup is known once a drain or a walk finds it standing; it is
        /// kept when it goes (the map merges, never replaces: N1), and
        /// forgotten exactly when it was absent from two consecutive walks
        /// and its unit claimed nothing at the second (N3). At the end,
        /// every unit made is attributed if it stands or is still known,
        /// and not otherwise. (A unit is made once, so ids are unique, as
        /// the kernel's are within a boot.)
        #[test]
        fn the_map_keeps_what_was_seen_and_prunes_after_two_walks(steps in steps()) {
            // tmpfs hands out inode numbers in order, as the kernel does cgroup ids;
            // elsewhere a freed one can be reused, and that case is set aside.
            let d = tempfile::tempdir_in("/dev/shm").or_else(|_| tempfile::tempdir()).unwrap();
            let slice = d.path().join("system.slice");
            std::fs::create_dir(&slice).unwrap();
            let dir = |k: usize| slice.join(format!("nw-u{k}.service"));
            let mut c = Cgroups::new(d.path());
            let mut ino: [Option<u64>; UNITS] = [None; UNITS];
            let mut live = [false; UNITS];
            let mut known = [false; UNITS];
            let mut absent_prev = [false; UNITS];
            for s in &steps {
                match s {
                    Step::Create(k) if ino[*k].is_none() => {
                        std::fs::create_dir(dir(*k)).unwrap();
                        let i = std::fs::metadata(dir(*k)).unwrap().ino();
                        // The filesystem reused an id: the model's premise (not reused) fails.
                        prop_assume!(!ino.contains(&Some(i)));
                        ino[*k] = Some(i);
                        live[*k] = true;
                    }
                    Step::Remove(k) if live[*k] => {
                        std::fs::remove_dir(dir(*k)).unwrap();
                        live[*k] = false;
                    }
                    Step::Drain => {
                        c.drain();
                        for k in 0..UNITS {
                            known[k] |= live[k];
                        }
                    }
                    Step::Walk(mask) => {
                        let claimed: BTreeSet<UnitId> = (0..UNITS).filter(|k| mask >> k & 1 == 1).map(|k| u(&format!("nw-u{k}"))).collect();
                        c.walk(&claimed);
                        for k in 0..UNITS {
                            let absent = known[k] && !live[k];
                            if absent && absent_prev[k] && !claimed.contains(&u(&format!("nw-u{k}"))) {
                                known[k] = false; // forgotten, for good
                                absent_prev[k] = false;
                            } else {
                                absent_prev[k] = absent;
                            }
                            known[k] |= live[k];
                        }
                    }
                    _ => {}
                }
            }
            for k in 0..UNITS {
                let Some(id) = ino[k] else { continue };
                let want = (live[k] || known[k]).then(|| u(&format!("nw-u{k}")));
                prop_assert_eq!(c.unit(id), want, "unit {} (live {}, known {}) after {:?}", k, live[k], known[k], steps);
            }
        }
    }
}

// ---- B-22 (b): what the tracker does with a WireGuard device read ---------

mod wgfold {
    use super::*;
    use crate::wg::Device;
    use crate::{Endpoint, Invocation, Proto};
    use std::net::{IpAddr, Ipv4Addr};

    const UNITS: usize = 3;
    const DEVS: usize = 3;

    fn unit(i: usize) -> UnitId {
        u(&format!("wg-quick-{i}"))
    }

    fn dev_name(d: usize) -> String {
        format!("wg{d}")
    }

    fn ep(n: u8) -> Endpoint {
        Endpoint { proto: Proto::Udp, addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)), port: 51_000 + n as u16 }
    }

    /// One read of the kernel: the devices that exist, each with its
    /// interface index (a device made again has another) and its peers'
    /// endpoints (numbers standing for addresses).
    type Read = Vec<(usize, u32, BTreeSet<u8>)>;

    fn devices(r: &Read) -> Vec<Device> {
        r.iter()
            .map(|(d, index, eps)| Device {
                name: dev_name(*d),
                ifindex: *index,
                endpoints: eps.iter().map(|n| ep(*n)).collect(),
            })
            .collect()
    }

    fn read() -> impl Strategy<Value = Read> {
        proptest::collection::btree_map(0..DEVS, (10u32..13, proptest::collection::btree_set(1u8..5, 0..4)), 0..=DEVS)
            .prop_map(|m| m.into_iter().map(|(d, (i, e))| (d, i, e)).collect())
    }

    #[derive(Clone, Debug)]
    enum Step {
        /// A unit sent a request configuring a device.
        Bind(usize, usize),
        /// The loop read the devices.
        Set(Read),
        /// An endpoint restored from the footprint files after a restart that
        /// lost `.state` (no binding with it).
        Restore(usize, u8),
        /// The device was deleted (RTM_DELLINK): and may be made again before
        /// the next read, with the same name and index.
        Del(usize),
    }

    fn steps() -> impl Strategy<Value = Vec<Step>> {
        proptest::collection::vec(
            prop_oneof![
                2 => (0..UNITS, 0..DEVS).prop_map(|(a, b)| Step::Bind(a, b)),
                3 => read().prop_map(Step::Set),
                1 => (0..UNITS, 1u8..5).prop_map(|(a, n)| Step::Restore(a, n)),
                1 => (0..DEVS).prop_map(Step::Del),
            ],
            0..16,
        )
    }

    fn endpoints(t: &Tracker, i: usize) -> BTreeSet<Endpoint> {
        t.footprint(&unit(i), NOW).endpoints
    }

    proptest! {
        #![proptest_config(cfg(512))]

        /// A unit's endpoints are exactly those of the devices it
        /// configured, as the last read has them: a peer that moved
        /// follows, and a unit that configured nothing (even one that made
        /// the tunnel) carries none. A binding lasts as long as the device
        /// it named (B-27): a read without the device, or with the name on a
        /// device of another interface index, ends it, so a later device of
        /// that name made by someone else is not this unit's, until this
        /// unit configures it again. `set_wireguard` says it changed
        /// something exactly when some unit's endpoints did.
        #[test]
        fn a_unit_carries_exactly_the_endpoints_of_the_devices_it_configured(steps in steps()) {
            let mut t = Tracker::default();
            // device -> the interface index its first read showed
            let mut bound: Vec<BTreeMap<usize, Option<u32>>> = vec![BTreeMap::new(); UNITS];
            let mut want: Vec<BTreeSet<Endpoint>> = vec![BTreeSet::new(); UNITS];
            for s in &steps {
                match s {
                    Step::Bind(a, d) => {
                        t.bind_wireguard(&unit(*a), &dev_name(*d));
                        bound[*a].insert(*d, None);
                    }
                    Step::Del(d) => {
                        t.apply(&Change { owner: Owner::Unattributed, kind: ChangeKind::Interface, object: dev_name(*d), iface: Some(dev_name(*d)), steers: false, removed: true });
                        for i in 0..UNITS {
                            if bound[i].remove(d).is_some() {
                                want[i].clear();
                            }
                        }
                    }
                    Step::Restore(a, n) => {
                        t.add_endpoint(&unit(*a), ep(*n));
                        want[*a].insert(ep(*n));
                    }
                    Step::Set(r) => {
                        let before = want.clone();
                        for i in 0..UNITS {
                            if bound[i].is_empty() {
                                continue;
                            }
                            let seen = bound[i].clone();
                            for (d, index) in seen {
                                match r.iter().find(|(x, _, _)| *x == d) {
                                    None => { bound[i].remove(&d); }
                                    Some((_, now, _)) if index.is_some_and(|was| was != *now) => { bound[i].remove(&d); }
                                    Some((_, now, _)) => { bound[i].insert(d, Some(*now)); }
                                }
                            }
                            want[i] = r.iter().filter(|(d, _, _)| bound[i].contains_key(d)).flat_map(|(_, _, e)| e.iter().map(|n| ep(*n))).collect();
                        }
                        let changed = t.set_wireguard(&devices(r));
                        prop_assert_eq!(changed, before != want, "the return value, on {:?}", r);
                    }
                }
                for (i, w) in want.iter().enumerate() {
                    prop_assert_eq!(&endpoints(&t, i), w, "unit {} after {:?}", i, s);
                }
            }
        }

        /// What a restart keeps (`.state`): a unit that configured a device
        /// still takes that device's endpoints after `attach`, as it would
        /// have without the restart.
        #[test]
        fn a_restart_keeps_which_device_a_unit_configured(steps in steps(), last in read()) {
            let mut t = Tracker::default();
            for s in &steps {
                match s {
                    Step::Bind(a, d) => t.bind_wireguard(&unit(*a), &dev_name(*d)),
                    Step::Set(r) => { t.set_wireguard(&devices(r)); }
                    Step::Restore(a, n) => t.add_endpoint(&unit(*a), ep(*n)),
                    Step::Del(d) => t.apply(&Change { owner: Owner::Unattributed, kind: ChangeKind::Interface, object: dev_name(*d), iface: Some(dev_name(*d)), steers: false, removed: true }),
                }
            }
            // What the restart keeps includes the index each binding was
            // pinned to, so a device made again while the watch was down
            // is not inherited either.
            let mut after = Tracker::attach(&t.claims(), &[], &BTreeSet::new());
            t.set_wireguard(&devices(&last));
            after.set_wireguard(&devices(&last));
            for i in 0..UNITS {
                prop_assert_eq!(endpoints(&after, i), endpoints(&t, i), "unit {}", i);
            }
        }

        /// The latch: what a protecting invocation had, it keeps passing
        /// for the hold, though the device (and so its peers) is gone from
        /// every later read: a tunnel whose interface leaves with its last
        /// process still names its peer.
        #[test]
        fn a_protecting_invocation_keeps_every_endpoint_it_had(reads in proptest::collection::vec(read(), 1..8)) {
            let a = unit(0);
            let mut t = Tracker::default();
            let ch = |kind, object: &str, steers| Change { owner: Owner::Unit(a.clone()), kind, object: object.into(), iface: Some("wg0".into()), steers, removed: false };
            t.apply(&ch(ChangeKind::Interface, "wg0", false));
            t.apply(&ch(ChangeKind::Route, "route-wg0-0", true));
            t.set_virtual(["wg0".to_string()].into());
            t.set_invocation(&a, Invocation { id: Some("a".repeat(32)), ended: false });
            t.bind_wireguard(&a, "wg0");
            let mut seen: BTreeSet<Endpoint> = BTreeSet::new();
            for r in &reads {
                t.set_wireguard(&devices(r));
                // The binding may have ended with the device; the unit's
                // invocation still had what it carried while bound.
                if let Some((_, _, e)) = r.iter().find(|(d, _, _)| *d == 0)
                    && t.claims().wireguard.contains(&(a.clone(), "wg0".to_string()))
                {
                    seen.extend(e.iter().map(|n| ep(*n)));
                }
                let f = t.footprint(&a, NOW);
                prop_assert!(f.protecting);
                prop_assert!(seen.is_subset(&f.endpoints), "lost {:?} of {:?}", seen.difference(&f.endpoints).collect::<Vec<_>>(), f.endpoints);
            }
        }
    }
}

/// The two cases the first drafts of the wg tests let through (prop-auditor's
/// mutants on #71): a request naming its device by an empty name is
/// unnamed, and a peer whose own attributes are cut is an error, never a
/// smaller list.
mod wgcases {
    use super::*;
    use crate::ebpf::HOOK_GENL;
    use crate::wg::{self, Genl};

    const FAMILY: u16 = 0x21;

    fn request(attrs: &[Vec<u8>]) -> Event {
        let mut body = vec![1u8, 1, 0, 0]; // WG_CMD_SET_DEVICE
        body.extend(attrs.concat());
        event(HOOK_GENL, OWN_NETNS, FAMILY, 0, &body)
    }

    #[test]
    fn an_empty_device_name_is_unnamed_not_a_device() {
        let name = nl_attr(2, b"\0");
        assert_eq!(wg::classify(&request(std::slice::from_ref(&name)), FAMILY), Genl::SetUnnamed);
        let index = nl_attr(1, &7u32.to_ne_bytes());
        assert_eq!(wg::classify(&request(&[name, index]), FAMILY), Genl::SetIndex(7), "the index still names it");
    }

    #[test]
    fn a_peer_with_a_cut_attribute_is_an_error_not_a_smaller_list() {
        // The peer's own attribute claims 100 bytes and has 4.
        let mut cut = 100u16.to_ne_bytes().to_vec();
        cut.extend(4u16.to_ne_bytes());
        let peers = nl_attr(8, &nl_attr(0, &cut));
        let mut body = vec![0u8, 1, 0, 0];
        body.extend([nl_attr(2, b"wg0\0"), peers].concat());
        let mut m = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
        m.extend([0x21, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        m.extend(body);
        assert!(wg::devices(&[m]).is_err());
    }
}

// ---- B-22 (a): DNS and proxy steer for the owners of the interface that carries them

mod dnscharge {
    use super::*;
    use crate::dns::{self, Charge, Key, Lookup, Owners, Target, World};
    use std::net::IpAddr;

    const TOOLS: usize = 4;

    fn tool(i: usize) -> UnitId {
        u(&format!("tool{i}"))
    }

    /// The interfaces of this world: two virtual with owners to be drawn,
    /// one virtual nobody owns, one physical (the uplink) that a DHCP
    /// client's unit may have added a route over.
    const IFACES: [&str; 4] = ["tun0", "tun1", "orphan0", "wan0"];

    fn is_virtual(i: &str) -> bool {
        i != "wan0"
    }

    /// The addresses the settings may name, each with its kernel answer to
    /// be drawn (the route table is an input, not something the code looks up).
    fn addrs() -> [IpAddr; 5] {
        ["10.0.0.1", "10.1.0.1", "192.0.2.1", "2001:db8::1", "203.0.113.1"].map(|a| a.parse().unwrap())
    }

    #[derive(Clone, Debug)]
    struct Scene {
        creators: Vec<BTreeSet<usize>>,
        routers: Vec<BTreeSet<usize>>,
        /// Per address: 0..4 an interface, 4 no route, 5 failed, 6 one of
        /// the machine's own addresses (`local … dev lo`).
        kernel: Vec<u8>,
    }

    fn scene() -> impl Strategy<Value = Scene> {
        let owners = || proptest::collection::vec(proptest::collection::btree_set(0..TOOLS, 0..=2), IFACES.len());
        (owners(), owners(), proptest::collection::vec(0u8..7, 5)).prop_map(|(creators, routers, kernel)| Scene {
            creators,
            routers,
            kernel,
        })
    }

    fn target() -> impl Strategy<Value = Target> {
        prop_oneof![
            4 => (0usize..5, proptest::option::weighted(0.25, 0usize..IFACES.len()))
                .prop_map(|(a, z)| Target::Addr { addr: addrs()[a], zone: z.map(|i| IFACES[i].to_string()) }),
            1 => Just(Target::Unreadable),
        ]
    }

    fn charge_of(sc: &Scene, targets: &[Target], link: Option<&str>) -> Charge {
        let virt: BTreeSet<String> = IFACES.iter().filter(|i| is_virtual(i)).map(|i| i.to_string()).collect();
        let owners = |n: &str| match IFACES.iter().position(|i| *i == n) {
            Some(k) => Owners {
                creators: sc.creators[k].iter().map(|i| tool(*i)).collect(),
                routers: sc.routers[k].iter().map(|i| tool(*i)).collect(),
            },
            None => Owners::default(),
        };
        let lookup = |a: &IpAddr| match addrs().iter().position(|x| x == a).map(|k| sc.kernel[k]) {
            Some(i @ 0..4) => Lookup::Via(IFACES[i as usize].to_string()),
            Some(4) => Lookup::NoRoute,
            Some(6) => Lookup::Local,
            _ => Lookup::Failed,
        };
        dns::charges(
            targets,
            link,
            &World { virtual_ifaces: &virt, owners: &owners, lookup: &lookup, ifname: &|_| None },
        )
    }

    /// The rule, written from §12d and the coordinator's decision, not from
    /// `carried`: the interface a setting rides is named by the resolved
    /// link it belongs to, else by its zone, else by what the kernel says;
    /// a physical one charges nobody; a virtual one charges its creators and
    /// the units that routed over it; a virtual one with none, a failed
    /// lookup and an unreadable address are unknown; no route charges nobody.
    fn oracle(sc: &Scene, targets: &[Target], link: Option<&str>) -> (BTreeSet<UnitId>, bool) {
        let ride = |iface: &str| -> (BTreeSet<UnitId>, bool) {
            let k = IFACES.iter().position(|i| *i == iface).expect("one of ours");
            if !is_virtual(iface) {
                return (BTreeSet::new(), false);
            }
            let both: BTreeSet<usize> = sc.creators[k].union(&sc.routers[k]).copied().collect();
            let none = both.is_empty();
            (both.into_iter().map(tool).collect(), none)
        };
        let (mut who, mut unknown) = (BTreeSet::new(), false);
        let mut take = |(w, u): (BTreeSet<UnitId>, bool)| {
            who.extend(w);
            unknown |= u;
        };
        for t in targets {
            match t {
                Target::Unreadable => take((BTreeSet::new(), true)),
                Target::Addr { addr, zone } => {
                    if let Some(l) = link {
                        take(ride(l));
                    } else if let Some(z) = zone {
                        take(ride(z));
                    } else {
                        match sc.kernel[addrs().iter().position(|x| x == addr).unwrap()] {
                            i @ 0..4 => take(ride(IFACES[i as usize])),
                            4 | 6 => {}
                            _ => take((BTreeSet::new(), true)),
                        }
                    }
                }
            }
        }
        (who, unknown)
    }

    proptest! {
        #![proptest_config(cfg(2048))]

        /// A setting charges exactly the owners of the interface that
        /// carries it (and is unknown exactly when something cannot be
        /// placed): the uplink charges nobody however many units added
        /// routes over it, a lookup that picks a virtual link with an owner
        /// charges its creators and its routers and no other tool, and a
        /// lookup that fails, an address that cannot be read or a virtual
        /// link nobody owns is unknown.
        #[test]
        fn a_setting_charges_the_owners_of_the_interface_that_carries_it(
            sc in scene(),
            targets in proptest::collection::vec(target(), 0..5),
            link in proptest::option::weighted(0.25, 0usize..IFACES.len()),
        ) {
            let link = link.map(|i| IFACES[i]);
            let c = charge_of(&sc, &targets, link);
            let (who, unknown) = oracle(&sc, &targets, link);
            prop_assert_eq!((&c.owners, c.unknown), (&who, unknown), "{:?} link {:?}", targets, link);
        }

        /// A charge moves with the route: the same settings under another
        /// kernel answer charge the owners of the new interface (recomputed,
        /// nothing remembered), and the same input twice gives the same answer.
        #[test]
        fn a_route_change_moves_the_charge(sc in scene(), other in proptest::collection::vec(0u8..7, 5), targets in proptest::collection::vec(target(), 1..4)) {
            let first = charge_of(&sc, &targets, None);
            prop_assert_eq!(&first, &charge_of(&sc, &targets, None), "same input, same charge");
            let moved = Scene { kernel: other, ..sc.clone() };
            let (who, unknown) = oracle(&moved, &targets, None);
            let c = charge_of(&moved, &targets, None);
            prop_assert_eq!((c.owners, c.unknown), (who, unknown));
        }

        /// `set_dns` replaces every DNS and proxy object and touches nothing
        /// else: after it the charges standing are exactly those given (an
        /// object left out is gone for everyone, a charge cannot stick), an
        /// unknown one is an object-bound mark with no unit behind it, the
        /// interface and route claims are as they were, and a tool is
        /// protecting while it owns a charged object or something else does.
        #[test]
        fn set_dns_replaces_every_dns_object_and_nothing_else(
            first in charges_map(),
            second in charges_map(),
        ) {
            let mut t = Tracker::default();
            // Claims that are not DNS: a tool's interface and route.
            let ch = |kind, object: &str, steers| Change { owner: Owner::Unit(tool(0)), kind, object: object.into(), iface: Some("tun0".into()), steers, removed: false };
            t.apply(&ch(ChangeKind::Interface, "tun0", false));
            t.apply(&ch(ChangeKind::Route, "route-tun0-0", true));
            let others = |t: &Tracker| t.claims().objects.into_iter().filter(|o| !matches!(o.1, ChangeKind::Dns | ChangeKind::Proxy)).collect::<Vec<_>>();
            let before = others(&t);
            t.set_dns(&first);
            prop_assert_eq!(t.dns_charges(), nonempty(&first));
            t.set_dns(&second);
            prop_assert_eq!(t.dns_charges(), nonempty(&second), "nothing of the first survives");
            prop_assert_eq!(others(&t), before, "other claims untouched");
            let mut fresh = Tracker::default();
            fresh.apply(&ch(ChangeKind::Interface, "tun0", false));
            fresh.apply(&ch(ChangeKind::Route, "route-tun0-0", true));
            fresh.set_dns(&second);
            for i in 0..TOOLS {
                prop_assert_eq!(t.footprint(&tool(i), NOW).protecting, fresh.footprint(&tool(i), NOW).protecting, "tool{} as if fresh", i);
            }
            let owned: BTreeSet<UnitId> = second.values().flat_map(|c| c.owners.iter().cloned()).collect();
            for i in 1..TOOLS {
                prop_assert_eq!(t.footprint(&tool(i), NOW).protecting, owned.contains(&tool(i)), "tool{}", i);
            }
            let v = t.view(WatchState::Attached { at: NOW }, &[tool(1)], NOW);
            let any_unknown = second.values().any(|c| c.unknown);
            prop_assert_eq!(v.unattributed.iter().any(|w| w.contains("Dns") || w.contains("Proxy")), any_unknown);
        }
    }

    fn keys() -> [Key; 3] {
        [
            (ChangeKind::Dns, "resolv.conf".into()),
            (ChangeKind::Dns, "link tun0".into()),
            (ChangeKind::Proxy, "/etc/environment".into()),
        ]
    }

    fn charges_map() -> impl Strategy<Value = BTreeMap<Key, Charge>> {
        proptest::collection::vec((proptest::collection::btree_set(1usize..TOOLS, 0..=2), any::<bool>()), 3).prop_map(
            |v| {
                keys()
                    .into_iter()
                    .zip(v)
                    .map(|(k, (o, unknown))| (k, Charge { owners: o.into_iter().map(tool).collect(), unknown }))
                    .collect()
            },
        )
    }

    fn nonempty(m: &BTreeMap<Key, Charge>) -> BTreeMap<Key, Charge> {
        m.iter().filter(|(_, c)| !c.owners.is_empty() || c.unknown).map(|(k, c)| (k.clone(), c.clone())).collect()
    }

    proptest! {
        #![proptest_config(cfg(512))]

        /// `interface_owners` is the creators (units with an interface claim
        /// on the name) and the routers (units with a *steering* route over
        /// it), whatever else is claimed: a non-steering route, another
        /// interface, or a removed object adds no owner.
        #[test]
        fn interface_owners_are_creators_and_steering_routers(ops in ops()) {
            let t = tracker_of(&ops);
            for name in ["v0", "v1", "p0"] {
                let owners = t.interface_owners(name);
                let (mut creators, mut routers) = (BTreeSet::new(), BTreeSet::new());
                for unit in ["a", "b"] {
                    let c = t.claims();
                    for (cu, k, _, i, steers) in &c.objects {
                        if cu.name != unit || i.as_deref() != Some(name) { continue; }
                        match k {
                            ChangeKind::Interface => { creators.insert(u(unit)); }
                            ChangeKind::Route if *steers => { routers.insert(u(unit)); }
                            _ => {}
                        }
                    }
                }
                prop_assert_eq!((owners.creators, owners.routers), (creators, routers), "{}", name);
            }
        }
    }
}

#[cfg(feature = "loader")]
mod routeclassify {
    use super::*;
    use crate::dns::Lookup;

    fn reply(kind: &Reply) -> Vec<u8> {
        let mut m = vec![0u8; 16];
        match kind {
            Reply::Oif(i, ty) => {
                // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type
                m.extend(vec![2u8, 32, 0, 0, 0, 0, 0, *ty, 0, 0, 0, 0]);
                m.extend(nl_attr(1, &[10, 0, 0, 1])); // RTA_DST
                m.extend(nl_attr(4, &i.to_ne_bytes())); // RTA_OIF
                m[4..6].copy_from_slice(&24u16.to_ne_bytes());
            }
            Reply::NoOif => {
                m.extend(vec![2u8, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                m.extend(nl_attr(1, &[10, 0, 0, 1]));
                m[4..6].copy_from_slice(&24u16.to_ne_bytes());
            }
            Reply::Err(code) => {
                m[4..6].copy_from_slice(&2u16.to_ne_bytes());
                m.extend(code.to_ne_bytes());
            }
            Reply::Short => {
                m.truncate(10);
            }
        }
        let len = m.len() as u32;
        if !matches!(kind, Reply::Short) {
            m[0..4].copy_from_slice(&len.to_ne_bytes());
        }
        m
    }

    #[derive(Clone, Debug)]
    enum Reply {
        Oif(u32, u8),
        NoOif,
        Err(i32),
        Short,
    }

    proptest! {
        #![proptest_config(cfg(1024))]

        /// What the kernel's reply to a route lookup comes to: an output
        /// interface that has a name is `Via` it; one that has no name (an
        /// index the host cannot resolve), a reply that names none, a short
        /// or malformed one and any other error is `Failed` (fail closed);
        /// only the kernel's two "unreachable" errors are `NoRoute`.
        #[test]
        fn a_route_reply_is_via_no_route_or_failed(
            r in prop_oneof![
                3 => ((1u32..8), prop_oneof![Just(1u8), Just(2), Just(3), Just(7)]).prop_map(|(i, t)| Reply::Oif(i, t)),
                1 => Just(Reply::NoOif),
                3 => prop_oneof![Just(-101i32), Just(-113), Just(-2), Just(-1), Just(0), Just(-22)].prop_map(Reply::Err),
                1 => Just(Reply::Short),
            ],
        ) {
            let mut names = |i: u32| (i % 2 == 1).then(|| format!("if{i}"));
            let got = crate::route::classify(&reply(&r), &mut names);
            let want = match &r {
                // The machine's own address (`RTN_LOCAL`) is not a path out, whether or
                // not its interface (`lo`) has a name.
                Reply::Oif(_, 2) => Lookup::Local,
                Reply::Oif(i, _) if i % 2 == 1 => Lookup::Via(format!("if{i}")),
                Reply::Err(-101) | Reply::Err(-113) => Lookup::NoRoute,
                _ => Lookup::Failed,
            };
            prop_assert_eq!(got, want, "{:?}", r);
        }

        /// Whatever bytes come back, a lookup never panics and never
        /// invents an interface for bytes that name none.
        #[test]
        fn a_route_reply_of_any_bytes_is_never_invented(bytes in proptest::collection::vec(any::<u8>(), 0..96)) {
            let mut names = |i: u32| Some(format!("if{i}"));
            let got = crate::route::classify(&bytes, &mut names);
            if let Lookup::Via(n) = got {
                // The name must come from an RTA_OIF attribute actually present.
                let idx: u32 = n.trim_start_matches("if").parse().unwrap();
                let needle = idx.to_ne_bytes();
                prop_assert!(bytes.windows(4).any(|w| w == needle), "{n} from nowhere");
            }
        }
    }
}
