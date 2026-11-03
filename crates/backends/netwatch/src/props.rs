//! Properties for the pure parts of netwatch (ledger rows N1-N9, docs/
//! regression-ledger.md): each states the invariant a fix established, with
//! an oracle written from the spec (§12d) or the kernel's own numbering
//! rather than from the code under test, and a frame condition where the
//! fix must change nothing else. The ledger says which mutant each one
//! catches. `PROPTEST_CASES` overrides the case counts.

use crate::ebpf::{Event, HOOK_NETDEV, HOOK_NFBATCH, HOOK_NFNETLINK, HOOK_RTNETLINK, HOOK_SOCKOPT};
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
        0u32..9
    ];
    // A header with a type that matters (link/route/rule messages, with and
    // without NLM_F_CREATE) followed by arbitrary bytes.
    let ty = prop_oneof![Just(16u16), Just(17), Just(19), Just(24), Just(25), Just(32), Just(33), any::<u16>()];
    (hooks, ty, any::<u16>(), proptest::collection::vec(any::<u8>(), 0..80))
        .prop_map(move |(hook, ty, flags, body)| event(hook, netns, ty, flags, &body))
}

proptest! {
    #![proptest_config(cfg(512))]

    /// An event acting in another network namespace changes nothing here,
    /// unless it is a link request that may reach into this one (then the
    /// mover's footprint is unattributed). The frame: a request elsewhere
    /// that cannot reach us leaves every footprint and claim as it was.
    #[test]
    fn events_in_other_namespaces_change_nothing_here(
        other in (1u32..).prop_filter("not ours", |n| *n != OWN_NETNS),
        ev in any_event(0),
    ) {
        let ev = Event { netns: other, ..ev };
        let reaches = ev.hook == HOOK_RTNETLINK && matches!(ev.nlmsg_type(), Some(16 | 19));
        let mut t = baseline();
        let before = rendered(&t);
        take(&mut t, &ev, OWN_NETNS, || Some(UnitId::service("other")), &mut no_names);
        if !reaches {
            prop_assert_eq!(rendered(&t), before, "{:?}", ev);
        }
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

    /// A link request acting elsewhere that names a namespace in this
    /// machine's reach (IFLA_NET_NS_PID 19, IFLA_NET_NS_FD 28,
    /// IFLA_TARGET_NETNSID 46) may move a device into the host's: the mover
    /// is charged as unattributed (protecting: fail closed), or nobody's
    /// unit is known and the global marker stands. A request with only
    /// other attributes changes nothing (the frame). Over RTM_NEWLINK and
    /// RTM_SETLINK, with other attributes before and after.
    #[test]
    fn a_link_request_elsewhere_that_reaches_here_is_never_dropped(
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
        let tools = [UnitId::service("wg"), mover.clone()];
        let v = t.view(WatchState::Attached { at: NOW }, &tools, NOW);
        if reach.is_some() {
            if known {
                prop_assert!(v.units["other"].unattributed && v.units["other"].protecting, "{:?}", v.units["other"]);
            } else {
                prop_assert!(!v.unattributed.is_empty(), "nobody's unit known: the global marker");
            }
        } else {
            prop_assert_eq!(rendered(&t), before_state);
        }
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
