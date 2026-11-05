//! Rename identity, independently constructed before and after by name.
//! A rename changes neither the owners nor any fact other than the name.

use super::*;
use crate::ebpf::{Event, HOOK_NETRENAME};
use crate::parse::{take, take_cached};
use proptest::prelude::*;

const HOST: u32 = 41;
const FOREIGN: u32 = 42;
type Shape = [(bool, bool, bool, bool)];

fn event(netns: u32, was: &str, now: &str) -> Event {
    let mut data = vec![0; 32];
    data[..was.len()].copy_from_slice(was.as_bytes());
    data[16..16 + now.len()].copy_from_slice(now.as_bytes());
    Event { cgroup: 1, tgid: 2, hook: HOOK_NETRENAME, len: 32, netns, cgpath: None, data }
}

// An identity can have several owners and route users. The same symbolic
// fixture instantiated under its new name is the oracle, rather than a
// second implementation that walks and renames the production maps.
fn fixture(identity: &str, shape: &Shape) -> Tracker {
    let mut t = Tracker::default();
    let endpoint = Endpoint { proto: Proto::Udp, addr: "192.0.2.8".parse().unwrap(), port: 51820 };
    t.virtual_ifaces.extend([identity.to_string(), "unrelated0".into()]);
    t.unattributed.insert((ChangeKind::Route, "anonymous-route".into()), Some(identity.into()));
    t.pre_attach.insert((ChangeKind::Route, "gap-route".into()), Some(identity.into()));
    t.route_through.insert("found-route".into(), identity.into());
    for (n, &(creator, router, ended, history)) in shape.iter().enumerate() {
        let u = UnitId::service(&format!("owner-{n}"));
        let mut s = Standing::default();
        s.objects.insert((ChangeKind::Interface, "unrelated0".into()), (Some("unrelated0".into()), false));
        if creator {
            s.objects.insert((ChangeKind::Interface, identity.into()), (Some(identity.into()), false));
        }
        if router {
            s.objects.insert((ChangeKind::Route, format!("route-{n}")), (Some(identity.into()), true));
        }
        s.endpoints.insert(endpoint);
        s.unattributed = n % 2 == 0;
        t.units.insert(u.clone(), s);
        t.invocations.insert(u.clone(), Invocation { id: Some(format!("{:032x}", n + 1)), ended });
        if history {
            let l = Latch {
                protecting: true,
                ifaces: BTreeSet::from([identity.into()]),
                endpoints: BTreeSet::from([endpoint]),
            };
            t.latched.insert(u.clone(), l.clone());
            t.next_latch.insert(u, l);
        }
    }
    t.relatch();
    t
}

fn apply(t: &mut Tracker, ev: &Event) {
    // The renamer is deliberately not one of the original owners.
    take(t, ev, HOST, || Some(UnitId::service("renamer")), &mut |_| None);
}

fn state(t: &Tracker) -> String {
    format!("{t:?}")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn renaming_changes_only_the_name_and_preserves_every_owner_and_latch(
        was in "nw[a-z]{1,6}", now in "nw[a-z]{1,6}",
        shape in prop::collection::vec((any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()), 1..5),
    ) {
        let mut t = fixture(&was, &shape);
        apply(&mut t, &event(HOST, &was, &now));
        prop_assert_eq!(state(&t), state(&fixture(&now, &shape)));
        // Removing the final name clears the interface and every route
        // through it, while the invocation's protecting history survives.
        t.apply(&Change { owner: Owner::Unattributed, kind: ChangeKind::Interface,
            object: now.clone(), iface: Some(now.clone()), steers: false, removed: true });
        prop_assert!(!t.claims().objects.iter().any(|o| o.2 == was || o.3.as_deref() == Some(now.as_str())));
        prop_assert!(t.latched.values().all(|l| l.protecting));
    }

    #[test]
    fn a_foreign_rename_changes_nothing(
        was in "nw[a-z]{1,6}", now in "nw[a-z]{1,6}",
        shape in prop::collection::vec((any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()), 1..5),
    ) {
        let mut t = fixture(&was, &shape);
        let before = state(&t);
        apply(&mut t, &event(FOREIGN, &was, &now));
        prop_assert_eq!(state(&t), before);
    }

    #[test]
    fn a_rename_without_both_names_preserves_claims_and_fails_closed(
        name in "nw[a-z]{1,6}", missing_old in any::<bool>(), unknown_netns in any::<bool>(),
    ) {
        let mut t = fixture(&name, &[(true, true, false, true)]);
        let before = t.claims();
        let ev = if missing_old { event(HOST, "", &name) } else { event(HOST, &name, "") };
        apply(&mut t, &Event { netns: if unknown_netns { 0 } else { HOST }, ..ev });
        prop_assert_eq!(t.claims().objects, before.objects);
        if unknown_netns {
            prop_assert!(t.lost_unplaced);
        } else {
            prop_assert!(t.units.get(&UnitId::service("renamer")).is_some_and(|s| s.unattributed));
        }
    }
}

#[test]
fn the_unfixed_rename_and_partial_renames_are_caught() {
    let shape = [(true, false, false, true), (false, true, true, true)];
    let before = fixture("old", &shape);
    let want = state(&fixture("new", &shape));
    assert_ne!(state(&before), want, "ignoring the rename is caught");
    let mut t = before.clone();
    apply(&mut t, &event(HOST, "old", "new"));
    assert_eq!(state(&t), want);
    // Independently break one component at a time: stale owners, routes,
    // attach state, virtual classification, and either invocation latch.
    let mut mutants = vec![];
    let mut m = t.clone();
    m.units = before.units.clone();
    mutants.push(m);
    let mut m = t.clone();
    m.unattributed = before.unattributed.clone();
    mutants.push(m);
    let mut m = t.clone();
    m.pre_attach = before.pre_attach.clone();
    mutants.push(m);
    let mut m = t.clone();
    m.route_through = before.route_through.clone();
    mutants.push(m);
    let mut m = t.clone();
    m.virtual_ifaces = before.virtual_ifaces.clone();
    mutants.push(m);
    let mut m = t.clone();
    m.latched = before.latched.clone();
    mutants.push(m);
    let mut m = t.clone();
    m.next_latch = before.next_latch.clone();
    mutants.push(m);
    for m in mutants {
        assert_ne!(state(&m), want, "a partial rename escaped");
    }
}

fn route(index: u32, prefix: u8) -> Event {
    let mut data = vec![0u8; 28];
    data[4..6].copy_from_slice(&24u16.to_ne_bytes());
    data[6..8].copy_from_slice(&0x400u16.to_ne_bytes());
    data[16] = 2;
    data[17] = prefix;
    data[20] = 254;
    data.extend(8u16.to_ne_bytes());
    data.extend(4u16.to_ne_bytes());
    data.extend(index.to_ne_bytes());
    if prefix != 0 {
        data.extend(8u16.to_ne_bytes());
        data.extend(1u16.to_ne_bytes());
        data.extend([192, 0, 2, 0]);
    }
    let len = data.len() as u32;
    data[..4].copy_from_slice(&len.to_ne_bytes());
    Event { cgroup: 1, tgid: 2, hook: crate::ebpf::HOOK_RTNETLINK, len, netns: HOST, cgpath: None, data }
}

fn deleted(index: u32) -> Event {
    let mut data = vec![0u8; 32];
    data[..4].copy_from_slice(&32u32.to_ne_bytes());
    data[4..6].copy_from_slice(&17u16.to_ne_bytes());
    data[20..24].copy_from_slice(&index.to_ne_bytes());
    Event { cgroup: 1, tgid: 2, hook: crate::ebpf::HOOK_RTNETLINK, len: 32, netns: HOST, cgpath: None, data }
}

// Exercise the helper the loader actually calls. `legacy` is precisely its
// old policy: a cached index never refreshes, including across a rename.
fn cached(
    t: &mut Tracker,
    ev: &Event,
    owner: &UnitId,
    names: &mut BTreeMap<u32, String>,
    live: &BTreeMap<u32, String>,
    legacy: bool,
) {
    if legacy {
        take(t, ev, HOST, || Some(owner.clone()), &mut |i| {
            if !names.contains_key(&i) {
                *names = live.clone();
            }
            names.get(&i).cloned()
        });
    } else {
        take_cached(t, ev, HOST, || Some(owner.clone()), names, &mut || live.clone());
    }
}

fn cache_history(index: u32, was: &str, now: &str, delete: bool, legacy: bool) -> Result<(), String> {
    let creator = UnitId::service("creator");
    let router = UnitId::service("router");
    let mut t = Tracker::default();
    for u in [&creator, &router] {
        t.set_invocation(u, Invocation { id: Some("a".repeat(32)), ended: false });
    }
    t.apply(&Change {
        owner: Owner::Unit(creator.clone()),
        kind: ChangeKind::Interface,
        object: was.into(),
        iface: Some(was.into()),
        steers: false,
        removed: false,
    });
    let mut names = BTreeMap::new();
    let mut live = BTreeMap::from([(index, was.to_string())]);
    // A nonsteering route populates the cache without masking the bug with
    // an already-protecting invocation latch.
    cached(&mut t, &route(index, 24), &creator, &mut names, &live, legacy);
    if t.footprint(&creator, 1).protecting || t.footprint(&router, 1).protecting {
        return Err("the precondition already protected an owner".into());
    }
    live = if delete { BTreeMap::new() } else { BTreeMap::from([(index, now.to_string())]) };
    cached(&mut t, &event(HOST, was, now), &UnitId::service("renamer"), &mut names, &live, legacy);
    if delete {
        // Both events were queued; the live device is already gone. Its
        // observed rename must still let an index-only deletion find it.
        cached(&mut t, &deleted(index), &creator, &mut names, &live, legacy);
        if !t.claims().objects.is_empty() || !names.is_empty() {
            return Err(format!("queued delete left {:?}, cache {names:?}", t.claims()));
        }
    } else {
        cached(&mut t, &route(index, 0), &router, &mut names, &live, legacy);
        for u in [&creator, &router] {
            let f = t.footprint(u, 1);
            if !f.protecting || f.ifaces != BTreeSet::from([now.into()]) || f.unattributed {
                return Err(format!("{} did not protect the final identity: {f:?}", u.name));
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn a_cached_nonsteering_route_cannot_hide_a_default_after_rename(
        index in 1u32..4096, was in "old[a-z]{1,5}", now in "new[a-z]{1,5}",
    ) {
        prop_assert!(cache_history(index, &was, &now, false, false).is_ok());
    }

    #[test]
    fn a_queued_rename_then_index_only_delete_needs_no_live_device(
        index in 1u32..4096, was in "old[a-z]{1,5}", now in "new[a-z]{1,5}",
    ) {
        prop_assert!(cache_history(index, &was, &now, true, false).is_ok());
    }

    #[test]
    fn an_unresolved_steering_index_never_uses_a_historical_name(index in 1u32..4096) {
        let u = UnitId::service("router");
        let mut t = Tracker::default();
        let mut names = BTreeMap::from([(index, "historical".into())]);
        cached(&mut t, &route(index, 0), &u, &mut names, &BTreeMap::new(), false);
        prop_assert!(t.footprint(&u, 1).protecting && t.footprint(&u, 1).unattributed);
        prop_assert!(t.claims().objects.is_empty());
    }
}

#[test]
fn the_old_loader_cache_policy_is_caught() {
    for delete in [false, true] {
        assert!(cache_history(7, "old0", "new0", delete, true).is_err());
        assert!(cache_history(7, "old0", "new0", delete, false).is_ok());
    }
}
