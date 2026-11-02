use super::*;
use planarian_schema::UnitId;
use std::net::IpAddr;

fn change(owner: Owner, kind: ChangeKind, object: &str, iface: Option<&str>, steers: bool) -> Change {
    Change { owner, kind, object: object.into(), iface: iface.map(Into::into), steers, removed: false }
}

fn unit(u: &UnitId) -> Owner {
    Owner::Unit(u.clone())
}

const NOW: u64 = 1_000;
const ATTACHED: WatchState = WatchState::Attached { at: NOW };

/// §12d: an unnamed tool's interface carries the default route: protecting.
#[test]
fn an_interface_carrying_the_default_route_protects() {
    let netd = UnitId::service("gym-netd");
    let mut t = Tracker::default();
    t.apply(&change(unit(&netd), ChangeKind::Interface, "gnet0", Some("gnet0"), false));
    assert!(!t.footprint(&netd, NOW).protecting, "an interface alone steers nothing");
    t.apply(&change(unit(&netd), ChangeKind::Route, "0.0.0.0/0", Some("gnet0"), true));
    let f = t.footprint(&netd, NOW);
    assert!(f.protecting && f.ifaces.contains("gnet0"), "{f:?}");
    let v = t.view(ATTACHED, std::slice::from_ref(&netd), NOW);
    assert!(v.protecting_now("gym-netd", NOW));
}

/// The route may be someone else's: the interface's creator protects.
#[test]
fn a_default_route_over_its_interface_protects_whoever_added_it() {
    let (tool, other) = (UnitId::service("gym-netd"), UnitId::service("gym-routes"));
    let mut t = Tracker::default();
    t.apply(&change(unit(&tool), ChangeKind::Interface, "gnet0", Some("gnet0"), false));
    t.apply(&change(unit(&other), ChangeKind::Route, "::/0", Some("gnet0"), true));
    assert!(t.footprint(&tool, NOW).protecting);
    // And removing the route ends it.
    t.apply(&Change { removed: true, ..change(unit(&other), ChangeKind::Route, "::/0", Some("gnet0"), true) });
    assert!(!t.footprint(&tool, NOW).protecting);
}

/// A tool that never steered traffic, with a healthy watch: not protecting.
#[test]
fn a_tool_without_steering_does_not_protect() {
    let syncd = UnitId::service("gym-syncd");
    let mut t = Tracker::default();
    t.apply(&change(unit(&syncd), ChangeKind::Interface, "gsync0", Some("gsync0"), false));
    let v = t.view(ATTACHED, std::slice::from_ref(&syncd), NOW);
    assert!(!v.protecting_now("gym-syncd", NOW), "{v:?}");
}

/// Fail closed (§12d): a stale footprint, a watch not attached (or stale),
/// a missing footprint, an unattributed change, a lost event.
#[test]
fn everything_unknown_counts_as_protecting() {
    let syncd = UnitId::service("gym-syncd");
    let t = Tracker::default();
    let v = t.view(ATTACHED, std::slice::from_ref(&syncd), NOW);
    assert!(!v.protecting_now("gym-syncd", NOW), "healthy and clean: not protecting");
    assert!(v.protecting_now("gym-syncd", NOW + FRESH_SECS + 1), "stale footprint and watch");
    assert!(!v.protecting_now("gym-syncd", NOW - AHEAD_SECS), "up to 5 s ahead is fresh");
    assert!(v.protecting_now("gym-syncd", NOW - AHEAD_SECS - 1), "further ahead is not");
    let mut stale = v.clone();
    stale.units.get_mut("gym-syncd").unwrap().at = NOW - FRESH_SECS - 1;
    assert!(stale.protecting_now("gym-syncd", NOW), "stale footprint, fresh watch");
    let failed = t.view(
        WatchState::Failed { reason: "fentry rtnetlink_rcv_msg: no BTF".into() },
        std::slice::from_ref(&syncd),
        NOW,
    );
    assert!(failed.protecting_now("gym-syncd", NOW), "the watch failed to attach");
    assert!(FootprintView::default().protecting_now("gym-syncd", NOW), "nothing known");
    assert!(v.protecting_now("not-a-tool", NOW), "no footprint");

    let mut u = Tracker::default();
    u.apply(&change(Owner::Unattributed, ChangeKind::Route, "0.0.0.0/0", None, true));
    let v = u.view(ATTACHED, std::slice::from_ref(&syncd), NOW);
    assert!(!v.unattributed.is_empty() && v.protecting_now("gym-syncd", NOW), "an unattributed steering change stands");
    u.apply(&Change { removed: true, ..change(Owner::Unattributed, ChangeKind::Route, "0.0.0.0/0", None, true) });
    assert!(u.view(ATTACHED, std::slice::from_ref(&syncd), NOW).unattributed.is_empty(), "and it is gone");

    let mut l = Tracker::default();
    l.lost(Some(&syncd));
    assert!(l.view(ATTACHED, std::slice::from_ref(&syncd), NOW).protecting_now("gym-syncd", NOW));
    let mut g = Tracker::default();
    g.lost(None);
    assert!(!g.view(ATTACHED, std::slice::from_ref(&syncd), NOW).unattributed.is_empty(), "an unplaced loss");
}

#[test]
fn file_name_is_percent_n() {
    assert_eq!(file_name(&UnitId::service("wg-quick-wg0")), "wg-quick-wg0");
    assert_eq!(file_name(&UnitId::service("openvpn@work")), "openvpn@work");
    assert_eq!(file_name(&UnitId::service("openvpn@work.service")), "openvpn@work");
}

fn sample() -> FootprintView {
    let wg = UnitId::service("wg-quick-wg0");
    let quiet = UnitId::service("gym-syncd");
    let mut t = Tracker::default();
    t.apply(&change(unit(&wg), ChangeKind::Interface, "wg0", Some("wg0"), false));
    t.apply(&change(unit(&wg), ChangeKind::Route, "0.0.0.0/0", Some("wg0"), true));
    t.add_endpoint(&wg, Endpoint { proto: Proto::Udp, addr: "192.0.2.7".parse::<IpAddr>().unwrap(), port: 51820 });
    t.add_endpoint(&wg, Endpoint { proto: Proto::Udp, addr: "2001:db8::7".parse::<IpAddr>().unwrap(), port: 51820 });
    t.view(ATTACHED, &[wg, quiet], NOW)
}

#[test]
fn the_files_round_trip() {
    let d = tempfile::tempdir().unwrap();
    let v = sample();
    write(d.path(), &v).unwrap();
    assert_eq!(read(d.path()), v);
    assert_eq!(std::fs::read_to_string(d.path().join(".watch")).unwrap(), format!("attached {NOW}\n"));
    let wg = std::fs::read_to_string(d.path().join("wg-quick-wg0")).unwrap();
    assert_eq!(
        wg,
        format!("protecting yes\nat {NOW}\niface wg0\nendpoint udp 192.0.2.7 51820\nendpoint udp 2001:db8::7 51820\n")
    );
    // A unit that leaves the view loses its file; the marker comes and goes.
    let mut fewer = v.clone();
    fewer.units.remove("gym-syncd");
    fewer.unattributed = vec!["Route 0.0.0.0/0: no unit made it".into()];
    write(d.path(), &fewer).unwrap();
    assert!(!d.path().join("gym-syncd").exists() && d.path().join(".unattributed").exists());
    write(d.path(), &v).unwrap();
    assert!(!d.path().join(".unattributed").exists());
}

/// Fail closed on read: a footprint that does not parse reads as missing.
#[test]
fn an_unreadable_footprint_reads_as_missing() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), &sample()).unwrap();
    std::fs::write(d.path().join("gym-syncd"), "protecting maybe\nat 1000\n").unwrap();
    std::fs::write(d.path().join(".watch"), "attached soon\n").unwrap();
    let v = read(d.path());
    assert!(!v.units.contains_key("gym-syncd") && v.watch == WatchState::Unknown);
    assert!(v.protecting_now("gym-syncd", NOW));
}

/// The hold's script (nix/posture.nix) reads these files with these exact
/// lines; they must see what this crate wrote.
#[test]
fn the_hold_scripts_lines_read_what_is_written() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), &sample()).unwrap();
    let sh = |script: &str| {
        let o = std::process::Command::new("sh").arg("-c").arg(script).arg("sh").arg(d.path()).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    };
    // The endpoints and interfaces it passes, read as `proto addr port`.
    let allow =
        sh(r#"awk '$1 == "iface" { print "iface", $2 } $1 == "endpoint" { print $2, $3, $4 }' "$1/wg-quick-wg0" |
        while read -r proto addr port; do echo "[$proto|$addr|$port]"; done"#);
    assert_eq!(allow, "[iface|wg0|]\n[udp|192.0.2.7|51820]\n[udp|2001:db8::7|51820]\n");
    // The heartbeat, its `at`, and the protecting line.
    assert_eq!(sh(r#"read -r state ts < "$1/.watch"; echo "$state $ts""#), format!("attached {NOW}\n"));
    assert_eq!(sh(r#"awk '$1 == "at" { print $2; exit }' "$1/gym-syncd""#), format!("{NOW}\n"));
    assert_eq!(sh(r#"grep -qx 'protecting yes' "$1/wg-quick-wg0" && echo held"#), "held\n");
    assert_eq!(sh(r#"grep -qx 'protecting no' "$1/gym-syncd" && echo free"#), "free\n");
}

mod parsing {
    use crate::ebpf::{Event, HOOK_NFBATCH, HOOK_NFNETLINK, HOOK_RTNETLINK};
    use crate::model::{ChangeKind, Owner};
    use crate::parse::{Parsed, parse};
    use planarian_schema::UnitId;

    fn attr(ty: u16, v: &[u8]) -> Vec<u8> {
        let mut a = ((4 + v.len()) as u16).to_ne_bytes().to_vec();
        a.extend(ty.to_ne_bytes());
        a.extend(v);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    fn msg(hook: u32, ty: u16, flags: u16, body: &[u8]) -> Event {
        let mut d = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
        d.extend(ty.to_ne_bytes());
        d.extend(flags.to_ne_bytes());
        d.extend([0u8; 8]);
        d.extend(body);
        Event { cgroup: 1, tgid: 2, hook, len: d.len() as u32, data: d }
    }

    fn owner() -> Owner {
        Owner::Unit(UnitId::service("wg-quick-wg0"))
    }

    fn names(i: u32) -> Option<String> {
        (i == 7).then(|| "wg0".to_string())
    }

    fn one(p: Parsed) -> crate::model::Change {
        match p {
            Parsed::Changes(mut c) if c.len() == 1 => c.remove(0),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_created_link_is_an_interface() {
        let mut body = vec![0u8; 16]; // ifinfomsg
        body.extend(attr(3, b"wg0\0"));
        let c = one(parse(&msg(HOOK_RTNETLINK, 16, 0x400 | 0x1, &body), &owner(), &names));
        assert_eq!((c.kind, c.object.as_str(), c.steers, c.removed), (ChangeKind::Interface, "wg0", false, false));
        // Setting a link up creates nothing.
        assert_eq!(parse(&msg(HOOK_RTNETLINK, 16, 0x1, &body), &owner(), &names), Parsed::Nothing);
        // Deleting by index alone still names it.
        let mut del = vec![0u8; 16];
        del[4..8].copy_from_slice(&7u32.to_ne_bytes());
        let c = one(parse(&msg(HOOK_RTNETLINK, 17, 0x1, &del), &owner(), &names));
        assert!(c.removed && c.object == "wg0");
    }

    fn route(dst_len: u8, oif: u32) -> Vec<u8> {
        let mut b = vec![2u8, dst_len, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0]; // rtmsg: AF_INET, main
        if dst_len > 0 {
            b.extend(attr(1, &[10, 0, 0, 0]));
        }
        b.extend(attr(4, &oif.to_ne_bytes()));
        b
    }

    #[test]
    fn a_default_or_all_covering_route_steers() {
        for (dst_len, steers) in [(0, true), (1, true), (8, false)] {
            let c = one(parse(&msg(HOOK_RTNETLINK, 24, 0x400, &route(dst_len, 7)), &owner(), &names));
            assert_eq!((c.kind, c.steers, c.iface.as_deref()), (ChangeKind::Route, steers, Some("wg0")), "/{dst_len}");
        }
        let c = one(parse(&msg(HOOK_RTNETLINK, 25, 0, &route(0, 7)), &owner(), &names));
        assert!(c.removed, "RTM_DELROUTE");
        // A read changes nothing.
        assert_eq!(parse(&msg(HOOK_RTNETLINK, 26, 0x300, &route(0, 7)), &owner(), &names), Parsed::Nothing);
    }

    #[test]
    fn a_catch_all_rule_steers() {
        // fib_rule_hdr: AF_INET, dst 0, src 0, tos, table, res, res, action TO_TBL, flags.
        let mut b = vec![2u8, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        b.extend(attr(15, &51820u32.to_ne_bytes()));
        let c = one(parse(&msg(HOOK_RTNETLINK, 32, 0x400, &b), &owner(), &names));
        assert!(c.kind == ChangeKind::Rule && c.steers, "{c:?}");
        b[1] = 24; // a rule for one destination prefix does not catch all
        assert!(!one(parse(&msg(HOOK_RTNETLINK, 32, 0x400, &b), &owner(), &names)).steers);
    }

    #[test]
    fn nftables_changes_are_firewall_changes_and_reads_are_not() {
        let c = one(parse(&msg(HOOK_NFBATCH, 0x10, 0x1, &[0u8; 4]), &owner(), &names));
        assert!(c.kind == ChangeKind::Firewall && c.steers);
        let newrule = (10u16 << 8) | 6;
        assert!(matches!(parse(&msg(HOOK_NFNETLINK, newrule, 0x1, &[0u8; 4]), &owner(), &names), Parsed::Changes(_)));
        let getrule = (10u16 << 8) | 7;
        assert_eq!(parse(&msg(HOOK_NFNETLINK, getrule, 0x301, &[0u8; 4]), &owner(), &names), Parsed::Nothing);
        let ctnetlink = (1u16 << 8) | 0;
        assert_eq!(parse(&msg(HOOK_NFNETLINK, ctnetlink, 0x1, &[0u8; 4]), &owner(), &names), Parsed::Nothing);
    }

    #[test]
    fn a_route_past_the_capture_is_unreadable() {
        let mut e = msg(HOOK_RTNETLINK, 24, 0x400, &route(0, 7));
        let n = e.data.len();
        e.data.truncate(n - 3);
        assert!(matches!(parse(&e, &owner(), &names), Parsed::Unreadable(_)));
    }

    #[test]
    fn the_event_layout_matches_the_kernel_side() {
        assert_eq!(crate::ebpf::EVENT_SIZE, 8 + 4 + 4 + 4 + 4 + 512);
    }
}
