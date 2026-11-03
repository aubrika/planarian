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
        while !a.len().is_multiple_of(4) {
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
        Event { cgroup: 1, tgid: 2, hook, len: d.len() as u32, netns: HOST, cgpath: None, data: d }
    }

    /// The host's netns inode in these tests (init_net's is 0xF0000000).
    pub const HOST: u32 = 0xF000_0000;

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
        let c = one(parse(&msg(HOOK_RTNETLINK, 16, 0x400 | 0x1, &body), &owner(), &mut names));
        assert_eq!((c.kind, c.object.as_str(), c.steers, c.removed), (ChangeKind::Interface, "wg0", false, false));
        // Setting a link up creates nothing.
        assert_eq!(parse(&msg(HOOK_RTNETLINK, 16, 0x1, &body), &owner(), &mut names), Parsed::Nothing);
        // Deleting by index alone still names it.
        let mut del = vec![0u8; 16];
        del[4..8].copy_from_slice(&7u32.to_ne_bytes());
        let c = one(parse(&msg(HOOK_RTNETLINK, 17, 0x1, &del), &owner(), &mut names));
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
            let c = one(parse(&msg(HOOK_RTNETLINK, 24, 0x400, &route(dst_len, 7)), &owner(), &mut names));
            assert_eq!((c.kind, c.steers, c.iface.as_deref()), (ChangeKind::Route, steers, Some("wg0")), "/{dst_len}");
        }
        let c = one(parse(&msg(HOOK_RTNETLINK, 25, 0, &route(0, 7)), &owner(), &mut names));
        assert!(c.removed, "RTM_DELROUTE");
        // A read changes nothing.
        assert_eq!(parse(&msg(HOOK_RTNETLINK, 26, 0x300, &route(0, 7)), &owner(), &mut names), Parsed::Nothing);
    }

    #[test]
    fn a_catch_all_rule_steers() {
        // fib_rule_hdr: AF_INET, dst 0, src 0, tos, table, res, res, action TO_TBL, flags.
        let mut b = vec![2u8, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        b.extend(attr(15, &51820u32.to_ne_bytes()));
        let c = one(parse(&msg(HOOK_RTNETLINK, 32, 0x400, &b), &owner(), &mut names));
        assert!(c.kind == ChangeKind::Rule && c.steers, "{c:?}");
        b[1] = 24; // a rule for one destination prefix does not catch all
        assert!(!one(parse(&msg(HOOK_RTNETLINK, 32, 0x400, &b), &owner(), &mut names)).steers);
        // The kernel's own rules (to local, main, default) redirect nothing.
        for table in [253u32, 254, 255] {
            let mut k = vec![2u8, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
            k.extend(attr(15, &table.to_ne_bytes()));
            assert!(!one(parse(&msg(HOOK_RTNETLINK, 32, 0x400, &k), &owner(), &mut names)).steers, "table {table}");
        }
    }

    #[test]
    fn nftables_changes_are_firewall_changes_and_reads_are_not() {
        let c = one(parse(&msg(HOOK_NFBATCH, 0x10, 0x1, &[0u8; 4]), &owner(), &mut names));
        assert!(c.kind == ChangeKind::Firewall && c.steers);
        let newrule = (10u16 << 8) | 6;
        assert!(matches!(
            parse(&msg(HOOK_NFNETLINK, newrule, 0x1, &[0u8; 4]), &owner(), &mut names),
            Parsed::Changes(_)
        ));
        let getrule = (10u16 << 8) | 7;
        assert_eq!(parse(&msg(HOOK_NFNETLINK, getrule, 0x301, &[0u8; 4]), &owner(), &mut names), Parsed::Nothing);
        let ctnetlink = 1u16 << 8;
        assert_eq!(parse(&msg(HOOK_NFNETLINK, ctnetlink, 0x1, &[0u8; 4]), &owner(), &mut names), Parsed::Nothing);
    }

    /// Every nftables message type, by name (`enum nf_tables_msg_types`):
    /// the GETs read; everything else changes, the resets (a zeroed quota
    /// can flip a verdict) and an unknown later type included (fail
    /// closed). vm-netwatch (n): `nft list` sends GETFLOWTABLE (23), which
    /// the old `% 3 == 1` rule took for a change.
    #[test]
    fn every_nftables_read_is_a_read_and_the_rest_change() {
        let reads = [
            ("GETTABLE", 1),
            ("GETCHAIN", 4),
            ("GETRULE", 7),
            ("GETSET", 10),
            ("GETSETELEM", 13),
            ("GETGEN", 16),
            ("GETOBJ", 19),
            ("GETFLOWTABLE", 23),
        ];
        let changes = [
            ("NEWTABLE", 0),
            ("DELTABLE", 2),
            ("NEWCHAIN", 3),
            ("DELCHAIN", 5),
            ("NEWRULE", 6),
            ("DELRULE", 8),
            ("NEWSET", 9),
            ("DELSET", 11),
            ("NEWSETELEM", 12),
            ("DELSETELEM", 14),
            ("NEWOBJ", 18),
            ("DELOBJ", 20),
            ("NEWFLOWTABLE", 22),
            ("DELFLOWTABLE", 24),
            ("DESTROYTABLE", 26),
            ("DESTROYCHAIN", 27),
            ("DESTROYRULE", 28),
            ("DESTROYSET", 29),
            ("DESTROYSETELEM", 30),
            ("DESTROYOBJ", 31),
            ("DESTROYFLOWTABLE", 32),
            ("GETOBJ_RESET", 21),
            ("GETRULE_RESET", 25),
            ("GETSETELEM_RESET", 33),
            ("a later kernel's", 40),
        ];
        let ty = |n: u16| (10u16 << 8) | n;
        for (name, n) in reads {
            assert_eq!(
                parse(&msg(HOOK_NFNETLINK, ty(n), 0x301, &[0u8; 4]), &owner(), &mut names),
                Parsed::Nothing,
                "{name}"
            );
        }
        for (name, n) in changes {
            assert!(
                matches!(parse(&msg(HOOK_NFNETLINK, ty(n), 0x1, &[0u8; 4]), &owner(), &mut names), Parsed::Changes(_)),
                "{name}"
            );
        }
    }

    #[test]
    fn a_route_past_the_capture_is_unreadable() {
        let mut e = msg(HOOK_RTNETLINK, 24, 0x400, &route(0, 7));
        let n = e.data.len();
        e.data.truncate(n - 3);
        assert!(matches!(parse(&e, &owner(), &mut names), Parsed::Unreadable(_)));
    }

    #[test]
    fn the_event_layout_matches_the_kernel_side() {
        // cgroup, tgid, hook, len, captured, netns, cgflags, 4 names of 96,
        // the capture.
        assert_eq!(crate::ebpf::EVENT_SIZE, 8 + 4 * 6 + 4 * 96 + 512);
    }

    /// An event as the ring buffer hands it over, cgroup names leaf first.
    fn raw(cgflags: u32, names: &[&[u8]]) -> Vec<u8> {
        let mut b = vec![0u8; crate::ebpf::EVENT_SIZE];
        b[24..28].copy_from_slice(&0xF000_0000u32.to_ne_bytes());
        b[28..32].copy_from_slice(&cgflags.to_ne_bytes());
        for (i, n) in names.iter().enumerate() {
            b[32 + 96 * i..32 + 96 * i + n.len()].copy_from_slice(n);
        }
        b
    }

    /// The kernel's cgroup path is used only when whole: the walk reached
    /// the root and no name filled its slot.
    #[test]
    fn the_cgroup_path_is_read_only_when_whole() {
        use crate::ebpf::{CG_ROOT, Event};
        let ev =
            Event::parse(&raw(3 | CG_ROOT, &[b"nw-tpl@a.service\0", b"system-nw\\x2dtpl.slice\0", b"system.slice\0"]))
                .unwrap();
        assert_eq!(ev.cgpath.as_deref(), Some("system.slice/system-nw\\x2dtpl.slice/nw-tpl@a.service"));
        assert_eq!(ev.netns, 0xF000_0000);
        assert_eq!(
            ev.cgpath.as_deref().and_then(crate::host::unit_of_cgroup),
            Some(planarian_schema::UnitId::service("nw-tpl@a"))
        );
        // Deeper than four: no root reached, so no path.
        assert_eq!(Event::parse(&raw(4, &[b"a\0", b"b\0", b"c\0", b"d\0"])).unwrap().cgpath, None);
        // A name that filled its slot may be cut short.
        assert_eq!(Event::parse(&raw(1 | CG_ROOT, &[&[b'x'; 96]])).unwrap().cgpath, None);
        // Under user.slice: a path, but no unit (unattributed).
        let user = Event::parse(&raw(2 | CG_ROOT, &[b"user@1000.service\0", b"user.slice\0"])).unwrap();
        assert_eq!(user.cgpath.as_deref().and_then(crate::host::unit_of_cgroup), None);
        // No names read (the offsets were not set).
        assert_eq!(Event::parse(&raw(0, &[])).unwrap().cgpath, None);
    }
}

mod sockopt {
    use crate::ebpf::{Event, HOOK_SOCKOPT};
    use crate::model::{ChangeKind, Owner};
    use crate::parse::{Parsed, parse};
    use planarian_schema::UnitId;

    /// Legacy iptables (`nf_setsockopt`): any call from a unit is a steering
    /// firewall change (fail closed).
    #[test]
    fn a_legacy_table_change_is_a_steering_firewall_change() {
        let mut data = vec![2u8, 0, 0, 0];
        data.extend(64i32.to_ne_bytes()); // IPT_SO_SET_REPLACE
        let ev = Event { cgroup: 1, tgid: 2, hook: HOOK_SOCKOPT, len: 8, netns: 0xF000_0000, cgpath: None, data };
        let owner = Owner::Unit(UnitId::service("gym-netd"));
        match parse(&ev, &owner, &mut |_| None) {
            Parsed::Changes(c) => assert!(c.len() == 1 && c[0].kind == ChangeKind::Firewall && c[0].steers, "{c:?}"),
            other => panic!("{other:?}"),
        }
    }
}

#[cfg(feature = "loader")]
mod loader_checks {
    /// `READY=1` reaches the notify socket (a path, or an abstract `@name`).
    #[test]
    fn ready_reaches_the_notify_socket() {
        use std::os::unix::net::UnixDatagram;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("notify");
        let sock = UnixDatagram::bind(&path).unwrap();
        crate::loader::notify_ready(Some(&path));
        let mut buf = [0u8; 32];
        let n = sock.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
        crate::loader::notify_ready(None); // not under systemd: nothing to do
    }

    /// A watch that cannot start writes `.watch` = `failed <reason>` first,
    /// then still tells systemd it is ready (once), so boot never waits on
    /// the start timeout and the hold already reads it as not attached.
    #[test]
    fn a_failed_start_writes_failed_then_ready() {
        use std::os::unix::net::UnixDatagram;
        let d = tempfile::tempdir().unwrap();
        let (fp, path) = (d.path().join("footprint"), d.path().join("notify"));
        let sock = UnixDatagram::bind(&path).unwrap();
        sock.set_nonblocking(true).unwrap();
        let r = crate::loader::run(&d.path().join("no-export.json"), &d.path().join("none.o"), &fp, Some(&path));
        assert!(r.is_err());
        let watch = std::fs::read_to_string(fp.join(".watch")).unwrap();
        assert!(watch.starts_with("failed "), "{watch}");
        let mut buf = [0u8; 32];
        let n = sock.recv(&mut buf).expect("READY=1 was sent");
        assert_eq!(&buf[..n], b"READY=1");
        assert!(sock.recv(&mut buf).is_err(), "exactly once");
    }

    /// An unusable object (here, not ELF) is the exit-1 path: `failed`,
    /// READY=1 once, and an error, without asking the kernel or retrying.
    #[test]
    fn an_unusable_object_exits_after_failed_and_ready() {
        use std::os::unix::net::UnixDatagram;
        let d = tempfile::tempdir().unwrap();
        let (fp, path) = (d.path().join("footprint"), d.path().join("notify"));
        let (export, object) = (d.path().join("export.json"), d.path().join("netwatch.bpf.o"));
        std::fs::write(&export, r#"{"networkTools": ["wg-quick-wg0"], "units": {}}"#).unwrap();
        std::fs::write(&object, b"not an object").unwrap();
        let sock = UnixDatagram::bind(&path).unwrap();
        sock.set_nonblocking(true).unwrap();
        let r = crate::loader::run(&export, &object, &fp, Some(&path));
        assert!(r.unwrap_err().contains("not an eBPF object"));
        let watch = std::fs::read_to_string(fp.join(".watch")).unwrap();
        assert!(watch.starts_with("failed ") && watch.contains("not an eBPF object"), "{watch}");
        let mut buf = [0u8; 32];
        let n = sock.recv(&mut buf).expect("READY=1 was sent");
        assert_eq!(&buf[..n], b"READY=1");
        assert!(sock.recv(&mut buf).is_err(), "exactly once");
    }

    /// What the kernel refuses is retried: each refusal is reported (the
    /// caller writes `failed <reason>`, READY=1 the first time) and waited
    /// out, until an attach succeeds.
    #[test]
    fn a_kernel_refusal_is_retried_until_it_attaches() {
        use crate::loader::{Start, retry};
        let mut tries = 0;
        let (mut refused, mut waits) = (Vec::new(), 0);
        let r = retry(
            || {
                tries += 1;
                if tries < 3 {
                    Err(Start::Kernel(format!("attach kprobe nfnetlink_rcv_msg: try {tries}")))
                } else {
                    Ok(tries)
                }
            },
            |why| refused.push(why.to_string()),
            || {
                waits += 1;
                true
            },
        );
        assert_eq!(r, Ok(3));
        assert_eq!(refused, ["attach kprobe nfnetlink_rcv_msg: try 1", "attach kprobe nfnetlink_rcv_msg: try 2"]);
        assert_eq!(waits, 2);
    }

    /// An unusable result during retries ends them (exit 1), and a stop
    /// while waiting ends them without another try.
    #[test]
    fn retries_end_on_an_unusable_object_or_a_stop() {
        use crate::loader::{Start, retry};
        let mut tries = 0;
        let r: Result<(), _> = retry(
            || {
                tries += 1;
                Err(if tries == 1 { Start::Kernel("refused".into()) } else { Start::Unusable("no LOST map".into()) })
            },
            |_| {},
            || true,
        );
        assert_eq!(r, Err(Start::Unusable("no LOST map".into())));
        assert_eq!(tries, 2);

        let mut tries = 0;
        let r: Result<(), _> = retry(
            || {
                tries += 1;
                Err(Start::Kernel("refused".into()))
            },
            |_| {},
            || false,
        );
        assert!(matches!(r, Err(Start::Kernel(_))));
        assert_eq!(tries, 1, "no try after the stop");
    }

    /// The two nfnetlink functions are in a module, so kprobes; the
    /// built-in ones stay fentry (coordinator, Nov 2).
    #[test]
    fn module_functions_are_kprobes() {
        use crate::loader::{Kind, PROBES};
        for (prog, func, kind) in PROBES {
            // register_netdevice at exit: the name is final only then.
            let want = match func {
                f if f.starts_with("nfnetlink_") => Kind::KProbe,
                "register_netdevice" => Kind::FExit,
                _ => Kind::FEntry,
            };
            assert_eq!(kind, want, "{prog} ({func})");
        }
    }

    /// netwatch watches its own netns, so it refuses to run outside the
    /// host's (pid 1's).
    #[test]
    fn it_refuses_a_netns_other_than_the_hosts() {
        let d = tempfile::tempdir().unwrap();
        for p in ["self/ns", "1/ns"] {
            std::fs::create_dir_all(d.path().join(p)).unwrap();
        }
        std::fs::write(d.path().join("self/ns/net"), "").unwrap();
        std::fs::write(d.path().join("1/ns/net"), "").unwrap();
        let e = crate::loader::host_netns(d.path()).unwrap_err();
        assert!(e.contains("not in the host's network namespace"), "{e}");
        std::fs::remove_file(d.path().join("1/ns/net")).unwrap();
        std::os::unix::fs::symlink(d.path().join("self/ns/net"), d.path().join("1/ns/net")).unwrap();
        assert!(crate::loader::host_netns(d.path()).is_ok(), "the same namespace");
    }

    /// An empty or foreign object is refused before the kernel is asked.
    #[test]
    fn an_object_without_the_programs_is_refused() {
        assert!(crate::loader::check_object(&[]).unwrap_err().contains("not an eBPF object"));
        assert!(crate::loader::check_object(b"\x7fELF not really").is_err());
    }
}

/// Attribution (crate docs): a unit's cgroup is recorded as it is made and
/// kept after it goes, so a oneshot that exits at once is still charged
/// with its change; a cgroup never seen fails closed.
#[cfg(feature = "loader")]
mod cgroups {
    use crate::cgroups::Cgroups;
    use crate::{Change, ChangeKind, Owner, Tracker, WatchState};
    use planarian_schema::UnitId;
    use std::collections::BTreeSet;
    use std::os::unix::fs::MetadataExt;

    fn ino(p: &std::path::Path) -> u64 {
        std::fs::metadata(p).unwrap().ino()
    }

    fn tree() -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let slice = d.path().join("system.slice");
        std::fs::create_dir(&slice).unwrap();
        (d, slice)
    }

    /// A tick's walk merges: a unit whose cgroup went is still known.
    const NEW: &str = "fedcba9876543210fedcba9876543210";
    const NEXT: &str = "00112233445566778899aabbccddeeff";

    /// A unit cgroup with its InvocationID (as `user.invocation_id`, which
    /// an unprivileged test can set); `false` if this filesystem refuses.
    fn start(dir: &std::path::Path, id: Option<&str>) -> bool {
        std::fs::create_dir(dir).unwrap();
        id.is_none_or(|id| {
            rustix::fs::setxattr(dir, "user.invocation_id", id.as_bytes(), rustix::fs::XattrFlags::empty()).is_ok()
        })
    }

    fn state(c: &Cgroups, u: &str) -> Option<crate::Invocation> {
        c.invocations().find(|(x, _)| **x == UnitId::service(u)).map(|(_, i)| i)
    }

    fn inv(id: Option<&str>, ended: bool) -> Option<crate::Invocation> {
        Some(crate::Invocation { id: id.map(str::to_string), ended })
    }

    /// An invocation ends on IN_DELETE, and only at `finish` (after the
    /// ring drain); a restart is a new invocation; a cgroup whose id is not
    /// readable yet is a new one with none (`protecting unknown`).
    #[test]
    fn an_invocation_ends_when_its_cgroup_goes() {
        let (d, slice) = tree();
        let vpn = slice.join("wg-gym.service");
        if !start(&vpn, Some(NEW)) {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let mut c = Cgroups::new(d.path());
        assert_eq!(state(&c, "wg-gym"), inv(Some(NEW), false), "read at the walk");
        std::fs::remove_dir(&vpn).unwrap();
        c.drain();
        assert_eq!(state(&c, "wg-gym"), inv(Some(NEW), false), "not ended before the ring drain");
        assert_eq!(c.finish(), vec![UnitId::service("wg-gym")]);
        assert_eq!(state(&c, "wg-gym"), inv(Some(NEW), true));
        assert!(c.finish().is_empty(), "once");
        assert!(start(&vpn, Some(NEXT)));
        c.drain();
        assert_eq!(state(&c, "wg-gym"), inv(Some(NEXT), false), "restarted: a new invocation");
        assert!(start(&slice.join("late.service"), None));
        c.drain();
        assert_eq!(state(&c, "late"), inv(None, false), "made, id not set yet");
    }

    /// Without IN_DELETE (refused, or the queue overflowed), the absence
    /// check at a drain sees the cgroup gone.
    #[test]
    fn an_invocation_ends_by_absence_without_inotify() {
        let (d, slice) = tree();
        let vpn = slice.join("wg-gym.service");
        if !start(&vpn, Some(NEW)) {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let mut c = Cgroups::new(d.path()).without_inotify();
        std::fs::remove_dir(&vpn).unwrap();
        c.drain();
        assert_eq!(c.finish(), vec![UnitId::service("wg-gym")]);
        assert_eq!(state(&c, "wg-gym"), inv(Some(NEW), true));
    }

    /// After a netwatch restart, an invocation whose cgroup was already gone
    /// is not known at all, so never `ended`: its hold holds.
    #[test]
    fn a_restart_never_ends_an_invocation_it_did_not_see_go() {
        let (d, slice) = tree();
        let mut c = Cgroups::new(d.path());
        assert!(start(&slice.join("other.service"), None));
        c.drain();
        assert_eq!(state(&c, "wg-gym"), None);
        assert!(c.finish().is_empty());
        let _ = slice;
    }

    #[test]
    fn the_map_merges_and_does_not_replace() {
        let (d, slice) = tree();
        let unit = slice.join("nw-route.service");
        std::fs::create_dir(&unit).unwrap();
        let mut c = Cgroups::new(d.path());
        let id = ino(&unit);
        std::fs::remove_dir(&unit).unwrap();
        let running = c.walk(&BTreeSet::new());
        assert!(!running.contains("nw-route"));
        assert_eq!(c.unit(id), Some(UnitId::service("nw-route")));
    }

    /// The cgroup is made (IN_CREATE wakes the loop, which drains), the
    /// oneshot changes something and exits, its cgroup goes; then its event
    /// is read: still charged to it, from the IN_CREATE record alone.
    #[test]
    fn a_unit_gone_before_its_event_is_read_is_still_attributed() {
        let (d, slice) = tree();
        let mut c = Cgroups::new(d.path());
        let unit = slice.join("nw-sockopt.service");
        std::fs::create_dir(&unit).unwrap();
        let id = ino(&unit);
        c.drain();
        std::fs::remove_dir(&unit).unwrap();
        assert_eq!(c.unit(id), Some(UnitId::service("nw-sockopt")));
    }

    /// Made and gone before netwatch saw it at all: unknown, so the change
    /// is unattributed and the hold reads `.unattributed` (fail closed).
    #[test]
    fn a_cgroup_never_seen_is_unattributed() {
        let (d, _) = tree();
        let mut c = Cgroups::new(d.path());
        assert_eq!(c.unit(424_242), None);
        let owner = c.unit(424_242).map(Owner::Unit).unwrap_or(Owner::Unattributed);
        let mut t = Tracker::default();
        t.apply(&Change {
            owner,
            kind: ChangeKind::Firewall,
            object: "legacy tables pf 2".into(),
            iface: None,
            steers: true,
            removed: false,
        });
        let v = t.view(WatchState::Attached { at: 100 }, &[UnitId::service("nw-sockopt")], 100);
        assert!(!v.unattributed.is_empty(), "fail closed");
        assert!(v.protecting_now("nw-sockopt", 100), "held: not known to be not protecting");
    }

    /// Bounded: an id is forgotten once its cgroup has been gone for two
    /// walks and its unit claims nothing; a claimed unit's id is kept.
    #[test]
    fn gone_unclaimed_ids_are_forgotten_and_claimed_ones_kept() {
        let (d, slice) = tree();
        let (quiet, vpn) = (slice.join("nw-quiet.service"), slice.join("nw-route.service"));
        std::fs::create_dir(&quiet).unwrap();
        std::fs::create_dir(&vpn).unwrap();
        let mut c = Cgroups::new(d.path());
        let (iq, iv) = (ino(&quiet), ino(&vpn));
        assert_eq!(c.len(), 2);
        std::fs::remove_dir(&quiet).unwrap();
        std::fs::remove_dir(&vpn).unwrap();
        let claimed: BTreeSet<UnitId> = [UnitId::service("nw-route")].into();
        c.walk(&claimed); // gone once: both kept, so an unread event still finds them
        assert_eq!(c.len(), 2);
        c.walk(&claimed); // gone twice: the unclaimed one goes
        assert_eq!(c.len(), 1);
        assert_eq!(c.unit(iv), Some(UnitId::service("nw-route")));
        assert_eq!(c.unit(iq), None);
        c.walk(&BTreeSet::new()); // its claim gone too: forgotten
        assert!(c.is_empty());
    }

    #[test]
    fn a_unit_in_a_new_slice_is_found() {
        let (d, slice) = tree();
        let mut c = Cgroups::new(d.path());
        let tpl = slice.join("system-nw\\x2dtpl.slice");
        std::fs::create_dir(&tpl).unwrap();
        // Made before the new slice is watched: found by the scan on watch.
        let a = tpl.join("nw-tpl@a.service");
        std::fs::create_dir(&a).unwrap();
        let ida = ino(&a);
        c.drain();
        // Made after: found by the slice's own watch.
        let b = tpl.join("nw-tpl@b.service");
        std::fs::create_dir(&b).unwrap();
        let idb = ino(&b);
        c.drain();
        std::fs::remove_dir(&a).unwrap();
        std::fs::remove_dir(&b).unwrap();
        assert_eq!(c.unit(ida), Some(UnitId::service("nw-tpl@a")));
        assert_eq!(c.unit(idb), Some(UnitId::service("nw-tpl@b")));
    }
}

mod host {
    use crate::host::{expand_tools, network_tools, unit_of_cgroup};
    use planarian_schema::UnitId;
    use std::collections::BTreeSet;

    #[test]
    fn the_exports_network_tools() {
        let e = r#"{"networkTools": ["wg-quick-wg0", "openvpn@"], "units": {}}"#;
        assert_eq!(network_tools(e), Some(vec!["wg-quick-wg0".into(), "openvpn@".into()]));
        assert_eq!(network_tools("{}"), None, "missing: fail closed");
        assert_eq!(network_tools("not json"), None);
        assert_eq!(network_tools(r#"{"networkTools": [1]}"#), None);
    }

    #[test]
    fn a_cgroup_belongs_to_its_service() {
        assert_eq!(unit_of_cgroup("/system.slice/wg-quick-wg0.service"), Some(UnitId::service("wg-quick-wg0")));
        assert_eq!(unit_of_cgroup("system.slice/openvpn@work.service/payload"), Some(UnitId::service("openvpn@work")));
        assert_eq!(unit_of_cgroup("/user.slice/user-1000.slice/session-2.scope"), None);
        assert_eq!(unit_of_cgroup("/"), None);
        assert_eq!(unit_of_cgroup("/system.slice/foo.slice"), None);
        // How systemd places a template's instances: in the template's slice.
        assert_eq!(
            unit_of_cgroup("/system.slice/system-openvpn.slice/openvpn@work.service"),
            Some(UnitId::service("openvpn@work"))
        );
        assert_eq!(
            unit_of_cgroup("system.slice/system-nw\\x2dtpl.slice/nw-tpl@a.service/payload"),
            Some(UnitId::service("nw-tpl@a"))
        );
        assert_eq!(unit_of_cgroup("/system.slice/system-openvpn.slice"), None);
    }

    #[test]
    fn templates_expand_to_running_instances() {
        let running: BTreeSet<String> = ["openvpn@work", "openvpn@home", "sshd", "openvpn"].map(String::from).into();
        let t = expand_tools(&["wg-quick-wg0".into(), "openvpn@".into()], &running);
        let names: Vec<&str> = t.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["openvpn@home", "openvpn@work", "wg-quick-wg0"], "a plain tool is listed even when stopped");
    }
}

/// The set the daemon carries: every tool `protecting_now` says protects.
#[test]
fn the_protecting_set() {
    let (vpn, quiet) = (UnitId::service("wg-quick-wg0"), UnitId::service("gym-syncd"));
    let v = sample();
    let set = v.protecting(&[vpn.clone(), quiet.clone()], NOW);
    assert!(set.contains(&vpn) && !set.contains(&quiet), "{set:?}");
    let all = FootprintView::default().protecting(&[vpn.clone(), quiet.clone()], NOW);
    assert_eq!(all.len(), 2, "nothing known: every tool counts");
}

/// §12d, the watch restarted (coordinator, Nov 2; the reviewer's #38 3c).
mod restart {
    use super::*;

    fn vpn() -> UnitId {
        UnitId::service("wg-quick-wg0")
    }

    /// The links something created (wg0 is a wireguard link).
    fn virt() -> std::collections::BTreeSet<String> {
        ["wg0".to_string()].into()
    }

    /// What the kernel holds: wg0, and a default route over it.
    fn standing() -> Vec<Change> {
        vec![
            change(Owner::Unattributed, ChangeKind::Interface, "wg0", Some("wg0"), false),
            change(Owner::Unattributed, ChangeKind::Route, "route 2 254 /0 oif 7 metric 0", Some("wg0"), true),
        ]
    }

    fn before() -> Tracker {
        let mut t = Tracker::default();
        t.apply(&change(unit(&vpn()), ChangeKind::Interface, "wg0", Some("wg0"), false));
        t.apply(&change(unit(&vpn()), ChangeKind::Route, "route 2 254 /0 oif 7 metric 0", Some("wg0"), true));
        t
    }

    #[test]
    fn a_restart_keeps_a_protecting_footprint() {
        let t = Tracker::attach(&before().claims(), &standing(), &virt());
        let v = t.view(ATTACHED, &[vpn()], NOW);
        assert!(v.units["wg-quick-wg0"].protecting, "{v:?}");
        assert!(v.unattributed.is_empty(), "everything standing is claimed: {v:?}");
    }

    /// With `.state` gone, the footprint files' `iface` lines still claim
    /// the interface, and the standing default route over it protects.
    #[test]
    fn a_restart_from_the_files_alone_keeps_it_too() {
        let files = before().view(ATTACHED, &[vpn()], NOW);
        let t = Tracker::attach(&Tracker::claims_from_files(&files), &standing(), &virt());
        let v = t.view(ATTACHED, &[vpn()], NOW);
        assert!(v.units["wg-quick-wg0"].protecting && v.unattributed.is_empty(), "{v:?}");
    }

    #[test]
    fn an_object_made_in_the_gap_is_unattributed_until_it_is_gone() {
        let mut now = standing();
        let gap = change(Owner::Unattributed, ChangeKind::Rule, "rule 2 100 51820", None, true);
        now.push(gap.clone());
        let mut t = Tracker::attach(&before().claims(), &now, &virt());
        let v = t.view(ATTACHED, &[vpn()], NOW);
        assert!(v.unattributed.iter().any(|r| r.starts_with("pre-attach") && r.contains("rule 2 100 51820")), "{v:?}");
        // Removed (by anyone): the marker clears.
        t.apply(&Change { removed: true, owner: unit(&UnitId::service("someone-else")), ..gap });
        assert!(t.view(ATTACHED, &[vpn()], NOW).unattributed.is_empty());
    }

    #[test]
    fn a_claim_whose_object_is_gone_is_dropped() {
        // wg0 and its route went away while nobody watched.
        let t = Tracker::attach(&before().claims(), &[], &virt());
        let v = t.view(ATTACHED, &[vpn()], NOW);
        assert!(!v.units["wg-quick-wg0"].protecting && v.unattributed.is_empty(), "{v:?}");
    }

    #[test]
    fn a_clean_boot_has_no_marker() {
        let t = Tracker::attach(&Claims::default(), &[], &virt());
        let v = t.view(ATTACHED, &[vpn()], NOW);
        assert!(v.unattributed.is_empty() && !v.units["wg-quick-wg0"].protecting, "{v:?}");
        // But steering found at boot with no claims (the /run files lost)
        // is unattributed.
        let t = Tracker::attach(&Claims::default(), &standing(), &virt());
        assert!(!t.view(ATTACHED, &[vpn()], NOW).unattributed.is_empty());
    }

    /// A route removed by another unit drops the claim of the unit that
    /// added it (removal is global).
    #[test]
    fn removal_is_global() {
        let mut t = before();
        t.apply(&Change {
            removed: true,
            ..change(
                unit(&UnitId::service("other")),
                ChangeKind::Route,
                "route 2 254 /0 oif 7 metric 0",
                Some("wg0"),
                true,
            )
        });
        assert!(!t.footprint(&vpn(), NOW).protecting);
    }

    /// The machine's own uplink: a default route over a physical NIC that no
    /// unit created is not pre-attach steering (it would hold every failure).
    #[test]
    fn the_uplinks_default_route_is_not_unattributed() {
        let uplink = vec![
            change(Owner::Unattributed, ChangeKind::Interface, "eth0", Some("eth0"), false),
            change(Owner::Unattributed, ChangeKind::Route, "route 2 254 /0 oif 7 metric 0", Some("eth0"), true),
        ];
        let t = Tracker::attach(&Claims::default(), &uplink, &virt());
        assert!(t.view(ATTACHED, &[vpn()], NOW).unattributed.is_empty());
    }

    /// The reviewer's (i): steering made in the gap over a tunnel nobody
    /// claims is unattributed, and clears when the tunnel is deleted (the
    /// kernel drops its routes without a message for each).
    #[test]
    fn deleting_a_gap_tunnel_clears_its_routes() {
        let gap = vec![
            change(Owner::Unattributed, ChangeKind::Interface, "wg0", Some("wg0"), false),
            change(Owner::Unattributed, ChangeKind::Route, "route 2 254 /0 oif 7 metric 0", Some("wg0"), true),
        ];
        let mut t = Tracker::attach(&Claims::default(), &gap, &virt());
        assert!(!t.view(ATTACHED, &[vpn()], NOW).unattributed.is_empty(), "made unwatched");
        t.apply(&Change {
            removed: true,
            ..change(Owner::Unattributed, ChangeKind::Interface, "wg0", Some("wg0"), false)
        });
        assert!(t.view(ATTACHED, &[vpn()], NOW).unattributed.is_empty(), "the tunnel and its route are gone");
        // And a unit's own route claims over its deleted tunnel go too.
        let mut b = before();
        b.apply(&Change { removed: true, ..change(unit(&vpn()), ChangeKind::Interface, "wg0", Some("wg0"), false) });
        assert!(!b.footprint(&vpn(), NOW).protecting);
    }

    #[test]
    fn claims_round_trip_as_json() {
        let c = before().claims();
        let back: Claims = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }
}

/// §12d: steering is "an interface it created that carries a default or
/// all-covering route". The same rule on both paths (coordinator, Nov 2):
/// NetworkManager's DHCP default route over wlan0, an interface no unit
/// created, does not make it protecting, watched or found at attach.
mod physical_nic {
    use super::*;

    fn nm() -> UnitId {
        UnitId::service("NetworkManager")
    }

    fn dhcp_default() -> Change {
        change(unit(&nm()), ChangeKind::Route, "route 2 254 /0 oif 3 metric 600", Some("wlan0"), true)
    }

    #[test]
    fn watched_a_default_route_over_a_physical_nic_is_not_protecting() {
        let mut t = Tracker::default();
        t.apply(&dhcp_default());
        let v = t.view(ATTACHED, &[nm()], NOW);
        assert!(!v.units["NetworkManager"].protecting && v.unattributed.is_empty(), "{v:?}");
        assert!(!v.protecting_now("NetworkManager", NOW), "its failure holds nothing");
        // Nor does one nobody can be charged with.
        let mut u = Tracker::default();
        u.apply(&Change { owner: Owner::Unattributed, ..dhcp_default() });
        assert!(u.view(ATTACHED, &[nm()], NOW).unattributed.is_empty());
        // Over a tunnel NM created, it does.
        let mut v = Tracker::default();
        v.apply(&change(unit(&nm()), ChangeKind::Interface, "tun0", Some("tun0"), false));
        v.apply(&change(unit(&nm()), ChangeKind::Route, "route 2 254 /0 oif 9 metric 50", Some("tun0"), true));
        assert!(v.footprint(&nm(), NOW).protecting);
        // And an unattributed one over a link created while watched fails closed.
        let mut w = Tracker::default();
        w.apply(&change(unit(&nm()), ChangeKind::Interface, "tun0", Some("tun0"), false));
        w.apply(&change(Owner::Unattributed, ChangeKind::Route, "route 2 254 /0 oif 9 metric 50", Some("tun0"), true));
        assert!(!w.view(ATTACHED, &[nm()], NOW).unattributed.is_empty());
    }

    #[test]
    fn at_attach_a_default_route_over_a_physical_nic_is_not_protecting() {
        // Claimed by NM before the restart, still standing: kept, but steers nothing.
        let mut before = Tracker::default();
        before.apply(&dhcp_default());
        let standing = vec![
            change(Owner::Unattributed, ChangeKind::Interface, "wlan0", Some("wlan0"), false),
            Change { owner: Owner::Unattributed, ..dhcp_default() },
        ];
        let physical = std::collections::BTreeSet::new();
        let t = Tracker::attach(&before.claims(), &standing, &physical);
        let v = t.view(ATTACHED, &[nm()], NOW);
        assert!(!v.units["NetworkManager"].protecting && v.unattributed.is_empty(), "{v:?}");
        // Unclaimed (the files lost): still not pre-attach.
        let t = Tracker::attach(&Claims::default(), &standing, &physical);
        assert!(t.view(ATTACHED, &[nm()], NOW).unattributed.is_empty());
    }
}

/// The BTF reader (trusted code in the loader): the offsets on the kernel
/// this runs on and on a synthetic kernel; refusal, never a panic or an
/// out-of-bounds answer, on malformed input.
mod btf {
    use crate::btf::{Btf, NetnsOffsets};

    /// A BTF blob, written by hand.
    struct Blob {
        types: Vec<u8>,
        strs: Vec<u8>,
        count: u32,
    }

    impl Blob {
        fn new() -> Blob {
            Blob { types: vec![], strs: vec![0], count: 0 }
        }
        fn name(&mut self, n: &str) -> u32 {
            if n.is_empty() {
                return 0;
            }
            let off = self.strs.len() as u32;
            self.strs.extend(n.as_bytes());
            self.strs.push(0);
            off
        }
        /// A type; returns its id. `members` are (name, type, byte offset).
        fn ty(&mut self, name: &str, kind: u32, size_or_type: u32, members: &[(&str, u32, u32)]) -> u32 {
            let n = self.name(name);
            let info = (kind << 24) | members.len() as u32;
            for v in [n, info, size_or_type] {
                self.types.extend(v.to_le_bytes());
            }
            if kind == 1 {
                self.types.extend(32u32.to_le_bytes()); // int encoding: 32 bits
            }
            for (mname, mty, off) in members {
                let mn = self.name(mname);
                for v in [mn, *mty, off * 8] {
                    self.types.extend(v.to_le_bytes());
                }
            }
            self.count += 1;
            self.count
        }
        fn bytes(&self) -> Vec<u8> {
            let mut b = vec![0x9f, 0xeb, 1, 0];
            for v in [24u32, 0, self.types.len() as u32, self.types.len() as u32, self.strs.len() as u32] {
                b.extend(v.to_le_bytes());
            }
            b.extend(&self.types);
            b.extend(&self.strs);
            b
        }
    }

    /// The shape of the netns path on 6.18, with `sk` inside an anonymous
    /// union as there.
    fn kernel() -> Vec<u8> {
        let mut b = Blob::new();
        let uint = b.ty("unsigned int", 1, 4, &[]);
        let ns_common = b.ty("ns_common", 4, 32, &[("inum", uint, 24)]);
        let net = b.ty("net", 4, 512, &[("ns", ns_common, 152)]);
        let net_ptr = b.ty("", 2, net, &[]);
        let anon = b.ty("", 4, 8, &[("net", net_ptr, 0)]);
        let possible = b.ty("possible_net_t", 8, anon, &[]);
        let sk_common = b.ty("sock_common", 4, 136, &[("skc_net", possible, 48)]);
        let sock = b.ty("sock", 4, 760, &[("__sk_common", sk_common, 0)]);
        let sock_ptr = b.ty("", 2, sock, &[]);
        let union = b.ty("", 5, 8, &[("sk", sock_ptr, 0), ("ip_defrag_offset", uint, 0)]);
        b.ty("sk_buff", 4, 232, &[("", union, 24)]);
        b.bytes()
    }

    #[test]
    fn the_running_kernels_netns_offsets_resolve() {
        let Ok(bytes) = std::fs::read("/sys/kernel/btf/vmlinux") else { return };
        let o = NetnsOffsets::from_btf(&Btf::parse(&bytes).unwrap()).unwrap();
        // Where these land depends on the kernel's config (this sandbox's
        // 6.18 gives 24, 48, 176), so only that they resolve, inside their
        // structs: the exact layout is pinned by the synthetic kernel below.
        assert!(o.skb_sk >= 16 && o.sk_net >= 16 && o.net_inum >= 16, "{o:?}");
        let c = crate::btf::CgroupOffsets::from_btf(&Btf::parse(&bytes).unwrap()).unwrap();
        assert!(c.task_cgroups > 0 && c.kn_name > 0, "{c:?}");
        let n = crate::btf::NetdevOffsets::from_btf(&Btf::parse(&bytes).unwrap()).unwrap();
        assert!(n.name > 0 && n.net > 0 && n.name != n.net, "{n:?}");
    }

    #[test]
    fn a_synthetic_kernels_netns_offsets_resolve() {
        let o = NetnsOffsets::from_btf(&Btf::parse(&kernel()).unwrap()).unwrap();
        assert_eq!(o, NetnsOffsets { skb_sk: 24, sk_net: 48, net_inum: 176 });
    }

    #[test]
    fn what_is_not_btf_is_refused() {
        assert!(Btf::parse(b"").is_err());
        assert!(Btf::parse(b"\x7fELF....................").is_err());
        let mut short = vec![0x9f, 0xeb, 1, 0, 24, 0, 0, 0];
        short.extend([0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(Btf::parse(&short).is_err(), "a section past the end");
    }

    /// A member outside its struct, and an anonymous member that contains
    /// itself, are refused (no out-of-bounds answer, no endless recursion).
    #[test]
    fn a_bad_layout_is_refused() {
        let mut b = Blob::new();
        let uint = b.ty("unsigned int", 1, 4, &[]);
        b.ty("ns_common", 4, 16, &[("inum", uint, 24)]); // past its 16 bytes
        assert!(Btf::parse(&b.bytes()).unwrap().offset("ns_common", &["inum"]).is_err());

        let mut b = Blob::new();
        // Type 1 is an anonymous struct whose only member is itself.
        b.ty("", 4, 8, &[("", 1, 0)]);
        b.ty("loop", 4, 8, &[("", 1, 0)]);
        assert!(Btf::parse(&b.bytes()).unwrap().offset("loop", &["x"]).is_err());
    }

    /// A kind past ENUM64 has data the reader cannot size: refused, not
    /// skipped (which would misread every type after it).
    #[test]
    fn an_unknown_kind_is_refused() {
        let mut b = Blob::new();
        b.ty("unsigned int", 1, 4, &[]);
        b.ty("future", 20, 0, &[]);
        let e = Btf::parse(&b.bytes()).err().unwrap();
        assert!(e.contains("unknown kind 20"), "{e}");
        let mut b = Blob::new();
        b.ty("", 0, 0, &[]); // kind 0 is not a type
        assert!(Btf::parse(&b.bytes()).is_err());
    }

    /// Mutated and truncated blobs: an answer or a refusal, never a panic.
    #[test]
    fn malformed_blobs_never_panic() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut blobs = vec![(kernel(), 4000)];
        if let Ok(real) = std::fs::read("/sys/kernel/btf/vmlinux") {
            blobs.push((real, 24));
        }
        for (base, rounds) in blobs {
            for _ in 0..rounds {
                let mut b = base.clone();
                match next() % 4 {
                    0 => b.truncate((next() as usize) % (b.len() + 1)),
                    1 => {
                        // A header field.
                        let at = 4 + 4 * (next() as usize % 5);
                        b[at..at + 4].copy_from_slice(&(next() as u32).to_le_bytes());
                    }
                    _ => {
                        for _ in 0..1 + next() % 8 {
                            let at = (next() as usize) % b.len();
                            b[at] = next() as u8;
                        }
                    }
                }
                if let Ok(btf) = Btf::parse(&b) {
                    let _ = NetnsOffsets::from_btf(&btf);
                    let _ = crate::btf::CgroupOffsets::from_btf(&btf);
                    let _ = crate::btf::NetdevOffsets::from_btf(&btf);
                    let _ = btf.offset("sk_buff", &["sk", "x", "y"]);
                }
            }
        }
    }
}

/// Namespaces (crate docs): only changes in netwatch's own netns, the
/// host's, count. The reviewer's case on #42: a container's own `wg0`
/// going away must not take the host VPN's claim with it.
mod namespaces {
    use crate::ebpf::{Event, HOOK_RTNETLINK, HOOK_SOCKOPT};
    use crate::parse::{Scope, scope, take};
    use crate::{Tracker, WatchState};
    use planarian_schema::UnitId;

    const HOST: u32 = 0xF000_0000;
    const CONTAINER: u32 = 0xF000_1234;
    const NOW: u64 = 100;

    fn attr(ty: u16, v: &[u8]) -> Vec<u8> {
        let mut a = ((4 + v.len()) as u16).to_ne_bytes().to_vec();
        a.extend(ty.to_ne_bytes());
        a.extend(v);
        while !a.len().is_multiple_of(4) {
            a.push(0);
        }
        a
    }

    fn msg(netns: u32, ty: u16, flags: u16, body: &[u8]) -> Event {
        let mut d = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
        d.extend(ty.to_ne_bytes());
        d.extend(flags.to_ne_bytes());
        d.extend([0u8; 8]);
        d.extend(body);
        Event { cgroup: 1, tgid: 2, hook: HOOK_RTNETLINK, len: d.len() as u32, netns, cgpath: None, data: d }
    }

    fn new_link(name: &str) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b.extend(attr(3, format!("{name}\0").as_bytes()));
        b
    }

    fn del_link(index: u32) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[4..8].copy_from_slice(&index.to_ne_bytes());
        b
    }

    fn default_route(oif: u32) -> Vec<u8> {
        let mut b = vec![2u8, 0, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
        b.extend(attr(4, &oif.to_ne_bytes()));
        b
    }

    /// Index 7 is `wg0` on the host; the container's `wg0` may share it.
    fn names(i: u32) -> Option<String> {
        (i == 7).then(|| "wg0".to_string())
    }

    fn vpn() -> UnitId {
        UnitId::service("wg-quick-wg0")
    }

    /// The host VPN made `wg0` and the default route through it.
    fn host_vpn() -> Tracker {
        let mut t = Tracker::default();
        take(&mut t, &msg(HOST, 16, 0x400 | 0x1, &new_link("wg0")), HOST, || Some(vpn()), &mut names);
        take(&mut t, &msg(HOST, 24, 0x400, &default_route(7)), HOST, || Some(vpn()), &mut names);
        assert!(t.view(WatchState::Attached { at: NOW }, &[vpn()], NOW).protecting_now("wg-quick-wg0", NOW));
        t
    }

    fn clean(t: &Tracker) -> bool {
        t.view(WatchState::Attached { at: NOW }, &[vpn()], NOW).unattributed.is_empty()
    }

    #[test]
    fn a_containers_wg0_going_leaves_the_host_vpn_protecting() {
        let mut t = host_vpn();
        // The container's `wg-quick down`: its wg0 (same index) and route go.
        take(&mut t, &msg(CONTAINER, 25, 0, &default_route(7)), HOST, || None, &mut names);
        take(&mut t, &msg(CONTAINER, 17, 0x1, &del_link(7)), HOST, || None, &mut names);
        let v = t.view(WatchState::Attached { at: NOW }, &[vpn()], NOW);
        assert_eq!(v.units["wg-quick-wg0"].ifaces, ["wg0".to_string()].into(), "the host claim stands");
        assert!(v.protecting_now("wg-quick-wg0", NOW));
        assert!(clean(&t));
        // The same removal on the host does take it.
        take(&mut t, &msg(HOST, 17, 0x1, &del_link(7)), HOST, || None, &mut names);
        assert!(t.view(WatchState::Attached { at: NOW }, &[vpn()], NOW).units["wg-quick-wg0"].ifaces.is_empty());
    }

    /// A container's own default route and firewall are not host steering:
    /// nothing is unattributed while it runs.
    #[test]
    fn a_containers_own_steering_holds_nothing() {
        let mut t = Tracker::default();
        take(&mut t, &msg(CONTAINER, 16, 0x400 | 0x1, &new_link("eth0")), HOST, || None, &mut names);
        take(&mut t, &msg(CONTAINER, 24, 0x400, &default_route(7)), HOST, || None, &mut names);
        let sockopt = Event {
            cgroup: 1,
            tgid: 2,
            hook: HOOK_SOCKOPT,
            len: 8,
            netns: CONTAINER,
            cgpath: None,
            data: vec![2, 0, 0, 0, 64, 0, 0, 0],
        };
        take(&mut t, &sockopt, HOST, || None, &mut names);
        assert!(clean(&t));
    }

    /// The probe could not read the netns: fail closed, and never apply it
    /// (so it cannot remove a host claim either).
    #[test]
    fn an_unknown_netns_fails_closed() {
        let mut t = host_vpn();
        take(&mut t, &msg(0, 17, 0x1, &del_link(7)), HOST, || None, &mut names);
        assert!(!clean(&t));
        let v = t.view(WatchState::Attached { at: NOW }, &[vpn()], NOW);
        assert_eq!(v.units["wg-quick-wg0"].ifaces, ["wg0".to_string()].into());
    }

    /// A link message elsewhere that may reach into the host (moved by
    /// netns pid or fd, or aimed at a netns id) is never dropped: charged
    /// to the mover's unit as unattributed, or to nobody if it is unknown.
    #[test]
    fn a_link_moved_from_elsewhere_is_unattributed() {
        for ty in [19u16, 28, 46] {
            let mut body = new_link("wg1");
            body.extend(attr(ty, &1u32.to_ne_bytes()));
            assert_eq!(scope(&msg(CONTAINER, 16, 0x1, &body), HOST), Scope::Reaches, "attr {ty}");
            assert_eq!(scope(&msg(CONTAINER, 19, 0x1, &body), HOST), Scope::Reaches, "RTM_SETLINK, attr {ty}");
        }
        let mut body = new_link("wg1");
        body.extend(attr(28, &3u32.to_ne_bytes()));
        let mover = UnitId::service("nspawn-mover");
        let mut t = Tracker::default();
        take(&mut t, &msg(CONTAINER, 19, 0x1, &body), HOST, || Some(mover.clone()), &mut names);
        let v = t.view(WatchState::Attached { at: NOW }, std::slice::from_ref(&mover), NOW);
        assert!(v.units["nspawn-mover"].unattributed && v.protecting_now("nspawn-mover", NOW), "the mover holds");
        let mut t = Tracker::default();
        take(&mut t, &msg(CONTAINER, 19, 0x1, &body), HOST, || None, &mut names);
        assert!(!clean(&t), "no mover known: unattributed for all");
        assert_eq!(scope(&msg(CONTAINER, 16, 0x1, &new_link("wg1")), HOST), Scope::Elsewhere);
        assert_eq!(scope(&msg(HOST, 16, 0x1, &new_link("wg1")), HOST), Scope::Host);
    }
}

/// Interfaces of every kind (coordinator, Nov 2): `register_netdevice`
/// sees a tun made by ioctl, which no netlink message announces; "virtual"
/// is read live from sysfs; and a unit routing over another unit's virtual
/// link protects as well.
mod interfaces {
    use crate::ebpf::{Event, HOOK_NETDEV, HOOK_RTNETLINK};
    use crate::parse::{Parsed, parse, take};
    use crate::{Owner, Tracker, WatchState};
    use planarian_schema::UnitId;
    use std::collections::BTreeSet;

    const HOST: u32 = 0xF000_0000;
    const NOW: u64 = 100;

    fn registered(name: &str, netns: u32) -> Event {
        let mut data = name.as_bytes().to_vec();
        data.resize(16, 0);
        Event { cgroup: 1, tgid: 2, hook: HOOK_NETDEV, len: 16, netns, cgpath: None, data }
    }

    fn attr(ty: u16, v: &[u8]) -> Vec<u8> {
        let mut a = ((4 + v.len()) as u16).to_ne_bytes().to_vec();
        a.extend(ty.to_ne_bytes());
        a.extend(v);
        a
    }

    /// RTM_NEWROUTE `dst/len` over `oif`.
    fn route(dst: [u8; 4], len: u8, oif: u32) -> Event {
        let mut body = vec![2u8, len, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
        if len > 0 {
            body.extend(attr(1, &dst));
        }
        body.extend(attr(4, &oif.to_ne_bytes()));
        let mut d = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
        d.extend(24u16.to_ne_bytes());
        d.extend(0x400u16.to_ne_bytes());
        d.extend([0u8; 8]);
        d.extend(body);
        Event { cgroup: 1, tgid: 2, hook: HOOK_RTNETLINK, len: d.len() as u32, netns: HOST, cgpath: None, data: d }
    }

    fn names(i: u32) -> Option<String> {
        match i {
            9 => Some("tun0".into()),
            2 => Some("eth0".into()),
            _ => None,
        }
    }

    fn by(u: &UnitId) -> impl FnOnce() -> Option<UnitId> + '_ {
        move || Some(u.clone())
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// Classic OpenVPN: tun0 by ioctl, then 0/1 and 128/1 over it.
    #[test]
    fn a_tun_made_by_ioctl_protects() {
        let vpn = UnitId::service("openvpn-work");
        let mut t = Tracker::default();
        take(&mut t, &registered("tun0", HOST), HOST, by(&vpn), &mut names);
        take(&mut t, &route([0, 0, 0, 0], 1, 9), HOST, by(&vpn), &mut names);
        take(&mut t, &route([128, 0, 0, 0], 1, 9), HOST, by(&vpn), &mut names);
        t.set_virtual(set(&["tun0", "lo"]));
        let v = t.view(WatchState::Attached { at: NOW }, std::slice::from_ref(&vpn), NOW);
        let f = &v.units["openvpn-work"];
        assert!(f.protecting, "{f:?}");
        assert_eq!(f.ifaces, set(&["tun0"]));
    }

    /// A persistent tun made by a setup unit, routed over by the VPN: both
    /// hold (the coordinator's narrow reading).
    #[test]
    fn a_route_over_another_units_tun_protects_both() {
        let (setup, vpn) = (UnitId::service("tun-setup"), UnitId::service("openvpn-work"));
        let mut t = Tracker::default();
        take(&mut t, &registered("tun0", HOST), HOST, by(&setup), &mut names);
        take(&mut t, &route([0, 0, 0, 0], 1, 9), HOST, by(&vpn), &mut names);
        t.set_virtual(set(&["tun0"]));
        let v = t.view(WatchState::Attached { at: NOW }, &[setup.clone(), vpn.clone()], NOW);
        assert!(v.units["tun-setup"].protecting, "the creator");
        assert!(v.units["openvpn-work"].protecting, "the router");
        assert_eq!(v.units["openvpn-work"].ifaces, set(&["tun0"]));
    }

    /// A physical NIC registered in a unit's context is not one it created,
    /// and NetworkManager's default route over it protects nobody.
    #[test]
    fn a_physical_nic_is_never_created_by_a_tool() {
        let (udev, nm) = (UnitId::service("systemd-udevd"), UnitId::service("NetworkManager"));
        let mut t = Tracker::default();
        take(&mut t, &registered("eth0", HOST), HOST, by(&udev), &mut names);
        take(&mut t, &route([0, 0, 0, 0], 0, 2), HOST, by(&nm), &mut names);
        t.set_virtual(set(&["lo"])); // eth0 resolves under its PCI device
        let v = t.view(WatchState::Attached { at: NOW }, &[udev.clone(), nm.clone()], NOW);
        assert!(!v.units["systemd-udevd"].protecting && !v.units["NetworkManager"].protecting, "{v:?}");
        assert!(v.unattributed.is_empty());
    }

    /// A link that is virtual by sysfs but was never seen made (moved in
    /// from another netns): a default route over it that nobody can be
    /// charged with fails closed, never exempt as a physical NIC.
    #[test]
    fn a_moved_in_link_is_not_a_physical_nic() {
        let mut t = Tracker::default();
        take(&mut t, &route([0, 0, 0, 0], 0, 9), HOST, || None, &mut names);
        t.set_virtual(set(&["tun0"]));
        let v = t.view(WatchState::Attached { at: NOW }, &[], NOW);
        assert!(!v.unattributed.is_empty(), "fail closed");
    }

    /// A container's registration is its own business; a nameless one is
    /// unreadable (fail closed).
    #[test]
    fn registrations_elsewhere_are_ignored_and_nameless_ones_unreadable() {
        let vpn = UnitId::service("openvpn-work");
        let mut t = Tracker::default();
        take(&mut t, &registered("tun0", 0xF000_1234), HOST, by(&vpn), &mut names);
        take(&mut t, &route([0, 0, 0, 0], 1, 9), HOST, by(&vpn), &mut names);
        t.set_virtual(set(&["tun0"]));
        // The registration elsewhere made no claim: the unit created nothing.
        let claims = t.claims();
        assert!(!claims.objects.iter().any(|o| o.1 == crate::ChangeKind::Interface), "{claims:?}");
        // Its own all-covering route over the host's virtual tun0 (made by
        // nobody it knows of) still protects (coordinator, Nov 3).
        let v = t.view(WatchState::Attached { at: NOW }, std::slice::from_ref(&vpn), NOW);
        assert!(v.units["openvpn-work"].protecting);
        let owner = Owner::Unit(vpn);
        assert!(matches!(parse(&registered("", HOST), &owner, &mut names), Parsed::Unreadable(_)));
    }

    #[test]
    fn virtual_links_are_read_from_sysfs() {
        let d = tempfile::tempdir().unwrap();
        let class = d.path().join("class/net");
        std::fs::create_dir_all(&class).unwrap();
        for (name, target) in [
            ("eth0", "../../devices/pci0000:00/0000:00:08.0/virtio7/net/eth0"),
            ("tun0", "../../devices/virtual/net/tun0"),
            ("lo", "../../devices/virtual/net/lo"),
        ] {
            std::os::unix::fs::symlink(target, class.join(name)).unwrap();
        }
        assert_eq!(crate::host::read_virtual_ifaces(&class), set(&["lo", "tun0"]));
        // This machine's own, read live.
        let live = crate::host::read_virtual_ifaces(std::path::Path::new("/sys/class/net"));
        if std::path::Path::new("/sys/class/net/lo").exists() {
            assert!(live.contains("lo"));
        }
    }
}

/// A restart never downgrades (crate docs, "On every attach"): a legacy
/// table claim, made by any `nf_setsockopt` while watched (fail closed,
/// even one the kernel refused), survives when the kernel cannot show
/// legacy tables at all; it goes when it can and none stand. vm-netwatch
/// (g) found this on a kernel without legacy xtables.
#[cfg(feature = "loader")]
mod legacy_restart {
    use crate::snapshot::legacy_tables;
    use crate::{Change, ChangeKind, Owner, Tracker, WatchState};
    use planarian_schema::UnitId;

    const NOW: u64 = 100;

    fn after_restart(names: Option<&str>) -> crate::FootprintView {
        let u = UnitId::service("nw-sockopt");
        let mut t = Tracker::default();
        t.apply(&Change {
            owner: Owner::Unit(u.clone()),
            kind: ChangeKind::Firewall,
            object: "legacy tables pf 2".into(),
            iface: None,
            steers: true,
            removed: false,
        });
        assert!(t.view(WatchState::Attached { at: NOW }, std::slice::from_ref(&u), NOW).units["nw-sockopt"].protecting);
        let standing: Vec<Change> = legacy_tables(names, 2).into_iter().collect();
        Tracker::attach(&t.claims(), &standing, &Default::default()).view(WatchState::Attached { at: NOW }, &[u], NOW)
    }

    #[test]
    fn a_claim_the_kernel_cannot_disprove_survives() {
        let v = after_restart(None); // no /proc/net/ip_tables_names
        assert!(v.units["nw-sockopt"].protecting, "a restart never downgrades");
        assert!(v.unattributed.is_empty(), "and nothing unclaimed is pre-attach");
    }

    #[test]
    fn a_claim_on_tables_gone_goes() {
        let v = after_restart(Some(""));
        assert!(!v.units["nw-sockopt"].protecting);
        let v = after_restart(Some("filter\n"));
        assert!(v.units["nw-sockopt"].protecting, "standing tables keep the claim");
    }

    /// Unclaimed legacy tables found at attach are pre-attach (fail
    /// closed); where none can exist, nothing is.
    #[test]
    fn unclaimed_tables_are_pre_attach_only_when_they_stand() {
        let at = |names| {
            let standing: Vec<Change> = legacy_tables(names, 2).into_iter().collect();
            Tracker::attach(&Default::default(), &standing, &Default::default())
                .view(WatchState::Attached { at: NOW }, &[], NOW)
                .unattributed
        };
        assert!(!at(Some("filter\n")).is_empty());
        assert!(at(None).is_empty());
        assert!(at(Some("")).is_empty());
    }
}

/// The coordinator's two rulings, Nov 3 (vm-netwatch (n3)).
mod rulings_nov3 {
    use crate::{Change, ChangeKind, Owner, Tracker, WatchState};
    use planarian_schema::UnitId;
    use std::collections::BTreeSet;

    const NOW: u64 = 100;

    fn route(u: &UnitId, iface: &str) -> Change {
        Change {
            owner: Owner::Unit(u.clone()),
            kind: ChangeKind::Route,
            object: format!("route 2 254 0.0.0.0/0 oif {iface} metric 4003"),
            iface: Some(iface.into()),
            steers: true,
            removed: false,
        }
    }

    /// (a) A footprint with an `unattributed` line says `protecting yes`.
    #[test]
    fn unattributed_reads_protecting_yes() {
        let u = UnitId::service("backdoor");
        let mut t = Tracker::default();
        t.lost(Some(&u));
        let f = t.footprint(&u, NOW);
        assert!(f.unattributed && f.protecting, "{f:?}");
        let text = crate::contract::render(&f);
        assert!(text.contains("protecting yes") && text.contains("unattributed"), "{text}");
    }

    /// (b) A default route the unit added over a virtual link it did not
    /// create: moved in from another netns (nothing registered it here).
    #[test]
    fn a_route_over_a_moved_in_link_protects_its_maker() {
        let u = UnitId::service("backdoor");
        let mut t = Tracker::default();
        t.apply(&route(&u, "nwmove0"));
        t.set_virtual(["nwmove0".to_string()].into());
        let v = t.view(WatchState::Attached { at: NOW }, std::slice::from_ref(&u), NOW);
        assert!(v.units["backdoor"].protecting);
        assert_eq!(v.units["backdoor"].ifaces, BTreeSet::from(["nwmove0".to_string()]));
    }

    /// ...but over a physical NIC it still steers nothing of its own.
    #[test]
    fn a_route_over_a_physical_nic_still_protects_nobody() {
        let nm = UnitId::service("NetworkManager");
        let mut t = Tracker::default();
        t.apply(&route(&nm, "wlan0"));
        t.set_virtual(["lo".to_string()].into());
        let v = t.view(WatchState::Attached { at: NOW }, std::slice::from_ref(&nm), NOW);
        assert!(!v.units["NetworkManager"].protecting);
    }
}

/// The hold's order on a failure (coordinator, Nov 3; vm-netsec: a VPN that
/// steered and died before netwatch's next write read as not protecting).
/// Each footprint names the unit's latest invocation, and says `ended` once
/// that invocation's cgroup is gone and the ring has been drained after; the
/// hold releases only on its own invocation, `ended`, and not protecting
/// (`hold_may_release`).
mod hold_order {
    use crate::contract::{parse_footprint, render};
    use crate::ebpf::{Event, HOOK_NETDEV, HOOK_RTNETLINK};
    use crate::parse::take;
    use crate::{FootprintView, Invocation, Tracker, WatchState, hold_may_release};
    use planarian_schema::UnitId;

    const HOST: u32 = 0xF000_0000;
    const OLD: &str = "0123456789abcdef0123456789abcdef";
    const NEW: &str = "fedcba9876543210fedcba9876543210";

    fn vpn() -> UnitId {
        UnitId::service("wireguard-gym")
    }

    fn view(text: &str, now: u64) -> FootprintView {
        let mut v = FootprintView { watch: WatchState::Attached { at: now }, ..Default::default() };
        if let Some(f) = parse_footprint(text) {
            v.units.insert("wireguard-gym".into(), f);
        }
        v
    }

    fn file(protecting: &str, invocation: Option<&str>, ended: bool) -> String {
        let mut s = format!("protecting {protecting}\nat 100\n");
        if let Some(i) = invocation {
            s.push_str(&format!("invocation {i}\n"));
        }
        if ended {
            s.push_str("ended\n");
        }
        s
    }

    /// The table: the invocation, `ended`, and protecting.
    #[test]
    fn the_hold_releases_only_when_everything_lines_up() {
        let ok = |f: &str, inv: Option<&str>| hold_may_release(&view(f, 100), &vpn(), inv, 100);
        assert!(ok(&file("no", Some(NEW), true), Some(NEW)), "its invocation, ended, not protecting");
        assert!(!ok(&file("no", Some(OLD), true), Some(NEW)), "stale: the last invocation's");
        assert!(!ok(&file("no", None, false), Some(NEW)), "no invocation in the file");
        assert!(!ok(&file("no", Some(NEW), true), None), "systemd gave none");
        assert!(!ok(&file("no", Some(NEW), true), Some(OLD)), "another invocation");
        assert!(!ok(&file("no", Some(NEW), false), Some(NEW)), "not ended: the ring not drained after");
        assert!(!ok(&file("unknown", None, false), Some(NEW)), "a new cgroup whose id is not readable yet");
        assert!(!ok(&file("yes", Some(NEW), true), Some(NEW)), "protecting");
        assert!(!ok("", Some(NEW)), "no file");
        // Stale: written too long ago to trust.
        assert!(!hold_may_release(&view(&file("no", Some(NEW), true), 100), &vpn(), Some(NEW), 100 + 3600));
    }

    /// The footprint the tracker gives for each invocation state.
    #[test]
    fn the_tracker_writes_the_invocation_state() {
        let mut t = Tracker::default();
        let f = |t: &Tracker| t.footprint(&vpn(), 100);
        assert!(f(&t).invocation.is_none() && !f(&t).ended && !f(&t).unknown);
        assert!(t.set_invocation(&vpn(), Invocation { id: None, ended: false }));
        assert!(f(&t).unknown && f(&t).protecting, "an unread id is protecting unknown");
        assert!(render(&f(&t)).starts_with("protecting unknown\n"));
        assert!(t.set_invocation(&vpn(), Invocation { id: Some(NEW.into()), ended: false }));
        assert!(!t.set_invocation(&vpn(), Invocation { id: Some(NEW.into()), ended: false }), "unchanged");
        assert_eq!(f(&t).invocation.as_deref(), Some(NEW));
        assert!(!f(&t).ended && !f(&t).unknown && !f(&t).protecting);
        assert!(t.set_invocation(&vpn(), Invocation { id: Some(NEW.into()), ended: true }));
        assert!(f(&t).ended);
        // A loss in the drain that ended it: unattributed, so it holds.
        t.lost(Some(&vpn()));
        let text = render(&f(&t));
        assert!(!hold_may_release(&view(&text, 100), &vpn(), Some(NEW), 100), "{text}");
    }

    /// The formats: `invocation` is 32 lowercase hex, `ended` and
    /// `protecting unknown` bare, or the file is not trusted.
    #[test]
    fn the_formats_parse_strictly() {
        let f = parse_footprint(&file("no", Some(NEW), true)).unwrap();
        assert_eq!(f.invocation.as_deref(), Some(NEW));
        assert!(f.ended && !f.unknown && !f.protecting);
        assert_eq!(parse_footprint(&render(&f)), Some(f), "round trip");
        let u = parse_footprint("protecting unknown\nat 1\n").unwrap();
        assert!(u.unknown && u.protecting);
        assert_eq!(parse_footprint(&render(&u)), Some(u), "round trip");
        for bad in ["FEDCBA9876543210FEDCBA9876543210", "fedcba98", "fedcba9876543210fedcba987654321g"] {
            assert_eq!(parse_footprint(&format!("protecting no\nat 1\ninvocation {bad}\n")), None, "{bad}");
        }
        for bad in ["ended yes", "invocation", "protecting maybe"] {
            assert_eq!(parse_footprint(&format!("protecting no\nat 1\n{bad}\n")), None, "{bad}");
        }
        // The xattr's value, as systemd writes it (raw bytes or hex).
        #[cfg(feature = "loader")]
        {
            use crate::cgroups::invocation_hex;
            assert_eq!(invocation_hex(&[0xfe; 16]).as_deref(), Some("fefefefefefefefefefefefefefefefe"));
            assert_eq!(invocation_hex(NEW.to_uppercase().as_bytes()).as_deref(), Some(NEW));
            assert_eq!(invocation_hex(b"short"), None);
        }
    }

    fn registered(name: &str) -> Event {
        let mut data = name.as_bytes().to_vec();
        data.resize(16, 0);
        Event { cgroup: 1, tgid: 2, hook: HOOK_NETDEV, len: 16, netns: HOST, cgpath: None, data }
    }

    fn route(dst: u8, len: u8) -> Event {
        let a = |ty: u16, v: &[u8]| {
            let mut x = ((4 + v.len()) as u16).to_ne_bytes().to_vec();
            x.extend(ty.to_ne_bytes());
            x.extend(v);
            x
        };
        let mut body = vec![2u8, len, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
        if len > 0 {
            body.extend(a(1, &[dst, 0, 0, 0]));
        }
        body.extend(a(4, &9u32.to_ne_bytes()));
        let mut d = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
        d.extend(24u16.to_ne_bytes());
        d.extend(0x400u16.to_ne_bytes());
        d.extend([0u8; 8]);
        d.extend(body);
        Event { cgroup: 1, tgid: 2, hook: HOOK_RTNETLINK, len: d.len() as u32, netns: HOST, cgpath: None, data: d }
    }

    fn names(i: u32) -> Option<String> {
        (i == 9).then(|| "wg0".into())
    }

    /// What the property runs: netwatch's order, or one of its mutants.
    #[derive(Clone, Copy, PartialEq)]
    enum Order {
        /// Observe removals, drain the ring, then `ended` (the loader's).
        Netwatch,
        /// Release on `protecting no` alone (the rule before Nov 3).
        NotProtecting,
        /// Drain the ring, then observe removals: `ended` before the events
        /// submitted between the two are applied.
        RingFirst,
    }

    /// The property (rule 23), over `Order`: random events, a random death,
    /// the cgroup removed at some instant after, random passes of the loop
    /// (a third of rounds with the last changes, death and removal inside
    /// one pass's observe-to-ring gap), ring losses in a quarter of rounds
    /// (charged as the loader does). The hold polls every 50 ms from the
    /// death until 3 s after the removal, and may read any version of the
    /// files written meanwhile (its phase is arbitrary). Returns the rounds
    /// where a unit that steered before it died was released, or one that
    /// did not was held though a loss-free pass ended it in time.
    fn property(order: Order) -> Vec<u32> {
        let mut failed = Vec::new();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n.max(1)
        };
        for round in 0..3000 {
            // Times in µs. The cgroup is made at `born`, its events follow, its last process exits at
            // `death`, and its cgroup is removed at `removed`.
            let born = 1_000_000 + rnd(2_000_000);
            let mut t = born;
            let steers = rnd(2) == 0;
            // A third of rounds are tight: the tool's last changes, its death
            // and its cgroup's removal all fall inside one pass, between
            // where removals are observed and where the ring is read (the
            // ordering bug that matters most; coordinator, Nov 3).
            let tight = rnd(3) == 0;
            // A tool that steers and dies at once (vm-netsec), or slowly.
            let fast = tight || rnd(2) == 0;
            let gap = if fast { 3_000 } else { 400_000 };
            let mut events: Vec<(u64, Event)> = Vec::new();
            t += 1 + rnd(gap);
            events.push((t, registered("wg0")));
            for _ in 0..rnd(4) {
                t += 1 + rnd(gap);
                events.push((t, route(10, 24))); // steers nothing
            }
            if steers {
                for dst in [0u8, 128] {
                    t += 1 + rnd(gap);
                    events.push((t, route(dst, 1)));
                }
            }
            // systemd sets the InvocationID before the unit's first process
            // starts; until netwatch reads it, `protecting unknown`.
            let readable = born + rnd(events[0].0 - born);
            let (death, removed, forced) = if tight {
                // The pass starts just before the first steering change (or
                // the last change) and ends after the removal.
                let first = events.len() - if steers { 2 } else { 1 };
                let start = events[first].0 - 1 - rnd(500);
                let e = 4_000 + rnd(16_000);
                let death = t + 1 + rnd(start + e - t - 1);
                let removed = death + rnd(start + e - death + 1);
                (death, removed, Some((start, e)))
            } else {
                let death = t + 1 + rnd(if fast { 3_000 } else { 300_000 });
                let soon = rnd(2) == 0;
                (death, death + rnd(if soon { 2_000 } else { 200_000 }), None)
            };
            let deadline = removed + 3_000_000;
            // A pass at `d`: removals observed at one instant, the ring read
            // at another `e` later (netwatch: observe first), the files
            // written at the end. Passes come at least every 50 ms when
            // idle, jittered; some late (a busy machine).
            let mut passes = Vec::new();
            let mut forced = forced;
            // A quarter of rounds lose events in some passes of the unit's
            // life (a loss holds every unit until reboot, so not more).
            let lossy = rnd(4) == 0;
            let mut d = born.saturating_sub(rnd(5_000_000));
            while d < deadline {
                let late = rnd(10) == 0;
                let step = 1 + rnd(if late { 1_500_000 } else { 60_000 });
                let e = rnd(20_000);
                // The ring overflows in this pass, losing what it reads.
                let lost = lossy && d + step > born && rnd(8) == 0;
                if let Some((fd, fe)) = forced
                    && d + step + e >= fd
                {
                    passes.push((fd, fe, false));
                    d = fd + fe;
                    forced = None;
                    continue;
                }
                d += step;
                passes.push((d, e, lost));
            }
            // Before: the last invocation's footprint, ended, `protecting no`.
            let mut files = view(&file("no", Some(OLD), true), 0);
            let mut written = 0u64;
            let mut tracker = Tracker::default();
            tracker.set_virtual(["wg0".to_string()].into());
            tracker.set_invocation(&vpn(), Invocation { id: Some(OLD.into()), ended: true });
            let mut inv = Invocation { id: Some(OLD.into()), ended: true };
            let mut seen_born = false;
            let mut removing = false;
            let mut next = 0;
            let mut released = false;
            let mut poll = death;
            let release = |v: &FootprintView, now: u64| match order {
                Order::NotProtecting => !v.protecting_now("wireguard-gym", now),
                _ => hold_may_release(v, &vpn(), Some(NEW), now),
            };
            let mut in_time = false;
            for &(d, e, lost) in &passes {
                let (observe, ring) = if order == Order::RingFirst { (d + e, d) } else { (d, d + e) };
                let end = d + e;
                // The hold polls what was written before each instant.
                while poll < end && poll <= deadline {
                    if poll >= written && release(&files, poll / 1_000_000) {
                        released = true;
                    }
                    poll += 50_000;
                }
                if poll > deadline {
                    break;
                }
                // The cgroups: made (an unread id first), then removed.
                if !seen_born && observe > born {
                    seen_born = true;
                    inv = Invocation { id: None, ended: false };
                }
                if seen_born && inv.id.is_none() && !inv.ended && observe > readable {
                    inv.id = Some(NEW.into());
                }
                if seen_born && !inv.ended && observe >= removed {
                    removing = true;
                }
                tracker.set_invocation(&vpn(), inv.clone());
                // The ring: every event submitted before it is read.
                while next < events.len() && events[next].0 < ring {
                    if !lost {
                        take(&mut tracker, &events[next].1, HOST, || Some(vpn()), &mut names);
                    }
                    next += 1;
                }
                if lost {
                    tracker.lost(None);
                }
                if removing {
                    removing = false;
                    inv.ended = true;
                    // (Today a loss also holds every unit until reboot, via
                    // `.unattributed`; this charge does not rely on that.)
                    if lost {
                        tracker.lost(Some(&vpn()));
                    }
                }
                tracker.set_invocation(&vpn(), inv.clone());
                files = written_files(&tracker, end / 1_000_000);
                written = end;
                // A hold polls at any phase: every version of the files
                // written while it waits is one it may read.
                if (death..=deadline).contains(&end) && release(&files, end / 1_000_000) {
                    released = true;
                }
                in_time |= inv.ended && !lost && end <= deadline;
            }
            let bad = if steers { released } else { in_time && !released && files.unattributed.is_empty() };
            if bad {
                failed.push(round);
            }
        }
        failed
    }

    /// What the hold reads after a write: the unit's file through its text
    /// form, and `.unattributed` (a loss nothing could place holds every
    /// unit until reboot).
    fn written_files(t: &Tracker, at: u64) -> FootprintView {
        let mut v = t.view(WatchState::Attached { at }, &[vpn()], at);
        for f in v.units.values_mut() {
            *f = parse_footprint(&render(f)).expect("netwatch's own file parses");
        }
        v
    }

    #[test]
    fn a_unit_that_steered_before_it_died_is_never_released() {
        assert_eq!(property(Order::Netwatch), Vec::<u32>::new());
    }

    /// The property is not vacuous: each mutant of the order fails it.
    #[test]
    fn the_property_catches_each_mutant() {
        for m in [Order::NotProtecting, Order::RingFirst] {
            let failed = property(m);
            eprintln!("mutant {} fails {} rounds, first {:?}", m as u8, failed.len(), failed.first());
            assert!(failed.first().is_some_and(|r| *r < 50), "mutant {} caught late or never", m as u8);
        }
    }
}
