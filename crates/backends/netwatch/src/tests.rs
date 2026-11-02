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
            let want = if func.starts_with("nfnetlink_") { Kind::KProbe } else { Kind::FEntry };
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
