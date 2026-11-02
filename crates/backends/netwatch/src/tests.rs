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
    let mut stale = v.clone();
    stale.units.get_mut("gym-syncd").unwrap().at = NOW - FRESH_SECS - 1;
    assert!(stale.protecting_now("gym-syncd", NOW), "stale footprint, fresh watch");
    let failed = t.view(WatchState::AttachFailed { at: NOW }, std::slice::from_ref(&syncd), NOW);
    assert!(failed.protecting_now("gym-syncd", NOW), "the watch failed to attach");
    assert!(FootprintView::default().protecting_now("gym-syncd", NOW), "nothing known");
    assert!(v.protecting_now("not-a-tool", NOW), "no footprint");

    let mut u = Tracker::default();
    u.apply(&change(Owner::Unattributed, ChangeKind::Route, "0.0.0.0/0", None, true));
    let v = u.view(ATTACHED, std::slice::from_ref(&syncd), NOW);
    assert!(v.unattributed && v.protecting_now("gym-syncd", NOW), "an unattributed steering change stands");
    u.apply(&Change { removed: true, ..change(Owner::Unattributed, ChangeKind::Route, "0.0.0.0/0", None, true) });
    assert!(!u.view(ATTACHED, std::slice::from_ref(&syncd), NOW).unattributed, "and it is gone");

    let mut l = Tracker::default();
    l.lost(Some(&syncd));
    assert!(l.view(ATTACHED, std::slice::from_ref(&syncd), NOW).protecting_now("gym-syncd", NOW));
    let mut g = Tracker::default();
    g.lost(None);
    assert!(g.view(ATTACHED, std::slice::from_ref(&syncd), NOW).unattributed, "an unplaced loss");
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
        format!("at {NOW}\nprotecting yes\niface wg0\nendpoint udp 192.0.2.7 51820\nendpoint udp 2001:db8::7 51820\n")
    );
    // A unit that leaves the view loses its file; the marker comes and goes.
    let mut fewer = v.clone();
    fewer.units.remove("gym-syncd");
    fewer.unattributed = true;
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
    std::fs::write(d.path().join("gym-syncd"), "at 1000\nprotecting maybe\n").unwrap();
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
