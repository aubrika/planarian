//! §12d: `UnitBackend::protecting` on the fake reads the scripted footprints
//! as the Linux side reads the files: fail closed for every unknown.

use planarian_backend_netwatch::{Change, ChangeKind, Owner};
use planarian_fake::{MemStore, gym_world};
use planarian_schema::{UnitBackend, UnitId};

fn change(owner: Owner, kind: ChangeKind, object: &str, iface: Option<&str>, steers: bool) -> Change {
    Change { owner, kind, object: object.into(), iface: iface.map(Into::into), steers, removed: false }
}

#[test]
fn the_fake_reports_who_is_protecting() {
    let (netd, syncd) = (UnitId::service("gym-netd"), UnitId::service("gym-syncd"));
    let tools = [netd.clone(), syncd.clone()];
    let f = gym_world(MemStore::new(1 << 20));
    {
        let mut w = f.w();
        w.netwatch.apply(&change(Owner::Unit(netd.clone()), ChangeKind::Interface, "gnet0", Some("gnet0"), false));
        w.netwatch.apply(&change(Owner::Unit(netd.clone()), ChangeKind::Route, "default gnet0", Some("gnet0"), true));
    }
    let set = f.protecting(&tools).unwrap();
    assert!(set.contains(&netd) && !set.contains(&syncd), "{set:?}");
    // A stale footprint, and then a failed watch: fail closed.
    f.w().netwatch_stale.insert(syncd.clone());
    assert!(f.protecting(&tools).unwrap().contains(&syncd), "stale");
    f.w().netwatch_stale.clear();
    f.w().netwatch_failed = Some("attach failed".into());
    assert_eq!(f.protecting(&tools).unwrap().len(), 2, "no watch: every tool");
}
