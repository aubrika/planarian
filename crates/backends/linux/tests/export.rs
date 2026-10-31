//! The JSON the NixOS module exports (captured from `checks.module-eval`)
//! parses into the schema the daemon uses.

use planarian_backend_linux::nixos::Export;
use planarian_schema::*;

#[test]
fn module_export_parses() {
    let text = include_str!("export-sample.json");
    let e: Export = serde_json::from_str(text).expect("module export parses");
    let eval = e.into_eval(Hash::ZERO);
    let app = &eval.units[&UnitId::service("gym-app")];
    assert!(app.edges.iter().any(|x| x.to == UnitId::service("gym-db") && x.kind == EdgeKind::Requires));
    assert_eq!(app.systemd_restart.as_ref().unwrap().restart_sec, Millis::secs(5));
    assert!(app.probes.iter().all(|p| p.check_contract().is_ok()));
    assert!(eval.units.contains_key(&UnitId::service("sshd")));
    assert!(eval.units.contains_key(&UnitId::target("graphical-session")));
    assert_eq!(
        eval.units[&UnitId::target("graphical-session")].desired.when,
        Condition::SessionEstablished { uid: None, seated: false }
    );
    assert!(eval.user_units.iter().any(|u| u.id.name == "pipewire"));
    assert_eq!(eval.core_units.len(), 2);
}
