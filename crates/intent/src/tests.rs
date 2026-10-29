use super::*;
use planarian_schema::fixtures::*;

fn index() -> Index {
    let mut nm = service("NetworkManager");
    nm.synonyms = vec!["wifi".into(), "wi-fi".into(), "network".into(), "internet".into()];
    let mut web = service("gym-web");
    web.synonyms = vec!["web server".into()];
    let mut backup = service("restic-backup");
    backup.synonyms = vec!["backup".into(), "backups".into()];
    let mut pw = service("service@1000:pipewire");
    pw.synonyms = vec!["sound".into(), "audio".into()];
    Index::new(
        &defs([nm, web, backup, pw]),
        vec![
            CatalogEntry { id: ChangeId("keyboard-layout".into()), description: "Set the keyboard layout".into() },
            CatalogEntry { id: ChangeId("font-scale".into()), description: "Set the font scale for text".into() },
        ],
        vec![RuntimeOption {
            path: "font.scale".into(),
            keywords: vec!["text".into(), "font".into(), "fonts".into(), "letters".into()],
            current: Some(Value::Str("1".into())),
            step_milli: 250,
            min_milli: 500,
            max_milli: 3000,
        }],
    )
}

fn propose(phrase: &str) -> Transition {
    match interpret(phrase, &index(), Timestamp(1_000_000)) {
        Interpretation::Propose(m) => m.transition,
        other => panic!("{phrase:?}: {other:?}"),
    }
}

#[test]
fn spec_examples() {
    assert_eq!(propose("reconnect wifi"), Transition::RestartUnit(UnitId::service("NetworkManager")));
    assert_eq!(propose("Restart the web server!"), Transition::RestartUnit(UnitId::service("gym-web")));
    assert_eq!(
        propose("make text bigger"),
        Transition::SetRuntimeOption { path: "font.scale".into(), value: Value::Str("1.25".into()) }
    );
    assert_eq!(interpret("make it faster", &index(), Timestamp(0)), Interpretation::Unmatched);
}

#[test]
fn stopping_is_always_stop_and_suppress() {
    // The spec's own example: a suppression, so Planarian doesn't fight the user.
    match propose("stop the backup service while I work on it") {
        Transition::StopAndSuppress { unit, until: Until::Explicit, .. } => {
            assert_eq!(unit, UnitId::service("restic-backup"))
        }
        t => panic!("unexpected {t:?}"),
    }
}

#[test]
fn stopping_forms() {
    let backup = UnitId::service("restic-backup");
    match propose("stop backups until I say") {
        Transition::StopAndSuppress { unit, until: Until::Explicit, .. } => assert_eq!(unit, backup),
        t => panic!("{t:?}"),
    }
    match propose("pause backup for 20 minutes") {
        Transition::StopAndSuppress { unit, until: Until::At(t), .. } => {
            assert_eq!(unit, backup);
            assert_eq!(t, Timestamp(1_000_000 + 20 * 60_000));
        }
        t => panic!("{t:?}"),
    }
    match propose("stop gym-web until next boot") {
        Transition::StopAndSuppress { until: Until::NextBoot, .. } => {}
        t => panic!("{t:?}"),
    }
    assert_eq!(propose("start gym-web again"), Transition::LiftOverride(UnitId::service("gym-web")));
    assert_eq!(propose("done with backups"), Transition::LiftOverride(backup.clone()));
    for phrase in ["stop gym-web", "turn sound off", "stop backups for 2 hours"] {
        assert!(matches!(propose(phrase), Transition::StopAndSuppress { .. }), "{phrase}");
    }
}

#[test]
fn fuzzy_catalog_requests_are_confirmed_not_proposed() {
    match interpret("change keyboard layout", &index(), Timestamp(0)) {
        Interpretation::Confirm(ms) => assert_eq!(
            ms[0].transition,
            Transition::ApplyChange { change: ChangeId("keyboard-layout".into()), args: Default::default() }
        ),
        other => panic!("{other:?}"),
    }
}
