//! Property tests: `DerivedFacts` journaled by earlier builds still decode
//! (§12c: a journal replays across an upgrade). Catch-up coverage for bugs
//! fixed during development (`docs/regression-ledger.md`):
//!
//! - #37: `removes` was changed from `Vec<UnitId>` (journaled since 4bb9c99)
//!   to `Vec<(UnitId, Sensitivities)>`, so a `Prepared` record main had
//!   written no longer decoded. The fix kept main's form and added the
//!   parallel `removes_each`.
//! - #21 (C10): `disruption` became a set; a record holding the single value
//!   written before it must read back as the set holding that value.
//!
//! The old forms are written here as JSON text, the way those builds wrote
//! them, not by serializing today's types. `PROPTEST_CASES` goes deeper.

use planarian_schema::*;
use proptest::prelude::*;
use proptest::test_runner::{Config, FailurePersistence};
use serde_json::{Value, json};

fn config() -> Config {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(256);
    Config { cases, failure_persistence: None::<Box<dyn FailurePersistence>>, ..Config::default() }
}

/// A unit id and the text an earlier build journaled for it.
fn unit() -> impl Strategy<Value = (UnitId, String)> {
    let kind = prop_oneof![Just("service"), Just("device"), Just("target")];
    let scope = prop_oneof![Just(None), (1000..1003u32).prop_map(Some)];
    (kind, "[a-z][a-z0-9-]{0,7}", scope).prop_map(|(kind, name, uid)| {
        let text = match uid {
            None => format!("{kind}:{name}"),
            Some(uid) => format!("{kind}@{uid}:{name}"),
        };
        (text.parse().expect("a well-formed unit id"), text)
    })
}

fn disruption() -> impl Strategy<Value = (Disruption, &'static str)> {
    prop_oneof![
        Just((Disruption::None, "None")),
        Just((Disruption::Brief, "Brief")),
        Just((Disruption::SessionLoss, "SessionLoss")),
        Just((Disruption::DataInterruption, "DataInterruption")),
        Just((Disruption::ConnectivityLoss, "ConnectivityLoss")),
    ]
}

fn sensitivities() -> impl Strategy<Value = Sensitivities> {
    any::<[bool; 5]>().prop_map(|[routine, security, user_data, external, core]| Sensitivities {
        routine,
        security,
        user_data,
        external,
        core,
    })
}

/// Today's facts, apart from the fields under test.
fn base(caller_uid: u32, flags: [bool; 6], removes_sensitivity: Sensitivities) -> DerivedFacts {
    DerivedFacts {
        affected_units: vec![UnitId::service("gym-web")],
        sensitivity: Sensitivities::default(),
        disruption: Disruptions::of(Disruption::Brief),
        recovery: Recovery::Revertible,
        touches_manifest: flags[0],
        touches_canonical_probe: flags[1],
        changes_desired: flags[2],
        touches_core: flags[3],
        below_security_floor: flags[4],
        other_sessions_affected: flags[5],
        affected_sessions: Vec::new(),
        restores_unattributed_stop: false,
        restarts_failed_unit: false,
        removes_sensitivity,
        removes: Vec::new(),
        removes_each: Vec::new(),
        restarts_held_unit: false,
        caller: Actor::user(caller_uid),
        config_diff: None,
    }
}

proptest! {
    #![proptest_config(config())]

    /// #37: facts journaled in main's form since 4bb9c99 (`removes` a list of
    /// unit ids, no `removes_each`) decode, with `removes` as written and
    /// `removes_each` empty, whatever the units.
    #[test]
    fn removes_in_mains_form_decodes(
        removed in proptest::collection::vec(unit(), 0..5),
        uid in 1000..1003u32,
        flags in any::<[bool; 6]>(),
        rs in sensitivities(),
    ) {
        let today = base(uid, flags, rs);
        let mut v = serde_json::to_value(&today).unwrap();
        let m = v.as_object_mut().unwrap();
        m.insert("removes".into(), Value::Array(removed.iter().map(|(_, t)| json!(t)).collect()));
        m.remove("removes_each");
        let mut back: DerivedFacts = match serde_json::from_value(v) {
            Ok(f) => f,
            Err(e) => return Err(TestCaseError::fail(format!("main's form does not decode: {e}"))),
        };
        // Compared as text, so the test compiles whatever `removes` holds.
        let texts: Vec<&str> = removed.iter().map(|(_, t)| t.as_str()).collect();
        prop_assert_eq!(serde_json::to_value(&back.removes).unwrap(), json!(texts));
        back.removes = Default::default();
        prop_assert_eq!(back, today);
    }

    /// #21 (C10): facts journaled before the disruption set (one value, and
    /// none of the fields added since) decode as the set holding that value.
    #[test]
    fn a_single_disruption_decodes_as_its_set(
        (d, text) in disruption(),
        uid in 1000..1003u32,
        flags in any::<[bool; 6]>(),
    ) {
        let today = base(uid, flags, Sensitivities::default());
        let mut v = serde_json::to_value(&today).unwrap();
        let m = v.as_object_mut().unwrap();
        m.insert("disruption".into(), json!(text));
        for later in ["removes", "removes_each", "removes_sensitivity", "restarts_held_unit", "restarts_failed_unit"] {
            m.remove(later);
        }
        let back: DerivedFacts = match serde_json::from_value(v) {
            Ok(f) => f,
            Err(e) => return Err(TestCaseError::fail(format!("a single disruption does not decode: {e}"))),
        };
        prop_assert_eq!(&back.disruption, &Disruptions::of(d));
        let mut expect = today;
        expect.disruption = Disruptions::of(d);
        prop_assert_eq!(back, expect);
    }
}
