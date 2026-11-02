//! §16 *Approvals show the change* (owner decision, Nov 2): the
//! configuration a generation transition that asks would apply. The core
//! builds it from the derived facts, which come from the evaluated
//! generations (§11), never from the proposal. `planarian approve`, the
//! console and the notice show it; `approve --json` and IPC
//! `Pending.diff` carry the same data. A diff that differs when the facts
//! are re-derived at approval changes the token's `bound_to` (the binding
//! hashes the facts), so the approval does not apply and the change asks
//! again.

use planarian_ipc::{ApprovalDiff, OptionChange, RemovedUnit, sensitivity_kinds};
use planarian_policy::Tables;
use planarian_schema::*;

/// Said when the evaluated generations could not be read, so the options
/// shown are the requested override settings only.
pub const UNAVAILABLE: &str = "evaluated options unavailable; showing the requested settings";

/// Said when the facts carry no sensitivity per removed unit (a record
/// journaled before `removes_each`), so each shows the change's union.
pub const EACH_UNAVAILABLE: &str = "each removed unit's own sensitivity unavailable; showing the change's";

/// The removed units with their sensitivities: `removes_each[i]` for
/// `removes[i]` when the two are the same length, otherwise the union
/// `removes_sensitivity` for each, and `false` (the display says so).
pub fn removed(f: &DerivedFacts) -> (Vec<(UnitId, Sensitivities)>, bool) {
    if f.removes_each.len() == f.removes.len() {
        (f.removes.iter().cloned().zip(f.removes_each.iter().copied()).collect(), true)
    } else {
        (f.removes.iter().map(|u| (u.clone(), f.removes_sensitivity)).collect(), false)
    }
}

/// Shown first: what a person most needs to see before approving.
fn first(s: &Sensitivities) -> bool {
    s.contains(Sensitivity::Security) || s.contains(Sensitivity::External)
}

/// The diff a generation transition would apply; empty for any other.
/// `config_diff` and `removed` (the units it would remove or stop, from
/// [`removed`]) come from the derived facts.
pub fn diff(
    t: &Transition,
    config_diff: Option<&ConfigDiff>,
    evaluated: bool,
    removed: &[(UnitId, Sensitivities)],
    each_known: bool,
    tables: &Tables,
) -> ApprovalDiff {
    if !t.changes_generation() {
        return ApprovalDiff::default();
    }
    let mut options: Vec<OptionChange> = config_diff
        .into_iter()
        .flat_map(|d| d.options.entries.iter())
        .map(|(path, (old, new))| {
            let sensitivity = tables.option_sensitivity(path);
            OptionChange {
                path: path.clone(),
                old: old.clone(),
                new: new.clone(),
                kinds: sensitivity_kinds(&sensitivity),
                sensitivity,
            }
        })
        .collect();
    options.sort_by(|a, b| (!first(&a.sensitivity), &a.path).cmp(&(!first(&b.sensitivity), &b.path)));
    // Each removed unit's sensitivity as derive computed it, the lookup the
    // decision used (§16: shown as decided).
    let mut removes: Vec<RemovedUnit> = removed
        .iter()
        .map(|(u, sensitivity)| RemovedUnit {
            unit: u.clone(),
            kinds: sensitivity_kinds(sensitivity),
            sensitivity: *sensitivity,
        })
        .collect();
    removes.sort_by(|a, b| (!first(&a.sensitivity), &a.unit).cmp(&(!first(&b.sensitivity), &b.unit)));
    // Never present the smaller list as the whole change.
    let notes: Vec<&str> =
        [(!evaluated).then_some(UNAVAILABLE), (!each_known && !removes.is_empty()).then_some(EACH_UNAVAILABLE)]
            .into_iter()
            .flatten()
            .collect();
    let note = (!notes.is_empty()).then(|| notes.join("; "));
    ApprovalDiff { options, removes, note }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables() -> Tables {
        Tables {
            option_sensitivity: vec![
                ("services.openssh".into(), Sensitivities::of(&[Sensitivity::Security])),
                ("networking.wireguard".into(), Sensitivities::of(&[Sensitivity::External])),
            ],
            ..Default::default()
        }
    }

    fn facts(opts: &[(&str, Option<Value>, Option<Value>)]) -> ConfigDiff {
        let mut d = ConfigDiff::default();
        for (p, o, n) in opts {
            d.options.insert(p.to_string(), (o.clone(), n.clone()));
        }
        d
    }

    /// Every option with old, new and sensitivity; Security and External
    /// first, then by path; removed units with their sensitivity.
    #[test]
    fn the_diff_puts_security_and_external_first() {
        let f = facts(&[
            ("a.font.scale", Some(Value::Str("1".into())), Some(Value::Str("1.25".into()))),
            ("services.openssh.enable", Some(Value::Bool(true)), Some(Value::Bool(false))),
            ("networking.wireguard.interfaces.wg0", None, Some(Value::Str("on".into()))),
        ]);
        let sshd = UnitId::service("sshd");
        let removed = [(sshd.clone(), Sensitivities::of(&[Sensitivity::Security]))];
        let d = diff(&Transition::Rollback, Some(&f), true, &removed, true, &tables());
        let paths: Vec<&str> = d.options.iter().map(|o| o.path.as_str()).collect();
        assert_eq!(paths, ["networking.wireguard.interfaces.wg0", "services.openssh.enable", "a.font.scale"]);
        assert!(d.options[1].sensitivity.contains(Sensitivity::Security));
        assert_eq!(d.options[1].old, Some(Value::Bool(true)));
        assert_eq!(d.options[1].new, Some(Value::Bool(false)));
        assert_eq!(d.removes.len(), 1);
        assert_eq!(d.removes[0].unit, sshd);
        assert_eq!(d.removes[0].kinds, ["Security"]);
        let l = d.lines();
        assert_eq!(l[0], "networking.wireguard.interfaces.wg0 added: on [External]");
        assert_eq!(l[1], "services.openssh.enable: true → false [Security]");
        assert_eq!(l[3], "removes or stops service:sshd [Security]");
        let s = d.summary().unwrap();
        assert!(s.starts_with("changes 3 options (2 Security/External:"), "{s}");
        assert!(s.ends_with("removes or stops service:sshd"), "{s}");
    }

    /// A removed Security user template shows `[Security]`: its sensitivity
    /// is derive's, the decision's own lookup, not a `defs` lookup that
    /// misses templates (#37 review).
    #[test]
    fn a_removed_security_user_template_shows_security() {
        let tpl: UnitId = "service@0:user-vpn".parse().unwrap();
        let d = diff(
            &Transition::Rollback,
            None,
            true,
            &[(tpl, Sensitivities::of(&[Sensitivity::Security]))],
            true,
            &tables(),
        );
        assert_eq!(d.lines(), ["removes or stops service@0:user-vpn [Security]"]);
    }

    /// When the evaluated generations could not be read, the display says so
    /// rather than present the requested settings as the whole change.
    #[test]
    fn an_unreadable_evaluation_is_said() {
        let f = facts(&[("a.font.scale", Some(Value::Str("1".into())), Some(Value::Str("1.25".into())))]);
        let d = diff(&Transition::Rollback, Some(&f), false, &[], true, &tables());
        assert_eq!(d.note.as_deref(), Some(UNAVAILABLE));
        assert_eq!(d.lines()[0], UNAVAILABLE);
        assert!(d.summary().unwrap().contains(UNAVAILABLE));
        assert!(diff(&Transition::Rollback, Some(&f), true, &[], true, &tables()).note.is_none());
    }

    /// A transition that is not a generation one shows no diff.
    #[test]
    fn only_generation_transitions_have_a_diff() {
        let f = facts(&[("services.openssh.enable", Some(Value::Bool(true)), Some(Value::Bool(false)))]);
        let d = diff(&Transition::RestartUnit(UnitId::service("sshd")), Some(&f), true, &[], true, &tables());
        assert!(d.is_empty());
        assert_eq!(d.summary(), None);
    }

    /// `DerivedFacts` as main journals it (since 4bb9c99): `removes` a list
    /// of unit ids and no `removes_each`. A literal, not a round-trip, so a
    /// change to the field's form fails here (#37 review: an undecodable
    /// record is truncated, or Integrity).
    const FACTS_BEFORE_REMOVES_EACH: &str = r#"{"affected_units":["service:sshd"],"sensitivity":["Security"],
        "disruption":{"brief":true,"session_loss":false,"data_interruption":false,"connectivity_loss":false},
        "recovery":"Revertible","touches_manifest":true,"touches_canonical_probe":false,"changes_desired":true,
        "touches_core":false,"below_security_floor":false,"other_sessions_affected":false,"affected_sessions":[],
        "restores_unattributed_stop":false,"restarts_failed_unit":false,"removes_sensitivity":["Security"],
        "removes":["service:sshd","service:gym-web"],"restarts_held_unit":false,
        "caller":{"User":{"uid":0,"session":null,"seat":null,"active":false}},
        "config_diff":{"options":{"services.openssh.enable":[true,false]}}}"#;

    #[test]
    fn facts_journaled_before_removes_each_decode_and_show_the_union() {
        let f: DerivedFacts = serde_json::from_str(FACTS_BEFORE_REMOVES_EACH).expect("main's form decodes");
        let (sshd, web) = (UnitId::service("sshd"), UnitId::service("gym-web"));
        assert_eq!(f.removes, [sshd.clone(), web.clone()]);
        assert!(f.removes_each.is_empty());
        let (units, each_known) = super::removed(&f);
        assert!(!each_known);
        let d = diff(&Transition::Rollback, f.config_diff.as_ref(), true, &units, each_known, &tables());
        assert_eq!(d.note.as_deref(), Some(EACH_UNAVAILABLE), "it says so");
        let l = d.lines();
        assert!(l.contains(&"removes or stops service:sshd [Security]".to_string()), "{l:?}");
        assert!(l.contains(&"removes or stops service:gym-web [Security]".to_string()), "the union for each: {l:?}");
        // Same length: each its own.
        let mut f = f;
        f.removes_each = vec![Sensitivities::of(&[Sensitivity::Security]), Sensitivities::default()];
        let (units, each_known) = super::removed(&f);
        assert!(each_known);
        assert_eq!(units, [(sshd, f.removes_each[0]), (web, Sensitivities::default())]);
        let d = diff(&Transition::Rollback, None, true, &units, each_known, &tables());
        assert!(d.note.is_none());
    }

    /// A whole `Prepared` record as main journals it, `removes` non-empty
    /// (fixtures/prepared-before-removes-each.json: a Rollback that removes
    /// sshd, written by this tree with `removes_each` taken out).
    #[test]
    fn a_prepared_record_journaled_before_removes_each_decodes() {
        let raw = include_str!("fixtures/prepared-before-removes-each.json");
        assert!(!raw.contains("removes_each"), "the fixture is main's form");
        let r: planarian_txn::ledger::Record = serde_json::from_str(raw).expect("main's record decodes");
        let planarian_txn::ledger::Record::Prepared(t) = r else { panic!("a Prepared record") };
        assert_eq!(t.facts.removes, [UnitId::service("sshd")]);
        assert!(t.facts.removes_each.is_empty());
        assert!(t.facts.removes_sensitivity.security);
    }
}
