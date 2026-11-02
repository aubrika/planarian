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

/// Shown first: what a person most needs to see before approving.
fn first(s: &Sensitivities) -> bool {
    s.contains(Sensitivity::Security) || s.contains(Sensitivity::External)
}

/// The diff a generation transition would apply; empty for any other.
/// `config_diff` and `removed` (the units it would remove or stop) come from
/// the derived facts; each unit's sensitivity from `defs`.
pub fn diff(
    t: &Transition,
    config_diff: Option<&ConfigDiff>,
    evaluated: bool,
    removed: &[(UnitId, Sensitivities)],
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
    let note = (!evaluated).then(|| UNAVAILABLE.to_string());
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
        let d = diff(&Transition::Rollback, Some(&f), true, &removed, &tables());
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
        let d =
            diff(&Transition::Rollback, None, true, &[(tpl, Sensitivities::of(&[Sensitivity::Security]))], &tables());
        assert_eq!(d.lines(), ["removes or stops service@0:user-vpn [Security]"]);
    }

    /// When the evaluated generations could not be read, the display says so
    /// rather than present the requested settings as the whole change.
    #[test]
    fn an_unreadable_evaluation_is_said() {
        let f = facts(&[("a.font.scale", Some(Value::Str("1".into())), Some(Value::Str("1.25".into())))]);
        let d = diff(&Transition::Rollback, Some(&f), false, &[], &tables());
        assert_eq!(d.note.as_deref(), Some(UNAVAILABLE));
        assert_eq!(d.lines()[0], UNAVAILABLE);
        assert!(d.summary().unwrap().contains(UNAVAILABLE));
        assert!(diff(&Transition::Rollback, Some(&f), true, &[], &tables()).note.is_none());
    }

    /// A transition that is not a generation one shows no diff.
    #[test]
    fn only_generation_transitions_have_a_diff() {
        let f = facts(&[("services.openssh.enable", Some(Value::Bool(true)), Some(Value::Bool(false)))]);
        let d = diff(&Transition::RestartUnit(UnitId::service("sshd")), Some(&f), true, &[], &tables());
        assert!(d.is_empty());
        assert_eq!(d.summary(), None);
    }
}
