//! §16 *Approvals show the change* (owner decision, Nov 2): the
//! configuration a generation transition that asks would apply. The core
//! builds it from the derived facts, which come from the evaluated
//! generations (§11), never from the proposal. `planarian approve`, the
//! console and the notice show it; `approve --json` and IPC
//! `Pending.diff` carry the same data. A diff that differs when the facts
//! are re-derived at approval changes the token's `bound_to` (the binding
//! hashes the facts), so the approval does not apply and the change asks
//! again.

use planarian_ipc::{ApprovalDiff, OptionChange};
use planarian_policy::Tables;
use planarian_schema::*;

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
    removed: &[UnitId],
    tables: &Tables,
    defs: &UnitDefs,
) -> ApprovalDiff {
    if !t.changes_generation() {
        return ApprovalDiff::default();
    }
    let mut options: Vec<OptionChange> = config_diff
        .into_iter()
        .flat_map(|d| d.options.entries.iter())
        .map(|(path, (old, new))| OptionChange {
            path: path.clone(),
            old: old.clone(),
            new: new.clone(),
            sensitivity: tables.option_sensitivity(path),
        })
        .collect();
    options.sort_by(|a, b| (!first(&a.sensitivity), &a.path).cmp(&(!first(&b.sensitivity), &b.path)));
    let mut removes: Vec<(UnitId, Sensitivities)> =
        removed.iter().map(|u| (u.clone(), defs.get(u).map(|d| d.sensitivity).unwrap_or_default())).collect();
    removes.sort_by(|a, b| (!first(&a.1), &a.0).cmp(&(!first(&b.1), &b.0)));
    ApprovalDiff { options, removes }
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
        let mut defs = UnitDefs::new();
        let mut def = planarian_schema::fixtures::service("sshd");
        def.sensitivity = Sensitivities::of(&[Sensitivity::Security]);
        defs.insert(sshd.clone(), def);
        let d = diff(&Transition::Rollback, Some(&f), std::slice::from_ref(&sshd), &tables(), &defs);
        let paths: Vec<&str> = d.options.iter().map(|o| o.path.as_str()).collect();
        assert_eq!(paths, ["networking.wireguard.interfaces.wg0", "services.openssh.enable", "a.font.scale"]);
        assert!(d.options[1].sensitivity.contains(Sensitivity::Security));
        assert_eq!(d.options[1].old, Some(Value::Bool(true)));
        assert_eq!(d.options[1].new, Some(Value::Bool(false)));
        assert_eq!(d.removes, vec![(sshd, Sensitivities::of(&[Sensitivity::Security]))]);
        let l = d.lines();
        assert_eq!(l[0], "networking.wireguard.interfaces.wg0 added: on [External]");
        assert_eq!(l[1], "services.openssh.enable: true → false [Security]");
        assert_eq!(l[3], "removes or stops service:sshd [Security]");
        let s = d.summary().unwrap();
        assert!(s.starts_with("changes 3 options (2 Security/External:"), "{s}");
        assert!(s.ends_with("removes or stops service:sshd"), "{s}");
    }

    /// A transition that is not a generation one shows no diff.
    #[test]
    fn only_generation_transitions_have_a_diff() {
        let f = facts(&[("services.openssh.enable", Some(Value::Bool(true)), Some(Value::Bool(false)))]);
        let d = diff(&Transition::RestartUnit(UnitId::service("sshd")), Some(&f), &[], &tables(), &UnitDefs::new());
        assert!(d.is_empty());
        assert_eq!(d.summary(), None);
    }
}
