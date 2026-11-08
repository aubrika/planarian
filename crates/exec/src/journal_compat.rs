//! §12c: compare a target build with the decisive journal it will inherit.
use planarian_txn::journal::{JournalRequirements, original};

/// Missing metadata means the original format's set, not today's. A
/// malformed descriptor is never treated as absent or as compatible.
pub(crate) fn unsupported(required: &JournalRequirements, target: Option<&str>) -> Result<Vec<String>, String> {
    let target = match target {
        Some(json) => serde_json::from_str::<JournalRequirements>(json)
            .map_err(|e| format!("target journalKinds is malformed: {e}"))?,
        None => original(),
    };
    if target.format == 0 || target.kinds.is_empty() {
        return Err("target journalKinds has no format or record kinds".into());
    }
    Ok(required.unsupported_by(&target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    proptest! {
        /// A compatible target never asks merely because the journal has
        /// requirements; removing any required format, kind, or decisive
        /// field is surfaced. Fields are checked even for a known kind.
        #[test]
        fn every_missing_decisive_requirement_is_reported(
            kind in "[A-Z][a-z]{1,12}", field in "[a-z]{1,12}",
            format in any::<bool>(), missing_kind in any::<bool>(), missing_field in any::<bool>(),
        ) {
            let kind = format!("Extra{kind}");
            let required = JournalRequirements {
                format: 3,
                kinds: vec!["Prepared".into(), kind.clone()],
                fields: [(kind.clone(), vec![field.clone()])].into(),
            };
            let target = JournalRequirements {
                format: if format { 2 } else { 3 },
                kinds: if missing_kind { vec!["Prepared".into()] } else { required.kinds.clone() },
                fields: if missing_field { BTreeMap::new() } else { required.fields.clone() },
            };
            let json = serde_json::to_string(&target).unwrap();
            let got = unsupported(&required, Some(&json)).unwrap();
            prop_assert_eq!(got.is_empty(), !format && !missing_kind && !missing_field);
            let complete = serde_json::to_string(&required).unwrap();
            prop_assert!(unsupported(&required, Some(&complete)).unwrap().is_empty());
        }
    }

    #[test]
    fn an_absent_export_is_legacy_and_a_broken_one_is_refused() {
        let required = JournalRequirements { format: 3, kinds: vec!["Prepared".into()], fields: BTreeMap::new() };
        assert!(!unsupported(&required, None).unwrap().is_empty());
        for broken in ["", "{", "{}", r#"{"format":0,"kinds":[],"fields":{}}"#] {
            assert!(unsupported(&required, Some(broken)).is_err(), "{broken}");
        }
    }
}
