//! Decisive journal requirements exported by a build and carried through
//! compaction (§12c). Only semantic extensions to the original format-2
//! schema need field names here; adding a decisive field extends this registry
//! in the same change as its reader and writer.

use super::{DECISIVE_KINDS, JournalError};
use crate::ledger::Record;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const CHECKPOINT_REQUIREMENTS: &str = "_journal_requirements";

/// What a build reads, or what a journal needs its next reader to understand.
/// Field names are paths within the serialized record kind; `checkpoint`
/// names the equivalent paths in the serialized ledger. `*` is a map key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRequirements {
    pub format: u8,
    pub kinds: Vec<String>,
    pub fields: BTreeMap<String, Vec<String>>,
}

impl JournalRequirements {
    pub(super) fn empty() -> Self {
        // A transition will itself write Prepared and Advance before its
        // target becomes live. Even an empty journal therefore needs a
        // reader for the writer's current format.
        let mut kinds: Vec<String> = ORIGINAL_KINDS.iter().map(|s| (*s).to_owned()).collect();
        kinds.sort();
        Self { format: 3, kinds, fields: BTreeMap::new() }
    }

    pub(super) fn merge(&mut self, other: &Self) {
        self.format = self.format.max(other.format);
        self.kinds.extend(other.kinds.iter().cloned());
        self.kinds.sort();
        self.kinds.dedup();
        for (kind, fields) in &other.fields {
            let ours = self.fields.entry(kind.clone()).or_default();
            ours.extend(fields.iter().cloned());
            ours.sort();
            ours.dedup();
        }
    }

    /// The exact unsupported format, decisive kinds and decisive fields.
    /// Callers show and bind these names in an Administrator approval.
    pub fn unsupported_by(&self, target: &Self) -> Vec<String> {
        let mut missing = vec![];
        if self.format > target.format {
            missing.push(format!("journal format {} (target reads {})", self.format, target.format));
        }
        for kind in &self.kinds {
            if !target.kinds.contains(kind) {
                missing.push(format!("record kind {kind}"));
            }
        }
        for (kind, fields) in &self.fields {
            for field in fields {
                if !target.fields.get(kind).is_some_and(|known| known.contains(field)) {
                    missing.push(format!("decisive field {kind}.{field}"));
                }
            }
        }
        missing.sort();
        missing.dedup();
        missing
    }
}

// Frozen at the introduction of the export. Do not extend this list when
// adding a new kind: a target without an export does not read the new kind.
const ORIGINAL_KINDS: &[&str] = &[
    "Prepared",
    "Advance",
    "Takeover",
    "Renew",
    "OpBegin",
    "OpAck",
    "OverrideSet",
    "OverrideLifted",
    "Incident",
    "KnownGood",
    "LiveTested",
    "AcceptedBaseline",
    "SecurityFloor",
    "ExternalAccepted",
    "TokenUsed",
    "AgentStarted",
    "Resolved",
    "Reconciliation",
    "HoldApplied",
    "HoldLifted",
];

const ORIGINAL_FIELDS: &[(&str, &[&str])] = &[
    ("Advance", &["withdrawn_for"]),
    ("Prepared", &["prepared_again_from"]),
    ("checkpoint", &["live.*.txn.prepared_again_from", "terminal.*.prepared_again_from", "terminal.*.withdrawn_for"]),
];

/// A generation predating the export reads only the original format-2 set.
pub fn original() -> JournalRequirements {
    JournalRequirements {
        format: 2,
        kinds: ORIGINAL_KINDS.iter().map(|s| (*s).to_owned()).collect(),
        fields: ORIGINAL_FIELDS
            .iter()
            .map(|(kind, fields)| ((*kind).to_owned(), fields.iter().map(|s| (*s).to_owned()).collect()))
            .collect(),
    }
}

/// This build's reader capabilities. The new facts field decides whether a
/// generation transition asks, so it is decisive even though it has a default.
pub fn supported() -> JournalRequirements {
    let mut reads = original();
    reads.format = 3;
    reads.kinds = DECISIVE_KINDS.iter().map(|s| (*s).to_owned()).collect();
    reads.fields.entry("Prepared".into()).or_default().push("facts.journal_incompatibility".into());
    reads.fields.entry("checkpoint".into()).or_default().push("live.*.txn.facts.journal_incompatibility".into());
    reads.fields.entry("checkpoint".into()).or_default().push("not_prepared_again".into());
    reads
}

fn active(value: &serde_json::Value, path: &[&str]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return match value {
            serde_json::Value::Null => false,
            serde_json::Value::Array(a) => !a.is_empty(),
            serde_json::Value::Object(o) => !o.is_empty(),
            _ => true,
        };
    };
    if *first == "*" {
        return value.as_object().is_some_and(|o| o.values().any(|v| active(v, rest)));
    }
    value.get(*first).is_some_and(|v| active(v, rest))
}

fn fields_in(kind: &str, value: &serde_json::Value, out: &mut JournalRequirements) {
    if let Some(paths) = supported().fields.get(kind) {
        for path in paths {
            if active(value, &path.split('.').collect::<Vec<_>>()) {
                out.fields.entry(kind.to_owned()).or_default().push(path.clone());
            }
        }
    }
}

pub(super) fn record_requirements(record: &Record) -> Result<JournalRequirements, JournalError> {
    let mut required = JournalRequirements::empty();
    let (kind, class) = super::kind_and_class(record);
    if class != super::Class::Decisive || matches!(record, Record::Skipped { .. }) {
        return Ok(required);
    }
    required.kinds.push(kind.to_owned());
    // This record becomes the checkpoint's declined-ID set at compaction.
    if matches!(record, Record::NotPreparedAgain { .. }) {
        required.fields.entry("checkpoint".into()).or_default().push("not_prepared_again".into());
    }
    let value = serde_json::to_value(record).map_err(|e| JournalError::Corrupt(e.to_string()))?;
    if let Some(payload) = value.get(kind) {
        fields_in(kind, payload, &mut required);
    }
    // A decisive field and its checkpoint representation are one semantic
    // requirement. Keep both from the first record onward, rather than
    // adding/removing the checkpoint spelling as a pending transaction
    // enters/leaves the live set (which could otherwise re-ask forever).
    let aliases: &[(&str, &str, &[&str])] = &[
        ("Prepared", "facts.journal_incompatibility", &["live.*.txn.facts.journal_incompatibility"]),
        ("Prepared", "prepared_again_from", &["live.*.txn.prepared_again_from", "terminal.*.prepared_again_from"]),
        ("Advance", "withdrawn_for", &["terminal.*.withdrawn_for"]),
    ];
    for (record_kind, field, paths) in aliases {
        if *record_kind == kind && required.fields.get(kind).is_some_and(|fields| fields.iter().any(|f| f == field)) {
            required.fields.entry("checkpoint".into()).or_default().extend(paths.iter().map(|p| (*p).to_owned()));
        }
    }
    Ok(required)
}

pub(super) fn checkpoint_requirements(value: &serde_json::Value) -> Result<JournalRequirements, JournalError> {
    let mut required = match value.get(CHECKPOINT_REQUIREMENTS) {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| JournalError::Integrity(format!("the checkpoint's journal requirements do not parse: {e}")))?,
        // History already compacted by a pre-export build cannot be recovered
        // from the remaining log. Keep the entire original decisive set.
        None => original(),
    };
    fields_in("checkpoint", value, &mut required);
    Ok(required)
}
