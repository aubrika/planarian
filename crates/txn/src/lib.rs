//! Planarian transaction kernel (SPEC §12, §12c).
//!
//! - `machine`: which journal state may follow which. Pure; a Verus target.
//! - `ledger`: journal records and the live state they establish. Its
//!   `validate` enforces I6, I15 and the recovery interlock on every record.
//! - `journal`: the write-ahead, CRC-framed, preallocated log, with
//!   checkpoint-then-truncate compaction.
//! - `store`: durable storage (in-memory for the fake harness, files on disk).
//! - `kernel`: drives one transaction through execution, takeover and the
//!   crash-recovery table, over a `Host` that provides backends and probes.
//! - `fake`: in-memory backends for the fake harness.

pub mod fake;
pub mod journal;
pub mod kernel;
pub mod ledger;
pub mod machine;
pub mod store;
