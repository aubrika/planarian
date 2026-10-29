//! Planarian schema (SPEC §8): types, status derivation and the state digest.
//! No I/O. Intended for the Verus subset: no `dyn`, no `unsafe`, no floats,
//! integer time.

#![cfg_attr(verus_keep_ghost, verifier::allow(autoderive_clone_without_spec))]
// Verus idioms: `&Vec` for its `@` view, explicit `match` and nested `if`
// rather than `matches!` and let-chains.
#![allow(clippy::ptr_arg, clippy::match_like_matches_macro, clippy::collapsible_if)]

pub mod authz;
pub mod backend;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod gc;
pub mod ids;
pub mod pathmap;
pub mod spec;
pub mod state;
pub mod transition;
pub mod txn;
pub mod unit;

pub use authz::*;
pub use backend::*;
pub use ids::*;
pub use pathmap::PathMap;
pub use state::*;
pub use transition::*;
pub use txn::*;
pub use unit::*;
