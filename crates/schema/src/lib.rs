//! Planarian schema (SPEC §8): types, status derivation and the state digest.
//! No I/O. Intended for the Verus subset: no `dyn`, no `unsafe`, no floats,
//! integer time.

pub mod backend;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod ids;
pub mod spec;
pub mod state;
pub mod transition;
pub mod txn;
pub mod unit;

pub use backend::*;
pub use ids::*;
pub use state::*;
pub use transition::*;
pub use txn::*;
pub use unit::*;
