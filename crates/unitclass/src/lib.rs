//! Classify systemd unit files as network tools at build time, and check the
//! hold is in force in a merged unit tree (B-23; SPEC §12d "Which units").
//!
//! The classification is computed from the unit files, never from names, and
//! fails closed: a unit that cannot be read exactly is a tool. Everything here
//! is a pure function of file text, except [`tree`], which reads directories.

pub mod rule;
pub mod syntax;
pub mod tree;

#[cfg(test)]
mod tests;
