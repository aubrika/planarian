//! planariad's core, independent of the real backends: the tick loop and the
//! request handler. The `planariad` binary instantiates it with the systemd,
//! udev and nixos-rebuild backends; the gym, with the fake machine.

pub mod config;
pub mod core;
pub mod render;
pub mod snapshot;

pub use core::{Core, CoreConfig, LogRecord, Peer};
pub use planarian_incident::STARTUP_GRACE;
