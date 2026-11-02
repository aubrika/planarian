//! netwatch (SPEC §12d "Which units"; owner decision, Nov 2): which network
//! tools are *protecting traffic*, from changes the kernel attributes to the
//! unit that made them.
//!
//! The kernel half (`crates/backends/netwatch-ebpf`, built by
//! `nix/netwatch-ebpf.nix`) watches the netlink receive paths and reports,
//! for every message, the sender's cgroup and what it touched. This crate
//! keeps each unit's current *footprint* from those reports ([`Tracker`]),
//! decides whether it is protecting traffic, and writes and reads the files
//! the hold reads (§12d), as specified below. The fake backend scripts the
//! same [`Tracker`], so the fake and the real machine share one meaning.
//!
//! # The file contract (the single source)
//!
//! Directory `/run/planarian/footprint/` ([`DIR`]). Every timestamp `<t>` is
//! an integer number of seconds on one clock, [`CLOCK`]; a file is *fresh*
//! when `now - <t> <= `[`FRESH_SECS`]. netwatch rewrites every file below on
//! each tick ([`TICK_SECS`]), each atomically (a temporary file renamed over
//! it), so a reader never sees a partial file.
//!
//! - `.watch`: one line, `attached <t>` while all three probes are attached
//!   and events flow, or `attach-failed <t>` if any probe failed to attach
//!   (or the watch stopped). Anything else, a missing file, or a stale
//!   `<t>` means the watch is not known to be healthy.
//! - `.unattributed`: present (empty) while any change that steers traffic
//!   stands that the kernel could not attribute to a unit, or after a lost
//!   event that could not be placed; absent otherwise.
//! - `<%N>`: one file per network tool (the export's `networkTools`), named
//!   as systemd's `%N` (the unit name, `@` and instance kept, `.service`
//!   dropped). Written, with `protecting no`, for every network tool as soon
//!   as the probes attach, so a missing file was never seen by a healthy
//!   watch. Lines, in this order:
//!   - `at <t>`: when netwatch last confirmed this footprint;
//!   - `protecting yes` or `protecting no`;
//!   - `iface <name>`: one per interface the unit created (zero or more);
//!   - `endpoint <proto> <addr> <port>`: one per peer endpoint (zero or
//!     more; `<proto>` is `tcp` or `udp`, `<addr>` an IPv4 or IPv6 address
//!     without brackets);
//!   - `unattributed`: present if a lost event may have touched this unit.
//!
//! *Protecting* means the footprint includes, now: an interface the unit
//! created that carries a default or all-covering route; a policy rule that
//! catches all traffic; DNS servers on its interface; the system proxy; or
//! firewall rules that drop or redirect traffic ([`Footprint::protecting`]).
//!
//! A reader treats a unit as protecting (fail closed, §12d) unless all of
//! these hold: `.watch` is `attached` and fresh; `.unattributed` is absent;
//! the unit's file exists, is fresh, says `protecting no`, and has no
//! `unattributed` line ([`FootprintView::protecting_now`]). `nix/posture.nix`
//! (the hold's script) applies exactly these rules.

mod contract;
mod model;

pub use contract::{CLOCK, DIR, FRESH_SECS, TICK_SECS, file_name, read, write};
pub use model::{Change, ChangeKind, Endpoint, Footprint, FootprintView, Owner, Proto, Tracker, WatchState};

#[cfg(test)]
mod tests;
