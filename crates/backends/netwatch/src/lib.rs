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
//! Agreed with lane-nix (the hold's script, `planarian-hold condition` in
//! `nix/posture.nix`), lane-daemon and the coordinator, Nov 2.
//!
//! **Directory** `/run/planarian/footprint/` ([`DIR`]). Every file is written
//! to a temporary name and renamed into place, so the hold never reads a torn
//! file. `/run` is cleared at boot, so nothing here crosses a boot.
//!
//! **Clock.** Every timestamp `<t>` is CLOCK_BOOTTIME whole seconds
//! ([`CLOCK`]): the integer part of `/proc/uptime`'s first field, or
//! `clock_gettime(CLOCK_BOOTTIME)` truncated. Not Unix time, so a stepped wall
//! clock cannot make a stamp fresh. A stamp is *fresh* when `now - <t>` is
//! between `-`[`AHEAD_SECS`] and [`FRESH_SECS`] (−5 to 30 s).
//!
//! **`.watch`**, one line:
//! - `attached <t>` while every probe is attached and events flow,
//!   rewritten at least every [`TICK_SECS`] (5 s);
//! - or `failed <reason>` when an attach failed or the watch was lost.
//!
//! Anything else, a missing file, or a stale `attached` means the watch is
//! not known to be healthy.
//!
//! **`.unattributed`**: present while any change that steers traffic stands
//! that netwatch could not charge to a unit, or after a lost event
//! (ring-buffer overflow, dropped receive) it could not place. Its content
//! is one reason per line; readers test only for presence. It is removed
//! only when no such change stands.
//!
//! **`<unit>`**: one file per network tool, named as the systemd unit
//! without `.service` (an instance keeps its `@`: `gym-tpl@a`;
//! [`file_name`]). Lines, in this order:
//! - `protecting yes` or `protecting no`;
//! - `at <t>`: when netwatch last confirmed it, refreshed at least with
//!   every heartbeat;
//! - `iface <name>`: one per interface the unit created that steers
//!   traffic (zero or more): what the hold passes;
//! - `endpoint <udp|tcp> <address> <port>`: one per peer endpoint it needs
//!   (zero or more; IPv4 or IPv6 without brackets);
//! - `unattributed`: a change charged here that the kernel could not fully
//!   attribute, or a lost event that touched it.
//!
//! **On every attach** (boot or restart of the watch; coordinator, Nov 2,
//! from the reviewer's #38 finding 3c), in this order, so a restart never
//! downgrades a footprint and a change made while nobody watched fails
//! closed ([`Tracker::attach`]):
//! 1. **Load** the claims kept before: `.state` (netwatch's own record, a
//!    dot-file the hold does not read), or, if it is gone, the footprint
//!    files' `iface` lines. A claim whose object (interface, route, rule,
//!    table) still stands is kept, so a footprint that was `protecting
//!    yes` still is; a claim whose object is gone is dropped.
//! 2. **Snapshot** what stands now through netlink dumps: links, routes and
//!    rules (IPv4 and IPv6), nftables tables, and legacy tables
//!    (`/proc/net/*_tables_names`).
//! 3. **Unclaimed steering** found standing is recorded in `.unattributed`
//!    as `pre-attach <object>`: it was made while nobody watched. It clears
//!    only when its object is gone (an interface's routes go with it). A
//!    default route over a physical interface no unit created (the
//!    machine's uplink: no link kind) is not "an interface it created" and
//!    is not recorded; one over a virtual link (dummy, wireguard, tun, …)
//!    or over no interface is. At boot the watch starts before
//!    `network-pre.target` with `/run` fresh, so nothing is unclaimed.
//! 4. Only then, `protecting no` (and `at`) for every name in
//!    `/etc/planarian/export.json`'s top-level `networkTools` with no claim.
//!    A name ending in `@` is a template: it is written per instance as
//!    instances start. A file is kept across the unit's stop, and replaced
//!    by a fresh footprint when the unit comes back.
//!
//! The probes attach before the snapshot is taken, so a change racing it is
//! seen as an event too (applying it twice changes nothing).
//!
//! **Protecting** means the footprint includes, now: an interface the unit
//! created that carries a default or all-covering route (a `/0` or `/1`, in
//! any table, whoever added the route); a policy rule that catches all
//! traffic (no selectors, to a table other than the kernel's local, main and
//! default); DNS servers on its interface; the system proxy; or firewall
//! rules that drop or redirect traffic ([`Tracker`]). Fail closed where the
//! kernel's messages are not read in full: any nftables batch or legacy
//! table change (`nf_setsockopt`) from a unit counts as firewall rules that
//! steer. A route by itself makes nobody protecting: only through an
//! interface its creator made. A default route over a physical NIC no unit
//! created (NetworkManager's DHCP route over wlan0) steers nothing, watched
//! or found at attach; one over a virtual link, or over none, that nobody can
//! be charged with is unattributed (fail closed).
//!
//! **Not yet observed** (docs/bypasses.md, temporary): DNS servers set
//! through resolved (D-Bus) or `/etc/resolv.conf`, the system proxy, and
//! WireGuard peer endpoints (generic netlink is not read).
//!
//! **The hold's order.** When a network tool fails, it is held unless all of
//! these pass: (1) no unexpired release; (2) `.watch` is `attached` and
//! fresh; (3) no `.unattributed`; (4) the unit's file exists; (5) its `at` is
//! fresh; (6) it says `protecting no`, with no `unattributed` line.
//! [`FootprintView::protecting_now`] is (2) to (6); the release is the
//! hold's own.

mod contract;
pub mod ebpf;
pub mod host;
#[cfg(feature = "loader")]
pub mod loader;
mod model;
pub mod parse;
#[cfg(feature = "loader")]
pub mod snapshot;

pub use contract::{AHEAD_SECS, CLOCK, DIR, FRESH_SECS, TICK_SECS, file_name, read, read_claims, write, write_state};
pub use model::{Change, ChangeKind, Claims, Endpoint, Footprint, FootprintView, Owner, Proto, Tracker, WatchState};

#[cfg(test)]
mod tests;
