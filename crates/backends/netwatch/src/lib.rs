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
//! **When the files are written**: whenever a drain of the ring changed
//! anything, and whenever a unit's invocation state changed (below), not
//! only on the tick; the tick (every [`TICK_SECS`]) refreshes every `at`,
//! a file whose invocation has `ended` included (coordinator, Nov 3).
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
//! - `protecting yes`, `protecting no`, or `protecting unknown`: the
//!   unit's latest invocation has a cgroup whose InvocationID netwatch has
//!   not read yet (systemd sets it just after making the cgroup, before the
//!   unit's first process). `unknown` reads as protecting. `yes` is a
//!   latch per invocation (reviewer and coordinator, Nov 3): an invocation
//!   found protecting at any point stays `protecting yes`, with the `iface`
//!   and `endpoint` lines that made it so, until a new invocation replaces
//!   it; neither `ended` nor its interface or routes going clear it. A
//!   tun-based VPN's interface leaves with its last process, before its
//!   cgroup goes and with no netlink request, so what stands at `ended`
//!   is not what it did. Steering seen while a unit has no live invocation
//!   (none known yet, or the last one ended) is the next one's: its cgroup
//!   was made between netwatch's cgroups read and its ring read. One
//!   replaced before it ended passes its latch on (fail closed);
//! - `at <t>`: when netwatch last confirmed it, refreshed at least with
//!   every heartbeat;
//! - `invocation <32 lowercase hex>`: the unit's latest systemd
//!   InvocationID, from its cgroup's `trusted.invocation_id` (or
//!   `user.invocation_id`), kept after the cgroup goes. A file whose
//!   `invocation` is not 32 lowercase hex is not trusted;
//! - `ended`: that invocation's cgroup is gone (IN_DELETE seen, or found
//!   absent at the start of a drain: no directory at its path, or one with
//!   another inode, which on cgroupfs is the cgroup id, never reused in a
//!   boot) and the ring has been drained after.
//!   A probe runs inside the syscall, and a cgroup can be removed only once
//!   its last process has exited, so everything the invocation did is in
//!   the file. Written only for an invocation whose id this netwatch read
//!   while its cgroup stood and whose removal it then saw: after a restart
//!   of netwatch, one that went meanwhile never reads `ended`. If the ring
//!   lost events in the drain that ended it, the unit is `unattributed`;
//! - `iface <name>`: one per interface the unit created that steers
//!   traffic (zero or more): what the hold passes;
//! - `endpoint <udp|tcp> <address> <port>`: one per peer endpoint it needs
//!   (zero or more; IPv4 or IPv6 without brackets);
//! - `unattributed`: a change charged here that the kernel could not fully
//!   attribute, or a lost event that touched it. A file with this line
//!   always says `protecting yes` too (coordinator, Nov 3): fail closed, and
//!   the file says what the hold reads.
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
//! **Interfaces.** "An interface it created" is seen at the return of
//! `register_netdevice`, on success only (on entry the name can still be a
//! template, `tun%d`, which it resolves), which runs in the creator's
//! context for every kind: a tun or tap made by `ioctl(TUNSETIFF)` (classic OpenVPN,
//! wireguard-go, tailscaled), which no netlink message announces, as well
//! as netlink-made links, whose RTM_NEWLINK is a second witness. Only a
//! *virtual* link can be one a tool created; virtual is read live each
//! tick (`/sys/class/net/<if>` under `/sys/devices/virtual/`), so a tun made
//! by ioctl or a link moved in from another netns is never taken for a
//! physical NIC. And (coordinator, Nov 2 and 3; the spec reads "...over a
//! virtual interface it did not create...") a default or all-covering route
//! the unit added over a virtual link it did not create makes it protecting
//! too: one another unit made (OpenVPN on a persistent tun a setup unit
//! made: both hold), one moved in from another netns, one made before the
//! watch attached. Routes over a physical NIC stay exempt.
//!
//! **Protecting** means the footprint includes, now: an interface the unit
//! created that carries a default or all-covering route (a `/0` or `/1`, in
//! any table, whoever added the route); a policy rule that catches all
//! traffic (no selectors, to a table other than the kernel's local, main and
//! default); DNS servers on its interface; the system proxy; or firewall
//! rules that drop or redirect traffic ([`Tracker`]). Fail closed where the
//! kernel's messages are not read in full: any nftables batch or legacy
//! table change (`nf_setsockopt`) from a unit counts as firewall rules that
//! steer. On a kernel without legacy xtables (`CONFIG_NETFILTER_XTABLES_LEGACY`
//! unset: no `/proc/net/*_tables_names`), nothing can show such a claim
//! gone, so a unit that ever called `nf_setsockopt` stays protecting until
//! reboot, across netwatch's restarts and the unit's own stop (claims
//! outlive the unit, as a route it left behind still steers). Deliberate:
//! it fails closed (coordinator, Nov 2). A route by itself makes nobody protecting: only through an
//! interface its creator made. A default route over a physical NIC no unit
//! created (NetworkManager's DHCP route over wlan0) steers nothing, watched
//! or found at attach; one over a virtual link, or over none, that nobody can
//! be charged with is unattributed (fail closed).
//!
//! **Attribution.** The unit is the first `<name>.service` under
//! `system.slice`, past any slices (a template's instances sit in the
//! template's slice). The probe reads the sender's cgroup path from kernfs
//! at the request (`task->cgroups->dfl_cgrp->kn`, up to four names toward
//! the root, at offsets the loader takes from BTF), so a unit is known even
//! if its cgroup is gone before netwatch reads the event. The path is used
//! only when whole (the walk reached the root, no name cut short); else the
//! cgroup id is looked up. systemd makes a unit's cgroup before its first
//! process starts, so netwatch records ids as cgroups are made (inotify on `system.slice` and
//! the slices under it, waking the loop at once) and keeps them after the
//! cgroup goes: a oneshot that changes something and exits at once is still
//! charged with it. Keeping old ids is safe because cgroup ids are 64-bit
//! and not reused within a boot. An id is forgotten only once its cgroup
//! has been gone for two walks (a tick apart, so none of its events is
//! still unread) and its unit claims nothing in the footprint, so the map
//! stays bounded on a long-lived host. A cgroup made and
//! gone before netwatch saw it at all leaves the change unattributed
//! (`.unattributed`: fail closed).
//!
//! **Namespaces** (reviewer, #42). How traffic leaves the machine is the
//! host netns's business, so only requests that act in netwatch's own netns
//! (`/proc/self/ns/net`; the unit runs in the host's) count. Each probe
//! reports the netns the request acts on: the kernel's own `sock_net(skb->
//! sk)` for netlink, the socket's for `setsockopt` (the netns whose tables
//! it changes). That is the target, not the sender's netns (`nsproxy`): a
//! process can open a socket in one netns and then `setns` to another, and
//! what changes is the socket's. The tracker's keys (names, and indices
//! resolved through the host's /sys/class/net) are therefore implicitly the
//! host's; a debug assertion in `parse::take` keeps it so. Rust eBPF has no CO-RE,
//! so the loader reads where `sk_buff.sk`, `sock.__sk_common.skc_net.net`
//! and `net.ns.inum` are from the running kernel's BTF and sets them in the
//! object before load (an object without those globals is unusable). The
//! BTF reader refuses a kind of type it does not know (kind 0, or past
//! ENUM64): it cannot skip data it cannot size without misreading every
//! type after it. So a future kernel that adds a kind makes netwatch fail
//! closed (`failed BTF: unknown kind N`, the hold holds), and the reader in
//! `btf.rs` needs updating for it (coordinator, Nov 2). A
//! container's or a `PrivateNetwork=` service's own interfaces, routes and
//! firewall are ignored, so a container's `wg0` going away leaves the host
//! VPN's `wg0` claim standing. Fail closed: a netns the probe could not
//! read, or a link message elsewhere that may reach into the host (moved
//! by `IFLA_NET_NS_PID`/`_FD`, or aimed by `IFLA_TARGET_NETNSID`), is a loss
//! nothing can place (`.unattributed`, until the next attach).
//!
//! **Starting** (coordinator, Nov 2). Whatever happens, `.watch` is
//! written before systemd hears `READY=1`, and systemd hears it once, so
//! boot never waits on the start timeout and the hold already reads the
//! watch as attached or not.
//! - An *unusable object or input* (the object missing, not ELF, a program
//!   absent or of the wrong type, a map missing; the export unreadable or
//!   without `networkTools`): write `failed <reason>`, send `READY=1`, exit
//!   1. No retry can fix it.
//! - The *kernel refuses* a load or an attach, or the snapshot fails: write
//!   `failed <reason>`, send `READY=1`, stay up and try again every
//!   `loader::RETRY_SECS` (30 s), rewriting the reason each time. The
//!   first attach that succeeds reconciles (above) and writes `attached`.
//!
//! Probes: `rtnetlink_rcv_msg`, `nf_setsockopt`, `genl_rcv_msg` and
//! `register_netdevice` are built in, so fentry, or fexit for
//! `register_netdevice` (they need vmlinux's BTF); `nfnetlink_rcv_msg` and
//! `nfnetlink_rcv_batch` are in the `nfnetlink` module (`=m` on NixOS
//! kernels), so kprobes by symbol, which need the module loaded: the
//! initrd loads it (`boot.kernelModules`), since netwatch starts early in
//! `sysinit.target`, before every network tool and ordered after nothing
//! (lane-nix, Nov 2). If it is not loaded yet, the attach is a kernel
//! refusal and is retried, so the watch recovers once it is
//! (`loader::PROBES`).
//!
//! **DNS and the system proxy** (B-22 a; `dns`, `files`). A unit that points
//! the machine's resolver at its own servers, or sets the system proxy,
//! steers traffic through files, not netlink. Each setting is one *object*:
//! `(Dns, "resolv.conf")`, `(Dns, "link <ifname>")` for a resolved link
//! (`/run/systemd/resolve/netif/<ifindex>`), `(Proxy, "<file>")` for
//! `/etc/environment`, NixOS's `/etc/set-environment` and `/etc/profile.d/*`.
//! Whether it steers is computed from its *current content* on every read
//! and never remembered: a name server that is not loopback (the machine's
//! own stub: a dead one fails DNS closed rather than leaking; 127.0.0.0/8,
//! `::1`, a zone or port or `#name` suffix allowed; an unreadable one
//! steers), or a proxy variable (`http_proxy`, `https_proxy`, `all_proxy`,
//! `ftp_proxy`, any case) with a value. Content that stops steering, or a
//! file or link that goes, clears the object for *everyone*, so a charge
//! cannot stick. The objects are singletons: a new claimant replaces the old.
//! `dns::reconcile` decides who claims what (coordinator, Nov 3):
//! - a steering write by a process in a unit is that unit's alone;
//! - one by a process netwatch cannot place in a unit (gone, or in none), or
//!   steering content with no claimant (standing at attach, or an event
//!   missed), is charged to the network tools *running at that moment*, the
//!   only ones that could have written it; with none running it is the
//!   machine's baseline and charged to nobody. It is never the global
//!   `.unattributed` marker, which on any DHCP machine would hold every
//!   tool for good;
//! - a resolved link's DNS is its interface's owner's (the unit with a claim
//!   on the interface), whoever wrote it over D-Bus: the failure that matters
//!   is a VPN dying and resolved falling back to other links' servers; with
//!   no owner it is the running tools'.
//!
//! *Who wrote.* fanotify on the directories (`FAN_CLOSE_WRITE|FAN_MODIFY` on
//! children) hands over the file written and the writer's pid; the pid's
//! cgroup is read at once. Replace-by-rename (resolvconf, NetworkManager) is
//! found by inode: the temporary file's inode is the new file's (`files`). No
//! fanotify (refused in a container) makes every change an unknown writer.
//! The in-kernel probe that would attribute exactly (as the netlink probes
//! do) is deferred.
//!
//! *Not covered* (docs/bypasses.md, B-22): DNS or proxy content found at
//! attach with no network tool running; the proxy anywhere but the files
//! above (per-user dconf, a unit's own `Environment=`, an application's
//! configuration); a local DNS proxy's own upstream configuration; and a
//! write by a process netwatch cannot place, which is charged to the tools
//! running then and not to one started later.
//!
//! **The hold's order.** When a network tool fails, it is held unless all of
//! these pass: (1) no unexpired release; (a) the unit's file says
//! `invocation` equal to the unit's `InvocationID` (else it describes
//! another run) and `ended` (else what the run did may be still to come),
//! waited for by polling, at most about 3 s; (2) `.watch` is `attached` and
//! fresh; (3) no `.unattributed`; (4) the unit's file exists; (5) its `at`
//! is fresh; (6) it says `protecting no`, with no `unattributed` line
//! (coordinator, Nov 3: a VPN that steered and died before the next write
//! read as the last run's `protecting no`). A unit whose cgroup never
//! empties (a process left behind with `KillMode=none`) never reads
//! `ended`, so it is held: fail closed. [`FootprintView::protecting_now`]
//! is (2) to (6); [`hold_may_release`] is (a) and (2) to (6), the reference
//! the property tests check; the release is the hold's own.

pub mod btf;
#[cfg(feature = "loader")]
pub mod cgroups;
mod contract;
pub mod dns;
pub mod ebpf;
#[cfg(feature = "loader")]
pub mod files;
pub mod host;
#[cfg(feature = "loader")]
pub mod loader;
mod model;
pub mod parse;
#[cfg(feature = "loader")]
pub mod snapshot;

pub use contract::{
    AHEAD_SECS, CLOCK, DIR, FRESH_SECS, TICK_SECS, file_name, hold_may_release, read, read_claims, write, write_state,
};
pub use model::{
    Change, ChangeKind, Claims, Endpoint, Footprint, FootprintView, Invocation, Owner, Proto, Tracker, WatchState,
};

#[cfg(test)]
mod props;
#[cfg(test)]
mod tests;
