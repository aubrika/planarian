# The watch in the initrd (design, B-26)

Status: **design for review, no code.** Author: lane-change-path. Reviewers: lane-nix (the Nix side), the coordinator, the reviewer. Closes B-26 when built; SPEC §12d, "The watch in the initrd" (owner decision, Nov 3), is the requirement and this file does not change its words.

The spec's words, which this design has to meet:

- With the systemd initrd, the watch also runs in the initrd, ordered before every network tool there.
- Its probes and event queue stay in the kernel across the switch to the root.
- The stage-2 watch takes over the initrd's footprints and the events queued meanwhile.
- If the stage-2 watch cannot take over (a version mismatch, or the probes are gone), it attaches afresh, and anything it cannot attribute counts as protecting.
- A unit the watch itself needs in order to start cannot wait for it; for those, a failure before the watch attaches holds traffic.
- With a scripted initrd the initrd runs no network tools.

## 1. What exists today

`planarian-netwatch` (crates/backends/netwatch) loads `netwatch.bpf.o` with aya and attaches ten probes (`loader::PROBES`): eight fentry or fexit programs (including the entry and exit pairs for namespace moves and renames) and two kprobes on module functions (`nfnetlink_rcv_msg`, `nfnetlink_rcv_batch`). The object has these maps:

| Map | Kind | Role |
| --- | --- | --- |
| `EVENTS` | ring buffer, 512 KiB (about 560 events of 928 bytes) | the events |
| `LOST` | `Array<u64>`, 1 entry | events that did not fit; userspace reads it as a lost event, which fails closed |
| `MOVE_SRC`, `RENAME_SRC` | `Array<[u8; N]>`, 1 entry | per-call scratch between an entry and its exit probe |
| `.rodata` | frozen globals | BTF offsets the loader sets (`NETNS_*`, `CG_*`, `NETDEV_*`) |

Everything is owned by the watch process: when it exits, every link detaches and every map is freed. Two things follow. First, a watch that has not started yet watches nothing, which is why B-26 exists (the units in `nix/netwatch-unordered.nix`'s `initrdSurvivors` act before it). Second, a restart of the watch in stage 2 is itself an unwatched window that the attach snapshot (`Tracker::attach`, N6: `pre-attach` objects) covers only for what still stands.

## 2. What has to outlive the process

Pin to bpffs: the **links** (each holds its program alive) and the **maps**. A process that exits leaves the probes attached and the ring filling; the next process opens the pins and keeps reading.

- **Links, ten of them.** The fentry and fexit programs attach as `bpf_link`s, which pin. The two kprobes may not, depending on aya: older aya attaches a kprobe as a perf event with the program set by ioctl, which closes with the process, while aya 0.12 and later may hand back a pinnable `FdLink` for it (reviewer; check the pinned version first). If it does not, two ways out, to decide with lane-nix after a VM check (assumption A2):
  1. Replace the two kprobes with fentry on the module functions. That needs the module's BTF (`attach_btf_obj_fd`, kernel 5.11 and later), and nfnetlink loaded before the watch loads (§12d already says "nfnetlink loaded in the initrd").
  2. Create the kprobe links with `BPF_LINK_CREATE` and `BPF_PERF_EVENT` (kernel 5.15 and later), which aya may not expose; if not, a small raw syscall in the loader.
  Option 1 keeps one mechanism for all ten. A probe that cannot be pinned is a design blocker, not something to paper over: it would make the takeover claim false for that hook.
- **Maps.** `EVENTS`, `LOST`, `MOVE_SRC`, `RENAME_SRC` and the frozen `.rodata` map.
- **A META map** (new, one-entry `Array`): `{ magic, layout_version, object_sha256, ring_bytes, probe_count, prog_tags[10] }`, written by the loader at first load and then frozen (`BPF_MAP_FREEZE`), so it describes the object that was loaded.

## 3. Layout

One directory, `/run/planarian/netwatch-bpf/`, the root of **Planarian's own bpffs instance** (not the system's `/sys/fs/bpf`; see below):

```
link-<probe>      one per entry of loader::PROBES (10)
map-EVENTS  map-LOST  map-MOVE_SRC  map-RENAME_SRC  map-RODATA  map-META
```

The directory is the root of a bpffs mounted with `-o mode=0700` (without the option the instance's root came up with default permissions in the probe), owned by root; the parent `/run/planarian/` is `root:root` `0755` as today, so nothing but the mount's root needs `0700`. bpffs enforces the file modes, so no uid but root can open, replace or unlink a pin. The watch checks owner and mode (with `fstat` on the opened directory, not the path) on every takeover and refuses a pin set that is not `0700 root` or that holds an entry it does not know (§5, "refuse").

**The bpffs instance must cross the switch-root, and the system's does not.** lane-nix's probe (nixos kernel 6.18.57, systemd 260.5; run 42483509297, branch `lane-nix/initrd-probes` at 0c04bc8) found that pins made in the initrd's own `/sys/fs/bpf` are **not** there in stage 2: systemd's switch-root leaves a fresh, empty bpffs instance (A1 failed, twice). A separate bpffs mounted under `/run` in the initrd **did** survive with every pin intact, because `/run` moves to stage 2 with its submounts (A1b passed). So the design mounts its own instance:

- `/run/planarian/netwatch-bpf` is a bpffs mount (`mount -t bpf -o mode=0700 bpf …`), made in the initrd before the initrd watch loads, by a mount unit (lane-nix's side) so that it is in the host mount namespace and not a service's private one.
- Stage 2 does not mount a new one: the instance moved with `/run`. The stage-2 unit has the same mount unit ordered before it, and the mount is idempotent (already mounted at that path: nothing to do; the loader checks it is a bpffs with `statfs` and refuses a path that is not, §5 "refuse"). With no initrd watch (a scripted initrd) the stage-2 mount unit makes the instance fresh, and the same code runs.
- A pin directory that is not a bpffs root, or whose mount is not `0700 root`, is refused.
- Never use the system's `/sys/fs/bpf` for any of this: stage 2 probably over-mounts the initrd's instance rather than freeing it, so pins made there stay attached but hidden (reviewer, #94).
- When a generation turns netwatch off, a named unit (`planarian-netwatch-bpf-clear.service`, `ExecStart` unpins the links and unmounts `/run/planarian/netwatch-bpf`, run from the stage-2 stop of the watch only when the export says it is off; the unit exists **only in generations with netwatch off** (reviewer, #94), so a generation with the watch on carries no unit that could remove the instance) removes the instance, so a stopped watch does not leave probes attached for a unit nobody runs. A plain stop or restart of the watch leaves it (§5).

## 4. The build-hash and layout check

Takeover compares what is pinned with what this binary expects, before it trusts a single pin:

1. `META.magic` and `layout_version` equal this binary's constants (`layout_version` is bumped by any change to `Event`, a map, or a probe).
2. `META.object_sha256` equals the SHA-256 of the `netwatch.bpf.o` this binary carries. A rebuilt object with the same layout still mismatches, which is the conservative answer: the initrd and the root carry the same Planarian build only at boot (both come from one generation); after a `nixos-rebuild switch` they differ, so a mismatch means the generations differ and the stage-2 object is the one to run (§5, "replace").
3. Every pinned map has the expected type, key size, value size and `max_entries` (`bpf_obj_get_info_by_fd`); `ring_bytes` equals the ring's `max_entries`.
4. There are exactly ten links, and each one's program name and attach target (`bpf_link_info`) match its entry in `PROBES`. Comparing each program's tag (`bpf_prog_info.tag`, a hash of its instructions) with the one recorded in META at load would make the skew check exact for the programs themselves; META carries the ten tags for that.
5. `LOST[0]` is read: nonzero means events were dropped while nobody consumed, and is reported as a lost event (global `lost`), exactly as a drop is today.

This check is for **version skew, not tamper**: root can rewrite anything (X-1), and the defence against anyone else is the `0700` pin directory (§3). The check says so in its error text.

The takeover decision is a pure function of the observed pin state and the binary's expectations, so it takes a property test (§8).

## 5. Takeover, in order

Stage 1 (the initrd watch, a unit ordered before every network tool in the initrd):

1. Load the object; set the BTF globals; write META; freeze it.
2. Attach all ten probes; pin every link and map.
3. Write `.watch attached` and the first footprints into `/run/planarian/footprint/` (the initrd's `/run` moves to stage 2, so they cross), with `.state`.
4. Keep reading the ring and updating footprints until the initrd's systemd stops it (at `initrd-cleanup`'s isolate, before the switch-root itself, reviewer). The process exiting leaves the probes and ring in place.

Stage 2 (`planarian-netwatch.service`, which today attaches afresh) first looks for pins:

- **adopt**: all checks pass. Open the pinned maps; read the ring from where the initrd left it (the backlog first, so events queued in the gap are attributed); load `.state` and the footprints; take the attach snapshot as today and treat anything unclaimed as `pre-attach`. No gap: the probes never detached.
- **replace** (a version mismatch only: `layout_version` or `object_sha256` differs, and the pins are otherwise consistent and `0700 root`): load and attach the stage-2 object *first* and pin it under a sibling directory, so the kernel never stops watching. Then, in this order (reviewer, #90):
  1. If the layouts are the same (only the object hash differs): drain the old ring to empty, apply everything in it, then unpin and remove the old set; only after that apply anything from the new ring. The old backlog is older than anything in the new ring, and applying in that order keeps events in the order they happened.
  2. If the layouts differ (`layout_version` or the `Event` shape): the new binary cannot parse the old ring, so its backlog is **reported as a loss** (global `lost`, which fails closed), the old set is unpinned, and the new ring is read from empty.
  Both sets observe for a moment, and applying an event twice changes nothing. After a `nixos-rebuild switch` the initrd is the previous generation's, so a restart of the stage-2 watch normally takes this path: replace is the ordinary case after a switch, not an exotic one (lane-nix).
- **refuse** (a pin missing, a link not live, the wrong owner or mode, an unknown entry, a check failure that is not a plain version mismatch): do not use any pin; remove what can be removed; attach afresh as today. Everything the initrd watch did is then unobserved, so the attach snapshot's `pre-attach` rule is the safety net, and `.state`'s claims are kept as today. **Fails closed.**

The same code is the answer to a restart of the stage-2 watch: pins mean a restart is no longer an unwatched window either. `systemctl stop planarian-netwatch` leaves the pins and the probes (the watch is "stopped" while the kernel still watches), and a hold on a failing tool still reads `.watch` as not attached, so it holds: unchanged from today.

**Units that cannot wait.** The initrd survivors need two orderings, not one (lane-nix): `After=planarian-netwatch-initrd.service` in the initrd (a drop-in or the unit's own entry), and the existing `After=planarian-netwatch.service` in stage 2, which orders a restart there; a stage-2 `After=` on an initrd unit orders nothing, since the initrd's systemd and units are gone after switch-root. The exceptions shrink to the initrd watch's own startup chain (what must run for the loader to work: the module loads, `systemd-udevd` if the BTF or bpffs needs it, the mount of bpffs). `nix/netwatch-unordered.nix` gets an `initrd` list for that chain, with the same cycle check as today, and `initrdSurvivors` empties out. A failure of one of those units before the watch attaches still holds traffic, as the spec says.

## 6. The ring, sized from a measured event count

The ring is fixed when the map is created in the initrd, so it must hold everything between the first probe and the stage-2 takeover. Today's 512 KiB holds about 560 events.

Measure first, then set the size:

1. The loader logs, at takeover, the number of events it drained from the backlog (`drained` in the first pass) and the final `LOST` value, as one journal line per boot. The count has to cover the whole stretch from the initrd watch's first probe to stage 2's drain: the events the initrd watch consumed before it stopped (logged by it at exit) plus the backlog stage 2 drains. This needs a loader option for the ring size and the log lines, which are product code, so the measurement boots wait on that change (A1–A3 do not).
2. lane-nix runs VM boots with a deliberately large ring (16 MiB) for the initrd configurations that matter: no initrd networking; `boot.initrd.network` with static addresses; with networkd in the initrd; a WireGuard or VLAN link set up in the initrd. It records `drained` for each.
3. `ring_bytes = round_up_pow2(max_over_configs(drained) × 928 × 4)`, with a floor of 512 KiB, and the number and the configurations recorded in this file.

The measurement boots include a long initrd (a wait on a disk-unlock prompt before switch-root, the reviewer's request), not only the quick ones. The 4× margin covers slower hardware and a longer initrd (disk unlock waiting on a person, which is the real unknown: nothing in the initrd generates netlink requests while it waits, so the count should not grow with time, and the measurement must include that case). The function (`ring_bytes_for(measured)`) is pure and has a property test: the result is a power of two, at least the floor, at least `measured × 928`, and monotone in `measured`.

An overflow is never silent: `LOST` counts it and takeover reports it as a lost event, which fails closed (global `unattributed`).

## 7. What this changes in the docs

- **B-26**: closes when this lands and the VM case passes. Its "pre-attach" interplay stays: a change the initrd watch missed because the initrd watch did not exist yet (the chain in §5) is still read as `pre-attach`.
- **B-22**: unchanged. The gaps in DNS and proxy observation are independent of when the watch attaches.
- A new row **B-29** only if a hook cannot be pinned (§2): that hook is then unwatched across switch-root and the row says which.
- `docs/bypasses.md` gains nothing else; a pin directory writable by root only adds no path that root did not already have (X-1).
- SPEC §12d: no change in wording. If the spec's "or the probes are gone" is meant to include "refused because the pins are not `0700 root`", that is one clause the owner can accept as is.

## 8. Tests

- **Property (pure):** `takeover_decision(observed, expected) -> {Adopt, Replace, Refuse}`. Adopt only when every check in §4 passes; any single inconsistency (wrong owner, mode, extra entry, a missing link, a map of the wrong shape, a nonzero `LOST` is not a refusal but a reported loss) is never Adopt; a hash-only mismatch with everything else consistent is Replace, never Adopt. Each check disabled in turn fails the property (rule 23).
- **Property (pure):** `ring_bytes_for` as in §6.
- **Unit:** META write-then-freeze; a META that was not frozen refuses.
- **VM (lane-nix, `nix/tests`):** boot with the initrd watch; (a) a network tool in the initrd makes a steering change and stage-2 footprints name it; (b) the same with the initrd watch's objects replaced by a different build (replace path: no event lost, old pins gone); (c) pins removed before stage 2 (refuse: the unit holds and `pre-attach` appears); (d) a pin directory made `0755` (refuse); (e) the A1 probe (does the bpffs instance cross); (f) a restart of the stage-2 watch keeps the probes and the backlog.

## 9. Unverified assumptions (each needs a VM or kernel check before code)

- **A1** *Result (lane-nix, #90 probe): the system's `/sys/fs/bpf` instance is not carried (failed); a bpffs of our own under `/run` is (passed).* §3 uses the second.
- **A2** *Result: all ten hooks held by pinned links and listed in stage 2 after the loader had exited, the two kprobes as `perf_event` links (so §2's option 2 works on this kernel); the other eight are fentry/fexit `tracing` links. Module BTF for nfnetlink is present in the initrd once the module is loaded, so option 1 is also available.* **Still open (A2b):** the probe used bpftool; whether aya can create or pin a perf-event link (or I make the raw `BPF_LINK_CREATE` call) is the next check, and it is mine (a loader spike, no product change).
- **A3** *Result: the initrd unit's cgroup is `0::/system.slice/initrd-probe.service`, the same shape as stage 2, so `unit_of_cgroup` should map it.* Confirm with the real watch when it runs in the initrd.
- **A4** *Result: `/run` files written in the initrd survived, and the `CLOCK_BOOTTIME` stamp continued (5.00 in the initrd, 24.27 after), so the freshness window holds.* Not covered: an initrd that takes much longer (disk unlock waiting on a person); the measurement boots in §6 should include one.
- **A5** A new process resumes a pinned ring where the last one stopped. The consumer position of a `BPF_MAP_TYPE_RINGBUF` lives in the ring's own mapped page, not in the process, so a fresh mapping of the pinned map should see it. If a VM shows otherwise, the fallback is to treat the whole ring as unread, which re-applies events already applied and is harmless (applying an event twice changes nothing).

## 10. What I need from lane-nix

- The initrd unit for the watch (`boot.initrd.systemd.services.planarian-netwatch-initrd`), with the binary and `netwatch.bpf.o` in the initrd's closure, ordered before every network tool the initrd runs, and the `initrd` list in `nix/netwatch-unordered.nix` for its startup chain with the cycle check.
- A mount unit for `/run/planarian/netwatch-bpf` (`Type=bpf`, `Options=mode=0700`), in the initrd before the initrd watch and in stage 2 before `planarian-netwatch.service`; `module-eval` asserts the options.
- The VM boots in §6 (large ring, several initrd configurations) and the numbers back to me for §6's formula.
- `module-eval` assertions: a scripted initrd gets no initrd watch and no initrd network tools (spec); the systemd initrd gets the unit and its ordering.
- The export: a field saying whether the initrd watch is configured, so the stage-2 watch and the posture scripts know whether `.watch` from the initrd is expected.

## 11. Order of work

1. A1, A2, A3 and A4 are probed (§9): the layout changed (own bpffs under `/run`), nothing else did. A2b, aya's ability to pin the kprobe links, is next, as a loader spike with no product change; if aya cannot and a raw call is needed, say so before building.
2. The pure pieces with their properties: `takeover_decision`, `ring_bytes_for`. No kernel needed.
3. The loader: pin on first load, META, adopt / replace / refuse, `drained` logging.
4. lane-nix's unit, ordering and `module-eval` assertions.
5. The measured ring size and the VM cases in §8; B-26 closed.

Each step is a separate PR; steps 3 and 4 need a catalog run (they decide what is held and when).
