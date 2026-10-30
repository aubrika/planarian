# Phase A gate (GA) status

Where Planarian stands against the Phase A exit gate (SPEC §4), with the
evidence for each criterion and how to reproduce it. Updated 2026-10-29.

## Summary

**No open High row under SPEC v4.5** (installed 2026-10-29). §17b holds every
gate while a High row in `docs/bypasses.md` is open. Both were closed on
2026-10-30 after their VM entries passed: B-1 (agents are their own
principals, `agent-run-own-principal`) and B-2 (the floor reads the whole
configuration's package set, `floor-service-package-fix`). The remaining rows
are Medium and Low. The criteria below are re-confirmed by the next full VM
catalog run on head.


| Criterion | Status |
| --- | --- |
| 1. The demonstration | **Passes**, on the fake harness and on VMs (CI, KVM, on every push) |
| 2. ≥ 60% of the catalog cleared deterministically | **99 of 101 (98%)**, provisional (see §2): 81 PASS on the fake harness, 74 PASS and 2 UNSUPPORTED on VMs, every key checked; the 101st is the invisibility benchmark, still running |
| Q8, the personal-profile gate (owner decision) | **Met, provisionally:** every must-pass and intent entry passes on each harness it lists (the benchmark's entry pending); no acceptance entry is UNSUPPORTED on VMs; 98% cleared (≥ 95%). Final once the whole VM catalog passes on one commit (run dispatched 2026-10-29 on 5368267) |
| 2. Every bad generation reverted | Yes, on both harnesses, including a full /boot at publish and a daemon killed mid-change |
| 2. The manifest-weakening fault rejected | Yes (`manifest-weaken-via-proposal`; `manifest-weaken-out-of-band` on VMs) |
| 2. Zero gamed successes | Guarded: see "Passes that prove something"; entries a harness cannot run faithfully are UNSUPPORTED there, never passed |
| 2. Unnecessary interventions on the intent cases = 0 | 0, on the 8 intent entries the fake harness runs and the VM runs of all 12 |
| 3. `policy` proofs pass in CI | Yes: `ci.yml`'s `nix` job runs the Verus check |
| 4. Baselines: the invisibility budget (§21) | Idle (VM, 5 min, run "Invisibility budget" #2): **0.063% of one core, 7.9 MB resident, 1.58 wakeups/s** (targets < 0.5%, < 50 MB). The game frame-time comparison has not completed yet: the first runs found no Xonotic demo (harness fix pending a run). |
| 4. Baselines: the verification ratio (§17a) | **Trust count = 32; global d:a = 47:50 (28:43 at GA; then four proved obligations mapped to I6 and I12, I21–I23 added for ten more, and I18's hash chain proved)** (`planarian-gym verification`, a CI ratchet; per invariant in `docs/verification.md`) |

## 1. The demonstration

`crates/gym/demo.sh` runs the four steps as catalog entries:

| Step | Entry | Fake harness | VM (CI, KVM) |
| --- | --- | --- | --- |
| A fault is repaired | `svc-killed` | PASS | PASS |
| A bad configuration is reverted | `svc-misconfig-listen-address` | PASS | PASS |
| `planariad` killed during activation; the watchdog recovers | `crash-activating-bad` | PASS | PASS |
| The daemon restarts, reconciles the journal and explains it | `crash-daemon-restart-reconciles` | PASS | PASS |

The first VM run of the bad-configuration step committed the change, which was
correct for what the VM did: its web service ignored the listen-address option,
so the "bad" change broke nothing. The fixture now binds the configured
address, and the step passes. (CI run "VM tests" #5: all four steps, plus the
runtime, generations and installer VM tests.)

## 2. The catalog

The latest results, 2026-10-29 (v4.4 catalog: 101 entries):

| Harness | PASS | UNSUPPORTED | FAIL / PARTIAL | Not run there |
| --- | --- | --- | --- | --- |
| Fake (`cargo run -p planarian-gym -- run`, in CI on every push) | 81 | 0 | 0 | 19 VM-only, 1 benchmark |
| VMs (`vm.yml`, all 76 VM entries on KVM) | 74 | 2 | 0 | 24 fake-only, 1 benchmark |
| Benchmark (`bench.yml`) | — | — | — | `quiet-reference-workload`: run #5 in progress |

**Provisional:** the VM verdicts come from the full run on 8f3f296 (71
PASS) plus re-runs of the entries fixed afterwards on 06560cb and 6e72eff
(`storage-journal-btrfs-reuse`, `residue-oom-kill`, and
`policy-daemon-session-drop-rebind`, whose first run hung when its VM
froze). Later commits changed the journal (I18's proof moved the chain
check into `txn::chain`), so a full run on the head is dispatched; this
table becomes final when it passes.

Cleared on at least one harness: 99 of 101. Not cleared: 
`desktop-boot-fails-rollback` (UNSUPPORTED: the test VM boots its kernel
directly, never a published generation; a repair entry, VM-only) and
`quiet-reference-workload` (pending the benchmark). UNSUPPORTED on VMs but
cleared on the fake: `storage-nix-full-gc` (the test VM's Nix store is the
host's). Fake-only by deviation: `suspend-resume` and
`storage-enospc-during-build` (docs/deviations.md). Now run on VMs that
were not before: `storage-journal-btrfs-reuse` (a btrfs journal disk,
snapshot and churn) and `residue-oom-kill` (a real cgroup OOM kill). The
desktop entries run against a stand-in greeter and compositor
(docs/AGENTS.md), not COSMIC.

**Q8, the personal-profile gate** (owner decision, catalog-review §9),
checked against these results:

| Condition | Result |
| --- | --- |
| Every must-pass and intent entry (81) passes on each harness it lists | Yes on the fake and on VMs; `quiet-reference-workload` (must-pass, benchmark) pending |
| No acceptance entry (47) UNSUPPORTED on VMs without a deviation | Yes: the two UNSUPPORTED entries are repair entries, neither tagged acceptance |
| At least 95% of entries cleared on at least one harness | 99 of 101 (98%); 100 of 101 if the benchmark passes |

The history of the VM runs follows; each found real bugs.

### The VM catalog (CI run "VM tests" #7, 2026-10-28)

The first run of all 62 VM entries on KVM. The jobs show red because their
last step, uploading artifacts, hit the repository's storage quota; the
verdicts are read from the logs.

| Verdict | Entries |
| --- | --- |
| PASS | 36 |
| UNSUPPORTED (`desktop-boot-fails-rollback`) | 1 |
| FAIL | 21 |
| PARTIAL | 3 |
| Hung (`suspend-resume`: the VM did not come back from suspend) | 1 |

Most failures were the VM harness, not Planarian, and are fixed for the
next run: faults timed to `Staged`, which the real backend never journals
(staging and the build happen before the transaction is prepared; the
daemon now pauses before the call so the fault lands exactly); a knob read
only at start, and one-off knobs that outlived a restart; a local blocked
port that timed out instead of refusing; a kill timed to a slow
activation's call that fired only after the call returned; three judge
keys never implemented.

One was a real Planarian bug: on systemd 260, `loginctl show-session` with
a comma-separated `--property` list prints nothing, so Planarian never saw
a login session, on any machine. The graphical-session deadline, per-user
units and the session inputs to authorization were inert. Fixed (one
`--property` per property, with a test); six desktop and user-unit entries
failed on it. Untracked files left out of a build are now reported (§9
step 1), which no entry had noticed.

### The whole VM catalog again (CI run "VM tests" #18, 2026-10-29)

| Verdict | Entries |
| --- | --- |
| PASS | 50 |
| UNSUPPORTED | 5 |
| FAIL | 6 |
| Hung | `suspend-resume` (the VM did not wake) |

UNSUPPORTED on the gym VM, with the reason, and still run on the fake
where they can be: `desktop-boot-fails-rollback` (the VM boots its kernel
directly, never a published generation), `storage-nix-full-gc` and
`storage-enospc-during-build` (the VM's Nix store is the host's: it cannot
fill or be collected), `storage-journal-btrfs-reuse` (the VM's journal is
ext4), and `policy-daemon-wifi-runtime` (a mistake in the plan, fixed:
it passed before and runs again).

What the runs since #11 found:

- Real Planarian bugs, fixed, each with a test that fails without the fix:
  notices stopped reaching the journal once 64 had accumulated; a file
  added during a build was not reported as left out; binding a device to
  another driver never worked on real hardware (the current driver was not
  unbound first, and generic drivers such as vfio-pci bind only through
  `driver_override`).
- Gym VM harness and fixtures, fixed: the step watchers and the slow
  activation hook ran without a PATH, so faults timed into a change never
  happened; the journal's and /boot's own filesystems were never mounted;
  no system profile; pipewire restarted itself and had no link to its sound
  card; S3 suspend never resumed; held-down entries judged statuses frozen
  at the crash; the judge picked an arbitrary collection for `emergency`.
- Open: `net-gateway-down` expects an incident when traffic to the gateway
  is dropped, but SPEC §10 makes a timed-out probe Unknown, never Failed,
  so Planarian (rightly, by the spec) opens none. A question for the owner.

### The whole VM catalog, third run (CI run "VM tests" #24, 2026-10-29)

62 VM entries (`suspend-resume` moved to the fake; `net-upstream-down`
added):

| Verdict | Entries |
| --- | --- |
| PASS | 56 |
| UNSUPPORTED | 4: `desktop-boot-fails-rollback`, `storage-nix-full-gc`, `storage-enospc-during-build`, `storage-journal-btrfs-reuse` |
| FAIL | 2: `drv-unbound-audio`, `storage-boot-full-publish` (fixed since: a revert no longer fails on a disk it cannot free) |

Real Planarian bugs this round, each with a test that fails without the
fix: status requests ran the probes, which starved the repair loop (a
killed service was restarted 100 s late); a failed publish left the boot
default naming the candidate; a driver that binds but cannot drive the
device passed the check; a revert failed on a full /boot it could not
free. Owner decision: dropped traffic to an external dependency stays
Unknown and is said (`net-gateway-down`); the refused case is
`net-upstream-down`.

The fake harness: 57 of 72 entries, all PASS (the rest are VM-only).

### Passes that prove something

- The judge fails an entry if any key goes unchecked (PARTIAL fails CI), if a
  run has no status samples, or if a key names a unit the machine never had.
- `cargo test -p planarian-gym` runs real entries, alters their evidence the
  way a bug would (a restart while interlocked, two owners of one epoch, a
  lost suppression after compaction, …) and expects the judge to fail.
- Mutations of the kernel were caught by the entries: no quiescence on
  takeover (three crash entries fail), and stopping before the suppression is
  journaled (`intent-user-stops-service` fails).
- Fixes that came out of this: two fake-harness fidelity bugs (slow HTTP made
  TCP probes time out; the slow-worker crash never overlapped), a catalog
  bug (`service:graphical-session` named a unit that does not exist), and
  the gym VM's web service ignoring its listen address.

## 3. Proofs and CI

`ci.yml` on every push: fmt, clippy (also with the gym's hooks), the tests,
the fake catalog and the GA demonstration, the dependency boundaries, the
Verus proofs, the Kani harnesses. `vm.yml` on every push: the NixOS VM tests
(runtime, generations, posture, installer), the four GA demonstration entries on
VMs, and three entries that guard the gym harness itself (a step timed into
a change, a user session with a device, a real /boot); the whole VM catalog
by hand (about 70 runner minutes per push for
`vm.yml`; several hundred for the whole catalog).

## Not part of the gate, still open

- The Asterinas VM target (allowed to stay red; not started).
- The Firecracker microVM target (`nix build .#firecracker-target`, CI job `firecracker`, non-gating): boots Planarian under Firecracker and checks one repair.
- Booting into a published generation in a VM (needs a VM that boots through
  its own boot loader).
- COSMIC itself in the gym VM.
