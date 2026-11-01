# Phase A gate (GA) status

Where Planarian stands against the Phase A exit gate (SPEC §4), with the
evidence for each criterion and how to reproduce it. Updated 2026-11-01,
from one commit and one run: **`6ad8521`, "VM tests" run 110**
(whole catalog, dispatched 2026-11-01 01:30 UTC), and CI run 140 on the
same commit.

## Summary

**The gate is not called.** It is the owner's to call, once every box on
the epic's gate checklist (issue #7) is ticked. Where rule 19 stands:

| Step | State |
| --- | --- |
| (a) Reconcile the close-out review | Done: `docs/review-reconciliation.md` |
| (b) B-20 (I24) | Closed (`8231a07`) |
| (c) Documentation sweep | Done |
| (d) §28's required changes | Done in PR #6 except what issue #7 lists: §12f *Rollbacks* (the Oct 31 amendment, three new §15 cases), P19, C18 (#9); C10, C19, P21, P24 and two remainders (#10); P11 and module-eval assertions (#11); deviations for anything left (#12) |
| (e) §15 harness contract, §17a accounting checks | Done: runners nonzero on ERROR/FAIL/PARTIAL and on an UNSUPPORTED must-pass or acceptance entry without a `docs/deviations.md` waiver; CI strict; the accounting checked (`62fb19e`, `82a76ab`) |
| (f) One whole VM catalog run, this file from it | Run 110 on `6ad8521` (below). To be repeated on the closing commit once #8–#11 have merged (#12) |

The bypass register has no open High row; six Medium rows stay open, none
for Phase A.

| Criterion (SPEC §4, Q8) | Status at `6ad8521` |
| --- | --- |
| 1. The demonstration | **Passes** on the fake harness (CI run 140) and on VMs (run 110, the four `ga-demo` jobs) |
| 2. ≥ 60% of the catalog cleared deterministically | **154 of 156 (98.7%)**: 130 of 130 PASS on the fake harness; 99 PASS and 2 UNSUPPORTED of 101 on VMs; every key checked |
| Q8, the personal-profile gate | Every must-pass and intent entry passes on each harness it lists, except `quiet-reference-workload`, whose benchmark has not run since R13 changed it (#8); no acceptance entry UNSUPPORTED; ≥ 95% cleared |
| 2. Every bad generation reverted | Yes, on both harnesses |
| 2. The manifest-weakening fault rejected | Yes (`manifest-weaken-via-proposal`; `manifest-weaken-out-of-band` on VMs) |
| 2. Zero gamed successes | Guarded: an unchecked key is PARTIAL and fails; UNSUPPORTED is never a pass |
| 2. Unnecessary interventions on the intent cases = 0 | 0 on all 14 intent entries |
| 3. `policy` proofs pass in CI | Yes: Verus verifies 17 / 54 / 52 obligations in `schema` / `policy` / `txn`, and the check fails when that differs from `docs/verification-ratio.toml`; Kani 4 + 4 harnesses (`txn`, `exec`) |
| 4. Baselines: the invisibility budget (§21) | Not re-measured: `bench.nix` now reads cgroup accounting and per-frame p99 (R13); its run is #8's. The last figures (before R13, proxy p99) are under "Earlier results" |
| 4. Baselines: the verification ratio (§17a) | **Trust count 37; internal-unproven 5; global d:a 52:63** (`planarian-gym verification --gate`, clean) |

## The catalog at `6ad8521`

156 entries: 130 run on the fake harness, 101 on VMs (75 on both), 25
VM-only, and `quiet-reference-workload` on the benchmark.

| Harness | PASS | UNSUPPORTED | FAIL / PARTIAL / ERROR | Not run there |
| --- | --- | --- | --- | --- |
| Fake (`planarian-gym run --strict`, CI run 140) | 130 | 0 | 0 | 25 VM-only, 1 benchmark |
| VMs ("VM tests" run 110, one job per entry) | 99 | 2 | 0 | 55 fake-only |
| Benchmark | — | — | — | `quiet-reference-workload`: to run (#8) |

The two UNSUPPORTED verdicts are `repair` entries, which the harness
contract does not gate, and each has a row in `docs/deviations.md`
("Harness waivers"): `storage-nix-full-gc` (the test VM's store is the
host's; it passes on the fake) and `desktop-boot-fails-rollback` (the test
VM boots its kernel directly; VM-only, so not cleared anywhere).

Found on the way to this run, and fixed with a test that fails without the
fix: a takeover acked an op its fenced but still running predecessor had
just acked itself, which left the transaction in flight
(`crash-slow-worker-overlap`, run 109; `6ad8521`). Open, for the owner: in
the same entry the restarted daemon's startup revert stalls for 15
minutes before the watchdog finishes it (PR #6).

## Earlier results

What follows is history: results on earlier commits and catalogs, kept for
what each run found. None of it is this gate's evidence.

| Criterion | Status then |
| --- | --- |
| 4. Baselines: the invisibility budget (§21) | Idle (VM, 5 min, run "Invisibility budget" #2): **0.063% of one core, 7.9 MB resident, 1.58 wakeups/s** (targets < 0.5%, < 50 MB), sampled from two main PIDs. Game (run "Invisibility budget" #5, Xonotic `the-big-keybench` timedemo on llvmpipe, five runs per condition): no measurable difference with Planarian stopped, idle, or busy; median p99 38.5 ms in all three (Mann–Whitney p = 1.0). That p99 was the engine's one-second minimum, a proxy R13 removed. |

## 1. The demonstration (history)

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

## 2. The catalog on 2026-10-29 (history)

The results then (v4.4 catalog: 101 entries):

| Harness | PASS | UNSUPPORTED | FAIL / PARTIAL | Not run there |
| --- | --- | --- | --- | --- |
| Fake (`cargo run -p planarian-gym -- run`, in CI on every push) | 81 | 0 | 0 | 19 VM-only, 1 benchmark |
| VMs (`vm.yml`, all 76 VM entries on KVM) | 74 | 2 | 0 | 24 fake-only, 1 benchmark |
| Benchmark (`bench.yml`) | 1 | — | — | `quiet-reference-workload`: run #5 (proxy p99; see criterion 4) |

**Not final then:** the VM verdicts came from the full run on 8f3f296 (71
PASS) plus re-runs of the entries fixed afterwards on 06560cb and 6e72eff
(`storage-journal-btrfs-reuse`, `residue-oom-kill`, and
`policy-daemon-session-drop-rebind`, whose first run hung when its VM
froze). Later commits changed the journal (I18's proof moved the chain
check into `txn::chain`), so a full run on the head is dispatched; this
table becomes final when it passes.

Cleared on at least one harness: 100 of 101. Not cleared:
`desktop-boot-fails-rollback` (UNSUPPORTED: the test VM boots its kernel
directly, never a published generation; a repair entry, VM-only).
`quiet-reference-workload` passes on its own harness (benchmark run #5). UNSUPPORTED on VMs but
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
| Every must-pass and intent entry (81) passes on each harness it lists | Yes on the fake and on VMs; `quiet-reference-workload` (must-pass) passes on the benchmark, with the proxy caveat |
| No acceptance entry (47) UNSUPPORTED on VMs without a deviation | Yes: the two UNSUPPORTED entries are repair entries, neither tagged acceptance |
| At least 95% of entries cleared on at least one harness | 100 of 101 (99%) |

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
