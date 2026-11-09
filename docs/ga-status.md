# Phase A gate (GA) status

Where Planarian stands against the Phase A exit gate (SPEC §4), with the
evidence for each criterion and how to reproduce it. Updated 2026-11-09,
from one commit and two runs on it: **`577edb3`** (main after #96, the
freeze commit), the whole VM catalog, "VM tests" run **42554727307**
(dispatched `catalog: true`, no ids; 129 of 129 jobs succeeded), and CI run
**42554606293** (`rust`, `nix`, `kani`: all succeeded).

What this refresh covers: rule 19(f), the catalog and proof figures, and the
bypass-register counts. The rows for (a)–(e) and the criteria this file did
not re-measure (marked) are as of the 2026-11-01 version and are the
coordinator's to update.

## Summary

**The gate is not called.** It is the owner's to call, once every box on
the epic's gate checklist (issue #7) is ticked. Where rule 19 stands:

| Step | State |
| --- | --- |
| (a) Reconcile the close-out review | Done (as of 2026-11-01): `docs/review-reconciliation.md` |
| (b) B-20 (I24) | Closed (`8231a07`; as of 2026-11-01) |
| (c) Documentation sweep | Done (as of 2026-11-01) |
| (d) §28's required changes | As of 2026-11-01 (not refreshed here): done in PR #6 except what issue #7 lists |
| (e) §15 harness contract, §17a accounting checks | Done (as of 2026-11-01; the strict runs of 2026-11-09 below enforce it): runners nonzero on ERROR/FAIL/PARTIAL and on an UNSUPPORTED must-pass or acceptance entry without a `docs/deviations.md` waiver; CI strict; the accounting checked |
| (f) One whole VM catalog run, this file from it | **Done on `577edb3`: run 42554727307, 129 of 129 jobs succeeded** (below) |

The bypass register (`docs/bypasses.md`, `planarian-gym verification`) at
`577edb3` has no open High row; open Medium: B-4, B-8, B-9, B-10, B-18,
B-19, B-22, B-23, B-26 (nine); open Low: B-28, B-29, B-30 (three). B-23 is
partly closed by #96: raw units shipped through `systemd.packages` are
classified at build time; its still-open parts, which fail open, are listed
in the row.

| Criterion (SPEC §4, Q8) | Status at `577edb3` |
| --- | --- |
| 1. The demonstration | Fake harness: CI's `demo.sh --harness fake` step succeeded. VMs: the four `ga-demo` jobs of run 42554727307 succeeded (`svc-killed`, `svc-misconfig-listen-address`, `crash-activating-bad`, `crash-daemon-restart-reconciles`) |
| 2. ≥ 60% of the catalog cleared deterministically | Fake harness: **140 of 140 PASS (100%)**, of which the metrics block counts 139 as runnable, all fully checked (CI run 42554606293, `planarian-gym run --strict`; the one entry the metrics leave out is `fake-assumptions-conformance`, which runs the conformance suite and has no simulation). VMs: **all 101 `catalog` jobs of run 42554727307 succeeded**; a job fails on ERROR, FAIL, PARTIAL, or an UNSUPPORTED without a waiver, so none of the 101 did. The per-entry verdict files are not read here: the two waived UNSUPPORTED entries of 2026-11-01 (below) are expected to be UNSUPPORTED still |
| Q8, the personal-profile gate | Not re-measured on 2026-11-09. Value at 2026-11-01 (`6ad8521`): every must-pass and intent entry passes on each harness it lists, except `quiet-reference-workload`, whose benchmark had not run since R13 changed it (#8); no acceptance entry UNSUPPORTED; ≥ 95% cleared |
| 2. Every bad generation reverted | **Yes**, on the entries that activate a bad generation: `gen-bad-switch`, `svc-misconfig-listen-address` and `crash-activating-bad` (fake and VM) all PASS on the fake harness (CI run 42554606293) and their VM `catalog` jobs succeeded (run 42554727307; the last two also as `ga-demo` jobs); `revert-fails` and `revert-fails-interlock-survives-compaction` (failed reverts) likewise. Not measured: `desktop-boot-fails-rollback` is a waived UNSUPPORTED (its row in `docs/deviations.md`), so a bad boot entry reverted by rollback is cleared nowhere |
| 2. The manifest-weakening fault rejected | In the catalog (`manifest-weaken-via-proposal` on both harnesses, `manifest-weaken-out-of-band` on VMs), passing in the runs above |
| 2. Zero gamed successes | Guarded: an unchecked key is PARTIAL and fails; UNSUPPORTED is never a pass |
| 2. Unnecessary interventions on the intent cases = 0 | 0 on the 10 intent entries the fake harness runs (CI run 42554606293) |
| 3. `policy` proofs pass in CI | Yes: Verus verifies 17 / 54 / 52 obligations in `schema` / `policy` / `txn` with 0 errors; Kani: two runs, 4 and 5 harnesses, 0 failures (`nix` and `kani` jobs, run 42554606293) |
| 4. Baselines: the invisibility budget (§21) | **Not measured on the current benchmark at `577edb3`, nor at `6ad8521`**: `bench.nix` reads cgroup accounting and per-frame p99 since R13, and that run is #8's. The pre-R13 figures (idle 0.063% of one core, 7.9 MB resident, 1.58 wakeups/s; game median p99 38.5 ms, a proxy R13 removed) are under "Earlier results", with no date recorded there |
| 4. Baselines: the verification ratio (§17a) | **Trust count 37; internal-unproven 5; global d:a 52:63** (`planarian-gym verification`, `rust` job, run 42554606293) |

## The catalog at `577edb3`

166 entries: 140 list the fake harness, 101 list VMs (76 on
both), 25 VM-only, and `quiet-reference-workload` lists only the benchmark.

| Harness | Result at `577edb3` |
| --- | --- |
| Fake (`planarian-gym run --strict`, CI run 42554606293) | 140 PASS of 140 entries that list the fake harness (the other 26 are not fake). The metrics block counts 139 of them: it counts an entry only when the simulation returns a run, and `fake-assumptions-conformance` (a matrix entry that runs the conformance suite, with no simulation) is not counted; it passed. Repair rate 16 of 16; 0 unnecessary interventions on 10 intent entries |
| VMs ("VM tests" run 42554727307, one job per entry) | 101 of 101 `catalog` jobs succeeded |
| The run's other jobs | `prebuild`, `catalog-ids`, `firecracker`, `installer`, `vm-generations`, `vm-netsec`, `vm-netwatch`, `vm-posture`, `vm-runtime`, `vm-unitclass-systemd`, 4 `ga-demo`, 14 `gym-smoke`: all succeeded (129 jobs in all) |
| Benchmark | `quiet-reference-workload`: not run here |

The UNSUPPORTED verdicts of the 2026-11-01 catalog were two `repair`
entries, which the harness contract does not gate, each with a row in
`docs/deviations.md` ("Harness waivers"): `storage-nix-full-gc` and
`desktop-boot-fails-rollback`. Those rows are unchanged.

Between the 2026-11-01 evidence and this one the catalog gained entries and
many fixes merged (among them the unmanaged-tool rule, #93, and the raw-unit
classification, #96); the whole-catalog run above is the first to run all of
them together on one commit. One catalog run on
the way (a #96 candidate, 42534118414) had one failing job, a stall of the
gym judge's unbounded `systemctl --user --machine=` call after a session
drop; it passed on a single-entry re-run, and that call's bounding is on the
post-audit list.

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
