# Phase A gate (GA) status

Where Planarian stands against the Phase A exit gate (SPEC §4), with the
evidence for each criterion and how to reproduce it. Updated 2026-10-28.

## Summary

| Criterion | Status |
| --- | --- |
| 1. The demonstration | **Passes**, on the fake harness and on VMs (CI, KVM) |
| 2. ≥ 60% of the catalog cleared deterministically | **54 of 71 (76%)** on the fake harness, every key checked |
| 2. Every bad generation reverted | Yes on the fake harness; on VMs for the demonstration's bad change and the crash entries run so far |
| 2. The manifest-weakening fault rejected | Yes (`manifest-weaken-via-proposal`) |
| 2. Zero gamed successes | Guarded: see "Passes that prove something" |
| 2. Unnecessary interventions on the intent cases = 0 | 0 of 4 |
| 3. `policy` proofs pass in CI | Yes: `ci.yml`'s `nix` job runs the Verus check |

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

Fake harness (`cargo run -p planarian-gym -- run`, also in CI):

| Result | Entries |
| --- | --- |
| PASS (every key in `required_post` checked) | 54 |
| PARTIAL, FAIL, UNSUPPORTED | 0 |
| VM-only (the fake cannot run them) | 17 |

The 60% is counted over the whole catalog (71 entries), with the 17 VM-only
entries as not cleared.

The 17 VM-only entries run on the VM harness (`nix run .#gym-vm`, or
`vm.yml` by hand in CI). Of those, `svc-killed-defer-to-systemd` passes;
`desktop-boot-fails-rollback` is UNSUPPORTED there, because the test VM boots
its kernel directly and so never boots a published generation; the rest are
not yet scored on VMs. Entries that run on both harnesses also pass on VMs
where tried: the demonstration's four, `crash-activating-good`, and the Wi-Fi
selection entry `policy-daemon-wifi-runtime` (simulated radios, hostapd,
NetworkManager and wpa_supplicant). The desktop entries run against a stand-in greeter and
compositor (docs/AGENTS.md), not COSMIC.

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

Still to look at: `crash-stop-and-suppress`, `drv-bind-fails-restores-previous`
(a real bind of vfio-pci fails at once, so there is no Checking state),
`net-gateway-down` (a dropped gateway makes probes time out, so the client
is Unknown rather than Failed), `storage-budget-unsatisfiable`,
`suspend-resume`, and `storage-nix-full-gc` (the test VM has no separate
`/nix` filesystem).

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
(runtime, generations, installer) and the four GA demonstration entries on
VMs; the whole VM catalog by hand (about 70 runner minutes per push for
`vm.yml`; several hundred for the whole catalog).

## Not part of the gate, still open

- The Asterinas VM target (allowed to stay red; not started).
- Booting into a published generation in a VM (needs a VM that boots through
  its own boot loader).
- COSMIC itself in the gym VM.
