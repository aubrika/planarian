# v4.6 review reconciliation

SPEC v4.6 rule 19(a): before work on a finding, confirm it is still open
at the working head, and record the commit that closed any that are not.
Reconciled 2026-10-30 at head `b219d81` against:

- **The consolidated handoff** (R01–R16, S01–S07; recommendations D01–D08),
  baseline `bd6d24d`, with file:line evidence for each R item.
- **SPEC v4.6 §28**, which also cites the four Oct 29 code audits (ids C,
  P, D, K, H). That review document was not available to this session, so
  its items are reconciled from §28's prose and the code, not from its
  file:line evidence. Where §28 pairs an audit id with an R or S id, the R
  or S evidence was used.

Status: **open** (the defect or gap is present at `b219d81`), **partly**
(some of it is closed; the rest is open, as stated), **closed** (with the
commit), or **decided** (a specification decision v4.6 makes; the
implementation it requires is listed as open or closed separately).

## Repository findings (R)

| Id | Finding | At `b219d81` | Evidence at head | Work |
| --- | --- | --- | --- | --- |
| R01 | Boot-only publication has an uncovered crash window | open | `kernel.rs` publishes the one-shot while the transaction says `Built`; no `Publishing` state exists | §28: `TxnState::Publishing`, crash-table row |
| R02 | Security-floor advancement is outside durable commit | open | the floor is derived in `exec` after `Committed`, not in the kernel's commit; the watchdog and boot-only paths skip it | I25 |
| R03 | A stopped override erases the disruption it causes | open | `derive.rs`: `SetOverride` sets `disruption = None` and narrows affected units to the unit | §11 equivalent effects |
| R04 | Existing-generation operations omit activation consequences | closed | `plan_existing` takes the target's dry activation and its recorded override content; a dry activation without a plan is `ActivationUnknown` | §11 equivalent effects |
| R05 | Launcher-created agents are outside failure-posture enforcement | closed | `start_agent` units run in `planarian-agents.slice`, ordered after `planarian-ready.target`, refused while a failure class is raised, limited per unit and per uid; the posture stops the slice | §12d `planarian-agents.slice` |
| R06 | Probe timeouts do not bound total execution time | closed | `probe.rs`: resolution, connect and every read share one deadline; the batch returns by its allowance and a straggler is `Timeout` | §10 whole-probe deadline |
| R07 | Already-degraded units can lose more health without blocking commit | open | `host.rs`'s check compares unit status, skips units not Running before | §9 per-probe post-check |
| R08 | Rejected release requests still replenish repair budgets | open | `core.rs`: `LiftOverride` calls `incidents.human_acted` whatever the result | §13 |
| R09 | Unauthorized callers can reach expensive prebuild work | open | `user_submit` queues `prebuild_job` before `decide` runs | §12 admission before work |
| R10 | Failed dry activation is accepted as usable risk evidence | open | `nixos.rs` parses `dry-activate` output without checking its exit or timeout | §9 step 3, rule 21 |
| R11 | Override replacement is check-then-rename, not compare-and-swap | closed | `swap_override` compares and renames under an exclusive `flock` on `planarian/`; promote, restore and collect under `profile.lock`; `txn/<id>/` by exclusive `mkdir`, swept after the checkpoint; the override store pruned (C5) | I23 under `flock`; X-12 |
| R12 | The VM catalog runner exits 0 after total build failure | closed | `run-vm.sh` and `vm.yml` apply `nix/gym/harness-contract.py`: nonzero on ERROR, FAIL, PARTIAL, and on an UNSUPPORTED must-pass or acceptance entry without a waiver row in `docs/deviations.md` ("Harness waivers") naming entry and harness | §15 harness contract |
| R13 | The benchmark cannot establish the full invisibility claim | closed: bench run 41338935488 (below) | idle from cgroup accounting over every Planarian service and op unit (CPUUsageNSec; RSS and wakeups of every process in them); p99 from MangoHud's per-frame log only, no fallback | §15, §21 |
| R14 | The verification ratchet can inflate counts or lose coverage | closed | duplicate invariants and obligations rejected; a baseline invariant must still be accounted; a discharged name must be a `proof fn`, a function with `ensures` inside `verus!` or a `#[kani::proof]` harness; `[verifier]` counts tie the Verus obligations to the Verus run, which fails on a mismatch | §17a accounting checks |
| R15 | Unsupported regressions can remain green | closed | `ci.yml` runs the fake catalog `--strict`, which applies the same rule and the same `docs/deviations.md` table to the fake harness | §15 harness contract |
| R16 | Gate and bypass documentation lag the implementation | partly | the register was reconciled through B-19/X-11 (cae89a9 … 805cd1c); `ga-status.md`, `guarantees.md`, `AGENTS.md` still lag | rule 19(c) sweep |

## Specification decisions (S)

| Id | Decision | v4.6 | Implementation at `b219d81` |
| --- | --- | --- | --- |
| S01 | One floor-qualified automatic boot fallback | decided: the publishing generation, never `known_good` automatically (§12 step 7) | open (with R01) |
| S02 | Early admission separate from boot confirmation | decided: two milestones (§10) | open |
| S03 | Liveness of intentionally parked states | decided: `Built` bounded at 24 h; `AwaitingBoot` unbounded and reported (§12f, I12) | open |
| S04 | An operable Phase A approval topology | decided: §11 and §16 text | docs only |
| S05 | Which sessions carry a graphical expectation | decided: seated sessions only (§10) | open |
| S06 | External-outage attribution needs a traversable edge | decided: Requires or Diagnostic ≥ 0.7; the module rejects weaker (§10) | open |
| S07 | Normative drift: token restart semantics, I6's list | decided: tokens die with the daemon; I6 lists `Checking` and `Publishing` | open |

## Found since the review

| Id | Finding | Status |
| --- | --- | --- |
| B-20 | A second `agent run` under a running agent's name rebinds its authority (I24) | open: registered and fixed first (rule 19(b)) |
| — | Approval at a terminal had no effect on the VM harness (the `script` wrapper) | fixed in `b219d81`; VM confirmation pending |
| — | Collected generations kept their build and `gen-<n>` GC roots, so collection freed nothing | fixed in `805cd1c` |

## Closed since the reconciliation

The tables above are the snapshot at `b219d81`. These have closed since,
each with its acceptance case in the same commit (rule 19(d)); every case
was checked to fail with its fix removed. Commits on `main` came before
branch protection; the rest are in PR #2.

| Id | Commit | Acceptance |
| --- | --- | --- |
| B-20 (I24) | `8231a07` (main) | `agent-name-collision` (fake, VM) |
| R03 | `20d4f2c` (main) | `override-stopped-equals-stop` |
| R08 | `4d27bce` (main) | `release-refused-leaves-incident` |
| R10 | `c6347cb` (main) | `dry-activate-exit-nonzero`, `-timeout`, `-truncated` |
| R09 | `443667e` | `unauthorized-change-does-no-work` |
| R07 | `ff11187` | `degraded-unit-loses-a-probe` |
| R02 (I25) | `af5bf42` | `floor-moves-via-watchdog`, `floor-moves-via-boot-only`, `revert-to-older-sets-no-floor` |
| S07 (tokens), C21 | `0bb8783` | `approval-dies-with-daemon` (fake, VM), `reprepared-keeps-caller` |
| S07 (I6's list) | `fa44baf` | kernel test `i6_generation_transactions_are_exclusive` |
| I7 (C1, C17) | `d9e1ed2` | `approval_recorded_by` on `approve-at-terminal-runs` |
| C14 | `ced94fa` | Verus lemma `agents_and_unattributed_are_refused` |
| C16 | `7059f7d` | `checkpoint-bad-crc`; txn test `damaged_checkpoint_is_integrity` |
| S03 | `6c8967e`, `edc849f`, `0251fb8` | `built-parking-expires`, `awaiting-boot-reminds-daily`; core test `an_expired_wait_reopens_its_incident` |
| S05 | `cfe40ba` | `ssh-session-expects-no-desktop` |
| S06 | `728cfe5` | module-eval: a 500/1000 edge rejected, 700/1000 accepted |
| C3 | `fe94ffe` | `override-over-attested-refused` |
| P23 | `8a0e523` | `residue-first-kill-teaches-stop` |
| R01, S01 | `88a984a` | `crash-publishing-before-publish`, `crash-publishing-after-publish` |
| S02 | `cd9a522`, `4e5cd1c` | `boot-only-admitted-not-confirmed`, `boot-only-repair-during-confirmation`, `boot-only-kernel-confirmed` |
| R06 | `48c3907` | `probe-trickling-endpoint` (VM); backend tests `trickling_http_has_one_total_deadline`, `a_stalled_resolver_is_inside_the_deadline`, `a_wedged_probe_does_not_hold_the_batch` |
| R05 | `7bfe155` | `posture-stops-launched-agents` (VM); backend test `no_agent_starts_while_a_failure_class_is_raised`; core test `agents_per_uid_are_limited` |
| C6, C4 | `8079c64` | `candidate-nar-mismatch-refused`; backend tests `old_build_roots_age_out`, `nar_hash_from_both_json_shapes` |
| P7, P8 | `905a06d`, `b077335` | core tests `a_write_back_queues_behind_a_generation_transaction`, `a_deferred_repair_is_deferred_in_fact` |
| P13–P17, P22, K10 | `9abea74`, `999ac42` | vm-posture subtests P14–P17; core tests `mark_good_needs_root_at_a_terminal`, `report_boot_and_posture_answer`, `a_committed_change_missing_from_the_overrides_is_lost`; `a_weaker_posture_waits_for_the_boot`, `a_lost_change_is_reapplied`, `reapply_does_what_the_original_did` (P18 already shipped) |
| C2, P9, P10, D4 | `ed1c15d` | core test `an_owner_edit_while_waiting_is_stale_when_the_window_opens`; `every_reader_is_bounded_by_bytes_max`; C22 and R09's bound verified unchanged |
| R12, R14, R15, R13 | `62fb19e`, waivers moved to `docs/deviations.md` after the owner's review | `the_accounting_checks_bite`; run-vm.sh's verdict logic exercised on a sample; the Verus check's count comparison |
| R04 | `5d9d986` | `switch-facts-from-dry-activation`; exec tests `rollback_facts_come_from_the_dry_activation`, `an_existing_generation_without_a_plan_is_refused`; `dry-activate-*` now refused with `ActivationUnknown` |
| R11, C5 | `867ffc1` | `en-i23-third-party-override-kept` (now also VM); backend tests `the_override_swap_waits_for_the_directory_lock`, `the_override_store_is_pruned`; txn tests `txn_fences_are_exclusive_and_swept_after_checkpoint`, `file_store_txn_dirs_are_exclusive` |

`4e5cd1c` also carries an owner decision (31 Oct) amending I6, §10 and §12
Concurrency: unit and device repairs run while an admitted boot-only change
awaits its confirmation, and a canonical unit that needed a repair in that
window means the change is not confirmed.

Every case above that lists the VM harness passed in one whole-catalog run
on one commit: "VM tests" run 110 on `6ad8521` (99 PASS, 2 waived
UNSUPPORTED `repair` entries, 0 not cleared; `docs/ga-status.md`). The fake
harness passes all 130 of its entries on the same commit (CI run 140).

| Found by the run | Commit | Case |
| --- | --- | --- |
| A takeover acked an op its fenced predecessor had just acked itself: `DuplicateOp`, the transaction left in flight (run 109, `crash-slow-worker-overlap`) | `6ad8521` | txn test `a_late_ack_from_the_old_owner_is_not_acked_twice`; the entry on VMs |
| P9's warning fired on nearly every VM tick | `6ad8521` | core test `a_slow_tick_is_warned` (at most one a minute) |
| The restarted daemon's startup revert stalled 15 minutes: switch-to-configuration reloaded sshd, ordered after `planarian-ready.target`, which waited on `planariad`'s own start (`systemctl list-jobs`, VM run 41288596484). Activation recoveries now run just after ready (owner decision, Nov 1; §12 and §10 amended) | #14 (`a018b08`, `21d4a8d`); the guard and windows in #15 | kernel `deferred_recovery_runs_no_activation_before_ready`, core `restart_reverts_an_interrupted_activation_after_ready`; the VM judge fails a stalled activation (shown failing on `main` without the fix, VM run 41355934489); `crash-slow-worker-overlap` reaches ready 0.3 s after the restart |

**R13, the invisibility bench** (`bench.invisibility`, run 41338935488 on
`4585982`, after MangoHud's `no_display` was found to switch off its per-frame
log). Idle, over five minutes, across every Planarian service's cgroup: CPU
0.403% of one core (target < 0.5%), resident 12.4 MB (target < 50 MB),
cgroup memory 16.5 MB, 1.55 wakeups/s. The game: Xonotic's timedemo,
software-rendered (llvmpipe), five runs per condition, interleaved, each run's
p99 from MangoHud's per-frame log (about 35,660 frames each). Median p99:
stopped 43.24 ms, idle 43.57 ms, busy 43.77 ms. Two-sided Mann-Whitney U
against stopped: idle p = 0.42, busy p = 0.22. Neither is significant at
alpha 0.01, so no measurable interference. Idle CPU is inside the target by about
20%; the earlier run with the same accounting (41334477890, whose game half
recorded no frames) measured 0.284%, so it varies run to run. `ga-status.md` takes these figures in #12's
closing rewrite.

Still open, each in issue #7's lanes: §12f
*Rollbacks*, P19, C18 (#9); C10, C19, P21, P24 and the R06/P10 remainders
(#10); P11 and the module-eval assertions (#11); deviations and the closing
run (#12). S04 is docs only. §17a's Phase A proof obligations are met (I17
proved; the residue classifier under Kani).

## Reviewer: P21 acceptance tests (#10), 2 Nov

Written from §17a (the assumptions the proofs rely on include "the journal's
fsync is durable"), §18.12 (`fake-assumptions-conformance`: the fake is a
second implementation of each, and the matrix covers each mutating call under
Partial, Unknown and Fenced) and §12 (the journal is "fsync'd"), on
`review/lane-change-path-p21`.

- `crates/gym/src/tests.rs::the_conformance_matrix_covers_unbind_and_cancel`:
  `MATRIX` has `unbind` and `cancel`, and `conformance::injected` passes for
  each under every outcome (it already fails if the entry never makes the
  call). On `main`: "unbind is not in the conformance matrix".
- `crates/txn/tests/memstore_sync.rs`: `MemStore::crash()` (power loss) keeps
  exactly what the last `sync` covered: an unsynced write is gone, a synced one
  survives, a journal-appended record survives and replays. On `main`: does
  not compile (no `crash`; `sync` is a no-op).

Not tested, by nature: `conformance.rs`'s comment that no fake-harness entry
makes `cancel` or `unbind` must go once the matrix covers them.

## lane-nix (#11): reconciliation, 2 Nov

Read #11 and its owner decision (P24, 1 Nov), this file, `nix/module.nix`,
`nix/posture.nix`, `nix/tests/eval.nix`, and the pinned nixpkgs
(`1f607aa`, nixos-26.05) greetd and systemd-lib modules.

| Item | Found | Doing |
| --- | --- | --- |
| P11 | `probeJSON` exports an `Exec` probe as `kind.Exec` with nothing else marking it; §9 wants it flagged. `Export` and `ProbeDef` have no `deny_unknown_fields`, so an added key is read as before | flag it in the export; assert in module-eval |
| P13 | The greetd module aliases `display-manager.service` to `greetd.service` and sets `services.displayManager.enable = mkDefault true`. So with greetd, `principalUnits` lists both names and the posture defines a second, `ExecStart`-less `display-manager.service` unit; systemd-lib's alias `ln -sfn` overwrites its file, so the built tree is right by order of operations only (checked: `display-manager.service -> greetd.service`). The reference configuration hits this (cosmic-greeter runs on greetd). "`displayManager.enable` unset" never holds with greetd | order `display-manager.service` only when greetd is not enabled; `greetd.service` when it is; assert in module-eval that no stray unit is defined |
| module-eval | Asserts neither the greetd ordering, the posture's SSH group, nor the Exec flag. The SSH rule lives in the `respond` script (`AllowGroups ${adminGroup} root`), reachable at eval only through the script's text | the three assertions (reviewer's case first) |
| P24 | `wireplumber` is in `userControllable.units` and has a canonical probe, but no default unit, so nothing watches it | declare it per the owner decision; assert in module-eval |
| posture comment | `posture.nix` said in-budget restarts keep planariad activating, so the target stays up. Run 41288596484 shows otherwise: each SIGSEGV in vm-posture logs `Stopped target Planarian is ready` with no `OnFailure=`; in crash-slow-worker-overlap the SIGKILL drops the target and a restart of the restarting unit raises Absent through `ExecStopPost` (result `success`) | comment corrected; ordering unchanged (I20; any change is the coordinator's) |

## Reviewer: P11 module-eval case (#11), 2 Nov

Written from §9 ("`Exec` probes … are flagged") and the coordinator's key
decision (each exported probe carries `flagged = true` iff its kind is Exec,
the key absent otherwise), on `review/lane-nix-p11`. `nix/tests/eval.nix`
gives `gym-db` an Exec probe and asserts: an Exec probe is exported (so the
check is not vacuous); every exported Exec probe has `flagged = true`; no
other exported probe has the key. On `main`: the build throws "every exported
Exec probe carries flagged = true".

lane-nix, P11 (2 Nov): `probeJSON` in `nix/module.nix` adds `flagged = true`
to an exported probe whose type is `exec`, and nothing to the others. The
reviewer's case above fails on `main` ("every exported Exec probe carries
flagged = true") and passes with it. No Rust reader denies unknown fields, so
`Export` and `ProbeDef` read the key as before; the gym VMs' own Exec probes
(`snd-hda0-driven`, `pipewire-has-a-card`, `wifi-associated`) carry it on
real machines.

| Item | Found | Doing |
| --- | --- | --- |
| P11, scope (review 5731300056) | P11 flags the export only. §9's "flagged in the console and the journal" is still open: neither shows an Exec probe today. The Rust readers are to show it from `ProbeKind::Exec`, not from the `flagged` key | no code in P11; open for the console and daemon lanes |

## lane-daemon (#9), reconciled 2026-11-02 at `47caca7`

| Id | At `47caca7` | Evidence at head | Work |
| --- | --- | --- | --- |
| §12f *Rollbacks* | open, partly | `exec::schedule` parks any generation candidate in `Built` while `Foreground` holds, and a session-disturbing one whose source is not User/Intent while a session is in use: a diagnoser `Rollback` is parked in both cases, which §12f forbids. User/Intent rollbacks already skip the idle-session wait, but still wait under `Foreground`. `Core::repair_one` already skips, under quiet mode, incidents whose target fails `foreground_depends_on` (P8), so an unrelated repair rollback is not submitted and its budget does not advance. The §11 session-loss floor (`policy` AskFirst) is applied before `schedule`, so a repair rollback that ends a session is already parked for approval, not run. `Reverting` runs inside `Kernel::run` and is never deferred. A repair rollback submitted while another generation transaction is live (one waiting in `Built` counts, I6) is refused `busy` by the ledger, not held | one PR: `schedule` treats a diagnoser `Rollback` as a repair; the repair loop holds a generation repair while a generation transaction is live; the three acceptance cases |
| P19 | open | `Core::context` sets `core_hash: Hash::ZERO`; the record exists (`nix/posture.nix` installs `/etc/planarian/core.sha256`, which `planarian-recovery` checks) but `planariad` never read it | filled from the record: `config::core_hash`, set by `main.rs` after `Core::start`; core test `the_state_carries_the_recorded_core_hash` |
| C18 | open | no `SnapshotBackend` is wired in Phase A (the trait exists in `schema::backend`; nothing implements or calls it), so every `UserData` transaction meets the unsupported case; nothing records `NoSnapshot`. Step 6 sits between `Kernel::prepare` and the run, in `exec::submit`/`approve`; `schedule` is the point both reach | one PR, in the daemon's executor log (`LogRecord`) |

## lane-change-path (#10), reconciled 2026-11-02 at `47caca7`

Owner decisions in force (issue #10 comments, 1 Nov): R06 follows §10 as
written, with one `ProbeResult` variant allowed in `crates/schema`; P24
declares wireplumber (lane-nix, #11).

| Id | Status at `47caca7` | Evidence | Crosses lanes |
| --- | --- | --- | --- |
| C10 | open | `exec/src/derive.rs:46` folds `restart_disruption` with `max`; `Disruption`'s `Ord` (`schema/src/unit.rs:128`) ranks ConnectivityLoss over DataInterruption and DataInterruption over SessionLoss, so ConnectivityLoss + DataInterruption keeps only ConnectivityLoss and a seated user escapes the DataInterruption floor (§11) | yes: `DerivedFacts.disruption` is one `Disruption` in `schema/src/transition.rs:173` and in SPEC §5 (`pub disruption: Disruption`); read by `policy` (floors in `lib.rs` and the Verus `proofs.rs`), `daemon/src/render.rs`, `gym/src/metrics.rs`, `tray`, `txn` tests |
| C19 | open | `touches_manifest` (`derive.rs:104`) compares `edges`, `sensitivity`, `restart_disruption`, `synonyms` and User probes of units present in both; not `desired`, `systemd_restart`, `startup_grace`, `runtime_repair`, `stops_are_faults`, added or removed units, nor `user_units` at all | no |
| P21 | open | `gym/src/conformance.rs:20-21` says `cancel` and `unbind` are made by no fake-harness entry, and the matrix omits them; the "Journal fsync is durable" contract cannot fail because `MemStore::sync` (`txn/src/store.rs:167`) is a no-op and a drop loses nothing unsynced. The fake's `cancel` and `unbind` already honour `World::inject` (`fake/src/lib.rs:919`, `:1057`) | yes: `conformance.rs` is in `crates/gym`, `MemStore` in `crates/txn` |
| R06 remainder | open | `run_batch_with` (`backends/linux/src/probe.rs:271`) maps a straggler to `ProbeResult::Timeout`; §10 says "recorded `Unknown` and abandoned" | yes: a new variant breaks the exhaustive match in `daemon/src/render.rs:99`, and `daemon/src/core.rs:1189`, `:1325` match `Timeout \| Error(_)` and must also take it |
| P24 | decided | `share/canonical.json:81` keeps `wireplumber`; the declaration is lane-nix's (`nix/module.nix`) | lane-nix |
| P10 remainder | open | `SideEffects::Measurement { per }` is read nowhere; the scheduler's `interval` (`state/src/lib.rs:174`) ignores it. §10 binds it to the cadence scheduler only; runs on request (`request`, `reprobe`, Checking's fresh assembler) are not rate-limited (reviewer, #18) | no |

## lane-nix: P24, 2 Nov

| Item | Found | Doing |
| --- | --- | --- |
| P24 (lane-nix, 2 Nov) | Pinned nixpkgs: `services.pipewire.wireplumber.enable` defaults to `services.pipewire.enable`; the user unit `wireplumber.service` carries `BindsTo=pipewire.service` (and `Alias=pipewire-session-manager.service`). The gym VMs already declare wireplumber with that edge, at normal priority, so the module's `mkDefault` leaves them as they were | `nix/module.nix` declares `wireplumber` (`scope = "user"`, `Requires` on `service@0:pipewire`) when PipeWire and WirePlumber are both enabled. module-eval: present in the reference configuration with the edge, absent with WirePlumber off. Fails on `main` |

## Reviewer: P13 and SSH-group module-eval cases (#11), 2 Nov

Written from §12d ("ordered before every unit that admits a principal: the
display manager (whichever unit NixOS uses for it …)"; "*Restrict remote
access to administrators* means Planarian's administrators (root and
`planarian-admin`), not `wheel`"), on `review/lane-nix-p13-sshgroup`. The
pinned nixpkgs greetd module always aliases `display-manager.service` to
`greetd.service`. Checks in `nix/tests/eval.nix`:

- reference configuration (greetd): greetd is the DM (non-vacuous);
  `greetd.service` is after `planarian-ready.target`; no ExecStart-less
  `display-manager` unit is defined beside the alias. On `main` the last one
  FAILS (the posture defines a stub `display-manager.service`).
- the same configuration with SDDM instead: `display-manager.service` is a
  real unit and is after the target. Passes on `main` (guard).
- SSH: the `planarian-respond@` script writes at least one `AllowGroups` line;
  every such line is `AllowGroups planarian-admin root` and never names
  `wheel` (read from the script, IFD); sshd's `extraConfig` includes
  `/run/planarian/sshd/*.conf`. Passes on `main` (guard); a mutation writing
  `wheel` fails it.

| Item | Found | Doing |
| --- | --- | --- |
| P13, module-eval (lane-nix, 2 Nov) | As reconciled above: with greetd on, `principalUnits` listed both `display-manager.service` and `greetd.service`, so the posture defined an `ExecStart`-less `display-manager.service`; the built tree came out right only because systemd-lib's alias `ln -sfn` runs after the unit links | `nix/posture.nix` orders `greetd.service` when greetd is enabled, else `display-manager.service` when NixOS runs one. The reviewer's case passes unedited: greetd ordered, no stub beside the alias, SDDM's `display-manager.service` ordered, and the SSH group (`AllowGroups planarian-admin root`, never `wheel`; the drop-in included) asserted. The module-eval assertions task closes with it |

## Reviewer: C10 acceptance test (#10), 2 Nov

Written from §11's global floors only (`review/lane-change-path-c10`).
`crates/exec/src/tests.rs::each_disruption_keeps_its_own_floor`: a seated
administrator's Rollback restarts a ConnectivityLoss unit (no floor for a
local caller) and a DataInterruption unit (AskFirst unless it is the caller's
own session). On `main` it commits without asking: `max` over `Disruption`'s
order keeps ConnectivityLoss and the DataInterruption floor is lost. The
control (the ConnectivityLoss unit alone) runs on `main` and must keep
running. The test asserts the decision (Parked), not the representation of
the combined disruption.

## Reviewer: C10 catalog case (#10, against #21), 2 Nov

Written from §11's global floors (`review/lane-change-path-c10-case`), at the
coordinator's request against `main` plus #21 (`core/disruption-set`).
`disruption-each-kind-keeps-its-floor`: a seated administrator's Rollback
restarts a ConnectivityLoss unit and a DataInterruption unit (fixtures
`gym-tunnel`, `gym-sync`, both Routine; step `restarts_on_switch`, fake only).
It must carry both kinds and ask. On `main`: FAIL, committed without asking,
disruption ConnectivityLoss only. Control
`disruption-connectivity-alone-seated-runs` (the ConnectivityLoss unit alone)
passes on `main` and must keep passing.

### lane-change-path: C10 and the already-failed rule (#27), 2 Nov

| Id | Status | What closes it | Case |
| --- | --- | --- | --- |
| C10 | closed by #21 (the set type, floors per member) and #27 (`unit_facts` inserts every unit's `restart_disruption`) | §11 global floors, each applied to its own kind | exec `each_disruption_keeps_its_own_floor`; catalog `disruption-each-kind-keeps-its-floor` (FAIL on `main` + #21, PASS here), control `disruption-connectivity-alone-seated-runs` |
| §11 already-failed rule | closed by #27 | §11 as amended in #22 (owner decision, Nov 2): "A unit that has already failed (observed `Failed`, or not running while it is desired running, when the facts are derived) contributes no disruption of its own ... Every other unit the transition touches still contributes its own." `derive.rs` `already_failed` reads the observation passed to that derivation (`DeriveInput::state`), so it is current at proposal, at approval and before Activating; status `Failed`, `Stopped` or `Absent` while desired Running and expected. `Unknown` (Timeout, Error, Abandoned), Degraded, Transitioning and overridden units still contribute | exec `an_already_failed_unit_contributes_no_disruption`, `an_unknown_unit_still_contributes_its_disruption`, `a_unit_recovered_before_approval_asks_again` (the reviewer's) |

## Reviewer: C19 acceptance test (#10), 2 Nov

Written from §9 (a manifest entry is `desired`, `edges`, `sensitivity`,
`restartDisruption`, `probes`, `synonyms`; the manifest is Security) and §11's
ApplyChange row (AskFirst when `touches_manifest`), plus issue #10's C19 field
list, on `review/lane-change-path-c19`. `crates/exec/src/derive_c19_tests.rs`
(hooked from `derive.rs`) edits one field of one entry at a time:
`desired` status and condition; `systemd_restart`, `startup_grace`,
`runtime_repair`, `stops_are_faults`; an added and a removed unit; a user-scope
entry's field, an added and a removed user-scope entry. Each must touch the
manifest. Controls: an identical manifest does not; the fields already covered
(synonyms, restart_disruption, sensitivity) still do. On `main`: 4 of 6 fail
(desired, the exported fields, added/removed, user scope).

### lane-change-path: C19 (#10), 2 Nov

| Id | Status | What closes it | Case |
| --- | --- | --- | --- |
| C19 | closed by this PR | `derive.rs` `touches_manifest` compares every entry whole (canonical probes left to `touches_canonical`), system and user scope, and an added or removed entry; it had compared only `edges`, `sensitivity`, `restart_disruption`, `synonyms` and user probes of units present in both | reviewer's `crates/exec/src/derive_c19_tests.rs` (4 of 6 fail on `main`; all pass); fake verdicts unchanged |

### lane-change-path: P21 (#10), 2 Nov

| Id | Status | What closes it | Case |
| --- | --- | --- | --- |
| P21 | closed by this PR | `MemStore` keeps an undo log of log writes since the last `sync`: `sync` makes them durable, the new `crash()` (a power loss) undoes them, so the fake's "Journal fsync is durable" contract can fail. `conformance::MATRIX` adds `unbind` (`drv-bind-fails-restores-previous`: a failed bind's revert) and `cancel` (`crash-job-outlives-drain`: an unanswered activation's jobs), each under Partial, Unknown and Fenced; the comment that no fake entry makes them is corrected. The fake's `unbind` and `cancel` already honoured `World::inject` (`fake/src/lib.rs`), so `crates/fake` is unchanged | reviewer's `crates/txn/tests/memstore_sync.rs` (did not compile on `main`) and gym test `the_conformance_matrix_covers_unbind_and_cancel` (failed on `main`); both pass |

## Reviewer: §12f *Rollbacks* acceptance cases (#9), 2 Nov

Written from §12f (*Rollbacks*, *Quiet mode*), §11 global floors and §13
ordering only, before the builder's code (`review/lane-daemon-12f-rollbacks`).

| Case | On `main` | Why |
| --- | --- | --- |
| `rollback-repair-foreground-dependency` | FAIL | no Rollback runs: the Wi-Fi repair chain parks at its first step (below) |
| `rollback-repair-foreground-unrelated` | PASS | the repair loop already skips non-dependency incidents under quiet mode; the case guards it |
| `rollback-repair-session-loss-asks` | PASS | the Rollback is already AskFirst/SessionLoss and pending; the case guards it against a "repair skips the floors" regression |

Test vocabulary these needed, added on the review branch (it crosses into
lane-gym's `crates/gym/src/**` and lane-change-path's `crates/fake/**`;
the coordinator decides whether it stays there):

- `break_in_generation {unit, generation, switch_restarts?}` (fake only): a
  committed generation's flaw that shows once it is live; restarts cannot fix
  it, a switch away from that generation does.
- fixture `service:gym-printer` (Routine, Brief): a unit no foreground work
  depends on.
- `[[txn]] count = 0` with `while_foreground = "<session>"`, and incident
  `budget_steady_while_foreground`. Both shown to bite: added to
  `quiet-repair-not-deferred` (a repair that is not deferred), both fail.

Open, for the owner: under §11, a diagnoser-proposed change with
ConnectivityLoss is AskFirst ("a `SetRuntimeOption` Wi-Fi change proposed by
the diagnoser ... ask"), and §12f says the floors apply to a repair rollback.
A Rollback that restarts NetworkManager is ConnectivityLoss (§11's own gym
case). So the English of `rollback-repair-foreground-dependency` ("the
rollback runs at once") cannot pass as written without a decision; on the
fake today the chain does not even reach the Rollback, because the in-place
Wi-Fi repair parks at AskFirst. The case is written to the literal English
(runs during Foreground, no approval step) pending that decision.

## lane-daemon: §12f *Rollbacks* (#9), 2 Nov

Built against the owner's decisions of 2 Nov (PR #22) and the reviewer's
cases above, at `main` `f470cc1`.

| Rule | Change | Evidence |
| --- | --- | --- |
| A User/Intent `Rollback` runs at once, also under `Foreground` | `exec::schedule`: a `Rollback` from User, Intent or the diagnoser never waits in `Built`; the §11 floors were applied before it, so one may still be parked for approval | core test `a_rollback_never_waits_for_a_window` (fails on `main`) |
| A diagnoser `Rollback` is a repair, never parked in `Built` | the same | the same test; `rollback-repair-session-loss-asks` (AskFirst, pending) |
| Under `Foreground`, an unrelated repair rollback is not submitted, budget unchanged | unchanged: `repair_one` already filters by `foreground_depends_on` | `rollback-repair-foreground-unrelated` |
| I6: a rollback of any source, at the moment it is about to run (admitted, and approved if it asked), withdraws what waits in `Built`; each is prepared again once the rollback is terminal, keeping its parking start; one past `Built` is waited for; one parked for approval in `Prepared` is left alone (owner and coordinator, Nov 2) | `exec::schedule`: before running a rollback (User/Intent `Rollback` or `planarian undo`'s `Revert`, or the diagnoser's `Rollback`), `Kernel::reject(id, Interrupted)` on each waiting transaction; the ledger's I6 `compatible` admits a `Prepared` rollback beside a `Built` one, so nothing is withdrawn earlier. `Core::note_withdrawn` keeps each one's proposal, caller and `waiting_since`; `prepare_again` (shared with the restart path) re-links a diagnoser repair to its incident and restores the parking start (`keep_waiting_since`). The repair loop already does not run while a transaction is past `Built`. No `crates/txn` change | core tests `a_parked_rollback_withdraws_nothing_until_approved`, `undo_withdraws_a_waiting_update_and_runs`, `a_refused_repair_rollback_withdraws_nothing`, `a_repair_rollback_leaves_a_parked_update_alone`, `a_repair_prepared_again_keeps_its_incident` |
| `Reverting` never deferred | unchanged (`Kernel::run`) | — |

`rollback-repair-foreground-dependency` stays FAIL until lane-change-path's
derive change (§11: a unit already failed contributes no disruption) lands:
the Wi-Fi repair chain still parks at the ConnectivityLoss floor before it
reaches the Rollback. The case is not edited.

### lane-daemon: the withdrawal survives a restart (#26 review at `2cba51e`), 2 Nov

At `2cba51e`, `Core::withdrawn` lived only in memory. The startup re-prepare
took only transactions that recovery interrupted, and a withdrawn one is
already terminal. So a restart between the withdrawal and the next tick after
the rollback lost the update, even though the notice said it would be
prepared again. The reviewer's case is
`a_withdrawn_update_is_prepared_again_after_a_restart` (7b5cb65, unedited).

The fix: each fact is atomic with the record that makes it true, and no new
record kind is added (coordinator, Nov 2).
- `Record::Advance.withdrawn_for` (serde default) is written by
  `Kernel::withdraw` from `exec::schedule` and folded into
  `TerminalTxn.withdrawn_for`.
- `Transaction.prepared_again_from` (serde default) is set only through
  `Executor::submit_again`, which only the daemon's `prepare_again` calls.
  It is not in `Proposal`, so no caller can name a withdrawn transaction. It
  is folded into `TerminalTxn.prepared_again_from`.
- At start, `withdrawn` is rebuilt as the withdrawn terminal transactions that
  no live or terminal transaction names. It is deduped against the restart
  re-prepare set.
- `apply_advance` passes the new field to `archive` (`external_body`), so
  the proof's obligations are unchanged.

Tests:
- daemon: `a_withdrawn_update_prepared_again_is_not_prepared_twice_after_a_restart`
  and `an_ordinary_submission_prepares_nothing_again`;
- daemon: `records_journaled_before_the_withdrawal_fields_decode`, literals of
  main's Advance, Prepared and checkpoint `TerminalTxn`;
- txn: `withdrawal_links_replay_and_survive_compaction`.
