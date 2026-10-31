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
| R04 | Existing-generation operations omit activation consequences | open | `SwitchGeneration`/`Rollback`/`Revert` derive no activation plan or override diff | §11 equivalent effects |
| R05 | Launcher-created agents are outside failure-posture enforcement | open | `start_agent` units are not in `agentUnits` and have no readiness ordering | §12d `planarian-agents.slice` |
| R06 | Probe timeouts do not bound total execution time | open | `probe.rs`: DNS resolution outside the deadline; the batch joins every thread | §10 whole-probe deadline |
| R07 | Already-degraded units can lose more health without blocking commit | open | `host.rs`'s check compares unit status, skips units not Running before | §9 per-probe post-check |
| R08 | Rejected release requests still replenish repair budgets | open | `core.rs`: `LiftOverride` calls `incidents.human_acted` whatever the result | §13 |
| R09 | Unauthorized callers can reach expensive prebuild work | open | `user_submit` queues `prebuild_job` before `decide` runs | §12 admission before work |
| R10 | Failed dry activation is accepted as usable risk evidence | open | `nixos.rs` parses `dry-activate` output without checking its exit or timeout | §9 step 3, rule 21 |
| R11 | Override replacement is check-then-rename, not compare-and-swap | open | `swap_override` compares then renames, unlocked | I23 under `flock`; X-12 |
| R12 | The VM catalog runner exits 0 after total build failure | open | `nix/gym/run-vm.sh` ends with an unconditional summary | §15 harness contract |
| R13 | The benchmark cannot establish the full invisibility claim | open | `bench.nix` samples two MainPIDs; p99 is the engine's one-second minimum | §15, §21 |
| R14 | The verification ratchet can inflate counts or lose coverage | partly | `b219d81`-era `verification.rs` requires an English entry per proved invariant (e49c37a); duplicates, removed baseline invariants and textual name checks remain | §17a accounting checks |
| R15 | Unsupported regressions can remain green | partly | VM catalog jobs accept UNSUPPORTED only for two named entries (b219d81); the fake runner and `ci.yml` still accept it | §15 harness contract |
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

`4e5cd1c` also carries an owner decision (31 Oct) amending I6, §10 and §12
Concurrency: unit and device repairs run while an admitted boot-only change
awaits its confirmation, and a canonical unit that needed a repair in that
window means the change is not confirmed.

These cases run on the fake harness only unless marked; the VM catalog run
of rule 19(f) is still to come.

Still open from the tables above: R04, R05, R06, R11, R12, R13, R14 (the
rest), R15 (the fake runner and `ci.yml`), R16 (`ga-status.md` waits for
19(f)); S04 is docs only. Still open from §28 beyond R and S: C4, C6, P7, P8,
P13–P18, P22, K10.
