# Shared-core safety reconciliation

Instruction baseline: `805cd1c953d78044a8c94ef9e3d35e33eb1dfb1a`.
Original review baseline: `bd6d24d17c7d304715436bfa18c13c6343bcbf4e`.
Integrated main: `20d4f2c72d39996cf8b54f6168903837e8e50417`, retaining
its adopted SPEC v4.6 contracts and intervening fixes. The existing
[acceptance manifest](shared-core-acceptance.json) still identifies an earlier
candidate and must be regenerated after the implementation stabilizes. Earlier
`eaf5a56`/`9acaaf4` records remain historical after this source integration;
their controls or partial CI results do not certify the merged candidate.

“Fixed by this PR” denotes a prepared source change; acceptance remains open
until required current-source regressions and checks pass. Local Python
accounting fixtures and source/format controls establish neither Rust
compilation nor actual Verus/Kani/VM/hardware acceptance.


## Observed checks and pending rerun

At published revision `1d10786c8d883d9a3885376ead6ff3e32de4b184`,
[CI run 41146692117](https://github.com/aubrika/planarian/actions/runs/41146692117)
passed formatting and all five Kani harnesses. The Verus subprocess reported
17, 52 and 59 verified with zero errors; the combined Nix job later failed
package tests, so its proof-artifact export and aggregate verification gate
did not run. Clippy rejected a complex decoded-agent-registry type. Two
executor regressions failed because their fixtures used an invalid catalog
argument and a graphical-session template instead of concrete session targets.
Those fixes are prepared in subsequent source commits; they require a rerun.

[VM run 41146692182](https://github.com/aubrika/planarian/actions/runs/41146692182)
started the installed-entry machines. Fourteen completed failures stopped at
the initial canonical root-filesystem space check; enlarging the qcow overlay
had not grown its root partition/filesystem. Four other completed jobs stopped
at the same package-test failures before VM startup. The installer passed.
The fixture now grows the partition/filesystem and retains the canonical
2 GiB / 5% thresholds. Later boot milestones and the remaining catalog cases
have no pass claim from those failures.

Local accounting/metric controls pass (34 tests), and the installed-boot
fixture's three assertion/PTY controls pass. These include real local PTY,
exit-status and output-cap checks, but no Nix evaluation or installed-entry
VM execution. The later S02/S03/S06 changes invalidate use of earlier proof
or VM results as certification of the new candidate.

## Disposition and D01 requirement map

SPEC v4.6's owner decisions are authoritative. The previous PR alternatives
for early boot-only commitment, unbounded Built parking/G5, optional weak-edge
external metadata, and arbitrary-editor CAS are superseded where v4.6 adopts
a different contract. They are not competing normative text. Main's I24
instance-authority fix (`8231a07`), R03 (`20d4f2c`), R08 (`4d27bce`), R10
(`c6347cb`) and approval PTY fix (`b219d81`) are retained.

The baseline remains 47:56, trust 37 and internal-unproven 5. Removing the
superseded proposed G5 is not a baseline reset. I24/I25 are separately stated
tested v4.6 invariants; source-name presence does not discharge them. B-20 is
the closed agent-instance finding. Cooperative override locking is R11/B-21;
non-cooperating writers are the adopted X-12. Engineering priority P1 and a
bypass-register High are distinct; a zero High count closes no R/S requirement.

| ID | Status | Requirement and current path | Regression | Before → prepared behavior | Evidence; remaining acceptance/assumption |
| --- | --- | --- | --- | --- | --- |
| R01 | fixed by this PR | §12/I6/I15; `crates/txn/src/kernel.rs:run_boot_only/reconcile_boot_publication; schema txn; watchdog` | `boot_publication_crash_boundaries_remain_tracked_for_both_owners; partial_unknown_and_failed_boot_publication_reconcile_actual_effects; boot_publication_interlock_preserves_candidate_roots_on_disk; withdrawal_effects_with_failed_partial_or_lost_replies_remain_interlocked; fake withdrawal Partial/Unknown/Fenced conformance` | Built publication could mutate before tracked state → PublishingBoot precedes intent/call; unknown boot/selection interlocks with candidate/root/fallback; old publication intent reconciles | Source + authored UNRUN regressions; Run current-source publication/withdrawal crash matrix through daemon/watchdog and installed-entry tests, plus ext4/nodatacow-btrfs durability. PublishingBoot implements the adopted Publishing obligation; no missing historical facts are inferred. |
| R02 | fixed by this PR | §12e/I16; `crates/txn/src/kernel.rs:write_committed; exec/lib.rs; watchdog` | `every_generation_completion_establishes_the_same_floor; completion_crashes_and_torn_floor_or_commit_writes_preserve_the_obligation; a_fenced_completion_cannot_write_global_floor_or_baseline_records` | Daemon best-effort floor followed Committed; watchdog/boot-only omitted it → Versioned durable intent; fenced serialized floor and path-appropriate baseline obligations precede Committed; boot-only confirmation records KnownGood without LiveTested, and interrupted completion remains obligated | Source + authored UNRUN regressions; Actual proofs/daemon/watchdog/restart/boot-only fault runs; historical terminal facts require administrator migration, not inference |
| R03 | already fixed with evidence | §11/I21; `crates/exec/src/derive.rs` | `stopped_override_has_the_same_effects_and_floor_as_a_stop` | Stopped override erased disruption/dependents → Adopted main R03 stop-equivalence fix retained; PR adds independent local/SSH/multiuser/dependent-effect coverage and conservative union/max of old/candidate effects. | Source + authored UNRUN regression; Run local/SSH/multiuser cases and actual display/network consequences |
| R04 | fixed by this PR | §9/§11/I14; `crates/exec/src/lib.rs:plan_existing/revalidate_activation; backend-linux/nixos.rs` | `existing_generation_derives_activation_and_override_configuration; changed_activation_preflight_is_rejected_before_execution` | Existing targets used manifests without actual activation/config differences → Target-bound preflight/override identity; execution revalidates base and activation evidence; Unknown rejects | Source + authored UNRUN regressions; Run equal-UnitDefs changed-content NixOS VM cases; unmodeled discovery/historical target evidence fails closed |
| R05 | fixed by this PR | §12d/I20/owner agent decision; `crates/backends/linux/src/systemd.rs; nix/posture.nix; daemon AgentRun` | `launcher_units_are_externally_supervised_and_bounded; admission_counts_starts_and_preserves_root_capacity; nix/tests/posture.nix public launches; sequential failed/short-lived launch quota and registry replay/compaction/historical-integrity cases` | Transient agents escaped static agentUnits posture list → Preserve main I24 instance-bound authority (8231a07): successful launch returns InvocationID, then AgentStarted(instance,by) is durably recorded before requests gain authority. A failed launch/append grants none. Existing live name is refused; stopped-name reuse follows the new instance and may change launching uid. Readiness-bound bounded agent slice, live/name quotas/root reserves and checkpoint dedup remain resource controls, not name-based authorization. | Source + authored UNRUN unit/VM regressions; Execute merged public launcher Absent/Crashed/Integrity, same-name/instance collision, legacy no-instance records, journal-write failure, root capacity and actual cgroup resource tests. Numeric resource limits remain proposed refinements; I24 is adopted. |
| R06 | fixed by this PR | §10 bounded total probe lifetime; `crates/backends/linux/src/probe.rs; cmd.rs` | `trickling_http_has_one_total_deadline; resolver_process_is_cancelled_inside_the_total_deadline; inherited_output_pipe_is_inside_the_deadline` | DNS escaped timeout; per-read HTTP deadlines reset; inherited pipes could stall cleanup → Cancellable resolver/process groups, one network deadline, bounded batches/workers/output, no detached resolver thread | Source + authored UNRUN regressions; getent CLI syntax only; Run blocked DNS/connect/write/trickle/resource accounting with measured scheduling margin; responsive local filesystem/kernel remains platform assumption |
| R07 | fixed by this PR | §12 checking/I10; `crates/exec/src/host.rs; schema CheckContext; watchdog` | `mixed_baselines_preserve_each_passing_probe_through_replay; missing_stale_timeout_error_and_old_pass_are_not_preservation_evidence; authorized_removal_changes_applicability_but_probe_removal_does_not` | Aggregate Degraded/Unknown omitted individual passing evidence → Versioned durable applicable passing probe definitions independently preserved, requiring fresh new Pass | Source + authored UNRUN regressions; Run replay/watchdog cases and real canonical checks; authorized applicability changes distinct from weakening |
| R08 | already fixed with evidence | §13 authorized incident control; `crates/daemon/src/core.rs release handlers` | `denied_release_preserves_incident_and_linked_overrides` | Denied release still replenished incident/released linked overrides → Main R08 authorized-success-only incident mutation fix is retained alongside the PR complete incident/linked-override regression. | Source + authored UNRUN regression; Run full incident budget/cooldown/state comparison and successful release control |
| R09 | fixed by this PR | §11 authenticated admission; `crates/exec/src/lib.rs admission/prebuild_job; daemon/core.rs/main.rs queue` | `unauthorized_catalog_change_does_no_expensive_work; deferred_catalog_work_authenticates_before_staging; expensive_work_is_bounded_per_principal_with_admin_reserve` | Valid unauthorized catalog requests staged/built before authorization → Cheap authenticated capability/argument admission; bounded attributed queue, admin reserve, full post-build policy retained | Source + authored UNRUN regressions; Run actual stage/evaluate/build call counts/load; AskFirst remains admitted for authorized proposals |
| R10 | already fixed with evidence | §9 trustworthy risk evidence; `crates/backends/linux/src/nixos.rs:checked_dry_activate` | `discovery_checks_real_command_exit_timeout_and_protocol` | Discovery ignored actual failure/timeout/incomplete output → Main R10 rejects unusable command outcomes; PR retains stricter protocol/completeness/model-evidence checks and actual-command regression. | Source + authored UNRUN actual-command regression; Run actual pinned NixOS backend/VM; NixOS own child-script honesty remains explicit trust boundary |
| R11 | fixed by this PR | Adopted SPEC v4.6 §9/I23 cooperative directory-lock writer boundary; accepted X-12 for other writers; `crates/backends/linux/src/nixos.rs:swap_override_after_comparison` | `cooperating writer directory-lock regression; demonstrates_unclosed_arbitrary_editor_override_replacement_bypass (accepted X-12 characterization)` | Final hash comparison and rename were not serialized under the supported directory lock; arbitrary-editor CAS was also overstated. → Adopted writer model retained: promotion/restoration acquire the exclusive directory flock around final comparison, replace and directory sync. Non-cooperating/pre-opened-descriptor editors remain the explicitly accepted X-12, not a false CAS proof. B-20 remains the distinct closed I24 agent-instance finding; B-21 tracks current lock acceptance until verified. | Source + authored UNRUN negative characterization; Run the actual Rust/backend cooperative-writer race, promotion/restoration/replay and supported-filesystem durability cases. A successful local extracted lock control is not compiled backend or VM evidence. |
| R12 | fixed by this PR | §15 verdict integrity; `nix/gym/run-vm.sh; acceptance.py; nix/tests/gym-vm.nix` | `test_acceptance.py actual runner failing-build/status/coverage cases` | Nix eval success + all builds fail returned zero; missing/duplicate/bad verdict ignored → Build/step/judge errors propagate; exact derived expected IDs/roles; stale results cleared | Executed local shell/Python regression + pre-fix counterfactual; Current complete Nix VM catalog still unrun; baseline script failed all seven injected negative assertions, fixed runner rejects them |
| R13 | open | §21 resource/performance acceptance; `nix/tests/bench.nix; nix/gym/performance.py` | `test_performance.py; installed metric helper CPU-load subtest` | MainPID counters missed helpers; one-second min FPS falsely used as frame p99 → Whole-cgroup CPU/memory and actual frame-only metrics prepared; physical input interface/plan; no desktop measurement invented; persistent monitor-owned-work slice includes transient probe/Nix/posture helpers; shared service/frontend exclusions explicit | Source + local Python metric regressions (see report); Reference hardware, measured input latency, full personal-profile repetitions and proposed practical margin adoption remain outstanding |
| R14 | fixed by this PR | §17a proof integrity/ratchet; `nix/gym/proofs.py; gym/verification.rs; docs/proof-obligations.toml` | `test_proofs.py duplicate/deleted/conditional/unverified names and stale/failed receipts` | Name/count presence could discharge removed or unverified properties → Unique source/engine mapping + complete successful current-source receipts; preserve baseline invariant set and 47:56 denominator | Executed local Python accounting controls; actual Kani and zero-error Verus output observed at 1d10786, with the combined job/gate incomplete as recorded above; rerun the exact final candidate and validate successful source-bound artifacts. Synthetic verifier logs remain accounting controls, not proofs |
| R15 | fixed by this PR | §15 role-qualified coverage; `nix/gym/acceptance.py/run-fake.sh; gym/main.rs; workflows` | `test_acceptance.py required Unsupported/omission/waiver/exit negatives` | Applicable required coverage silently disappeared as Unsupported → Exact current id/harness/role and explicit reviewed expiring waivers; no blanket Unsupported acceptance | Executed local Python/shell controls; No waivers adopted; full current fake/VM/bench catalog and required critical PR checks must pass |
| R16 | fixed by this PR | §18 documentation/evidence; `docs/SPEC.md; AGENTS.md; deviations/guarantees/ga-status/bypasses/verification` | `nix/gym/manifest.py; test_manifest.py; reconciliation and source fingerprint` | Historical/mixed results and narrower proofs overstated current closure → One authoritative proposed contract; historical evidence labeled; current acceptance manifest leaves unrun gates open | Source + executed local manifest-accounting controls; Regenerate records on the stable merged candidate; retain adopted v4.6 contracts and baseline37/47:56, label earlier source records historical, execute required compiler/proof/VM/durability/performance cases. No merged or unioned historical result is current certification. |
| S01 | open | Adopted v4.6 §12: publishing/running generation is automatic boot fallback, at or above floor; KnownGood below floor stays manual.; `txn automatic_target_eligible; Linux boot publication/default; installed-entry target` | `failed_boot_only_generation_uses_floor_eligible_fallback_not_old_known_good; no_floor_eligible_automatic_boot_target_refuses_before_publication; nix/tests/boot-entries.nix installed UEFI/systemd-boot boundary/confirmation/failure-interval matrix (UNRUN)` | Live/watchdog/boot selection eligibility not unified → Adopted main fallback identity rule retained. Shared publication/recovery must bind that publishing generation and reject missing/floor-ineligible evidence; installed EFI persistent/one-shot identities are independently observed. | Source + authored UNRUN regressions; Run the actual G1 vulnerable/G2 floor/G3 failed boot installed-entry cases and verify all supported recovery paths use the publishing generation. Other bootloader/initrd layouts have no unified enforcement/evidence claim. |
| S02 | fixed by this PR | Adopted v4.6 §10 admission/confirmation contract; `daemon Core::confirm_boot; txn await_boot/confirm_boot; installed-entry target` | `admitted_candidate_confirms_at_ten_boot_minutes_across_a_daemon_restart; failed_canonical_confirmation_restores_the_boot_fallback_without_live_activation; watchdog_does_not_supply_the_daemons_boot_confirmation_checkpoint; boot_completion_requires_durable_generation_override_metadata_before_bookkeeping; an_unsupported_boot_admission_never_implies_confirmation; nix/tests/boot-entries.nix` | Early commitment is superseded. Durable versioned same-boot admission leads to Promoted; only the daemon at ten boot minutes, with a fresh canonical check after takeover/drain and exact boot/generation evidence, completes KnownGood/floor/Committed without LiveTested. Same-boot watchdog/reconciliation leaves confirmation pending; failed confirmation restores the publishing fallback and requires restart without live-activating a boot-only fallback. | Prepared source + authored UNRUN Rust/VM regressions; three local fixture assertion/PTY controls pass. Execute the exact candidate through daemon/watchdog/restart, historical admission, metadata-write failure and failure-between-milestones installed-entry cases. Missing historical admission never implies confirmation. |
| S03 | fixed by this PR | Adopted v4.6 §12f/I12: Built parking limit 24 h; AwaitingBoot unbounded and reported waiting; `Executor::expire_waiting; Core waiting notices; txn recovery` | `foreground_parking_expires_at_24_boot_hours_and_releases_the_candidate; opening_the_window_at_the_deadline_cancels_instead_of_activating; a_window_before_the_parking_deadline_still_activates; failed_cancellation_keeps_the_waiting_plan_and_root_for_retry; foreground_waiting_expires_with_a_named_reissue_notice_and_reopens_its_incident; published_boot_candidate_waits_without_limit_and_repeats_restart_notice_daily` | The G5 proposal is superseded. Built expires after 24 boot-clock hours as Cancelled(Daemon), releases its candidate root, names the change/reissue action and reopens its linked incident with the consumed budget slot restored. AwaitingBoot remains protected and unbounded, with daily restart reminders and explicit waiting status. | Prepared source + authored UNRUN regressions; execute wall-clock corrections, deadline/window boundary, failed cancellation/retry, restart, incident refund and daily reminders. No forced reboot or defeated foreground work; G5 is absent without changing the historical ratio/trust baseline. |
| S04 | already fixed with evidence | §11/I19 root-only independent approval; `policy::may_approve; daemon approve terminal check; exec workflow` | `root_proposals_require_resubmission_by_an_independent_administrator; existing no-self-approval/terminal cases` | Root-only proposer cannot self-approve; another admin cannot approve original root request → Preserve authority; document nonroot authorized admin fresh proposal/root approval; agent shares user principal | Source at 805cd1c + authored UNRUN workflow regression; Root-only install limitation/manual physical recovery remains explicit; no account creation or approval broadening |
| S05 | fixed by this PR | Adopted v4.6 §10: general authenticated user-service applicability differs from local seated graphical expectation; `state::Assembler::defs; SessionInfo; Linux logind` | `ssh_and_tty_logins_do_not_create_compositor_expectations; locked_and_inactive_graphical_sessions_keep_their_own_readiness; desktop_eligibility_requires_graphical_type_and_live_lifecycle` | SSH/TTY authentication created desktop deadlines → SSH never creates a graphical incident; per-session instances/deadlines preserve two sessions for one uid and locked/greeter/lifecycle cases. Missing observation evidence remains conservative. | Source + authored UNRUN regressions; Execute current merged SSH/TTY/greeter/locked/closing/two-session cases and confirm any added graphical-Type eligibility is an explicitly supported backend lifecycle interpretation of the adopted seated-session contract. |
| S06 | fixed by this PR | Adopted v4.6 §10: external dependency Requires or Diagnostic>=700; module rejects weaker declarations; `diagnose external dependency safety guard; nix/module.nix externalAssertions` | `weak_external_diagnostic_dependency_blocks_local_repair_on_http_503; timed_out_external_dependency_stays_unknown_and_does_not_trigger_local_repair; external_wants_and_ordering_do_not_become_functional_prerequisites; nix/tests/eval.nix module assertion controls` | Weak external Diagnostic metadata could allow local restart/rollback during outage. The module now validates represented external targets, rejects Diagnostic confidence below 700, and requires Readiness establishes explicitly naming service:external:<name> to have a matching Requires or Diagnostic>=700 edge. Wants/Ordering remain non-functional annotations. The repair veto preserves Timeout->Unknown and no local repair for a failed external root. | Prepared source + authored UNRUN Rust and 11 Nix module assertion controls (500/699 reject, 700 accepts, missing edge/target, Wants/Ordering and unrelated local/Diagnostic text controls). Execute module evaluation and actual HTTP503/Timeout cases. Dependency declarations use explicit external unit IDs; URLs and arbitrary prose do not infer an edge. |
| S07 | already fixed with evidence | Adopted v4.6 §11/§12c: unused tokens die with daemon; consumed replay protection and authorized recovery persist; `Executor::new/parked maps; checkpoint Ledger; approve TokenUsed; SPEC` | `unused_approval_does_not_survive_restart_or_compaction; consumed_approval_replay_protection_survives_restart_and_compaction; approval_consumption_write_failure_keeps_execution_parked` | Implementation already discarded unused approvals; docs claimed persisted/rebound authority → Align volatile unused approvals; preserve consumed-token protection and authorized recovery; fix TokenUsed write failure; include Checking/PublishingBoot | Source at 805cd1c plus source fix and authored UNRUN regressions; Run merged expiry/restart/replay/write-failure/live recovery and historical fixtures; preserve adopted approval-audit identity requirements, Checking/Publishing exclusivity, and canonical definition versus applicability distinctions. |
| P09 | fixed by this PR | §10/§12c signed prefix; `txn::Journal::verified_snapshot; daemon hooks/Core cache` | `the_signature_covers_the_head_sequence_and_checkpoint; exported_prefix_and_ledger_survive_other_writers_replay_and_compaction; health_reporting_only_reads_the_cached_state_and_journal_cut` | Format1 lacked head and reporting ran observe/probes → Format2 signed sequence/head/checkpoint identity from consistent ledger cut; cached physical observation context; explicit unavailable/invalid and legacy support | Source + authored UNRUN regressions; Run signing/tamper/restart/compaction/Minimal integration; verify added retained-chain cost on reference workload; no remote witness claim |
| GC | open | §12b/I3 protected candidate survival; `gym gc-during-approval; live terminal transport; VM step/judge` | `approval_candidate_survives_collection_and_commits_in_both_retention_modes; gc-during-approval; gc-retain-all-generations` | Historical VM stays generation1/Prepared after 900s approval stall following successful GC → Main b219d81 identifies/fixes the broken script terminal transport with a real fresh PTY/session and positive approve-at-terminal-runs case; preserve it with PR whole-process deadline/error propagation and exact verdict checks. Candidate survival/verification/Committed oracles stay intact in normal and retain-all modes. | Historical VM job at 805cd1c; source + authored UNRUN regression; Execute the merged real VM GC and positive terminal approval cases to validate the main diagnosis/fix. Historical no-approval response did not establish candidate deletion; no longer window, unreviewed Unsupported or weaker postcondition is permitted. |

## Shared prerequisite boundary

This PR covers the shared Phase A prerequisite set named by the brief
(P01–P09, P11–P12): schema/state/health, executor-derived policy facts,
transactions/watchdog, incidents, NixOS mechanisms/posture, signed local hooks,
and gym/acceptance controls. P09 is explicit above. The separate fleet document
with individual P01–P08/P11–P12 labels is not present in the repository or supplied
attachment, so its exact per-ID crosswalk remains review work; no labels or
fleet acceptance are invented. P10 is conditional Phase B candidate-bound
sandbox behavior; P13–P14 are optional. Coordinator/consensus/remote approval
or mutation, scheduler/workload protocols, model work and C01–C07 remain separate.
Firecracker repair smoke remains non-gating Phase A evidence.

## Preserved authority and format boundaries

Agents act with their launching user's current permissions, attributed without
a login session/seat/terminal, and only through the successfully launched,
durably journaled instance (I24). A name is not an authority token. A failed
start or failed/torn authority append grants no authority; legacy records without
an instance do not acquire one on replay. Stopped-name reuse follows the new
instance, while live collisions remain refused. Live/name resource quotas are
separate from this authority rule.

GC remains Runtime with existing administrator authorization and protected sets;
retain-all protects every generation even during emergency collection, while
other garbage may still be collected. Existing build/generation-root cleanup
is retained. Unresolved generation interlocks keep candidate/root/fallback facts;
unknown historical identities require administrator reconciliation before unsafe GC.

Journal framing stays chain format 2. CheckContext v1 stores completion and
passing-probe obligations; terminal/interlock evidence v1 preserves formerly
lost facts. BootAdmission v1 binds the epoch-owned admission record to its
boot identity and boot clock; old checkpoints without it acquire no admission. Missing historical fields remain absent/Unknown. The implementation's
PublishingBoot is SPEC's Publishing state; old readers cannot safely downgrade
an in-flight new history. Report format 2 signs a consistent cached ledger-prefix
context under a separate domain without fresh probes. Log format 2 and completion
evidence v1 separate lifecycle, actuation, sampled expectation and observed health.
Supported replay/consumer fixtures must execute before acceptance is complete.

## D08 evidence and remaining gates

Expected IDs/roles/harnesses are derived from the current catalog, including main's
positive terminal-approval, instance-collision and R03/R08/R10 cases. No historical
count, blank waiver, or unreviewed Unsupported result can shrink required coverage.
The two legacy direct-kernel/storage Unsupported exceptions in main remain a
review-metadata migration issue: this PR does not invent reviewer/expiry evidence.

See the [acceptance report](shared-core-acceptance-report.md),
[machine manifest](shared-core-acceptance.json), and
[reproduction tooling](shared-core-acceptance-tooling.md). After every implementation,
fixture, governing-contract or build/CI change, select a new immutable candidate and
rerun affected checks. Evidence-only follow-ups may change only the declared evidence
files. No union of selected historical passes certifies a release.

The shared foundation is not freeze-ready until adopted v4.6 behavior, current
Rust/proof/VM/installed-entry/durability acceptance and accurately scoped performance
evidence agree. S02/S03 source changes are prepared and still require compiled
and installed-entry acceptance; S06 module validation requires actual Nix
evaluation, and S01 layout coverage remains explicit until its required cases pass. Cooperative-lock and GC/positive-approval
cases still need current execution. Full
personal-profile optical input and real GPU/frame measurements require reference
hardware and reviewed practical margins; headless/synthetic controls cannot satisfy them.
