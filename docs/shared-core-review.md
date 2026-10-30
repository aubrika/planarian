# Shared-core safety reconciliation

Instruction/current-main baseline: `805cd1c953d78044a8c94ef9e3d35e33eb1dfb1a`.
Original review baseline: `bd6d24d17c7d304715436bfa18c13c6343bcbf4e`.
The fixing candidate is the immutable `source.revision` in
[shared-core-acceptance.json](shared-core-acceptance.json); no historical run
is attributed to that candidate. “Fixed by this PR” below means the source
change is prepared; **acceptance is incomplete** until its required runs pass.
Authored Rust regressions are UNRUN because Rust/Nix/Verus/Kani/VM tools are
unavailable here. Local Python tests use explicit stub/synthetic inputs to
check acceptance accounting, not to establish actual repairs or proofs.

## Disposition and D01 requirement map

Proposed normative amendments live only in [SPEC](SPEC.md), including the
S01–S07 contracts. Their adoption remains pending owner review; no invariant
is weakened or authority expanded. Initial catalog review is already accepted.
Engineering P1 and bypass-register High are distinct: zero High rows does not
close any R/S item. B-20/R11 is an open Medium replacement invariant gap.

| ID | Status | Requirement and current path | Regression | Before → prepared behavior | Evidence; remaining acceptance/assumption |
| --- | --- | --- | --- | --- | --- |
| R01 | fixed by this PR | §12/I6/I15; `crates/txn/src/kernel.rs:run_boot_only/reconcile_boot_publication; schema txn; watchdog` | `boot_publication_crash_boundaries_remain_tracked_for_both_owners; partial_unknown_and_failed_boot_publication_reconcile_actual_effects; boot_publication_interlock_preserves_candidate_roots_on_disk` | Built publication could mutate before tracked state → PublishingBoot precedes intent/call; unknown boot/selection interlocks with candidate/root/fallback; old publication intent reconciles | Source + authored UNRUN regressions; Installed-entry VM crash matrix, actual ext4/btrfs execution and powered failure evidence still required |
| R02 | fixed by this PR | §12e/I16; `crates/txn/src/kernel.rs:write_committed; exec/lib.rs; watchdog` | `every_generation_completion_establishes_the_same_floor; completion_crashes_and_torn_floor_or_commit_writes_preserve_the_obligation; a_fenced_completion_cannot_write_global_floor_or_baseline_records` | Daemon best-effort floor followed Committed; watchdog/boot-only omitted it → Versioned durable intent; fenced serialized floor/LiveTested precede Committed, interrupted completion remains obligated | Source + authored UNRUN regressions; Actual proofs/daemon/watchdog/restart/boot-only fault runs; historical terminal facts require administrator migration, not inference |
| R03 | fixed by this PR | §11/I21; `crates/exec/src/derive.rs` | `stopped_override_has_the_same_effects_and_floor_as_a_stop` | Stopped override erased disruption/dependents → Equivalent stop effects share floors; LeaveAlone remains nonactuating | Source + authored UNRUN regression; Run local/SSH/multiuser cases and actual display/network consequences |
| R04 | fixed by this PR | §9/§11/I14; `crates/exec/src/lib.rs:plan_existing/revalidate_activation; backend-linux/nixos.rs` | `existing_generation_derives_activation_and_override_configuration; changed_activation_preflight_is_rejected_before_execution` | Existing targets used manifests without actual activation/config differences → Target-bound preflight/override identity; execution revalidates base and activation evidence; Unknown rejects | Source + authored UNRUN regressions; Run equal-UnitDefs changed-content NixOS VM cases; unmodeled discovery/historical target evidence fails closed |
| R05 | fixed by this PR | §12d/I20/owner agent decision; `crates/backends/linux/src/systemd.rs; nix/posture.nix; daemon AgentRun` | `launcher_units_are_externally_supervised_and_bounded; admission_counts_starts_and_preserves_root_capacity; nix/tests/posture.nix public launches` | Transient agents escaped static agentUnits posture list → Readiness-bound bounded slice; failure marker before slice stop; live and durable-name quotas/root reserves; same-owner reuse deduplicates registry, each launch still journaled; failed start cannot reattribute; distinct registry names and repeated starts are bounded | Source + authored UNRUN unit/VM regressions; Run actual systemd Absent/Crashed/Integrity/recovery/resource limits; proposed numerical/name-lifecycle refinements await owner review |
| R06 | fixed by this PR | §10 bounded total probe lifetime; `crates/backends/linux/src/probe.rs; cmd.rs` | `trickling_http_has_one_total_deadline; resolver_process_is_cancelled_inside_the_total_deadline; inherited_output_pipe_is_inside_the_deadline` | DNS escaped timeout; per-read HTTP deadlines reset; inherited pipes could stall cleanup → Cancellable resolver/process groups, one network deadline, bounded batches/workers/output, no detached resolver thread | Source + authored UNRUN regressions; getent CLI syntax only; Run blocked DNS/connect/write/trickle/resource accounting with measured scheduling margin; responsive local filesystem/kernel remains platform assumption |
| R07 | fixed by this PR | §12 checking/I10; `crates/exec/src/host.rs; schema CheckContext; watchdog` | `mixed_baselines_preserve_each_passing_probe_through_replay; missing_stale_timeout_error_and_old_pass_are_not_preservation_evidence; authorized_removal_changes_applicability_but_probe_removal_does_not` | Aggregate Degraded/Unknown omitted individual passing evidence → Versioned durable applicable passing probe definitions independently preserved, requiring fresh new Pass | Source + authored UNRUN regressions; Run replay/watchdog cases and real canonical checks; authorized applicability changes distinct from weakening |
| R08 | fixed by this PR | §13 authorized incident control; `crates/daemon/src/core.rs release handlers` | `denied_release_preserves_incident_and_linked_overrides` | Denied release still replenished incident/released linked overrides → Effects follow successful durable authorized LiftOverride only | Source + authored UNRUN regression; Run full incident budget/cooldown/state comparison and successful release control |
| R09 | fixed by this PR | §11 authenticated admission; `crates/exec/src/lib.rs admission/prebuild_job; daemon/core.rs/main.rs queue` | `unauthorized_catalog_change_does_no_expensive_work; deferred_catalog_work_authenticates_before_staging; expensive_work_is_bounded_per_principal_with_admin_reserve` | Valid unauthorized catalog requests staged/built before authorization → Cheap authenticated capability/argument admission; bounded attributed queue, admin reserve, full post-build policy retained | Source + authored UNRUN regressions; Run actual stage/evaluate/build call counts/load; AskFirst remains admitted for authorized proposals |
| R10 | fixed by this PR | §9 trustworthy risk evidence; `crates/backends/linux/src/nixos.rs:checked_dry_activate` | `discovery_checks_real_command_exit_timeout_and_protocol` | Discovery ignored actual failure/timeout/incomplete output → Reject nonzero/timeouts/capped/malformed/incomplete/unmodeled discovery before optimistic activation | Source + authored UNRUN actual-command regression; Run actual pinned NixOS backend/VM; NixOS own child-script honesty remains explicit trust boundary |
| R11 | blocked | §9/I23; `crates/backends/linux/src/nixos.rs:swap_override_after_comparison` | `demonstrates_unclosed_arbitrary_editor_override_replacement_bypass` | Check-then-rename is not arbitrary-editor CAS → No false closure: race characterization covers FD/rename editors and promotion/restoration; B-20 remains open | Source + authored UNRUN negative characterization; Requires enforceable exclusive writer profile or explicit owner adoption of a justified narrower contract; advisory locking/mode bits alone do not suffice |
| R12 | fixed by this PR | §15 verdict integrity; `nix/gym/run-vm.sh; acceptance.py; nix/tests/gym-vm.nix` | `test_acceptance.py actual runner failing-build/status/coverage cases` | Nix eval success + all builds fail returned zero; missing/duplicate/bad verdict ignored → Build/step/judge errors propagate; exact derived expected IDs/roles; stale results cleared | Executed local shell/Python regression + pre-fix counterfactual; Current complete Nix VM catalog still unrun; baseline script failed all seven injected negative assertions, fixed runner rejects them |
| R13 | open | §21 resource/performance acceptance; `nix/tests/bench.nix; nix/gym/performance.py` | `test_performance.py; installed metric helper CPU-load subtest` | MainPID counters missed helpers; one-second min FPS falsely used as frame p99 → Whole-cgroup CPU/memory and actual frame-only metrics prepared; physical input interface/plan; no desktop measurement invented | Source + local Python metric regressions (see report); Reference hardware, measured input latency, full personal-profile repetitions and proposed practical margin adoption remain outstanding |
| R14 | fixed by this PR | §17a proof integrity/ratchet; `nix/gym/proofs.py; gym/verification.rs; docs/proof-obligations.toml` | `test_proofs.py duplicate/deleted/conditional/unverified names and stale/failed receipts` | Name/count presence could discharge removed or unverified properties → Unique source/engine mapping + complete successful current-source receipts; preserve baseline invariant set and 47:56 denominator | Executed local Python accounting controls; source map only; Actual Verus/Kani runs unrun; proposed proof map requires review; synthetic verifier logs are accounting controls, not proofs |
| R15 | fixed by this PR | §15 role-qualified coverage; `nix/gym/acceptance.py/run-fake.sh; gym/main.rs; workflows` | `test_acceptance.py required Unsupported/omission/waiver/exit negatives` | Applicable required coverage silently disappeared as Unsupported → Exact current id/harness/role and explicit reviewed expiring waivers; no blanket Unsupported acceptance | Executed local Python/shell controls; No waivers adopted; full current fake/VM/bench catalog and required critical PR checks must pass |
| R16 | fixed by this PR | §18 documentation/evidence; `docs/SPEC.md; AGENTS.md; deviations/guarantees/ga-status/bypasses/verification` | `nix/gym/manifest.py; test_manifest.py; reconciliation and source fingerprint` | Historical/mixed results and narrower proofs overstated current closure → One authoritative proposed contract; historical evidence labeled; current acceptance manifest leaves unrun gates open | Source + executed local manifest-accounting controls; Normative amendments remain proposed; final candidate tests/proofs/VM evidence and R11/GC/S01-S02 closure required |
| S01 | open | §12e/I1/I16; `txn automatic_target_eligible; Linux boot publication/default; installed-entry target` | `failed_boot_only_generation_uses_floor_eligible_fallback_not_old_known_good; no_floor_eligible_automatic_boot_target_refuses_before_publication` | Live/watchdog/boot selection eligibility not unified → Proposed single eligibility rule: recoverable trusted target >= current floor; manual below-floor known_good remains menu-only; no target -> admin recovery | Source + authored UNRUN regressions; Complete initrd/bootloader enforcement and installed-entry failure evidence remain open; preserve manual fallback distinction |
| S02 | open | §10/§12d readiness milestones; `daemon READY path; Core boot_confirmation; txn await_boot; installed-entry target` | `healthy early-ready/later-confirmation and failed-candidate installed-entry cases` | Boot confirmation and early ready were inconsistently summarized → Existing early READY retained; checked commit/live_tested separated from later ten-minute known_good; proposed normative alignment | Source; existing behavior reconciled; Owner adoption and real installed-entry failure-between-milestones evidence required |
| S03 | blocked pending owner review | §12f/G1 conditional liveness; `txn Built/AwaitingBoot recovery; SPEC parking contract` | `intentional_boot_parking_has_no_forced_reboot_or_untracked_cancellation; interrupted_withdrawal_never_claims_the_boot_candidate_untracked` | No stated progress assumptions for intentional parked work → Proposed explicit external-window/operator-reboot assumptions; no forced progress/cancellation of published obligation | Source + authored UNRUN regressions; Proposed G5 adds one counted progress assumption (current 47:57/trust 38 vs unchanged baseline 47:56/trust 37); explicit contract/baseline decision required, no reset. Run long foreground/deferred reboot/restart and verified withdrawal tests |
| S04 | already fixed with evidence | §11/I19 root-only independent approval; `policy::may_approve; daemon approve terminal check; exec workflow` | `root_proposals_require_resubmission_by_an_independent_administrator; existing no-self-approval/terminal cases` | Root-only proposer cannot self-approve; another admin cannot approve original root request → Preserve authority; document nonroot authorized admin fresh proposal/root approval; agent shares user principal | Source at 805cd1c + authored UNRUN workflow regression; Root-only install limitation/manual physical recovery remains explicit; no account creation or approval broadening |
| S05 | fixed by this PR | §10 session applicability; `state::Assembler::defs; SessionInfo; Linux logind` | `ssh_and_tty_logins_do_not_create_compositor_expectations; locked_and_inactive_graphical_sessions_keep_their_own_readiness; desktop_eligibility_requires_graphical_type_and_live_lifecycle` | SSH/TTY authentication created desktop deadlines → Separate authenticated user services from local graphical x11/wayland active/online sessions; missing type defaults false | Source + authored UNRUN regressions; Run greeter/locked/closing/two-session VM evidence; fixture stand-in is not COSMIC performance |
| S06 | fixed by this PR | §10/§13 external-outage guarantee; `diagnose external dependency safety guard` | `weak_external_diagnostic_dependency_blocks_local_repair_on_http_503; timed_out_external_dependency_stays_unknown_and_does_not_trigger_local_repair; external_wants_and_ordering_do_not_become_functional_prerequisites` | Weak external Diagnostic edge could allow local restart/rollback during outage → Explicit external Diagnostic/Requires readiness veto separate from explanation confidence; Wants/Ordering unchanged | Source + authored UNRUN regressions; Honest dependency metadata required; run actual HTTP503/Timeout VM cases and adopt proposed contract |
| S07 | already fixed with evidence | §11/§12c approval restart; `Executor::new/parked maps; checkpoint Ledger; approve TokenUsed; SPEC` | `unused_approval_does_not_survive_restart_or_compaction; consumed_approval_replay_protection_survives_restart_and_compaction; approval_consumption_write_failure_keeps_execution_parked` | Implementation already discarded unused approvals; docs claimed persisted/rebound authority → Align volatile unused approvals; preserve consumed-token protection and authorized recovery; fix TokenUsed write failure; include Checking/PublishingBoot | Source at 805cd1c plus source fix and authored UNRUN regressions; Run expiry/restart/replay/live recovery/historical fixtures; proposed contract adoption remains pending |
| P09 | fixed by this PR | §10/§12c signed prefix; `txn::Journal::verified_snapshot; daemon hooks/Core cache` | `the_signature_covers_the_head_sequence_and_checkpoint; exported_prefix_and_ledger_survive_other_writers_replay_and_compaction; health_reporting_only_reads_the_cached_state_and_journal_cut` | Format1 lacked head and reporting ran observe/probes → Format2 signed sequence/head/checkpoint identity from consistent ledger cut; cached physical observation context; explicit unavailable/invalid and legacy support | Source + authored UNRUN regressions; Run signing/tamper/restart/compaction/Minimal integration; verify added retained-chain cost on reference workload; no remote witness claim |
| GC | open | §12b/I3 protected candidate survival; `gym gc-during-approval; live terminal transport; VM step/judge` | `approval_candidate_survives_collection_and_commits_in_both_retention_modes; gc-during-approval; gc-retain-all-generations` | Historical VM stays generation1/Prepared after 900s approval stall following successful GC → Historical log rules out inferring candidate deletion from verdict; fix swallowed step/transport failures, preserve candidate survival/verification/commit oracle | Historical VM job at 805cd1c; source + authored UNRUN regression; Exact historical hang cause and real normal/retain-all VM reproduction remain required; no longer window/Unsupported/oracle weakening |

## Shared prerequisite boundary

This PR covers the shared Phase A prerequisite set named by the brief
(P01–P09, P11–P12): schema/state/health, executor-derived policy facts,
transactions/watchdog, incidents, NixOS mechanisms/posture, signed local hooks,
and gym/acceptance controls. P09 is mapped explicitly above. The separate
fleet specification with individual P01–P08/P11–P12 labels is not present in
main or the supplied attachment, so its exact per-ID crosswalk remains owner
review; no labels or fleet acceptance are invented. P10 is conditional Phase B
candidate-bound sandbox behavior; P13–P14 are optional. C01–C07, coordinator,
consensus/remote approval/mutation, scheduler/workload protocols and model work
remain separate. Firecracker repair smoke remains non-gating Phase A evidence.

## Preserved owner decisions and format boundaries

Launched agents act with their user's current permissions, attributed without
a login session/seat/terminal. GC remains Runtime with existing administrator
authorization and protected sets; retain-all protects every generation even
in emergency collection and other garbage may still be collected. Prior
build-root/generation-root cleanup is preserved. An unresolved generation
interlock retains candidate/root/fallback; unknown historical identity blocks
unsafe collection until administrator reconciliation.

Journal framing remains chain format 2. CheckContext v1 records completion
and passing-probe obligations; terminal/interlock evidence v1 preserves facts
formerly discarded. Historical absent fields remain absent/Unknown and are
never reinterpreted as authority/evidence. New PublishingBoot histories require
a new reader; an old daemon cannot safely downgrade an in-flight history.
Health report format 2 uses a new signing domain and explicit legacy evidence.
Executor log format 2 and completion evidence v1 separate lifecycle, operation,
expectation and health. Supported old-format replay/consumer fixtures are
authored but still require execution.

## D08 evidence and remaining gates

See [acceptance report](shared-core-acceptance-report.md), the
[machine manifest](shared-core-acceptance.json), and
[reproduction tooling](shared-core-acceptance-tooling.md). Expected IDs/roles/
harnesses come from the current catalog, with no blanket Unsupported waiver.
The 47:56 invariant-support ratchet, trust 37 and internal-unproven 5 baseline
are preserved. Proposed G5 makes current declarations 47:57/trust 38; this
regression is visible and the existing ratchet must reject it until an explicit
owner decision on the conditional contract and any justified baseline amendment; 45 unique proof IDs support 47 invariant edges. No successful
current verifier artifact exists yet.

Implementation is prepared for the items labeled fixed; the shared foundation
is not freeze-ready. R11 needs an enforceable writer boundary or explicit
adopted contract decision; GC needs exact cause/reproduction; S01/S02 need
complete installed-entry/early-boot acceptance. S03/G5 additionally needs explicit owner review of the visible ratchet regression. Every required Rust/Nix/proof/
VM/durability gate remains unrun here. Full personal-profile input/frame
measurements require reference hardware and approved practical margins.
No headless subset or mixed-revision passes certify that gate.
