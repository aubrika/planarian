# Regression ledger

One row per Planarian bug found during development, the fix, and the test
that now catches it (owner decision, Nov 3: catch-up coverage for every bug
surfaced in development; from now on a PR that changes a pure fold, parser,
classifier or state machine carries a property test for what it changes).

Sources: `git log` on `main` (and merged PR bodies), `docs/review-reconciliation.md`,
`docs/ga-status.md`, `docs/catalog-review.md`, `docs/bypasses.md`. The clone's
history starts at a graft (Oct 29): bugs found in VM runs #7, #18 and #24 were
fixed before it, so they have no fixing commit here. The code and the test
are cited instead.

**Kind:** *proptest* (an invariant over generated inputs), *Kani*, *Verus*,
*unit* (a fixed case), *gym-fake* or *gym-VM* (a catalog entry,
`crates/gym/catalog/phase-a/`), *VM* (a NixOS VM test, `nix/tests/*.nix`),
*eval* (module-eval).

**Fails on revert:** *verified* means this ledger's author reintroduced the
bug on a scratch tree and watched the test fail; the output is quoted.
*recorded* means the fix's author or the reviewer recorded it, in the commit
or the cited doc. *none recorded* means nobody has shown it yet.

**Adding a row** (§18 rule 23, owner decision, Nov 3): a PR that fixes a bug
adds its row here in the same PR, in the section for its area, with the next
free number. Fill in the bug, the fix (the PR number; the commit once merged),
the crate and function, the test that fails on the unfixed code, the test's
kind, and the evidence it fails on revert (the failing output or minimal
case). A bug that only a kernel or a VM can show cites its VM test. A PR that
changes a pure fold, parser, classifier, ordering or state machine also
carries a property test for the invariant it changes.

**Status:** **covered** (the strongest cheap test exists and bites), **gap**
(a property-shaped bug held only by fixed cases; a property test is owed),
**pending** (the fix is not on `main` yet).

## Journal and transaction kernel (`crates/txn`, `crates/schema`)

| # | Bug | Fixed in | Crate::function | Test that catches it | Kind | Fails on revert | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| J1 | An intact tail record that did not parse was truncated as if torn. It was evidence lost, not Integrity (§12c Format) | #41 (`b3f106f`, `a4134b1`) | txn::Journal::scan | `an_intact_frame_is_never_truncated` (txn/tests/journal_props.rs); `intact_but_unparsable_tail_is_integrity_and_kept` (journal.rs) | proptest + unit | verified: with #41's journal.rs change reverted, "record 1 of 1 does not parse but open gave Ok(0)", minimal `n = 1, byte = 0` | covered |
| J2 | (#41's other side) the fix must still truncate a torn tail, and keep every earlier record | #41 | txn::Journal::stop_at_tail | `a_torn_tail_drops_only_the_last_record` (journal_props.rs); `torn_tail_is_still_truncated` (journal.rs) | proptest + unit | verified: the over-correction (Integrity instead of truncating) panics "a torn tail opens" | covered |
| J3 | A withdrawal (§12f) lived only in the daemon's memory: a restart between the withdrawal and the rollback's end lost the update | #26 (`2a24d30`) | txn::Kernel::withdraw, Ledger::apply_advance/archive (`Advance.withdrawn_for`, `Transaction.prepared_again_from`) | `reopening_keeps_every_link` (journal_props.rs); `withdrawal_links_replay_and_survive_compaction` (kernel.rs) | proptest + unit | verified, three ways: `withdrawn_for` not serialized → minimal `[Prepare(false), Withdraw(0, 0)]`; `archive` dropping it → fails; `prepared_again_from` not serialized → minimal `[Prepare, Withdraw, PrepareAgain]` | covered |
| J4 | (#26, daemon half) at start, what is still to be prepared again is rebuilt from the journal, once and deduped against the restart re-prepare set | #26 (`2a24d30`) | daemon::Core::start (inline filter) | `a_withdrawn_update_is_prepared_again_after_a_restart`, `a_withdrawn_update_prepared_again_is_not_prepared_twice_after_a_restart`, `an_ordinary_submission_prepares_nothing_again` (daemon/src/core/tests.rs) | unit | recorded: reviewer's case `7b5cb65` failed at `2cba51e` | gap, waiting on extraction (lane-daemon pulls the selection out of `Core::start` with `NotPreparedAgain`) |
| J5 | `DerivedFacts.removes` changed shape (`Vec<UnitId>` → pairs), so a `Prepared` record main had journaled stopped decoding | #37 (`1d1eae2`) | schema::DerivedFacts (`removes`, `removes_each`) | `removes_in_mains_form_decodes` (schema/tests/journal_compat_props.rs); `records_journaled_before_the_withdrawal_fields_decode` (core/tests.rs, literal fixtures) | proptest + unit | verified: with `removes: Vec<(UnitId, Sensitivities)>`, "main's form does not decode: invalid type: string \"service:a\", expected a tuple of size 2" | covered |
| J6 | C10: the disruption became a set; records holding the single value must read as that set | #21 (`1371314`) | schema::Disruptions (`DisruptionsRepr`) | `a_single_disruption_decodes_as_its_set` (journal_compat_props.rs); `disruptions_read_the_old_single_value` (transition.rs) | proptest + unit | verified: `One(_) => Brief` gives Brief for "SessionLoss"; dropping `serde(from)` fails "invalid type: string \"None\"" | covered |
| J7 | A takeover acked an op its fenced, still-running predecessor had just acked: `DuplicateOp`, transaction left in flight | `6ad8521` (#6) | txn::Kernel::supersede_unacked | `a_late_ack_from_the_old_owner_is_not_acked_twice` (kernel.rs); `crash-slow-worker-overlap` | unit + gym-VM | recorded: "with the check removed it fails on DuplicateOp" | gap, waiting on extraction: an interleaving property (old owner's OpAck vs takeover's supersede, no op acked twice) |
| J8 | C16: a damaged checkpoint read as Absent (start empty), not Integrity | `7059f7d` (#2) | txn::Journal::load_checkpoint | `damaged_checkpoint_is_integrity` (journal.rs); `checkpoint-bad-crc` | unit + gym-fake | recorded: "fail without the change" | gap: proptest over checkpoint corruptions ⇒ Integrity, never Absent |
| J9 | P21: `MemStore::sync` was a no-op, so the fake's "journal fsync is durable" contract could not fail; `cancel`/`unbind` absent from the conformance matrix | #32 (`c142215`, `d151b5d`, `97b6c61`) | txn::MemStore::crash/sync; gym::conformance::MATRIX | `a_write_not_yet_synced_is_lost_in_a_crash`, `a_synced_write_survives_a_crash`, `an_appended_record_survives_a_crash` (memstore_sync.rs); `the_conformance_matrix_covers_unbind_and_cancel` | unit | recorded: did not compile on `main`; "unbind is not in the conformance matrix" | gap: model-based proptest of write/sync/crash sequences |
| J10 | `FileStore` fence creation did not fsync the txn directory | #33 (`2e493ab`) | txn::FileStore::create_fence/set_fence | `file_store_set_fence_creates_a_missing_directory` (journal.rs) | unit | none recorded | covered (I/O, not property-shaped) |
| J11 | R01/S01: boot-only publication had an uncovered crash window (no `Publishing` state) | `88a984a` (#2) | txn::Kernel (`TxnState::Publishing`, recover_publishing) | `crash-publishing-before-publish`, `crash-publishing-after-publish`; Verus `only_generations_publish` | gym-fake + Verus | recorded: "the second fails without the fix" | covered |
| J12 | R02/I25: the security floor advanced outside durable commit; the watchdog and boot-only paths skipped it | `af5bf42` (#2) | txn::Kernel commit | `floor-moves-via-watchdog`, `floor-moves-via-boot-only`, `revert-to-older-sets-no-floor` | gym-fake | recorded: "without the kernel's derivation the first two … fail" | covered |
| J13 | S07: I6's exclusive list omitted `Checking` and `Publishing` | `fa44baf` (#2) | schema::TxnState::exclusive; txn ledger compatible | `i6_generation_transactions_are_exclusive` (kernel.rs); Verus `i6_one_generation_active` | unit + Verus | recorded: "fails with Checking dropped" | covered |
| J14 | R11/C5: the override swap was check-then-rename, not compare-and-swap; txn dirs not exclusive | `867ffc1` (#6) | backends-linux::nixos::swap_override; txn::Store::create_fence/forget_fences | Kani `override_swap_never_overwrites_a_third_party`; `the_override_swap_waits_for_the_directory_lock`; `txn_fences_are_exclusive_and_swept_after_checkpoint`; `en-i23-third-party-override-kept` | Kani + unit + gym | recorded (reconciliation: "every case was checked to fail with its fix removed") | covered |
| J15 | Startup revert stalled 15 min: the activation recovery ran before `planarian-ready.target` | #14 (`a018b08`), VM guard #15 (`6b03181`) | txn::Kernel::reconcile_deferring/finish_deferred; daemon::Core::finish_recovery | `deferred_recovery_runs_no_activation_before_ready`, `undeferred_reconcile_recovers_at_once` (kernel.rs); `restart_reverts_an_interrupted_activation_after_ready` (core/tests.rs); VM judge `stalls` on `crash-slow-worker-overlap` | unit + gym-VM | recorded: "shown failing on `main` without the fix, VM run 41355934489" | covered (systemd job ordering; VM-shaped) |

## Daemon timing, holds and posture (`crates/daemon`, `crates/incident`, `nix/posture.nix`)

| # | Bug | Fixed in | Crate::function | Test that catches it | Kind | Fails on revert | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| D1 | P16 race: after a planariad restart, `planarian-posture-lift` could run before `planarian-respond@absent`, find no alarm, and leave Absent raised | #43 (`862ea72`; VM wait `a206de6`) | nix/posture.nix (lift `After=` respond@absent/@crashed; counts the markers) | vm-posture subtest P16 (nix/tests/posture.nix); module-eval ordering + marker check (nix/tests/eval.nix) | VM + eval | recorded: VM run 41507137168 failed P16 | covered (systemd ordering; no pure function) |
| D2 | flap-30s: the repair backoff was anchored at the tick's `observed_at` (observation start, before the probes ran), so after a slow observation two attempts came 59 967 ms apart for a 60 s floor. Fixed by anchoring at the clock read after the attempt | #44 (`ec10006`) | daemon::Core::repair_one/activate_waiting → incident::Manager::record_attempt | `timing_props::slow_observations_never_shorten_a_backoff_or_a_cooldown` (daemon core/tests.rs); `backoff_is_kept_between_attempts_even_after_a_slow_observation` | proptest + unit | verified: with `ec10006` reverted, "attempts 2 and 3 55000 ms apart (min 60000 ms)" (cooldown check disabled to isolate it); with the cooldown check on, it fails first on the cooldown's anchor | covered |
| D3 | The 1 h / 6 h cooldowns and the 6 h hold were anchored the same wrong way | #44 (`da88be7`) | daemon::Core::repair_one → Manager::exhausted/escalate | `timing_props::slow_observations_never_shorten_a_backoff_or_a_cooldown`; `an_exhausted_cooldown_runs_from_the_decision` | proptest + unit | verified: with `da88be7` reverted, "cooldown until 1700003620500 set on a tick from 1700000020500 (+500 ms of probes)", minimal `f = UnknownDriver` | covered for cooldowns; the hold (`escalate`, RevertBlockedByFloor) is checked by the same property but none of its faults reach it, so its anchor rests on the unit test of `da88be7` |
| D4 | P9's slow-tick warning fired on nearly every VM tick | `6ad8521` (#6) | daemon::Core::tick (`last_slow_warning`) | `a_slow_tick_is_warned` (core/tests.rs) | unit | none recorded | gap: rate-limit property (at most one a minute, none lost from the count) |
| D5 | Notices stopped reaching the journal once 64 had accumulated | before history | daemon::Core::say/notices_since | `notices_keep_reaching_the_journal_once_the_deque_is_full` (core/tests.rs) | unit | recorded (ga-status, generic) | gap: ring-buffer cursor property over random say/drain interleavings |
| D6 | Status requests ran the probes, starving the repair loop (a killed service restarted 100 s late) | before history | daemon::Core::handle | `status_requests_do_not_run_the_probes` (core/tests.rs) | unit | recorded (ga-status, generic) | covered |
| D7 | R08: a refused release still replenished the repair budget | `4d27bce` | daemon::Core (LiftOverride) | `release-refused-leaves-incident` | gym-fake + gym-VM | recorded: "fails without the fix" | covered |
| D8 | P7/P8: a write-back did not queue behind a generation transaction; a deferred repair was not deferred | `905a06d`, `b077335` (#6) | daemon::Core::flush_writebacks/foreground_depends_on | `a_write_back_queues_behind_a_generation_transaction`, `a_deferred_repair_is_deferred_in_fact` | unit | recorded (generic) | covered |
| D9 | S03: a repair parked in `Built` was not bounded at 24 h, and its waiting spent a budget slot | `6c8967e`, `edc849f`, `0251fb8` (#2) | exec::Executor (Built expiry); daemon::Core | `built-parking-expires`, `awaiting-boot-reminds-daily`; `an_expired_wait_reopens_its_incident` | gym-fake + unit | recorded: "fails without the change" | covered |
| D10 | §12f: a rollback waited for a window; a repair rollback was parked in `Built` | #26 (`1f142d1`) | exec::schedule | `a_rollback_never_waits_for_a_window` + four I6 withdrawal tests (core/tests.rs); `rollback-repair-*` | unit + gym-fake | recorded: "fails on `main`" | covered |
| D11 | C18: no `NoSnapshot` was logged for a UserData transaction; an approval's agent was lost when its change waited | #24 (`721b388`, `5f58ac5`, `9fe4939`, `a406ae7`) | daemon::Core (LogRecord) | `user_data_without_a_snapshot_backend_logs_no_snapshot` + three agent tests (core/tests.rs) | unit | recorded: `5f58ac5`, `a406ae7` "fails without the fix" | covered |
| D12 | P19: `core_hash` was always `Hash::ZERO` | #19 (`ce55165`) | daemon::config::core_hash | `the_state_carries_the_recorded_core_hash` | unit | none recorded | covered |
| D13 | P23: the first residue kill taught nothing | `8a0e523` (#2) | daemon::Core (residue) | `residue-first-kill-teaches-stop`; Kani residue harnesses | gym-fake + Kani | recorded: "fails with the lesson removed" | covered |
| D14 | Network hold (#36/#40): a flushed hold table failed open; a restart lifted the hold; a failed re-apply was never retried; an uncheckable table re-applied every tick; mapped IPv4 flows were cut; the scope walk was unbounded | #36, #40 (`80edb77`, `6f68d55`, `d147ec6`, `bc38cc8`, `3f8cb25`, `504a43a`) | daemon::hold, backends-linux::hold, `planarian-hold@` | `a_flushed_hold_table_is_put_back`, `a_failed_reapply_is_retried_with_backoff`, `an_uncheckable_hold_table_alarms_once_and_is_checked_again`, `reapply_reloads_an_active_hold_and_starts_an_inactive_one`; vm-netsec; module-eval | unit + VM + eval | recorded per commit | gap (one): the hold fold `Ledger::holds()` (last event per unit wins) is a pure fold held by one unit test |

## Change path: derive, policy, exec (`crates/exec`, `crates/policy`)

| # | Bug | Fixed in | Crate::function | Test that catches it | Kind | Fails on revert | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | C10: `restart_disruption` folded with `max`, so ConnectivityLoss + DataInterruption kept only ConnectivityLoss and a seated user escaped the DataInterruption floor | #21 (`1371314`), #27 (`5fc95e2`) | exec::derive::unit_facts | `each_disruption_keeps_its_own_floor` and three already-failed tests (exec/src/tests.rs); `c10_two_disruptions_meet_both_floors` (policy); `disruption-each-kind-keeps-its-floor` | proptest + unit + gym-fake | `derive::props::the_disruption_is_every_touched_units_own_kind` (exec/src/derive_props.rs). verified: the `max` fold put back gives `{session_loss}` for SessionLoss + Brief; recorded: "On `main` it commits without asking" | covered |
| C2 | C19: `touches_manifest` compared only four fields, not `desired`, restart/grace fields, added or removed units, or user scope | #29 (`ff6f426`, `3e52492`) | exec::derive::touches_manifest | `derive_c19_tests.rs` (six cases) | unit | recorded: "4 of 6 fail on `main`" | gap: for any single-field edit of any entry, `touches_manifest(m, m') ⇔ m ≠ m'` (canonical probes aside) |
| C3 | R03: a stopped override erased the disruption it causes | `20d4f2c` | exec::derive::derive (SetOverride arm) | `override-stopped-equals-stop` | proptest + gym-fake + gym-VM | `derive::props::an_override_that_stops_derives_a_stops_facts` (exec/src/derive_props.rs). verified: with the pre-R03 arm put back, an override stopping NetworkManager derives no disruption where the stop derives ConnectivityLoss; recorded: "without the fix the override ran" | covered |
| C4 | R07: an already-degraded unit could lose another probe and still commit | `ff11187` | exec::host::ExecHost::violations | `degraded-unit-loses-a-probe` | gym-fake | recorded: "without the per-probe check it committed" | gap: probe passing before and failing after ⇒ a violation, for any unit status |
| C5 | A driver that binds but cannot drive the device passed the check | before history | exec::host::ExecHost::violations | `drv-bind-fails-restores-previous` (fake + VM); `drv_bind_fails_restores_previous` (kernel.rs) | gym + unit | recorded (ga-status, generic) | gap: same checker as C4 (Bound and a failing Readiness ⇒ violation) |
| C6 | C3: an attested override could be replaced by someone other than its holder | `fe94ffe` (#2) | exec::unmet | `override-over-attested-refused`; `an_attested_override_is_replaced_only_by_its_holder` | gym-fake + unit | recorded: "fails without the check" | covered |
| C7 | R04: existing-generation operations omitted activation consequences | `5d9d986` (#6) | exec::Executor::plan_existing | `switch-facts-from-dry-activation`; `rollback_facts_come_from_the_dry_activation`, `an_existing_generation_without_a_plan_is_refused` | gym-fake + unit | recorded (generic) | covered |
| C8 | R09: an unauthorized caller reached the prebuild | `443667e` | exec::Executor::admit | `unauthorized-change-does-no-work` | gym-fake | recorded: "without admission it staged and built once" | covered |
| C9 | S07/C21: an approval could approve a later identical request; approvals survived a daemon restart | `4fb9b47`, `0bb8783` (#2) | exec::Executor::binding; daemon::Core | `an_earlier_approval_never_approves_a_later_identical_request`; `approval-dies-with-daemon`, `reprepared-keeps-caller` | unit + gym | recorded: "fails with the transaction left out of the binding" | covered |
| C10 | C2: an owner edit while a change waited was not stale when the window opened | `ed1c15d` (#6) | exec::Executor::revalidate | `an_owner_edit_while_waiting_is_stale_when_the_window_opens` | unit | recorded (generic) | covered |
| C11 | A rollback to an un-overridden known_good did not diff the evaluated options, so restoring a Security option did not ask | #34 (`3f24a2d`) | exec::derive::option_diff | `a_rollback_that_restores_a_security_option_asks_without_an_override` | unit | recorded: "fails with the comparison disabled" | gap: diff property (any option whose value differs between the generations appears, with its sensitivity) |
| C12 | A removed user template lost its sensitivity; the approval showed it without [Security] | #34 (`5827fbf`), #37 (`f7e2dc3`) | exec::derive::removed_units; daemon::approval | `removed_units_carry_their_sensitivity`; `a_removed_security_user_template_shows_security`; `removed_units_and_their_own_sensitivities_do_not_move_a_decision` (policy, I14) | unit | none recorded | covered |
| C13 | A file added during a build was not reported as left out | before history | exec::Executor::submit_from | `an_untracked_file_added_during_the_build_is_reported_not_stale`; `untracked_files_do_not_make_it_stale` | unit | recorded (generic) | covered |
| C14 | C14: the model was authorized as the daemon, not as an agent | `ced94fa` (#2) | policy::authorized | Verus `agents_and_unattributed_are_refused` | Verus | proved | covered |
| C15 | B-5 fail-closed made every undeclared system unit External, so routine changes waited and vm-generations timed out | `69b1e9e` | exec::derive (sensitivity lookup) | derive test in `69b1e9e`; module-eval | unit + eval | none recorded | covered |
| C16 | P10: `SideEffects::Measurement { per }` was read nowhere; a measurement probe could run on every tick | #18 (`33294f7`, `6f2a407`) | state::Assembler::within_rate | `a_measurement_probe_runs_at_most_once_per_its_per` (state/src/tests.rs) | unit | none recorded | gap: timing property (at most one cadence run per `per` window, over random tick times) |

## Backends, identity, gym (`crates/backends/linux`, `crates/gym`)

| # | Bug | Fixed in | Crate::function | Test that catches it | Kind | Fails on revert | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | systemd 260: `loginctl show-session` with a comma-separated `--property` printed nothing, so no session was ever seen | before history | backends-linux::logind::show_session_argv | `one_property_flag_each`, `parses` (logind.rs); six desktop and user-unit VM entries | unit + gym-VM | recorded: the six entries failed on it | covered (external-tool behaviour) |
| B2 | Binding a device to another driver never worked on hardware (the holder was not unbound; generic drivers need `driver_override`) | before history | backends-linux::sysfs::Sysfs::bind | `bind_overrides_the_driver_match_and_clears_it` (sysfs.rs) | unit | recorded (generic) | covered (sysfs sequence; kernel-real only on VM) |
| B3 | A failed publish left the boot default naming the candidate | before history | backends-linux::nixos::Nixos::publish_boot | `storage_boot_full_publish_reverts` (kernel.rs); `storage-boot-full-publish` (fake + VM) | unit + gym | recorded (generic) | covered |
| B4 | A revert failed on a full /boot it could not free | before history | backends-linux::nixos::Nixos::publish_boot | `storage-boot-full-publish` (VM) | gym-VM | recorded: "fixed since" (ga-status run #24) | covered |
| B5 | Collected generations kept their build and `gen-<n>` GC roots, so collection freed nothing | `805cd1c` | backends-linux::nixos::prune_roots | `stale_roots_are_pruned_before_a_collection`; `gc-retain-all-generations` | unit + gym-fake | none recorded | covered |
| B6 | R10: a failed, timed-out or truncated dry activation was accepted as a plan | `c6347cb` | backends-linux::nixos::dry_activate_failure | `a_failed_dry_activation_is_no_plan`; `dry-activate-exit-nonzero`, `-timeout`, `-truncated` | unit + gym-fake | recorded: "unit-tested for each" | gap: classifier property (any nonzero exit, timeout or truncation ⇒ no plan, whatever the output) |
| B7 | R06: probe timeouts did not bound total time; a straggler at the batch deadline was `Timeout`, not `Abandoned` | `48c3907` (#6), `524c927` (#23) | backends-linux::probe::run_batch_with | `trickling_http_has_one_total_deadline`, `a_stalled_resolver_is_inside_the_deadline`, `a_wedged_probe_does_not_hold_the_batch`, `a_straggler_is_abandoned_and_its_own_timeout_stays_timeout`; `probe-trickling-endpoint` (VM) | unit + gym-VM | recorded: "each failing with its part of the fix removed" | covered (real sockets) |
| B8 | R05: agents launched outside the failure posture | `7bfe155` (#6) | backends-linux::systemd::start_agent | `no_agent_starts_while_a_failure_class_is_raised`; `agents_per_uid_are_limited`; `posture-stops-launched-agents` (VM) | unit + gym-VM | recorded | covered |
| B9 | B-20: a second `agent run` under a running agent's name rebound its authority | `8231a07` | backends-linux::systemd::instance_of_cgroup; txn::Ledger::agent_for | `agent-name-collision` (fake + VM) | gym | recorded (generic) | covered |
| B10 | B-6/B-3: session resolved from a bare pid; the terminal claimed by the client | `725f290` | daemon main peer_pidfd/peer_of | `a_peer_is_read_through_its_pidfd`; `identity-peer-exited` (VM); `approve-needs-real-terminal` | unit + gym-VM | none (pid reuse cannot be staged) | covered |
| B11 | B-7: tokens, leases and cooldowns on the wall clock | `89eb2b4` | schema::Clock::boot_now | Kani `approval_tokens_expire_after_their_lifetime`; `token-wall-clock-moved-back` | Kani + gym-fake | recorded | covered |
| B12 | B-11: any unattributed stop was accepted as an inferred override | `c84075d` | daemon::Core (inferred overrides) | Kani `residue_is_inferred_only_where_allowed`; `residue-infer-stops-false` | Kani + gym | none recorded | covered |
| B13 | B-15: dynamic-uid services could fill the connection cap | `db5b0f4` | daemon main `admits` | `reserved_slots_are_for_administrators_and_sessions` | unit | none recorded | gap: `admits(peer, mine, total)` is pure: a property that 16 slots stay for administrators and session callers |
| B14 | B-16: replay protection lived in a root-writable cache | `db5b0f4` | daemon::hooks::replayed | `the_journal_not_the_cache_decides_what_is_a_replay` | unit | none recorded | covered |
| B15 | Approval at a terminal had no effect on the VM harness (`script` wrapper) | `b219d81` | gym::live::request_at | `approve-at-terminal-runs` (fake + VM) | gym-VM | recorded: four entries "left their AskFirst change Prepared" | covered |
| B16 | The `TokenUsed` record was on the boot clock, so the judge missed the approver on the VM | `641a479` (#2) | exec (TokenUsed) | `the_approval_record_is_on_the_wall_clock` | unit | recorded: "fails with the boot clock" | covered |
| B17 | en-i6's judge checked `Activating` only | `faf936d` (#13) | gym::check | `repair_prepared_in_each_exclusive_state` | unit | recorded: "against the old judge the test fails" | covered |

Harness and fixture bugs (the VM harness, catalog typos, test waits) are in
`docs/ga-status.md`; they are not Planarian's and are left out.

## netwatch (PR #42, not merged)

Rows are written when #42 merges, with its fixes' commits. Expected, from
the coordinator's list:

| # | Bug | Test owed | Status |
| --- | --- | --- | --- |
| N1 | inotify `IN_CREATE` against the cgroup walk: the attribution map was replaced, not merged | proptest: any interleaving of create events and walks gives the union of claims | pending |
| N2 | Template slices | parser proptest over unit/slice names | pending |
| N3 | A claim pruned before 2 walks without it | proptest over walk sequences: pruned iff absent from 2 consecutive walks | pending |
| N4 | netns scoping: only host-netns events count; an unreadable netns is `.unattributed` | classifier proptest | pending |
| N5 | Interface names with `%d` | parser proptest | pending |
| N6 | Restart: loaded sockopt claims dropped; unclaimed steering pre-attach must go to `.unattributed` | model proptest across a restart | pending |
| N7 | `nft list` counted as a change (8 pure GETs are reads; RESETs are changes) | classifier proptest over the nft message types | pending |
| N8 | `unattributed` must imply `protecting yes` | proptest over the fold's output | pending |
| N9 | A route over a virtual interface the unit did not create | classifier proptest | pending |

## Counts

62 rows for bugs fixed on `main`: 15 journal and kernel (J), 14 daemon (D),
16 change path (C), 17 backends, identity and gym (B). Another 9 netwatch
rows are pending #42. 16 rows still owe a property test (status **gap**).
J4 and J7 wait on lane-daemon's extraction of pure functions. The rest, in
the coordinator's order: D14, C1, C3, J8, J9, then D4, D5, C2, C4, C5, C11,
C16, B6 and B13.
The rest are covered by the strongest cheap test their shape allows; for
bugs that depend on the kernel or systemd, that is a VM test.
