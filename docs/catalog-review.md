# Phase A fault catalog: owner review packet

Covers `crates/gym/catalog/phase-a.toml` (SPEC §18.0) and, from §5 on, the v4.4 draft `crates/gym/catalog/phase-a-v4.4-draft.toml`. Per §18.0, work stops here until the owner signs off.

The catalog has 71 entries: 46 `must-pass`, 16 `repair`, 9 `intent`. 54 run on the fake-backend harness and 61 on the NixOS VM; most run on both.

## 1. Coverage

### §15 families (minimum one each)

| §15 family | Entries |
| --- | --- |
| service killed | `svc-killed`, `svc-killed-defer-to-systemd`, `svc-killed-user-scope` |
| service misconfigured | `svc-misconfig-state-file`, `svc-misconfig-listen-address` |
| required dependency stopped | `dep-required-stopped` |
| ordering-only predecessor stopped | `dep-ordering-only-stopped`, `dep-wants-optional-failed` |
| driver unbound | `drv-unbound-audio`, `drv-unbound-nic-asks`, `drv-bind-fails-restores-previous` |
| bad generation activated | `gen-bad-switch`, `svc-misconfig-listen-address`, `gen-override-only-change`, `gen-disable-reenable-canonical` |
| daemon killed during Activating / Checking / Reverting | `crash-activating-bad`, `crash-activating-good`, `crash-checking`, `crash-reverting` (+ 10 more, below) |
| revert fails | `revert-fails`, `revert-fails-interlock-survives-compaction` |
| probe delayed past timeout, service healthy | `probe-delayed-healthy` (+ `probe-diagnostic-stale-healthy`, `probe-failed-beats-stale`, `probe-http-503-degraded`) |
| external config edit during a build | `stale-owner-edit-during-build`, `stale-untracked-file-ignored`, `gc-during-approval` |
| intentional service stop | `intent-user-stops-service`, `intent-cli-stop-rewritten`, `intent-start-again-repairs` |
| suspend/resume | `suspend-resume` |
| network unavailable at gateway, driver fine | `net-gateway-down`, `net-external-dependency-down` |
| flapping service | `flap-30s`, `flap-regression-escalates` |
| storage full | `storage-nix-full-gc`, `storage-budget-unsatisfiable`, `storage-journal-fs-full`, … (8) |
| manifest edited to weaken a probe | `manifest-weaken-via-proposal`, `manifest-weaken-out-of-band` |
| login screen idle, autologin off | `login-greeter-idle` |
| boot-to-desktop failure | `desktop-auth-ok-compositor-fails`, `desktop-boot-fails-rollback` |

### §15 v4-review acceptance cases (all required)

| Case | Entry |
| --- | --- |
| kill + immediate restart with a slow worker surviving | `crash-slow-worker-overlap` |
| override-only candidate changes evaluated output | `gen-override-only-change` |
| owner edits source during a build → `Stale` | `stale-owner-edit-during-build` |
| crash at Activating, Checking, Published, Promoted, Reverting | `crash-activating-bad`/`-good`, `crash-checking`, `crash-published`, `crash-promoted`, `crash-reverting` |
| disable then re-enable a service with a canonical probe | `gen-disable-reenable-canonical` |
| Diagnostic evidence expires on a healthy machine | `probe-diagnostic-stale-healthy` |
| definite Failed while another probe is stale | `probe-failed-beats-stale` |
| auth succeeds, compositor never reaches target | `desktop-auth-ok-compositor-fails` |
| idle greeter | `login-greeter-idle` |
| user stops a running service | `intent-user-stops-service` |
| unprivileged user suppresses a system Security unit | `authz-unprivileged-suppress-security` |
| daemon proposes session-dropping rebind and runtime Wi-Fi change | `policy-daemon-session-drop-rebind`, `policy-daemon-wifi-runtime` |
| optional `Wants=` unit fails | `dep-wants-optional-failed` |
| journal filesystem filled to the reserved boundary | `storage-journal-fs-full` (ext4, btrfs, ZFS) |

### Other gym cases named in the spec body

§9.5 GC during approval → `gc-during-approval`. §9.6 override-only, no Stale → `gen-override-only-change` (`never = Rejected(Stale)`). §10 HTTP 503 → `probe-http-503-degraded`. §10 external dependency down → `net-external-dependency-down`. §12 withheld job reply → `crash-withheld-job-reply`. §12 job outlives the drain → `crash-job-outlives-drain`. §12 simultaneous takeover → `crash-simultaneous-takeover`. §12 Runtime Rollback / StopAndSuppress crash → `crash-runtime-rollback`, `crash-stop-and-suppress`. §12 failed bind → `drv-bind-fails-restores-previous`. §12c interlock across compaction → `revert-fails-interlock-survives-compaction`. §12c btrfs reuse, compaction with live state, torn writes → `storage-journal-btrfs-reuse`, `journal-compaction-preserves-state`, `journal-torn-write`. §12c ENOSPC by state, `/boot` → `storage-enospc-during-build`, `storage-boot-full-publish`.

### Additions beyond the spec (tagged `extra`)

These are cheap to run and each protects one specific rule: `stale-untracked-file-ignored`, `authz-forged-actor-overwritten`, `core-target-rejected`, `user-unit-after-logout`, `cond-device-unplugged`, `desktop-second-user-deadline`, `policy-stale-digest`, `policy-refinement-violation`, `approval-token-invalidated`, `approval-token-expired`. Cut any of them if you want a leaner catalog.

### GA demo (§4 GA(1), §18.1)

`svc-killed` → `svc-misconfig-listen-address` → `crash-activating-bad` → `crash-daemon-restart-reconciles`. `gym/demo.sh` will run these four in order.

## 2. Format decisions that need sign-off

1. **`required_post` is wider than `Expectation`.** §8's `Expectation` can only state unit statuses and a generation. Over half the cases need to assert journal paths, policy decisions, incident states, the interlock, or the boot default and override source. I kept `Expectation`'s fields at the top level of `required_post` and added extension keys (listed in the file header). **Proposal:** in `gym`, define `RequiredPost { expect: Expectation, txns, incidents, … }`. `Expectation` stays the proposal type and is not widened.
2. **`RawAction` is undefined in the spec.** The file header proposes a vocabulary of about 30 actions. Some are fake-only (`backend_result`, `advance_clock`, `withhold_reply`).
3. **A `scoring` field decides what "≥ 60% of the catalog cleared deterministically" means.** Proposal: the denominator is the `repair` entries only (15 of them). Every `must-pass` and `intent` entry must pass at 100%, since GA(2) already demands that ("every bad generation reverted", "zero gamed successes", "unnecessary-intervention rate = 0"). See Q1.
4. **A `harness` field** marks which cases the fake-backend txn kernel can run. That kernel is next in the build order, and 53 entries can exercise it before any VM exists.
5. **Global checks** (gamed success, I5/I6/I7/I12/I13/I14/I15, `RecoveryFailed` = 0 unless asserted) are applied by the scorer to every entry. They are not repeated per entry.

## 3. Spec gaps found while writing the catalog

These need a schema decision, and none of them is a §19 item. I have not changed SPEC.md.

| # | Gap | Where | Suggested fix |
| --- | --- | --- | --- |
| G1 | `RejectReason` has no `Unauthorized`, `Interrupted`, or `NoSpace`, but the spec uses all three | §8 vs §11, §12 crash table, §12c | Add the three variants |
| G2 | `DerivedFacts` has no `changes_desired` | §8 vs §9 applicability | Add the field |
| G3 | `SystemState` has no `accepted_baseline` | §8 vs §12, §16 | Add `accepted_baseline: Option<GenerationId>` |
| G4 | `UnitKind { Service, Device }` cannot name `graphical-session` (a target) | §8, §9 | Add `Target`, or document targets as `Service` |
| G5 | The comment on `ProbeDef.side_effects` lists `Network`, which is not a variant; it omits `Measurement` and `RemoteStateChange` | §8 | Fix the comment |
| G6 | `BindDriver.driver: StorePath`, but in-tree drivers are named (`snd_hda_intel`), not store paths | §8 | `DriverRef { name, module: Option<StorePath> }` |
| G7 | Journal record kinds beyond `TxnState` (OpId, suppression, reconciliation, resolve, checkpoint marker) are referenced but not typed | §12, §12c | Define `JournalRecord` in `txn` (my job; flagging it so it's no surprise) |
| G8 | §14 rewrites "a `StopUnit` issued through the CLI", but §16's CLI has no `stop` verb. The Audible-probe "user-initiated diagnostic" has no CLI verb either | §14, §16, §10 | Add `planarian stop <unit>` and `planarian diagnose <unit> [--probe]` |
| G9 | The §11 Suppress row reads "AskFirst when caller is not an authorized user", but the authorization rule rejects unauthorized callers outright. So the row can only mean daemon/model callers, whose suppressions §15 counts as gamed | §11, §15 | Reword the row to "caller is not a user" |
| G10 | The header says the next artifact is "the catalog and the fake-backend transaction kernel"; §18.0 says to stop after the catalog | header vs §18 | I followed §18.0 and stopped |

## 4. Questions for you

**Decided 2026-10-26: the owner accepted the default on all four.** What that changed: `dep-required-stopped` now asserts an `OutOfBandStopHint` report (Q2), the new entry `owner-rebuild-breaks-service` covers Q3, and the Q4 rule is recorded in `docs/deviations.md`.

- **Q1. What counts as "cleared" for the 60% gate?** `svc-misconfig-state-file` cannot be fixed by restarting. Its Phase A `required_post` is a correct escalation (3 attempts, backoff, report), and it is tagged `phase-b-upgrade`. Does that count as cleared? My default is yes: "cleared" means `required_post` holds, and the separate *repair rate* metric reports the honest number. The stricter reading would count only entries that end with the target healthy.
- **Q2. Out-of-band `systemctl stop` by root.** `dep-required-stopped` assumes that a stop made outside Planarian is a fault and gets repaired. Principle 9 ("don't fight the user") applies only to stops that go through Planarian. A sysadmin's habitual `systemctl stop` will be undone within about two ticks. Is that the intended behaviour, or should a stop issued by uid 0 through systemd (visible in the job's `org.freedesktop.systemd1` caller) become a suppression? My default: repair it, as the spec currently reads, and print a console hint pointing at `planarian stop`.
- **Q3. The owner's own `nixos-rebuild switch` breaks a service.** Should Planarian ever propose `Rollback` over a generation the owner built and switched to themselves? There is no catalog entry for this yet. My default: restart attempts, then escalate. Never roll back an owner-built generation without AskFirst.
- **Q4. Fixture realism.** Several VM cases rely on things that are known to be fiddly: S3 suspend in QEMU, mac80211_hwsim + hostapd, driving the COSMIC greeter login from a test script, and dropping a D-Bus reply. If any of these can't be made reliable, I'd move that case to `harness = ["fake"]` and log it in `docs/deviations.md`. Is that acceptable, or must every acceptance case run on the VM?

---

# v4.4 additions (2026-10-29)

Spec v4.4 adds acceptance cases and the malicious-declaration family to §15. Per §18.0 and the v4.4 handoff, the new entries are drafted for review before any other v4.4 code. They are in `crates/gym/catalog/phase-a-v4.4-draft.toml`, apart from `phase-a.toml`, so the gym and CI keep running the signed-off catalog. On sign-off they move into `phase-a.toml`. The mechanical renames there (`Suppress` → `SetOverride`, `suppressions` → `overrides`, CLI `suppress` → `override`) land with the schema change, because the judge reads those keys.

The draft has 31 entries: 25 `must-pass`, 4 `repair`, 2 `intent`; 26 run on the fake harness and 24 on the VM. 26 are §15 acceptance cases and 5 are tagged `extra`.

## 5. Coverage of the v4.4 cases

| §15 v4.4 case | Entry |
| --- | --- |
| Standard posture, Absent (mask the unit) | `posture-absent-masked` |
| Standard posture, Crashed (kill it past its budget) | `posture-crashed-budget` |
| Standard posture, Integrity: core hash | `posture-integrity-core-hash` |
| Standard posture, Integrity: journal chain | `posture-integrity-journal-chain` |
| Standard posture, Integrity: undeclared early unit | `posture-integrity-undeclared-early-unit` |
| Security update, then a probe failure: no revert below the floor, `RevertBlockedByFloor` | `floor-revert-blocked` |
| Kernel update: boot-only path, confirmed at next boot | `boot-only-kernel-confirmed` |
| Kernel update: reverted when the injected boot fails | `boot-only-kernel-boot-fails` |
| User-session principal overrides the firewall: held for an administrator | `authz-user-overrides-firewall` |
| Non-administrator stops the network while another uid is online | `authz-nonadmin-stops-network-other-session` |
| Two graphical sessions, second compositor fails | `session-second-compositor-fails` |
| Logout of one of two sessions | `session-logout-one-of-two` |
| Unattributed `kill -9` of a service under Standard | `residue-kill9-service` |
| Unattributed `kill -9` of the firewall | `residue-kill9-security` (fixture `gym-guard`), `residue-stop-firewall` (the real firewall) |
| OOM kill | `residue-oom-kill` |
| Retained journal record edited on disk | `journal-record-edited` |
| Staged update while `Foreground` holds | `quiet-staged-update-foreground` |
| Fake backend against every `docs/assumptions.md` entry, under `Partial`, `Unknown` and fenced outcomes | `fake-assumptions-conformance` (one run per assumption × outcome) |
| Malicious declaration | `malicious-decl-owner-rebuild`, `malicious-decl-catalog-enable`, `malicious-decl-input-update` (three declaration paths) |
| §12f gym case (reference game) | `quiet-reference-workload`, `quiet-repair-not-deferred` |
| Changed v4-review case: unprivileged override of a Security unit is held, not rejected | `authz-unprivileged-override-security` replaces `authz-unprivileged-suppress-security` |
| v4-review case not in the v4.3 catalog: unprivileged stop of a non-controllable system unit → `Unauthorized` | `authz-unprivileged-stop-unauthorized` |

Extras: `floor-update-fails-reverts`, `floor-manual-rollback-needs-admin` (also checks I19), `authz-ssh-not-local`, `authz-last-admin-kept` (I17), `residue-kill9-undo`.

The draft's header lists the new `required_post` keys, raw actions and fixtures. The ones that need the most work are `fail_boot`, `plant_early_unit` and the per-session compositor.

## 6. Conflicts with the signed-off catalog

**C1. The unattributed residue changes what 14 existing entries mean.** v4.4 §11: under Relaxed and Standard, a raw signal or a direct sysfs write that stops a non-Security unit is accepted until the next boot as an inferred override, not repaired. These existing entries inject exactly that and expect a repair:

| Inject | Entries |
| --- | --- |
| `kill -9` / `SIGTERM` of a service | `svc-killed` (GA demo step 1), `svc-killed-user-scope`, `svc-misconfig-state-file`, `dep-ordering-only-stopped`, `dep-wants-optional-failed`, `probe-failed-beats-stale`, and in setup or after steps `revert-fails`, `revert-fails-interlock-survives-compaction`, `storage-journal-fs-full` |
| `kill -9` of a `Restart=on-failure` service | `svc-killed-defer-to-systemd` |
| out-of-band `systemctl stop` by root | `dep-required-stopped` (your Q2 decision: repair, with a hint) |
| sysfs unbind | `drv-unbound-audio`, `drv-unbound-nic-asks`, `policy-daemon-session-drop-rebind` |

Two of these, read literally, contradict the spec itself. §12f's gym case says "a PipeWire kill during the workload is repaired immediately", but under Standard a PipeWire `kill -9` would be inferred as intended. And from udev, Planarian cannot tell a sysfs unbind someone typed from a driver that dropped its device: both are the same `unbind` uevent.

What Planarian can observe: for a service, systemd's `Result=` and the signal number, but not who sent it. **Proposal:**

- **Residue** (inferred override under Standard): a unit that stopped on a termination signal (`SIGKILL`, `SIGTERM`, `SIGINT`, `SIGHUP`) with `Result=signal`, or on a `systemctl stop` job not issued by Planarian.
- **Fault:** a crash signal (`SIGSEGV`, `SIGBUS`, `SIGABRT`, `SIGILL`, `SIGFPE`), a non-zero exit, `Result=oom-kill`, a failed start, a timeout.
- **Fault, always:** a device found unbound. The unbind source is not observable, so treating it as residue would mean never repairing drivers.

The kill cases above switch to `SIGSEGV` (as `quiet-repair-not-deferred` already does), and §12f's "PipeWire kill" reads as a crash. `dep-required-stopped` becomes a residue case, which reverses Q2 in line with v4.4. The device rule gets a row in `docs/deviations.md`.

**C2. `authz-unprivileged-suppress-security` is now wrong.** v4.4 holds the override for an administrator rather than rejecting it. It is replaced, as noted in §5.

**C3. Renames.** These are mechanical and covered above.

## 7. Spec gaps found while writing the v4.4 entries

| # | Gap | Where | Suggested fix |
| --- | --- | --- | --- |
| G11 | "A non-administrator stops the network while another uid's session is online (AskFirst)". Authorization runs before the floors, and the network is not user-controllable by default (only "their own Wi-Fi selection"). So the case is `Reject(Unauthorized)` unless the network is in `userControllable`. | §11, §15 | The entry adds `device:net-gym0` to `userControllable` in setup. Alternatively, say in §11 that this floor is reached only for user-controllable units. |
| G12 | The NixOS firewall is a oneshot (`RemainAfterExit`), so a `kill -9` of it has nothing to kill. | §15 | Cover both readings: a long-running Security fixture (`gym-guard`) for the kill, and an out-of-band stop of the real firewall. |
| G13 | Does a raw stop of a `Restart=on-failure` unit that systemd restarts on its own create an inferred override? `svc-killed-defer-to-systemd` says defer to systemd. | §11, §12 | Do nothing: an override is inferred only for a unit that stays stopped past systemd's own restart. |
| G14 | Malicious declaration: "when" can mean the generation's creation time, the transaction time, or the commit time of the owner's source. A rebuild outside Planarian has no Planarian actor; only the uid that ran it, if known from the journal of `nixos-rebuild`. | §15 | The report names the path (catalog transaction, out-of-band rebuild, flake input) and the best available who and when, and marks fields it cannot attest as `unattested`. |
| G15 | `quiet-reference-workload`'s input-to-display latency cannot be measured in a VM without a GPU. | §21 | Frame time in the VM gates every run. Latency is measured on the reference machine at phase gates. |

## 8. Questions for you (v4.4)

- **Q5. The unattributed residue (C1).** Accept the proposed residue/fault split by signal and `Result=`, and "devices are always faults"? If yes, 10 entries change their injected signal and `dep-required-stopped` flips to a residue case.
- **Q6. Stop and ask: v4.4 against the Phase A proofs already written.** The handoff says v4.4 lands before Phase A's proofs, but proofs already exist. These are affected:
  - `policy/src/proofs.rs`: `i5_autonomy_never_touches_reject`, `global_floors`, `unauthorized_is_refused_first`, `i14_facts_caller_is_not_authority` and others pattern-match `Decision::Allow(Tier)`. That becomes `Allow { tier, approver }`. `decide`'s input gains `Authorization`, and two new floors (`other_sessions_affected`, `below_security_floor`) apply.
  - `txn/src/ledger.rs`: verified ledger state with `Record::Suppressed`/`Unsuppressed` and `suppressions`.
  - `schema::Actor`: under `verus!`.

  My plan is to change the types and re-prove: the proofs stay, their statements extend, and new proofs are added for I16 and I19. Nothing gets weaker. Every proof is re-run in CI (`checks.verus`), and the verification ratio is reported before and after. Do you agree that re-proving is acceptable here and not a "migration"?
- **Q7. The reference game for the invisibility budget (owner-open).** My proposal: **Xonotic**, which is in nixpkgs, free, and has a built-in, deterministic `timedemo` playback of a recorded demo. Frame times would be logged by MangoHud (also in nixpkgs), which keeps the method independent of the game.
  - Sequence: 5 runs each, interleaved, with Planarian stopped, then idle, then with queued work (a GC, a staged update, a non-urgent fault). The PipeWire crash at a fixed point only in the last condition.
  - Pass: no significant difference in p99 frame time (Mann-Whitney U on per-run p99, α = 0.01) and wakeups/s reported.
  - The VM runs it with software rendering as a regression check on every run; a real reference machine runs it at phase gates.
  - Fallback if you'd rather have a racing game: SuperTuxKart's benchmark mode.
- **Q8. Coverage threshold for the personal-profile gate.** Still yours; I have left it open.

## 9. Decisions (2026-10-29)

- **Q5:** accepted as proposed. The unattributed residue is a termination signal (`SIGKILL`, `SIGTERM`, `SIGINT`, `SIGHUP`) with `Result=signal`, or a `systemctl stop` not issued by Planarian. A crash signal, a non-zero exit, `Result=oom-kill`, a failed start and a timeout are faults. A device found unbound is always a fault. The v4.3 kill cases switch to `SIGSEGV`, and `dep-required-stopped` becomes a residue case.
- **Q6:** accepted. Change the types, extend the existing proofs, and add proofs as needed (I16, I19). Report the verification ratio before and after.
- **Q7:** accepted. The reference game is Xonotic's `timedemo`, with MangoHud frame logging.
- **Q8:** left to my discretion, aiming high. The personal-profile gate needs every `must-pass` and `intent` entry to PASS on each harness it lists, and no acceptance case to be UNSUPPORTED on the VM unless a `docs/deviations.md` row moves it to the fake (Q4). It also needs at least 95% of all entries cleared on at least one harness.
