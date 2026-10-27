# Phase A fault catalog: owner review packet

Covers `crates/gym/catalog/phase-a.toml` (SPEC §18.0). Per §18.0, work stops here until the owner signs off.

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
