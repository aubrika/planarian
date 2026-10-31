# Planarian — Spec history

The changelogs of earlier spec revisions, moved out of `SPEC.md` at v4.6 so the spec stays the size of what is current. Section numbers are kept as they were, so references such as "§27" still resolve. These records are historical: where one disagrees with `SPEC.md`, the spec wins. The latest revision's changes (§28 at v4.6) stay in `SPEC.md`; when a new revision lands, move the previous one here.

## 22. Changes from v3

- Restored principles (now 12) and invariants (I1–I14) that v3 referenced but omitted.
- Desired/observed/health separated; conditions (`AfterLogin`, `DeviceConnected`, power); suppressions; `Unknown`, `Transitioning`, stale evidence; user-scoped units. Fixes the login-screen and user-stopped-service faults.
- Edges typed (`Ordering`/`Requires`/`Diagnostic`); `After=` no longer implies dependency.
- Probe contract: sandbox, limits, side effects; disruptive probes OnDemand only; `establishes` field.
- Sensitivity composable; `Disruption` and `Recovery` as separate properties; `Decision::Reject` separate from tiers; `max_tier` can no longer make a forbidden action approvable.
- Policy facts derived by the executor from the evaluated generation (I14); `OptionChange.sensitivity` removed from proposals; refinement check and executor-owned requirements made explicit.
- Approval bound to the concrete candidate, base, policy version, cumulative hash, derived facts; re-validated at execution; single-use.
- Transaction kernel with write-ahead journal, `Partial`/`Unknown` outcomes, recovery watchdog as a separate unit, daemon restart reconciliation, self-protection during activation; `live_tested` vs boot-confirmed `known_good`.
- Change catalog with handlers replaces free-form `ConfigDiff` in proposals; override file promoted only on commit; user config pinned per transaction.
- Incident lifecycle: defer to systemd, backoff, durable budgets, regression and flap handling, cooldowns, escalation.
- Gym: lifecycle and intent families; unnecessary-intervention and disruption metrics; held-out families for B; GA includes the kill-mid-activation demonstration.
- Verification narrowed to `schema`/`policy`/`txn` with `docs/assumptions.md`; re-observation claim corrected; store-integrity claim corrected for input-addressed paths.
- GC: in-flight candidates protected; space budgets.
- `mark-good` authorization; log record contents; `dyn`/generics contradiction resolved.
- Phase A scope kept full and Asterinas target kept non-gating, per owner decision.

## 23. Changes from v4

- §12: exclusive transaction ownership with lease epochs; worker fencing via pidfd and job draining; the watchdog may not commit before `Published`; the daemon waits for a watchdog-held lease; I15 added; gym case for overlapping owners.
- §9/§12: immutable staged source (NAR-hashed) evaluated with pure-eval; build before approval; `verify_candidate` before activation; the token binds expectation, revert target, and recovery strategy; `activate_live` and `publish_boot` separated; `Published`/`Promoted` journaled; atomic-rename-plus-dir-fsync promotion; watchdog revert restores the override source; crash-recovery table.
- §8/§9/§10: `ProbeRole` Readiness vs Diagnostic; side-effect probes are Diagnostic; status derivation puts definite `Failed` above Unknown; probe applicability follows the candidate's authorized desired state, distinct from definition tampering.
- §8/§9: `Condition::SessionEstablished` from logind replaces the circular `AfterLogin`; the session probe is the result, not the prerequisite.
- §8/§12/§14: `StopAndSuppress` composite; suppression journaled before stop; no post-hoc prompt; CLI `StopUnit` rewritten.
- §11: `SO_PEERCRED` authentication; authorization rule separate from risk; actor fields overwritten; global floors for NonReversible and disruption apply to every transition kind.
- §8/§9/§13: `Wants` edge kind preserved as weak; SCC-based root-causing for cycles.
- §10/§12c: per-filesystem storage units; preallocated journal; ENOSPC behavior by state; `CollectGarbage { emergency }`; `BudgetUnsatisfiable`.
- §12: read-only vs mutating backend calls; `Prepared` on the Allow path; per-transition `RecoveryStrategy`; Runtime outcomes never trigger generation reversion; `restartIfChanged`/`stopIfChanged` as the real self-protection mechanism.
- §16: `accepted_baseline` distinct from boot-confirmed `known_good`; initial enrollment; operational limits made normative.
- §17a: progress assumptions stated for I12; fencing and idempotence added to the trusted-assumptions list.
- §12a, §14, §20, §21 made self-contained.

## 24. Changes from v4.1

- §12: takeover requires confirmed quiescence (jobs cancelled and gone, workers reaped); a drain timeout ends in `RecoveryFailed`, never in proceeding; lease transfer is atomic via `flock` plus rename; the watchdog triggers on `Published`/`Promoted` too and, from `Checking`, completes the whole authorized commit path or reverts.
- §8/§12: per-transition `Handler` and `RecoveryStrategy` independent of tier; `Rollback` is a generation operation even at Runtime tier; `BindDriver` is a device operation with `UnbindDevice` recovery; the crash-recovery table branches on strategy.
- §9/§12b: transaction-specific `base.nix` with content-hash identities; promotion and restoration idempotent by hash comparison; no shared `.prev`; GC root created at `Built` and kept through approval; dirty-Git staging defined by Nix-visible bytes.
- §12c: length-prefixed CRC'd records with torn-tail handling; checkpoint-then-truncate compaction preserving all live state; filesystem contract for ext4/XFS/btrfs/ZFS with a sentinel fallback.
- §8/§10: `SideEffects::Measurement` permits bounded network/local I/O for Readiness probes; `RemoteStateChange` stays Diagnostic; external dependencies are units with edges.

## 25. Changes from v4.2

- §9: `base_source` (owner source with base override) separated from `staged_source` (candidate tree); stale check compares the working tree to `base_source` only; both bound to the token; Git-revision wording removed; step numbering fixed.
- §9/§12: `build` roots its own output under `gcroots/planarian/builds/` without a lease; the transaction adopts the root; orphan roots cleaned at startup.
- §12: durable `OpId` journaled before every mutating call and tagged onto the backend job; quiescence covers jobs discovered by `jobs_tagged` for unacknowledged ops; a backend that cannot say → `RecoveryFailed`.
- §12/§12c: `RecoveryFailed` sets a persisted **recovery interlock** carried in the checkpoint; cleared only by administrator `planarian resolve`; crash table row for `Checking, ReobserveOnly`.
- Consistency: `ProbeRole`, canonical-probe paragraph, and agent instruction 4 all carry the `Measurement` exception; I12's terminal set includes `Rejected` and `Cancelled`.
- I4 reworded to applicable Readiness probes; atomic transaction creation with initial lease; `Rejected`/`Cancelled` terminal states; incident closure on the desired predicate; `SessionEstablished` scoped to `user`-class sessions and a specific session id; intent-case scoring scoped to autonomous action.

## 26. Changes from v4.3

Incorporates the owner-approved conceptual review (Future Work v0.2 §1.1–§1.11 and the decisions in its §13).

- §7: principles 13–15 (reference monitor and species-blind principals; invisible under normal use; failure response enforced outside the monitor); principle 9 generalized to attributed overrides. Invariants I16 (security floor), I17 (administrator set non-empty), I18 (hash-chained journal), I19 (no self-approval, no self-escalation), I20 (no agent without the monitor).
- §8: `Suppression` generalized to `Override { desired: LeaveAlone | Stopped | Absent | Detected, attribution }`; `Suppress`/`Unsuppress` become `SetOverride`/`LiftOverride`; `UnitStatus::Overridden`. `Actor::User` carries session, seat, and active; `Actor::Agent` reserved. `Condition::Foreground`. `security_floor` in `SystemState`; `below_security_floor` and `other_sessions_affected` in `DerivedFacts`. Typed probe kinds `DBus`, `FilePresent`; `Exec` administrator-only. `Posture`, `FailureClass`. `RejectReason` gains the `Unauthorized`, `Interrupted`, and `NoSpace` variants v4.3 used but did not declare.
- §9: probe-kind rule; signed external desired-state source (hook); catalog coverage as a gym metric; `NotInCatalog` by phase; graphical-session readiness bound to the session's compositor; learned edges need a gym case. New §9a: PlanarianOS as a distribution with three profiles, per-profile gates, accounts, live mode.
- §10: foreground signals; user services desired while any session of the uid exists; actor resolution from logind; boot report; signed health report (hook) with a core-computed disclosure profile.
- §11: principals and capabilities; Phase B non-human grants; overrides on Security units need an administrator; per-session "own session"; multi-user and security-floor floors; approval as a capability with no self-approval; deliberate actions carry identity; the unattributed residue by posture.
- §12: activation window and sandbox check on the generation path. New §12d (boot ordering, `planarian-ready.target`, failure classes, responses, four postures, configurable timeout, boot-chain locking), §12e (security floor), §12f (activation scheduling and quiet mode), §12g (sandbox tier, Phase B). §12c: hash-chained records and chain head in the checkpoint.
- §13–§14: overrides; quiet-mode deferral; attributed stop phrasings.
- §15: v4.4 acceptance cases; malicious-declaration family; invisibility, coverage, AskFirst-rate, and verification metrics as ratchets; Firecracker target non-gating from A.
- §16: CLI additions; frontends section (the console is one optional frontend).
- §17a: the verification ratio d:a and the trust count reported at every gate. Phase A proof targets add I16 (in `decide` and target selection) and I19.
- §18: agent instructions 10–17; rule 4's preserve list extended to I10–I20.
- §4, §5, §6, §19, §20, §21: roadmap rows (Phase C is PlanarianOS), scope, layout, decisions, model residency, broker and future directions, invisibility budget. §20's idle unload stays at 10 min, now declared rather than fixed.
- §1–§3: overview prose, the diagram, and feature-table rows updated to overrides, attributed actions, the security floor, failure posture, quiet mode, and the sandbox tier.
- Consistency pass after review: `Decision::Allow` carries an `ApproverClass`; `ApprovalToken` binds its approver; `PrincipalId`, `Capability`, `Grant`, and `Authorization` declared; `Actor::Unattributed` for inferred overrides, which never apply to Security-sensitive units; `EscalationReason` (including `RevertBlockedByFloor`); a boot-only generation path with the `AwaitingBoot` state; I1 and I6 clarified against the floor and waiting transactions; the v4-review Security-override case changed from rejected to held for administrator approval; CLI verbs `override`/`release` replace `suppress`/`unsuppress`; §12c's checkpoint also carries overrides and the security floor.

## 27. Changes from v4.4

Incorporates the spec vulnerability review of Oct 29 (findings B-1–B-18 against commit `1bc09b2`).

- §5, §6, §7, §17b, §18: the bypass register `docs/bypasses.md`; principle 16 (name every way around); agent rule 18; no gate passes with an open High row (B-14 and the review's appendix).
- §7: principle 6 and I14 extended from proposals to every request field (B-3); I2 states what the A–D core hash detects (B-12); I16 states the inspected set (B-2); I18 states whom the chain holds against (B-8).
- §10, §11: identity from a pidfd, never a bare pid (B-6); a caller property that matters is established by the daemon (B-3); agents are their own principals, started by `planarian agent run` with `DynamicUser=` (B-1); approval's terminal established by the daemon (B-3); `inferStops = false` exempts units from residue inference, and inferred overrides stay listed until acknowledged (B-11; the review's `Critical` sensitivity became this manifest option, so no proved type changes); sensitivity completeness with fail-closed defaults and a gym entry (B-5).
- §10: the boot report covers units in A, processes from C, and flags a test build (B-10, B-13).
- §12c: chain head in the signed health report for off-machine witnessing (C), measured-boot anchor (E); the external source's sequence number in the checkpoint (B-8, B-16).
- §12d: alarms are local in A; a dead-man signal from C; the core hash covers every Planarian binary and script; a test build is an `Integrity` failure (B-9, B-12, B-13).
- §12e: the floor is derived from the whole system closure, with a CVE feed from B; gym case for a service-package fix (B-2).
- §12h (new): time on `CLOCK_BOOTTIME` for everything that does not survive a reboot; NTS recommended (B-7).
- §20, I9: the model is treated as an adversary, so its judgement is not a vector; containment is, and the model service's sandbox is now normative, with a gym case in B (B-18; the review's accepted row X-9 withdrawn).
- §11, §19: `inferStops` marked provisional, with the condition for replacing it by an `importance` property.
- §15, §16: test builds named and confined; socket slots reserved for administrators and sessions; `agent run`; new metrics (B-13, B-15, B-1).
- §17a: 𝒯 accounted as platform trust, proof-validity trust (now including the specifications, Verus, Z3, and rustc), and the internal-unproven count; every proved invariant gets a gym entry written from the English (B-4, B-14).
- Not spec changes: `guarantees.md` says Kani runs by hand, but CI runs it (B-17; correct the doc).
