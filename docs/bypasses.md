# Bypass register

Every known route by which the machine can reach a state SPEC v4.6 says cannot happen, or by which a stated guarantee stops describing the real machine (SPEC §17b). **B** rows are open findings; **X** rows are accepted by design. Ids are never reused. No gate passes with an open High row.

**Breaks:** *always invoked* (a change reaches the machine without the monitor), *tamperproof* (something guarded can alter the monitor or its record), *correct* (the monitor runs intact but decides on wrong inputs, or proves a narrower property than stated).

**Severity:** High = defeats a stated guarantee in the shipped configuration without root. Medium = needs root, a network position or a likely deployment, or the spec overstated the mechanism. Low = narrow, availability-only, or process. Accepted = outside the claim by design.

Seeded from the spec vulnerability review of 2026-10-29 against commit `1bc09b2`. Status "Open (v4.5 §x)" means the spec now requires the fix and the code does not have it yet.

## Open

| Id | Route | Breaks | Severity | Status | Mitigation | Phase |
| --- | --- | --- | --- | --- | --- | --- |
| B-4 | `decide` is proved, but its inputs (`DerivedFacts`, `Authorization`) are computed by unproven code | Correct (inputs) | Medium | Open (v4.5 §17a) | Internal-unproven count reported separately; fail-closed defaults; `derive` proved in C | A accounting; C proof |
| B-8 | The journal hash chain is unkeyed; root can rewrite it consistently | Tamperproof | Medium | Open (v4.5 I18, §12c) | I18 qualified; chain head in the signed health report for off-machine witnessing; TPM anchor | A wording; C witness; E anchor |
| B-9 | Posture alarms and notification are local; root can clear them and a stopped `planariad` can go unnoticed | Tamperproof | Medium | Open (v4.5 §12d) | Dead-man signal from the signed health report to an off-machine receiver | C |
| B-10 | The boot report checks units, not processes | Always invoked | Medium | Open (v4.5 §10) | Early processes outside the closure | C |
| B-18 | The model service escapes its sandbox before I9 is proved, and becomes a process with its uid's capabilities (it parses untrusted text and drives a GPU) | Tamperproof (I9) | Medium | Open (v4.5 §20, I9) | Normative sandbox: dynamic uid, no capabilities, strict read-only filesystem, Unix sockets only, syscall allowlist, render node only, proposal socket as the only write path; gym case attempting every other write path | B sandbox and case; E proof |
| B-19 | A package referenced only by a store-path string (an `ExecStart=` naming `/nix/store/…` directly, a script's interpolated path) has no `meta` to read at evaluation, so a fix to it does not move the security floor | Correct (I16) | Medium | Open | Residue of B-2: the evaluated inspected set covers every package *value*; the CVE feed matching the built closure covers strings | B |

| B-21 | Supported override writers are not yet proved serialized across final hash comparison and rename by the required directory flock | Correct (I23 cooperative writer boundary) | Medium | Open (shared-core R11) | Implement and test the directory lock for promotion/restoration, preserving conflicting edits by cooperating writers. Arbitrary editors outside that boundary are the separately adopted X-12, not a claim of arbitrary-editor CAS | A |

## Closed

Kept, with the commit that closed each and the gym entry that holds it closed (§17b).

| Id | Route | Breaks | Severity | Status | Mitigation | Phase |
| --- | --- | --- | --- | --- | --- | --- |
| B-1 | An agent started by a user runs under that uid and holds its capabilities, including Administrator for a `planarian-admin` member | Correct (authority) | High | Closed (544de86) | No longer a defect: by owner decision (2026-10-30) an agent holds its user's capabilities, as X-11 records. `planarian agent run` (`DynamicUser=`, unit `planarian-agent-<name>`, identified by cgroup through the peer's pidfd) journals who started it, so the agent acts with exactly that user's permissions and every request is attributed to it; one with no journaled start holds nothing. Gym: agent-run-own-principal, agent-has-its-users-permissions (fake and VM) | A launcher and docs; B required; C refused by agent-host profile |
| B-2 | The security floor is derived from `environment.systemPackages` only; fixes in service packages, the kernel or firmware do not move it | Correct (I16) | High | Closed (d2e173b) | Derived from every package value the evaluated configuration holds (system and unit packages, enabled services' package options, unit `path`, kernel, firmware) and their runtime inputs; the residue is B-19. Gym: floor-service-package-fix (VM) | A closure; B feed |
| B-3 | `Request::Approve { tty }` is set by the client; any root process can claim a terminal | Correct (approval) | Medium | Closed (725f290) | Daemon reads the peer's controlling terminal from its pidfd; field removed. Gym: approve-needs-real-terminal (fake and VM) | A; broker in C |
| B-5 | Untagged security units (fail2ban, AppArmor, USBGuard, a VPN) are Routine everywhere | Correct (classification) | Medium | Closed (02ba283) | Security by default for the named units and option trees; an undeclared or untagged system unit is External (fail closed); the named list is checked by `checks.module-eval` | A |
| B-6 | Session resolved from a bare pid; same-uid pid reuse attributes the wrong session (I21) | Correct (identity) | Medium | Closed (725f290) | `SO_PEERPIDFD` and pidfd-based lookups; a peer gone before it is resolved is its uid alone, with no session or terminal. Pid reuse itself cannot be staged reproducibly; the guarantee rests on P10. Gym: identity-peer-exited (VM) | A |
| B-7 | Token expiry, leases and cooldowns use wall-clock time; moving it back extends approvals; unauthenticated NTP lets a network attacker do it | Correct (I8 expiry) | Medium | Closed (89eb2b4) | `CLOCK_BOOTTIME` for tokens, leases and deadlines; per-process anchored wall clock for the rest; NTS recommended | A |
| B-11 | Under Standard, any non-Security stop by signal or unissued `systemctl stop` is accepted as an inferred override until boot | Correct (repair) | Medium | Closed (c84075d) | `inferStops = false` for backup, sync and desktop units; inferred overrides listed until acknowledged (`planarian ack`). Gym: residue-infer-stops-false, residue-inferred-listed-until-ack (fake and VM) | A |
| B-12 | The core hash is written by the same build it checks and covers only `planariad` | Tamperproof | Medium | Closed (cc86ca5) | Every Planarian binary and posture script is in the core-hash record, each checked by planarian-recovery; signatures in E. Gym: posture-integrity-core-hash, posture-integrity-core-script (VM) | A coverage; E signature |
| B-13 | The `gym-hooks` package accepts fault injection and stale-digest proposals over the socket | Always invoked | Low | Closed (cc86ca5) | Module assertion; a test build started without the gym's permission exits as an Integrity failure. Gym: test-build-is-integrity (VM); checks.module-eval | A |
| B-14 | Specifications and proof tools (Verus, Z3, rustc) are trusted but uncounted; a wrong spec is certified by its proof | Correct (proof) | Low | Closed (e49c37a) | Counted as proof-validity trust (V7–V11); a gym entry per proved invariant written from the English (`en-i5` … `en-i23`), and `planarian-gym verification` fails if a proved invariant has none. A wrong specification is still certified by its proof; what changed is that the English entries can now catch it | A |
| B-15 | Many dynamic-uid services can fill the global connection cap | Always invoked (availability) | Low | Closed (db5b0f4) | 16 of the 64 slots reserved for administrators and callers in a login session | A |
| B-16 | The external source's replay protection lives in a root-writable cache | Correct (I14 input) | Low | Closed (db5b0f4) | Last accepted sequence number and digest in the journal (and so its checkpoint), held by a verified ledger rule | A (before any producer) |
| B-17 | `guarantees.md` says Kani runs by hand; CI runs it | — | Low | Closed (8bf52c9) | Corrected in `guarantees.md` and `verification.md` | A |
| B-20 | A second `planarian agent run` under a running agent's name rebinds that agent: authority was looked up by name, so an administrator re-running `agent run helper` made alice's running agent an administrator's | Correct (authority) | High | Closed (8231a07) | I24: authority bound to the unit instance (InvocationID, read from the peer's cgroup xattr) a start journaled after it succeeded; `agent run` refuses a name in use, naming its owner. Gym: agent-name-collision (fake and VM) | A |

## Accepted

| Id | Route | Breaks | Narrowed by | Phase |
| --- | --- | --- | --- | --- |
| X-1 | Root edits the store, `/boot`, the binaries, the journal or the posture state | All | Detection only: boot report, hash chain, core hash | E |
| X-2 | A `nixos-rebuild` outside Planarian | Always invoked | Observed as an unconfirmed base, never trusted; wrapped by PlanarianOS | C |
| X-3 | Firmware, bootloader and initrd run before `planarian-ready.target` | Always invoked | Boot-chain locking and Secure Boot (C); measured boot (E); nothing below firmware | C, E |
| X-4 | Physical access | All | Disk sealing | E |
| X-5 | A malicious unit that works correctly and passes its probes | Correct | Nothing; the malicious-declaration entries score whether its origin is reported | — |
| X-6 | The supply chain: nixpkgs content, cache signatures, input-addressed store paths | Correct | Nix's boundary, not Planarian's | — |
| X-7 | Backends report success falsely; systemd or the kernel misbehave (P1, P6, P8) | Correct | Re-observation and probes after every call; replaced in D and E | D, E |
| X-8 | The approver: fatigue, social engineering, persuasion by a model | Correct | AskFirst kept rare (per-week ratchet); the change shown in full | — |
| X-9 | *Withdrawn 2026-10-29.* The model's judgement is not a vector: the model is treated as an adversary, so a bad proposal is one any attacker could make and is a policy, catalog or probe finding under its own name. Containment is B-18; persuading an approver is X-8 | — | — | — |
| X-10 | A program a user runs under their own uid, outside `planarian agent run` (an agent started by hand from a shell) | Correct (authority) | It is that user, with that user's capabilities, as anything they run is, and unattributed: Planarian cannot tell a program from its user. The README says to use `planarian agent run`, which gives the same permissions with attribution; C's agent-host profile refuses agents outside it | C |
| X-11 | An agent holds its user's capabilities, including Administrator when an administrator starts it (owner decision, 2026-10-30) | Correct (authority) | By design, not a defect: agents are not treated differently from their users in what they may do. Every request is attributed to the agent in the executor log; who started it is in the hash-chained journal; it has no login session or terminal, so it cannot approve an AskFirst change through the daemon's terminal check (unless it allocates its own pty, the known weakness of §16), and its own AskFirst proposals are its user's, which that user cannot approve (I19) | — |

| X-12 | An override-file writer that does not take the daemon's exclusive directory lock | Correct (I23 replacement) | Accepted by SPEC v4.6 §9/I23: only cooperating lock-taking writers are inside the replacement guarantee. Root ownership or an advisory lock does not constrain arbitrary editors/pre-opened descriptors. The external-editor race characterization remains evidence of this accepted bypass, not proof of CAS against those editors | A boundary; wrapped editors from C |
