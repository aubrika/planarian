# Bypass register

Every known route by which the machine can reach a state SPEC v4.5 says cannot happen, or by which a stated guarantee stops describing the real machine (SPEC §17b). **B** rows are open findings; **X** rows are accepted by design. Ids are never reused. No gate passes with an open High row.

**Breaks:** *always invoked* (a change reaches the machine without the monitor), *tamperproof* (something guarded can alter the monitor or its record), *correct* (the monitor runs intact but decides on wrong inputs, or proves a narrower property than stated).

**Severity:** High = defeats a stated guarantee in the shipped configuration without root. Medium = needs root, a network position or a likely deployment, or the spec overstated the mechanism. Low = narrow, availability-only, or process. Accepted = outside the claim by design.

Seeded from the spec vulnerability review of 2026-10-29 against commit `1bc09b2`. Status "Open (v4.5 §x)" means the spec now requires the fix and the code does not have it yet.

## Open

| Id | Route | Breaks | Severity | Status | Mitigation | Phase |
| --- | --- | --- | --- | --- | --- | --- |
| B-1 | An agent started by a user runs under that uid and holds its capabilities, including Administrator for a `planarian-admin` member | Correct (authority) | High | Open (v4.5 §11, §16) | Agents are their own principals via `planarian agent run` (`DynamicUser=`); the same-uid case becomes X-10 once the launcher ships | A launcher and docs; B required; C refused by agent-host profile |
| B-2 | The security floor is derived from `environment.systemPackages` only; fixes in service packages, the kernel or firmware do not move it | Correct (I16) | High | Open (v4.5 §12e) | Derive from the whole system closure; CVE feed in B; administrator mark remains | A closure; B feed |
| B-3 | `Request::Approve { tty }` is set by the client; any root process can claim a terminal | Correct (approval) | Medium | Open (v4.5 §11) | Daemon reads the peer's controlling terminal from its pidfd; field removed | A; broker in C |
| B-4 | `decide` is proved, but its inputs (`DerivedFacts`, `Authorization`) are computed by unproven code | Correct (inputs) | Medium | Open (v4.5 §17a) | Internal-unproven count reported separately; fail-closed defaults; `derive` proved in C | A accounting; C proof |
| B-5 | Untagged security units (fail2ban, AppArmor, USBGuard, a VPN) are Routine everywhere | Correct (classification) | Medium | Closed (02ba283) | Security by default for the named units and option trees; an undeclared or untagged system unit is External (fail closed); the named list is checked by `checks.module-eval` | A |
| B-6 | Session resolved from a bare pid; same-uid pid reuse attributes the wrong session (I21) | Correct (identity) | Medium | Open (v4.5 §10) | `SO_PEERPIDFD` and pidfd-based lookups | A |
| B-7 | Token expiry, leases and cooldowns use wall-clock time; moving it back extends approvals; unauthenticated NTP lets a network attacker do it | Correct (I8 expiry) | Medium | Closed (89eb2b4) | `CLOCK_BOOTTIME` for tokens, leases and deadlines; per-process anchored wall clock for the rest; NTS recommended | A |
| B-8 | The journal hash chain is unkeyed; root can rewrite it consistently | Tamperproof | Medium | Open (v4.5 I18, §12c) | I18 qualified; chain head in the signed health report for off-machine witnessing; TPM anchor | A wording; C witness; E anchor |
| B-9 | Posture alarms and notification are local; root can clear them and a stopped `planariad` can go unnoticed | Tamperproof | Medium | Open (v4.5 §12d) | Dead-man signal from the signed health report to an off-machine receiver | C |
| B-10 | The boot report checks units, not processes | Always invoked | Medium | Open (v4.5 §10) | Early processes outside the closure | C |
| B-11 | Under Standard, any non-Security stop by signal or unissued `systemctl stop` is accepted as an inferred override until boot | Correct (repair) | Medium | Open (v4.5 §11) | `inferStops = false` for backup, sync and desktop units; inferred overrides listed until acknowledged | A |
| B-12 | The core hash is written by the same build it checks and covers only `planariad` | Tamperproof | Medium | Open (v4.5 I2, §12d) | Cover every Planarian binary and script; signatures in E | A coverage; E signature |
| B-13 | The `gym-hooks` package accepts fault injection and stale-digest proposals over the socket | Always invoked | Low | Open (v4.5 §12d, §15) | Module assertion; boot report raises Integrity | A |
| B-14 | Specifications and proof tools (Verus, Z3, rustc) are trusted but uncounted; a wrong spec is certified by its proof | Correct (proof) | Low | Open (v4.5 §17a) | Counted as proof-validity trust; a gym entry per proved invariant written from the English | A |
| B-15 | Many dynamic-uid services can fill the global connection cap | Always invoked (availability) | Low | Open (v4.5 §16) | Reserved slots for administrators and sessions | A |
| B-16 | The external source's replay protection lives in a root-writable cache | Correct (I14 input) | Low | Open (v4.5 §12c) | Last accepted sequence number in the journal checkpoint | A (before any producer) |
| B-17 | `guarantees.md` says Kani runs by hand; CI runs it | — | Low | Closed (8bf52c9) | Corrected in `guarantees.md` and `verification.md` | A |
| B-18 | The model service escapes its sandbox before I9 is proved, and becomes a process with its uid's capabilities (it parses untrusted text and drives a GPU) | Tamperproof (I9) | Medium | Open (v4.5 §20, I9) | Normative sandbox: dynamic uid, no capabilities, strict read-only filesystem, Unix sockets only, syscall allowlist, render node only, proposal socket as the only write path; gym case attempting every other write path | B sandbox and case; E proof |

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
