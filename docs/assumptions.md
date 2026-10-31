# Trusted assumptions

Every externally specified behavior the proofs rely on (SPEC §17a). Each Verus `assume` / `external_body` site gets a line here in the same PR that adds it (SPEC §18.11).

## Verified code (`policy`, `schema`)

No `assume` and no `external_body` function. Trusted instead:

| Trusted | Sites |
| --- | --- |
| **V1** vstd's specifications of `Vec`, `String::as_str`, `str::unicode_len`, `str::get_char` | `policy` string helpers |
| **V2** `Value` is an opaque external type (`external_type_specification`); nothing about it is assumed | `schema::transition` |
| **V3** Serde impls are unverified (`external_derive`) | `schema`, `policy`, `txn` |
| **V4** `Expectation`, `CheckContext`, `ApprovalToken`, `Incident` are opaque external types | `schema::txn`, `schema::transition` |
| **V5** Ledger bookkeeping helpers (`push_tag`, `tag_string`, `note_why`, `archive`, `set_override`, `lift_override`, `record_incident`, `use_token`) are `external_body` with no postcondition: each receives only the field it updates, so the verified fields are untouched by construction; trusted only to terminate | `txn::ledger` |
| **V6** vstd's specifications of `Vec::push`, `insert`, `remove`, `is_empty` and `Box` | `txn::ledger` |
| **V7** The specifications the proofs prove against (`decide_spec`, `step_spec`, `inv`, `chained`, the lemma statements) say what the SPEC's English means. A proof certifies a wrong specification as readily as a right one; each proved invariant has a gym entry written from the English to catch the difference (§17a). | `policy`, `txn`, `schema` |
| **V8** Verus is sound: what it reports verified holds of the code. | every proof |
| **V9** Z3, the solver Verus calls, is sound. | every proof |
| **V10** rustc compiles the verified code to a program with the semantics Verus checked. | every proof |
| **V11** Kani and its back end CBMC are sound within the stated bounds. | `txn::kani`, `exec::kani` |

See `verification.md` for what is proved.

## Phase A: stated in SPEC §17a, not yet bound to proof sites

| Assumption | Sites |
| --- | --- |
| **P1** Backend `Outcome` is honest: `Succeeded` means applied; `Unknown` means the backend cannot say | — |
| **P2** `activate_live(revert_to)` restores the activation state of `revert_to` | — |
| **P3** `publish_boot` and the override promotion rename are idempotent | — |
| **P4** Journal fsync is durable and the preallocation is writable | — |
| **P5** SHA-256 is collision-resistant (the journal's hash chain, I18) | `txn::chain` (the chain decision, proved), `txn::journal` (its I/O) |
| **P6** systemd reports unit state truthfully over D-Bus and honors `X-RestartIfChanged` / `X-StopIfChanged` | — |
| **P7** Fencing is effective: a stale-epoch call is refused before it mutates | — |
| **P8** The kernel and systemd are correct | — |
| **P10** A pidfd names one process for as long as it is held, and `SO_PEERPIDFD` (Linux ≥ 6.5) names the process that connected; so a recycled pid can never be mistaken for the peer (§10, B-6). The gym cannot exercise pid reuse itself: Linux hands out pids in increasing order and wraps only after `pid_max` (4 194 304 on 64-bit systems, 32 768 on some), so the same pid coming back to another process of the same uid, in another session, inside one request's lifetime, cannot be arranged reproducibly. `identity-peer-exited` checks the case the pidfd rule decides (a peer gone before it is resolved). The rarity is not the protection; the pidfd is. | `daemon::session_of` |

P9 (facts derived honestly) moved to U1 in the v4.5 re-accounting: it is Planarian's own code, not an assumption about the world.

## Internal unproven code (not assumptions; work not yet proved)

Planarian's own code that the proven gates take input from (SPEC §17a). Counted as the **internal-unproven count**, never in the trust count; it must not grow and is expected to fall from Phase C. Invariants that rest on one cite its id.

| Id | Code | Proved in |
| --- | --- | --- |
| **U1** | `exec::derive`: `DerivedFacts` from the evaluated generation, never from a proposal (I14's other half; property-tested) | C |
| **U2** | `user_authorization` and the administrator lookup (`planarian-admin` membership, root) | C |
| **U3** | The residue classifier (§11: which unit endings are a person's stop) | Kani in A, Verus in C |
| **U4** | Journal I/O around the verified chain: framing, torn-tail truncation, checkpoint replace | C |
| **U5** | Identity resolution (§10): peer credentials and pidfd to logind session, seat, terminal | C |

## Progress assumptions for I12

**G1** Some lease holder eventually runs. **G2** A fenced worker eventually stops issuing calls, or its calls are refused. **G3** Journal writes eventually succeed. **G4** Backend calls terminate. Intentionally parked states follow the separately adopted SPEC v4.6 I12/§12f contract: Built expires at 24 hours; AwaitingBoot is reported as waiting for reboot. The former draft G5 proposal is superseded and is not a current extra assumption.

The ids (V, P, G, U) are what `docs/verification-ratio.toml` cites. The trust count is the number of V, P and G ids plus every `external_body` and `assume` site in the verified crates; the internal-unproven count is the number of U ids (`planarian-gym verification`). Per invariant, `assumes` lists what that invariant specifically rests on; proof-validity trust (V7–V11) underlies every proof alike and is counted once, in the trust count, not repeated on each row.

## Fake harness (tests only, not proof sites)

`txn::fake` models the backends in memory. Each kernel test's claim is only as good as the fake's fidelity to the contracts above: fencing refuses a stale epoch before any effect, `jobs_tagged` finds every job an op started (or answers `None`), and `swap_override` is a compare-and-swap. The VM harness must check real backends against these contracts; its presence is not evidence of a pass. Under adopted SPEC v4.6 I23, real replacement additionally requires the exclusive directory lock for cooperating writers; writers outside that boundary are X-12. An atomic SwapStep model is not arbitrary-editor CAS. Cooperative enforcement is implemented; its compiled/backend race and durability acceptance remain R11/B-21 until executed.

The new withdrawal contract also injects accepted Partial/Unknown and Fenced outcomes against the shared fake adapter; dedicated kernel regressions retain roots after lost withdrawal replies. These authored additions remain UNRUN in this draft.

The catalog entry `fake-assumptions-conformance` (`crates/gym/src/conformance.rs`) runs both halves on every CI run. It holds one check per row above against the fake. It then injects Partial (the effect landed, the call failed), Unknown and Fenced into each mutating call (restart, stop, activate_live, publish_boot, publish_boot_once, swap_override, bind, collect_garbage) during a catalog entry that makes that call. Every transaction must end terminal (I12) and the journal must replay (I15). No fake-harness entry makes `cancel`, `unbind` or the runtime `set`. `GenerationBackend::protect` has no caller.
