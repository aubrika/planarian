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

See `verification.md` for what is proved.

## Phase A: stated in SPEC §17a, not yet bound to proof sites

| Assumption | Sites |
| --- | --- |
| **P1** Backend `Outcome` is honest: `Succeeded` means applied; `Unknown` means the backend cannot say | — |
| **P2** `activate_live(revert_to)` restores the activation state of `revert_to` | — |
| **P3** `publish_boot` and the override promotion rename are idempotent | — |
| **P4** Journal fsync is durable and the preallocation is writable | — |
| **P5** SHA-256 is collision-resistant (the journal's hash chain, I18) | `txn::journal::chain` |
| **P6** systemd reports unit state truthfully over D-Bus and honors `X-RestartIfChanged` / `X-StopIfChanged` | — |
| **P7** Fencing is effective: a stale-epoch call is refused before it mutates | — |
| **P8** The kernel and systemd are correct | — |
| **P9** The executor derives `DerivedFacts` from the evaluated generation, never from a proposal (I14's other half; property-tested, verified in Phase C) | `exec::derive` |

## Progress assumptions for I12

**G1** Some lease holder eventually runs. **G2** A fenced worker eventually stops issuing calls, or its calls are refused. **G3** Journal writes eventually succeed. **G4** Backend calls terminate.

The ids (V, P, G) are what `docs/verification-ratio.toml` cites; the trust count is their number plus every `external_body` and `assume` site in the verified crates (`planarian-gym verification`).

## Fake harness (tests only, not proof sites)

`txn::fake` models the backends in memory. Each kernel test's claim is only as good as the fake's fidelity to the contracts above: fencing refuses a stale epoch before any effect, `jobs_tagged` finds every job an op started (or answers `None`), and `swap_override` is a compare-and-swap. The VM harness exists to check the real backends against these same contracts.

The catalog entry `fake-assumptions-conformance` (`crates/gym/src/conformance.rs`) runs both halves on every CI run. It holds one check per row above against the fake. It then injects Partial (the effect landed, the call failed), Unknown and Fenced into each mutating call (restart, stop, activate_live, publish_boot, publish_boot_once, swap_override, bind, collect_garbage) during a catalog entry that makes that call. Every transaction must end terminal (I12) and the journal must replay (I15). No fake-harness entry makes `cancel`, `unbind` or the runtime `set`. `GenerationBackend::protect` has no caller.
