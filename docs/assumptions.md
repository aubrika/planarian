# Trusted assumptions

Every externally specified behavior the proofs rely on (SPEC §17a). Each Verus `assume` / `external_body` site gets a line here in the same PR that adds it (SPEC §18.11).

## Verified code (`policy`, `schema`)

No `assume` and no `external_body` function. Trusted instead:

| Trusted | Sites |
| --- | --- |
| vstd's specifications of `Vec`, `String::as_str`, `str::unicode_len`, `str::get_char` | `policy` string helpers |
| `Value` is an opaque external type (`external_type_specification`); nothing about it is assumed | `schema::transition` |
| Serde impls are unverified (`external_derive`) | `schema`, `policy`, `txn` |
| `Expectation`, `CheckContext`, `ApprovalToken`, `Incident` are opaque external types | `schema::txn`, `schema::transition` |
| Ledger bookkeeping helpers (`push_tag`, `tag_string`, `note_why`, `archive`, `set_override`, `lift_override`, `record_incident`, `use_token`) are `external_body` with no postcondition: each receives only the field it updates, so the verified fields are untouched by construction; trusted only to terminate | `txn::ledger` |
| vstd's specifications of `Vec::push`, `insert`, `remove`, `is_empty` and `Box` | `txn::ledger` |

See `verification.md` for what is proved.

## Phase A: stated in SPEC §17a, not yet bound to proof sites

| Assumption | Sites |
| --- | --- |
| Backend `Outcome` is honest: `Succeeded` means applied; `Unknown` means the backend cannot say | — |
| `activate_live(revert_to)` restores the activation state of `revert_to` | — |
| `publish_boot` and the override promotion rename are idempotent | — |
| Journal fsync is durable and the preallocation is writable | — |
| SHA-256 is collision-resistant (the journal's hash chain, I18) | `txn::journal::chain` |
| systemd reports unit state truthfully over D-Bus and honors `X-RestartIfChanged` / `X-StopIfChanged` | — |
| Fencing is effective: a stale-epoch call is refused before it mutates | — |
| The kernel and systemd are correct | — |

## Progress assumptions for I12

Some lease holder eventually runs; a fenced worker eventually stops issuing calls or its calls are refused; journal writes eventually succeed; backend calls terminate.

## Fake harness (tests only, not proof sites)

`txn::fake` models the backends in memory. Each kernel test's claim is only as good as the fake's fidelity to the contracts above: fencing refuses a stale epoch before any effect, `jobs_tagged` finds every job an op started (or answers `None`), and `swap_override` is a compare-and-swap. The VM harness exists to check the real backends against these same contracts.

The catalog entry `fake-assumptions-conformance` (`crates/gym/src/conformance.rs`) runs both halves on every CI run. It holds one check per row above against the fake. It then injects Partial (the effect landed, the call failed), Unknown and Fenced into each mutating call (restart, stop, activate_live, publish_boot, publish_boot_once, swap_override, bind, collect_garbage) during a catalog entry that makes that call. Every transaction must end terminal (I12) and the journal must replay (I15). No fake-harness entry makes `cancel`, `unbind` or the runtime `set`. `GenerationBackend::protect` has no caller.
