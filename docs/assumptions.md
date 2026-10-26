# Trusted assumptions

Every externally specified behavior the proofs rely on (SPEC §17a). Each Verus `assume` / `external_body` site gets a line here in the same PR that adds it (SPEC §18.11).

## Phase A: stated in SPEC §17a, not yet bound to proof sites

| Assumption | Sites |
| --- | --- |
| Backend `Outcome` is honest: `Succeeded` means applied; `Unknown` means the backend cannot say | — |
| `activate_live(revert_to)` restores the activation state of `revert_to` | — |
| `publish_boot` and the override promotion rename are idempotent | — |
| Journal fsync is durable and the preallocation is writable | — |
| systemd reports unit state truthfully over D-Bus and honors `X-RestartIfChanged` / `X-StopIfChanged` | — |
| Fencing is effective: a stale-epoch call is refused before it mutates | — |
| The kernel and systemd are correct | — |

## Progress assumptions for I12

Some lease holder eventually runs; a fenced worker eventually stops issuing calls or its calls are refused; journal writes eventually succeed; backend calls terminate.
