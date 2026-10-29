# Verification

What the Verus proofs and Kani harnesses establish, what they trust, and
how to run them (SPEC §17a). Pins are in `pins.md`; the trusted assumptions in `assumptions.md`.

## Running

```
nix build .#checks.x86_64-linux.verus     # in the Nix sandbox, pinned Verus
cargo verus verify -p planarian-policy    # with a local Verus; also verifies planarian-schema
```

The flake check uses Verus's published release and the Rust toolchain it
was built against (`nix/verus.nix`, pins in `pins.md`). It fails if any
proof obligation fails: dropping the cumulative check from `decide` makes
it fail. The crates also build with plain `cargo`, which erases the proof
code: `vstd` is an ordinary dependency.

## The ratio d:a and the trust count (§17a)

`docs/verification-ratio.toml` lists, for each invariant, the obligations
a tool discharges on every run (Verus lemmas and verified functions, Kani
harnesses) and the `assumptions.md` ids it rests on. Tests are listed but
not counted. `planarian-gym verification` checks every name against the
source and every id against `assumptions.md`, prints the report, and fails
CI if the global or any per-invariant ratio falls or the trust count grows.

GA baseline (2026-10-29): **trust count = 32** (19 `assumptions.md` entries
plus 13 `external_body` sites: 8 ledger helpers and 5 opaque types);
**global d:a = 28:43**, raised to **32:43** the same day by mapping four
proved obligations (`only_generations_publish` and
`boot_only_never_activates` to I6, `step_allowed` and `add_interlock` to
I12; arguments in `guarantees.md` §3). Invariants with a proof claim in
Phase A: I5 4:3, I6 7:5, I11 2:2, I12 9:8, I14 1:2, I15 2:2, I16 2:3, I19 3:1.
I1–I4, I7, I13, I17, I18 and I20 are tested, not proved (their proof
phases are in SPEC §8).

Before and after v4.4 (owner decision Q6): Verus verified 17 / 37 / 38
obligations in `schema` / `policy` / `txn` before the v4.4 types, and
17 / 52 / 42 after (52 with the G16 lemma). No proof was weakened. The policy lemmas extend to the
new types and add I16 and I19. The ledger adds v4.4's I6 and the boot-only
path.

## `policy` (Phase A target: done)

`decide` itself is verified: its postcondition is `r == decide_spec(*i)`,
and everything it calls has a postcondition tying it to a spec function
(the string comparisons, the longest-prefix option lookup, the §11
authorization rule, the per-transition table, the floors). The properties are
lemmas about `decide_spec` in `crates/policy/src/proofs.rs`:

| Lemma | Property |
| --- | --- |
| `i5_autonomy_never_touches_reject` | The autonomy setting never turns a Reject into a tier or back, never changes a reason, yields no tier above itself but AskFirst, never changes the approver class, and raising it never makes a decision stricter. |
| `i11_non_routine_session_asks` | A non-Routine diff, this change's or the session's cumulative one, means AskFirst or Reject. |
| `i11_session_only_raises` | A change inside a session is decided at least as strictly as on its own. |
| `global_floors` | Non-reversible; session or data loss unless the user's own session; connectivity loss unless the caller has a seat; a session or connectivity loss reaching another uid's session unless an administrator: AskFirst or Reject, for every transition kind. |
| `own_session_is_per_session` | A session loss lands on the caller's own session only when it is exactly the caller's session; another session of the same uid, or an unknown one, asks. |
| `i16_below_floor_needs_administrator` | A target below the security floor is AskFirst with `ApproverClass::Administrator`, or refused, for every transition kind, caller and autonomy setting (I16, the `decide` part). |
| `administrator_class_only_on_ask_first` | An Administrator approver class only ever comes with AskFirst. |
| `security_override_held_for_administrator` | A non-administrator's override (`SetOverride`, `LiftOverride`, `StopAndSuppress`) of a Security-sensitive unit is never `Unauthorized` and never runs on its own: AskFirst for an administrator, or another refusal. |
| `security_restart_runs_alone_only_to_restore` | A restart of a Security-sensitive unit runs below AskFirst only when it restores an unattributed stop (`restores_unattributed_stop`) of a unit that is not also External (§11, G16). |
| `agents_and_unattributed_are_refused` | An agent (reserved) and the unattributed actor are always `Unauthorized`: an inferred override never passes through `decide`. |
| `i19_no_self_approval` | `may_approve` never lets a principal approve its own proposal, requires `Approve`, and requires `Administrator` for that class; `may_grant` never grants to the approver itself, never on its own proposal, and only a capability the approver holds (I19). |
| `i10_canonical_probe_changes_ask` | A change to a canonical probe's definition (probe tampering) is AskFirst or Reject. |
| `unauthorized_is_refused_first` | An unauthorized caller gets `Reject(Unauthorized)`, whatever else holds. |
| `core_is_never_a_target` | A transition touching the core is rejected. |
| `only_administrators_resolve` | Only an administrator can clear the recovery interlock. |
| `users_cannot_change_generations` | A non-admin user cannot switch, revert, roll back, load models, restore snapshots, collect garbage, bind drivers or resolve. |
| `i14_facts_caller_is_not_authority` | The `caller` field in the derived facts has no effect on the decision. |

Authorization (§11, v4.4) is by capability: `Authorization { principal, actor,
capabilities }` is computed by the daemon from `SO_PEERCRED`, the caller's
logind session and group membership (`user_authorization`), and capabilities
count only for users in Phase A. `may_approve` and `may_grant` (I19) are
verified the same way as `decide`.

`decide` takes no `Proposal`, so I14 in §17a's sense ("`decide` has no
`Proposal` input") holds by its signature.

**Mutation check.** Each of these makes verification fail at the expected
place: dropping the cumulative check from `decide` only (its postcondition
fails), from both `decide` and the spec (the I11 lemma fails), letting the
prefix match ignore the `.` (`is_under` fails), and making the autonomy cap
reject (the I5 lemma fails).

**Trusted, not proved:**
- vstd's specifications of `Vec`, `String::as_str`, `str::unicode_len` and
  `str::get_char` (vstd `assume_specification`s for std).
- That the executor derives `DerivedFacts` correctly (I14's other half:
  facts come from the evaluated generation). `exec` is not verified in
  Phase A (§17a: Kani and proptest in A, Verus in C).
- `Value` is opaque to the proofs; `decide` never inspects option values.
- Serialization: serde impls are `external_derive`, unverified.

## `schema`

The types `decide` and the ledger read are inside `verus!`;
`Sensitivities`' operations, the transition-to-recovery table and the
`TxnState` predicates are verified against their specs.

`schema::digest` is not proved (see `deviations.md` for why). A property
test over random states checks it: perturbing resources or any observation
timestamp never changes the digest, and changing the generation, an
override, or a unit's observed state always does.

## `txn` (Phase A target: done for the state machine and the ledger)

Every record goes through `Ledger::validate` before it is written and
`Ledger::apply` when it is applied or replayed; both are verified.

**State machine** (`machine.rs`): `step_allowed` equals `step_spec`.

| Lemma | Property |
| --- | --- |
| `i12_steps_terminate` | Every allowed step lowers a rank: at most eight steps, no cycles. |
| `i12_terminal_always_reachable` | Every non-terminal state has an allowed step to a terminal one (Cancelled before mutation, RecoveryFailed after). |
| `terminal_is_final` | Terminal states have no successors. |
| `refusal_only_before_mutation` | Rejected and Cancelled only before anything was mutated. |
| `runtime_never_reverts` | Runtime operations never revert, publish or promote. |
| `only_generations_publish`, `generations_commit_after_promotion` | Only generation operations publish (a one-shot boot entry included); they commit only from Promoted. |
| `boot_only_never_activates` | The boot-only path (§12 step 7): `AwaitingBoot` is entered only from `Built`, so the candidate is never live-activated, and left only for `Promoted` or a revert. |

Together with the progress assumptions (`assumptions.md`), these are I12: a
lease holder that keeps stepping reaches a terminal state within eight steps.

**Ledger** (`ledger.rs`). `inv` holds that live transactions have unique ids,
issued ids, leases naming them, non-terminal states, the recovery strategy
their transition fixes, and I6 as v4.4 states it: every two live
transactions are `compatible`, meaning at most one generation-changing
transaction is active (in flight, or waiting in `Built`), and while one is in
flight other than `AwaitingBoot`, no other transaction is (unit and device
repairs may run while one awaits a boot). `i6_one_generation_active` states
this from `inv`. Proved on the code:

- `validate` accepts a record only if `rules` hold: the sequence number is
  next; an Advance, Takeover, Renew or OpBegin carries the transaction's
  current lease epoch (I15: only the lease holder advances the journal); an
  Advance follows `step_spec`, and one that starts mutating is refused while
  the interlock is set for an autonomous caller (§12c), and every Advance is
  refused when its new state would not be compatible with another live
  transaction (I6); a Takeover strictly raises the epoch; an OpAck names an op that was
  begun and not yet acknowledged (write-ahead at the journal: no outcome
  without its OpBegin); a Prepared transaction gets a fresh id and epoch 1,
  and is refused while the interlock is set for an autonomous caller.
- `apply` preserves `inv`, never lowers a live transaction's epoch, and an
  Advance to RecoveryFailed always sets the interlock (I12's alerting half).
- `well_formed` decides `inv`; a checkpoint read from disk must pass it.
- `add_interlock` (the sentinel path) preserves `inv`.

**Mutation check.** Each of these fails verification: skipping the I6
exclusivity check in `validate`; accepting a takeover with an equal epoch;
not setting the interlock on RecoveryFailed; dropping I6 from the rule;
dropping the "one active generation transaction" clause from the
executable compatibility check.

**Not proved here:** that the kernel journals OpBegin before the backend
call it names (it does, in `kernel.rs`, which is not verified; §17a puts
`exec` under Verus only in Phase C, with Kani harnesses and proptest in
Phase A; see Kani below), and the bookkeeping helpers listed in
`assumptions.md`.

## Kani: the kernel's decisions and exec (Phase A target: done)

§17a gives `exec` orchestration Kani harnesses and proptest in Phase A. The
kernel journals through serde JSON, which bounded model checking cannot get
through, so the decisions it makes are pure functions in
`crates/txn/src/kernel.rs` that it calls, and the harnesses check those for
every input (`kani::any()`; the state and strategy enums are enumerated in
full). The ordering of journal writes around backend calls is covered
elsewhere: the Verus ledger rules (an `OpAck` needs its `OpBegin`; I15
epochs) and the exec property tests, which crash the kernel at each of 15
points and check recovery.

```
cargo install --locked kani-verifier && cargo kani setup   # once; not in nixpkgs
cargo kani -p planarian-txn
cargo kani -p planarian-exec
```

Kani is not packaged in nixpkgs, so there is no flake check; it runs from
`cargo kani` (version in `pins.md`). Timings are on 4 cores.

| Harness | Proves | Time |
| --- | --- | --- |
| `txn::kani::recovery_table_follows_the_state_machine` | For every non-terminal state and every recovery strategy, `recovery_action` (the crash-recovery table `recover_steps` dispatches on) refuses exactly the pre-mutation states, and every sequence of states the chosen kernel path can journal starts at that state, takes only steps `machine::step_allowed` (Verus-verified) permits, and ends terminal. The paths are read off the kernel functions each action runs. | ~50 s |
| `txn::kani::watchdog_takes_over_only_when_it_should` | `should_take_over` (the watchdog rule): only in the mutation window, never from itself, never from a live owner within its deadline or lease grace; always from a dead owner in the window. No overflow for any clock value. | ~1 s |
| `txn::kani::takeover_fences_out_the_previous_owner` | `next_epoch` and `fence_admits` (I15): a takeover's epoch is above the lease's and the store's fence; once fenced, the old epoch and every other epoch are refused and only the new one admitted; a second takeover fences out the first; at `u64::MAX` the takeover backs off instead of overflowing. `fence_admits` is the check both the real backends and the fake use. | <1 s |
| `txn::kani::override_swap_never_overwrites_a_third_party` | `swap_step` (§9 step 4): swap only when the live override holds the expected source, done exactly when it holds the target, otherwise third party; the revert direction swaps back. | <1 s |
| `exec::kani::approval_tokens_expire_after_their_lifetime` | `token_expired` (§12 step 4): never expired at issue, expired exactly after 24 h, stays expired; no overflow. | <1 s |

Bounds: the recovery harness unwinds loops 6 times (paths are at most 4
steps); the others have no loops. Hash inputs vary in two bytes (only
equality matters).

**Mutation check.** Each of these makes a harness fail: the token expiry as
it was written before (`issued + TOKEN_LIFETIME` without saturation:
"attempt to add with overflow", a real panic on an extreme clock value,
fixed); mapping Activating under RevertGeneration to re-observe-and-commit;
computing the takeover epoch without the store's fence.

Extracting the decisions changed no behaviour, with one exception: a
takeover at epoch `u64::MAX` now backs off with `LostLease` instead of
overflowing.
