# Verification

What the Verus proofs establish, what they trust, and how to run them
(SPEC §17a). Pins are in `pins.md`; the trusted assumptions in `assumptions.md`.

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

## `policy` (Phase A target: done)

`decide` itself is verified: its postcondition is `r == decide_spec(*i)`,
and everything it calls has a postcondition tying it to a spec function
(the string comparisons, the longest-prefix option lookup, the §11
authorization rule, the per-transition table, the floors). The properties are
lemmas about `decide_spec` in `crates/policy/src/proofs.rs`:

| Lemma | Property |
| --- | --- |
| `i5_autonomy_never_touches_reject` | The autonomy setting never turns a Reject into a tier or back, never changes a reason, yields no tier above itself but AskFirst, and raising it never makes a decision stricter. |
| `i11_non_routine_session_asks` | A non-Routine diff, this change's or the session's cumulative one, means AskFirst or Reject. |
| `i11_session_only_raises` | A change inside a session is decided at least as strictly as on its own. |
| `global_floors` | Non-reversible; session or data loss unless the user's own session; connectivity loss unless a local user: AskFirst or Reject, for every transition kind. |
| `i10_canonical_probe_changes_ask` | A change to a canonical probe's definition (probe tampering) is AskFirst or Reject. |
| `unauthorized_is_refused_first` | An unauthorized caller gets `Reject(Unauthorized)`, whatever else holds. |
| `core_is_never_a_target` | A transition touching the core is rejected. |
| `only_administrators_resolve` | Only an administrator can clear the recovery interlock. |
| `users_cannot_change_generations` | A non-admin user cannot switch, revert, roll back, load models, restore snapshots, collect garbage, bind drivers or resolve. |
| `i14_facts_caller_is_not_authority` | The `caller` field in the derived facts has no effect on the decision. |

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

The types `decide` reads are inside `verus!`; `Sensitivities`' operations
are verified against their specs. `schema::digest` is not yet proved.

## `txn`

Not yet verified.
