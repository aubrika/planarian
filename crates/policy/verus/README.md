# Policy proofs

`policy.rs` proves I5, I11, the global floors, I10, CoreTarget and
authorization-first about `decide_spec`. How that connects to the shipped
`decide` is in `../src/model.rs`; what is proved and what is only tested is in
`docs/deviations.md`.

## Running

Verus is built from source at the commit in `docs/pins.md`:

```
git clone https://github.com/verus-lang/verus && cd verus && git checkout <commit>
cd source && rustup toolchain install          # Verus's own toolchain (1.99.1)
cargo install cargo-make --locked
export VERUS_Z3_PATH=$PWD/z3                   # z3 4.16.0
cargo make build
```

Then, from the repository root:

```
VERUS_Z3_PATH=… path/to/verus crates/policy/verus/policy.rs
# verification results:: 5 verified, 0 errors
```

After editing the body between the MODEL markers here, make the same edit in
`../src/model.rs`; `cargo test -p planarian-policy` fails until both match and
the model still agrees with `decide`.
