# Pins

Changes to pins happen only by PR (SPEC §17).

| Input | Pin | Where |
| --- | --- | --- |
| nixpkgs | `nixos-26.05` at `1f607aa79b6356ed45d3cd3c8079c196e79efa2c` (2026-10-25) | `flake.lock` (fetched through git, see deviations) |
| Rust toolchain | 1.95.0 (matches nixpkgs 26.05's `rustc`) | `rust-toolchain.toml`, `Cargo.toml` `rust-version` |
| Verus | release `0.2026.10.26.d17fbd0` (commit `d17fbd0c58abf0d5e86825ea64b96aba72b1b31f`), the published x86_64-linux binaries | `nix/verus.nix` |
| Verus's Rust toolchain | 1.99.1 with `rustc-dev`, from static.rust-lang.org by the channel manifest's hashes (Verus pins its own; the workspace builds with 1.95.0) | `nix/verus.nix` |
| z3 (for Verus) | 4.16.0, shipped in the Verus release | `nix/verus.nix` |
| Kani | `kani-verifier` 0.68.0 (CBMC 6.11.0, its own nightly-2026-08-21 toolchain), installed with `cargo install --locked kani-verifier` | not in the flake: `cargo kani` |
| vstd | `0.0.0-2026-10-25-0158` from crates.io (the pinned Verus commit's) | `Cargo.toml` |
