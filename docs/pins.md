# Pins

Changes to pins happen only by PR (SPEC §17).

| Input | Pin | Where |
| --- | --- | --- |
| nixpkgs | `nixos-26.05` at `1f607aa79b6356ed45d3cd3c8079c196e79efa2c` (2026-10-25) | `flake.lock` (fetched through git, see deviations) |
| Rust toolchain | 1.95.0 (matches nixpkgs 26.05's `rustc`) | `rust-toolchain.toml`, `Cargo.toml` `rust-version` |
| Verus | not yet: the build could not run here (see deviations) | — |
| z3 (for Verus) | 4.16.0, the version Verus's `get-z3.sh` names | — |
