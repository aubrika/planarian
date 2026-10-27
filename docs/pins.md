# Pins

Changes to pins happen only by PR (SPEC §17).

| Input | Pin | Where |
| --- | --- | --- |
| nixpkgs | `nixos-26.05` at `1f607aa79b6356ed45d3cd3c8079c196e79efa2c` (2026-10-25) | `flake.lock` (fetched through git, see deviations) |
| Rust toolchain | 1.95.0 (matches nixpkgs 26.05's `rustc`) | `rust-toolchain.toml`, `Cargo.toml` `rust-version` |
| Verus | `0.2026.10.26.1b5a744` (commit `1b5a744c26e8277ed008cb6e0c669d2f4b65939a`), built from source | `docs/verification.md` |
| Verus's Rust toolchain | 1.99.1 (Verus pins its own; separate from the workspace's 1.95.0) | Verus's `rust-toolchain.toml` |
| z3 (for Verus) | 4.16.0, the version Verus's `get-z3.sh` names | `VERUS_Z3_PATH` |
| vstd | `0.0.0-2026-10-25-0158` from crates.io (the pinned Verus commit's) | `Cargo.toml` |
