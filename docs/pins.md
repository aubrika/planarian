# Pins

Changes to pins happen only by PR (SPEC §17).

| Input | Pin | Where |
| --- | --- | --- |
| nixpkgs | `nixos-26.05` at `1f607aa79b6356ed45d3cd3c8079c196e79efa2c` (2026-10-25) | `flake.lock` (fetched through git, see deviations) |
| Rust toolchain | 1.95.0 (matches nixpkgs 26.05's `rustc`) | `rust-toolchain.toml`, `Cargo.toml` `rust-version` |
| eBPF build (netwatch, §12d) | the pinned rustc 1.95.0 with `RUSTC_BOOTSTRAP=1` for `-Z build-std=core`, and `bpf-linker` 0.9.15, both nixpkgs' at the pin above (LLVM 21.1.8); the build fails if their LLVM majors differ. The library's crates for `build-std` are a fixed-output vendor (`fetchCargoVendor`, hash in the file), so evaluation builds nothing; a rustc bump fails that hash until it is renewed. aya-ebpf 0.1.x builds on 1.95; 0.2.x declares rustc 1.98 | `nix/netwatch-ebpf.nix` |
| Verus | release `0.2026.10.26.d17fbd0` (commit `d17fbd0c58abf0d5e86825ea64b96aba72b1b31f`), the published x86_64-linux binaries | `nix/verus.nix` |
| Verus's Rust toolchain | 1.99.1 with `rustc-dev`, from static.rust-lang.org by the channel manifest's hashes (Verus pins its own; the workspace builds with 1.95.0) | `nix/verus.nix` |
| z3 (for Verus) | 4.16.0, shipped in the Verus release | `nix/verus.nix` |
| Kani | `kani-verifier` 0.68.0 (CBMC 6.11.0, its own nightly-2026-08-21 toolchain), installed with `cargo install --locked kani-verifier`; the release bundle `kani-0.68.0-x86_64-unknown-linux-gnu.tar.gz` has sha256 `32e2b484d73ede0bbf64a2cf0879c4259422497d8aec4ee67d448de9ae7843d3`, checked by `sha256sum -c` on every use in `.github/workflows/ci.yml` (the digest was computed from one download of the GitHub release asset; the release publishes none) | not in the flake: `cargo kani` |
| vstd | `0.0.0-2026-10-25-0158` from crates.io (the pinned Verus commit's) | `Cargo.toml` |
| mdBook (the guarantees site, §17c) | 0.5.2, nixpkgs' at the pin above (`nix shell --inputs-from . nixpkgs#mdbook`) | `.github/workflows/site.yml` |
