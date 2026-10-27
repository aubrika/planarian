# AGENTS.md

Instructions to coding agents working on Planarian. Source of truth: SPEC §18 (`docs/SPEC.md`); this file mirrors it and must be updated alongside it.

0. **First deliverable, before any other code:** the Phase A fault catalog (`crates/gym/catalog/phase-a.toml`), one entry per §15 family at minimum, each with `inject`, `required_post`, `intent`, `family`; stop for owner review.
1. **Second deliverable:** the GA demonstration script (`gym/demo.sh`): fault → repair; bad config → revert; kill `planariad` during `Activating`; watchdog reverts; restart daemon; reconciliation record printed. Build toward making it pass; everything else is in service of it.
2. Implement Phase A only; traits for B–E with one implementation.
3. Build order: `schema` → `txn` (with the journal and an in-memory fake backend) → `policy` → `state` + `backends/systemd` + `backends/udev` → `exec` + `backends/nixos-rebuild` → `watchdog` → `changes` → `incident` → `diagnose` → `gym` → `intent` → `cli` → `daemon` → `console`. The console Graph view may be built as soon as `state` works.
4. Preserve however the schema evolves: I5, I6, I10, I11, I12, I13, I14, I15; `digest()` excludes resources and timestamps; `Proposal` is the only write path; policy facts derived by the executor; gym scores on `required_post` and intent cases, never on absence of errors; diagnoser before any model; probes with side effects other than `None` or a bounded `Measurement` never on a cadence.
5. Do not resolve §19 items; `TODO(owner)` with the stated default.
6. No language model, LLM API, or prompt anywhere in Phase A.
7. Where NixOS and this spec disagree on mechanism, follow NixOS and record in `docs/deviations.md`.
8. Every executor outcome must be reproducible from the log: proposal, pre/post state, `DerivedFacts`, `PolicyVersion`, probe evidence, decision, outcome.
9. `schema`, `policy`, `txn` in the Verus subset; land `policy` proofs before starting `exec`.
10. The Asterinas gym target may stay red. Classify failures; fix only `Core`.
11. Every new `assume`/`external_body` adds a line to `docs/assumptions.md` in the same PR.

## Status

- [x] 0. Phase A fault catalog: `crates/gym/catalog/phase-a.toml`. Owner accepted the defaults 2026-10-26.
- [x] 1. GA demonstration: `crates/gym/demo.sh --harness fake` passes all four steps.
- Build order (item 3), all implemented: `schema`, `txn`, `policy`, `state`, the real backends (`crates/backends/linux`), `exec`, `watchdog`, `changes`, `incident`, `diagnose`, `gym`, `intent`, `cli`, `daemon`. The console is not built (see `docs/deviations.md`).
- Packaging: `flake.nix` (package, `nixosModules.default`/`reference`, template, checks), `nix/module.nix`, `nix/reference.nix`.

Checks and where they run:
- `cargo test`: unit and fake-harness tests for every crate.
- `cargo run -p planarian-gym -- run`: the catalog on the fake harness. Reports PASS, PARTIAL (some keys not checkable on the fake), FAIL, UNSUPPORTED, or VM-only.
- `nix run .#gym-vm -- [ID ...]`: the catalog on real NixOS VMs, one test per entry (`legacyPackages.<system>.gym-vm.<id>`, nix/tests/gym-vm.nix). The VM carries the fixtures for real (services, a sound card, a GPU, a second NIC, a USB stick to hot-unplug, a small journal filesystem, an upstream machine at 10.0.2.2) and a Planarian built with `gym-hooks` (fault injection: crash points, backend results and delays through /run/planarian-gym). Configuration changes use prebuilt candidates picked by a shim owner flake. The in-VM half is `planarian-gym vm …` (crates/gym/src/live.rs); the judge is the fake harness's, fed from the real journal, executor log, notices and a status sampler. Each entry takes its catalog window in wall-clock time (ending early once it passes, unless a key could still turn), so all 62 take hours; build them in parallel with KVM.
- `nix build .#checks.x86_64-linux.package`: the package and its tests, in the Nix sandbox.
- `nix build .#checks.x86_64-linux.module-eval`: evaluates a full NixOS system with the module and asserts on the exported manifest.
- `nix build .#checks.x86_64-linux.vm-runtime`: a NixOS VM on real systemd. Needs KVM to be fast; without KVM it runs under emulation in about 20–30 minutes.

- `nix build .#checks.x86_64-linux.boundaries` (or `nix/tests/boundaries.sh`): the dependency rule (§5, §17): core crates use no backends, `std::process`, `/proc`, `/sys` or `/nix`; no `dyn` in schema, policy, txn, exec; nothing lifts `unsafe_code = forbid`.
- `nix build .#checks.x86_64-linux.vm-generations`: a NixOS VM applies a cataloged change (commits), a bad one (reverts), and keeps a user's stop through both.
- `nix build .#iso`: the same demo machine as a live USB image (nix/live/iso.nix; shared parts in nix/demo/common.nix), UEFI and BIOS, everything in RAM.
- `nix run .#vm` / `nix run .#vm-text`: an interactive demo VM (nix/vm/machine.nix) whose /etc/nixos evaluates to the booted system, so changes made inside are real rebuilds. `checks.demo-vm` builds it.
- `cargo kani -p planarian-txn` and `cargo kani -p planarian-exec`: the Kani harnesses for the kernel's decision rules and token expiry (§17a). Kani is not in nixpkgs: `cargo install --locked kani-verifier && cargo kani setup`. See `docs/verification.md`.
- `nix build .#checks.x86_64-linux.verus`: `decide` verified and the §17a policy properties proved, in the Nix sandbox with the pinned Verus. See `docs/verification.md`.

**Not yet done:** a Verus proof of `schema::digest` (property-tested instead; see deviations); a gym VM harness for the catalog's VM-only entries that need devices or a desktop (drivers, suspend, the greeter and compositor, journal filesystems). On real NixOS, `vm-runtime` and `vm-generations` cover service kills, deferring to systemd, escalation within budget, user stops (including across generation changes), authorization, and generation commit and revert.
