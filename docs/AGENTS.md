# AGENTS.md

Instructions to coding agents working on Planarian. Source of truth: SPEC §18 (`docs/SPEC.md`); this file mirrors it and must be updated alongside it.

0. **First deliverable, before any other code:** the Phase A fault catalog (`crates/gym/catalog/phase-a.toml`), one entry per §15 family at minimum, each with `inject`, `required_post`, `intent`, `family`; stop for owner review.
1. **Second deliverable:** the GA demonstration script (`gym/demo.sh`): fault → repair; bad config → revert; kill `planariad` during `Activating`; watchdog reverts; restart daemon; reconciliation record printed. Build toward making it pass; everything else is in service of it.
2. Implement Phase A only; traits for B–E with one implementation.
3. Build order (historical; every crate exists at v4.6): `schema` → `txn` (with the journal and the `fake` backends) → `policy` → `state` + `backends/linux` (systemd, logind, sysfs) → `exec` + `backends/linux` (nixos-rebuild) → `watchdog` → `changes` → `incident` → `diagnose` → `gym` → `intent` → `cli` → `daemon` → `console`. The console Graph view may be built as soon as `state` works.
4. Preserve however the schema evolves: I5, I6, I10–I25; `digest()` excludes resources and timestamps; `Proposal` is the only write path; policy facts derived by the executor; gym scores on `required_post` and intent cases, never on absence of errors; diagnoser before any model; probes with side effects other than `None` or a bounded `Measurement` never on a cadence.
5. Do not resolve §19 items; `TODO(owner)` with the stated default.
6. No language model, LLM API, or prompt anywhere in Phase A.
7. Where NixOS and this spec disagree on mechanism, follow NixOS and record in `docs/deviations.md`.
8. Every executor outcome must be reproducible from the log: proposal, pre/post state, `DerivedFacts`, `PolicyVersion`, probe evidence, decision, outcome.
9. `schema`, `policy`, `txn` in the Verus subset; land `policy` proofs before starting `exec`.
10. The Asterinas and Firecracker gym targets may stay red in A. Classify failures; fix only `Core`.
11. Every new `assume`/`external_body` adds a line to `docs/assumptions.md` in the same PR.
12. The fake backend used by the transaction kernel MUST satisfy every entry in `docs/assumptions.md`, not only the trait signatures: it is a second real implementation, not a mock. The gym runs the kernel against it under injected `Partial`, `Unknown`, and fenced outcomes.
13. The journal is hash-chained from the first commit that writes it (I18).
14. Never implement Planarian's response to its own failure inside `planariad`; it lives in `nix/posture.nix` as systemd and initrd units (§12d).
15. Report the invisibility budget (§21) and the verification ratio (§17a) from the first gym run; treat any degradation as a failing test.
16. `docs/future-work.md` is non-normative. Cite it; do not implement from it. If anything there seems to block Phase A, stop and ask.
17. Phase A was held open for v4.4: the schema-affecting changes (`Override`, the `Actor` shape, the security floor, the hash-chained journal) land before the Phase A proofs are written, not as migrations after them.
18. Keep `docs/bypasses.md` current (§17b): a PR that adds a path to the machine adds a row or says it opens none.
19. **v4.6 handoff, in this order.** (a) Reconcile: the close-out review in the project ("Phase A close-out review, head 805cd1c") lists every finding with its status at that head; before touching anything, confirm each item you take on is still open at *your* head and record which commit closed the ones that aren't. (b) B-20 first (I24; §11, §16): register the row, fix, add `agent-name-collision` to both harnesses. (c) The documentation sweep: every doc agrees with head and with this spec before any further status is cited (`ga-status.md`'s summary; `guarantees.md`'s accounting; `bypasses.md`'s three tables; `AGENTS.md` mirroring §18 rules 0–21; `catalog-review.md`'s counts and a v4.6 section; `phase-a.toml`'s header; the deviations rows §28 names). (d) The §28 required changes, one PR each, each with its §15 acceptance case landing in the same PR. (e) §15's harness contract and §17a's accounting checks. (f) Then, and only then, run the whole VM catalog on one commit and update `ga-status.md` from that run; a gate claim cites one commit and one run, never a union of runs.
20. **Equivalent effects, equivalent treatment.** When two spellings of a request, two paths to a commit, or two sources of a proposal produce the same effect on the machine, they get the same derived facts, the same floors, and the same bookkeeping (§11, I25). A PR that adds a spelling, a path or a source states which existing one it is equivalent to and shows the gym case that holds them equal.
21. **Nothing is derived from a failed tool.** A backend or helper that exits nonzero, times out, or returns truncated output never contributes a smaller plan, a `None` disruption, or a passing verdict; the step fails or the change parks (§9 step 3, §15 harness contract).

## Status

- [x] 0. Phase A fault catalog: `crates/gym/catalog/phase-a.toml`. Owner accepted the defaults 2026-10-26.
- [x] 1. GA demonstration: `crates/gym/demo.sh --harness fake` passes all four steps.
- Build order (item 3), all implemented: `schema`, `txn`, `policy`, `state`, the real backends (`crates/backends/linux`), `exec`, `watchdog`, `changes`, `incident`, `diagnose`, `gym`, `intent`, `cli`, `daemon`, and the read-only console (`crates/console`, §16a) and status indicator (`crates/tray`).
- Packaging: `flake.nix` (package, `nixosModules.default`/`reference`, template, checks), `nix/module.nix`, `nix/reference.nix`.

Checks and where they run:
- `cargo test`: unit and fake-harness tests for every crate.
- `cargo run -p planarian-gym -- run [--id ID] [-v] [--notices] [--strict]`: the catalog on the fake harness. Reports PASS, PARTIAL (a key went unchecked), FAIL, UNSUPPORTED (a step the fake cannot do), or VM-only; exits 1 on any FAIL or PARTIAL (and on UNSUPPORTED with `--strict`). `--notices` prints the daemon's notices for each entry. `cargo test -p planarian-gym` shows each judge check failing on evidence altered the way a bug would alter it.
- CI (`.github/workflows/`): `ci.yml` runs fmt, clippy (also with `gym-hooks`), the tests, the fake catalog and GA demo, the boundaries, the Verus proofs and the Kani harnesses on every push; `vm.yml` runs the NixOS VM tests and the GA demo on VMs (KVM) per push (the VM checks, the GA demonstration and a set of gym smoke entries, counted against the Actions quota in a private repo), and the whole VM catalog only by hand (`catalog=true`; one job per VM entry, 94 at v4.6).
- `nix run .#gym-vm -- [ID ...]`: the catalog on real NixOS VMs, one test per entry (`legacyPackages.<system>.gym-vm.<id>`, nix/tests/gym-vm.nix). The VM carries the fixtures for real (services, a sound card, a GPU, a second NIC, a USB stick to hot-unplug, a small journal filesystem, an upstream machine at 10.0.2.2) and a Planarian built with `gym-hooks` (fault injection: crash points, backend results and delays through /run/planarian-gym). Configuration changes use prebuilt candidates picked by a shim owner flake. The desktop is a stand-in (a greeter service and a per-user compositor that brings up graphical-session.target unless told to fail), since what the desktop entries test is Planarian's session deadline and boot confirmation, not COSMIC; Wi-Fi is three mac80211_hwsim radios with two hostapd access points; the USB stick is published at /run/gym-usb0 by udev. The VM boots its kernel directly, so an entry that reboots into a published generation (desktop-boot-fails-rollback) is UNSUPPORTED there. The in-VM half is `planarian-gym vm …` (crates/gym/src/live.rs); the judge is the fake harness's, fed from the real journal, executor log, notices and a status sampler. Each entry takes its catalog window in wall-clock time (ending early once it passes, unless a key could still turn), so the whole VM catalog (94 entries at v4.6) takes hours; CI builds them in parallel with KVM.
- `nix build .#checks.x86_64-linux.package`: the package and its tests, in the Nix sandbox.
- `nix build .#checks.x86_64-linux.module-eval`: evaluates a full NixOS system with the module and asserts on the exported manifest.
- `nix build .#checks.x86_64-linux.vm-runtime`: a NixOS VM on real systemd. Needs KVM to be fast; without KVM it runs under emulation in about 20–30 minutes.

- `nix build .#checks.x86_64-linux.boundaries` (or `nix/tests/boundaries.sh`): the dependency rule (§5, §17): core crates use no backends, `std::process`, `/proc`, `/sys` or `/nix`; no `dyn` in schema, policy, txn, exec; nothing lifts `unsafe_code = forbid`.
- `nix build .#checks.x86_64-linux.vm-generations`: a NixOS VM applies a cataloged change (commits), a bad one (reverts), and keeps a user's stop through both.
- `planarian-tray` (crates/tray): the status indicator, a StatusNotifierItem over zbus (ksni). Its level comes from `ConsoleReport::needs_attention` (crates/ipc), the same test the console uses to start visible. It ships in the console package.
- `nix build .#iso`: the same demo machine as a live USB image (nix/live/iso.nix; shared parts in nix/demo/common.nix), UEFI and BIOS, everything in RAM.
- `nix run .#vm` / `nix run .#vm-text`: an interactive demo VM (nix/vm/machine.nix) whose /etc/nixos evaluates to the booted system, so changes made inside are real rebuilds. `checks.demo-vm` builds it.
- `cargo kani -p planarian-txn` and `cargo kani -p planarian-exec`: the Kani harnesses for the kernel's decision rules and token expiry (§17a). Kani is not in nixpkgs: `cargo install --locked kani-verifier && cargo kani setup`. See `docs/verification.md`.
- `nix build .#checks.x86_64-linux.verus`: `decide` verified and the §17a policy properties proved, in the Nix sandbox with the pinned Verus. See `docs/verification.md`.

**Not yet done:** a Verus proof of `schema::digest` (property-tested instead; see deviations); a gym VM harness for the catalog's VM-only entries that need devices or a desktop (drivers, suspend, the greeter and compositor, journal filesystems). On real NixOS, `vm-runtime` and `vm-generations` cover service kills, deferring to systemd, escalation within budget, user stops (including across generation changes), authorization, and generation commit and revert.
