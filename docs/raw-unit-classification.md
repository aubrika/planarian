# Classifying raw-unit-file network tools at build time (design, B-23)

Status: **design for review, no code.** Author: lane-nix. Reviewers: the coordinator, the reviewer. Closes B-23 when built. SPEC §12d ("Which units") is the requirement and this file does not change its words: a *network tool* is "computed at build time from its systemd configuration, never from its name, and failing closed".

## 1. The gap

`nix/module.nix` classifies `config.systemd.services`. A unit that exists only as a file in a package listed in `systemd.packages` (never declared in `systemd.services`) is not in that set, so:

- it is not in the export's `networkTools`, so netwatch writes it no footprint and the daemon does not know it;
- it gets no `OnFailure=planarian-hold@%N.service` and no `After=planarian-netwatch.service`: its failure holds nothing and it is not ordered after the watch.

Reading unit files during evaluation would be import from derivation, which this repository does not do. B-23's workaround is a `systemd.services.<name> = { }` stub beside the package.

## 2. What the design rests on (checked, not assumed)

I evaluated a NixOS system with a tiny package shipping `rawtool.service` and a second package, built from `config.systemd.packages` itself, shipping `rawtool.service.d/50-planarian-hold.conf`:

1. **No infinite recursion.** A module may add `systemd.packages = [ dropins ]` where `dropins` is built from `lib.filter (p: !(p.planarianTag or false)) config.systemd.packages`. The filter only reads an attribute of each element, never its `drvPath`, so the derivation that is being defined does not force itself. (`nix eval` of the system succeeds.)
2. **The unit tree merges the drop-in.** `environment.etc."systemd/system".source` (the `system-units` derivation) contains `rawtool.service -> <raw package>/lib/systemd/system/rawtool.service` and `rawtool.service.d/50-planarian-hold.conf -> <drop-in package>/…`, so a package added to `systemd.packages` can add a drop-in to a unit another package ships. This is the mechanism `holdDropins` already relies on for units in `systemd.services`.

So the fix can be a **derivation that reads the raw unit files and writes the drop-ins beside them** (B-23's own wording: "the drop-in package reading the files it ships beside"), with nothing in evaluation depending on its output, only on its being listed.

## 3. Design

**3.1 The derivation `planarian-raw-units`.** Inputs: the elements of `config.systemd.packages` other than itself (and other than Planarian's own, which `own-units.nix` already excludes). At build time it:

1. Reads every `lib/systemd/system/*.service` and `etc/systemd/system/*.service` from every input, and every drop-in systemd applies to it from every input: the unit's own `<name>.service.d/`, each prefix directory (`a-b-c.service` takes `a-b-.service.d/` and `a-.service.d/`), the type-wide `service.d/` (systemd 253 and later), and, for an instance or a template, `<template>@.service.d/`. Drop-ins are applied as systemd applies them: all the directories' `*.conf` files sorted together by file name, a later assignment wins, an empty assignment resets a list setting. A drop-in file name that appears in two inputs is a collision the merged tree resolves by keeping one of them; I have not yet established which wins, so the code PR will determine it from the built unit tree, make the script read the same one, and test it. Until that is shown, a collision makes the unit a tool (fails closed).
2. For each unit, extracts the fields `isNetworkToolUnchecked` reads: `User`, `DynamicUser`, `CapabilityBoundingSet`, `AmbientCapabilities`, `NoNewPrivileges`, `DeviceAllow`, `BindPaths`, `BindReadOnlyPaths`, and applies **the same rule** (§3.4).
3. Writes `$out/lib/systemd/system/<unit>.service.d/50-planarian-hold.conf` for each network tool, with the same content `holdDropins` writes (`OnFailure=planarian-hold@%N.service`, plus `After=planarian-netwatch.service` when netwatch is on and the unit is not in `unordered.cycle`), and `$out/share/planarian/raw-network-tools.json`, the sorted list of unit names (a template's name keeps its `@`).

**3.2 Fail closed (rule 21).** A unit file the script cannot parse (unknown section syntax, an unreadable file, a `.d` drop-in that fails to parse) is a network tool, as an unevaluable `systemd.services` entry is today. So is a unit with a line that names one of the eight settings and that the script cannot parse, **including the granting ones**: an unparsable `DeviceAllow=`, `BindPaths=` or `BindReadOnlyPaths=` line makes a non-root unit a tool, because misreading it as unset would drop the `/dev/net/tun` and `/dev/ppp` grant and fail open. The same holds for an unparsable `User=`, `DynamicUser=`, `CapabilityBoundingSet=`, `AmbientCapabilities=` or `NoNewPrivileges=` line. (Unset happens to be the closed direction for `User=`, `DynamicUser=`, `CapabilityBoundingSet=` and `NoNewPrivileges=`, and the open one for `AmbientCapabilities=` and the three path settings, so the rule is the same for all eight and does not depend on which way each defaults.) A masked unit (a symlink to `/dev/null`) is not. A unit also declared in `systemd.services` is classified by *both* rules and is a tool if either says so. Socket- and timer-activated tools are ordered through their service, as today.

**3.3 The export.** `/etc/planarian/export.json` is `builtins.toJSON cfg.export` today. A raw tool's name is only known after the build, so `networkTools` there must become the union of the evaluated list and `raw-network-tools.json`. The file becomes the output of a small derivation (`jq` over the evaluated JSON and the raw list), not text built at evaluation. The consumers, planariad and netwatch, already read the file, not the evaluated attribute. The daemon needs no change to *use* these names: the unmanaged-tool path (lane-daemon, #93: a network tool with no `services.planarian.units` entry is held and alarmed, never restarted) is exactly what a raw tool is.

What does not change are the readers of the evaluated `cfg.export` and its sibling lists. A raw tool is not in them, and each is correct without the raw names:

| Reader | Why it is fine without raw names |
| --- | --- |
| `holdUnits` (the `OnFailure=` and `After=` drop-ins, the hold unit definitions) | A raw tool gets the same two lines from the derivation's drop-in, so the evaluated drop-ins have nothing to add. The hold unit for it is the template instance `planarian-hold@<unit>`, instantiated by `%N`; the daemon learns the name from the merged export (the unmanaged-tool path, #93). |
| `networkToolsUnordered` (the cycle check in `posture.nix`) | It checks evaluated `systemd.services` units for an ordering cycle against netwatch's startup chain. A raw unit has no evaluated ordering to cycle with; a raw unit that orders itself before netwatch in its own file would be a cycle the check cannot see. That is listed in §6 as a limit, not covered. |
| `networkToolsInitrd`, `netwatchInitrdSurvivors` | They list what the systemd initrd runs, from `boot.initrd.systemd` and the upstream list. A raw unit the initrd ships is not classified (§6); B-26 covers the initrd window. |
| `module-eval` assertions on `networkTools` (`nix/tests/eval.nix`) | They assert on evaluated units, which is what they mean to test. The raw-tool assertions read the built `export.json` instead (§4). |
| `cfg.export.devices` and `declarations` in the manifest | Unrelated to network tools. |
| Gym and VM fixtures that read `networkTools` | They declare their fixtures in `systemd.services`, where classification is unchanged. |

**3.4 One rule, two implementations, held equal.** The rule exists in Nix (`isNetworkToolUnchecked`, over `serviceConfig` attributes) and now in the build script (over unit-file text). Two copies of one rule is a rule-20 hazard, so the design holds them equal by test, and adds a test for the part that is new, the parser:

- **Semantic matrix (agreement).** A `module-eval` fixture takes every combination of the rule's inputs (user root or not, `DynamicUser`, bounding set absent / with `CAP_NET_ADMIN` / without, ambient capabilities, `NoNewPrivileges`, `DeviceAllow=/dev/net/tun`, `BindPaths=` of `/dev/ppp`, netdev units), declares each both as a `systemd.services` entry and as a raw unit file in a test package, and asserts the two classifiers agree. It is exhaustive over the rule's *meaning*, and it fails if either copy drifts.
- **Syntax property (the parser), prop-auditor's shape.** The matrix writes one spelling per input, so it does not test the parser. The parser's tests are:
  1. The agreement matrix above, exhaustive over the rule's inputs, with each input disabled in turn failing it.
  2. A generated-syntax property: draw a semantic configuration (user, `DynamicUser`, bounding and ambient capability sets, `NoNewPrivileges`, `DeviceAllow`, `BindPaths`, `BindReadOnlyPaths`), render it with random syntax (repeated assignments, empty resets, `~` inversion, quoting, `\` continuations, comments, case, numeric capability values, boolean spellings, section order, drop-ins whose file names sort differently from generation order, across the own, prefix, type-wide and template directories), then check `parse(render(c)) == c` and `class == rule(c)`.
  3. Fail closed as a property: an unknown construct in `[Service]`, an unreadable file, or a bad drop-in makes the unit a tool.
  4. Real systemd as a second oracle on a fixed sample: a Nix test runs `systemd-analyze cat-config` / `systemctl show` on the sample units and compares the effective settings with the parser's, as B-18's check does.
  5. The edges are enumerated deterministically (each construct alone and in pairs); only the rest is sampled.
  6. It runs in CI (below).
  7. Mutants: each parse rule disabled fails a named test.

**3.5 Where the parser lives, and why (my call, stated as prop-auditor asked).** A **Rust parser with proptest, in its own small crate invoked at build time**, rather than a Python script with a seeded generator in `module-eval`. Reasons: (1) the repository's rule-23 convention is proptest, run by `cargo test --workspace` on every CI push, while a generator inside `module-eval` runs only in the Nix check and the pinned nixpkgs may not ship `hypothesis`; (2) the parser then has mutants, shrinking and a regression-seed file like every other parser here; (3) the build-time derivation runs the crate's binary from `cfg.package` (`planarian-classify-units <package dirs…>`), so the same code is what CI tests and what the build runs; (4) `planariad --check-export` stays the consumer-side check of the merged file. Costs: the crate is outside nix/**, so I need a grant from the coordinator for a new crate (`crates/unitclass`, no dependency on the core crates, `std` only, covered by the boundaries check) and a line in the workspace manifest; nix/package.nix, which I own, installs the binary. The classification rule in the crate is a second copy of `isNetworkToolUnchecked`; the agreement matrix runs in `module-eval` using the built binary, so Nix and Rust cannot drift unseen.

**3.6 The merged result is verified (the reviewer's last point).** Writing our drop-in is not the same as its being in force: a package's later drop-in, or NixOS's own `overrides.conf` for a unit that is also in `systemd.services`, can carry an empty `OnFailure=` or `After=` that resets the list and silently strips the hold or the ordering. So the same crate has a second mode, `planarian-unitclass verify-hold <system-units dir> <tools>`: it reads the **final** unit tree (`environment.etc."systemd/system".source`, after every package, `overrides.conf` and our drop-in are merged), computes each network tool's *effective* `OnFailure=` and `After=` with the same merge semantics as the classifier, and requires `planarian-hold@%N.service` in `OnFailure=` and (when netwatch is on and the unit is not in `unordered.cycle`) `planarian-netwatch.service` in `After=`, for every tool in the evaluated list **and** the raw list. If any tool fails, **the system build fails** with the unit and the offending file named. It does not export the tool as held-with-the-hold-missing and alarm: a hold that is not in force is a fail-open the configuration can fix, and the build is where an administrator sees it. The check runs in `system.extraSystemBuilderCmds`, so it is part of building the toplevel. It covers declared tools too, which today have no such check.

**3.7 The binary's output is the Nix↔Rust boundary (coordinator's conditions).** The classifier's output (the sorted unit-name list, `raw-network-tools.json`) is read by `jq` in the export derivation and by `planariad` through the merged export; `module-eval` checks the format with the consumer's own parser (`planariad --check-export` on the built export, plus the crate's own `--check` of its output). A **nonzero exit or unparsable output** from the classifier or the verifier **fails the build**; it is never read as an empty list of tools (rule 21). A raw unit file the classifier cannot read is a tool, per §3.2, not an error.

## 4. Tests (rule 23: a logic change; the new classifier is the logic)

- **Agreement and syntax (§3.4):** the semantic matrix in `module-eval` (using the built binary), and the parser's property tests, edge enumeration and mutants in `cargo test -p planarian-unitclass`, which CI's `rust` job runs on every push; the real-systemd oracle runs in a Nix check (`vm-runtime`-style, KVM not needed for `systemd-analyze cat-config`). The PR names where each runs.
- **The B-23 case itself:** a raw package unit never declared in `systemd.services` appears in the built `export.json`'s `networkTools`, has the OnFailure/After drop-in in the built unit tree, and `planariad --check-export` parses the merged file (the consumer's own parser, the check B-23's row asks for).
- **Fail closed:** an unparsable raw unit file is a tool; a masked one is not.
- **The hold stays in force (§3.6):** a raw tool with a later drop-in carrying an empty `OnFailure=` fails the system build; the same for an empty `After=` on a unit not in `unordered.cycle`; a tool with an `overrides.conf` that does so (a declared unit) fails it too; a clean tree passes. Each fails with `verify-hold` disabled.
- **The boundary (§3.7):** the classifier exiting nonzero, or printing unparsable output, fails the build (the test replaces the binary with one that does each and shows the build fails, not an empty export).
- **Drop-in order:** a raw unit with its own drop-in resetting `CapabilityBoundingSet=` is read with systemd's semantics.
- **Not a tool:** a raw unit with `User=nobody`, a bounding set without the network capabilities and `NoNewPrivileges=yes` is not, and gets no drop-in.

Each test fails with the corresponding piece removed (checked and recorded in the PR). The PR carries a regression-ledger row only if it fixes a bug; B-23 is a documented gap, so it carries none, and says so.

## 5. Docs and gates

- B-23's row: closed, with the §6 limits that remain.
- `docs/deviations.md`: the classification now reads unit files at build time; evaluation never does.
- Catalog gate: this changes what the hold covers and the export's contents, so it needs a `vm.yml catalog: true` run (nix/module.nix and posture wiring are touched, which also invalidates earlier passes).
- `gym -- verification` and `gym -- site` must resolve after the docs change.

## 6. Limits stated up front

The row keeps these open, and every one of them **fails open** (an unclassified tool is never held and is not ordered after netwatch):

- Raw unit files from `environment.etc."systemd/system/…"` (some NixOS modules write them), which are not in `systemd.packages`.
- A raw unit that a **generator** creates at boot (systemd-sysv-generator, `systemd-fstab-generator`, a package's own generator): no file at build time.
- Names that exist only as `Alias=` or as a symlink to another unit.
- A raw unit that orders itself before `planarian-netwatch.service` in its own file: a cycle the evaluated check cannot see (systemd reports it at boot).
- A unit whose **drop-ins come from outside `systemd.packages`** and change its capabilities after the build (a runtime `systemctl edit` under `/etc/systemd/system`, which is mutable state).

Rated Medium as before: each needs a deliberately unusual packaging, and the workaround (a `systemd.services.<name> = { }` stub) classifies the unit.
- A raw unit shipped in the **initrd** is not in `networkToolsInitrd`.
- Units under `systemd.user` (user manager): not a gap, per B-23's own text (a user manager grants no capabilities).
- The script parses the unit-file syntax for the eight fields above only. A line that names one of them and that it cannot parse makes the unit a tool (§3.2); a line it does not understand that names none of the eight is ignored, as systemd ignores unknown keys.

## 7. Decisions (settled; revised after the reviewer's pass at bb74bf3)

1. The union export is a derivation (coordinator: OK).
2. `systemd.packages` only, as a partial close; the B-23 row keeps the rest open, rated, with the failure direction (coordinator: OK; §6 lists the five).
3. Rule-23 evidence for the parser is a generated-syntax property plus the semantic matrix (the reviewer's correction; the coordinator withdrew the fixture-only call). prop-auditor confirms the shape before code.
