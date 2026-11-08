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

1. Reads every `lib/systemd/system/*.service` and `etc/systemd/system/*.service` (and their `*.service.d/*.conf` from every input, in systemd's order: lexical by drop-in file name, later assignments win, an empty assignment resets a list setting), as systemd does.
2. For each unit, extracts the fields `isNetworkToolUnchecked` reads: `User`, `DynamicUser`, `CapabilityBoundingSet`, `AmbientCapabilities`, `NoNewPrivileges`, `DeviceAllow`, `BindPaths`, `BindReadOnlyPaths`, and applies **the same rule** (§3.4).
3. Writes `$out/lib/systemd/system/<unit>.service.d/50-planarian-hold.conf` for each network tool, with the same content `holdDropins` writes (`OnFailure=planarian-hold@%N.service`, plus `After=planarian-netwatch.service` when netwatch is on and the unit is not in `unordered.cycle`), and `$out/share/planarian/raw-network-tools.json`, the sorted list of unit names (a template's name keeps its `@`).

**3.2 Fail closed.** A unit file the script cannot parse (unknown section syntax, an unreadable file, a `.d` drop-in that fails to parse) is a network tool, as an unevaluable `systemd.services` entry is today. A masked unit (a symlink to `/dev/null`) is not. A unit also declared in `systemd.services` is classified by *both* rules and is a tool if either says so. Socket- and timer-activated tools are ordered through their service, as today.

**3.3 The export.** `/etc/planarian/export.json` is `builtins.toJSON cfg.export` today. A raw tool's name is only known after the build, so `networkTools` there must become the union of the evaluated list and `raw-network-tools.json`. The file becomes the output of a small derivation (`jq` over the evaluated JSON and the raw list), not text built at evaluation. The consumers, planariad and netwatch, already read the file, not the evaluated attribute. The daemon needs no change to *use* these names: the unmanaged-tool path (lane-daemon, #93: a network tool with no `services.planarian.units` entry is held and alarmed, never restarted) is exactly what a raw tool is.

What does not change: `holdUnits` and the evaluated `networkToolsUnordered` / `networkToolsInitrd` intersections stay evaluated lists, so a raw tool is not in them. That is correct for stage 2, because a raw tool gets its `After=` from the drop-in. It means a raw unit the systemd initrd ships is not in `networkToolsInitrd`; B-26 (the initrd watch) covers the initrd window, and §6 lists this as a stated limit.

**3.4 One rule, two implementations, held equal.** The rule exists in Nix (`isNetworkToolUnchecked`, over `serviceConfig` attributes) and now in the build script (over unit-file text). Two copies of one rule is a rule-20 hazard, so the design holds them equal by test instead of by hope: a `module-eval` fixture takes every combination of the rule's inputs (user root or not, `DynamicUser`, bounding set absent / with `CAP_NET_ADMIN` / without, ambient capabilities, `NoNewPrivileges`, `DeviceAllow=/dev/net/tun`, `BindPaths=` of `/dev/ppp`, netdev units), declares each both as a `systemd.services` entry and as a raw unit file in a test package, and asserts the two classifiers agree for all of them. That is exhaustive over the rule's inputs, which is stronger than a sampled property, and it fails if either copy drifts.

## 4. Tests (rule 23: a logic change; the new classifier is the logic)

- **Agreement (above):** the fixture matrix; each rule input disabled in turn in the script fails it.
- **The B-23 case itself:** a raw package unit never declared in `systemd.services` appears in the built `export.json`'s `networkTools`, has the OnFailure/After drop-in in the built unit tree, and `planariad --check-export` parses the merged file (the consumer's own parser, the check B-23's row asks for).
- **Fail closed:** an unparsable raw unit file is a tool; a masked one is not.
- **Drop-in order:** a raw unit with its own drop-in resetting `CapabilityBoundingSet=` is read with systemd's semantics.
- **Not a tool:** a raw unit with `User=nobody`, a bounding set without the network capabilities and `NoNewPrivileges=yes` is not, and gets no drop-in.

Each test fails with the corresponding piece removed (checked and recorded in the PR). The PR carries a regression-ledger row only if it fixes a bug; B-23 is a documented gap, so it carries none, and says so.

## 5. Docs and gates

- B-23's row: closed, with the §6 limits that remain.
- `docs/deviations.md`: the classification now reads unit files at build time; evaluation never does.
- Catalog gate: this changes what the hold covers and the export's contents, so it needs a `vm.yml catalog: true` run (nix/module.nix and posture wiring are touched, which also invalidates earlier passes).
- `gym -- verification` and `gym -- site` must resolve after the docs change.

## 6. Limits stated up front

- A raw unit that a **generator** creates at boot (systemd-sysv-generator, `systemd-fstab-generator`, a package's own generator) has no file at build time and is not classified. Same for `Alias=`-only names. The row keeps this as the remaining gap.
- A raw unit shipped in the **initrd** is not in `networkToolsInitrd`.
- Units under `systemd.user` (user manager): not a gap, per B-23's own text (a user manager grants no capabilities).
- The script parses the unit-file syntax for the nine fields above only. A line it does not understand inside `[Service]` that could matter (a typo of a capability setting) is read as unset, which is the fail-closed direction for this rule (unset bounding set and root user means a tool).

## 7. Decisions I need

1. **Is the union export (a derivation, not evaluated text) acceptable?** The alternative, import from derivation, is not. A third option, listing raw units by name in the configuration, is the workaround that already exists.
2. **Should `systemd.packages` itself be the only source?** Units from `environment.etc."systemd/system/*"` raw files, and from `systemd.generators`, are out of scope in this design.
3. **The exhaustive fixture as the rule-23 evidence instead of a proptest:** OK for the reviewer and prop-auditor?
