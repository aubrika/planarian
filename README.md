# Planarian

A self-healing layer for NixOS. It keeps three things separate: what your
system is meant to be (from your configuration), what it observes, and whether
what it observes is healthy. When they diverge it opens an incident and repairs
it, deterministically, through one executor that runs every change as a
journaled, revertible transaction. If Planarian itself is killed mid-change, a
separate watchdog finishes or reverts the change.

- Specification: [`docs/SPEC.md`](docs/SPEC.md) (v4.3)
- What differs from the spec, and why: [`docs/deviations.md`](docs/deviations.md)
- Fault catalog: [`crates/gym/catalog/phase-a.toml`](crates/gym/catalog/phase-a.toml)

**Status: Phase A, ready for initial user testing on NixOS 26.05.** No language
model is involved. The `policy` proofs verify; the `txn` proofs and the
visual console are not done yet (see `docs/AGENTS.md`).

## Trying it

Planarian needs a flake-based NixOS configuration. It never edits your own
files. It changes only `planarian/overrides.nix`, which your flake imports.

1. Add the input and modules to your flake (or start from the template:
   `nix flake init -t github:aubrika/planarian`):

   ```nix
   inputs.planarian.url = "github:aubrika/planarian";
   inputs.planarian.inputs.nixpkgs.follows = "nixpkgs";
   # in nixosSystem { modules = [ … ]; }:
   ./planarian/overrides.nix
   planarian.nixosModules.default
   planarian.nixosModules.reference   # optional: COSMIC, PipeWire, NetworkManager, catalog wiring
   { services.planarian.enable = true; services.planarian.owner = "/etc/nixos"; }
   ```

2. Copy `nix/template/planarian/overrides.nix` into your configuration as
   `planarian/overrides.nix`, exactly as it is, and `git add` it (flakes only
   see tracked files).
3. `nixos-rebuild switch --flake /etc/nixos#<hostname>`. The attribute must
   match `networking.hostName`, or set `services.planarian.flakeAttr`.
4. `planarian status`.

For the first 10 minutes Planarian says "no baseline yet" and only takes
Runtime actions (restarts, stops). When the canonical health checks pass at
that checkpoint, the generation becomes the known-good baseline.

## What to try

| Try | What should happen |
| --- | --- |
| `sudo systemctl kill -s KILL sshd` | Within about 15 s: an incident, a restart, and `planarian log` shows it. |
| `ask "stop <service> until I say"` | It stops and stays stopped; Planarian won't "repair" it. `ask "start <service> again"` undoes it. |
| `planarian stop <service>` | The same, until the next boot. |
| `ask "make text bigger"` (with the reference module) | A configuration change: built, activated, health-checked, then committed. `planarian log` shows each step. |
| `planarian apply listen-address service=… addr=…` with an address that can't work | Built, activated, checks fail, reverted automatically. |
| `planarian apply service-enable service=sshd enabled=false` | Security-sensitive, so it asks: `sudo planarian approve <hash>`, at a terminal. |
| As a normal user: `planarian suppress sshd` | Refused: `Unauthorized`. |

Other commands: `planarian incidents`, `planarian log -n 50`, `planarian undo`,
`planarian gc`, `planarian diagnose <unit>`, `planarian cancel <txn>`,
`planarian mark-good`, `planarian resolve <txn> --as-committed|--as-reverted|--manual-repaired`.

### Watching your own services

```nix
services.planarian.units.my-app.probes = [
  { id = "my-app-http"; type = "http"; url = "http://127.0.0.1:8080/health"; establishes = "my-app answers its health check"; }
];
```

Dependencies come from the systemd units themselves: `Requires=`, `BindsTo=`
and `Requisite=` become typed `Requires` edges, and `Wants=` and `After=`
become `Wants` and ordering edges that are never blamed for a failure. Add
`edges`, `sensitivity`, `restartDisruption` and `synonyms` as needed; see
`nix/module.nix`.

### If something goes wrong

- `planarian status` shows incidents, pending approvals, any recovery failure
  (which stops autonomous repair until `planarian resolve`), and what the
  daemon found after its last restart.
- Turn it off with `services.planarian.enable = false;` and rebuild. To keep it
  watching without acting, set `services.planarian.maxTier = "Observe";`, and
  everything asks first.
- The daemon logs to the journal: `journalctl -u planariad -u planarian-recovery`.
  The executor log is `/var/lib/planarian/log/executor.jsonl`.

## Development

```
cargo test                                   # every crate
cargo run -p planarian-gym -- run            # the fault catalog, fake harness
crates/gym/demo.sh --harness fake            # the GA demonstration
nix build .#checks.x86_64-linux.package      # package + tests in the Nix sandbox
nix build .#checks.x86_64-linux.module-eval  # a full NixOS system evaluated with the module
nix build .#checks.x86_64-linux.vm-runtime   # NixOS VM test on real systemd (KVM recommended)
```

License: [MPL-2.0](LICENSE).
