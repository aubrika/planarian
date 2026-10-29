<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="assets/identity/wordmarks/planarian-horizontal-light.svg">
    <img alt="planarian" src="assets/identity/wordmarks/planarian-horizontal-dark.svg" width="360">
  </picture>
</p>

# Planarian

A self-healing layer for NixOS. It keeps three things separate: what your
system is meant to be (from your configuration), what it observes, and whether
what it observes is healthy. When they diverge it opens an incident and repairs
it, deterministically, through one executor that runs every change as a
journaled, revertible transaction. If Planarian itself is killed mid-change, a
separate watchdog finishes or reverts the change.

- Specification: [`docs/SPEC.md`](docs/SPEC.md) (v4.4)
- What differs from the spec, and why: [`docs/deviations.md`](docs/deviations.md)
- Fault catalog: [`crates/gym/catalog/phase-a.toml`](crates/gym/catalog/phase-a.toml)

**Status: under construction.** This is experimental software that restarts
services and rebuilds and activates your NixOS configuration on its own. Try
it in a VM, or on a machine you can afford to break. Phase A (the
deterministic core, NixOS 26.05) is close to its exit gate
([`docs/ga-status.md`](docs/ga-status.md)); later phases are not started. No
language model is involved. `policy::decide`, the journal state machine and
the ledger are verified with Verus (`docs/verification.md`).

A prototype NixOS image with Planarian (a demo VM, a live USB stick and an
installer) is described in [`docs/planarian-os.md`](docs/planarian-os.md).
The VM is the safest way to look at it:

```sh
nix run github:aubrika/planarian#vm
```

## Trying it on your machine

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
   # optional, and not for an existing desktop: it switches the machine to
   # COSMIC, PipeWire, NetworkManager and a quiet boot (PlanarianOS's setup)
   # planarian.nixosModules.reference
   { services.planarian.enable = true; services.planarian.owner = "/etc/nixos"; }
   # and make yourself an administrator (approve, restart system services, resolve):
   { users.users.<you>.extraGroups = [ "planarian-admin" ]; }
   ```

2. Copy `nix/template/planarian/overrides.nix` into your configuration as
   `planarian/overrides.nix`, exactly as it is, and `git add` it (flakes only
   see tracked files).
3. `nixos-rebuild switch --flake /etc/nixos#<hostname>`. The attribute must
   match `networking.hostName`, or set `services.planarian.flakeAttr`.
4. `planarian status`.

Start with it watching only, so it asks before every action:

```nix
services.planarian.maxTier = "Observe";
```

Raise it to `"Runtime"` (restarts and stops on its own) or `"Tested"` (also
builds, activates and reverts configuration changes on its own, the default)
once you trust what it does. For the first 10 minutes Planarian says "no
baseline yet" and takes at most Runtime actions. When the canonical health
checks pass at that checkpoint, the generation becomes the known-good
baseline.

## What to try

`planarian status` shows what it sees: units, health, incidents, pending
approvals. To watch a repair, pick a service whose loss you don't mind (not
your SSH server or display manager on a machine you reach remotely) and
simulate a crash with `sudo systemctl kill -s SEGV <service>`: within about
15 s there should be an incident and a restart, and `planarian log` explains
it. A plain `kill` or `systemctl stop` is different: Planarian takes that as
something you meant, leaves the service stopped until the next boot, and says
how to undo it (`planarian release <service>`). `ask "stop
<service> until I say"` stops it and keeps it stopped; `ask "start <service>
again"` undoes that. The demo VM has fixture services and fault injection
for the rest (`docs/planarian-os.md`).

The console (`services.planarian.console.enable = true;`, on with the
reference module) shows the dependency graph with what is desired,
observed and healthy for each unit, the transaction timeline, the
generations and the incidents. It starts minimized unless something needs
attention. It is dark, like the rest of the identity (`assets/identity`).
While Planarian builds or applies a change, the mark in its window moves
(the kit's "working" motion); set `PLANARIAN_REDUCED_MOTION=1` to keep it still.

The status indicator (`services.planarian.tray.enable`, on with the console)
puts the planarian mark in the panel: no dot when all is well, blue-grey
while a change is being built or applied, amber when something needs a look
(an incident being repaired, an approval, a reverted change), red when
something needs a person (a repair that keeps failing, the recovery
interlock, or the daemon is unreachable). Its tooltip says what; clicking it
opens the console.

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

Services get a startup grace: a health check that fails in a unit's first
90 seconds after it comes up is not yet a fault (crashes are). Set
`services.planarian.startupGrace`, or `units.<name>.startupGrace` per unit,
for slow machines or slow-starting services.

### If something goes wrong

- `planarian status` shows incidents, pending approvals, any recovery failure
  (which stops autonomous repair until `planarian resolve`), and what the
  daemon found after its last restart.
- Turn it off with `services.planarian.enable = false;` and rebuild. To keep it
  watching without acting, set `services.planarian.maxTier = "Observe";`, and
  everything asks first.
- The daemon logs to the journal: `journalctl -u planariad -u planarian-recovery`.
  The executor log is `/var/lib/planarian/log/executor.jsonl`.
- A signed health report is kept at `/var/lib/planarian/health-report.json`
  (signature in `.sig`, public key in `health.pub`). It holds only unit
  statuses and open incident kinds; it is not sent anywhere.

## Development

```
cargo test                                   # every crate
cargo run -p planarian-gym -- run            # the fault catalog, fake harness
nix run .#gym-vm -- svc-killed-defer-to-systemd   # entries on real NixOS VMs (no ids: every VM entry; wants KVM)
crates/gym/demo.sh --harness fake            # the GA demonstration
cargo run -p planarian-gym -- serve --socket /tmp/p.sock   # a fake machine on a socket:
PLANARIAN_SOCKET=/tmp/p.sock cargo run -p planarian-console # try the console (or the CLI) against it
nix build .#checks.x86_64-linux.package      # package + tests in the Nix sandbox
nix build .#checks.x86_64-linux.module-eval  # a full NixOS system evaluated with the module
nix build .#checks.x86_64-linux.vm-runtime   # NixOS VM test on real systemd (KVM recommended)
nix build .#checks.x86_64-linux.verus        # the Verus proofs (docs/verification.md)
```

License: [MPL-2.0](LICENSE).
