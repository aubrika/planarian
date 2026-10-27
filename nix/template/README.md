# Planarian flake template

1. `nix flake init -t github:aubrika/planarian` in `/etc/nixos` (or merge the
   modules list into your existing flake).
2. Keep `planarian/overrides.nix` exactly as generated, and track it:
   `git add planarian/overrides.nix`. Flakes only see tracked files.
3. Set `networking.hostName` to match the `nixosConfigurations.<name>` attribute
   (or set `services.planarian.flakeAttr`).
4. `nixos-rebuild switch --flake /etc/nixos`, then `planarian status`.

For the first 10 minutes after the first boot with Planarian, it runs with
autonomy capped at Runtime and says "no baseline yet". Once the canonical
health checks pass at that checkpoint, the generation becomes known-good.
