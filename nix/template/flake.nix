{
  description = "A NixOS configuration with Planarian";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    planarian.url = "github:aubrika/planarian";
    planarian.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = inputs@{ nixpkgs, planarian, ... }: {
    # Rename `laptop` to this machine's hostname (networking.hostName).
    nixosConfigurations.laptop = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        # Planarian changes only this file, and only through transactions.
        ./planarian/overrides.nix
        planarian.nixosModules.default
        # PlanarianOS's desktop: COSMIC, PipeWire, NetworkManager, a quiet
        # boot. Not for a machine that already has a desktop you want.
        # planarian.nixosModules.reference
        {
          services.planarian.enable = true;
          services.planarian.owner = "/etc/nixos";
          # Asks before every action. "Runtime" restarts and stops on its
          # own; "Tested" also changes the configuration on its own.
          services.planarian.maxTier = "Observe";
          # Each generation records the inputs it was built from, so a
          # service a dependency declares is reported with its lock change.
          services.planarian.flakeInputs = builtins.mapAttrs
            (_: i: { rev = i.rev or i.narHash or ""; path = toString i.outPath; })
            (removeAttrs inputs [ "self" ]);
          # Administrators approve changes, restart system services and resolve.
          # users.users.<you>.extraGroups = [ "planarian-admin" ];
        }
      ];
    };
  };
}
