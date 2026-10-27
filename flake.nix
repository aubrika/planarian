{
  description = "Planarian: a self-healing layer for declaratively configured computers";

  # Pinned through git rather than the GitHub API; flake.lock records the commit (docs/pins.md).
  inputs.nixpkgs.url = "git+https://github.com/NixOS/nixpkgs?ref=nixos-26.05&shallow=1";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      demoVm = system: desktop: nixpkgs.lib.nixosSystem {
        specialArgs.inputs = { inherit nixpkgs; planarian = self; };
        modules = [
          self.nixosModules.demo
          ./nix/template/planarian/overrides.nix
          { nixpkgs.hostPlatform = system; planarian.demo.desktop = desktop; }
        ];
      };
    in
    {
      packages = forAll (pkgs: rec {
        planarian = pkgs.callPackage ./nix/package.nix { };
        console = pkgs.callPackage ./nix/console.nix { };
        default = planarian;
      });

      nixosModules = {
        default = { pkgs, lib, ... }: {
          imports = [ ./nix/module.nix ];
          services.planarian.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          services.planarian.console.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.console;
        };
        reference = ./nix/reference.nix;
        # The demo VM's machine (nix/vm/machine.nix); needs specialArgs.inputs.
        demo = ./nix/vm/machine.nix;
      };

      # The demo VM: `nix run .#vm` (desktop) or `nix run .#vm-text`.
      nixosConfigurations = nixpkgs.lib.foldl' (acc: system: acc // {
        "planarian-vm-${system}" = demoVm system true;
        "planarian-vm-text-${system}" = demoVm system false;
      }) { } systems;

      apps = forAll (pkgs:
        let
          s = pkgs.stdenv.hostPlatform.system;
          app = name: {
            type = "app";
            program = "${self.nixosConfigurations.${name}.config.system.build.vm}/bin/run-planarian-vm-vm";
            meta.description = "A NixOS VM running Planarian";
          };
        in {
          vm = app "planarian-vm-${s}";
          vm-text = app "planarian-vm-text-${s}";
        });

      templates.default = {
        path = ./nix/template;
        description = "A NixOS flake wired for Planarian";
      };

      checks = forAll (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        module-eval = import ./nix/tests/eval.nix { inherit pkgs self nixpkgs; };
        vm-runtime = import ./nix/tests/vm.nix { inherit pkgs self; };
        vm-generations = import ./nix/tests/vm-generations.nix { inherit pkgs self; };
        # The demo VM (`nix run .#vm-text`) builds.
        demo-vm = self.nixosConfigurations."planarian-vm-text-${pkgs.stdenv.hostPlatform.system}".config.system.build.vm;
        # The dependency rule (SPEC §5, §17).
        boundaries = pkgs.runCommand "planarian-boundaries" { } ''
          ${pkgs.bash}/bin/bash ${./nix/tests/boundaries.sh} ${./.} > $out
        '';
      } // pkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
        # Verus publishes binaries for x86_64-linux only.
        verus = import ./nix/tests/verus.nix { inherit pkgs; };
      });
    };
}
