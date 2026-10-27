{
  description = "Planarian: a self-healing layer for declaratively configured computers";

  # Pinned through git rather than the GitHub API; flake.lock records the commit (docs/pins.md).
  inputs.nixpkgs.url = "git+https://github.com/NixOS/nixpkgs?ref=nixos-26.05&shallow=1";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      demoVm = system: desktop: demoOn "demo" system desktop;
      demoOn = module: system: desktop: nixpkgs.lib.nixosSystem {
        specialArgs.inputs = { inherit nixpkgs; planarian = self; };
        modules = [
          self.nixosModules.${module}
          ./nix/template/planarian/overrides.nix
          { nixpkgs.hostPlatform = system; planarian.demo.desktop = desktop; }
        ];
      };
    in
    {
      packages = forAll (pkgs: rec {
        planarian = pkgs.callPackage ./nix/package.nix { };
        console = pkgs.callPackage ./nix/console.nix { };
        # The live USB image: `nix build .#iso`, then write result/iso/*.iso to a flash drive.
        iso = self.nixosConfigurations."planarian-live-${pkgs.stdenv.hostPlatform.system}".config.system.build.isoImage;
        default = planarian;
      });

      nixosModules = {
        default = { pkgs, lib, ... }: {
          imports = [ ./nix/module.nix ];
          services.planarian.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          services.planarian.console.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.console;
        };
        reference = ./nix/reference.nix;
        # The demo machine as a VM and as a live USB image; need specialArgs.inputs.
        demo = ./nix/vm/machine.nix;
        live = ./nix/live/iso.nix;
      };

      # The demo VM: `nix run .#vm` (desktop) or `nix run .#vm-text`.
      nixosConfigurations = nixpkgs.lib.foldl' (acc: system: acc // {
        "planarian-vm-${system}" = demoVm system true;
        "planarian-vm-text-${system}" = demoVm system false;
        "planarian-live-${system}" = demoOn "live" system true;
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
          # The gym's VM harness: `nix run .#gym-vm -- [ID ...]` (needs KVM to be quick).
          gym-vm = {
            type = "app";
            program = "${pkgs.writeShellApplication {
              name = "planarian-gym-vm";
              runtimeInputs = [ pkgs.jq pkgs.python3 ];
              text = builtins.readFile ./nix/gym/run-vm.sh;
            }}/bin/planarian-gym-vm";
            meta.description = "Run the fault catalog on NixOS VMs";
          };
        });

      # One NixOS test per VM-capable catalog entry: legacyPackages.<system>.gym-vm.<id>.
      legacyPackages = forAll (pkgs: {
        gym-vm =
          let
            entries = (builtins.fromTOML (builtins.readFile ./crates/gym/catalog/phase-a.toml)).fault;
            ids = map (e: e.id) (builtins.filter (e: builtins.elem "vm" (e.harness or [ ])) entries);
          in
          nixpkgs.lib.genAttrs ids (id: import ./nix/tests/gym-vm.nix { inherit pkgs self id; });
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
