{
  description = "Planarian: a self-healing layer for declaratively configured computers";

  # Pinned through git rather than the GitHub API; flake.lock records the commit (docs/pins.md).
  inputs.nixpkgs.url = "git+https://github.com/NixOS/nixpkgs?ref=nixos-26.05&shallow=1";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: rec {
        planarian = pkgs.callPackage ./nix/package.nix { };
        default = planarian;
      });

      nixosModules = {
        default = { pkgs, lib, ... }: {
          imports = [ ./nix/module.nix ];
          services.planarian.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
        reference = ./nix/reference.nix;
      };

      templates.default = {
        path = ./nix/template;
        description = "A NixOS flake wired for Planarian";
      };

      checks = forAll (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        module-eval = import ./nix/tests/eval.nix { inherit pkgs self nixpkgs; };
        vm-runtime = import ./nix/tests/vm.nix { inherit pkgs self; };
      } // pkgs.lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
        # Verus publishes binaries for x86_64-linux only.
        verus = import ./nix/tests/verus.nix { inherit pkgs; };
      });
    };
}
