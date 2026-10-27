# `planarian-install` (planarian-install.sh), for the live image: erases a disk and
# installs NixOS with Planarian and the reference desktop. The installed
# configuration is an owner flake at /etc/nixos pinned to the nixpkgs and
# planarian this image was built from; both sources are in this image's
# store and in the installed system's closure, so neither is fetched.
# `inputs` (specialArgs) is that pair of flakes.
{ config, lib, pkgs, inputs, ... }:

let
  self = inputs.planarian;
  ourLock = builtins.fromJSON (builtins.readFile ../../flake.lock);
  nixpkgsNode = ourLock.nodes.${ourLock.nodes.${ourLock.root}.inputs.nixpkgs};
  # From a clean checkout, the GitHub repository at this commit; from a
  # dirty tree (development), the source in the store.
  clean = self ? rev;
  planarianOriginal =
    if clean then { type = "github"; owner = "aubrika"; repo = "planarian"; }
    else { type = "path"; path = self.outPath; };
  planarianUrl =
    if clean then "github:aubrika/planarian" else "path:${self.outPath}";
  lock = {
    version = 7;
    root = "root";
    nodes = {
      root.inputs = { nixpkgs = "nixpkgs"; planarian = "planarian"; };
      nixpkgs = nixpkgsNode;
      planarian = {
        inputs.nixpkgs = [ "nixpkgs" ];
        locked = planarianOriginal // {
          narHash = self.narHash;
          lastModified = self.lastModified;
        } // lib.optionalAttrs clean { inherit (self) rev; };
        original = planarianOriginal;
      };
    };
  };
  nixpkgsUrl =
    let o = nixpkgsNode.original; in
    assert o.type == "git";
    "git+${o.url}?ref=${o.ref}${lib.optionalString (o.shallow or false) "&shallow=1"}";
  seed = pkgs.linkFarm "planarian-install-seed" {
    "flake.lock" = pkgs.writeText "flake.lock" (builtins.toJSON lock);
    "overrides.nix" = ../template/planarian/overrides.nix;
  };
  planarian-install = pkgs.writeShellApplication {
    name = "planarian-install";
    runtimeInputs = with pkgs; [
      coreutils util-linux parted dosfstools e2fsprogs btrfs-progs gawk gnugrep
      git mkpasswd systemd sudo config.system.build.nixos-install
      config.system.build.nixos-generate-config config.nix.package
    ];
    text = ''
      export PLANARIAN_SEED=${seed}
      export PLANARIAN_URL=${lib.escapeShellArg planarianUrl}
      export NIXPKGS_URL=${lib.escapeShellArg nixpkgsUrl}
      ${builtins.readFile ./planarian-install.sh}
    '';
  };
in
{
  environment.systemPackages = [ planarian-install ];
  # The sources the installed flake is locked to. (Planarian's packages are
  # in the image already, so installing compiles nothing.)
  system.extraDependencies = [ inputs.nixpkgs.outPath self.outPath ];
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  system.build.planarianInstall = planarian-install;
}
