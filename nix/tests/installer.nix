# planarian-install on an empty disk, up to the point nixos-install takes
# over (which would need the network inside the test): partitions, the
# btrfs journal directory without copy-on-write, a tracked owner flake whose
# inputs resolve from the store, and a configuration that evaluates, with the
# same Planarian package as the image (so installing compiles nothing).
{ pkgs, self, nixpkgs }:

let
  live = self.nixosConfigurations."planarian-live-${pkgs.stdenv.hostPlatform.system}".config;
  # Only the path, not a dependency on its whole build closure.
  planarianDrv = builtins.unsafeDiscardStringContext live.services.planarian.package.drvPath;
in
pkgs.testers.runNixOSTest {
  name = "planarian-installer";
  node.specialArgs.inputs = { inherit nixpkgs; planarian = self; };
  nodes.machine = { ... }: {
    imports = [ ../installer ];
    virtualisation.emptyDiskImages = [ 4096 ];
    virtualisation.memorySize = 3072;
    nix.settings.substituters = pkgs.lib.mkForce [ ];
    environment.systemPackages = [ pkgs.git ];
  };
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed("echo 'correct horse' > /tmp/pw")
    machine.succeed(
      "planarian-install --disk /dev/vdb --fs btrfs --hostname testbox --user ana"
      " --password-file /tmp/pw --timezone Europe/Lisbon --yes --no-install >&2"
    )
    machine.succeed("findmnt /mnt/boot -o FSTYPE -n | grep vfat")
    machine.succeed("findmnt /mnt -o OPTIONS -n | grep subvol=/@")
    machine.succeed("lsattr -d /mnt/var/lib/planarian | grep -q '^[^ ]*C'")
    machine.succeed("git -C /mnt/etc/nixos ls-files | grep -x planarian/overrides.nix")
    machine.succeed("grep -q 'initialHashedPassword = \"\\$y\\$' /mnt/etc/nixos/configuration.nix")

    flake = "/mnt/etc/nixos#nixosConfigurations.testbox.config"
    nix = "nix --offline --extra-experimental-features 'nix-command flakes' eval --raw"
    got = machine.succeed(f"{nix} {flake}.services.planarian.package.drvPath")
    assert got == "${planarianDrv}", f"planarian would be rebuilt: {got}"
    machine.succeed(f"{nix} {flake}.system.build.toplevel.drvPath >&2")
    machine.succeed(f"{nix.replace('--raw', '--json')} {flake}.users.users.ana.extraGroups | grep planarian-admin")
  '';
}
