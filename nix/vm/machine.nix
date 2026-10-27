# The demo VM (`nix run .#vm`): the demo machine (nix/demo/common.nix) as a
# QEMU VM whose disk image keeps its state between runs.
{ config, lib, modulesPath, ... }:

{
  imports = [
    (modulesPath + "/virtualisation/qemu-vm.nix")
    ../demo/common.nix
  ];

  planarian.demo = { module = "demo"; name = "demo VM"; };
  networking.hostName = lib.mkDefault "planarian-vm";
  # The VM may run without KVM, where everything starts slowly.
  services.planarian.startupGrace = lib.mkDefault 180;

  virtualisation = {
    memorySize = lib.mkDefault (if config.planarian.demo.desktop then 6144 else 3072);
    cores = lib.mkDefault 4;
    # Room for the free-space probes and for generations built inside.
    diskSize = lib.mkDefault 20480;
    graphics = config.planarian.demo.desktop;
    # Generations built inside survive a restart of the VM (with the disk image).
    writableStoreUseTmpfs = false;
    resolution = { x = 1280; y = 800; };
  };
}
