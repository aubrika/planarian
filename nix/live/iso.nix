# The live USB image (`nix build .#iso`): the demo machine (nix/demo/common.nix)
# booting from a flash drive on real hardware. Everything lives in RAM: changes
# Planarian makes are real rebuilds, and all of it is gone at the next boot.
{ lib, modulesPath, ... }:

{
  imports = [
    (modulesPath + "/installer/cd-dvd/iso-image.nix")
    (modulesPath + "/profiles/all-hardware.nix")
    ../demo/common.nix
  ];

  planarian.demo = { module = "live"; name = "live system"; };
  networking.hostName = lib.mkDefault "planarian-live";
  hardware.enableRedistributableFirmware = lib.mkDefault true;

  image.baseName = lib.mkForce "planarian-live";
  isoImage = {
    volumeID = "PLANARIAN_LIVE";
    makeEfiBootable = true;
    makeUsbBootable = true;
    prependToMenuLabel = "planarian live · ";
    # Faster to build than the default, a little larger.
    squashfsCompression = "zstd -Xcompression-level 6";
  };
}
