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

  # A second boot-menu entry that shows the boot as text.
  specialisation.verbose.configuration = {
    planarian.reference.verboseBoot = true;
    isoImage.configurationName = "verbose boot";
  };

  image.baseName = lib.mkForce "planarian-live";
  isoImage = {
    volumeID = "PLANARIAN_LIVE";
    makeEfiBootable = true;
    makeUsbBootable = true;
    # "planarian live: NixOS 26.05…", not "… Installer": it installs nothing.
    # (ASCII only: the boot loaders' fonts have no dashes.)
    prependToMenuLabel = "planarian live: ";
    appendToMenuLabel = "";
    # Dark boot menus: the kit's wordmark on charcoal instead of the NixOS theme.
    grubTheme = null;
    efiSplashImage = ../../assets/boot/efi-splash.png;
    splashImage = ../../assets/boot/bios-splash.png;
    # Faster to build than the default, a little larger.
    squashfsCompression = "zstd -Xcompression-level 6";
  };
}
