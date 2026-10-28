# The live USB image (`nix build .#iso`): the demo machine (nix/demo/common.nix)
# booting from a flash drive on real hardware. Everything lives in RAM: changes
# Planarian makes are real rebuilds, and all of it is gone at the next boot.
# It is also the installer: `planarian-install` (nix/installer) puts NixOS
# with Planarian and the reference desktop on a disk.
{ lib, pkgs, modulesPath, ... }:

{
  imports = [
    (modulesPath + "/installer/cd-dvd/iso-image.nix")
    (modulesPath + "/profiles/all-hardware.nix")
    ../demo/common.nix
    ../installer
  ];

  environment.etc."planarian-demo/WELCOME".text = lib.mkAfter ''
    To install on this computer's disk: sudo planarian-install
    (or "Install Planarian" in the applications).
  '';
  users.motd = lib.mkAfter ''
    To install on this computer's disk: sudo planarian-install
  '';
  environment.systemPackages = [
    (pkgs.makeDesktopItem {
      name = "planarian-install";
      desktopName = "Install Planarian";
      comment = "Install NixOS with Planarian on this computer";
      icon = "planarian";
      exec = "cosmic-term -e sudo planarian-install";
      categories = [ "System" ];
    })
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
    # "planarian live: NixOS 26.05…", not "… Installer": it boots into the
    # demo, and installing is a choice made from there.
    # (ASCII only: the boot loaders' fonts have no dashes.)
    prependToMenuLabel = "planarian live: ";
    appendToMenuLabel = "";
    # Dark boot menus: the kit's wordmark on charcoal instead of the NixOS theme.
    grubTheme = null;
    efiSplashImage = ../../assets/boot/efi-splash.png;
    # 800 x 600: NixOS's BIOS menu (isolinux) runs at that resolution and
    # draws the background unscaled from the top-left corner.
    splashImage = ../../assets/boot/bios-splash.png;
    # NixOS's layout with the kit's colours: its defaults are dark text,
    # chosen for the light NixOS background, and unreadable on charcoal.
    syslinuxTheme = ''
      MENU TITLE planarian live
      MENU RESOLUTION 800 600
      MENU CLEAR
      MENU ROWS 6
      MENU CMDLINEROW -4
      MENU TIMEOUTROW -3
      MENU TABMSGROW  -2
      MENU HELPMSGROW -1
      MENU HELPMSGENDROW -1
      MENU MARGIN 0

      #                                FG:AARRGGBB  BG:AARRGGBB   shadow
      MENU COLOR BORDER       30;44      #00000000    #00000000   none
      MENU COLOR SCREEN       37;40      #FFD0D3D6    #00000000   none
      MENU COLOR TABMSG       31;40      #FF8A9096    #00000000   none
      MENU COLOR TIMEOUT      1;37;40    #FFD0D3D6    #00000000   none
      MENU COLOR TIMEOUT_MSG  37;40      #FF8A9096    #00000000   none
      MENU COLOR CMDMARK      1;36;40    #FFFFFFFF    #00000000   none
      MENU COLOR CMDLINE      37;40      #FFD0D3D6    #00000000   none
      MENU COLOR TITLE        1;36;44    #00000000    #00000000   none
      MENU COLOR UNSEL        37;44      #FFD0D3D6    #00000000   none
      MENU COLOR SEL          7;37;40    #FF151719    #FFE8EAEC   none
      MENU COLOR HOTKEY       37;40      #FFFFFFFF    #00000000   none
      MENU COLOR HOTSEL       7;37;40    #FF151719    #FFE8EAEC   none
    '';
    # Faster to build than the default, a little larger.
    squashfsCompression = "zstd -Xcompression-level 6";
  };
}
