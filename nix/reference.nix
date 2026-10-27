# The reference configuration (§6): COSMIC with its greeter, PipeWire,
# NetworkManager, and Planarian's change catalog wired to options it can
# safely change. Import it alongside services.planarian.
{ config, lib, pkgs, ... }:

let
  cfg = config.planarian.reference;
in
{
  options.planarian.reference = {
    fontScale = lib.mkOption {
      type = lib.types.str;
      default = "1";
      description = "Text scale for GTK and Qt applications (changed by `ask \"make text bigger\"`).";
    };
    wifiNetwork = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "The preferred NetworkManager connection, brought up at boot.";
    };
  };

  config = {
    services.desktopManager.cosmic.enable = lib.mkDefault true;
    services.displayManager.cosmic-greeter.enable = lib.mkDefault true;
    services.pipewire = {
      enable = lib.mkDefault true;
      pulse.enable = lib.mkDefault true;
    };
    networking.networkmanager.enable = lib.mkDefault true;

    environment.sessionVariables = {
      GDK_DPI_SCALE = cfg.fontScale;
      QT_SCALE_FACTOR_ROUNDING_POLICY = "PassThrough";
    };

    systemd.services.planarian-wifi-preference = lib.mkIf (cfg.wifiNetwork != null) {
      description = "Bring up the preferred Wi-Fi network";
      after = [ "NetworkManager.service" ];
      wants = [ "NetworkManager.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig.Type = "oneshot";
      script = "${config.networking.networkmanager.package}/bin/nmcli connection up id ${lib.escapeShellArg cfg.wifiNetwork} || true";
    };

    # The console autostarts on the reference desktop (§16a).
    services.planarian.console.enable = lib.mkDefault true;

    services.planarian.catalog = {
      services = {
        sshd = "services.openssh.enable";
        printing = "services.printing.enable";
        avahi = "services.avahi.enable";
        bluetooth = "hardware.bluetooth.enable";
      };
      fontScaleOption = "planarian.reference.fontScale";
      keyboardLayoutOptions = [ "services.xserver.xkb.layout" ];
      keyboardLayouts = lib.mkDefault [ "us" "gb" "de" "fr" "es" ];
      wifiOption = "planarian.reference.wifiNetwork";
    };
  };
}
