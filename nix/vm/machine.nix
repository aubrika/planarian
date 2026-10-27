# The demo VM (`nix run .#vm`): NixOS with Planarian, the reference desktop,
# a few fixture services to break, and an owner flake at /etc/nixos that the
# VM can rebuild itself from.
#
# The same module is the VM as built on the host and the VM as Planarian
# evaluates it from /etc/nixos inside, so a change made in the VM rebuilds
# this very system plus the change. `inputs` (specialArgs) is the pair of
# flakes it came from: nixpkgs and planarian.
{ config, lib, pkgs, modulesPath, inputs, ... }:

let
  cfg = config.planarian.demo;
  # Rendered into /etc/nixos on first boot. Inputs are the same store paths
  # the VM was built from, so evaluating it inside needs no network.
  ownerFlake = pkgs.writeText "flake.nix" ''
    # This VM's own configuration. Planarian changes ./planarian/overrides.nix
    # (only through transactions); you can edit ./configuration.nix.
    {
      inputs.nixpkgs.url = "path:${inputs.nixpkgs.outPath}";
      inputs.planarian.url = "path:${inputs.planarian.outPath}";
      inputs.planarian.inputs.nixpkgs.follows = "nixpkgs";

      outputs = { nixpkgs, planarian, ... }: {
        nixosConfigurations.${config.networking.hostName} = nixpkgs.lib.nixosSystem {
          specialArgs.inputs = { inherit nixpkgs planarian; };
          modules = [
            planarian.nixosModules.demo
            ./configuration.nix
            ./planarian/overrides.nix
            # As built on the host (a path: input carries no git revision).
            { system.nixos.revision = nixpkgs.lib.mkForce ${builtins.toJSON config.system.nixos.revision};
              system.nixos.versionSuffix = nixpkgs.lib.mkForce ${builtins.toJSON config.system.nixos.versionSuffix}; }
          ];
        };
      };
    }
  '';
  ownerConfiguration = pkgs.writeText "configuration.nix" ''
    # Yours to edit. Planarian never changes this file.
    { ... }:
    {
      nixpkgs.hostPlatform = ${builtins.toJSON pkgs.stdenv.hostPlatform.system};
      planarian.demo.desktop = ${lib.boolToString cfg.desktop};
    }
  '';
  welcome = ''

    Planarian demo VM. You are logged in as "demo" (password: planarian;
    root's password is the same).

    For its first 10 minutes Planarian says "no baseline yet": it repairs
    services but asks before configuration changes. Once this boot's checks
    have passed for 10 minutes it becomes the known-good baseline. To skip the
    wait, confirm it yourself as the owner would:

      sudo planarian mark-good

    Things to try:

      planarian status                  what Planarian sees
      planarian-console                 the console window (desktop only)
      ask "restart the web server"      the intent front-end
      ask "make text bigger"            a generation change: built, tested, committed
      planarian apply service-enable service=gym-extra enabled=true
                                        another one: turns on a service in the config
      sudo planarian approve <hash>     approve something that asked first
      planarian log -n 20               what it did and why

    Faults to inject (then watch `planarian status`):
      demo-fault kill-web               SIGKILL gym-web: repaired by restart
      demo-fault corrupt-state          gym-state cannot start: tried, then handed to you
      demo-fault fix-state              undo the corruption
      demo-fault crash-loop             gym-restartful: systemd restarts it, Planarian stays out

    /etc/nixos is this machine's flake; changes Planarian makes land in
    /etc/nixos/planarian/overrides.nix.
  '';
in
{
  imports = [
    (modulesPath + "/virtualisation/qemu-vm.nix")
    ../module.nix
    ../reference.nix
  ];

  options.planarian.demo.desktop = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Run the COSMIC desktop with the console; false gives a text console in your terminal.";
  };
  options.services.gym-extra.enable = lib.mkEnableOption "the gym-extra fixture service";

  config = {
    services.planarian.package = lib.mkDefault inputs.planarian.packages.${pkgs.stdenv.hostPlatform.system}.default;
    services.planarian.console.package = lib.mkDefault inputs.planarian.packages.${pkgs.stdenv.hostPlatform.system}.console;

    networking.hostName = lib.mkDefault "planarian-vm";
    system.stateVersion = "26.05";

    services.planarian = {
      enable = true;
      owner = "/etc/nixos";
      catalog.services.gym-extra = "services.gym-extra.enable";
      units.gym-web = {
        synonyms = [ "web server" ];
        probes = [
          { id = "gym-web-http"; type = "http"; url = "http://127.0.0.1:8080/hostname"; establishes = "gym-web serves HTTP"; }
        ];
      };
      units.gym-state = { };
      units.gym-restartful = { };
    };

    # Desktop or not.
    services.desktopManager.cosmic.enable = cfg.desktop;
    services.displayManager.cosmic-greeter.enable = cfg.desktop;
    services.displayManager.autoLogin = lib.mkIf cfg.desktop { enable = true; user = "demo"; };
    services.getty.autologinUser = lib.mkIf (!cfg.desktop) "demo";
    services.pipewire.enable = lib.mkIf (!cfg.desktop) false;
    services.planarian.console.enable = cfg.desktop;

    users.users.demo = {
      isNormalUser = true;
      # The owner: planarian-admin may approve, restart system services, resolve.
      extraGroups = [ "wheel" "networkmanager" "planarian-admin" ];
      initialPassword = "planarian";
    };
    users.users.root.initialPassword = "planarian";
    users.motd = welcome;
    environment.etc."planarian-demo/WELCOME".text = welcome;

    # Fixtures (the gym catalog's): a web server with a health probe, a
    # service with a state file to corrupt, one systemd restarts itself, and
    # one off by default that a generation change can turn on.
    systemd.services.gym-web = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 127.0.0.1 --directory /etc";
    };
    systemd.services.gym-state = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.StateDirectory = "gym-state";
      script = ''
        if grep -q corrupt /var/lib/gym-state/state.json 2>/dev/null; then
          echo "state file is corrupt" >&2
          exit 1
        fi
        exec ${pkgs.coreutils}/bin/sleep infinity
      '';
    };
    systemd.services.gym-restartful = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = { ExecStart = "${pkgs.coreutils}/bin/sleep infinity"; Restart = "always"; RestartSec = "2s"; };
    };
    systemd.services.gym-extra = lib.mkIf config.services.gym-extra.enable {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };

    environment.systemPackages = [
      pkgs.curl
      (pkgs.writeShellScriptBin "demo-fault" ''
        set -e
        case "''${1:-}" in
          kill-web) sudo systemctl kill --signal=SIGKILL gym-web.service ;;
          corrupt-state) echo corrupt | sudo tee /var/lib/gym-state/state.json >/dev/null
                         sudo systemctl kill --signal=SIGTERM gym-state.service ;;
          fix-state) sudo rm -f /var/lib/gym-state/state.json ;;
          crash-loop) sudo systemctl kill --signal=SIGKILL gym-restartful.service ;;
          *) echo "usage: demo-fault kill-web|corrupt-state|fix-state|crash-loop" >&2; exit 2 ;;
        esac
      '')
    ];

    # The owner flake, written once; after that it is the VM's own.
    system.build.demoOwner = pkgs.linkFarm "planarian-demo-owner" {
      "flake.nix" = ownerFlake;
      "configuration.nix" = ownerConfiguration;
      "planarian/overrides.nix" = ../template/planarian/overrides.nix;
    };
    system.extraDependencies = [ inputs.nixpkgs.outPath inputs.planarian.outPath ];
    systemd.services.planarian-demo-owner = {
      description = "Write the demo VM's flake to /etc/nixos";
      wantedBy = [ "multi-user.target" ];
      before = [ "planariad.service" ];
      after = [ "nix-daemon.socket" ];
      wants = [ "nix-daemon.socket" ];
      unitConfig.ConditionPathExists = "!/etc/nixos/flake.nix";
      serviceConfig.Type = "oneshot";
      path = [ config.nix.package pkgs.git ];
      script = ''
        mkdir -p /etc/nixos/planarian
        install -m644 ${ownerFlake} /etc/nixos/flake.nix
        install -m644 ${ownerConfiguration} /etc/nixos/configuration.nix
        [ -e /etc/nixos/planarian/overrides.nix ] || install -m644 ${../template/planarian/overrides.nix} /etc/nixos/planarian/overrides.nix
        cd /etc/nixos && nix --extra-experimental-features "nix-command flakes" flake lock || true
      '';
    };
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    # Without the host's network, builds fail in seconds rather than minutes.
    nix.settings.connect-timeout = 5;
    security.sudo.wheelNeedsPassword = false;

    virtualisation = {
      memorySize = lib.mkDefault (if cfg.desktop then 4096 else 2048);
      cores = lib.mkDefault 4;
      # Room for the free-space probes and for generations built inside.
      diskSize = lib.mkDefault 20480;
      graphics = cfg.desktop;
      # Generations built inside survive a restart of the VM (with the disk image).
      writableStoreUseTmpfs = false;
      resolution = { x = 1280; y = 800; };
    };
  };
}
