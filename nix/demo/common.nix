# The demo machine, shared by the VM (`nix run .#vm`, nix/vm/machine.nix)
# and the live USB image (`nix build .#iso`, nix/live/iso.nix): NixOS with
# Planarian, the reference desktop, a few fixture services to break, and an
# owner flake at /etc/nixos that the machine can rebuild itself from.
#
# The same modules are the machine as built on the host and as Planarian
# evaluates it from /etc/nixos inside, so a change made inside rebuilds this
# very system plus the change. `inputs` (specialArgs) is the pair of flakes
# it came from: nixpkgs and planarian.
{ config, lib, pkgs, inputs, ... }:

let
  cfg = config.planarian.demo;
  # Rendered into /etc/nixos on first boot. Inputs are the same store paths
  # the VM was built from, so evaluating it inside needs no network.
  ownerFlake = pkgs.writeText "flake.nix" ''
    # This machine's own configuration. Planarian changes ./planarian/overrides.nix
    # (only through transactions); you can edit ./configuration.nix.
    {
      inputs.nixpkgs.url = "path:${inputs.nixpkgs.outPath}";
      inputs.planarian.url = "path:${inputs.planarian.outPath}";
      inputs.planarian.inputs.nixpkgs.follows = "nixpkgs";

      outputs = { nixpkgs, planarian, ... }: {
        nixosConfigurations.${config.networking.hostName} = nixpkgs.lib.nixosSystem {
          specialArgs.inputs = { inherit nixpkgs planarian; };
          modules = [
            planarian.nixosModules.${cfg.module}
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

    Planarian ${cfg.name}. You are logged in as "demo" (password: planarian;
    root's password is the same).

    For its first 10 minutes Planarian says "no baseline yet": it repairs
    services but asks before configuration changes. Once this boot's checks
    have passed for 10 minutes it becomes the known-good baseline. To skip the
    wait, confirm it yourself as the owner would:

      sudo planarian mark-good

    Things to try:

      planarian status                  what Planarian sees
      planarian-console                 the console (on the desktop it starts minimized in the dock)
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
    ../module.nix
    ../reference.nix
  ];

  options.planarian.demo.module = lib.mkOption {
    type = lib.types.str;
    description = "The flake's nixosModules entry for this platform (set by it), for the owner flake.";
  };
  options.planarian.demo.name = lib.mkOption {
    type = lib.types.str;
    description = "What to call this machine in the welcome text.";
  };
  options.planarian.demo.desktop = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Run the COSMIC desktop with the console; false gives a text console in your terminal.";
  };
  options.services.gym-extra.enable = lib.mkEnableOption "the gym-extra fixture service";

  config = {
    services.planarian.package = lib.mkDefault inputs.planarian.packages.${pkgs.stdenv.hostPlatform.system}.default;
    services.planarian.console.package = lib.mkDefault inputs.planarian.packages.${pkgs.stdenv.hostPlatform.system}.console;

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
    # No first-run wizard: open straight onto the desktop.
    environment.cosmic.excludePackages = lib.mkIf cfg.desktop [ pkgs.cosmic-initial-setup ];
    services.desktopManager.cosmic.showExcludedPkgsWarning = false;
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
    # On the desktop, a terminal with the same text opens at login (XDG
    # autostart, so it starts inside the session once the compositor is up).
    environment.etc."xdg/autostart/planarian-demo-welcome.desktop" = lib.mkIf cfg.desktop {
      text = ''
        [Desktop Entry]
        Type=Application
        Name=Planarian demo
        Exec=${pkgs.cosmic-term}/bin/cosmic-term -e ${pkgs.writeShellScript "planarian-demo-welcome" ''
          cat /etc/planarian-demo/WELCOME
          exec ${pkgs.bashInteractive}/bin/bash -l
        ''}
      '';
    };
    environment.etc."planarian-demo/WELCOME".text = welcome;
    # COSMIC's apps (the terminal among them) draw with wgpu, whose default
    # Vulkan path panics on software renderers without f16 shaders (VMs,
    # machines without a GPU driver). OpenGL works everywhere.
    environment.sessionVariables.WGPU_BACKEND = lib.mkIf cfg.desktop (lib.mkDefault "gl");

    # Fixtures (the gym catalog's): a web server with a health probe, a
    # service with a state file to corrupt, one systemd restarts itself, and
    # one off by default that a generation change can turn on.
    systemd.services.gym-web = {
      wantedBy = [ "multi-user.target" ];
      # Not root: it serves /etc (the probe reads /hostname), and must not
      # serve /etc/shadow.
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 127.0.0.1 --directory /etc";
      serviceConfig.DynamicUser = true;
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

    # The owner flake, written once; after that it is the machine's own.
    system.build.demoOwner = pkgs.linkFarm "planarian-demo-owner" {
      "flake.nix" = ownerFlake;
      "configuration.nix" = ownerConfiguration;
      "planarian/overrides.nix" = ../template/planarian/overrides.nix;
    };
    system.extraDependencies = [ inputs.nixpkgs.outPath inputs.planarian.outPath ];
    systemd.services.planarian-demo-owner = {
      description = "Write the demo machine's flake to /etc/nixos";
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
    # Without a network, builds fail in seconds rather than minutes.
    nix.settings.connect-timeout = 5;
    security.sudo.wheelNeedsPassword = false;
  };
}
