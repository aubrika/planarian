# Evaluate a NixOS configuration with Planarian and check the manifest it
# exports: canonical units are present, systemd dependencies became typed
# edges, and the self-protection flags are set. (No VM needed.)
{ pkgs, self, nixpkgs }:

let
  sys = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      self.nixosModules.default
      self.nixosModules.reference
      ../template/planarian/overrides.nix
      # §11 sensitivity completeness (B-5): the named security units,
      # declared with no sensitivity given.
      ({ lib, ... }: { services.planarian.units = lib.genAttrs securityNamed (_: { }); })
      ({ lib, ... }: {
        networking.hostName = "planarian-eval";
        system.stateVersion = "26.05";
        boot.loader.grub.enable = false;
        fileSystems."/" = { device = "/dev/vda"; fsType = "ext4"; };
        fileSystems."/boot" = { device = "/dev/vda1"; fsType = "vfat"; };
        services.openssh.enable = true;
        services.planarian.enable = true;
        systemd.services.gym-db = { wantedBy = [ "multi-user.target" ]; script = "sleep infinity"; };
        systemd.services.gym-app = {
          wantedBy = [ "multi-user.target" ];
          requires = [ "gym-db.service" ];
          after = [ "gym-db.service" ];
          script = "sleep infinity";
          serviceConfig = { Restart = "on-failure"; RestartSec = "5s"; };
          startLimitBurst = 3;
        };
        services.planarian.units.gym-db = { };
        services.planarian.units.gym-app.probes = [
          { id = "gym-app-tcp"; type = "tcp"; addr = "127.0.0.1:8081"; establishes = "gym-app accepts connections"; }
        ];
      })
    ];
  };
  # The named list (§11): firewall, openssh, fail2ban, usbguard, AppArmor,
  # audit and VPN units.
  securityNamed = [ "firewall" "nftables" "sshd" "fail2ban" "usbguard" "apparmor" "auditd" "wg-quick-wg0" "wireguard-wg0" "openvpn-office" "tailscaled" "strongswan" ];
  securityTrees = [ "security" "networking.firewall" "networking.nftables" "networking.wireguard" "networking.wg-quick" "services.openssh" "services.fail2ban" "services.usbguard" "services.openvpn" "services.tailscale" "services.strongswan" ];
  cfg = sys.config;
  export = cfg.services.planarian.export;
  unit = id: builtins.head (builtins.filter (u: u.id == id) export.units);
  app = unit "service:gym-app";
  check = cond: msg: if cond then true else throw "planarian module eval: ${msg}";
  checks = [
    (check (builtins.any (u: u.id == "service:sshd") export.units) "sshd is a canonical unit")
    (check (builtins.any (u: u.id == "device:fs-root") export.units) "fs-root is present")
    (check (builtins.any (u: u.id == "device:fs-boot") export.units) "fs-boot is present")
    (check (builtins.any (u: u.id == "target:graphical-session") export.units) "graphical-session for the desktop")
    (check (builtins.any (u: u.id == "service@0:pipewire") export.userUnits) "pipewire is per-user")
    (check (builtins.elem { from = "service:gym-app"; to = "service:gym-db"; kind = "Requires"; origin = "SystemdRequires"; } app.edges) "Requires= became a Requires edge")
    (check (builtins.elem { from = "service:gym-app"; to = "service:gym-db"; kind = "Ordering"; origin = "SystemdAfter"; } app.edges) "After= became an Ordering edge")
    (check (app.systemd_restart.restart_sec == 5000) "RestartSec parsed")
    (check (app.systemd_restart.start_limit_burst == 3) "StartLimitBurst (a string in NixOS) is a number")
    (check ((unit "service:sshd").sensitivity == [ "Security" ]) "sshd is Security")
    (check (builtins.all (n: (unit "service:${n}").sensitivity == [ "Security" ]) securityNamed) "every named security unit is Security without a tag (B-5)")
    (check (builtins.all (t: (cfg.services.planarian.optionSensitivity.${t} or [ ]) == [ "Security" ]) securityTrees) "every named option tree is Security (B-5)")
    (check (!cfg.systemd.services.planariad.restartIfChanged) "planariad survives activation")
    (check (!cfg.systemd.services.planarian-recovery.stopIfChanged) "the watchdog survives activation")
    (check (export.coreUnits."planariad.service" != "") "core unit hashes exported")
  ];
in
assert builtins.all (x: x) checks;
pkgs.writeText "planarian-module-eval.json" (builtins.toJSON export)
