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
  # §15 (B-13): the same configuration with the test build as its package.
  testBuildSys = sys.extendModules {
    modules = [ { services.planarian.package = pkgs.callPackage ../package.nix { gymHooks = true; }; } ];
  };
  refused = builtins.filter (a: !a.assertion) testBuildSys.config.assertions;
  # §10 (S06): a manifest with a 0.5-confidence edge to an external dependency.
  weakEdgeSys = sys.extendModules {
    modules = [ {
      services.planarian.units.gym-db.edges = [ { to = "service:external:gym-upstream"; kind = "Diagnostic"; confidence = 500; } ];
      services.planarian.units.gym-app.edges = [ { to = "external:gym-upstream"; kind = "Diagnostic"; confidence = 700; } ];
    } ];
  };
  weakRefused = builtins.filter (a: !a.assertion) weakEdgeSys.config.assertions;
  # P24 (owner decision, 1 Nov): WirePlumber is watched per user whenever
  # PipeWire and its WirePlumber session manager are both enabled.
  noWireplumberSys = sys.extendModules {
    modules = [ { services.pipewire.wireplumber.enable = false; } ];
  };
  wireplumberIn = e: builtins.filter (u: pkgs.lib.hasSuffix ":wireplumber" u.id) (e.units ++ e.userUnits);
  external = m: pkgs.lib.hasInfix "external dependency" m.message;
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
    (check (cfg.services.pipewire.enable && cfg.services.pipewire.wireplumber.enable) "the reference configuration runs PipeWire with WirePlumber (P24's check is not vacuous)")
    (check (builtins.map (u: u.id) (wireplumberIn export) == [ "service@0:wireplumber" ]) "wireplumber is a default per-user unit, and only that (P24)")
    (check (wireplumberIn noWireplumberSys.config.services.planarian.export == [ ]) "no wireplumber unit when services.pipewire.wireplumber.enable is false (P24)")
    (check (builtins.elem { from = "service:gym-app"; to = "service:gym-db"; kind = "Requires"; origin = "SystemdRequires"; } app.edges) "Requires= became a Requires edge")
    (check (builtins.elem { from = "service:gym-app"; to = "service:gym-db"; kind = "Ordering"; origin = "SystemdAfter"; } app.edges) "After= became an Ordering edge")
    (check (app.systemd_restart.restart_sec == 5000) "RestartSec parsed")
    (check (app.systemd_restart.start_limit_burst == 3) "StartLimitBurst (a string in NixOS) is a number")
    (check ((unit "service:sshd").sensitivity == [ "Security" ]) "sshd is Security")
    (check (builtins.all (n: (unit "service:${n}").sensitivity == [ "Security" ]) securityNamed) "every named security unit is Security without a tag (B-5)")
    (check (builtins.all (t: (cfg.services.planarian.optionSensitivity.${t} or [ ]) == [ "Security" ]) securityTrees) "every named option tree is Security (B-5)")
    (check (export.services.dbus-broker or null == [ "Routine" ] && export.services.systemd-logind or null == [ "Security" ] && !(export.services ? sshd)) "every undeclared system service has its shipped-table entry (B-5)")
    (check (builtins.any (w: pkgs.lib.hasInfix "NTS" w) cfg.warnings) "unauthenticated NTP is reported as a notice (§12h)")
    (check (!cfg.systemd.services.planariad.restartIfChanged) "planariad survives activation")
    (check (!cfg.systemd.services.planarian-recovery.stopIfChanged) "the watchdog survives activation")
    (check (export.coreUnits."planariad.service" != "") "core unit hashes exported")
    (check (builtins.any (a: pkgs.lib.hasInfix "test build" a.message) refused) "the module refuses the test build outside the gym (B-13)")
    (check (builtins.all (a: !(pkgs.lib.hasInfix "test build" a.message)) (builtins.filter (a: !a.assertion) cfg.assertions)) "the shipped package is not refused")
    (check (builtins.any (a: external a && pkgs.lib.hasInfix "gym-db -> service:external:gym-upstream (Diagnostic 500/1000)" a.message && !(pkgs.lib.hasInfix "gym-app" a.message)) weakRefused) "a 0.5-confidence edge to an external dependency is rejected, a 0.7 one is not (S06)")
    (check (!(builtins.any external (builtins.filter (a: !a.assertion) cfg.assertions))) "the reference configuration has no weak external edge")
  ];
in
assert builtins.all (x: x) checks;
pkgs.writeText "planarian-module-eval.json" (builtins.toJSON export)
