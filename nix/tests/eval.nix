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
        # §9 (P11): an administrator-authored Exec probe, next to typed ones.
        services.planarian.units.gym-db.probes = [
          { id = "gym-db-exec"; type = "exec"; argv = [ "true" ]; establishes = "gym-db answers a local query"; }
        ];
        # §12d: a network-security unit (Security and External), with the
        # endpoint its hold still lets it reach.
        systemd.services.gym-vpn = { wantedBy = [ "multi-user.target" ]; script = "sleep infinity"; };
        # §12d "Which units": one service per branch of the network-tool
        # rule, and its negatives.
        systemd.services.nt-ambient = { script = "true"; serviceConfig = { User = "nobody"; AmbientCapabilities = [ "CAP_NET_ADMIN" ]; }; };
        systemd.services.nt-tun = { script = "true"; serviceConfig = { DynamicUser = true; DeviceAllow = [ "/dev/net/tun rw" ]; }; };
        systemd.services.nt-inverted = { script = "true"; serviceConfig.CapabilityBoundingSet = "~CAP_SYS_ADMIN"; };
        systemd.services.nt-root-bounded = { script = "true"; serviceConfig.CapabilityBoundingSet = [ "CAP_NET_RAW" ]; };
        # A templated network tool (an openvpn@-style VPN): classified, its
        # instances carry the hold.
        systemd.services."nt-vpn@" = { script = "true"; };
        # Its instances: one known only to the manifest (classified by its
        # template), one with its own definition laid over the template.
        services.planarian.units."nt-vpn@office" = { };
        systemd.services."nt-vpn@home" = { overrideStrategy = "asDropin"; serviceConfig.Environment = "NT_HOME=1"; };
        services.planarian.units."nt-vpn@home" = { };
        # An instance of a template that is not a network tool.
        systemd.services."not-tpl@" = { script = "true"; serviceConfig = { DynamicUser = true; CapabilityBoundingSet = ""; }; };
        services.planarian.units."not-tpl@a" = { };
        # A foreign unit named like Planarian's: classified like any other.
        systemd.services.planarian-test-vpn = { script = "true"; serviceConfig = { DynamicUser = true; AmbientCapabilities = [ "CAP_NET_ADMIN" ]; }; };
        systemd.services.not-bounded-empty = { script = "true"; serviceConfig.CapabilityBoundingSet = ""; };
        systemd.services.not-unprivileged = { script = "true"; serviceConfig = { DynamicUser = true; CapabilityBoundingSet = ""; }; };
        systemd.services.not-bounded-other = { script = "true"; serviceConfig.CapabilityBoundingSet = [ "CAP_CHOWN" "CAP_SETUID" ]; };
        networking.wg-quick.interfaces.wg7 = { address = [ "10.99.0.1/24" ]; privateKeyFile = "/nonexistent"; peers = [ ]; };
        services.planarian.units.gym-vpn = {
          sensitivity = [ "Security" "External" ];
          holdAllow = [ { address = "192.0.2.7"; port = 51820; } ];
          holdInterfaces = [ "wg9" ];
        };
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
  # §12d (owner decision, Nov 2): the tunnel's own interface passes the hold
  # by default; the switch only takes it away.
  ownIfaceSys = sys.extendModules { modules = [ { services.planarian.holdAllowsOwnInterface = pkgs.lib.mkForce false; } ]; };
  # §12d (P13): "planariad is ordered before every unit that admits a
  # principal: the display manager (whichever unit NixOS uses for it —
  # `display-manager.service`, or `greetd.service` where `services.greetd` is
  # enabled …)". The pinned greetd module makes greetd.service the unit and
  # display-manager.service only its alias.
  ready = "planarian-ready.target";
  afterReady = c: n: builtins.elem ready (c.systemd.services.${n}.after or [ ]);
  # The same configuration with another display manager (SDDM), not greetd.
  sddmSys = sys.extendModules {
    modules = [ {
      services.greetd.enable = pkgs.lib.mkForce false;
      services.displayManager.cosmic-greeter.enable = pkgs.lib.mkForce false;
      services.displayManager.sddm.enable = true;
    } ];
  };
  sddm = sddmSys.config;
  # §12d (P14): "*Restrict remote access to administrators* means Planarian's
  # administrators (root and `planarian-admin`), not `wheel`." What the
  # posture's responses write for sshd, read from the script they run.
  respondScript = builtins.head (pkgs.lib.splitString " " cfg.systemd.services."planarian-respond@".serviceConfig.ExecStart);
  allowLines = builtins.filter (pkgs.lib.hasInfix "AllowGroups") (pkgs.lib.splitString "\n" (builtins.readFile respondScript));
  # P24 (owner decision, 1 Nov): WirePlumber is watched per user whenever
  # PipeWire and its WirePlumber session manager are both enabled.
  noWireplumberSys = sys.extendModules {
    modules = [ { services.pipewire.wireplumber.enable = false; } ];
  };
  # The owner's "both": WirePlumber enabled on its own, PipeWire off.
  noPipewireSys = sys.extendModules {
    modules = [ { services.pipewire.enable = pkgs.lib.mkForce false; services.pipewire.wireplumber.enable = pkgs.lib.mkForce true; } ];
  };
  wireplumberIn = e: builtins.filter (u: pkgs.lib.hasSuffix ":wireplumber" u.id) (e.units ++ e.userUnits);
  external = m: pkgs.lib.hasInfix "external dependency" m.message;
  export = cfg.services.planarian.export;
  unit = id: builtins.head (builtins.filter (u: u.id == id) export.units);
  app = unit "service:gym-app";
  # §9 (P11): "`Exec` probes … are flagged". Each exported probe carries
  # `flagged = true` iff its kind is Exec; the key is absent otherwise.
  probes = builtins.concatMap (u: u.probes or [ ]) (export.units ++ export.userUnits);
  isExec = p: builtins.isAttrs p.kind && p.kind ? Exec;
  # §12d "Network security fails closed": the hold, its OnFailure= wiring,
  # its re-application after nftables loads, and holdAllow in the export.
  # The drop-ins' exact text without netwatch (the package may carry it;
  # with it, each tool's drop-in also orders it after netwatch, checked on
  # nwSys below).
  hold = (sys.extendModules { modules = [ { services.planarian.package = pkgs.lib.mkForce (cfg.services.planarian.package // { netwatch = false; }); } ]; }).config.services.planarian;
  ownSet = import ../own-units.nix;
  # planarian-netwatch exists only with the netwatch package; its ordering
  # is read from the definition the module would make.
  # The shared netsec fixture (nix/tests/wireguard-gym.nix): a full-tunnel
  # VPN, whose own start adds the routes that steer traffic, so its
  # footprint protects and its failure holds (§12d).
  wgg = import ./wireguard-gym.nix { inherit pkgs; inherit (pkgs) lib; };
  wgUp = wgg.machineUp "192.0.2.1";
  wgUnit = ((wgg.machine { endpoint = "192.0.2.1"; }).systemd.services.wireguard-gym).serviceConfig;
  wgUpstream = wgg.peer.systemd.services.wg-gym-upstream;
  withNetwatch = s: s.extendModules { modules = [ { services.planarian.package = pkgs.lib.mkForce (s.config.services.planarian.package // { netwatch = true; }); } ]; };
  nwSys = withNetwatch sys;
  nwCfg = nwSys.config;
  nwUnit = nwCfg.systemd.services.planarian-netwatch;
  # §12d (owner decision, Nov 2): every network tool starts after netwatch.
  nwHold = nwCfg.services.planarian;
  nwOrdered = u: pkgs.lib.hasInfix "\nAfter=planarian-netwatch.service\n" nwHold.holdDropins."${u}.service.d/50-planarian-hold.conf";
  # An injected cycle: a network tool ordered before netwatch, through a
  # unit that is not one (transitively), fails evaluation.
  cycleSys = nwSys.extendModules { modules = [ {
    systemd.services.nt-early = { script = "true"; before = [ "nt-early-gate.service" ]; };
    systemd.services.nt-early-gate = { script = "true"; serviceConfig = { DynamicUser = true; CapabilityBoundingSet = ""; }; unitConfig.Before = "planarian-netwatch.service"; };
  } ]; };
  cycleRefused = builtins.filter (a: !a.assertion) cycleSys.config.assertions;
  # The boot transaction, from the unit files themselves (upstream
  # systemd's included, which evaluation cannot see): the demo VM's
  # configuration, whose closure the same CI job builds, with netwatch.
  bootSys = (withNetwatch self.nixosConfigurations."planarian-vm-text-${pkgs.stdenv.hostPlatform.system}").config;
  bootHold = bootSys.services.planarian;
  nwOrderedIn = u: pkgs.lib.hasInfix "\nAfter=planarian-netwatch.service\n" bootHold.holdDropins."${u}.service.d/50-planarian-hold.conf";
  unorderedSets = import ../netwatch-unordered.nix;
  sortU = l: builtins.sort builtins.lessThan (pkgs.lib.unique l);
  nwBefore = nwUnit.before;
  holdUnit = cfg.systemd.services."planarian-hold@";
  holdScript = builtins.readFile (builtins.head (pkgs.lib.splitString " " holdUnit.serviceConfig.ExecStart));
  vpn = unit "service:gym-vpn";
  nftDropin = hold.holdDropins."nftables.service.d/50-planarian-hold.conf";
  # §12d (netwatch): the reference kernel carries BTF and what aya's
  # programs on the netlink paths need. Read from its configuration (built,
  # like the respond script above). netwatch reports a failed attach at
  # runtime on any other kernel, and every network tool then holds.
  kernelConfig = builtins.filter builtins.isString (builtins.split "\n" (builtins.readFile cfg.boot.kernelPackages.kernel.configfile));
  kernelHas = o: builtins.elem "CONFIG_${o}=y" kernelConfig;
  # lane-daemon's list: fentry programs (BPF_PROG_TYPE_TRACING, the JIT's
  # trampolines, x86_64 direct-call ftrace) and a ring buffer.
  netwatchKernel = [ "BPF" "BPF_SYSCALL" "BPF_JIT" "DEBUG_INFO_BTF" "FTRACE" "FUNCTION_TRACER" "DYNAMIC_FTRACE" "DYNAMIC_FTRACE_WITH_DIRECT_CALLS" "CGROUPS" ];
  check = cond: msg: if cond then true else throw "planarian module eval: ${msg}";
  # The other side of the export's unit keys: planarian_schema::UnitDef,
  # read from its source. serde drops a key it does not know and defaults a
  # field it does not find, so a key the module renames is read as the
  # default, silently (`holds` read false for every unit once). The struct
  # has no rename, alias or flatten, so its field names are the keys.
  unitDefBody = let
    after = builtins.elemAt (builtins.split "pub struct UnitDef [{]" (builtins.readFile ../../crates/schema/src/unit.rs)) 2;
  in builtins.head (builtins.split "\n}\n" after);
  unitDefFields = map builtins.head (builtins.filter builtins.isList (builtins.split "pub ([a-z_]+):" unitDefBody));
  # The set planariad must read as network tools: the module's list, each
  # template standing for its instances.
  toolOrInstance = n: builtins.elem n hold.holdUnits
    || (let m = builtins.match "([^@]+@).+" n; in m != null && builtins.elem (builtins.head m) hold.holdUnits);
  # Which exported units planariad must read as network tools: by id from
  # the module's list (not from the export's own flag).
  expectedHolds = builtins.filter (id: toolOrInstance (pkgs.lib.removePrefix "service:" id)) (map (u: u.id) export.units);
  unitKeysRead = u: builtins.all (k: builtins.elem k unitDefFields) (builtins.attrNames u);
  checks = [
    (check (builtins.any isExec probes) "the configuration exports an Exec probe (P11's check is not vacuous)")
    (check (builtins.all (p: !(isExec p) || (p.flagged or null) == true) probes) "every exported Exec probe carries flagged = true (§9, P11)")
    (check (builtins.all (p: isExec p || !(p ? flagged)) probes) "no other exported probe carries flagged (§9, P11)")
    (check (cfg.services.greetd.enable or false) "the reference configuration's display manager is greetd (P13's first check is not vacuous)")
    (check (afterReady cfg "greetd") "greetd.service, the display manager's unit, is ordered after planarian-ready.target (§12d, P13)")
    (check (!(cfg.systemd.services ? display-manager) || (cfg.systemd.services.display-manager.serviceConfig.ExecStart or null) != null) "with greetd, no ExecStart-less display-manager.service is defined beside its alias (§12d, P13)")
    (check (!(sddm.services.greetd.enable or false) && (sddm.systemd.services.display-manager.serviceConfig.ExecStart or null) != null) "the SDDM configuration runs display-manager.service, not greetd (P13's second check is not vacuous)")
    (check (afterReady sddm "display-manager" && !(sddm.systemd.services ? greetd && afterReady sddm "greetd")) "with SDDM, display-manager.service is ordered after planarian-ready.target (§12d, P13)")
    (check (allowLines != [ ]) "the posture restricts sshd with AllowGroups (P14's check is not vacuous)")
    (check (builtins.all (l: pkgs.lib.hasInfix "AllowGroups planarian-admin root" l && !(pkgs.lib.hasInfix "wheel" l)) allowLines) "every AllowGroups the posture writes is planarian-admin and root, never wheel (§12d, P14)")
    (check (pkgs.lib.hasInfix "Include /run/planarian/sshd/*.conf" cfg.services.openssh.extraConfig) "sshd includes the posture's drop-in, so the restriction takes effect (§12d, P14)")
    (check (builtins.all (r: builtins.elem "planarian-respond@${r}.service" cfg.systemd.services.planarian-posture-lift.after) [ "absent" "crashed" ] && pkgs.lib.hasInfix "[ -e /run/planarian/failed-absent ]" (builtins.readFile "${cfg.systemd.services.planarian-posture-lift.serviceConfig.ExecStart}")) "the lift runs after the Absent and Crashed responses and counts their markers, so a restart's Absent is lifted (§12d, P16)")
    (check (builtins.all (n: builtins.elem n hold.holdUnits) [ "gym-vpn" "nt-ambient" "nt-tun" "nt-inverted" "nt-root-bounded" "wg-quick-wg7" "firewall" ]) "each branch of the network-tool rule classifies (§12d): root with no bounding set, ambient CAP_NET_ADMIN, DeviceAllow /dev/net/tun, an inverted bounding set, a bounding set with CAP_NET_RAW, a netdev from the wg-quick tree, the firewall")
    (check (builtins.elem "planarian-test-vpn" hold.holdUnits) "a foreign unit named planarian-* is classified: Planarian's own units are excluded by the set the module declares, not by name (§12d)")
    (check (builtins.all (n: cfg.systemd.services ? ${n} || (n == "planarian-netwatch" && !(cfg.services.planarian.package.netwatch or false))) ownSet && builtins.all (n: !(builtins.elem n hold.holdUnits)) ownSet && !(sys.options.services.planarian ? ownUnits)) "every unit in the module's own set exists and none is classified; the set is no option, so no configuration can widen it")
    (check (builtins.all (n: !(builtins.elem n hold.holdUnits)) [ "not-bounded-empty" "not-unprivileged" "not-bounded-other" "planariad" "planarian-recovery" ]) "a root unit with no network capabilities in its bounding set, an unprivileged one, and Planarian's own units are not network tools (§12d)")
    (check (builtins.elem "nt-vpn@" hold.holdUnits && hold.holdDropins."nt-vpn@.service.d/50-planarian-hold.conf" == "[Unit]\nOnFailure=planarian-hold@%N.service\n") "a templated network tool is classified, and each instance's failure holds as planarian-hold@<instance> (§12d)")
    (check (hold.holdDropins."firewall.service.d/50-planarian-hold.conf" == "[Unit]\nOnFailure=planarian-hold@%N.service\n") "the firewall is a network tool from its configuration, not its name (§12d)")
    (check (builtins.sort builtins.lessThan export.networkTools == builtins.sort builtins.lessThan hold.holdUnits) "the export lists every network tool, declared or not (netwatch's footprints)")
    (check (vpn.holds && vpn.hold_allow == [ { address = "192.0.2.7"; port = 51820; protocol = "udp"; } ] && vpn.hold_interfaces == [ "wg9" ]) "a network tool exports holds, its holdAllow and its holdInterfaces (§9, §12d)")
    (check (builtins.all (u: u.holds == toolOrInstance (pkgs.lib.removePrefix "service:" u.id)) export.units && builtins.all (u: !u.holds) export.userUnits) "every exported unit's holds is the computed rule: a network tool, or an instance of a templated one")
    (check (expectedHolds != [ ] && builtins.elem "service:nt-vpn@office" expectedHolds && builtins.elem "service:gym-vpn" expectedHolds) "the set planariad must read as network tools is not empty and holds an undeclared template instance")
    (check ((unit "service:nt-vpn@office").holds && (unit "service:nt-vpn@home").holds && !(unit "service:not-tpl@a").holds) "a templated network tool's instances export holds, declared or not; a non-tool template's do not (§12d)")
    (check (builtins.length unitDefFields > 10 && builtins.elem "holds" unitDefFields && !(pkgs.lib.hasInfix "rename" unitDefBody) && !(pkgs.lib.hasInfix "alias" unitDefBody) && !(pkgs.lib.hasInfix "flatten" unitDefBody)) "the daemon's UnitDef is read from its source, and its field names are the export's keys")
    (check (builtins.all unitKeysRead (export.units ++ export.userUnits) && !(unitKeysRead (vpn // { network_tool = true; }))) "the daemon's field: every key the export gives a unit is a UnitDef field, so none is dropped and read as its default (a renamed key is refused)")
    (check (!(sys.options.services.planarian.units.type.getSubOptions [ ] ? holds) && !(sys.options.services.planarian.units.type.getSubOptions [ ] ? networkTool)) "holds is not a manifest option, so no unit can opt out of the hold (§12d)")
    (check (hold.holdDropins."gym-vpn.service.d/50-planarian-hold.conf" == "[Unit]\nOnFailure=planarian-hold@%N.service\n") "a network-security unit's failure applies the hold through OnFailure= (§12d)")
    (check (!(cfg.systemd.services.gym-vpn ? onFailure) || !(builtins.elem "planarian-hold@gym-vpn.service" cfg.systemd.services.gym-vpn.onFailure)) "the OnFailure= is a drop-in, not a unit definition (no stub for an undefined unit)")
    (check (pkgs.lib.hasInfix "ExecStartPost=" nftDropin && pkgs.lib.hasInfix "ExecReload=" nftDropin && pkgs.lib.hasInfix " reapply" nftDropin) "a hold is re-applied after nftables.service starts or reloads, which may flush every table (§12d)")
    (check (cfg.environment.etc."planarian/hold/gym-vpn.allow".text == "udp 192.0.2.7 51820\niface wg9\n") "the hold passes the unit's holdAllow endpoints and its own interfaces, as a kill switch does (§12d; owner decision, Nov 2)")
    (check (ownIfaceSys.config.environment.etc."planarian/hold/gym-vpn.allow".text == "udp 192.0.2.7 51820\n") "with the switch off, the held unit's own interfaces are held too")
    (check (holdUnit.unitConfig.DefaultDependencies == false && !(holdUnit ? bindsTo && builtins.elem "planariad.service" holdUnit.bindsTo) && !(holdUnit ? partOf && builtins.elem "planariad.service" holdUnit.partOf)) "the hold unit does not depend on planariad, so it survives its restart (§12d)")
    (check (pkgs.lib.hasSuffix " reapply" holdUnit.serviceConfig.ExecReload) "a reload rebuilds the hold's table without lifting it (§12d)")
    (check (builtins.elem pkgs.nftables cfg.systemd.services.planariad.path) "planariad can check the hold's table (nft on its PATH)")
    (check (!holdUnit.restartIfChanged && !holdUnit.stopIfChanged) "an activation (a repair rollback, undo) never stops or restarts a running hold (§12d)")
    (check (holdUnit.serviceConfig.RemainAfterExit && pkgs.lib.hasSuffix " apply %i" holdUnit.serviceConfig.ExecStart && pkgs.lib.hasSuffix " lift %i" holdUnit.serviceConfig.ExecStop && pkgs.lib.hasSuffix " condition %i" holdUnit.serviceConfig.ExecCondition) "start applies, stop lifts, an unexpired release skips (§12d)")
    (check (nwUnit.serviceConfig.Type == "notify" && nwUnit.serviceConfig.NotifyAccess == "main" && nwUnit.serviceConfig.TimeoutStartSec == 30) "netwatch is ready only once attached (Type=notify), and boot never waits on it unbounded (§12d)")
    (check (builtins.all (u: builtins.elem u nwBefore) [ "network-pre.target" "firewall.service" "nftables.service" ]) "netwatch attaches before networking and the firewall, so their boot changes are attributed (§12d)")
    (check (!(nwUnit.serviceConfig ? PrivateNetwork && nwUnit.serviceConfig.PrivateNetwork != false) && !(nwUnit.serviceConfig ? User && nwUnit.serviceConfig.User != "root") && !(nwUnit.serviceConfig ? NetworkNamespacePath) && !(nwUnit.serviceConfig.DynamicUser or false) && builtins.elem "CAP_SYS_PTRACE" nwUnit.serviceConfig.CapabilityBoundingSet) "netwatch runs as root in the host's network namespace, and may read pid 1's: it refuses to start in any other, and reads /proc/1/ns/net to check (§12d)")
    (check (builtins.all (l: pkgs.lib.hasInfix l wgUp) [ "allowed-ips 0.0.0.0/0" "ip route replace 192.0.2.1/32 $path" "ip route replace 0.0.0.0/1 dev wg0" "ip route replace 128.0.0.0/1 dev wg0" ] && toString wgUnit.ExecStartPost == toString (pkgs.writeShellScript "wireguard-gym-up" wgUp) && pkgs.lib.hasSuffix "ip address replace ${wgg.upstream}/32 dev lo" wgUpstream.serviceConfig.ExecStart && builtins.elem "multi-user.target" wgUpstream.wantedBy && !(wgg.peer ? networking && wgg.peer.networking ? interfaces)) "the netsec fixture is a full-tunnel VPN: its own start routes 0.0.0.0/1 and 128.0.0.0/1 through wg0, after the endpoint's host route, so its footprint steers; the peer holds upstream on lo by a unit of its own (§12d)")
    (check (nwUnit.after == [ ] && !(nwUnit.unitConfig ? After) && nwUnit.unitConfig.DefaultDependencies == false && builtins.elem "nfnetlink" nwCfg.boot.initrd.kernelModules && builtins.elem "nfnetlink" nwCfg.boot.kernelModules && !(builtins.elem "nfnetlink" (nwSys.extendModules { modules = [ { boot.kernelModules = pkgs.lib.mkForce [ ]; } ]; }).config.boot.initrd.kernelModules) && nwUnit.serviceConfig.RuntimeDirectory == "planarian/footprint") "netwatch is ordered after nothing: nfnetlink comes from the initrd, its directory is its own (owner decision, Nov 2)")
    (check (builtins.elem "systemd-modules-load" nwHold.holdUnits && builtins.elem "systemd-udevd" nwHold.holdUnits && builtins.elem "nt-vpn@" nwHold.holdUnits) "early-boot and templated network tools exist here (the ordering check is not vacuous)")
    (check (builtins.all (u: builtins.elem u nwHold.networkToolsUnordered || nwOrdered u) nwHold.holdUnits) "every network tool not in nix/netwatch-unordered.nix starts after planarian-netwatch.service, a template's instances through its drop-in (owner decision, Nov 2)")
    (check (sortU nwHold.networkToolsUnordered == sortU (nwHold.netwatchCycle ++ nwHold.netwatchInitrdSurvivors) && builtins.all (u: builtins.elem u nwHold.holdUnits && (builtins.elem u unorderedSets.cycle || builtins.elem u (unorderedSets.initrdSurvivors ++ builtins.attrNames nwCfg.boot.initrd.systemd.services))) nwHold.networkToolsUnordered && nwCfg.services.planarian.export.networkToolsUnordered == nwHold.networkToolsUnordered) "the tools that do not start after netwatch are exactly those in its startup chain and the systemd initrd's survivors, and the export lists them")
    (check (bootHold.netwatchInitrdSurvivors != [ ] && builtins.elem "systemd-journald" bootHold.networkToolsUnordered && builtins.all nwOrderedIn bootHold.holdUnits) "on the demo VM (systemd initrd) journald, kept across switch-root, is listed as not starting after netwatch, and still carries the After= (a stage-2 restart is ordered)")
    (check ((nwSys.extendModules { modules = [ { boot.initrd.systemd.enable = pkgs.lib.mkForce false; } ]; }).config.services.planarian.networkToolsUnordered == nwHold.netwatchCycle) "with the scripted initrd, which keeps no unit across switch-root, only the startup chain is listed")
    (check (builtins.elem "modprobe@" bootHold.networkToolsInitrd && builtins.elem "systemd-udevd" bootHold.networkToolsInitrd && bootSys.services.planarian.export.networkToolsInitrd == bootHold.networkToolsInitrd && (nwSys.extendModules { modules = [ { boot.initrd.systemd.enable = pkgs.lib.mkForce false; } ]; }).config.services.planarian.networkToolsInitrd == [ ]) "the network tools the systemd initrd also runs are exported (modprobe@ and udevd on the demo VM; none with the scripted initrd)")
    (check (builtins.filter (a: !a.assertion) nwCfg.assertions == [ ] && cycleSys.config.services.planarian.netwatchCycle == [ "nt-early" ] && builtins.any (a: pkgs.lib.hasInfix "would be a cycle: nt-early." a.message) cycleRefused) "a network tool ordered before netwatch, transitively, fails evaluation, naming it")
    (check (builtins.all (u: !(pkgs.lib.hasInfix "planarian-netwatch" hold.holdDropins."${u}.service.d/50-planarian-hold.conf")) hold.holdUnits) "without netwatch, no tool is ordered after it")
    (check (pkgs.lib.hasInfix "/run/planarian/footprint" holdScript && pkgs.lib.hasInfix "protecting yes" holdScript && pkgs.lib.hasInfix "unattributed" holdScript && pkgs.lib.hasInfix "-le 30" holdScript && pkgs.lib.hasInfix "/proc/uptime" holdScript && pkgs.lib.hasInfix "-ge -5" holdScript && pkgs.lib.hasInfix ".unattributed" holdScript && pkgs.lib.hasInfix "its footprint is stale" holdScript) "the hold's condition reads the footprint and fails closed on a stale watch, a stale footprint, or a standing unattributed change (§12d)")
    (check (pkgs.lib.hasInfix "policy drop" holdScript && pkgs.lib.hasInfix "planarian-admin" holdScript && pkgs.lib.hasInfix "/run/planarian/hold-released" holdScript) "the hold table drops by default and keeps only administrator sessions (§12d)")
    (check (builtins.all kernelHas netwatchKernel) "the reference kernel has BTF and the BPF options netwatch needs: ${toString (builtins.filter (o: !(kernelHas o)) netwatchKernel)} missing (§12d)")
    (check (builtins.any (u: u.id == "service:sshd") export.units) "sshd is a canonical unit")
    (check (builtins.any (u: u.id == "device:fs-root") export.units) "fs-root is present")
    (check (builtins.any (u: u.id == "device:fs-boot") export.units) "fs-boot is present")
    (check (builtins.any (u: u.id == "target:graphical-session") export.units) "graphical-session for the desktop")
    (check (builtins.any (u: u.id == "service@0:pipewire") export.userUnits) "pipewire is per-user")
    (check (cfg.services.pipewire.enable && cfg.services.pipewire.wireplumber.enable) "the reference configuration runs PipeWire with WirePlumber (P24's check is not vacuous)")
    (check (builtins.map (u: u.id) (wireplumberIn export) == [ "service@0:wireplumber" ]) "wireplumber is a default per-user unit, and only that (P24)")
    (check (builtins.elem { from = "service@0:wireplumber"; to = "service@0:pipewire"; kind = "Requires"; origin = "Manifest"; } (builtins.head (wireplumberIn export)).edges) "wireplumber requires pipewire, as upstream's BindsTo= says (P24)")
    (check (wireplumberIn noWireplumberSys.config.services.planarian.export == [ ]) "no wireplumber unit when services.pipewire.wireplumber.enable is false (P24)")
    (check (wireplumberIn noPipewireSys.config.services.planarian.export == [ ]) "no wireplumber unit when services.pipewire.enable is false, even with wireplumber.enable set (P24: both)")
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
# §12d: the hold's condition, run (not read). The real built script with
# only its root (/run/planarian) moved into the build directory; the
# condition reads files and /proc/uptime and touches no nftables, so the
# build sandbox runs it as is. Exit 0 holds, 1 skips.
pkgs.runCommand "planarian-module-eval.json" {
  export = builtins.toJSON export;
  passAsFile = [ "export" ];
  nativeBuildInputs = [ pkgs.gnused pkgs.gawk pkgs.diffutils pkgs.jq ];
} ''
  # The export as planariad reads it (§12d; review of #38): parsed with its
  # own `nixos::Export` (`planariad --check-export`), the units it reads as
  # network tools are the module's, each template standing for its declared
  # instances, and include an instance; and no unit key is dropped or filled
  # by default on the way. Both fail on c5e9a7d (`network_tool`, and
  # instances read false).
  ${cfg.services.planarian.package}/bin/planariad --check-export $exportPath > parsed.json
  jq -c '[.units[] | select(.holds) | .id] | sort' parsed.json > holds-read
  echo '${builtins.toJSON expectedHolds}' | jq -c 'sort' > holds-want
  diff holds-want holds-read || { echo "export: the units planariad reads as network tools differ (above: want, read)" >&2; exit 1; }
  echo "ok: planariad reads $(jq length holds-read) network tools from the export, as the module classifies them, an instance among them"
  # Every key path (array indices folded), both ways (the reviewer's diff):
  # one only in the export is dropped by planariad, one only in the round
  # trip is filled by its default. The top-level network-tool lists are
  # read raw by netwatch and the module, not through Export.
  # (paths(scalars) would skip false and null: paths takes a predicate.)
  kp='[paths(type != "object" and type != "array") | map(if type == "number" then 0 else . end)] | unique'
  jq -c "del(.networkTools, .networkToolsInitrd, .networkToolsUnordered) | $kp" $exportPath > keys-export
  jq -c "$kp" parsed.json > keys-read
  # Exempt by name, one path: an Exec probe's `flagged` (§9, P11) is for
  # whoever reads the manifest; Rust readers show Exec from ProbeKind::Exec,
  # not from the key, so ProbeDef has no field for it (docs/
  # review-reconciliation.md, "Reviewer: P11 module-eval case", row
  # "P11, scope").
  jq -r '.[] | map(tostring) | join(".")' keys-export | grep -vxE '(units|userUnits)\.0\.probes\.0\.flagged' > paths-export
  jq -r '.[] | map(tostring) | join(".")' keys-read > paths-read
  diff paths-export paths-read || { echo "export: key paths differ between the export (<) and planariad's round trip (>): < is dropped, > is defaulted" >&2; exit 1; }
  [ -s paths-export ] || { echo "export: no key paths (the diff would be vacuous)" >&2; exit 1; }
  echo "ok: every key path in the export survives planariad's Export, and none is filled by default ($(wc -l < paths-export) paths)"

  root=$PWD/run
  # A stub systemctl, first on the script's PATH: the unit's InvocationID
  # is $STUB_INV (empty: the unit has none).
  cstub=$PWD/cstub; mkdir -p $cstub
  printf '#!${pkgs.runtimeShell}\nprintf "%%s\\n" "$STUB_INV"\n' > $cstub/systemctl; chmod +x $cstub/systemctl
  I=0123456789abcdef0123456789abcdef; export STUB_INV=$I
  sed -e "s|/run/planarian|$root|g" -e "s|^PATH=|PATH=$cstub:|" ${builtins.head (pkgs.lib.splitString " " holdUnit.serviceConfig.ExecStart)} > hold
  chmod +x hold
  F=$root/footprint R=$root/hold-released
  mkdir -p $F $R
  up=$(cut -d. -f1 /proc/uptime); wall=$(date +%s)
  expect() { want=$1; shift; set +e; ./hold condition u >/dev/null 2>&1; got=$?; set -e
    [ "$got" = "$want" ] || { echo "hold condition: $* -> $got, expected $want" >&2; exit 1; }
    echo "ok: $* -> $got"; }
  echo "attached $up" > $F/.watch
  printf 'protecting no\nat %s\ninvocation %s\nended\n' "$up" "$I" > $F/u;            expect 1 "a fresh protecting no skips"
  printf 'protecting no\nat %s\ninvocation %s\n' "$((up - 40))" "$I" > $F/u;   expect 0 "a stale stamp holds"
  printf 'protecting no\nat %s\ninvocation %s\n' "$wall" "$I" > $F/u;          expect 0 "a wall-clock-epoch stamp holds"
  printf 'protecting yes\nat %s\ninvocation %s\n' "$up" "$I" > $F/u;           expect 0 "protecting yes holds"
  printf 'protecting no\nat %s\ninvocation %s\nunattributed\n' "$up" "$I" > $F/u; expect 0 "an unattributed change charged here holds"
  printf 'protecting no\nat %s\ninvocation %s\n' "$up" "$I" > $F/u
  echo x > $F/.unattributed;                                expect 0 "a standing unattributed change anywhere holds"
  rm $F/.unattributed
  echo "attached $((up - 40))" > $F/.watch;                 expect 0 "a stale watch holds"
  echo "failed lost" > $F/.watch;                           expect 0 "a failed watch holds"
  echo "attached $up" > $F/.watch
  rm $F/u;                                                  expect 0 "a missing footprint holds"
  # This run's footprint only (owner decision, Nov 3): InvocationID.
  printf 'protecting no\nat %s\ninvocation %s\nended\n' "$up" "$I" > $F/u; expect 1 "this run, protecting no, ended: skips"
  printf 'protecting no\nat %s\ninvocation %s\n' "$up" "$I" > $F/u
  t0=$(date +%s%N); expect 0 "this run, protecting no, no ended: holds after the bounded wait"
  waited=$(( ($(date +%s%N) - t0) / 1000000 ))
  [ "$waited" -ge 2500 ] || { echo "the hold did not wait for ended ($waited ms)" >&2; exit 1; }
  echo "ok: it waited $waited ms (bound 3 s) before holding"
  printf 'protecting no\nat %s\ninvocation %s\nended\n' "$up" "fedcba9876543210fedcba9876543210" > $F/u
  expect 0 "an earlier run's footprint (another InvocationID, ended) holds"
  printf 'protecting no\nat %s\nended\n' "$up" > $F/u;     expect 0 "a footprint without an InvocationID holds"
  printf 'protecting unknown\nat %s\ninvocation %s\nended\n' "$up" "$I" > $F/u; expect 0 "this run, protecting unknown, ended: holds"
  printf 'protecting no\nat %s\ninvocation %s\nended\n' "$up" "$I" > $F/u
  export STUB_INV=; expect 0 "a unit with no InvocationID holds"; export STUB_INV=$I
  rm $F/u
  # The release cases: the footprint protects, so only the release decides.
  printf 'protecting yes\nat %s\ninvocation %s\n' "$up" "$I" > $F/u
  echo "$((wall + 600)) $((up + 600))" > $R/u;              expect 1 "an unexpired release skips"
  echo "$((wall - 1)) $((up + 600))" > $R/u;                expect 0 "an expired release (wall clock) holds"
  echo "$((wall + 600)) $((up - 1))" > $R/u;                expect 0 "an expired release (boottime, a clock step) holds"
  echo boot > $R/u;                                         expect 1 "a release until boot skips"
  echo "$((wall + 600))" > $R/u;                            expect 0 "a one-number marker (no boottime deadline) holds"
  echo garbage > $R/u;                                      expect 0 "a garbage marker holds"
  : > $R/u;                                                 expect 0 "an empty marker holds"
  echo "$((wall + 600)) $((up + 600)) x" > $R/u;            expect 0 "a marker with a third field holds"
  rm $R/u;                                                  expect 0 "no marker: the footprint decides (protecting yes holds)"
  # The administrator snapshot's parsing (#36), on `ss` lines: the built
  # script's own awk program, cut out of it. A dual-stack sshd's IPv4 peer
  # ([::ffff:a.b.c.d]) is IPv4; a native IPv6 flow stays IPv6; a process
  # outside the administrators' sessions is not taken.
  a=$(grep -n 'ss -tunpH state established' hold | cut -d: -f1)
  b=$(grep -n '>> "$dir/.admin"' hold | head -n1 | cut -d: -f1)
  sed -n "$((a + 1)),''${b}p" hold | sed '$s/}'"'"' >> .*/}/' > snapshot.awk
  printf '%s\n' \
    'tcp 0 0 [::ffff:192.168.1.1]:22 [::ffff:192.168.1.2]:40000 users:(("sshd-session",pid=7,fd=4))' \
    'tcp 0 0 [2001:db8::1]:22 [2001:db8::9]:40001 users:(("sshd-session",pid=7,fd=5))' \
    'tcp 0 0 10.0.2.15:22 10.0.2.2:40002 users:(("sshd-session",pid=8,fd=5))' \
    | awk -v pids=" 7 " -f snapshot.awk > snapshot.out
  printf '4 tcp 192.168.1.1 22 192.168.1.2 40000\n6 tcp 2001:db8::1 22 2001:db8::9 40001\n' > snapshot.want
  diff snapshot.want snapshot.out
  echo "ok: the administrator snapshot (mapped IPv4, native IPv6, a non-administrator left out)"
  # §12d: reapply fails closed when its table will not load (a stub nft,
  # first on the script's PATH, fails the full load and records the next).
  root=$PWD/run2 stub=$PWD/stub
  mkdir -p $root/hold $stub
  cat > $stub/nft <<STUB
  #!${pkgs.runtimeShell}
  n=\$(cat $stub/count 2>/dev/null || echo 0); n=\$((n + 1)); echo \$n > $stub/count
  if [ "\$*" = "-f -" ]; then cat > $stub/load.\$n; [ \$n -ge 2 ] && exit 0; exit 1; fi
  exit 0
  STUB
  chmod +x $stub/nft
  sed -e "s|/run/planarian|$root|g" -e "s|^PATH=|PATH=$stub:|" ${builtins.head (pkgs.lib.splitString " " holdUnit.serviceConfig.ExecStart)} > hold2
  chmod +x hold2
  touch $root/hold/u
  ./hold2 reapply
  grep -q 'set allow4' $stub/load.1 || { echo "reapply did not try the full table first" >&2; exit 1; }
  grep -q 'iif lo accept' $stub/load.2 && grep -q 'policy drop' $stub/load.2 && ! grep -q 'set allow4' $stub/load.2 \
    || { echo "reapply did not fall back to the lock" >&2; exit 1; }
  echo "ok: reapply with a failing table load holds everything but loopback"
  # §12d (owner decision, Nov 2): the boot transaction systemd builds from
  # the unit files, upstream ones included, has netwatch in it and no
  # ordering cycle; and the check finds one when netwatch is ordered after
  # an early-boot network tool (systemd-udevd).
  sd=${bootSys.systemd.package}
  units=${bootSys.environment.etc."systemd/system".source}
  mkdir -p probe injected/planarian-netwatch.service.d
  printf '[Unit]\nWants=graphical.target\n[Service]\nExecStart=%s/bin/systemctl\n' $sd > probe/probe-boot.service
  printf '[Unit]\nAfter=systemd-udevd.service\n' > injected/planarian-netwatch.service.d/x.conf
  # The sandbox has no /run for a system-scope test manager; the user-scope
  # one, in a runtime directory of its own, reads the same unit files and
  # builds the same ordering.
  mkdir xdg
  boot() { XDG_RUNTIME_DIR=$PWD/xdg SYSTEMD_LOG_LEVEL=debug SYSTEMD_UNIT_PATH=$PWD/probe:$1 $sd/bin/systemd-analyze verify --user --man=no probe-boot.service > $2 2>&1 || true; }
  boot $units boot.log
  grep -q 'Installed new job planarian-netwatch.service/start' boot.log && grep -q 'Installed new job systemd-udevd.service/start' boot.log \
    || { echo "the boot transaction has no netwatch or udevd job (the check is vacuous)" >&2; tail -20 boot.log >&2; exit 1; }
  if grep 'Found ordering cycle' boot.log >&2; then echo "the boot transaction has an ordering cycle" >&2; exit 1; fi
  boot $PWD/injected:$units injected.log
  grep -q 'Found ordering cycle.*planarian-netwatch.service' injected.log \
    || { echo "an injected cycle through systemd-udevd was not found" >&2; exit 1; }
  echo "ok: the boot transaction orders every network tool after netwatch with no cycle; an injected one is found"
  # The systemd initrd's survivors, from its unit files: a unit with
  # IgnoreOnIsolate= (initrd-cleanup isolates initrd-switch-root.target)
  # and no Conflicts= on initrd-switch-root keeps running into stage 2. On
  # the demo VM, those that are network tools are exactly the export's list
  # (its startup chain is empty).
  initrd=${bootSys.boot.initrd.systemd.contents."/etc/systemd/system".source}
  : > survivors
  for f in $initrd/*.service; do
    n=$(basename "$f" .service)
    body=$(cat "$f" "$f".d/*.conf 2>/dev/null || cat "$f")
    printf '%s\n' "$body" | grep -qiE '^IgnoreOnIsolate=(yes|true|1|on)$' || continue
    printf '%s\n' "$body" | grep -iE '^Conflicts=' | grep -qE 'initrd-switch-root\.(target|service)' && continue
    echo "$n" >> survivors
  done
  grep -qx systemd-journald survivors || { echo "the initrd survivor scan found no journald (the check is vacuous)" >&2; exit 1; }
  printf '%s\n' ${pkgs.lib.escapeShellArgs bootHold.holdUnits} | sort > tools
  sort survivors | comm -12 - tools > want
  printf '%s\n' ${pkgs.lib.escapeShellArgs (bootHold.netwatchCycle ++ bootHold.networkToolsUnordered)} | grep -v '^$' | sort -u > got
  diff want got || { echo "networkToolsUnordered differs from the initrd's survivors among the network tools (above: < from the files, > exported)" >&2; exit 1; }
  echo "ok: the systemd initrd's survivors that are network tools ($(tr '\n' ' ' < want)) are exactly networkToolsUnordered"
  # Every service the initrd ships, among the network tools, is exactly
  # networkToolsInitrd.
  for f in $initrd/*.service; do basename "$f" .service; done | sort > initrd-all
  comm -12 initrd-all tools > want-initrd
  printf '%s\n' ${pkgs.lib.escapeShellArgs bootHold.networkToolsInitrd} | grep -v '^$' | sort -u > got-initrd
  diff want-initrd got-initrd || { echo "networkToolsInitrd differs from the initrd's services among the network tools (< files, > exported)" >&2; exit 1; }
  echo "ok: the network tools the systemd initrd runs ($(wc -l < want-initrd)) are exactly networkToolsInitrd"
  cp $exportPath $out
''
