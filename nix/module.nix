# services.planarian: the Planarian daemon, its recovery watchdog, and the
# manifest (SPEC §9) it reads from the evaluated generation.
#
# The manifest says what NixOS doesn't: what depends on what, how to test each
# thing, how risky it is to touch. Defaults come from the systemd units
# themselves (Requires=/BindsTo=/Requisite= → Requires, Wants= → Wants,
# After= → Ordering), from shipped sensitivity and disruption tables, and from
# the services you enabled (sshd, NetworkManager, the display manager,
# PipeWire, the graphical session, filesystems).
#
# Planarian never edits your own Nix. Your flake imports
# ./planarian/overrides.nix (see the flake template), and Planarian changes
# only that file, through transactions.
{ config, options, lib, pkgs, ... }:

let
  # §12e: the security floor's inspected set. Every package value the
  # evaluated configuration holds (environment.systemPackages,
  # systemd.packages, every enabled services.* option that is a package or a
  # list of them, every unit's `path`, the kernel and firmware), then their
  # runtime inputs (buildInputs, propagatedBuildInputs), recursively. A
  # package referenced only by a store-path string in a unit file has no
  # `meta` to read at evaluation and is not seen (bypasses.md; the CVE feed
  # matches the built closure from Phase B).
  inspected =
    let
      ok = v: let r = builtins.tryEval v; in if r.success then r.value else null;
      isDrv = v: ok (lib.isDerivation v) == true;
      drvs = v:
        let x = ok v; in
        if x == null then [ ] else if isDrv x then [ x ] else if builtins.isList x then lib.filter isDrv x else [ ];
      # Through `options`, never by walking config values: a renamed option's
      # shim aborts when read, and abort is not catchable.
      pkgType = t:
        t.name == "package"
        || (lib.elem t.name [ "listOf" "nullOr" ] && (t.nestedTypes.elemType.name or "") == "package");
      isEnabled = n:
        let os = options.services.${n}; in
        n != "planarian" && os ? enable && lib.isOption os.enable && (os.enable.isDefined or false)
        && ok config.services.${n}.enable == true;
      fromServices = lib.concatMap
        (n:
          let os = options.services.${n}; in
          lib.concatMap
            (a: let o = os.${a}; in
              if lib.isOption o && (o.visible or true) != false && pkgType o.type then drvs config.services.${n}.${a} else [ ])
            (builtins.attrNames os))
        (lib.filter isEnabled (builtins.attrNames options.services));
      unitPaths = lib.concatMap (u: drvs (u.path or [ ])) (builtins.attrValues config.systemd.services);
      # The hold's drop-ins (§12d) are Planarian's own text files, no
      # package; they are computed from every service's configuration, which
      # may read this set (a cycle), so they are left out by their marker.
      roots = lib.concatMap drvs (config.environment.systemPackages
          ++ builtins.filter (p: !(p.planarianHoldDropins or false)) config.systemd.packages)
        ++ fromServices ++ unitPaths
        ++ drvs config.boot.kernelPackages.kernel ++ drvs config.hardware.firmware;
      item = p: let k = ok p.outPath; in if k == null then [ ] else [ { key = k; pkg = p; } ];
      inputs = p: lib.filter isDrv (lib.flatten (map (a: let v = ok (p.${a} or [ ]); in if v == null then [ ] else v) [ "buildInputs" "propagatedBuildInputs" ]));
    in
    map (i: i.pkg) (builtins.genericClosure {
      startSet = lib.concatMap item roots;
      operator = i: lib.concatMap item (inputs i.pkg);
    });
  insecureIn = p: (let r = builtins.tryEval (p.meta.knownVulnerabilities or [ ]); in if r.success then r.value else [ ]) != [ ];
  inherit (lib) mkOption mkEnableOption mkIf mkDefault types;
  cfg = config.services.planarian;

  sensitivities = [ "Routine" "Security" "UserData" "External" "Core" ];
  disruptions = [ "None" "Brief" "SessionLoss" "DataInterruption" "ConnectivityLoss" ];

  # Shipped tables (§9): the defaults when a unit doesn't say.
  # §11 sensitivity completeness (B-5): the units the security, firewall,
  # openssh, fail2ban, usbguard and VPN option trees create are Security
  # without a tag. By name, since a unit does not record the option tree
  # that declared it.
  securityUnit = name:
    builtins.elem name [ "sshd" "polkit" "systemd-logind" "firewall" "nftables" "fail2ban" "usbguard" "apparmor" "auditd" "tailscaled" "strongswan" "strongswan-swanctl" ]
    || lib.any (p: lib.hasPrefix p name) [ "wg-quick-" "wireguard-" "openvpn-" ];
  defaultSensitivity = name:
    if securityUnit name then [ "Security" ]
    else if builtins.elem name [ "NetworkManager" "wpa_supplicant" "systemd-networkd" ] then [ "External" ]
    else [ "Routine" ];
  # §12d "Which units": a *network tool* is a unit able to change how
  # traffic leaves the machine, computed at build time from its systemd
  # configuration, never from its name, and failing closed. It holds
  # CAP_NET_ADMIN or CAP_NET_RAW (ambient, or root's bounding set); it is
  # given /dev/net/tun or /dev/ppp explicitly (DeviceAllow= or Bind*Paths=;
  # TUNSETIFF needs CAP_NET_ADMIN, so bare device access creates nothing); it
  # declares network interfaces (the units the networkd netdev, WireGuard
  # and wg-quick option trees create); or it runs as root with no
  # CapabilityBoundingSet. A unit whose configuration does not evaluate is a
  # tool. Whether a network tool is a network-security unit is decided at
  # runtime, from its kernel-attributed footprint (the hold's condition).
  #
  # Templates (`openvpn@`) and their instances are classified like any unit
  # (a template's configuration is every instance's): the hold's instance is
  # the failed unit's own name, `@` included, which systemd's instance
  # syntax allows (`planarian-hold@openvpn@office.service`), filled in per
  # instance by `%N` in the OnFailure= drop-in. Not classified: Planarian's
  # own units, whose failures have their own posture (Absent, Crashed,
  # Integrity; §12d) and which change no routing.

  netdevUnits =
    lib.optional (config.systemd.network.enable && config.systemd.network.netdevs != { }) "systemd-networkd"
    ++ map (i: "wireguard-${i}") (lib.attrNames (config.networking.wireguard.interfaces or { }))
    ++ map (i: "wg-quick-${i}") (lib.attrNames (config.networking.wg-quick.interfaces or { }));
  # The set this module declares (posture.nix), not a name prefix: a
  # foreign `planarian-*` unit is classified like any other.
  ownUnits = name: builtins.elem name (import ./own-units.nix);
  netCaps = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
  words = v:
    if builtins.isList v then lib.concatMap words v
    else if builtins.isString v then lib.filter (w: w != "") (lib.splitString " " v)
    else [ (toString v) ];
  # A capability set as systemd reads it: "~" inverts it (all but these).
  grants = set: caps:
    let ws = words set; inverted = ws != [ ] && lib.hasPrefix "~" (builtins.head ws);
    in if inverted then lib.any (c: !(builtins.elem c (map (lib.removePrefix "~") ws))) caps
       else lib.any (c: builtins.elem c ws) caps;
  isNetworkToolUnchecked = name:
    let
      svc = config.systemd.services.${name};
      sc = svc.serviceConfig;
      user = sc.User or "root";
      root = (user == "root" || user == "0") && !(sc.DynamicUser or false);
      bounding = sc.CapabilityBoundingSet or null;
      devices = words ((sc.DeviceAllow or [ ]) ++ (sc.BindPaths or [ ]) ++ (sc.BindReadOnlyPaths or [ ]));
    in
    builtins.elem name netdevUnits
    || grants (sc.AmbientCapabilities or [ ]) netCaps
    || (root && (bounding == null || grants bounding netCaps))
    || lib.any (d: lib.hasInfix "/dev/net/tun" d || lib.hasInfix "/dev/ppp" d) devices;
  isNetworkTool = name:
    if ownUnits name || !(config.systemd.services ? ${name}) then false
    else let r = builtins.tryEval (builtins.deepSeq (isNetworkToolUnchecked name) (isNetworkToolUnchecked name)); in
      !r.success || r.value;
  # The build-time half of "network-security unit" (§12d); the runtime half
  # is the footprint, read by the hold's condition. The one rule: it feeds
  # the export's `holds` (computed, never settable; `UnitDef.holds` reads
  # it) and OnFailure=.
  isNetworkSecurity = name: _u: isNetworkTool name;
  networkTools = builtins.filter isNetworkTool (lib.attrNames config.systemd.services);
  defaultDisruption = name:
    if builtins.elem name [ "display-manager" "greetd" "graphical-session" ] then "SessionLoss"
    else if builtins.elem name [ "NetworkManager" "systemd-networkd" "wpa_supplicant" ] then "ConnectivityLoss"
    else if builtins.elem name [ "postgresql" "mysql" "redis" ] then "DataInterruption"
    else if lib.hasPrefix "fs-" name then "None"
    else "Brief";

  edgeModule = {
    options = {
      to = mkOption { type = types.str; description = "Target unit, e.g. `gym-db` or `device:snd-hda0`."; };
      kind = mkOption { type = types.enum [ "Requires" "Wants" "Ordering" "Diagnostic" ]; default = "Requires"; };
      confidence = mkOption { type = types.ints.between 0 1000; default = 800; description = "Per-mille, for Diagnostic edges."; };
    };
  };

  probeModule = { config, ... }: {
    options = {
      id = mkOption { type = types.str; };
      type = mkOption { type = types.enum [ "tcp" "http" "exec" "systemd-active" "free-space" ]; };
      addr = mkOption { type = types.nullOr types.str; default = null; };
      url = mkOption { type = types.nullOr types.str; default = null; };
      status = mkOption { type = types.int; default = 200; };
      argv = mkOption { type = types.listOf types.str; default = [ ]; };
      network = mkOption { type = types.bool; default = false; description = "Exec probes: allow network access."; };
      path = mkOption { type = types.nullOr types.str; default = null; };
      minBytes = mkOption { type = types.int; default = 0; };
      minPermille = mkOption { type = types.int; default = 0; };
      timeout = mkOption { type = types.int; default = 10; description = "Seconds."; };
      role = mkOption { type = types.enum [ "Readiness" "Diagnostic" ]; default = "Readiness"; };
      every = mkOption { type = types.nullOr types.int; default = null; description = "Seconds between runs; null runs it every tick."; };
      onDemand = mkOption { type = types.bool; default = config.role == "Diagnostic"; };
      cost = mkOption { type = types.enum [ "Trivial" "Cheap" "WakesHardware" ]; default = "Cheap"; };
      sideEffects = mkOption {
        type = types.enum [ "None" "Measurement" "Audible" "Visible" "RemoteStateChange" "Disk" ];
        default = if builtins.elem config.type [ "tcp" "http" ] then "Measurement" else "None";
      };
      establishes = mkOption { type = types.str; description = "What a pass actually shows, in plain words."; };
    };
  };

  unitModule = { name, config, ... }: {
    options = {
      kind = mkOption { type = types.enum [ "service" "target" "device" ]; default = "service"; };
      scope = mkOption {
        type = types.enum [ "system" "user" ];
        default = "system";
        description = "`user`: instantiated for each logged-in user, desired only while their session exists.";
      };
      desired = mkOption {
        type = types.enum [ "Running" "Stopped" "Bound" "Absent" ];
        default = if config.kind == "device" && !(lib.hasPrefix "fs-" name) then "Bound" else "Running";
      };
      when = mkOption { type = types.enum [ "always" "session" "seat" "ac" "battery" ]; default = "always"; };
      whenDevice = mkOption { type = types.nullOr types.str; default = null; description = "Desired only while this device is connected."; };
      edges = mkOption { type = types.listOf (types.submodule edgeModule); default = [ ]; };
      deriveEdges = mkOption { type = types.bool; default = true; description = "Add edges from the systemd unit's dependencies."; };
      sensitivity = mkOption { type = types.listOf (types.enum sensitivities); default = defaultSensitivity name; };
      restartDisruption = mkOption { type = types.enum disruptions; default = defaultDisruption name; };
      probes = mkOption { type = types.listOf (types.submodule probeModule); default = [ ]; };
      synonyms = mkOption { type = types.listOf types.str; default = [ ]; };
      startupGrace = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Seconds after this unit comes up during which a failing health probe is not yet a fault. `null`: `services.planarian.startupGrace`.";
      };
      sysfs = mkOption { type = types.nullOr types.str; default = null; description = "Devices: the sysfs directory, e.g. /sys/bus/pci/devices/0000:00:1b.0."; };
      inferStops = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether a stop outside Planarian (a signal, an unissued systemctl
          stop) may be taken, under the Relaxed and Standard postures, as the
          person's intent (an inferred override until the next boot). False
          for units whose absence is harm whoever caused it (backup, sync, the
          desktop's own units): such a stop is a fault, restarted and alarmed
          (§11). Security-sensitive units are always treated so.
        '';
      };
      holdAllow = mkOption {
        type = types.listOf (types.submodule {
          options = {
            address = mkOption { type = types.str; description = "An IPv4 or IPv6 address (a literal: nothing resolves names while traffic is held)."; };
            port = mkOption { type = types.port; };
            protocol = mkOption { type = types.enum [ "tcp" "udp" ]; default = "udp"; };
          };
        });
        default = [ ];
        example = [ { address = "198.51.100.7"; port = 51820; } ];
        description = ''
          For a network-security unit (§12d): the endpoints it needs to
          reconnect while its traffic is held, e.g. a WireGuard peer. Every
          other connection is refused until the unit is back.
        '';
      };
      holdInterfaces = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "wg0" ];
        description = ''
          For a network-security unit (§12d): its own network interfaces
          (a tunnel's). Traffic over them passes the hold, as a kill switch
          lets the tunnel itself through (owner decision, Nov 2), so a
          Readiness probe across the tunnel can pass and lift the hold.
        '';
      };
      runtimeRepair = mkOption {
        type = types.nullOr (types.enum [ "wifi.network" ]);
        default = null;
        description = ''
          A runtime-settable option whose other values can restore this unit:
          `wifi.network` for a unit with a Wi-Fi association probe. When it
          fails, Planarian proposes switching to another known network in range
          (it asks first: the switch drops connectivity).
        '';
      };
    };
  };

  # ---- Manifest → the JSON `planarian-schema` reads ----

  unitId = name: u: "${u.kind}${lib.optionalString (u.scope == "user") "@0"}:${name}";
  toId = s: if lib.hasInfix ":" s then s else "service:${s}";
  managed = lib.mapAttrsToList unitId cfg.units;

  # §10 (S06): an edge to an external dependency must be one the diagnoser
  # follows: Requires, or Diagnostic at its threshold (0.7) or above.
  isExternal = to: lib.hasPrefix "external:" to || lib.hasPrefix "service:external:" to;
  weakExternalEdges = lib.concatLists (lib.mapAttrsToList (name: u:
    map (e: "${name} -> ${e.to} (${e.kind}${lib.optionalString (e.kind == "Diagnostic") " ${toString e.confidence}/1000"})")
      (builtins.filter (e: isExternal e.to && !(e.kind == "Requires" || (e.kind == "Diagnostic" && e.confidence >= 700))) u.edges)
  ) cfg.units);

  depId = d:
    if lib.hasSuffix ".service" d then "service:${lib.removeSuffix ".service" d}"
    else if lib.hasSuffix ".target" d then "target:${lib.removeSuffix ".target" d}"
    else null;

  derivedEdges = name: u:
    let
      svc = config.systemd.services.${name} or null;
      mk = kind: origin: deps: map (d: { to = depId d; inherit kind origin; }) deps;
    in
    if svc == null || !u.deriveEdges || u.scope != "system" then [ ]
    else
      mk "Requires" "SystemdRequires" (svc.requires ++ svc.bindsTo ++ (svc.requisite or [ ]))
      ++ mk "Wants" "SystemdWants" svc.wants
      ++ mk "Ordering" "SystemdAfter" svc.after;

  edgeKind = e: if e.kind == "Diagnostic" then { Diagnostic = { inherit (e) confidence; }; } else e.kind;

  edgesJSON = name: u:
    let
      from = unitId name u;
      declared = map (e: { inherit from; to = toId e.to; kind = edgeKind e; origin = "Manifest"; }) u.edges;
      derived = map (e: { inherit from; inherit (e) to kind origin; })
        (builtins.filter (e: e.to != null && builtins.elem e.to managed && e.to != from) (derivedEdges name u));
    in
    declared ++ derived;

  whenJSON = u:
    if u.whenDevice != null then { DeviceConnected = toId u.whenDevice; }
    else {
      always = "Always";
      session = { SessionEstablished = { uid = null; seated = false; }; };
      seat = { SessionEstablished = { uid = null; seated = true; }; };
      ac = "OnAcPower";
      battery = "OnBattery";
    }.${u.when};

  secondsOf = v:
    if builtins.isInt v then v * 1000
    else if lib.hasSuffix "ms" v then lib.toInt (lib.removeSuffix "ms" v)
    else if lib.hasSuffix "s" v then lib.toInt (lib.removeSuffix "s" v) * 1000
    else lib.toInt v * 1000;

  restartJSON = name:
    let
      svc = config.systemd.services.${name} or null;
      sc = if svc == null then { } else svc.serviceConfig;
      restart = sc.Restart or "no";
    in
    if svc == null || restart == "no" then null
    else {
      restart = true;
      restart_sec = secondsOf (sc.RestartSec or "100ms");
      # NixOS stores StartLimitBurst as a string ("3") when startLimitBurst is set.
      start_limit_burst = let b = svc.unitConfig.StartLimitBurst or 5; in if builtins.isString b then lib.toInt b else b;
    };

  # §9 (P11): an Exec probe runs an arbitrary command, so it is flagged
  # wherever the manifest is read; typed probes carry no `flagged` key.
  probeJSON = p: lib.optionalAttrs (p.type == "exec") { flagged = true; } // {
    inherit (p) id role cost establishes;
    kind = {
      tcp = { Tcp = { inherit (p) addr; }; };
      http = { Http = { inherit (p) url status; }; };
      exec = { Exec = { inherit (p) argv; sandbox = { uid = 0; caps = [ ]; max_output = 4096; cpu_ms = 1000; inherit (p) network; }; }; };
      systemd-active = "SystemdActive";
      free-space = { FreeSpace = { inherit (p) path; min_bytes = p.minBytes; min_permille = p.minPermille; }; };
    }.${p.type};
    timeout = p.timeout * 1000;
    origin = "User";
    cadence = if p.onDemand then "OnDemand" else if p.every != null then { Every = p.every * 1000; } else "EveryTick";
    side_effects = if p.sideEffects == "Measurement" then { Measurement = { bytes_max = 4096; per = 5000; }; } else p.sideEffects;
  };

  unitJSON = name: u: {
    id = unitId name u;
    desired = { status = u.desired; when = whenJSON u; };
    edges = edgesJSON name u;
    inherit (u) sensitivity synonyms;
    restart_disruption = u.restartDisruption;
    probes = map probeJSON u.probes;
    systemd_restart = if u.scope == "system" && u.kind == "service" then restartJSON name else null;
    startup_grace = if u.startupGrace == null then null else u.startupGrace * 1000;
    runtime_repair = u.runtimeRepair;
    # §12d: whether its failure holds the machine's traffic, and what the
    # hold still lets it reach. The key is `holds`: planarian_schema::UnitDef
    # reads it, with a default of false, so a renamed key fails open
    # (module-eval's "the daemon's field" check).
    holds = u.kind == "service" && u.scope == "system" && isNetworkSecurity name u;
    hold_allow = map (a: { inherit (a) address port protocol; }) u.holdAllow;
    hold_interfaces = u.holdInterfaces;
    stops_are_faults = !u.inferStops;
  };

  unitsOf = scope: lib.mapAttrsToList unitJSON (lib.filterAttrs (_: u: u.scope == scope) cfg.units);

  unitHash = n: builtins.hashString "sha256" (config.systemd.units.${n}.text or "");

  optionValue = path: lib.attrByPath (lib.splitString "." path) null config;

  hasDesktop = config.services.desktopManager.cosmic.enable or false
    || config.services.xserver.enable
    || config.services.desktopManager.plasma6.enable or false;
  dmUnit = if config.services.greetd.enable or false then "greetd" else "display-manager";
  hasDm = (config.services.greetd.enable or false) || (config.services.displayManager.enable or false);
in
{
  imports = [ ./posture.nix ];

  options.services.planarian = {
    enable = mkEnableOption "Planarian, a self-healing layer for this NixOS system";

    package = mkOption {
      type = types.package;
      description = "The Planarian package (the flake's module sets it).";
    };

    console = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Start the read-only console with each graphical session. It starts minimized unless something needs attention.";
      };
      package = mkOption {
        type = types.package;
        description = "The console package (the flake's module sets it). It also holds `planarian-tray`.";
      };
    };

    tray.enable = mkOption {
      type = types.bool;
      default = cfg.console.enable;
      defaultText = lib.literalExpression "config.services.planarian.console.enable";
      description = "Show the status indicator in the panel with each graphical session: the planarian mark, amber when something needs a look, red when something needs a person. Clicking it opens the console.";
    };

    owner = mkOption {
      type = types.str;
      default = "/etc/nixos";
      description = "Your flake's directory. It must import ./planarian/overrides.nix; for a git flake that file must be tracked.";
    };

    flakeAttr = mkOption {
      type = types.str;
      default = "nixosConfigurations.${config.networking.hostName}";
      description = "The flake output that is this machine.";
    };

    agents.limits = {
      tasksMax = mkOption { type = types.ints.positive; default = 512; description = "TasksMax= for each agent `planarian agent run` launches (§12d)."; };
      memoryMax = mkOption { type = types.str; default = "4G"; description = "MemoryMax= for each launched agent (§12d)."; };
      perUid = mkOption { type = types.ints.positive; default = 4; description = "Agents one user may have running at once (§12d); a launch over it is refused."; };
    };

    sessionCompositors = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "cosmic-comp" ];
      description = ''
        Process names (`comm`) of compositors. A graphical session is up when one
        runs in that session's own cgroup (§9), which tells a second session of
        the same user apart from the first. Empty: judge by the user's
        graphical-session.target only.
      '';
    };

    externalSource = mkOption {
      type = types.nullOr (types.submodule {
        options = {
          publicKey = mkOption {
            type = types.strMatching "[0-9a-f]{64}";
            description = "The Ed25519 public key (64 hex digits) the document must verify against.";
          };
          path = mkOption {
            type = types.str;
            default = "/var/lib/planarian/external/desired.json";
            description = "Where a producer leaves the document, with its signature at `<path>.sig`.";
          };
        };
      });
      default = null;
      description = ''
        A signed external desired-state source (SPEC §9 hook). Its units join
        this generation's; a unit the generation declares stays the
        generation's. An older or unreadable document leaves the last valid
        one in force; an invalid signature is an integrity failure (§12d).
        Phase A has no producer. Security-sensitive, like all of
        services.planarian.
      '';
    };

    flakeInputs = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          rev = mkOption { type = types.str; default = ""; description = "The input's locked revision (or NAR hash)."; };
          path = mkOption { type = types.str; default = ""; description = "The input's store path."; };
        };
      });
      default = { };
      example = lib.literalExpression ''builtins.mapAttrs (_: i: { rev = i.rev or i.narHash or ""; path = toString i.outPath; }) (removeAttrs inputs [ "self" ])'';
      description = ''
        The owner flake's inputs, recorded in each generation (SPEC §15): a
        service declared by a file inside an input's source is reported with
        that input and its lock change. The flake template sets it.
      '';
    };

    healthReport.interval = mkOption {
      type = types.ints.unsigned;
      default = 3600;
      description = ''
        Seconds between signed health reports (SPEC §10 hook), written to
        /var/lib/planarian/health-report.json with its signature beside it
        and the key's public half in health.pub. Minimal disclosure: unit
        statuses and incident kinds only. 0 turns them off.
      '';
    };

    posture = mkOption {
      type = types.enum [ "Relaxed" "Standard" "Guarded" "Sealed" ];
      default = "Standard";
      description = "The failure posture (SPEC §12d). Phase A ships Standard; the others are for testing.";
    };

    startupGrace = mkOption {
      type = types.ints.unsigned;
      default = 90;
      description = ''
        Seconds after a unit comes up (at boot, or when it or Planarian starts
        it) during which a failing health probe is not yet a fault: the unit
        may still be starting. A crash is never covered. Raise it for slow
        machines or services that warm up slowly; units can set their own
        (`units.<name>.startupGrace`).
      '';
    };

    maxTier = mkOption {
      type = types.enum [ "Observe" "Runtime" "Tested" ];
      default = "Tested";
      description = "Autonomy: anything above this asks first. It never turns a refusal into a permission.";
    };

    gc = {
      keepGenerations = mkOption {
        type = types.ints.positive;
        default = 10;
        description = "Keep at most this many system generations (§12b). The generations Planarian must keep (known-good, current, previous, any in flight) are never collected.";
      };
      generationsPercent = mkOption {
        type = types.numbers.between 0 100;
        default = 20;
        description = "Generations may use at most this share of the Nix store's filesystem. Older generations are collected first until both bounds hold.";
      };
      retainAllGenerations = mkOption {
        type = types.bool;
        default = false;
        description = "Never collect a system generation, even when the store is nearly full: keep the full history (for export, or to go back to any of them). Other store garbage is still collected. The two bounds above are then reported, not enforced; deleting generations is otherwise a Runtime change (§12b).";
      };
    };

    userControllable = {
      units = mkOption { type = types.listOf types.str; default = [ "pipewire" "wireplumber" ]; description = "System units any local user may restart, stop or leave alone."; };
      changes = mkOption { type = types.listOf types.str; default = [ "font-scale" "wifi-select" ]; };
      options = mkOption { type = types.listOf types.str; default = [ "font.scale" "wifi.network" ]; };
    };

    units = mkOption {
      type = types.attrsOf (types.submodule unitModule);
      default = { };
      description = "The manifest: units Planarian watches, keyed by name (e.g. `sshd`, `fs-root`).";
    };

    testBuild = mkOption {
      type = types.bool;
      default = false;
      internal = true;
      description = ''
        This configuration is the gym's VM test and may run the test build
        (the gym-hooks package, which accepts fault injection over the
        socket). Anywhere else the module refuses that package, and a test
        build that runs anyway is an Integrity failure (§12d, §15).
      '';
    };

    optionSensitivity = mkOption {
      type = types.attrsOf (types.listOf (types.enum sensitivities));
      default = {
        "services.openssh" = [ "Security" ];
        "security" = [ "Security" ];
        "users" = [ "Security" ];
        "networking.firewall" = [ "Security" ];
        "networking.nftables" = [ "Security" ];
        "networking.wireguard" = [ "Security" ];
        "networking.wg-quick" = [ "Security" ];
        "services.fail2ban" = [ "Security" ];
        "services.usbguard" = [ "Security" ];
        "services.openvpn" = [ "Security" ];
        "services.tailscale" = [ "Security" ];
        "services.strongswan" = [ "Security" ];
        "services.planarian" = [ "Security" ];
        "networking" = [ "External" ];
        "boot" = [ "Security" ];
      };
      description = "Option-path prefix → sensitivity, for changes made through the catalog.";
    };

    catalog = {
      services = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = { sshd = "services.openssh.enable"; printing = "services.printing.enable"; };
        description = "Services that `service-enable` may turn on or off, with their enable option.";
      };
      fontScaleOption = mkOption { type = types.str; default = ""; };
      fontScales = mkOption { type = types.listOf types.str; default = [ "0.75" "1" "1.25" "1.5" "1.75" "2" ]; };
      keyboardLayoutOptions = mkOption { type = types.listOf types.str; default = [ ]; };
      keyboardLayouts = mkOption { type = types.listOf types.str; default = [ "us" ]; };
      wifiOption = mkOption { type = types.str; default = ""; };
      wifiNetworks = mkOption { type = types.listOf types.str; default = [ ]; };
      listenAddresses = mkOption {
        type = types.attrsOf (types.submodule { options = { option = mkOption { type = types.str; }; permitted = mkOption { type = types.listOf types.str; }; }; });
        default = { };
      };
      gymChoices = mkOption {
        type = types.attrsOf (types.submodule { options = {
          option = mkOption { type = types.str; };
          arg = mkOption { type = types.str; };
          permitted = mkOption { type = types.listOf types.str; };
        }; });
        default = { };
        internal = true;
        description = "Test-only catalog entries for the gym's VMs (`gym:<name>`).";
      };
    };

    export = mkOption {
      type = types.attrs;
      readOnly = true;
      internal = true;
      description = "What Planarian reads from an evaluated generation (also at /etc/planarian/export.json).";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.package.testBuild or false) || cfg.testBuild;
        message = "services.planarian.package is the gym's test build (planarian-gym-hooks), which accepts fault injection over its socket; it is for the gym's VM tests only (SPEC §15).";
      }
      {
        assertion = weakExternalEdges == [ ];
        message = "services.planarian: an edge to an external dependency must be Requires, or Diagnostic with confidence at least 700 (the diagnoser's threshold), so an outage is diagnosed as one and never restarts a local unit (SPEC §10). Too weak: ${lib.concatStringsSep ", " weakExternalEdges}.";
      }
    ];

    services.planarian.units = {
      fs-root = mkDefault { kind = "device"; };
      fs-journal = mkDefault { kind = "device"; };
      fs-boot = mkIf (config.fileSystems ? "/boot") (mkDefault { kind = "device"; });
      fs-nix = mkIf (config.fileSystems ? "/nix") (mkDefault { kind = "device"; });
      sshd = mkIf config.services.openssh.enable (mkDefault { synonyms = [ "ssh" ]; });
      NetworkManager = mkIf config.networking.networkmanager.enable (mkDefault { synonyms = [ "wifi" "wi-fi" "network" "internet" ]; });
      # The desktop's own unit: its absence is harm, whoever stopped it (§11).
      ${dmUnit} = mkIf hasDm (mkDefault { synonyms = [ "login screen" "greeter" ]; inferStops = false; });
      graphical-session = mkIf hasDesktop (mkDefault { kind = "target"; when = "seat"; synonyms = [ "desktop" ]; });
      pipewire = mkIf config.services.pipewire.enable (mkDefault { scope = "user"; synonyms = [ "sound" "audio" ]; });
      # P24 (owner decision, 1 Nov): PipeWire's session manager, per user.
      # Upstream's unit carries BindsTo=pipewire.service, which the module
      # cannot derive for a user unit: declared, so a PipeWire fault is
      # diagnosed at PipeWire.
      wireplumber = mkIf (config.services.pipewire.enable && config.services.pipewire.wireplumber.enable)
        (mkDefault { scope = "user"; edges = [ { to = "service@0:pipewire"; kind = "Requires"; } ]; });
    };

    services.planarian.holdUnits = networkTools;

    services.planarian.export = {
      units = unitsOf "system";
      # §12d: every system service that is a network tool, declared or not
      # (netwatch writes a footprint for each when its watch attaches).
      inherit networkTools;
      # The network tools not ordered after netwatch (its startup chain;
      # nix/netwatch-unordered.nix): their early changes may precede its
      # attach, and read as pre-attach steering (§12d).
      inherit (cfg) networkToolsUnordered;
      # The network tools the systemd initrd also runs: their initrd run
      # precedes netwatch; a stage-2 start is ordered after it (§12d).
      inherit (cfg) networkToolsInitrd;
      userUnits = unitsOf "user";
      coreUnits = {
        "planariad.service" = unitHash "planariad.service";
        "planarian-recovery.service" = unitHash "planarian-recovery.service";
      };
      devices = lib.mapAttrs (_: u: u.sysfs) (lib.filterAttrs (_: u: u.kind == "device" && u.sysfs != null) cfg.units);
      # §12e: the security floor rises when a committed generation drops a
      # package's nixpkgs knownVulnerabilities, over the inspected set above.
      # Reading `meta` does not trip nixpkgs' insecure-package check.
      packages = builtins.listToAttrs (map (p: { name = lib.getName p; value = lib.getVersion p; }) inspected);
      insecure = lib.unique (map lib.getName (lib.filter insecureIn inspected));
      # §15: every system service and the files that define it (NixOS's
      # definition locations), watched or not, so a declaration that turns
      # out to be malicious can be reported with its origin.
      declarations =
        let
          # The service names one definition sets, through mkIf/mkMerge.
          names = v:
            if !builtins.isAttrs v then [ ]
            else if (v._type or null) == "if" then (if v.condition then names v.content else [ ])
            else if (v._type or null) == "merge" then lib.concatMap names v.contents
            else if builtins.elem (v._type or null) [ "override" "order" ] then names v.content
            # A service set to a false `mkIf` is not declared by this file.
            else lib.filter (n: !(builtins.isAttrs v.${n} && (v.${n}._type or null) == "if" && !v.${n}.condition))
              (builtins.attrNames v);
          perDef = d:
            let r = builtins.tryEval (names d.value);
            in lib.genAttrs (if r.success then r.value else [ ]) (_: [ (toString d.file) ]);
          all = lib.zipAttrsWith (_: lib.concatLists) (map perDef options.systemd.services.definitionsWithLocations);
        in
        lib.filterAttrs (n: _: config.systemd.services ? ${n}) all;
      inputs = cfg.flakeInputs;
      # §11 sensitivity completeness: every system service NixOS defines
      # that the manifest does not declare has the shipped tables' entry,
      # so only a unit in neither fails closed.
      services = lib.mapAttrs (n: _: defaultSensitivity n)
        (lib.filterAttrs (n: _: !(cfg.units ? ${n})) config.systemd.services);
    };

    environment.etc."planarian/export.json".text = builtins.toJSON cfg.export;

    environment.etc."planarian/config.json".text = builtins.toJSON {
      inherit (cfg) owner flakeAttr maxTier optionSensitivity;
      allowTestBuild = cfg.testBuild;
      stateDir = "/var/lib/planarian";
      userControllableUnits = cfg.userControllable.units;
      userControllableChanges = cfg.userControllable.changes;
      userControllableOptions = cfg.userControllable.options;
      runtimeAllowlist = [ "font.scale" "wifi.network" ];
      catalog = {
        inherit (cfg.catalog) services fontScaleOption fontScales keyboardLayoutOptions keyboardLayouts wifiOption wifiNetworks;
        listenAddresses = lib.mapAttrs (_: l: { inherit (l) option permitted; }) cfg.catalog.listenAddresses;
        gymChoices = lib.mapAttrs (_: c: { inherit (c) option arg permitted; }) cfg.catalog.gymChoices;
      };
      runtimeOptions = lib.optional (cfg.catalog.fontScaleOption != "") {
        path = "font.scale";
        keywords = [ "text" "font" "fonts" "letters" "writing" ];
        current = let v = optionValue cfg.catalog.fontScaleOption; in if v == null then "1" else toString v;
        step = "0.25";
        min = "0.75";
        max = "2";
      };
      devices = cfg.export.devices;
      adminGroup = "planarian-admin";
      gc = {
        keepGenerations = cfg.gc.keepGenerations;
        generationsPermille = builtins.floor (cfg.gc.generationsPercent * 10);
        keepEmergency = 3;
        retainAll = cfg.gc.retainAllGenerations;
      };
      journalBytes = 64 * 1024 * 1024;
      startupGraceSecs = cfg.startupGrace;
      sessionCompositors = cfg.sessionCompositors;
      inherit (cfg) posture externalSource;
      bootReadyTimeoutSecs = cfg.bootReadyTimeout;
      agentLimits = { inherit (cfg.agents.limits) tasksMax memoryMax perUid; };
      healthReportSecs = cfg.healthReport.interval;
    };

    # With the console: its launcher entry and icons too.
    environment.systemPackages = [ cfg.package ] ++ lib.optional (cfg.console.enable || cfg.tray.enable) cfg.console.package;
    users.groups.planarian-admin = { };

    # The healer is not the patient (Principle 1): no activation restarts or
    # stops these two (NixOS honours X-RestartIfChanged/X-StopIfChanged), and a
    # candidate whose unit files for them differ is refused as touching the core.
    systemd.services.planarian-recovery = {
      description = "Planarian recovery watchdog";
      wantedBy = [ "multi-user.target" ];
      before = [ "planariad.service" ];
      restartIfChanged = false;
      stopIfChanged = false;
      path = [ config.nix.package pkgs.git config.systemd.package pkgs.util-linux pkgs.getent ];
      environment.PLANARIAN_CONFIG = "/etc/planarian/config.json";
      serviceConfig = {
        # On btrfs the journal is rewritten in place: mark its directory
        # nodatacow before the journal is first created (§12c), so a write
        # into the preallocation needs no new space (after a snapshot, once).
        ExecStartPre = "-${pkgs.writeShellScript "planarian-journal-fs" ''
          if [ "$(${pkgs.coreutils}/bin/stat -f -c %T /var/lib/planarian)" = btrfs ]; then
            ${pkgs.e2fsprogs}/bin/chattr +C /var/lib/planarian
          fi
        ''}";
        ExecStart = "${cfg.package}/bin/planarian-recovery";
        Restart = "always";
        RestartSec = 2;
        StateDirectory = "planarian";
      };
    };

    systemd.user.services.planarian-console = mkIf cfg.console.enable {
      description = "Planarian console";
      wantedBy = [ "graphical-session.target" ];
      partOf = [ "graphical-session.target" ];
      after = [ "graphical-session.target" ];
      serviceConfig = {
        ExecStart = "${cfg.console.package}/bin/planarian-console";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };

    systemd.user.services.planarian-tray = mkIf cfg.tray.enable {
      description = "Planarian status indicator";
      wantedBy = [ "graphical-session.target" ];
      partOf = [ "graphical-session.target" ];
      after = [ "graphical-session.target" ];
      serviceConfig = {
        ExecStart = "${cfg.console.package}/bin/planarian-tray";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };

    systemd.services.planariad = {
      description = "Planarian";
      wantedBy = [ "multi-user.target" ];
      wants = [ "planarian-recovery.service" ];
      after = [ "planarian-recovery.service" ];
      restartIfChanged = false;
      stopIfChanged = false;
      # nftables: the daemon checks the hold's table each tick (§12d).
      path = [ config.nix.package pkgs.git config.systemd.package pkgs.util-linux pkgs.kmod pkgs.getent pkgs.nftables ]
        ++ lib.optional config.networking.networkmanager.enable config.networking.networkmanager.package;
      environment.PLANARIAN_CONFIG = "/etc/planarian/config.json";
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/planariad";
        Restart = "always";
        RestartSec = 2;
        StateDirectory = "planarian";
        RuntimeDirectory = "planarian";
        RuntimeDirectoryPreserve = "yes";
      };
    };
  };
}
