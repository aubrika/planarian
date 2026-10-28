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
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption mkEnableOption mkIf mkDefault types;
  cfg = config.services.planarian;

  sensitivities = [ "Routine" "Security" "UserData" "External" "Core" ];
  disruptions = [ "None" "Brief" "SessionLoss" "DataInterruption" "ConnectivityLoss" ];

  # Shipped tables (§9): the defaults when a unit doesn't say.
  defaultSensitivity = name:
    if builtins.elem name [ "sshd" "polkit" "systemd-logind" ] then [ "Security" ]
    else if builtins.elem name [ "NetworkManager" "wpa_supplicant" "systemd-networkd" ] then [ "External" ]
    else [ "Routine" ];
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
      when = mkOption { type = types.enum [ "always" "session" "ac" "battery" ]; default = "always"; };
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
      session = { SessionEstablished = { uid = null; }; };
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

  probeJSON = p: {
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

    optionSensitivity = mkOption {
      type = types.attrsOf (types.listOf (types.enum sensitivities));
      default = {
        "services.openssh" = [ "Security" ];
        "security" = [ "Security" ];
        "users" = [ "Security" ];
        "networking.firewall" = [ "Security" ];
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
    };

    export = mkOption {
      type = types.attrs;
      readOnly = true;
      internal = true;
      description = "What Planarian reads from an evaluated generation (also at /etc/planarian/export.json).";
    };
  };

  config = mkIf cfg.enable {
    services.planarian.units = {
      fs-root = mkDefault { kind = "device"; };
      fs-journal = mkDefault { kind = "device"; };
      fs-boot = mkIf (config.fileSystems ? "/boot") (mkDefault { kind = "device"; });
      fs-nix = mkIf (config.fileSystems ? "/nix") (mkDefault { kind = "device"; });
      sshd = mkIf config.services.openssh.enable (mkDefault { synonyms = [ "ssh" ]; });
      NetworkManager = mkIf config.networking.networkmanager.enable (mkDefault { synonyms = [ "wifi" "wi-fi" "network" "internet" ]; });
      ${dmUnit} = mkIf hasDm (mkDefault { synonyms = [ "login screen" "greeter" ]; });
      graphical-session = mkIf hasDesktop (mkDefault { kind = "target"; when = "session"; synonyms = [ "desktop" ]; });
      pipewire = mkIf config.services.pipewire.enable (mkDefault { scope = "user"; synonyms = [ "sound" "audio" ]; });
    };

    services.planarian.export = {
      units = unitsOf "system";
      userUnits = unitsOf "user";
      coreUnits = {
        "planariad.service" = unitHash "planariad.service";
        "planarian-recovery.service" = unitHash "planarian-recovery.service";
      };
      devices = lib.mapAttrs (_: u: u.sysfs) (lib.filterAttrs (_: u: u.kind == "device" && u.sysfs != null) cfg.units);
    };

    environment.etc."planarian/export.json".text = builtins.toJSON cfg.export;

    environment.etc."planarian/config.json".text = builtins.toJSON {
      inherit (cfg) owner flakeAttr maxTier optionSensitivity;
      stateDir = "/var/lib/planarian";
      userControllableUnits = cfg.userControllable.units;
      userControllableChanges = cfg.userControllable.changes;
      userControllableOptions = cfg.userControllable.options;
      runtimeAllowlist = [ "font.scale" "wifi.network" ];
      catalog = {
        inherit (cfg.catalog) services fontScaleOption fontScales keyboardLayoutOptions keyboardLayouts wifiOption wifiNetworks;
        listenAddresses = lib.mapAttrs (_: l: { inherit (l) option permitted; }) cfg.catalog.listenAddresses;
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
      };
      journalBytes = 64 * 1024 * 1024;
      startupGraceSecs = cfg.startupGrace;
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
      path = [ config.nix.package pkgs.git config.systemd.package pkgs.util-linux ];
      environment.PLANARIAN_CONFIG = "/etc/planarian/config.json";
      serviceConfig = {
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
      path = [ config.nix.package pkgs.git config.systemd.package pkgs.util-linux pkgs.kmod ]
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
