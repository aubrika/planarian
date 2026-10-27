# The gym's VM harness (SPEC §15): one NixOS test per catalog entry, on a VM
# that carries the gym's fixtures for real. The in-VM half is
# `planarian-gym vm …` (crates/gym/src/live.rs); this file builds the VM and
# drives the steps that need the host: reboot, suspend and wake, hot-unplug,
# and the upstream machine.
#
# Planarian here is the `gymHooks` build (fault injection through
# /run/planarian-gym). Configuration changes cannot be built inside a VM
# test, so every candidate the catalog's changes can produce is prebuilt as a
# specialisation, and /etc/nixos is a shim flake that picks one by the
# assignments in planarian/overrides.nix (as in vm-generations.nix).
#
# Each test writes verdict.json to its output and always succeeds; the score
# is the verdicts (`nix run .#gym-vm`).
{ pkgs, self, id }:

let
  lib = pkgs.lib;
  catalog = ../../crates/gym/catalog/phase-a.toml;
  gymPkg = pkgs.callPackage ../package.nix { gymHooks = true; };

  # Every override set the catalog's changes produce (base: none).
  candidates = {
    base = { };
    listen = { services.gym-web.listenAddress = "192.0.2.10"; };
    font = { planarian.reference.fontScale = "1.25"; };
    sshd-off = { services.openssh.enable = false; };
    sshd-on = { services.openssh.enable = true; };
  };
  # What Planarian evaluates besides the export (nix/backends apply_expr).
  optionPaths = [
    "services.gym-web.listenAddress"
    "planarian.reference.fontScale"
    "services.openssh.enable"
    "services.gym-extra.enable"
  ];

  fixture = pkgs.writeScript "gym-fixture" ''
    #!${pkgs.python3}/bin/python3
    # A gym fixture service: listens on a port (HTTP for --http) and honours
    # knobs in /var/lib/gym-knobs/<name>/: fail_on_start, fail_after,
    # health (HTTP status), health_delay / probe_delay (answer late).
    import http.server, os, socketserver, sys, threading, time, json
    name, port = sys.argv[1], int(sys.argv[2])
    http_mode = "--http" in sys.argv
    knobs = f"/var/lib/gym-knobs/{name}"
    def knob(k):
        try: return open(f"{knobs}/{k}").read().strip()
        except OSError: return None
    def secs(v):
        if not v: return 0
        v = v.strip('"')
        for suf, mul in (("ms", .001), ("s", 1), ("m", 60), ("h", 3600)):
            if v.endswith(suf) and v[:-len(suf)].isdigit(): return int(v[:-len(suf)]) * mul
        return 0
    if knob("fail_on_start") in ("true", "True"):
        print("failing on start (knob)", file=sys.stderr); sys.exit(1)
    state = f"/var/lib/{name}/state.json"
    if os.path.exists(state):
        try: json.load(open(state))
        except ValueError:
            print(f"{state} is corrupt", file=sys.stderr); sys.exit(1)
    fa = secs(knob("fail_after"))
    if fa:
        threading.Timer(fa, lambda: os._exit(1)).start()
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            d = secs(knob("health_delay") or knob("probe_delay"))
            if d: time.sleep(d)
            code = int(knob("health") or 200)
            self.send_response(code); self.end_headers(); self.wfile.write(b"ok\n")
        def log_message(self, *a): pass
    class S(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True; daemon_threads = True
    if http_mode:
        S(("127.0.0.1", port), H).serve_forever()
    else:
        class T(socketserver.BaseRequestHandler):
            def handle(self):
                d = secs(knob("probe_delay"))
                if d: time.sleep(d)
        S(("127.0.0.1", port), T).serve_forever()
  '';

  svc = name: args: extra: lib.recursiveUpdate {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${fixture} ${name} ${args}";
      StateDirectory = name;
    };
  } extra;

  machineModule = { config, pkgs, ... }:
    let
      candidatesJson = pkgs.writeText "candidates.json" (builtins.toJSON (lib.mapAttrsToList (n: a: {
        name = n;
        assign = a;
        facts = facts (if n == "base" then config else config.specialisation.${n}.configuration);
      }) candidates));
    in {
    imports = [ self.nixosModules.default self.nixosModules.reference ];

    options.services.gym-web.listenAddress = lib.mkOption { type = lib.types.str; default = "127.0.0.1"; };
    options.services.gym-extra.enable = lib.mkEnableOption "gym-extra";
    # Only the booted base sets up /etc/nixos (a specialisation has none of its own).
    options.gym.isBase = lib.mkOption { type = lib.types.bool; default = true; };

    config = {
      # No desktop in this VM (the desktop entries need the COSMIC variant).
      services.desktopManager.cosmic.enable = lib.mkForce false;
      services.displayManager.cosmic-greeter.enable = lib.mkForce false;
      planarian.reference.verboseBoot = true;
      services.planarian.console.enable = lib.mkForce false;

      services.planarian = {
        enable = true;
        package = gymPkg;
        owner = "/etc/nixos";
        flakeAttr = "nixosConfigurations.machine";
        startupGrace = 20;
        catalog.services = { sshd = "services.openssh.enable"; gym-extra = "services.gym-extra.enable"; };
        catalog.listenAddresses.gym-web = { option = "services.gym-web.listenAddress"; permitted = [ "127.0.0.1" "192.0.2.10" ]; };
        units = {
          gym-web = {
            synonyms = [ "web server" "web" ];
            probes = [
              { id = "gym-web-http"; type = "http"; url = "http://127.0.0.1:8080/health"; establishes = "gym-web-http"; }
              { id = "gym-web-tcp"; type = "tcp"; addr = "127.0.0.1:8080"; establishes = "gym-web-tcp"; }
            ];
          };
          gym-db.probes = [ { id = "gym-db-tcp"; type = "tcp"; addr = "127.0.0.1:5432"; establishes = "gym-db-tcp"; } ];
          gym-app.probes = [ { id = "gym-app-tcp"; type = "tcp"; addr = "127.0.0.1:8081"; establishes = "gym-app-tcp"; } ];
          gym-cache.probes = [ { id = "gym-cache-tcp"; type = "tcp"; addr = "127.0.0.1:6379"; establishes = "gym-cache-tcp"; } ];
          gym-metrics = {
            restartDisruption = "None";
            probes = [ { id = "gym-metrics-tcp"; type = "tcp"; addr = "127.0.0.1:9100"; establishes = "gym-metrics-tcp"; } ];
          };
          gym-flap.probes = [ { id = "gym-flap-active"; type = "systemd-active"; establishes = "gym-flap-active"; } ];
          gym-restartful.probes = [ { id = "gym-restartful-active"; type = "systemd-active"; establishes = "gym-restartful-active"; } ];
          gym-upstream-client = {
            probes = [ { id = "gym-upstream-client-http"; type = "http"; url = "http://10.0.2.2:9000/health"; establishes = "gym-upstream-client-http"; } ];
            edges = [ { to = "service:external:gym-upstream"; kind = "Requires"; } ];
          };
          "external:gym-upstream" = {
            sensitivity = [ "External" ];
            restartDisruption = "None";
            deriveEdges = false;
            probes = [ { id = "gym-upstream-tcp"; type = "tcp"; addr = "10.0.2.2:9000"; establishes = "gym-upstream-tcp"; } ];
          };
          snd-hda0 = { kind = "device"; sysfs = "/sys/bus/pci/devices/0000:00:1b.0"; };
          net-gym0 = { kind = "device"; sysfs = "/sys/bus/pci/devices/0000:00:1d.0"; sensitivity = [ "External" ]; restartDisruption = "ConnectivityLoss"; };
          gpu0 = { kind = "device"; sysfs = "/sys/bus/pci/devices/0000:00:1c.0"; restartDisruption = "SessionLoss"; };
          wireplumber = { scope = "user"; };
        };
      };

      systemd.services = {
        gym-web = svc "gym-web" "8080 --http" { };
        gym-db = svc "gym-db" "5432" { };
        gym-cache = svc "gym-cache" "6379" { };
        gym-metrics = svc "gym-metrics" "9100" { };
        gym-app = svc "gym-app" "8081" {
          requires = [ "gym-db.service" ];
          after = [ "gym-db.service" "gym-cache.service" ];
          wants = [ "gym-metrics.service" ];
        };
        gym-flap = svc "gym-flap" "7001" { };
        gym-restartful = svc "gym-restartful" "7002" {
          serviceConfig = { Restart = "always"; RestartSec = "5s"; };
          startLimitBurst = 3;
        };
        gym-upstream-client = svc "gym-upstream-client" "7003" { };
        gym-extra = lib.mkIf config.services.gym-extra.enable (svc "gym-extra" "7004" { });
      };

      services.openssh.enable = true;
      networking.networkmanager.enable = true;
      networking.networkmanager.unmanaged = [ "type:ethernet" ];
      services.pipewire = { enable = true; pulse.enable = true; };
      networking.firewall.enable = false;
      # The catalog's upstream is "the VM host" at 10.0.2.2, which on eth0 is QEMU's
      # user-mode gateway; a host route sends it to the upstream node instead.
      networking.interfaces.eth1.ipv4.routes = [ { address = "10.0.2.2"; prefixLength = 32; } ];

      users.users = {
        alice = { isNormalUser = true; uid = 1000; };
        bob = { isNormalUser = true; uid = 1001; extraGroups = [ "planarian-admin" "wheel" ]; };
        carol = { isNormalUser = true; uid = 1002; };
      };

      environment.systemPackages = [ gymPkg pkgs.git pkgs.util-linux pkgs.iptables pkgs.curl ];
      environment.variables.PLANARIAN_GYM_CATALOG = "${catalog}";
      programs.git.config.safe.directory = "*";

      # Devices at fixed PCI addresses (their sysfs paths are in the manifest).
      virtualisation = {
        memorySize = 3072;
        cores = 2;
        diskSize = 8192;
        emptyDiskImages = [ 512 ];
        qemu.options = [
          "-device intel-hda,addr=0x1b" "-device hda-duplex"
          "-device virtio-gpu-pci,addr=0x1c"
          "-netdev user,id=gymnet" "-device virtio-net-pci,netdev=gymnet,addr=0x1d"
          "-device qemu-xhci,id=xhci" "-drive if=none,id=gymusb,driver=null-co,size=16M"
          "-device usb-storage,bus=xhci.0,drive=gymusb,id=gymusbdev"
        ];
      };
      boot.kernelModules = [ "snd_hda_intel" "virtio_gpu" ];
      # The journal on its own small filesystem (fill_fs fs-journal).
      fileSystems."/var/lib/planarian" = { device = "/dev/vdb"; fsType = "ext4"; autoFormat = true; };

      # The prebuilt candidates and out-of-band generations.
      specialisation = lib.mapAttrs (_: s: { configuration = { imports = [ s ]; gym.isBase = false; }; }) ((lib.mapAttrs (n: a:
        lib.mapAttrsRecursive (_: v: lib.mkOverride 90 v) a
      ) (removeAttrs candidates [ "base" ])) // {
        gym-web-false.systemd.services.gym-web.serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/false";
        weak-sshd-probe.services.planarian.units.sshd.probes = [
          { id = "sshd-tcp"; type = "tcp"; addr = "127.0.0.1:22"; timeout = 600; establishes = "weakened"; }
        ];
        throwaway0.environment.etc."gym-throwaway".text = "0";
        throwaway1.environment.etc."gym-throwaway".text = "1";
      });

      # /etc/nixos: the shim flake (written once; Planarian edits its overrides).
      systemd.services.gym-owner = lib.mkIf config.gym.isBase {
        wantedBy = [ "multi-user.target" ];
        before = [ "planariad.service" ];
        unitConfig.ConditionPathExists = "!/etc/nixos/flake.nix";
        serviceConfig.Type = "oneshot";
        path = [ pkgs.git pkgs.coreutils ];
        script = ''
          mkdir -p /etc/nixos/planarian
          cd /etc/nixos
          install -m644 ${shim} flake.nix
          install -m644 ${candidatesJson} candidates.json
          install -m644 ${../template/planarian/overrides.nix} planarian/overrides.nix
          echo '{ }' > configuration.nix
          booted=$(readlink -f /run/booted-system)
          ln -sfn $booted sys-base
          for c in ${lib.concatStringsSep " " (lib.attrNames (removeAttrs candidates [ "base" ]))}; do
            ln -sfn $(readlink -f $booted/specialisation/$c) sys-$c
          done
          git init -q && git add -A && git -c user.email=gym@planarian -c user.name=gym commit -qm owner
        '';
      };
    };
  };

  # Facts per candidate: the export and the option values Planarian reads.
  facts = c: lib.foldl' lib.recursiveUpdate
    { services.planarian.export = c.services.planarian.export; }
    (map (p: let path = lib.splitString "." p; in lib.setAttrByPath path (lib.attrByPath path null c)) optionPaths);

  shim = pkgs.writeText "flake.nix" ''
    # The owner flake, as a shim (nix/tests/gym-vm.nix).
    {
      outputs = { self }:
        let
          stub = { mkOverride = p: v: v; mkForce = v: v; mkDefault = v: v; };
          assigned = (import ./planarian/overrides.nix) { lib = stub; };
          all = builtins.fromJSON (builtins.readFile ./candidates.json);
          match = builtins.filter (c: c.assign == assigned) all;
          pick = if match == [ ] then throw "gym: no prebuilt candidate for these overrides" else builtins.head match;
          systems = { ${lib.concatStringsSep " " (map (c: "${c} = ./sys-${c};") (lib.attrNames candidates))} };
        in {
          nixosConfigurations.machine = {
            config = pick.facts // { system.build.toplevel = systems.''${pick.name}; };
            options = { };
          };
        };
    }
  '';

  test = pkgs.testers.runNixOSTest {
      name = "gym-${id}";
      nodes.machine = machineModule;
      nodes.upstream = { pkgs, ... }: {
        networking.interfaces.eth1.ipv4.addresses = lib.mkAfter [ { address = "10.0.2.2"; prefixLength = 32; } ];
        environment.etc.health.text = "ok\n";
        networking.firewall.enable = false;
        systemd.services.gym-upstream = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 9000 --bind 0.0.0.0 --directory /etc";
        };
      };
      testScript = ''
        import json, time
        ID = ${builtins.toJSON id}
        # The upstream first, so the machine never boots without it.
        upstream.start()
        upstream.wait_for_unit("gym-upstream.service")
        machine.start()
        machine.wait_for_unit("planariad.service")
        gym = "planarian-gym vm"
        plan = json.loads(machine.succeed(f"{gym} plan --id {ID}"))
        print(plan)
        if any(s.startswith("unsupported") for s in plan["steps"]):
            machine.succeed(f"mkdir -p /var/lib/gym-run && {gym} judge --id {ID} || true")
        else:
            print(machine.succeed(f"{gym} begin --id {ID} 2>&1"))
            import tomllib
            entry = next(e for e in tomllib.load(open("${catalog}", "rb"))["fault"] if e["id"] == ID)
            steps = []
            for k in ("setup", "inject", "after"):
                v = entry.get(k, [])
                steps += [v] if isinstance(v, dict) else v
            for i, (kind, st) in enumerate(zip(plan["steps"], steps)):
                raw = st.get("raw")
                if kind == "vm":
                    print(machine.execute(f"{gym} step --id {ID} --index {i} 2>&1")[1])
                elif kind == "host":
                    if raw == "reboot":
                        machine.shutdown(); machine.start(); machine.wait_for_unit("planariad.service")
                        machine.succeed("systemd-run --unit=gym-sampler -E PLANARIAN_GYM_CATALOG planarian-gym vm sample")
                    elif raw == "suspend":
                        machine.execute("systemctl suspend &")
                        d = st.get("duration", "60s")
                        time.sleep(int(d[:-1]) * (60 if d.endswith("m") else 1))
                        machine.send_monitor_command("system_wakeup")
                    elif raw == "hotunplug":
                        machine.send_monitor_command("device_del gymusbdev")
                    elif raw == "stop_host_service":
                        upstream.succeed("systemctl stop gym-upstream")
                    elif raw == "start_host_service":
                        upstream.succeed("systemctl start gym-upstream")
            print(machine.succeed(f"{gym} judge --id {ID} 2>&1"))
        machine.copy_from_vm("/var/lib/gym-run/verdict.json", "")
        if machine.execute("test -e /var/lib/gym-run/evidence.json")[0] == 0:
            machine.copy_from_vm("/var/lib/gym-run/evidence.json", "")
      '';
    };
in
test
