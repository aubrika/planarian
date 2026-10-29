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
    kparam = { gym.kernelParam = "virtio_gpu.modeset=0"; };
    payload = { services.gym-bad-payload.enable = true; };
  };
  # What Planarian evaluates besides the export (nix/backends apply_expr).
  optionPaths = [
    "services.gym-web.listenAddress"
    "planarian.reference.fontScale"
    "services.openssh.enable"
    "services.gym-extra.enable"
    "gym.kernelParam"
    "services.gym-bad-payload.enable"
  ];

  fixture = pkgs.writeScript "gym-fixture" ''
    #!${pkgs.python3}/bin/python3
    # A gym fixture service: listens on a port (HTTP for --http) and honours
    # knobs in /var/lib/gym-knobs/<name>/: fail_on_start, fail_after,
    # health (HTTP status), health_delay (answer late), probe_delay (answer
    # late; the harness also drops packets to the port, so connecting stalls).
    import http.server, os, socketserver, sys, threading, time, json
    name, port = sys.argv[1], int(sys.argv[2])
    http_mode = "--http" in sys.argv
    # --addr: the address to bind (an address on no interface fails to bind).
    addr = sys.argv[sys.argv.index("--addr") + 1] if "--addr" in sys.argv else "127.0.0.1"
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
    # A one-off knob (set_knob, marked <knob>.once) lasts until the next start;
    # a persistent one (set_persistent_knob) survives restarts.
    if os.path.isdir(knobs):
        for f in os.listdir(knobs):
            if f.endswith(".once"):
                for g in (f, f[:-len(".once")]):
                    try: os.remove(f"{knobs}/{g}")
                    except OSError: pass
    if knob("fail_on_start") in ("true", "True"):
        print("failing on start (knob)", file=sys.stderr); sys.exit(1)
    state = f"/var/lib/{name}/state.json"
    if os.path.exists(state):
        try: json.load(open(state))
        except ValueError:
            print(f"{state} is corrupt", file=sys.stderr); sys.exit(1)
    # fail_after: exit that long after starting, or after the knob appears,
    # whichever is later (it can be set while the service runs).
    def fail_after():
        since = None
        while True:
            fa = secs(knob("fail_after"))
            if fa and since is None:
                since = time.monotonic()
            if fa and time.monotonic() - since >= fa:
                print(f"failing after {fa}s (knob)", file=sys.stderr); os._exit(1)
            time.sleep(0.5)
    threading.Thread(target=fail_after, daemon=True).start()
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
        S((addr, port), H).serve_forever()
    else:
        class T(socketserver.BaseRequestHandler):
            def handle(self):
                d = secs(knob("probe_delay"))
                if d: time.sleep(d)
        S((addr, port), T).serve_forever()
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
      # One hostapd unit per access point (see the Wi-Fi notes below).
      accessPoints = lib.listToAttrs (lib.imap0 (i: ssid: lib.nameValuePair "hostapd-${ssid}" {
        wantedBy = [ "multi-user.target" ];
        bindsTo = [ "sys-subsystem-net-devices-wlan${toString i}.device" ];
        after = [ "sys-subsystem-net-devices-wlan${toString i}.device" ];
        serviceConfig.ExecStart = "${pkgs.hostapd}/bin/hostapd ${pkgs.writeText "${ssid}.conf" ''
          interface=wlan${toString i}
          driver=nl80211
          ssid=${ssid}
          hw_mode=g
          channel=${toString (1 + 5 * i)}
        ''}";
      }) [ "gym-ap-a" "gym-ap-b" ]);
      candidatesJson = pkgs.writeText "candidates.json" (builtins.toJSON (lib.mapAttrsToList (n: a: {
        name = n;
        assign = a;
        facts = facts (if n == "base" then config else config.specialisation.${n}.configuration);
      }) candidates));
    in {
    imports = [ self.nixosModules.default self.nixosModules.reference ./gym-payload.nix ];

    options.services.gym-web.listenAddress = lib.mkOption { type = lib.types.str; default = "127.0.0.1"; };
    options.services.gym-extra.enable = lib.mkEnableOption "gym-extra";
    # Only the booted base sets up /etc/nixos (a specialisation has none of its own).
    options.gym.isBase = lib.mkOption { type = lib.types.bool; default = true; };
    # A boot-only change for gym:kernel-param (desktop-boot-fails-rollback).
    options.gym.kernelParam = lib.mkOption { type = lib.types.str; default = ""; };

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
        catalog.services = {
          sshd = "services.openssh.enable";
          gym-extra = "services.gym-extra.enable";
          gym-bad-payload = "services.gym-bad-payload.enable";
        };
        catalog.listenAddresses.gym-web = { option = "services.gym-web.listenAddress"; permitted = [ "127.0.0.1" "192.0.2.10" ]; };
        catalog.gymChoices."gym:kernel-param" = { option = "gym.kernelParam"; arg = "param"; permitted = [ "virtio_gpu.modeset=0" ]; };
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
          snd-hda0 = {
            kind = "device";
            sysfs = "/sys/bus/pci/devices/0000:00:1b.0";
            # Driven, not just bound: a driver that binds but cannot drive
            # the card (vfio-pci) leaves the kernel with no sound card.
            probes = [ {
              id = "snd-hda0-driven";
              type = "exec";
              argv = [ "${pkgs.gnugrep}/bin/grep" "-qv" "no soundcards" "/proc/asound/cards" ];
              establishes = "the sound card is driven";
            } ];
          };
          # As in the fake's fixtures: alice's sound needs the sound card. (A
          # full definition: beside the module's mkDefault one, a partial one
          # would replace it and lose the user scope.)
          pipewire = {
            scope = "user";
            synonyms = [ "sound" "audio" ];
            edges = [ { to = "device:snd-hda0"; kind = "Requires"; } ];
            # Real pipewire keeps running when its card goes; the user just
            # loses sound. As the fake models it, pipewire degrades without a
            # card to drive (the kernel lists none).
            probes = [ {
              id = "pipewire-has-a-card";
              type = "exec";
              argv = [ "${pkgs.gnugrep}/bin/grep" "-qv" "no soundcards" "/proc/asound/cards" ];
              establishes = "pipewire has a sound card to drive";
            } ];
          };
          net-gym0 = { kind = "device"; sysfs = "/sys/bus/pci/devices/0000:00:1d.0"; sensitivity = [ "External" ]; restartDisruption = "ConnectivityLoss"; };
          gpu0 = { kind = "device"; sysfs = "/sys/bus/pci/devices/0000:00:1c.0"; restartDisruption = "SessionLoss"; };
          # The USB stick's storage interface, wherever it enumerates (udev
          # links it below while the stick is plugged in).
          # Removable: expected only while it is plugged in.
          gym-usb0 = { kind = "device"; sysfs = "/run/gym-usb0"; restartDisruption = "None"; whenDevice = "device:gym-usb0"; };
          # The stand-in desktop (below): the login screen, and each session's
          # graphical-session.target (its canonical probe is the 60 s deadline).
          display-manager.synonyms = [ "login screen" "greeter" ];
          graphical-session = { kind = "target"; when = "session"; synonyms = [ "desktop" ]; };
          NetworkManager = {
            runtimeRepair = "wifi.network";
            probes = [ {
              id = "wifi-associated";
              type = "exec";
              argv = [ "${pkgs.writeShellScript "wifi-associated" ''
                ${pkgs.networkmanager}/bin/nmcli -g GENERAL.STATE device show wlan2 | ${pkgs.gnugrep}/bin/grep -q '^100'
              ''}" ];
              establishes = "wlan2 is associated with a network";
            } ];
          };
          gym-usb-reader = {
            whenDevice = "device:gym-usb0";
            probes = [ { id = "gym-usb-reader-active"; type = "systemd-active"; establishes = "gym-usb-reader-active"; } ];
          };
          wireplumber = { scope = "user"; };
        };
      };

      systemd.services."hostapd-gym-ap-a" = accessPoints."hostapd-gym-ap-a";
      systemd.services."hostapd-gym-ap-b" = accessPoints."hostapd-gym-ap-b";
      systemd.services = {
        gym-web = svc "gym-web" "8080 --http --addr ${config.services.gym-web.listenAddress}" { };
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
        # Runs only while the stick is there: BindsTo its device unit.
        gym-usb-reader = {
          wantedBy = [ "dev-gymusb0.device" ];
          bindsTo = [ "dev-gymusb0.device" ];
          after = [ "dev-gymusb0.device" ];
          serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        };
        gym-extra = lib.mkIf config.services.gym-extra.enable (svc "gym-extra" "7004" { });
      };

      services.openssh.enable = true;
      networking.networkmanager.enable = true;
      networking.networkmanager.unmanaged = [ "type:ethernet" "interface-name:wlan0" "interface-name:wlan1" ];
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

      environment.systemPackages = [ gymPkg pkgs.git pkgs.util-linux pkgs.iptables pkgs.curl pkgs.jq ];
      environment.variables.PLANARIAN_GYM_CATALOG = "${catalog}";
      programs.git.config.safe.directory = "*";

      # The test VM's root disk has no partition table, so GRUB can't be
      # embedded in it: publish_boot would fail on grub-install, not on
      # anything Planarian does. nodev still writes the boot menu for real.
      boot.loader.grub.devices = lib.mkForce [ "nodev" ];

      # Failure-posture fixtures (§12d; catalog family failure-posture).
      # The stand-in agent principal, stopped by every failure class (I20).
      services.planarian.agentUnits = [ "gym-agent.service" ];
      # The gym VM boots slowly (many fixtures); 30 s raised Absent at boot.
      services.planarian.bootReadyTimeout = 120;
      systemd.services.gym-agent = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
      # The administrator (bob) runs `sudo planarian-ack` without a password.
      security.sudo.wheelNeedsPassword = false;
      # /etc/systemd/system is the store's here, so `systemctl mask` cannot
      # last across a reboot: a generator masks what the harness lists (in
      # the early directory, which outranks every other).
      systemd.generators.gym-mask = pkgs.writeShellScript "gym-mask" ''
        [ -r /var/lib/gym-posture/masked ] || exit 0
        while read -r u; do [ -n "$u" ] && ${pkgs.coreutils}/bin/ln -sf /dev/null "$2/$u"; done < /var/lib/gym-posture/masked
      '';
      # The recovery check reads the core hash from a writable copy that the
      # harness can corrupt (corrupt_core_hash); the check itself is unchanged.
      systemd.services.planarian-recovery.environment.PLANARIAN_CORE_HASH = lib.mkForce "/var/lib/gym-posture/core.sha256";
      systemd.services.planarian-recovery.preStart = ''
        [ -e /var/lib/gym-posture/core.sha256 ] || { mkdir -p /var/lib/gym-posture; cp /etc/planarian/core.sha256 /var/lib/gym-posture/core.sha256; }
      '';

      # Wi-Fi: three simulated radios in this kernel. wlan0 and wlan1 are the
      # access points gym-ap-a and gym-ap-b (one hostapd unit each, so one can
      # go away); wlan2 is NetworkManager's client. It knows both networks
      # but autoconnects only to gym-ap-a, so choosing gym-ap-b is left to
      # Planarian (which asks first).
      boot.extraModprobeConfig = "options mac80211_hwsim radios=3";
      networking.networkmanager.ensureProfiles.profiles = lib.genAttrs [ "gym-ap-a" "gym-ap-b" ] (ssid: {
        connection = {
          id = ssid;
          type = "wifi";
          interface-name = "wlan2";
          autoconnect = if ssid == "gym-ap-a" then "true" else "false";
        };
        wifi = { inherit ssid; mode = "infrastructure"; };
        # Nothing on the simulated APs hands out addresses; association is
        # what the probe checks.
        ipv4.method = "disabled";
        ipv6.method = "disabled";
      });
      # NetworkManager's wpa_supplicant; test VMs turn Wi-Fi off (mkVMOverride).
      networking.wireless.enable = lib.mkOverride 9 true;

      # A stand-in desktop. What the desktop entries test is Planarian's side
      # (a session must reach graphical-session.target within 60 s; a boot
      # whose greeter fails is not confirmed), not COSMIC itself, which this
      # VM cannot run quickly without a GPU. The greeter fails when the kernel
      # has no modesetting, as a real one would; each user's compositor brings
      # up graphical-session.target unless its knob says it fails.
      systemd.services.display-manager = {
        description = "Login screen (gym stand-in)";
        wantedBy = [ "multi-user.target" ];
        script = ''
          if ${pkgs.gnugrep}/bin/grep -q 'virtio_gpu.modeset=0' /proc/cmdline; then
            echo "no display: modesetting is off" >&2
            exit 1
          fi
          exec ${pkgs.coreutils}/bin/sleep infinity
        '';
      };
      # On a desktop, the session's clients start pipewire (it is socket-
      # activated); these logins have no clients, so start it with the session.
      systemd.user.services.pipewire.wantedBy = [ "default.target" ];
      # Upstream restarts pipewire on failure, and then Planarian rightly
      # leaves it to systemd (svc-killed-defer-to-systemd covers that). The
      # user-scope repair entries need a user service systemd won't restart.
      systemd.user.services.pipewire.serviceConfig.Restart = lib.mkForce "no";
      systemd.user.services.wireplumber.wantedBy = [ "default.target" ];
      systemd.user.targets.gym-desktop = {
        bindsTo = [ "graphical-session.target" ];
        wants = [ "graphical-session.target" ];
        before = [ "graphical-session.target" ];
      };
      systemd.user.services.cosmic-comp = {
        description = "Compositor (gym stand-in)";
        wantedBy = [ "default.target" ];
        script = ''
          if [ "$(cat /var/lib/gym-knobs/cosmic-comp@$(id -u)/exec_fail 2>/dev/null)" = true ]; then
            echo "compositor failed to start (knob)" >&2
            exit 1
          fi
          systemctl --user start gym-desktop.target
          exec ${pkgs.coreutils}/bin/sleep infinity
        '';
      };

      services.udev.extraRules = ''
        SUBSYSTEM=="block", ENV{ID_SERIAL_SHORT}=="GYMUSB0", ENV{DEVTYPE}=="disk", SYMLINK+="gymusb0", TAG+="systemd"
        SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTRS{serial}=="GYMUSB0", ACTION=="add", RUN+="${pkgs.coreutils}/bin/ln -sfn /sys%p /run/gym-usb0"
        SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_interface", ATTRS{serial}=="GYMUSB0", ACTION=="remove", RUN+="${pkgs.coreutils}/bin/rm -f /run/gym-usb0"
      '';

      # Devices at fixed PCI addresses (their sysfs paths are in the manifest).
      virtualisation = {
        memorySize = 3072;
        cores = 2;
        diskSize = 8192;
        emptyDiskImages = [ 512 256 ];
        qemu.options = [
          "-device intel-hda,addr=0x1b" "-device hda-duplex"
          "-device virtio-gpu-pci,addr=0x1c"
          "-netdev user,id=gymnet" "-device virtio-net-pci,netdev=gymnet,addr=0x1d"
          "-device qemu-xhci,id=xhci" "-drive if=none,id=gymusb,driver=null-co,size=16M"
          "-device usb-storage,bus=xhci.0,drive=gymusb,id=gymusbdev,serial=GYMUSB0"
        ];
      };
      # vfio-pci for drv-bind-fails-restores-previous: an admin binds the
      # sound card to it. The VM has no IOMMU, which vfio needs unless its
      # no-IOMMU mode is on.
      boot.kernelModules = [ "snd_hda_intel" "virtio_gpu" "mac80211_hwsim" "vfio-pci" ];
      # Suspend to idle: QEMU does not bring this VM back from S3 (deep), and
      # for systemd and Planarian a suspend is the same either way.
      boot.kernelParams = [ "mem_sleep_default=s2idle" "vfio.enable_unsafe_noiommu_mode=1" ]
        ++ lib.optional (config.gym.kernelParam != "") config.gym.kernelParam;
      # The journal on its own small filesystem (fill_fs fs-journal).
      # (virtualisation.fileSystems: in a test VM, plain fileSystems entries
      # are replaced by the VM's own, and were never mounted.)
      virtualisation.fileSystems."/var/lib/planarian" = { device = "/dev/vdb"; fsType = "ext4"; autoFormat = true; };
      # /boot on its own small filesystem, as on an installed machine
      # (fill_fs fs-boot; GRUB copies the kernels there since the store is
      # elsewhere). The test VM boots its kernel directly; this is what
      # publishing a generation writes.
      virtualisation.fileSystems."/boot" = { device = "/dev/vdc"; fsType = "ext4"; autoFormat = true; };

      # The prebuilt candidates and out-of-band generations.
      specialisation = lib.mapAttrs (_: s: { configuration = { imports = [ s ]; gym.isBase = false; }; }) ((lib.mapAttrs (n: a:
        lib.mapAttrsRecursive (_: v: lib.mkOverride 90 v) a
      ) (removeAttrs candidates [ "base" ])) // {
        gym-web-false.systemd.services.gym-web.serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/false";
        weak-sshd-probe.services.planarian.units.sshd.probes = [
          { id = "sshd-tcp"; type = "tcp"; addr = "127.0.0.1:22"; timeout = 600; establishes = "weakened"; }
        ];
        # The owner enables the payload and rebuilds outside Planarian.
        bad-payload.services.gym-bad-payload.enable = true;
        throwaway0.environment.etc."gym-throwaway".text = "0";
        throwaway1.environment.etc."gym-throwaway".text = "1";
      });

      # /etc/nixos: the shim flake (written once; Planarian edits its overrides).
      systemd.services.gym-owner = lib.mkIf config.gym.isBase {
        wantedBy = [ "multi-user.target" ];
        before = [ "planariad.service" ];
        unitConfig.ConditionPathExists = "!/etc/nixos/flake.nix";
        serviceConfig.Type = "oneshot";
        path = [ pkgs.git pkgs.coreutils config.nix.package ];
        script = ''
          mkdir -p /etc/nixos/planarian
          cd /etc/nixos
          install -m644 ${shim} flake.nix
          install -m644 ${candidatesJson} candidates.json
          install -m644 ${../template/planarian/overrides.nix} planarian/overrides.nix
          echo '{ }' > configuration.nix
          booted=$(readlink -f /run/booted-system)
          # An installed NixOS has a system profile from the start; a test VM
          # boots its kernel directly and has none until a switch.
          [ -e /nix/var/nix/profiles/system ] || nix-env -p /nix/var/nix/profiles/system --set "$booted"
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
                        machine.shutdown(); machine.start(); machine.wait_for_unit("multi-user.target")
                        # planariad, or (failure-posture entries) the posture's alarm.
                        machine.wait_until_succeeds("systemctl is-active planariad.service || test -e /run/planarian/alarm", timeout=600)
                        machine.succeed("systemd-run --unit=gym-sampler -E PATH -E PLANARIAN_GYM_CATALOG planarian-gym vm sample")
                    elif raw == "suspend":
                        d = st.get("duration", "60s")
                        secs = int(d[:-1]) * (60 if d.endswith("m") else 1)
                        # The RTC alarm wakes it; the monitor command is a backup.
                        # s2idle wakes on interrupts marked as wakeup sources: the RTC's.
                        print(machine.succeed(
                            "for w in /sys/class/rtc/rtc0/device/power/wakeup /sys/class/rtc/rtc0/power/wakeup; do"
                            " [ -e $w ] && echo enabled > $w; done; cat /sys/power/mem_sleep;"
                            " grep -H . /sys/class/rtc/rtc0/device/power/wakeup /sys/class/rtc/rtc0/power/wakeup 2>&1 || true"
                        ))
                        machine.succeed(f"rtcwake -m no -s {secs}")
                        machine.execute("systemctl suspend &")
                        time.sleep(secs)
                        machine.send_monitor_command("system_wakeup")
                        # Bounded: a command sent to a machine that never wakes waits forever.
                        machine.wait_for_console_text("PM: suspend exit", timeout=300)
                    elif raw == "hotunplug":
                        machine.send_monitor_command("device_del gymusbdev")
                    elif raw in ("stop_host_service", "start_host_service"):
                        verb = "stop" if raw == "stop_host_service" else "start"
                        name = st.get("name", "gym-upstream")
                        # The access points run beside the client (the radios are
                        # simulated in one kernel); the upstream on its own node.
                        node = machine if name.startswith("hostapd-") else upstream
                        node.succeed(f"systemctl {verb} {name}")
            # For triage: what the daemon and the step watchers did.
            print(machine.execute(
                "ls -la /run/planarian-gym; cat /run/planarian-gym/hooks.json; echo;"
                " journalctl -o short-monotonic --no-pager -u planariad -u planarian-recovery -u 'gym-watch-*' | tail -n 150;"
                " ls -la /var/lib/planarian /var/lib/planarian/log 2>&1; timeout 10 planarian log -n 10 2>&1;"
                " timeout 10 git -C /etc/nixos status --short 2>&1; tail -n 3 /etc/nixos/configuration.nix 2>&1"
            )[1])
            print(machine.succeed(f"{gym} judge --id {ID} 2>&1"))
            # The sampler's status changes over the whole window (one line per change).
            print(machine.execute(
                "echo 'status changes (sampler):'; jq -c '.status' /var/lib/gym-run/samples.jsonl 2>&1 | uniq | tail -n 40"
            )[1])
        machine.copy_from_machine("/var/lib/gym-run/verdict.json", "")
        if machine.execute("test -e /var/lib/gym-run/evidence.json")[0] == 0:
            machine.copy_from_machine("/var/lib/gym-run/evidence.json", "")
      '';
    };
in
test
