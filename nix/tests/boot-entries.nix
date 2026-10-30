# Installed-entry boot acceptance, separate from the direct-kernel gym. The
# private disk contains the root filesystem, ESP, systemd-boot and candidates.
# It does not certify other bootloaders, alternate ESP layouts or power loss.
{ pkgs, self, crashPoint ? null, recoverer ? "daemon", confirm ? false }:

assert builtins.elem recoverer [ "daemon" "watchdog" ];
pkgs.testers.runNixOSTest (
  { config, ... }:
  let
    m = config.nodes.machine;
    g1 = m.system.build.toplevel;
    g2cfg = m.specialisation.fixed.configuration;
    g3cfg = m.specialisation.candidate.configuration;
    g2 = g2cfg.system.build.toplevel;
    g3 = g3cfg.system.build.toplevel;
    facts = c: {
      services.planarian.export = c.services.planarian.export;
      gym.bootSlot = c.gym.bootSlot;
    };
    exports = pkgs.writeText "boot-entry-exports.json" (builtins.toJSON {
      base = facts m; fixed = facts g2cfg; candidate = facts g3cfg;
    });
    shim = pkgs.writeText "boot-entry-owner-flake.nix" ''
      {
        outputs = { self }:
          let
            text = builtins.readFile ./planarian/overrides.nix;
            has = slot: builtins.length (builtins.split ("bootSlot = lib[.]mkOverride 90 \"" + slot + "\"") text) > 1;
            pick = if has "g3" then "candidate" else if has "g2" then "fixed" else "base";
            exports = builtins.fromJSON (builtins.readFile ./exports.json);
            paths = { base = ./g1; fixed = ./g2; candidate = ./g3; };
          in { nixosConfigurations.machine = {
            config = exports.''${pick} // { system.build.toplevel = paths.''${pick}; };
            options = {};
          }; };
      }
    '';
    gymPkg = pkgs.callPackage ../package.nix { gymHooks = true; };
    # The daemon establishes approval's controlling terminal from the peer.
    # Allocate a new session/pty explicitly instead of inheriting driver stdin.
    onTerminal = pkgs.writeScriptBin "boot-test-terminal" ''
      #!${pkgs.python3}/bin/python3
      import errno, os, pty, select, signal, sys, time

      pid, fd = pty.fork()
      if pid == 0:
          os.execvp(sys.argv[1], sys.argv[1:])
      deadline = time.monotonic() + 110
      status = None
      output = bytearray()
      try:
          while True:
              remaining = deadline - time.monotonic()
              if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                  raise TimeoutError("terminal request exceeded 110 seconds")
              try:
                  chunk = os.read(fd, 4096)
              except OSError as error:
                  if error.errno != errno.EIO:
                      raise
                  break
              if not chunk:
                  break
              output.extend(chunk)
              if len(output) > 512 * 1024:
                  raise RuntimeError("terminal request output exceeded 512 KiB")
          while status is None:
              waited, result = os.waitpid(pid, os.WNOHANG)
              if waited == pid:
                  status = result
              elif time.monotonic() >= deadline:
                  raise TimeoutError("terminal request did not exit")
              else:
                  time.sleep(0.01)
          sys.stdout.buffer.write(output)
          sys.exit(os.waitstatus_to_exitcode(status))
      finally:
          os.close(fd)
          if status is None:
              try:
                  os.killpg(pid, signal.SIGKILL)
              except ProcessLookupError:
                  pass
              os.waitpid(pid, 0)
    '';
  in {
    name = "planarian-installed-entries-${recoverer}-${if confirm then "confirmation" else if crashPoint == null then "fallback" else builtins.replaceStrings [ ":" ] [ "-" ] crashPoint}";
    skipTypeCheck = true;
    globalTimeout = 5400;
    nodes.machine = { config, lib, ... }: {
      imports = [ self.nixosModules.default ];
      options.gym.bootSlot = lib.mkOption { type = lib.types.str; default = "g1"; };
      config = {
        virtualisation = {
          useBootLoader = true;
          directBoot.enable = false;
          useEFIBoot = true;
          efi.keepVariables = true;
          diskSize = 24576;
          memorySize = 3072;
          # With useBootLoader the test has a private store. A path mentioned
          # only by the host-side testScript is not copied into that store.
          additionalPaths = [ exports shim ../template/planarian/overrides.nix ];
        };
        boot.loader.grub.enable = lib.mkForce false;
        boot.loader.systemd-boot.enable = true;
        boot.loader.systemd-boot.editor = false;
        boot.loader.timeout = 0;
        boot.loader.efi.canTouchEfiVariables = true;
        boot.kernelParams = [ "planarian-boot-slot=${config.gym.bootSlot}" ];
        services.planarian = {
          enable = true;
          package = gymPkg;
          testBuild = true;
          owner = "/etc/nixos";
          flakeAttr = "nixosConfigurations.machine";
          bootReadyTimeout = 60;
          catalog.gymChoices."gym:boot-slot" = {
            option = "gym.bootSlot"; arg = "slot"; permitted = [ "g2" "g3" ];
          };
        };
        # This constant, fixture-only condition models an installed boot which
        # cannot admit the monitor. It is not changed between generations and
        # therefore does not bypass touches_core during candidate planning.
        systemd.services.planariad.unitConfig.ConditionPathExists = "!/var/lib/boot-test-no-monitor";
        systemd.services.planarian-recovery.unitConfig.ConditionPathExists = "!/var/lib/boot-test-no-monitor";
        users.users.proposer = { isNormalUser = true; uid = 1001; extraGroups = [ "planarian-admin" ]; };
        specialisation.fixed.configuration.gym.bootSlot = "g2";
        specialisation.candidate.configuration.gym.bootSlot = "g3";
        # Synthetic metadata models a vulnerable G1 and fixed G2/G3 using the
        # normal evaluated package-value inspection; no real CVE is invented.
        environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.jq onTerminal (
          let
            version = if config.gym.bootSlot == "g1" then "1" else "2";
            fixture = pkgs.runCommand "planarian-boot-fixture-${version}" {
              pname = "planarian-boot-fixture";
              inherit version;
            } ''mkdir -p $out/share; touch $out/share/fixture'';
          in fixture // { meta = (fixture.meta or { }) // {
            knownVulnerabilities = lib.optional (config.gym.bootSlot == "g1") "Synthetic acceptance-only vulnerability";
          }; }
        ) ];
      };
    };
    testScript = ''
      import json, re, shlex

      crash = ${if crashPoint == null then "None" else builtins.toJSON crashPoint}
      recoverer = ${builtins.toJSON recoverer}
      confirmation = ${if confirm then "True" else "False"}
      paths = {1: "${g1}", 2: "${g2}", 3: "${g3}"}

      def view():
          return json.loads(machine.succeed("planarian --json console"))

      def status():
          return view()["status"]

      def floor():
          # StatusReport deliberately has no floor field. Inspect the journal's
          # rendered durable records; this test does not compact its history.
          lines = json.loads(machine.succeed("planarian --json log -n 1000"))["lines"]
          records = sorted((line for line in lines if line["text"].startswith("security floor: ")), key=lambda line: line["seq"])
          assert records, "no durable security-floor record"
          text = records[-1]["text"]
          if text == "security floor: None":
              return None
          match = re.fullmatch(r"security floor: Some\(GenerationId\(([0-9]+)\)\)", text)
          assert match, text
          return int(match.group(1))

      def variable(name):
          code = "from pathlib import Path; p=Path('/sys/firmware/efi/efivars/" + name + "-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'); print(p.read_bytes()[4:].decode('utf-16-le').rstrip('\\0') if p.exists() else str())"
          return machine.succeed("python3 -c " + shlex.quote(code)).strip()

      def profile_entry(path):
          code = "from pathlib import Path; p=Path('/nix/var/nix/profiles'); print(max((int(l.name.split('-')[1]) for l in p.glob('system-*-link') if str(l.resolve()) == " + repr(path) + "), default=0))"
          number = int(machine.succeed("python3 -c " + shlex.quote(code)).strip())
          assert number > 0, (path, number)
          return f"nixos-generation-{number}.conf"

      def wait_ready():
          machine.wait_for_unit("planarian-ready.target", timeout=90)
          ready = int(machine.succeed("systemctl show planarian-ready.target -p ActiveEnterTimestampMonotonic --value").strip())
          check_started = int(machine.succeed("systemctl show planarian-posture-check -p ExecMainStartTimestampMonotonic --value").strip())
          assert ready > 0 and check_started > 0
          # The external checker polls every two seconds. Five seconds is the
          # predeclared scheduling allowance for this test, not ten minutes.
          assert max(0, ready - check_started) <= 65_000_000, (ready, check_started)
          # Reaching admission ready must not wait for the ten-minute milestone.
          uptime = float(machine.succeed("cut -d' ' -f1 /proc/uptime").strip())
          assert uptime < 600, f"admission readiness reached too late: {uptime}s"

      def submit(slot):
          response = json.loads(machine.succeed("runuser -u proposer -- planarian --json apply gym:boot-slot slot=g" + str(slot)))
          if response["kind"] == "needs-approval":
              command = "planarian --json approve " + response["approve"]
              code, output = machine.execute("timeout -k 5 120 boot-test-terminal " + command + " </dev/null")
              print("approval exit/output", code, output)
              if not (slot == 3 and crash is not None):
                  assert code == 0, output
          else:
              assert response["kind"] == "done", response

      machine.wait_for_unit("multi-user.target")
      wait_ready()
      machine.succeed("test -d /sys/firmware/efi/efivars", "test -f /boot/loader/loader.conf", "findmnt /boot -n -o FSTYPE | grep -x vfat")
      machine.succeed("grep -q planarian-boot-slot=g1 /proc/cmdline")
      machine.succeed("test \"$(readlink -f /run/booted-system)\" = ${g1}")
      machine.succeed("mkdir -p /etc/nixos/planarian", "install -m644 ${shim} /etc/nixos/flake.nix", "install -m644 ${exports} /etc/nixos/exports.json", "install -m644 ${../template/planarian/overrides.nix} /etc/nixos/planarian/overrides.nix", "ln -s ${g1} /etc/nixos/g1", "ln -s ${g2} /etc/nixos/g2", "ln -s ${g3} /etc/nixos/g3")
      machine.succeed("timeout -k 5 120 boot-test-terminal planarian mark-good </dev/null")
      g1_id = status()["generation"]
      assert status()["known_good"] == g1_id

      with subtest("G2 boots its installed entry and commits its security floor before delayed confirmation"):
          submit(2)
          machine.wait_until_succeeds("planarian log -n 200 | grep AwaitingBoot", timeout=180)
          assert variable("LoaderEntryOneShot") == profile_entry(paths[2])
          assert variable("LoaderEntryDefault") == profile_entry(paths[1])
          machine.shutdown()
          machine.start()
          wait_ready()
          machine.succeed("grep -q planarian-boot-slot=g2 /proc/cmdline", "test \"$(readlink -f /run/booted-system)\" = ${g2}")
          machine.wait_until_succeeds("planarian log -n 250 | grep 'txn 1: Committed'", timeout=180)
          g2_id = status()["generation"]
          assert g2_id > g1_id
          assert floor() == g2_id, status()
          assert status()["live_tested"] == g2_id, status()
          assert status()["known_good"] == g1_id, status()
          assert variable("LoaderEntryDefault") == profile_entry(paths[2])
          assert not variable("LoaderEntryOneShot")
          # The vulnerable manual fallback is still present in the installed ESP.
          machine.succeed("test -f /boot/loader/entries/" + profile_entry(paths[1]))

      if confirmation:
          with subtest("a healthy admitted boot confirms only at the delayed milestone"):
              machine.wait_until_succeeds("planarian --json status | jq -e '.known_good == .generation'", timeout=660)
              assert status()["known_good"] == g2_id
      else:
          with subtest("failure after admission and before confirmation invokes the declared posture"):
              machine.succeed("systemctl stop planariad")
              machine.wait_until_succeeds("test -e /run/planarian/failed-absent", timeout=90)
              machine.succeed("systemctl start planariad")
              machine.wait_for_unit("planarian-ready.target")
              assert status()["known_good"] == g1_id
              assert floor() == g2_id
          with subtest("publication crash boundaries remain tracked or prove withdrawal"):
              machine.succeed("systemctl stop planarian-recovery", "mkdir -p /run/systemd/system/planariad.service.d", "printf '[Service]\\nRestart=no\\n' > /run/systemd/system/planariad.service.d/boot-test.conf", "systemctl daemon-reload")
              if recoverer == "daemon":
                  # planariad Wants recovery; merely stopping it lets it race
                  # the intended daemon recovery when planariad starts again.
                  machine.succeed("systemctl mask --runtime planarian-recovery.service")
              if crash is not None:
                  machine.succeed("mkdir -p /run/planarian-gym", "printf '%s' " + shlex.quote(crash) + " > /run/planarian-gym/crash")
              else:
                  # EFI default overrides loader.conf; publication must reset a
                  # stale/manual selection to the eligible G2, not trust profile.
                  machine.succeed("bootctl set-default " + profile_entry(paths[1]))
              submit(3)
              if crash is not None:
                  machine.wait_until_fails("systemctl is-active --quiet planariad", timeout=30)
                  if recoverer == "watchdog" and crash not in ("State:Built", "State:AwaitingBoot"):
                      machine.succeed("systemctl start planarian-recovery")
                      machine.wait_until_succeeds("journalctl -u planarian-recovery --no-pager | grep 'transaction 2 →'", timeout=120)
                  machine.succeed("systemctl start planariad")
                  machine.wait_for_unit("planarian-ready.target")
              published = crash in (None, "OpCalled:publish_boot_once", "OpAcked:publish_boot_once", "State:AwaitingBoot")
              if published:
                  machine.wait_until_succeeds("planarian log -n 400 | grep 'txn 2: AwaitingBoot'", timeout=180)
                  assert variable("LoaderEntryOneShot") == profile_entry(paths[3])
                  assert variable("LoaderEntryDefault") == profile_entry(paths[2])
                  machine.succeed("test -d /nix/var/nix/gcroots/planarian/builds")
                  machine.succeed("python3 -c " + shlex.quote("from pathlib import Path; assert any(str(p.resolve()) == " + repr(paths[3]) + " for p in Path('/nix/var/nix/gcroots/planarian/builds').iterdir())"))
              else:
                  assert not variable("LoaderEntryOneShot")
                  assert variable("LoaderEntryDefault") == profile_entry(paths[2])
                  machine.wait_until_succeeds("planarian log -n 400 | grep -E 'txn 2: (Reverted|Rejected)'", timeout=180)

          if published:
              with subtest("failed one-shot G3 falls back to G2 above the floor; G1 stays manual"):
                  machine.succeed("touch /var/lib/boot-test-no-monitor")
                  machine.shutdown()
                  machine.start()
                  machine.wait_for_unit("multi-user.target")
                  machine.succeed("grep -q planarian-boot-slot=g3 /proc/cmdline", "test \"$(readlink -f /run/booted-system)\" = ${g3}")
                  machine.wait_until_succeeds("test -e /run/planarian/failed-absent", timeout=120)
                  machine.fail("systemctl is-active planarian-ready.target")
                  assert not variable("LoaderEntryOneShot")
                  assert variable("LoaderEntryDefault") == profile_entry(paths[2])
                  # No monitor changes the selection; the next real boot uses
                  # installed G2. This is operator-requested reboot, not a claim
                  # that Phase A's posture automatically forces a reboot.
                  machine.shutdown()
                  machine.start()
                  machine.wait_for_unit("multi-user.target")
                  if recoverer == "daemon":
                      # Runtime masks do not survive reboot. Both monitors are
                      # still held by the failure marker until it is removed.
                      machine.succeed("systemctl mask --runtime planarian-recovery.service")
                  machine.succeed("grep -q planarian-boot-slot=g2 /proc/cmdline", "test \"$(readlink -f /run/booted-system)\" = ${g2}", "rm /var/lib/boot-test-no-monitor")
                  if recoverer == "watchdog":
                      machine.succeed("systemctl start planarian-recovery")
                      machine.wait_until_succeeds("journalctl -u planarian-recovery --no-pager | grep 'transaction 2 → Reverted'", timeout=120)
                  machine.succeed("systemctl start planariad")
                  machine.wait_for_unit("planarian-ready.target")
                  machine.wait_until_succeeds("planarian log -n 500 | grep 'txn 2: Reverted'", timeout=180)
                  assert status()["generation"] == g2_id
                  assert floor() == g2_id
                  assert variable("LoaderEntryDefault") == profile_entry(paths[2])
                  machine.succeed("test -f /boot/loader/entries/" + profile_entry(paths[1]))
                  machine.fail("grep -q 'bootSlot = lib.mkOverride 90 \"g3\"' /etc/nixos/planarian/overrides.nix")

      machine.succeed("mkdir -p /tmp/boot-evidence", "planarian --json console > /tmp/boot-evidence/console.json", "planarian --json log -n 1000 > /tmp/boot-evidence/journal.json", "bootctl status > /tmp/boot-evidence/bootctl.txt", "cp /proc/cmdline /tmp/boot-evidence/cmdline", "cp /boot/loader/loader.conf /tmp/boot-evidence/loader.conf", "cp /etc/nixos/planarian/overrides.nix /tmp/boot-evidence/overrides.nix", "find /nix/var/nix/gcroots/planarian -type l -printf '%p -> %l\\n' > /tmp/boot-evidence/roots.txt", "uname -a > /tmp/boot-evidence/kernel.txt", "nix --version > /tmp/boot-evidence/nix-version.txt", "systemd --version > /tmp/boot-evidence/systemd-version.txt")
      machine.copy_from_machine("/tmp/boot-evidence", "")
    '';
  }
)
