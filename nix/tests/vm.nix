# A NixOS VM test of the runtime path on real systemd: detection, repair,
# respecting a user's stop, authorization, and the watchdog's presence.
# (Generation changes need an owner flake that can build inside the VM; that
# belongs to the gym's VM harness.)
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "planarian-runtime";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.planarian.enable = true;
    services.openssh.enable = true;
    users.users.alice = { isNormalUser = true; uid = 1000; };
    # Room for the canonical free-space probes (2 GB and 5% on /).
    virtualisation.diskSize = 8192;
    virtualisation.memorySize = 2048;

    # A tiny HTTP service with a health endpoint (catalog fixture gym-web).
    systemd.services.gym-web = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind 127.0.0.1 --directory /etc";
    };
    services.planarian.units.gym-web = {
      synonyms = [ "web server" ];
      probes = [
        { id = "gym-web-http"; type = "http"; url = "http://127.0.0.1:8080/hostname"; establishes = "gym-web serves HTTP"; }
      ];
    };
  };

  testScript = ''
    machine.wait_for_unit("planarian-recovery.service")
    machine.wait_for_unit("planariad.service")
    machine.wait_for_unit("gym-web.service")
    machine.wait_until_succeeds("planarian status | grep -E 'ok +service:gym-web'", timeout=600)

    with subtest("a killed service is repaired"):
        before = int(machine.succeed("planarian log -n 1000 | grep -c 'restart service:gym-web' || true").strip() or 0)
        machine.succeed("systemctl kill --signal=SIGKILL gym-web.service")
        machine.wait_until_succeeds(
            f"test $(planarian log -n 1000 | grep -c 'restart service:gym-web') -gt {before}", timeout=600
        )
        machine.wait_until_succeeds("systemctl is-active gym-web.service", timeout=600)

    with subtest("a user's stop is respected"):
        machine.succeed("ask 'stop gym-web until I say'")
        machine.sleep(60)
        machine.fail("systemctl is-active gym-web.service")
        machine.succeed("planarian status | grep -E 'service:gym-web +Suppressed'")
        machine.succeed("ask 'start gym-web again'")
        machine.wait_until_succeeds("systemctl is-active gym-web.service", timeout=600)

    with subtest("an unprivileged user cannot suppress sshd"):
        out = machine.fail("su alice -c 'planarian suppress sshd' 2>&1")
        assert "Unauthorized" in out, out

    with subtest("the executor log and journal exist"):
        machine.succeed("test -s /var/lib/planarian/log/executor.jsonl")
        machine.succeed("test -f /var/lib/planarian/journal/journal")
  '';
}
