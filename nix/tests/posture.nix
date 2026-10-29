# The failure posture (SPEC §12d, I20) on real systemd: the Standard
# posture's responses to each failure class, that no agent runs while
# Planarian is failed, and the recovery exits. All of it is systemd and
# shell (nix/posture.nix); planariad only reports.
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "planarian-posture";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.planarian.enable = true;
    services.planarian.bootReadyTimeout = 20;
    services.planarian.agentUnits = [ "gym-agent.service" ];
    services.openssh.enable = true;
    users.users.alice = { isNormalUser = true; uid = 1000; };
    users.users.admin = { isNormalUser = true; uid = 1001; extraGroups = [ "planarian-admin" ]; };
    environment.systemPackages = [ pkgs.python3 ];
    virtualisation.diskSize = 8192;
    virtualisation.memorySize = 2048;

    # The stand-in agent principal (catalog fixture gym-agent).
    systemd.services.gym-agent = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
  };

  testScript = ''
    def alarm():
        return machine.succeed("cat /run/planarian/alarm 2>/dev/null || true").strip()

    machine.wait_for_unit("planarian-ready.target")
    machine.wait_for_unit("gym-agent.service")

    with subtest("ready: no alarm, the agent runs, sshd admits everyone"):
        assert alarm() == "", alarm()
        machine.fail("test -e /run/planarian/sshd/posture.conf")
        # I20: the agent is ordered after ready.
        machine.succeed("systemctl show gym-agent.service -p After | grep -q planarian-ready.target")

    with subtest("Absent: planariad stopped outside a shutdown"):
        machine.succeed("systemctl stop planariad.service")
        machine.wait_until_succeeds("test -e /run/planarian/alarm", timeout=60)
        assert alarm().startswith("absent"), alarm()
        machine.wait_until_fails("systemctl is-active gym-agent.service", timeout=60)
        machine.succeed("grep -q 'AllowGroups planarian-admin' /run/planarian/sshd/posture.conf")
        machine.succeed("grep -q 'not running' /run/issue.d/50-planarian.issue")
        machine.succeed("journalctl -t planarian-posture | grep -q 'failure class absent'")
        # Recovery exit: ready again with a clean boot report.
        machine.succeed("systemctl start planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)
        machine.fail("test -e /run/planarian/sshd/posture.conf")
        machine.wait_for_unit("gym-agent.service")

    with subtest("Crashed: killed past its restart budget"):
        for _ in range(8):
            machine.succeed("systemctl kill --signal=SIGSEGV planariad.service || true")
            machine.sleep(3)
        machine.wait_until_succeeds("test -e /run/planarian/alarm", timeout=120)
        assert alarm().startswith("crashed"), alarm()
        machine.wait_until_fails("systemctl is-active gym-agent.service", timeout=60)
        machine.succeed("systemctl reset-failed planariad.service")
        machine.succeed("systemctl start planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)

    with subtest("Integrity: a retained journal record edited on disk"):
        machine.succeed("systemctl stop planariad.service planarian-recovery.service")
        # Stopping planariad raised Absent; clear it to see Integrity alone.
        machine.succeed("planarian-ack")
        # Change one digit inside the first record's timestamp, CRC fixed up by
        # nothing: the record is damaged and later records follow it.
        machine.succeed(
            "python3 - <<'PY'\n"
            "p='/var/lib/planarian/journal/journal'\n"
            "b=bytearray(open(p,'rb').read())\n"
            "i=b.find(b'\"at\":')+5\n"
            "b[i]=ord('1') if b[i]==ord('9') else b[i]+1\n"
            "open(p,'wb').write(b)\n"
            "PY"
        )
        machine.succeed("systemctl start planarian-recovery.service")
        machine.succeed("systemctl start planariad.service || true")
        machine.wait_until_succeeds("test -e /run/planarian/failed-integrity", timeout=120)
        assert alarm().startswith("integrity"), alarm()
        machine.succeed("grep -q 'tampered' /run/issue.d/50-planarian.issue")
        machine.succeed("grep -q 'DenyUsers' /run/planarian/sshd/posture.conf")
        machine.succeed("grep -q journal /run/planarian/integrity")
        machine.fail("systemctl is-active gym-agent.service")
        # Only an administrator clears it; alice cannot.
        machine.fail("su alice -c 'sudo -n planarian-ack'")
        machine.succeed("planarian-ack")
        machine.fail("test -e /run/planarian/alarm")
        machine.succeed("journalctl -t planarian-posture | grep -q 'acknowledged by root'")
  '';
}
