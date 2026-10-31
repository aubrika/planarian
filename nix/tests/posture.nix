# The failure posture (SPEC §12d, I20) on real systemd: the Standard
# posture's responses to each failure class, that no agent runs while
# Planarian is failed, and the recovery exits. All of it is systemd and
# shell (nix/posture.nix); planariad only reports.
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "planarian-posture";

  nodes.machine = { pkgs, lib, ... }: {
    imports = [ self.nixosModules.default ];
    services.planarian.enable = true;
    services.planarian.bootReadyTimeout = 20;
    services.planarian.agentUnits = [ "gym-agent.service" ];
    # §9 hook, with RFC 8032's first test key; no producer.
    services.planarian.externalSource.publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    services.openssh.enable = true;
    users.users = {
      alice = { isNormalUser = true; uid = 1000; };
      admin = { isNormalUser = true; uid = 1001; extraGroups = [ "planarian-admin" ]; };
    } // lib.listToAttrs (lib.genList (i: {
      name = "launcher${toString i}";
      value = { isNormalUser = true; uid = 1100 + i; };
    }) 7);
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

    with subtest("the signed health report is written locally, minimal"):
        machine.wait_until_succeeds("test -s /var/lib/planarian/health-report.json", timeout=60)
        machine.succeed("test $(tr -d '\\n' < /var/lib/planarian/health-report.json.sig | wc -c) = 128")
        machine.succeed("test $(stat -c %a /var/lib/planarian/health.key) = 600")
        machine.succeed("grep -q '\"profile\": \"Minimal\"' /var/lib/planarian/health-report.json")
        machine.fail("grep -q /nix/store /var/lib/planarian/health-report.json")

    with subtest("public launcher: caller and total limits preserve root recovery capacity"):
        for caller in range(7):
            for slot in range(4):
                machine.succeed(f"su launcher{caller} -c 'planarian agent run capacity-{caller}-{slot} -- sleep infinity'")
        machine.fail("su launcher0 -c 'planarian agent run caller-overflow -- sleep infinity'")
        machine.fail("su alice -c 'planarian agent run global-overflow -- sleep infinity'")
        for slot in range(4):
            machine.succeed(f"planarian agent run reserved-root-{slot} -- sleep infinity")
        machine.fail("planarian agent run total-overflow -- sleep infinity")
        # The launcher group does not contain the daemon or recovery watchdog.
        machine.succeed("test $(systemctl show planarian-agents.slice -p TasksMax --value) = 1024")
        machine.succeed("test $(systemctl show planarian-agent-reserved-root-0.service -p TasksMax --value) = 64")
        machine.succeed("systemctl stop planarian-agents.slice")
        machine.wait_until_fails("systemctl is-active planarian-agent-reserved-root-0.service")
        machine.succeed("planarian status")

    with subtest("Absent: planariad stopped outside a shutdown"):
        machine.succeed("planarian agent run launched-absent -- sleep infinity")
        machine.wait_for_unit("planarian-agent-launched-absent.service")
        machine.succeed("systemctl stop planariad.service")
        machine.wait_until_succeeds("test -e /run/planarian/alarm", timeout=60)
        assert alarm().startswith("absent"), alarm()
        machine.wait_until_fails("systemctl is-active planarian-agent-launched-absent.service", timeout=60)
        machine.fail("planarian agent run refused-absent -- sleep infinity")
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
        machine.succeed("planarian agent run launched-crashed -- sleep infinity")
        machine.wait_for_unit("planarian-agent-launched-crashed.service")
        for _ in range(8):
            machine.succeed("systemctl kill --signal=SIGSEGV planariad.service || true")
            machine.sleep(3)
        machine.wait_until_succeeds("test -e /run/planarian/alarm", timeout=120)
        assert alarm().startswith("crashed"), alarm()
        machine.wait_until_fails("systemctl is-active planarian-agent-launched-crashed.service", timeout=60)
        machine.fail("planarian agent run refused-crashed -- sleep infinity")
        machine.wait_until_fails("systemctl is-active gym-agent.service", timeout=60)
        machine.succeed("systemctl reset-failed planariad.service")
        machine.succeed("systemctl start planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)

    with subtest("Integrity: an external desired-state document with an invalid signature"):
        machine.succeed("planarian agent run launched-integrity -- sleep infinity")
        machine.wait_for_unit("planarian-agent-launched-integrity.service")
        machine.succeed("mkdir -p /var/lib/planarian/external")
        machine.succeed("echo '{\"seq\": 1, \"issued\": 0, \"units\": {}}' > /var/lib/planarian/external/desired.json")
        machine.succeed("printf '%0128d' 0 > /var/lib/planarian/external/desired.json.sig")
        machine.wait_until_succeeds("test -e /run/planarian/failed-integrity", timeout=120)
        assert alarm().startswith("integrity"), alarm()
        machine.wait_until_fails("systemctl is-active planarian-agent-launched-integrity.service", timeout=60)
        machine.fail("planarian agent run refused-integrity -- sleep infinity")
        machine.succeed("grep -q 'external desired-state source' /run/planarian/integrity")
        machine.fail("systemctl is-active gym-agent.service")
        machine.succeed("rm -r /var/lib/planarian/external")
        machine.succeed("planarian-ack")
        machine.succeed("systemctl restart planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)
        machine.succeed("systemctl start gym-agent.service")
        machine.succeed("planarian agent run launched-after-recovery -- sleep infinity")
        machine.wait_for_unit("planarian-agent-launched-after-recovery.service")

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
