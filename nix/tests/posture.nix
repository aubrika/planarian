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
    # §9 hook, with RFC 8032's first test key; no producer.
    services.planarian.externalSource.publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    services.openssh.enable = true;
    users.users.alice = { isNormalUser = true; uid = 1000; };
    users.users.admin = { isNormalUser = true; uid = 1001; extraGroups = [ "planarian-admin" ]; };
    environment.systemPackages = [ pkgs.python3 ];
    # P16: the same machine with a weaker posture and a longer timeout,
    # switched to live in the test.
    specialisation.lower.configuration = {
      services.planarian.posture = pkgs.lib.mkForce "Relaxed";
      services.planarian.bootReadyTimeout = pkgs.lib.mkForce 600;
    };
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

    with subtest("Absent: planariad stopped outside a shutdown"):
        machine.succeed("systemctl stop planariad.service")
        machine.wait_until_succeeds("test -s /run/planarian/alarm", timeout=60)
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
        machine.wait_until_succeeds("test -s /run/planarian/alarm", timeout=120)
        assert alarm().startswith("crashed"), alarm()
        machine.wait_until_fails("systemctl is-active gym-agent.service", timeout=60)
        machine.succeed("systemctl reset-failed planariad.service")
        machine.succeed("systemctl start planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)

    with subtest("Crashed: planarian-recovery crash-looping (P15)"):
        # SIGKILL: a crash without a core dump, so every kill lands on a
        # running watchdog (a SIGSEGV's dump outlasts the 2 s RestartSec,
        # and half the kills found it already down). Twelve in 36 s spend
        # the budget of five in 300 s.
        for _ in range(12):
            machine.succeed("systemctl kill --signal=SIGKILL planarian-recovery.service || true")
            machine.sleep(3)
        machine.wait_until_succeeds("test -s /run/planarian/alarm", timeout=120)
        assert alarm().startswith("crashed"), alarm()
        machine.wait_until_fails("systemctl is-active gym-agent.service", timeout=60)
        machine.succeed("systemctl reset-failed planarian-recovery.service")
        machine.succeed("systemctl start planarian-recovery.service")
        machine.succeed("planarian-ack")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=60)
        machine.wait_for_unit("gym-agent.service")

    with subtest("P14: under Absent, sshd admits Planarian's administrators, not wheel"):
        machine.succeed("systemctl stop planariad.service")
        machine.wait_until_succeeds("test -e /run/planarian/sshd/posture.conf", timeout=60)
        machine.succeed("grep -q 'AllowGroups planarian-admin root' /run/planarian/sshd/posture.conf")
        machine.fail("grep -q wheel /run/planarian/sshd/posture.conf")
        machine.succeed("systemctl start planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)
        machine.wait_for_unit("gym-agent.service")

    with subtest("P17: report boot and posture answer"):
        print(machine.succeed("planarian report boot"))
        out = machine.succeed("planarian posture")
        assert out.strip().startswith("posture: Standard, boot-ready timeout 20 s"), out

    with subtest("P16: a lowered posture switched live waits for the boot"):
        machine.succeed("/run/current-system/specialisation/lower/bin/switch-to-configuration test")
        machine.succeed("grep -q '\"posture\": *\"Relaxed\"' /etc/planarian/config.json || grep -q '\"posture\":\"Relaxed\"' /etc/planarian/config.json")
        machine.succeed("systemctl restart planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)
        out = machine.succeed("planarian posture")
        assert out.strip().startswith("posture: Standard, boot-ready timeout 20 s"), out
        assert "declares Relaxed, 600 s" in out and "next boot" in out, out
        machine.succeed("/run/booted-system/bin/switch-to-configuration test")
        machine.succeed("systemctl restart planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)
        machine.wait_for_unit("gym-agent.service")

    with subtest("Integrity: an external desired-state document with an invalid signature"):
        machine.succeed("mkdir -p /var/lib/planarian/external")
        machine.succeed("echo '{\"seq\": 1, \"issued\": 0, \"units\": {}}' > /var/lib/planarian/external/desired.json")
        machine.succeed("printf '%0128d' 0 > /var/lib/planarian/external/desired.json.sig")
        machine.wait_until_succeeds("test -e /run/planarian/failed-integrity", timeout=120)
        # respond marks the class before it writes the alarm: wait for both.
        machine.wait_until_succeeds("grep -q '^integrity' /run/planarian/alarm", timeout=60)
        assert alarm().startswith("integrity"), alarm()
        machine.succeed("grep -q 'external desired-state source' /run/planarian/integrity")
        machine.fail("systemctl is-active gym-agent.service")
        machine.succeed("rm -r /var/lib/planarian/external")
        machine.succeed("planarian-ack")
        machine.succeed("systemctl restart planariad.service")
        machine.wait_until_succeeds("test ! -e /run/planarian/alarm", timeout=120)
        machine.succeed("systemctl start gym-agent.service")

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
        # respond marks the class before it writes the alarm: wait for both.
        machine.wait_until_succeeds("grep -q '^integrity' /run/planarian/alarm", timeout=60)
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
