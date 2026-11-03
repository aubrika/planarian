# #35, §12d "Network security fails closed" (owner decision, Nov 2): the
# reviewer's VM case, written from the spec before the change. It observes
# only behaviour (connections, logins, the journal), never how the hold is
# built, so the lane may implement it however §12d allows.
#
# Fixture: lane-nix's shared `nix/tests/wireguard-gym.nix` (`wireguard-gym`,
# a wireguard-go tunnel 10.77.0.1-10.77.0.2 to node `peer`; Security and
# External; `holdAllow` = the peer's endpoint; `holdInterfaces` = wg0; a
# Readiness probe across the tunnel to 10.77.0.2:9000). Markers:
# /run/wireguard-gym-slow (seconds its start takes, to keep a restart in
# progress long enough to observe the hold) and /run/wireguard-gym-broken
# (its start fails). This case brings the servers, the users and the checks.
{ pkgs, self }:

let
  wgg = import ./wireguard-gym.nix { inherit pkgs; inherit (pkgs) lib; };
  ssh = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
  alarmText = "stopped unexpectedly. Network traffic is blocked until it is back.";
  # The restart loop's killer: waits for a new instance of wireguard-gym
  # (an InvocationID other than $1) to steer (128.0.0.0/1 over wg0, the last
  # route its start adds), sleeps $2 seconds, and SIGKILLs the unit. Writes
  # "<invocation> <ms from steering seen to kill>" to /run/nw-loop.done, or
  # "timeout" if no new instance steered within about a minute.
  killAfterSteer = pkgs.writeShellScript "kill-after-steer" ''
    PATH=${pkgs.lib.makeBinPath [ pkgs.coreutils pkgs.iproute2 pkgs.gnugrep pkgs.systemd ]}
    rm -f /run/nw-loop.done
    for _ in $(seq 3000); do
      cur=$(systemctl show -p InvocationID --value wireguard-gym.service)
      if [ -n "$cur" ] && [ "$cur" != "$1" ] && ip -o route show 128.0.0.0/1 | grep -q 'dev wg0'; then
        t0=$(date +%s%N)
        sleep "$2"
        systemctl kill --signal=SIGKILL wireguard-gym.service
        t1=$(date +%s%N)
        echo "$cur $(( (t1 - t0) / 1000000 ))" > /run/nw-loop.done
        exit 0
      fi
      sleep 0.01
    done
    echo timeout > /run/nw-loop.done
  '';
in
pkgs.testers.runNixOSTest {
  name = "planarian-netsec";
  # A hang fails in 40 minutes, not the default hour. Not lower: "repair
  # fails every attempt" alone waits out the backoff (10 + 60 + 300 s, §13),
  # and the restart loop runs four stop, start, kill and lift rounds.
  globalTimeout = 2400;

  nodes.peer = { pkgs, ... }: {
    imports = [ wgg.peer ];
    networking.firewall.enable = false;
    # Answers on the LAN and through the tunnel.
    systemd.services.web = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8000 --bind 0.0.0.0 --directory /etc";
    };
    systemd.services.web-tunnel = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 9000 --bind 0.0.0.0 --directory /etc";
    };
    environment.systemPackages = [ pkgs.curl pkgs.openssh ];
  };

  nodes.machine = { pkgs, nodes, ... }: {
    imports = [ self.nixosModules.default (wgg.machine { endpoint = nodes.peer.networking.primaryIPAddress; }) ];
    services.planarian.enable = true;
    services.openssh.enable = true;
    networking.firewall.enable = false;
    users.users.alice = { isNormalUser = true; uid = 1000; openssh.authorizedKeys.keys = [ ssh.snakeOilPublicKey ]; };
    users.users.carol = { isNormalUser = true; uid = 1002; openssh.authorizedKeys.keys = [ ssh.snakeOilPublicKey ]; };
    users.users.bob = {
      isNormalUser = true;
      uid = 1001;
      extraGroups = [ "planarian-admin" ];
      openssh.authorizedKeys.keys = [ ssh.snakeOilPublicKey ];
    };
    environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.util-linux pkgs.nftables ];
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 8192;

    # §12d classifier: a network tool by capability; one that is not (its
    # own network namespace, no capabilities); an untagged tool whose
    # short-lived start helper steers traffic (a dropping firewall rule for an
    # address nobody uses, so the test's own traffic is untouched).
    systemd.services.gym-capnet = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
      };
    };
    systemd.services.gym-privnet = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        DynamicUser = true;
        PrivateNetwork = true;
        CapabilityBoundingSet = [ "" ];
      };
    };
    systemd.services.gym-vpn-untagged = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        ExecStartPre = "${pkgs.bash}/bin/bash -c 'sleep $(cat /run/gym-vpn-untagged-slow 2>/dev/null || echo 0)'";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        ExecStartPost = "${pkgs.writeShellScript "gym-vpn-untagged-helper" ''
          ${pkgs.nftables}/bin/nft 'add table inet gymvpn'
          ${pkgs.nftables}/bin/nft 'add chain inet gymvpn out { type filter hook output priority 0; }'
          ${pkgs.nftables}/bin/nft 'add rule inet gymvpn out ip daddr 203.0.113.77 drop'
        ''}";
      };
    };
    # Declared, but with no sensitivity tag: only the kernel's attribution of
    # its helper's rule makes it a network-security unit. TODO (#35, parked
    # with the owner): the same with no entry at all, once §12d says what
    # happens to an undeclared network tool (held; repaired or not).
    services.planarian.units.gym-vpn-untagged = { };
    # The shared fixture's templated network tool (gym-tpl@, instance a),
    # declared with no tag so the daemon restarts it, as gym-vpn-untagged.
    services.planarian.units."gym-tpl@a" = { };
    # Something on loopback to reach while held.
    systemd.services.local-web = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8001 --bind 127.0.0.1 --directory /etc";
    };
  };

  testScript = ''
    import re

    ALARM = "${alarmText}"

    def lan_ok():
        return "curl -sf --max-time 5 -o /dev/null http://peer:8000/"
    def tunnel_ok():
        return "curl -sf --max-time 5 -o /dev/null http://10.77.0.2:9000/"
    # Upstream: an address beyond the LAN, served by the peer (wgg.upstream).
    # A full-tunnel VPN carries it over wg0 (0/1 and 128/1); with wg0 gone,
    # the machine's plain default route still reaches it, so a held machine
    # failing to reach it is the hold's doing, not a missing route.
    UP = "${wgg.upstream or "198.51.100.1"}"
    def up_ok():
        return f"curl -sf --max-time 5 -o /dev/null http://{UP}:8000/"
    def up_via_tunnel():
        return f"ip route get {UP} | grep -q 'dev wg0'"
    def new_ssh(user):
        # -n: stdin from /dev/null, never the backdoor console (an ssh that
        # reads hvc0 can wedge the driver's shell; gate 41553584226).
        return f"ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o ControlPath=none -i /root/key {user}@machine true"
    def alarms():
        return int(machine.succeed(f"journalctl -b -u planariad -o cat | grep -c '{ALARM}' || true").strip() or 0)
    def held():
        machine.succeed("nft list table inet planarian-hold")
        machine.succeed("systemctl is-active planarian-hold@wireguard-gym.service")
        machine.succeed("test -e /run/planarian/hold/wireguard-gym")
    def not_held(unit="wireguard-gym"):
        machine.fail(f"systemctl is-active planarian-hold@{unit}.service")
        machine.fail(f"test -e /run/planarian/hold/{unit}")
    def held_for(unit):
        machine.succeed("nft list table inet planarian-hold")
        machine.succeed(f"systemctl is-active planarian-hold@{unit}.service")
        machine.succeed(f"test -e /run/planarian/hold/{unit}")
    def as_alice(cmd):
        return machine.execute(f"su alice -c '{cmd}' 2>&1")
    def as_bob(cmd):
        # bob, an administrator who is not root, proposes, and root approves
        # at a terminal: I19, "No principal approves its own proposal".
        return machine.succeed(f"su bob -c '{cmd}' 2>&1 || true")
    def approve_as_root(out):
        h = re.search(r"approve ([0-9a-f]{64})", out)
        assert h, out
        machine.succeed(f"script -qec 'planarian approve {h.group(1)}' /dev/null")

    start_all()
    peer.succeed("install -m 600 ${ssh.snakeOilPrivateKey} /root/key")
    machine.wait_for_unit("planarian-ready.target")
    machine.wait_for_unit("wireguard-gym.service")
    peer.wait_for_unit("web.service")
    machine.wait_for_unit("local-web.service")
    machine.wait_for_unit("sshd.service")

    with subtest("baseline: the tunnel, the LAN and new SSH logins all work"):
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)
        machine.succeed(lan_ok())
        # Full tunnel: upstream goes over wg0, and arrives.
        machine.succeed(up_via_tunnel())
        machine.wait_until_succeeds(up_ok(), timeout=30)
        peer.succeed(new_ssh("alice"))
        not_held()
        assert alarms() == 0

    with subtest("planarian stop holds nothing (§12d: an attested stop is not a failure)"):
        # Stopping a Security/External unit asks (§11 StopUnit row).
        out = as_bob("planarian stop wireguard-gym")
        assert "approve" in out, out
        approve_as_root(out)
        machine.wait_until_fails("systemctl is-active wireguard-gym.service", timeout=60)
        machine.sleep(15)
        not_held()
        machine.succeed(lan_ok())
        peer.succeed(new_ssh("alice"))
        assert alarms() == 0, alarms()
        out = as_bob("planarian release wireguard-gym")
        if "approve" in out:
            approve_as_root(out)
        machine.succeed("systemctl start wireguard-gym.service")
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)

    with subtest("a kill holds traffic; the restart lifts the hold, with one alarm"):
        # An administrator's session, established before the failure.
        peer.succeed("ssh -n -fN -M -S /tmp/bob.sock -o ControlPersist=yes -o BatchMode=yes -o StrictHostKeyChecking=no -i /root/key bob@machine")
        peer.succeed("ssh -n -S /tmp/bob.sock bob@machine true")
        machine.succeed("echo 40 > /run/wireguard-gym-slow")
        machine.succeed("systemctl kill --signal=SIGKILL wireguard-gym.service")
        # Held: new outbound connections fail, loopback works, the admin's
        # established session survives, a new SSH login is refused.
        machine.wait_until_fails(lan_ok(), timeout=20)
        held()
        # The unit is down (killed; its restart still starting): no tunnel.
        machine.fail(tunnel_ok())
        # The leak a kill switch exists for: wg0 is gone, so upstream would
        # leave by the plain default route; held, it does not arrive.
        machine.fail(up_via_tunnel())
        machine.fail(up_ok())
        machine.succeed("curl -sf --max-time 5 -o /dev/null http://127.0.0.1:8001/")
        peer.succeed("ssh -n -S /tmp/bob.sock bob@machine true")
        peer.fail(new_ssh("alice"))
        peer.fail(new_ssh("bob"))
        # Address assignment passes the hold (§12d: "except loopback,
        # address assignment (DHCP, …)"): a lease renewed while held
        # succeeds, so a held machine never loses its address.
        leased = "journalctl -b -u dhcpcd -o cat | grep -c 'eth0: leased' || true"
        n0 = int(machine.succeed(leased).strip() or 0)
        machine.succeed("dhcpcd --rebind eth0")
        machine.wait_until_succeeds(f"[ $({leased}) -gt {n0} ]", timeout=20)
        held()
        # Restarted by Planarian at once; the hold lifts once it is Running
        # and its Readiness probe passes. That probe crosses the tunnel
        # (wireguard-gym-tunnel, 10.77.0.2:9000), so the lift itself shows the
        # hold passes traffic over the unit's own interface (§12d
        # `holdInterfaces`): without that it could never pass, and the hold
        # would never lift.
        machine.wait_until_succeeds("systemctl is-active wireguard-gym.service", timeout=120)
        machine.wait_until_succeeds(lan_ok(), timeout=60)
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)
        machine.succeed(up_via_tunnel())
        machine.wait_until_succeeds(up_ok(), timeout=30)
        peer.succeed(new_ssh("alice"))
        not_held()
        assert alarms() == 1, alarms()
        machine.succeed("rm -f /run/wireguard-gym-slow")

    with subtest("repair fails every attempt: the hold stays, administrators are notified"):
        machine.succeed("touch /run/wireguard-gym-broken")
        machine.succeed("systemctl kill --signal=SIGKILL wireguard-gym.service")
        machine.wait_until_fails(lan_ok(), timeout=20)
        # The attempt budget (3, backoff 10 s / 60 s / 300 s, §13) runs out.
        machine.wait_until_succeeds(
            "journalctl -b -u planariad -o cat | grep wireguard-gym | grep -Eqi 'needs a person|administrator'", timeout=900)
        machine.fail(lan_ok())
        # The unit is down (its start fails): no tunnel.
        machine.fail(tunnel_ok())
        peer.fail(new_ssh("alice"))
        # The hold survives a restart of planariad (§12d: Sensitivity::Core).
        machine.succeed("systemctl restart planariad.service")
        machine.wait_for_unit("planarian-ready.target")
        held()
        machine.fail(lan_ok())

    with subtest("a non-administrator's hold release asks for an administrator"):
        code, out = as_alice("planarian hold release wireguard-gym")
        assert "approv" in out.lower() and "administrator" in out.lower(), out
        code, out = machine.execute("su carol -c 'planarian hold release wireguard-gym' 2>&1")
        assert "approv" in out.lower() and "administrator" in out.lower(), out
        machine.sleep(10)
        held()
        machine.fail(lan_ok())

    with subtest("fixed: the unit comes back and the hold lifts"):
        machine.succeed("rm -f /run/wireguard-gym-broken")
        machine.succeed("systemctl reset-failed wireguard-gym.service; systemctl start wireguard-gym.service")
        machine.wait_until_succeeds(lan_ok(), timeout=120)
        not_held()
        peer.succeed(new_ssh("alice"))

    # §12d "Which units" (owner decisions, Nov 2): the classifier.
    with subtest("build-time tag: CAP_NET_ADMIN makes a network tool; PrivateNetwork=yes and no capabilities does not"):
        machine.succeed("systemctl show -p OnFailure gym-capnet.service | grep -q 'planarian-hold@'")
        machine.fail("systemctl show -p OnFailure gym-privnet.service | grep -q 'planarian-hold@'")
        machine.succeed("systemctl kill --signal=SIGKILL gym-privnet.service")
        machine.sleep(15)
        not_held("gym-privnet")
        machine.succeed(lan_ok())

    with subtest("netwatch: a declared, untagged tool whose short-lived helper set a dropping firewall rule is protecting"):
        # Declared with no tag: only the kernel's attribution (the helper ran
        # in gym-vpn-untagged's cgroup) makes it protecting.
        machine.succeed("nft list table inet gymvpn")
        machine.fail("pgrep -f gym-vpn-untagged-helper")
        machine.succeed("echo 30 > /run/gym-vpn-untagged-slow")
        machine.succeed("systemctl kill --signal=SIGKILL gym-vpn-untagged.service")
        machine.wait_until_fails(lan_ok(), timeout=20)
        held_for("gym-vpn-untagged")
        machine.wait_until_succeeds("systemctl is-active gym-vpn-untagged.service", timeout=120)
        machine.wait_until_succeeds(lan_ok(), timeout=60)
        not_held("gym-vpn-untagged")
        machine.succeed("rm -f /run/gym-vpn-untagged-slow")
        machine.succeed("journalctl -b -u planariad -o cat | grep gym-vpn-untagged | grep -q 'stopped unexpectedly'")

    with subtest("a crashed (exit 1, not killed) VPN restarts at once under the hold"):
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)
        machine.succeed("echo 30 > /run/wireguard-gym-slow")
        asked = "journalctl -b -u planariad -o cat | grep -c 'wireguard-gym.*needs approval' || true"
        before = int(machine.succeed(asked).strip() or 0)
        # wireguard-go exits with an error when its TUN device goes away: a
        # crash, not a kill. (Precondition: the unit ended by its exit code.)
        machine.succeed("ip link delete wg0")
        machine.wait_until_succeeds("journalctl -b -u wireguard-gym -o cat | grep -q 'status=1/FAILURE'", timeout=30)
        machine.wait_until_fails(lan_ok(), timeout=20)
        held()
        # Restarted at once, without asking (§11: restarts_held_unit).
        machine.wait_until_succeeds("systemctl is-active wireguard-gym.service", timeout=120)
        machine.wait_until_succeeds(lan_ok(), timeout=60)
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)
        not_held()
        after = int(machine.succeed(asked).strip() or 0)
        assert after == before, f"the restart asked: {before} -> {after}"
        machine.succeed("rm -f /run/wireguard-gym-slow")

    with subtest("a templated tool's instance holds as planarian-hold@<instance>, and the restart lifts it (%N)"):
        machine.wait_for_unit("gym-tpl@a.service")
        # OnFailure= comes from the template's drop-in, with %N filled in per instance.
        machine.succeed("systemctl show -p OnFailure gym-tpl@a.service | grep -qF 'planarian-hold@gym-tpl@a.service'")
        machine.succeed("nft list table inet gymtpl_a")
        machine.succeed("echo 30 > /run/gym-tpl-a-slow")
        machine.succeed("systemctl kill --signal=SIGKILL gym-tpl@a.service")
        machine.wait_until_fails(lan_ok(), timeout=20)
        held_for("gym-tpl@a")
        machine.wait_until_succeeds("systemctl is-active gym-tpl@a.service", timeout=120)
        machine.wait_until_succeeds(lan_ok(), timeout=60)
        not_held("gym-tpl@a")
        machine.succeed("rm -f /run/gym-tpl-a-slow")

    # Gate 41562892467: a VPN killed about 1 s after its restart was not
    # held, because its footprint was still the previous instance's
    # `protecting no`. §12d: "a footprint missing or stale when a network
    # tool fails ... count[s] as protecting". Each round starts a new
    # instance from an unheld state and kills it within 200 ms of its
    # steering, before netwatch can have written that instance's footprint
    # or just after. Held every time.
    with subtest("restart loop: a VPN dying within 200 ms of steering is held, every time"):
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)
        not_held()
        def mono(unit, prop):
            return int(machine.succeed(f"systemctl show -p {prop} --value {unit}").strip() or 0)
        for delay in ["0", "0.05", "0.1", "0.2"]:
            # A new instance by the attested path (§12d: an attested stop
            # holds nothing), so this round's hold can only be the kill's.
            out = as_bob("planarian stop wireguard-gym")
            assert "approve" in out, out
            approve_as_root(out)
            machine.wait_until_fails("systemctl is-active wireguard-gym.service", timeout=60)
            not_held()
            prev = machine.succeed("systemctl show -p InvocationID --value wireguard-gym.service").strip()
            before = alarms()
            machine.succeed(f"${killAfterSteer} '{prev}' {delay} </dev/null >/dev/null 2>&1 &")
            out = as_bob("planarian release wireguard-gym")
            if "approve" in out:
                approve_as_root(out)
            machine.succeed("systemctl start --no-block wireguard-gym.service")
            machine.wait_until_succeeds("test -s /run/nw-loop.done", timeout=90)
            done = machine.succeed("cat /run/nw-loop.done").strip()
            # Preconditions: a new instance steered, and the kill landed
            # within 200 ms of it (the killer's own poll adds <= 50 ms).
            assert done != "timeout", f"delay {delay}: no new instance steered"
            ms = int(done.split()[1])
            assert ms <= float(delay) * 1000 + 50, f"delay {delay}: the kill came {ms} ms after steering"
            # Held, by this kill's OnFailure=: the hold unit became active
            # after the unit died, not left over from an earlier hold.
            machine.wait_until_fails(lan_ok(), timeout=20)
            held()
            died = mono("wireguard-gym.service", "InactiveEnterTimestampMonotonic")
            hold_at = mono("planarian-hold@wireguard-gym.service", "ActiveEnterTimestampMonotonic")
            assert hold_at >= died > 0, f"delay {delay}: hold active at {hold_at}, unit died at {died}"
            machine.fail(up_ok())
            peer.fail(new_ssh("alice"))
            assert alarms() > before, f"delay {delay}: no alarm"
            # Back: the hold lifts once the unit is Running and Ready, by the
            # repair or, if this target has escalated (§13), by hand.
            machine.succeed("systemctl reset-failed wireguard-gym.service; systemctl start wireguard-gym.service")
            machine.wait_until_succeeds(lan_ok(), timeout=120)
            machine.wait_until_succeeds(tunnel_ok(), timeout=60)
            not_held()
  '';
}
