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
in
pkgs.testers.runNixOSTest {
  name = "planarian-netsec";

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
    environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.util-linux ];
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 8192;

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
    def new_ssh(user):
        return f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o ControlPath=none -i /root/key {user}@machine true"
    def alarms():
        return int(machine.succeed(f"journalctl -b -u planariad -o cat | grep -c '{ALARM}' || true").strip() or 0)
    def held():
        machine.succeed("nft list table inet planarian-hold")
        machine.succeed("systemctl is-active planarian-hold@wireguard-gym.service")
        machine.succeed("test -e /run/planarian/hold/wireguard-gym")
    def not_held():
        machine.fail("systemctl is-active planarian-hold@wireguard-gym.service")
        machine.fail("test -e /run/planarian/hold/wireguard-gym")
    def as_alice(cmd):
        return machine.execute(f"su alice -c '{cmd}' 2>&1")
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
        peer.succeed(new_ssh("alice"))
        not_held()
        assert alarms() == 0

    with subtest("planarian stop holds nothing (§12d: an attested stop is not a failure)"):
        out = machine.succeed("planarian stop wireguard-gym 2>&1 || true")
        if "approve" in out:
            approve_as_root(out)
        machine.wait_until_fails("systemctl is-active wireguard-gym.service", timeout=60)
        machine.sleep(15)
        not_held()
        machine.succeed(lan_ok())
        peer.succeed(new_ssh("alice"))
        assert alarms() == 0, alarms()
        out = machine.succeed("planarian release wireguard-gym 2>&1 || true")
        if "approve" in out:
            approve_as_root(out)
        machine.succeed("systemctl start wireguard-gym.service")
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)

    with subtest("a kill holds traffic; the restart lifts the hold, with one alarm"):
        # An administrator's session, established before the failure.
        peer.succeed("ssh -fN -M -S /tmp/bob.sock -o ControlPersist=yes -o BatchMode=yes -o StrictHostKeyChecking=no -i /root/key bob@machine")
        peer.succeed("ssh -S /tmp/bob.sock bob@machine true")
        machine.succeed("echo 40 > /run/wireguard-gym-slow")
        machine.succeed("systemctl kill --signal=SIGKILL wireguard-gym.service")
        # Held: new outbound connections fail, loopback works, the admin's
        # established session survives, a new SSH login is refused.
        machine.wait_until_fails(lan_ok(), timeout=20)
        held()
        # The unit is down (killed; its restart still starting): no tunnel.
        machine.fail(tunnel_ok())
        machine.succeed("curl -sf --max-time 5 -o /dev/null http://127.0.0.1:8001/")
        peer.succeed("ssh -S /tmp/bob.sock bob@machine true")
        peer.fail(new_ssh("alice"))
        peer.fail(new_ssh("bob"))
        # Restarted by Planarian at once; the hold lifts once it is Running
        # and its Readiness probe passes. That probe crosses the tunnel
        # (wireguard-gym-tunnel, 10.77.0.2:9000), so the lift itself shows the
        # hold passes traffic over the unit's own interface (§12d
        # `holdInterfaces`): without that it could never pass, and the hold
        # would never lift.
        machine.wait_until_succeeds("systemctl is-active wireguard-gym.service", timeout=120)
        machine.wait_until_succeeds(lan_ok(), timeout=60)
        machine.wait_until_succeeds(tunnel_ok(), timeout=60)
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
        peer.succeed(new_ssh("alice"))
  '';
}
