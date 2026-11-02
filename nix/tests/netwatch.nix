# §12d "Network security fails closed" → "Which units": the reviewer's VM
# case for netwatch, written from the spec before the service. "Planarian
# attributes every routing, interface, rule and nftables change to the unit
# that made it from inside the kernel … and keeps each unit's current
# *footprint* in `/run`." "A network tool is *protecting traffic* while the
# kernel has attributed to it a change that currently steers traffic: an
# interface it created that carries a default or all-covering route, … or
# firewall rules that drop or redirect traffic." "Fail closed: … a footprint
# missing or stale when a network tool fails, or a watch that failed to
# attach, all count as protecting."
#
# The footprint contract this reads (#38's hold condition, nix/posture.nix):
# /run/planarian/footprint/.watch is `attached <t>`; each network tool's file
# /run/planarian/footprint/<unit> (named by %N: no `.service`) has
# `protecting yes|no`, `at <t>` and `iface <name>` lines; every <t> is
# CLOCK_BOOTTIME seconds (/proc/uptime), fresh from 5 s ahead to 30 s old.
#
# Fixtures (all root with no capability bounding set, so network tools by
# the build-time rule): nw-route makes a dummy interface and a default route
# over it; nw-quiet steers nothing; nw-legacy adds a legacy-iptables OUTPUT
# drop; nw-nft loads an nftables table with an output drop. The drops target
# 203.0.113.79 and .80 (TEST-NET-3), and the default route has metric 4000,
# so none of them disturbs the test itself.
{ pkgs, self }:

let
  ipt = "${pkgs.iptables}/bin/iptables-legacy";
  ip = "${pkgs.iproute2}/bin/ip";
  nft = "${pkgs.nftables}/bin/nft";
  oneshot = start: stop: {
    wantedBy = [ "multi-user.target" ];
    after = [ "planarian-netwatch.service" ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; ExecStart = start; ExecStop = stop; };
  };
in
pkgs.testers.runNixOSTest {
  name = "planarian-netwatch";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.planarian.enable = true;
    networking.firewall.enable = false;
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.iproute2 pkgs.iptables pkgs.nftables ];

    systemd.services.nw-route = oneshot
      (pkgs.writeShellScript "nw-route-up" ''
        ${ip} link add nwdummy0 type dummy
        ${ip} link set nwdummy0 up
        ${ip} route add default dev nwdummy0 metric 4000
      '')
      "${ip} link delete nwdummy0";
    systemd.services.nw-quiet = {
      wantedBy = [ "multi-user.target" ];
      after = [ "planarian-netwatch.service" ];
      serviceConfig = { Type = "simple"; Restart = "no"; ExecStart = "${pkgs.coreutils}/bin/sleep infinity"; };
    };
    systemd.services.nw-legacy = oneshot
      "${ipt} -A OUTPUT -d 203.0.113.79 -j DROP"
      "${ipt} -D OUTPUT -d 203.0.113.79 -j DROP";
    systemd.services.nw-nft = oneshot
      "${nft} 'add table inet nwnft; add chain inet nwnft out { type filter hook output priority 0; }; add rule inet nwnft out ip daddr 203.0.113.80 drop'"
      "${nft} delete table inet nwnft";
    # Declared with no tag so the daemon restarts nw-quiet after (f).
    services.planarian.units.nw-quiet = { };
  };

  testScript = ''
    FP = "/run/planarian/footprint"

    def uptime():
        return int(machine.succeed("cut -d. -f1 /proc/uptime").strip())

    def fresh(t):
        age = uptime() - int(t)
        return -5 <= age <= 30

    def footprint(unit):
        return machine.succeed(f"cat {FP}/{unit}").splitlines()

    def stamp(lines):
        at = [l.split()[1] for l in lines if l.startswith("at ")]
        assert len(at) == 1, lines
        return at[0]

    def protecting(unit, want):
        # netwatch has seen the change (the footprint is current) and says so.
        machine.wait_until_succeeds(f"grep -qx 'protecting {want}' {FP}/{unit}", timeout=60)
        lines = footprint(unit)
        assert fresh(stamp(lines)), (unit, lines, uptime())
        return lines

    machine.wait_for_unit("planarian-ready.target")
    machine.wait_for_unit("planarian-netwatch.service")
    for u in ["nw-route", "nw-quiet", "nw-legacy", "nw-nft"]:
        machine.wait_for_unit(f"{u}.service")

    with subtest("(a) the watch is attached, with a fresh CLOCK_BOOTTIME stamp"):
        machine.wait_until_succeeds(f"grep -q '^attached ' {FP}/.watch", timeout=60)
        state, t = machine.succeed(f"cat {FP}/.watch").split()[:2]
        assert state == "attached" and fresh(t), (state, t, uptime())
        # It is refreshed: a later read is newer, and still fresh.
        machine.sleep(12)
        _, t2 = machine.succeed(f"cat {FP}/.watch").split()[:2]
        assert int(t2) > int(t) and fresh(t2), (t, t2, uptime())

    with subtest("(b) a dummy interface with a default route over it: protecting, with that interface"):
        lines = protecting("nw-route", "yes")
        assert "iface nwdummy0" in lines, lines

    with subtest("(c) a network tool that steers nothing: not protecting"):
        protecting("nw-quiet", "no")
        machine.fail(f"test -e {FP}/.unattributed")

    with subtest("(d) a legacy iptables OUTPUT drop: protecting"):
        machine.succeed("${ipt} -S OUTPUT | grep -q 203.0.113.79")
        protecting("nw-legacy", "yes")

    with subtest("(e) an nftables table that drops traffic: protecting"):
        machine.succeed("${nft} list table inet nwnft")
        protecting("nw-nft", "yes")

    with subtest("(f) a stopped watch goes stale, and a failing tool that was not protecting is held"):
        # Stopped, not killed: a killed watcher may be restarted at once, and
        # what is under test is a watch that is no longer refreshed.
        machine.succeed("systemctl kill --signal=SIGSTOP planarian-netwatch.service")
        machine.wait_until_succeeds(
            f"t=$(awk '{{print $2}}' {FP}/.watch); [ $(( $(cut -d. -f1 /proc/uptime) - t )) -gt 30 ]", timeout=90)
        # nw-quiet's footprint still says `protecting no`; only staleness can hold it.
        machine.succeed(f"grep -qx 'protecting no' {FP}/nw-quiet")
        machine.succeed("systemctl kill --signal=SIGKILL nw-quiet.service")
        machine.wait_until_succeeds("systemctl is-active planarian-hold@nw-quiet.service", timeout=30)
        machine.succeed("nft list table inet planarian-hold")
        machine.succeed("test -e /run/planarian/hold/nw-quiet")
        # The watch resumes; once nw-quiet is back, its hold lifts.
        machine.succeed("systemctl kill --signal=SIGCONT planarian-netwatch.service")
        machine.wait_until_succeeds(f"t=$(awk '{{print $2}}' {FP}/.watch); [ $(( $(cut -d. -f1 /proc/uptime) - t )) -le 30 ]", timeout=60)
        machine.wait_until_succeeds("systemctl is-active nw-quiet.service", timeout=120)
        machine.wait_until_fails("systemctl is-active planarian-hold@nw-quiet.service", timeout=120)
        machine.fail("test -e /run/planarian/hold/nw-quiet")
  '';
}
