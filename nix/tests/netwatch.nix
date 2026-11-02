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
# over it; nw-quiet steers nothing; nw-nft loads an nftables table with an
# output drop (to 203.0.113.80, TEST-NET-3); the default route has metric
# 4000, so none of them disturbs the test itself. There is no legacy-iptables
# fixture: the reference kernel has no legacy xtables tables
# (CONFIG_NETFILTER_XTABLES_LEGACY unset) and NixOS blacklists ip_tables with
# nftables, so nothing on it can steer through legacy iptables (see (d)).
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
    # The firewall on (nftables backend): its boot ruleset is a dropping
    # rule made at boot, and must be attributed to nftables.service, which
    # netwatch must have attached before (not read as pre-attach steering
    # that would hold every network tool's failure).
    networking.firewall.enable = true;
    networking.nftables.enable = true;
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
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        # /run/nw-quiet-slow: seconds its start takes, so the daemon's restart
        # (which lifts the hold) cannot outrun the check that the hold is up.
        ExecStartPre = "${pkgs.bash}/bin/bash -c 'sleep $(cat /run/nw-quiet-slow 2>/dev/null || echo 0)'";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
    systemd.services.nw-nft = oneshot
      "${nft} 'add table inet nwnft; add chain inet nwnft out { type filter hook output priority 0; }; add rule inet nwnft out ip daddr 203.0.113.80 drop'"
      "${nft} delete table inet nwnft";
    # A WireGuard interface (a network tool by its netdev, §12d), with no
    # peer: only its ordering after the watch is under test. A fixed test key.
    networking.wireguard.interfaces.wgnw = {
      ips = [ "10.78.0.1/24" ];
      privateKeyFile = "${pkgs.writeText "wgnw.key" "uJhR8JkZjr32TbqdjI+D0hftWxS1UzsOHfr1VRjvLWA="}";
      peers = [ ];
    };
    # A templated network tool, instance `a` (root, no bounding set).
    systemd.services."nw-tpl@" = {
      serviceConfig = { Type = "simple"; Restart = "no"; ExecStart = "${pkgs.coreutils}/bin/sleep infinity"; };
    };
    systemd.targets.multi-user.wants = [ "nw-tpl@a.service" ];
    # Declared with no tag so the daemon restarts nw-quiet after each kill.
    services.planarian.units.nw-quiet = { };
  };

  # A second node for netwatch's retry rule: no firewall, no nftables, and
  # no module loaded at boot, so nfnetlink is absent when netwatch starts.
  nodes.bare = { lib, ... }: {
    imports = [ self.nixosModules.default ];
    services.planarian.enable = true;
    networking.firewall.enable = false;
    networking.nftables.enable = false;
    boot.kernelModules = lib.mkForce [ ];
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

    def watch_fresh():
        machine.wait_until_succeeds(
            f"grep -q '^attached ' {FP}/.watch && t=$(awk '{{print $2}}' {FP}/.watch) && [ $(( $(cut -d. -f1 /proc/uptime) - t )) -le 30 ]", timeout=60)

    def quiet_is_held():
        # nw-quiet steers nothing; whatever holds it is the watch's state.
        machine.succeed("echo 30 > /run/nw-quiet-slow")
        machine.succeed(f"grep -qx 'protecting no' {FP}/nw-quiet")
        machine.succeed("systemctl kill --signal=SIGKILL nw-quiet.service")
        machine.wait_until_succeeds("systemctl is-active planarian-hold@nw-quiet.service", timeout=30)
        machine.succeed("nft list table inet planarian-hold")
        machine.succeed("test -e /run/planarian/hold/nw-quiet")

    def quiet_back_and_lifted():
        machine.wait_until_succeeds("systemctl is-active nw-quiet.service", timeout=120)
        machine.wait_until_fails("systemctl is-active planarian-hold@nw-quiet.service", timeout=120)
        machine.fail("test -e /run/planarian/hold/nw-quiet")
        machine.succeed("rm -f /run/nw-quiet-slow")

    machine.wait_for_unit("planarian-ready.target")
    machine.wait_for_unit("planarian-netwatch.service")
    for u in ["nw-route", "nw-quiet", "nw-nft"]:
        machine.wait_for_unit(f"{u}.service")

    with subtest("(a) the watch is attached, with a fresh CLOCK_BOOTTIME stamp"):
        machine.wait_until_succeeds(f"grep -q '^attached ' {FP}/.watch", timeout=60)
        state, t = machine.succeed(f"cat {FP}/.watch").split()[:2]
        assert state == "attached" and fresh(t), (state, t, uptime())
        # It is refreshed: a later read is newer, and still fresh.
        machine.sleep(12)
        _, t2 = machine.succeed(f"cat {FP}/.watch").split()[:2]
        assert int(t2) > int(t) and fresh(t2), (t, t2, uptime())

    with subtest("(a2) the firewall's boot ruleset is attributed to it, not pre-attach"):
        # netwatch was attached before nftables.service loaded its ruleset
        # (ordering alone is not enough if netwatch reports started before
        # its probes are attached).
        machine.succeed("${nft} list ruleset | grep -q 'policy drop'")
        protecting("nftables", "yes")
        machine.fail(f"test -e {FP}/.unattributed")

    with subtest("(j) at boot every network tool starts only after the watch is ready; nothing is pre-attach"):
        # "Every network tool is ordered after planarian-netwatch.service.
        # That service reports ready only once its probes are attached and
        # its first footprints are written" (§12d). Under Type=notify,
        # netwatch's ActiveEnter is its READY=1; a tool's InactiveExit is
        # when it began to start. Units the watch itself needs are exempt
        # (the export's networkToolsUnordered).
        import json
        export = json.loads(machine.succeed("cat /etc/planarian/export.json"))
        tools = set(export["networkTools"]) - set(export.get("networkToolsUnordered", []))
        for want in ["nw-route", "nw-quiet", "nw-nft", "nftables", "wireguard-wgnw", "nw-tpl@"]:
            assert want in tools, (want, sorted(tools))
        def mono(unit, prop):
            return int(machine.succeed(f"systemctl show -P {prop} {unit}").strip() or 0)
        ready = mono("planarian-netwatch.service", "ActiveEnterTimestampMonotonic")
        assert ready > 0, "netwatch never became active"
        units = []
        for t in sorted(tools):
            if t.endswith("@"):
                # (l) each loaded instance of a templated tool is ordered too.
                out = machine.succeed(f"systemctl list-units --all --plain --no-legend '{t}*.service' | awk '{{print $1}}'")
                units += [u for u in out.split() if u]
            else:
                units.append(f"{t}.service")
        assert "nw-tpl@a.service" in units, units
        early = []
        for u in units:
            began = mono(u, "InactiveExitTimestampMonotonic")
            if began and began < ready:
                early.append((u, began, ready))
        assert not early, f"started before the watch was ready: {early}"
        machine.fail(f"grep -rq 'pre-attach' {FP}")
        machine.fail(f"test -e {FP}/.unattributed")

    with subtest("(b) a dummy interface with a default route over it: protecting, with that interface"):
        lines = protecting("nw-route", "yes")
        assert "iface nwdummy0" in lines, lines

    with subtest("(c) a network tool that steers nothing: not protecting"):
        protecting("nw-quiet", "no")
        machine.fail(f"test -e {FP}/.unattributed")

    with subtest("(d) legacy iptables cannot steer on the reference kernel"):
        # It has no legacy xtables tables, so a legacy rule cannot be loaded
        # at all: that path (nf_setsockopt) has nothing to attribute here.
        # netwatch still attaches its probe for kernels that have it.
        machine.fail("${ipt} -A OUTPUT -d 203.0.113.79 -j DROP")
        machine.fail("${ipt} -S OUTPUT")

    with subtest("(e) an nftables table that drops traffic: protecting"):
        machine.succeed("${nft} list table inet nwnft")
        protecting("nw-nft", "yes")

    with subtest("(g) netwatch killed and restarted: what was protecting still reads protecting"):
        # A restart sees existing state it did not watch being made; a tool
        # that was protecting must not come back as `protecting no` (fail
        # closed: a change it cannot attribute counts as protecting).
        n0 = int(machine.succeed("systemctl show -P NRestarts planarian-netwatch.service").strip())
        _, t0 = machine.succeed(f"cat {FP}/.watch").split()[:2]
        machine.succeed("systemctl kill --signal=SIGKILL planarian-netwatch.service")
        machine.wait_until_succeeds(
            f"[ $(systemctl show -P NRestarts planarian-netwatch.service) -gt {n0} ] && systemctl is-active planarian-netwatch.service", timeout=60)
        machine.wait_until_succeeds(f"grep -q '^attached ' {FP}/.watch && [ $(awk '{{print $2}}' {FP}/.watch) -gt {t0} ]", timeout=60)
        for u in ["nw-route", "nw-nft"]:
            protecting(u, "yes")
        assert "iface nwdummy0" in footprint("nw-route")

    with subtest("(f) a stopped watch goes stale, and a failing tool that was not protecting is held"):
        # Stopped, not killed: a killed watcher may be restarted at once, and
        # what is under test is a watch that is no longer refreshed.
        machine.succeed("systemctl kill --signal=SIGSTOP planarian-netwatch.service")
        machine.wait_until_succeeds(
            f"t=$(awk '{{print $2}}' {FP}/.watch); [ $(( $(cut -d. -f1 /proc/uptime) - t )) -gt 30 ]", timeout=90)
        # nw-quiet's footprint still says `protecting no`; only staleness can hold it.
        quiet_is_held()
        # The watch resumes; once nw-quiet is back, its hold lifts.
        machine.succeed("systemctl kill --signal=SIGCONT planarian-netwatch.service")
        watch_fresh()
        quiet_back_and_lifted()

    with subtest("(h) a stopped watch reads failed, and a failing tool that was not protecting is held"):
        machine.succeed("systemctl stop planarian-netwatch.service")
        machine.succeed(f"grep -q '^failed' {FP}/.watch")
        quiet_is_held()
        machine.succeed("systemctl start planarian-netwatch.service")
        watch_fresh()
        quiet_back_and_lifted()

    with subtest("(i) steering made while the watch was down is unattributed after it re-attaches, and holds"):
        # Made by root from the test driver, outside any unit, while netwatch
        # is stopped: on attach, netwatch finds a default route it never saw
        # made and no claim covers (contract: `.unattributed`, reason
        # `pre-attach <object>`, until the object is gone).
        machine.succeed("systemctl stop planarian-netwatch.service")
        machine.succeed("${ip} link add nwgap0 type dummy && ${ip} link set nwgap0 up && ${ip} route add default dev nwgap0 metric 4001")
        machine.succeed("systemctl start planarian-netwatch.service")
        watch_fresh()
        machine.wait_until_succeeds(f"grep -q 'pre-attach' {FP}/.unattributed", timeout=30)
        # The claims survived the re-attach; nw-quiet is fresh and still `protecting no`.
        protecting("nw-route", "yes")
        protecting("nw-quiet", "no")
        quiet_is_held()
        # The object gone, the unattributed change no longer stands.
        machine.succeed("${ip} link delete nwgap0")
        machine.wait_until_fails(f"test -e {FP}/.unattributed", timeout=30)
        quiet_back_and_lifted()
    with subtest("(k) a watch that fails to start: network tools still start, .watch reads failed, a failing tool is held"):
        # "The ordering is not a dependency: if the watch fails to start,
        # network tools still start, and the watch counts as failed" (§12d).
        # Its eBPF object is made empty (a bind mount of /dev/null over it),
        # which the loader refuses.
        import re
        argv = machine.succeed("systemctl show -P ExecStart planarian-netwatch.service")
        m = re.search(r"--object (\S+)", argv)
        assert m, argv
        obj = m.group(1)
        machine.succeed("systemctl stop planarian-netwatch.service nw-quiet.service")
        machine.succeed(f"rm -f {FP}/.watch")
        machine.succeed(f"mount --bind /dev/null {obj}")
        # One transaction, as at boot: nw-quiet is ordered after the watch.
        machine.execute("systemctl start planarian-netwatch.service nw-quiet.service")
        machine.wait_until_succeeds("systemctl is-active nw-quiet.service", timeout=90)
        machine.wait_until_succeeds(f"grep -q '^failed' {FP}/.watch", timeout=60)
        quiet_is_held()
        # Repaired: the object back, the watch attaches, and the hold lifts.
        machine.succeed(f"umount {obj}")
        machine.succeed("systemctl reset-failed planarian-netwatch.service; systemctl start planarian-netwatch.service")
        watch_fresh()
        quiet_back_and_lifted()
    with subtest("(m) the kernel refuses the attach (nfnetlink absent): failed, up, and attached within ~30 s of the module loading"):
        # Coordinator, Nov 2: a load or attach the kernel refuses writes
        # `failed`, sends READY=1 and stays up, retrying every 30 s.
        bare.start()
        bare.wait_for_unit("planarian-netwatch.service")
        bare.fail("grep -qw '^nfnetlink' /proc/modules")
        bare.wait_until_succeeds(f"grep -q '^failed' {FP}/.watch", timeout=60)
        bare.succeed("systemctl is-active planarian-netwatch.service")
        n0 = bare.succeed("systemctl show -P NRestarts planarian-netwatch.service").strip()
        bare.succeed("modprobe nfnetlink")
        bare.wait_until_succeeds(f"grep -q '^attached ' {FP}/.watch", timeout=45)
        # Retried in place, not by systemd restarting it.
        assert bare.succeed("systemctl show -P NRestarts planarian-netwatch.service").strip() == n0
  '';
}
