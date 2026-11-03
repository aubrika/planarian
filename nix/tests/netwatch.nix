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
# over it; nw-quiet steers nothing; nw-sockopt makes a legacy-iptables call
# (setsockopt IPT_SO_SET_REPLACE, which reaches nf_setsockopt); nw-nft loads
# an nftables table with an output drop (to 203.0.113.80, TEST-NET-3). The
# default route has metric 4000, so none of them disturbs the test itself.
{ pkgs, self }:

let
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
    # (o)/(p) create tun devices: load the driver at boot rather than rely
    # on /dev/net/tun's autoload.
    boot.kernelModules = [ "tun" ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.iproute2 pkgs.iptables pkgs.nftables pkgs.wireguard-tools pkgs.jq ];

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
    # The reference kernel has no legacy xtables tables, so iptables-legacy
    # cannot load a rule; the call itself still reaches nf_setsockopt (in
    # ip_setsockopt, an IPT-range optname goes there before any module or
    # capability check) and returns ENOPROTOOPT. netwatch counts any such
    # call from a unit as steering (fail closed). The error is expected.
    systemd.services.nw-sockopt = oneshot
      (pkgs.writers.writePython3 "nw-sockopt-setsockopt" { } ''
        import errno
        import socket

        IPT_SO_SET_REPLACE = 64
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.IPPROTO_IP, IPT_SO_SET_REPLACE, b"x")
        except OSError as e:
            name = errno.errorcode.get(e.errno, e.errno)
            print("setsockopt IPT_SO_SET_REPLACE:", name)
      '')
      "${pkgs.coreutils}/bin/true";
    # A host VPN's interface named wg0 (a dummy: the name is what matters)
    # carrying a default route: protecting, for (n).
    systemd.services.nw-hostwg = oneshot
      (pkgs.writeShellScript "nw-hostwg-up" ''
        ${ip} link add wg0 type dummy
        ${ip} link set wg0 up
        ${ip} route add default dev wg0 metric 4002
      '')
      "${ip} link delete wg0";
    # (o) OpenVPN's way: the unit opens /dev/net/tun itself (ioctl
    # TUNSETIFF, no netlink), holds it, and routes the all-covering pair 0/1
    # and 128/1 over nwtun0: not a name the kernel's tun%d hands out, so
    # (q)'s kernel-named tun never collides with it. No IPv4 egress needed.
    systemd.services.nw-tun = {
      wantedBy = [ "multi-user.target" ];
      after = [ "planarian-netwatch.service" ];
      path = [ pkgs.iproute2 ];
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        ExecStart = pkgs.writers.writePython3 "nw-tun-holder" { } ''
          import fcntl
          import signal
          import struct
          import subprocess

          TUNSETIFF = 0x400454CA
          IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
          fd = open("/dev/net/tun", "r+b", buffering=0)
          req = struct.pack("16sH", b"nwtun0", IFF_TUN | IFF_NO_PI)
          fcntl.ioctl(fd, TUNSETIFF, req)
          for cmd in (["link", "set", "nwtun0", "up"],
                      ["route", "add", "0.0.0.0/1", "dev", "nwtun0"],
                      ["route", "add", "128.0.0.0/1", "dev", "nwtun0"]):
              subprocess.run(["ip"] + cmd, check=True)
          signal.pause()
        '';
      };
    };
    # (q) OpenVPN's default (`dev tun`): TUNSETIFF with an empty name, so
    # the kernel names the device itself (tun%d resolves at registration).
    # The helper writes the name it got to /run/nw-tunauto.name and routes
    # 0/1 and 128/1 over it at metric 60.
    systemd.services.nw-tunauto = {
      wantedBy = [ "multi-user.target" ];
      after = [ "planarian-netwatch.service" "nw-tun.service" ];
      path = [ pkgs.iproute2 ];
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        ExecStart = pkgs.writers.writePython3 "nw-tunauto-holder" { } ''
          import fcntl
          import signal
          import struct
          import subprocess

          TUNSETIFF = 0x400454CA
          IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
          fd = open("/dev/net/tun", "r+b", buffering=0)
          req = struct.pack("16sH", b"", IFF_TUN | IFF_NO_PI)
          got = fcntl.ioctl(fd, TUNSETIFF, req)
          name = got[:16].split(b"\0")[0].decode()
          for cmd in (["link", "set", name, "up"],
                      ["route", "add", "0.0.0.0/1", "dev", name,
                       "metric", "60"],
                      ["route", "add", "128.0.0.0/1", "dev", name,
                       "metric", "60"]):
              subprocess.run(["ip"] + cmd, check=True)
          with open("/run/nw-tunauto.name", "w") as f:
              f.write(name)
          signal.pause()
        '';
      };
    };
    # (p) A setup unit makes a persistent tun (`ip tuntap add`, ioctl) and
    # routes nothing; a second unit routes 0/1 and 128/1 over it (metric 50,
    # beside nwtun0's). Both count: the creator's interface carries the
    # routes, and the router steers over a virtual interface.
    systemd.services.nw-tunsetup = oneshot
      "${ip} tuntap add dev nwtap0 mode tun"
      "${ip} tuntap del dev nwtap0 mode tun";
    systemd.services.nw-tunroute = (oneshot
      (pkgs.writeShellScript "nw-tunroute-up" ''
        ${ip} link set nwtap0 up
        ${ip} route add 0.0.0.0/1 dev nwtap0 metric 50
        ${ip} route add 128.0.0.0/1 dev nwtap0 metric 50
      '')
      "${ip} route flush dev nwtap0") // {
        after = [ "planarian-netwatch.service" "nw-tunsetup.service" ];
        requires = [ "nw-tunsetup.service" ];
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
    # (r) The mover: a network tool (root, no bounding set) that runs, in its
    # own cgroup, each script the driver drops at /run/nw-mover/go, and
    # never stops (so no stop of it is under test). Exit status in rc.
    systemd.services.nw-mover = {
      wantedBy = [ "multi-user.target" ];
      after = [ "planarian-netwatch.service" ];
      path = [ pkgs.iproute2 pkgs.coreutils pkgs.bash ];
      serviceConfig = { Type = "simple"; Restart = "no"; };
      script = ''
        mkdir -p /run/nw-mover
        while :; do
          if [ -e /run/nw-mover/go ]; then
            bash /run/nw-mover/go > /run/nw-mover/out 2>&1; rc=$?
            rm -f /run/nw-mover/go; echo $rc > /run/nw-mover/rc
          fi
          sleep 0.2
        done
    # (s) A WireGuard tunnel that configures its own peers over generic
    # netlink (`wg set`), as a VPN client does: one IPv4 and one IPv6 peer,
    # TEST-NET and documentation addresses (nothing answers; only what the
    # footprint and the hold carry is under test). Its default route has
    # metric 4007, so it steers (protecting) without carrying the test's
    # traffic. ExecReload moves the first peer, from inside its cgroup, as a
    # roaming client or `wg syncconf` does. /run/nw-wg-slow: seconds its
    # start takes, so the daemon's restart cannot outrun the hold's check.
    systemd.services.nw-wg = {
      wantedBy = [ "multi-user.target" ];
      after = [ "planarian-netwatch.service" ];
      path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.coreutils ];
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        ExecStartPre = "${pkgs.bash}/bin/bash -c 'sleep $(cat /run/nw-wg-slow 2>/dev/null || echo 0)'";
        ExecReload = pkgs.writeShellScript "nw-wg-reload" ''
          set -e
          PATH=${pkgs.lib.makeBinPath [ pkgs.wireguard-tools pkgs.coreutils ]}
          wg set nwwg0 peer "$(cat /run/nw-wg/p1)" endpoint 192.0.2.8:51822
        '';
      };
      script = ''
        set -e
        mkdir -p /run/nw-wg
        ip link del nwwg0 2>/dev/null || true
        ip link add nwwg0 type wireguard
        wg genkey > /run/nw-wg/key
        p1="$(wg genkey | wg pubkey)"; p2="$(wg genkey | wg pubkey)"
        echo "$p1" > /run/nw-wg/p1
        wg set nwwg0 private-key /run/nw-wg/key listen-port 51900 \
          peer "$p1" endpoint 192.0.2.7:51820 allowed-ips 10.79.0.2/32 \
          peer "$p2" endpoint '[2001:db8::7]:51821' allowed-ips 10.79.0.3/32
        ip link set nwwg0 up
        ip route add default dev nwwg0 metric 4007
        exec sleep infinity
      '';
    };
    # A templated network tool, instance `a` (root, no bounding set).
    systemd.services."nw-tpl@" = {
      serviceConfig = { Type = "simple"; Restart = "no"; ExecStart = "${pkgs.coreutils}/bin/sleep infinity"; };
    };
    systemd.targets.multi-user.wants = [ "nw-tpl@a.service" ];
    # Declared with no tag so the daemon restarts nw-quiet after each kill.
    services.planarian.units.nw-quiet = { };
    # Declared too, so the daemon restarts nw-wg after (s)'s kill.
    services.planarian.units.nw-wg = { };
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
        # Brought back by hand: what is under test here is the hold and its
        # lift (Running, so the hold lifts), not the repair, which vm-netsec
        # checks. (f), (h), (i) and (k) each kill nw-quiet inside one
        # incident's window, so by (k) §13's attempt budget is spent and no
        # repair comes (gate 41596671872). A repair already under way is
        # joined, not doubled.
        machine.succeed("rm -f /run/nw-quiet-slow")
        machine.succeed("systemctl reset-failed nw-quiet.service; systemctl start nw-quiet.service")
        machine.wait_until_succeeds("systemctl is-active nw-quiet.service", timeout=120)
        machine.wait_until_fails("systemctl is-active planarian-hold@nw-quiet.service", timeout=120)
        # is-active fails as soon as the hold unit is deactivating, before
        # its ExecStop (`lift`) has removed the marker: wait for that too.
        machine.wait_until_fails("test -e /run/planarian/hold/nw-quiet", timeout=30)
        machine.succeed("rm -f /run/nw-quiet-slow")

    machine.wait_for_unit("planarian-ready.target")
    machine.wait_for_unit("planarian-netwatch.service")
    for u in ["nw-mover", "nw-wg", "nw-route", "nw-quiet", "nw-sockopt", "nw-nft", "nw-hostwg", "nw-tun", "nw-tunsetup", "nw-tunroute", "nw-tunauto"]:
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
        for want in ["nw-route", "nw-quiet", "nw-sockopt", "nw-nft", "nftables", "wireguard-wgnw", "nw-tpl@"]:
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
        # A unit the systemd initrd also runs (the export's
        # networkToolsInitrd, names or templates) that last started there,
        # before the switch to userspace, did not start in stage 2: whatever
        # it left steering is caught at attach as pre-attach. Exempt only
        # then; one restarted in stage 2 is checked like any other.
        initrd = set(export.get("networkToolsInitrd", []))
        userspace = int(machine.succeed("systemctl show -P UserspaceTimestampMonotonic").strip() or 0)
        assert userspace > 0, "no UserspaceTimestampMonotonic"
        def in_initrd(u):
            n = u.removesuffix(".service")
            return n in initrd or ("@" in n and n.split("@")[0] + "@" in initrd)
        early = []
        for u in units:
            began = mono(u, "InactiveExitTimestampMonotonic")
            if began and began < ready:
                if in_initrd(u) and began < userspace:
                    continue
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

    with subtest("(d) a legacy-iptables call (nf_setsockopt) from a unit: protecting"):
        # nw-sockopt's call returned an error (no legacy tables here), and
        # the unit still finished: what is under test is the attribution.
        machine.succeed("journalctl -b -u nw-sockopt -o cat | grep -q 'setsockopt IPT_SO_SET_REPLACE'")
        protecting("nw-sockopt", "yes")
        # Context: this kernel has no legacy xtables tables (iptables-legacy
        # fails at boot, gate run 41507137168), so the call above is the only
        # producer here. Checked without a call of our own, which would be an
        # unattributed change from the test driver.
        machine.fail("test -e /proc/net/ip_tables_names")

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
        for u in ["nw-route", "nw-sockopt", "nw-nft"]:
            protecting(u, "yes")
        assert "iface nwdummy0" in footprint("nw-route")

    with subtest("(n) other network namespaces are not the host's: same-named wg0, routes, a moved interface"):
        # §12d: protecting is about "how traffic leaves the machine", the host
        # netns. The driver's commands run in backdoor.service, a network
        # tool here, so whatever netwatch takes from them is charged to it.
        def dump():
            # What netwatch wrote, for a timeout's log.
            print(machine.execute(f"for f in {FP}/backdoor {FP}/nw-hostwg {FP}/.unattributed {FP}/.watch; do echo \"== $f\"; cat \"$f\" 2>&1; done")[1])
        def wait_or_dump(cmd, timeout):
            try:
                machine.wait_until_succeeds(cmd, timeout=timeout)
            except Exception:
                dump()
                raise
        try:
            protecting("nw-hostwg", "yes")
            assert "iface wg0" in footprint("nw-hostwg")
            protecting("backdoor", "no")
        except Exception:
            dump()
            raise
        machine.succeed("${ip} netns add nwns")
        # Fail-open guard: a wg0 made and deleted in another netns leaves the
        # host VPN's wg0 claim (and its route) alone.
        machine.succeed("${ip} -n nwns link add wg0 type dummy && ${ip} -n nwns link set wg0 up")
        machine.succeed("${ip} -n nwns link del wg0")
        # Spurious-hold guard: a default route inside the netns is not host
        # steering.
        machine.succeed("${ip} -n nwns link add nsd0 type dummy && ${ip} -n nwns link set nsd0 up")
        machine.succeed("${ip} -n nwns route add default dev nsd0")
        machine.sleep(12)
        try:
            lines = protecting("nw-hostwg", "yes")
            assert "iface wg0" in lines, lines
            protecting("backdoor", "no")
            machine.fail(f"test -e {FP}/.unattributed")
        except Exception:
            dump()
            raise
        # A virtual interface made in the netns and moved into the host is
        # host steering once a default route uses it: charged to whoever
        # moved it, or unattributed; never read as a physical NIC.
        machine.succeed("${ip} -n nwns link add nwmove0 type dummy && ${ip} -n nwns link set nwmove0 netns 1")
        machine.succeed("${ip} link set nwmove0 up && ${ip} route add default dev nwmove0 metric 4003")
        # The contract allows either: the mover protecting, or the mover's
        # footprint marked `unattributed`, or the global `.unattributed`.
        wait_or_dump(
            f"grep -qx 'protecting yes' {FP}/backdoor || grep -qx unattributed {FP}/backdoor"
            f" || test -e {FP}/.unattributed", 30)
        machine.succeed("${ip} link del nwmove0 && ${ip} netns del nwns")
        # Gone again: nothing global stands. A per-unit `unattributed` mark on
        # the mover may outlive the link (fail closed), so backdoor is not
        # required back at `protecting no`.
        wait_or_dump(f"! test -e {FP}/.unattributed", 30)
        protecting("nw-hostwg", "yes")

    with subtest("(r) moves between namespaces: into the host a claim by its host name, out of it gone, between others nothing"):
        # §12d: "Planarian attributes every routing, interface, rule and
        # nftables change to the unit that made it"; "an interface it created
        # that carries a default or all-covering route" is protecting. A move
        # into the host makes a host interface, so it is the mover's, under
        # the name it has in the host; once that device is gone, nothing it
        # made steers traffic, and the mover is not protecting (B-24: no
        # unattributed mark that outlives the device). A move out removes the
        # host interface, by its host name. A move between two other netns
        # does not touch the host.
        def mover(script):
            machine.succeed("rm -f /run/nw-mover/rc")
            machine.succeed(f"cat > /run/nw-mover/go.tmp <<'NWEOF'\nset -e\n{script}\nNWEOF\nmv /run/nw-mover/go.tmp /run/nw-mover/go")
            machine.wait_until_succeeds("test -e /run/nw-mover/rc", timeout=30)
            rc = machine.succeed("cat /run/nw-mover/rc").strip()
            assert rc == "0", (rc, machine.succeed("cat /run/nw-mover/out"))
        def show():
            print(machine.execute(f"for f in {FP}/nw-mover {FP}/.unattributed; do echo \"== $f\"; cat \"$f\" 2>&1; done; ip -br link")[1])
        def check(fn):
            try:
                fn()
            except Exception:
                show()
                raise
        def clean(lines, *gone):
            # No unattributed mark on the mover, none global, no claim by these names.
            assert "unattributed" not in lines, lines
            machine.fail(f"test -e {FP}/.unattributed")
            for n in gone:
                assert f"iface {n}" not in lines, (n, lines)
        def quiet_mover(*gone):
            lines = protecting("nw-mover", "no")
            clean(lines, *gone)

        check(lambda: quiet_mover())
        machine.succeed("${ip} netns add nwa && ${ip} netns add nwb")

        # (a) Into the host, renamed on the way (the host name is not the one
        # it had in nwa), from inside nwa: `netns 1` is PID 1's, the host's.
        mover("""
        ip -n nwa link add nwin_ns type dummy
        ip netns exec nwa ip link set dev nwin_ns netns 1 name nwin0
        ip link set nwin0 up
        ip route add default dev nwin0 metric 4005
        """)
        def moved_in():
            lines = protecting("nw-mover", "yes")
            assert "iface nwin0" in lines, lines
            clean(lines, "nwin_ns")
        check(moved_in)
        # Deleted in the host by another unit (the driver): the claim goes
        # with the device, and the mover is quiet again.
        machine.succeed("${ip} link del nwin0")
        check(lambda: quiet_mover("nwin0", "nwin_ns"))

        # (b) A host interface it made, carrying a default route, moved out
        # to nwb with a new name: removed by its host name.
        mover("""
        ip link add nwout0 type dummy
        ip link set nwout0 up
        ip route add default dev nwout0 metric 4006
        """)
        def made():
            lines = protecting("nw-mover", "yes")
            assert "iface nwout0" in lines, lines
            clean(lines)
        check(made)
        mover("ip link set dev nwout0 netns nwb name nwout_b")
        check(lambda: quiet_mover("nwout0", "nwout_b"))
        machine.succeed("${ip} -n nwb link show nwout_b")

        # (c) Between two other netns: nothing in the host changes.
        mover("""
        ip -n nwa link add nwab0 type dummy
        ip -n nwa link set dev nwab0 netns nwb name nwab1
        ip -n nwb link set nwab1 up
        ip -n nwb route add default dev nwab1
        """)
        machine.sleep(12)
        check(lambda: quiet_mover("nwab0", "nwab1"))

        machine.succeed("${ip} netns del nwa && ${ip} netns del nwb")
        check(lambda: quiet_mover())

    with subtest("(o) a tun the unit opened itself (as OpenVPN does), carrying /1 routes: protecting"):
        # §12d: "an interface it created that carries a default or
        # all-covering route", however it was created: here by ioctl on
        # /dev/net/tun, which netlink never sees.
        machine.succeed("test -d /sys/devices/virtual/net/nwtun0")
        lines = protecting("nw-tun", "yes")
        assert "iface nwtun0" in lines, lines
        machine.fail(f"test -e {FP}/.unattributed")

    with subtest("(p) one unit makes a persistent tun, another routes over it: both protecting"):
        machine.succeed("test -d /sys/devices/virtual/net/nwtap0")
        machine.succeed("${ip} route show 0.0.0.0/1 | grep -q 'dev nwtap0'")
        assert "iface nwtap0" in protecting("nw-tunsetup", "yes")
        protecting("nw-tunroute", "yes")
        machine.fail(f"test -e {FP}/.unattributed")

    with subtest("(q) a tun the kernel named (OpenVPN's default, tun%d): protecting, under its real name"):
        machine.wait_until_succeeds("test -s /run/nw-tunauto.name", timeout=60)
        name = machine.succeed("cat /run/nw-tunauto.name").strip()
        assert name.startswith("tun") and "%" not in name, name
        lines = protecting("nw-tunauto", "yes")
        assert f"iface {name}" in lines, (name, lines)
        machine.fail(f"grep -rq 'tun%d' {FP}")

    with subtest("(s) a WireGuard tunnel's peers: endpoints in its footprint, a changed peer follows, the hold passes them once the device is gone"):
        # §12d: "Its own interfaces and peer endpoints, read from its
        # footprint, are what the hold passes"; the hold passes "traffic to
        # the endpoints" so the tunnel can re-handshake and its restart can
        # lift the hold. B-22 (b): peers are set over generic netlink.
        def show():
            print(machine.execute(f"for f in {FP}/nw-wg {FP}/.unattributed; do echo \"== $f\"; cat \"$f\" 2>&1; done; wg show nwwg0 endpoints; nft list table inet planarian-hold")[1])
        def check(fn):
            try:
                fn()
            except Exception:
                show()
                raise
        def has(line, timeout=60):
            check(lambda: machine.wait_until_succeeds(f"grep -qx '{line}' {FP}/nw-wg", timeout=timeout))
        def standing(addr):
            # netwatch's own record of what stands now (`.state`, its claims):
            # whether any endpoint there names addr.
            return machine.execute(
                f"jq -e --arg a '{addr}' '[.endpoints[] | tostring | select(contains($a))] | length > 0' {FP}/.state")[0] == 0

        # (1) Its footprint carries both peers, each as the hold reads it.
        check(lambda: protecting("nw-wg", "yes"))
        has("iface nwwg0")
        has("endpoint udp 192.0.2.7 51820")
        has("endpoint udp 2001:db8::7 51821")
        machine.fail(f"test -e {FP}/.unattributed")

        # (1b) Other netns are not the host's ((n)): a device of the same
        # name configured in another netns, by the driver (itself a network
        # tool), binds the driver to nothing of the host's. It takes none of
        # the host tunnel's peers, and nothing is unattributed.
        machine.succeed("${ip} netns add nwg && ${ip} -n nwg link add nwwg0 type wireguard")
        machine.succeed("k=$(wg genkey | wg pubkey) && ${ip} netns exec nwg wg set nwwg0 peer $k endpoint 192.0.2.99:51830 allowed-ips 10.80.0.2/32")
        machine.sleep(12)
        def foreign_binds_nothing():
            lines = footprint("backdoor")
            assert not any(l.startswith("endpoint ") or l == "unattributed" for l in lines), lines
            machine.fail(f"test -e {FP}/.unattributed")
        check(foreign_binds_nothing)
        machine.succeed("${ip} netns del nwg")

        # (2) The tunnel moves its first peer (`wg set`, from its own
        # cgroup): the footprint follows, and what stands is the new one.
        machine.succeed("systemctl reload nw-wg.service")
        machine.succeed("wg show nwwg0 endpoints | grep -q '192.0.2.8:51822'")
        has("endpoint udp 192.0.2.8 51822")
        has("endpoint udp 2001:db8::7 51821")
        check(lambda: machine.wait_until_succeeds(
            f"jq -e '[.endpoints[] | tostring | select(contains(\"192.0.2.8\"))] | length > 0' {FP}/.state", timeout=30))
        assert not standing("192.0.2.7"), "the moved peer's old endpoint still stands"

        # (3) The device goes (deleted outside it): nothing of it stands, so
        # no endpoint stands; the invocation's latch keeps them, and when the
        # tunnel then fails, the hold passes its peers (and its interface),
        # so a restart can reach them.
        machine.succeed("${ip} link del nwwg0")
        check(lambda: machine.wait_until_succeeds(
            f"! jq -e '[.endpoints[] | tostring | select(contains(\"192.0.2.8\") or contains(\"2001:db8::7\"))] | length > 0' {FP}/.state", timeout=30))
        has("endpoint udp 192.0.2.8 51822")
        has("endpoint udp 2001:db8::7 51821")
        machine.succeed("echo 30 > /run/nw-wg-slow")
        machine.succeed("systemctl kill --signal=SIGKILL nw-wg.service")
        check(lambda: machine.wait_until_succeeds("systemctl is-active planarian-hold@nw-wg.service", timeout=30))
        machine.succeed("test -e /run/planarian/hold/nw-wg")
        table = machine.succeed("nft list table inet planarian-hold")
        for want in ["udp . 192.0.2.8 . 51822", "udp . 2001:db8::7 . 51821", '"nwwg0"']:
            assert want in table, (want, table)

        # Back (the daemon restarts it): the hold lifts, and the new
        # invocation's footprint is its own peers, not the last one's.
        machine.succeed("rm -f /run/nw-wg-slow")
        check(lambda: machine.wait_until_succeeds("systemctl is-active nw-wg.service", timeout=120))
        check(lambda: machine.wait_until_fails("test -e /run/planarian/hold/nw-wg", timeout=120))
        has("endpoint udp 192.0.2.7 51820")
        check(lambda: machine.wait_until_succeeds(f"! grep -q '192.0.2.8' {FP}/nw-wg", timeout=30))

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
