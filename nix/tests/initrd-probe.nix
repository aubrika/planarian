# Probes for the watch in the initrd (docs/netwatch-initrd.md §9, B-26): the
# kernel questions the design rests on, answered on a VM with no Planarian
# product code. A tiny clang-built eBPF object hooks the same ten kernel
# functions as `loader::PROBES` (fentry, fexit and kprobe on the same names),
# bpftool loads it in the systemd initrd and pins what it can, and the driver
# looks after switch-root.
#
#   A1  a bpffs pin made in the initrd is visible after switch-root;
#   A2  all ten hooks are held by pinned links that outlive the loader
#       process (the two kprobes need a perf-event link, kernel 5.15+);
#   A3  what the initrd's cgroup paths look like (for `unit_of_cgroup`), and
#       whether module BTF for nfnetlink exists;
#   A4  a file written in the initrd under /run survives, with its
#       CLOCK_BOOTTIME stamp continuing.
#
# The test prints one line per question and fails if A1 or A2 do not hold; A3
# and A4 are reported. The result goes to lane-change-path (design #90).
{ pkgs, self ? null }:

let
  hooks = [
    { name = "rtnetlink"; sec = "fentry/rtnetlink_rcv_msg"; }
    { name = "nfnetlink"; sec = "kprobe/nfnetlink_rcv_msg"; }
    { name = "nfbatch"; sec = "kprobe/nfnetlink_rcv_batch"; }
    { name = "sockopt"; sec = "fentry/nf_setsockopt"; }
    { name = "genl"; sec = "fentry/genl_rcv_msg"; }
    { name = "netdev"; sec = "fexit/register_netdevice"; }
    { name = "netmove_enter"; sec = "fentry/__dev_change_net_namespace"; }
    { name = "netmove"; sec = "fexit/__dev_change_net_namespace"; }
    { name = "netrename_enter"; sec = "fentry/netif_change_name"; }
    { name = "netrename"; sec = "fexit/netif_change_name"; }
  ];
  source = pkgs.writeText "probe.c" ''
    typedef unsigned long long u64;
    #define SEC(name) __attribute__((section(name), used))
    ${pkgs.lib.concatMapStrings (h: ''
      SEC("${h.sec}") int ${h.name}(void *ctx) { return 0; }
    '') hooks}
    char LICENSE[] SEC("license") = "GPL";
  '';
  object = pkgs.stdenv.mkDerivation {
    name = "initrd-probe-object";
    dontUnpack = true;
    nativeBuildInputs = [ pkgs.clang pkgs.llvm ];
    hardeningDisable = [ "all" ];
    buildPhase = ''
      clang -target bpf -O2 -g -c ${source} -o probe.o
    '';
    installPhase = "install -D probe.o $out/probe.o";
  };
  bpftool = pkgs.bpftools;
  fs = "/sys/fs/bpf";
in
pkgs.testers.runNixOSTest {
  name = "planarian-initrd-probe";

  nodes.machine = { pkgs, lib, ... }: {
    virtualisation.memorySize = 2048;
    boot.initrd.systemd.enable = true;
    boot.initrd.kernelModules = [ "nfnetlink" ];
    boot.initrd.systemd.storePaths = [ bpftool object pkgs.coreutils pkgs.util-linux pkgs.findutils ];
    boot.initrd.systemd.services.initrd-probe = {
      description = "initrd probe: pin a map and the ten hooks' links";
      wantedBy = [ "initrd.target" ];
      before = [ "initrd-switch-root.service" ];
      after = [ "systemd-modules-load.service" "sysroot.mount" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig.Type = "oneshot";
      script = ''
        export PATH=${lib.makeBinPath [ bpftool pkgs.coreutils pkgs.util-linux pkgs.findutils ]}:$PATH
        mkdir -p /run/probe
        exec > /run/probe/initrd.log 2>&1
        set -x
        cat /proc/uptime > /run/probe/uptime
        cat /proc/self/cgroup > /run/probe/cgroup
        ls /sys/kernel/btf > /run/probe/btf || true
        if mountpoint -q ${fs}; then echo already > /run/probe/bpffs; else
          mount -t bpf bpf ${fs} && echo mounted-by-probe > /run/probe/bpffs; fi
        findmnt ${fs} >> /run/probe/bpffs || true
        mkdir -p ${fs}/p
        bpftool map create ${fs}/p/map type array key 4 value 8 entries 1 name probemap
        bpftool prog loadall ${object}/probe.o ${fs}/p/progs autoattach || echo LOADFAIL
        echo done > /run/probe/state
      '';
    };
  };

  testScript = ''
    import json

    machine.wait_for_unit("multi-user.target")
    R = {}
    ilog = machine.succeed("cat /run/probe/initrd.log || true")
    print(ilog)
    print("initrd cgroup:", machine.succeed("cat /run/probe/cgroup").strip())
    print("module BTF (initrd):", machine.succeed("cat /run/probe/btf").split())
    print("stage-2 module BTF:", machine.succeed("ls /sys/kernel/btf | tr '\n' ' '"))
    print("bpffs in initrd:", machine.succeed("cat /run/probe/bpffs").strip())
    print("uptime initrd / now:", machine.succeed("cat /run/probe/uptime").strip(), "/", machine.succeed("cat /proc/uptime").strip())
    print("state:", machine.succeed("cat /run/probe/state").strip())

    # A1: the map pin crossed switch-root.
    R["A1"] = machine.execute("test -e ${fs}/p/map")[0] == 0
    print("tree:", machine.succeed("find ${fs} | sort"))
    machine.succeed("${bpftool}/sbin/bpftool map show pinned ${fs}/p/map || ${bpftool}/bin/bpftool map show pinned ${fs}/p/map")

    # A2: links live after the loader exited and after switch-root.
    links = json.loads(machine.succeed("${bpftool}/bin/bpftool -j link show || ${bpftool}/sbin/bpftool -j link show"))
    print("links:", json.dumps(links))
    kinds = sorted({(l.get("type"), l.get("target_obj_id") is not None) for l in links})
    print("link kinds:", kinds)
    R["A2"] = len([l for l in links if l.get("prog_id") is not None]) >= 10
    print("RESULT", json.dumps(R))
    assert R["A1"], "A1: the bpffs pin did not cross switch-root"
    assert R["A2"], "A2: fewer than ten live links"
  '';
}
