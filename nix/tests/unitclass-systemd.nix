# Real systemd as the second oracle for `planarian-unitclass` (B-23,
# docs/raw-unit-classification.md; prop-auditor's requirement 4, as B-18's
# check did for capability syntax). A VM loads a fixed set of raw unit files
# (the constructs the parser claims to read: resets, accumulation, inversion,
# numeric and lower-case capability names, continuations with a comment,
# boolean spellings, drop-ins whose names sort differently from their
# directories, a prefix drop-in, a template instance, the hold's own drop-in
# and the two strippers) and, for each, compares what `systemctl show` reports
# with what the classifier computes from the same tree:
#   - the effective value of every setting the rule reads (and OnFailure=,
#     After=), after normalising systemd's spelling;
#   - the classification: the rule restated here over systemd's own values
#     against the classifier's verdict.
# Not covered by the oracle, and tested only against the model in
# `cargo test -p planarian-unitclass`: the type-wide `service.d/` drop-in
# (it would apply to every unit in the VM), and the `~`-merging cases the
# parser reads as ambiguous on purpose (they err toward granting).
{ pkgs, self }:

let
  inherit (pkgs) lib;
  hold = "[Unit]\nOnFailure=planarian-hold@%N.service\nAfter=planarian-netwatch.service\n";
  svc = text: "[Service]\nExecStart=/bin/true\n" + text;
  fixtures = {
    "o-plain.service" = svc "User=nobody\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_CHOWN CAP_KILL\n";
    "o-reset.service" = svc "CapabilityBoundingSet=CAP_CHOWN\nCapabilityBoundingSet=\nCapabilityBoundingSet=CAP_NET_RAW\n";
    "o-emptybounding.service" = svc "User=nobody\nCapabilityBoundingSet=\n";
    "o-accum.service" = svc "AmbientCapabilities=CAP_KILL\nAmbientCapabilities=CAP_NET_RAW\n";
    "o-ambreset.service" = svc "AmbientCapabilities=CAP_KILL\nAmbientCapabilities=\n";
    "o-invert.service" = svc "CapabilityBoundingSet=~CAP_NET_ADMIN CAP_SYS_TIME\n";
    "o-numeric.service" = svc "AmbientCapabilities=13 cap_kill\nCapabilityBoundingSet=cap_net_admin\n";
    "o-continue.service" = svc "AmbientCapabilities=CAP_KILL \\\n# a comment inside the continuation\n  CAP_NET_RAW\n";
    "o-bool-true.service" = svc "NoNewPrivileges=True\nDynamicUser=on\n";
    "o-bool-one.service" = svc "NoNewPrivileges=1\nDynamicUser=0\n";
    "o-bool-off.service" = svc "NoNewPrivileges=off\nDynamicUser=no\nUser=root\n";
    "o-user-zero.service" = svc "User=0\n";
    "o-dyn.service" = svc "DynamicUser=yes\n";
    "o-device.service" = svc "User=nobody\nNoNewPrivileges=yes\nDeviceAllow=/dev/null rw\nDeviceAllow=/dev/net/tun rw\n";
    "o-devreset.service" = svc "User=nobody\nNoNewPrivileges=yes\nDeviceAllow=/dev/net/tun rw\nDeviceAllow=\n";
    "o-bind.service" = svc "User=nobody\nNoNewPrivileges=yes\nBindPaths=/dev/ppp\nBindReadOnlyPaths=/dev/null\n";
    "o-dropin-order.service" = svc "User=a\n";
    "o-dropin-order.service.d/20-b.conf" = "[Service]\nUser=bob\n";
    "o-dropin-order.service.d/10-c.conf" = "[Service]\nUser=carl\n";
    "o-dropin-reset.service" = svc "User=nobody\nNoNewPrivileges=yes\nAmbientCapabilities=CAP_NET_ADMIN\n";
    "o-dropin-reset.service.d/10-reset.conf" = "[Service]\nAmbientCapabilities=\n";
    "o-pre-x.service" = svc "User=nobody\nNoNewPrivileges=yes\n";
    "o-pre-.service.d/10-grant.conf" = "[Service]\nAmbientCapabilities=CAP_NET_RAW\n";
    "o-tmpl@.service" = svc "User=nobody\nNoNewPrivileges=yes\n";
    "o-tmpl@.service.d/10-grant.conf" = "[Service]\nBindPaths=/dev/net/tun\n";
    "o-hold.service" = svc "User=nobody\n";
    "o-hold.service.d/50-planarian-hold.conf" = hold;
    "o-hold-strip.service" = svc "User=nobody\n";
    "o-hold-strip.service.d/50-planarian-hold.conf" = hold;
    "o-hold-strip.service.d/90-strip.conf" = "[Unit]\nOnFailure=\n";
    "o-after-strip.service" = svc "User=nobody\n";
    "o-after-strip.service.d/50-planarian-hold.conf" = hold;
    "o-after-strip.service.d/90-strip.conf" = "[Unit]\nAfter=\n";
  };
  pkg = pkgs.runCommand "unitclass-oracle-units" { } (''
    mkdir -p $out/lib/systemd/system
  '' + lib.concatStrings (lib.mapAttrsToList (path: text: ''
    mkdir -p "$out/lib/systemd/system/$(dirname ${lib.escapeShellArg path})"
    printf '%s' ${lib.escapeShellArg text} > "$out/lib/systemd/system/"${lib.escapeShellArg path}
  '') fixtures));
  units = [
    "o-plain" "o-reset" "o-emptybounding" "o-accum" "o-ambreset" "o-invert" "o-numeric" "o-continue"
    "o-bool-true" "o-bool-one" "o-bool-off" "o-user-zero" "o-dyn" "o-device" "o-devreset" "o-bind"
    "o-dropin-order" "o-dropin-reset" "o-pre-x" "o-tmpl@a" "o-hold" "o-hold-strip" "o-after-strip"
  ];
  capNames = [
    "CAP_CHOWN" "CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH" "CAP_FOWNER" "CAP_FSETID"
    "CAP_KILL" "CAP_SETGID" "CAP_SETUID" "CAP_SETPCAP" "CAP_LINUX_IMMUTABLE"
    "CAP_NET_BIND_SERVICE" "CAP_NET_BROADCAST" "CAP_NET_ADMIN" "CAP_NET_RAW"
    "CAP_IPC_LOCK" "CAP_IPC_OWNER" "CAP_SYS_MODULE" "CAP_SYS_RAWIO" "CAP_SYS_CHROOT"
    "CAP_SYS_PTRACE" "CAP_SYS_PACCT" "CAP_SYS_ADMIN" "CAP_SYS_BOOT" "CAP_SYS_NICE"
    "CAP_SYS_RESOURCE" "CAP_SYS_TIME" "CAP_SYS_TTY_CONFIG" "CAP_MKNOD" "CAP_LEASE"
    "CAP_AUDIT_WRITE" "CAP_AUDIT_CONTROL" "CAP_SETFCAP" "CAP_MAC_OVERRIDE"
    "CAP_MAC_ADMIN" "CAP_SYSLOG" "CAP_WAKE_ALARM" "CAP_BLOCK_SUSPEND"
    "CAP_AUDIT_READ" "CAP_PERFMON" "CAP_BPF" "CAP_CHECKPOINT_RESTORE"
  ];
in
pkgs.testers.runNixOSTest {
  name = "planarian-unitclass-systemd";

  nodes.machine = { ... }: {
    systemd.packages = [ pkg ];
    environment.systemPackages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.default ];
    virtualisation.memorySize = 1024;
  };

  testScript = ''
    import json

    CAPS = json.loads('${builtins.toJSON capNames}')
    UNITS = json.loads('${builtins.toJSON units}')

    def show_systemd(unit):
        keys = "User,DynamicUser,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,DeviceAllow,BindPaths,BindReadOnlyPaths,OnFailure,After"
        out = machine.succeed(f"systemctl show -p {keys} {unit}.service")
        props = {}
        for line in out.splitlines():
            k, _, v = line.partition("=")
            props.setdefault(k, []).append(v)
        return props

    def first(props, key):
        return props.get(key, [""])[0]

    def capset(text):
        return sorted(set(w.upper() for w in text.split()) & set(CAPS))

    def words(props, key):
        out = []
        for v in props.get(key, []):
            for w in v.split():
                out.append(w)
        return out

    def path_of(entry):
        return entry.split(":")[0].lstrip("-+")

    def sem_systemd(unit, props):
        return {
            "user": first(props, "User"),
            "dynamic": first(props, "DynamicUser") == "yes",
            "nnp": first(props, "NoNewPrivileges") == "yes",
            "bounding": capset(first(props, "CapabilityBoundingSet")),
            "ambient": capset(first(props, "AmbientCapabilities")),
            "device": [path_of(v.split()[0]) for v in props.get("DeviceAllow", []) if v.split()],
            "bind": [path_of(w) for w in words(props, "BindPaths")],
            "bindro": [path_of(w) for w in words(props, "BindReadOnlyPaths")],
            "on_failure": sorted(set(words(props, "OnFailure"))),
            "after": sorted(set(words(props, "After"))),
        }

    def caps_of(c):
        if c["state"] == "unset":
            return None
        if c["state"] == "reset":
            return []
        if c["inverted"]:
            return sorted(set(CAPS) - set(c["caps"]))
        return sorted(c["caps"])

    def sem_ours(unit, o):
        bounding = caps_of(o["bounding"])
        ambient = caps_of(o["ambient"])
        name = unit.removesuffix(".service")
        return {
            "user": o["user"] or "",
            "dynamic": bool(o["dynamic_user"]),
            "nnp": bool(o["no_new_privileges"]),
            "bounding": sorted(CAPS) if bounding is None else bounding,
            "ambient": [] if ambient is None else ambient,
            "device": [path_of(v.split()[0]) for v in o["device_allow"]],
            "bind": [path_of(w) for w in o["bind_paths"]],
            "bindro": [path_of(w) for w in o["bind_read_only_paths"]],
            "on_failure": sorted(set(w.replace("%N", name) for w in o["on_failure"])),
            "after": sorted(set(o["after"])),
        }

    def tool_by_systemd(s):
        net = {"CAP_NET_ADMIN", "CAP_NET_RAW"}
        root = s["user"] in ("", "root", "0") and not s["dynamic"]
        bounding_open = bool(net & set(s["bounding"]))
        devices = s["device"] + s["bind"] + s["bindro"]
        dev = any("/dev/net/tun" in d or "/dev/ppp" in d for d in devices)
        return bool(net & set(s["ambient"])) or (root and bounding_open) or (bounding_open and not s["nnp"]) or dev

    machine.wait_for_unit("multi-user.target")
    bad = []
    for u in UNITS:
        props = show_systemd(u)
        ours = json.loads(machine.succeed(f"planarian-unitclass show --units /etc/systemd/system {u}.service"))
        a = sem_systemd(u, props)
        b = sem_ours(u + ".service", ours)
        for k in a:
            if k == "after":
                # systemd adds defaults to After=; ours must be a subset.
                if not set(b[k]) <= set(a[k]):
                    bad.append((u, k, a[k], b[k]))
            elif a[k] != b[k]:
                bad.append((u, k, a[k], b[k]))
        if tool_by_systemd(a) != ours["tool"]:
            bad.append((u, "tool", tool_by_systemd(a), ours["tool"]))
        print(f"{u}: tool={ours['tool']}")
    assert not bad, "systemd and planarian-unitclass disagree: " + json.dumps(bad, indent=1)
  '';
}
