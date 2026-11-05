# The capability-set predicate used by the build-time network-tool classifier.
# Unknown syntax grants authority conservatively; it can never waive a hold.
{ lib }:
let
  words = v:
    if builtins.isList v then lib.concatMap words v
    else if builtins.isString v then lib.filter (w: builtins.isString w && w != "") (builtins.split "[[:space:]]+" v)
    else [ (toString v) ];
  # systemd accepts capability names case-insensitively and by decimal id.
  # Unknown/new spellings fail closed instead of silently omitting a tool.
  capabilityNames = [
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
  capabilityIds = lib.listToAttrs (lib.imap0 (i: name: { name = toString i; value = name; }) capabilityNames);
  capability = word:
    let name = lib.toUpper word; in
    if builtins.elem name capabilityNames then name else capabilityIds.${word} or null;
  # A capability set as systemd reads it: a leading "~" inverts one
  # assignment. Multiple inverted list assignments have merge semantics
  # different from one joined assignment: conservatively treat those, and
  # every unrecognised token, as granting network authority.
in
set: caps:
    let
      ws = words set;
      inverted = ws != [ ] && lib.hasPrefix "~" (builtins.head ws);
      tokens = if inverted then words (lib.removePrefix "~" (lib.concatStringsSep " " ws)) else ws;
      normalized = map capability tokens;
      ambiguous = !(builtins.isString set || (builtins.isList set && builtins.all builtins.isString set))
        || (builtins.isList set && lib.any (w: lib.hasPrefix "~" w) ws);
    in ambiguous || builtins.elem null normalized
       || (if inverted then lib.any (c: !(builtins.elem c normalized)) caps
           else lib.any (c: builtins.elem c normalized) caps)
