# Failure posture (SPEC §12d, I20): what this machine does when Planarian
# itself is absent, has crashed, or finds tampering. Enforced by systemd, never
# by planariad (AGENTS.md rule 14): planariad only reports (it reaches ready,
# or stops with status 78 on an integrity failure), and these units respond.
#
#   planarian-ready.target         reached when planariad is ready
#   planarian-failed@<class>.target  absent | crashed | integrity
#   planarian-respond@<class>      the posture's responses for that class
#   planarian-posture-check        independent check: ready within the timeout
#   planarian-posture-lift         restrictions lift once ready is reached again
#                                  (except integrity: an administrator clears it)
#   planarian-ack                  `sudo planarian-ack`: the administrator's exit
#
# Phase A ships the Standard posture. Its responses:
#   absent / crashed: alarm, notify administrators, disable agents, restrict
#     remote access to administrators; local login proceeds.
#   integrity: alarm (the tampering text), notify, disable agents, remote
#     access off (no mesh exists in A); local login proceeds with the warning.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption mkIf types concatStringsSep optionalString;
  cfg = config.services.planarian;

  # Units that admit a principal (§12d): ordered after planarian-ready.target.
  principalUnits =
    lib.optional config.services.openssh.enable "sshd.service"
    # P13: the display manager is whichever unit NixOS runs for it. greetd
    # is its own unit, greetd.service; NixOS's greetd module aliases
    # display-manager.service to it (and turns services.displayManager on),
    # so ordering that name too would define a second, ExecStart-less
    # display-manager.service that the alias link merely overwrites.
    ++ (if config.services.greetd.enable or false then [ "greetd.service" ]
        else lib.optional (config.services.xserver.enable || config.services.displayManager.enable or false) "display-manager.service")
    # The template: greetd's module disables its autovt@tty1 instance, and
    # ordering a disabled instance does nothing.
    ++ [ "user@.service" "getty@.service" "autovt@.service" ];


  alarmText = {
    absent = "Planarian, which protects this computer from unsafe changes, is not running. Assistants and system changes are turned off until it is fixed. An administrator has been notified.";
    crashed = "Planarian, which protects this computer from unsafe changes, is not running. Assistants and system changes are turned off until it is fixed. An administrator has been notified.";
    integrity = "This computer may have been tampered with. Do not enter passwords or open sensitive files. An administrator has been notified.";
  };

  respond = pkgs.writeShellScript "planarian-respond" ''
    set -u
    class="$1"
    PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.util-linux config.systemd.package ]}
    mkdir -p /run/planarian /run/issue.d /run/planarian/sshd
    case "$class" in
      integrity) text=${lib.escapeShellArg alarmText.integrity} ;;
      crashed) text=${lib.escapeShellArg alarmText.crashed} ;;
      *) text=${lib.escapeShellArg alarmText.absent} ;;
    esac
    # Integrity is never weakened by a later, milder class.
    if [ -e /run/planarian/failed-integrity ] && [ "$class" != integrity ]; then
      exit 0
    fi
    touch "/run/planarian/failed-$class"
    # I20: no agent principal runs while Planarian is failed (their
    # ConditionPathExistsGlob keeps them from starting again): the declared
    # agent units, and every agent the launcher created, by stopping their
    # slice as a whole (R05).
    ${optionalString (cfg.agentUnits != [ ]) "systemctl stop ${concatStringsSep " " cfg.agentUnits} || true"}
    systemctl stop planarian-agents.slice || true
    # Alarm: on the login screen (getty's issue) and in every session; the
    # tray and the console read /run/planarian/alarm.
    printf '%s\n%s\n' "$class" "$text" > /run/planarian/alarm
    printf '\n*** %s ***\n\n' "$text" > /run/issue.d/50-planarian.issue
    wall "Planarian ($class): $text" || true
    # Notify administrators: locally, in the journal at alert level (Phase A
    # has no remote channel). The boot report goes with it when there is one.
    logger -p auth.alert -t planarian-posture "failure class $class: $text"
    if [ -e /run/planarian/integrity ]; then
      logger -p auth.alert -t planarian-posture "integrity finding: $(cat /run/planarian/integrity)"
    fi
    # Restrict remote access: administrators only, or nobody for integrity.
    ${optionalString config.services.openssh.enable ''
      if [ "$class" = integrity ]; then
        printf 'Match all\n  DenyUsers *\n' > /run/planarian/sshd/posture.conf
      else
        # P14: Planarian's administrators (root and ${cfg.adminGroup}), not wheel.
        printf 'Match all\n  AllowGroups ${cfg.adminGroup} root\n' > /run/planarian/sshd/posture.conf
      fi
      systemctl try-reload-or-restart sshd.service || true
    ''}
  '';

  lift = pkgs.writeShellScript "planarian-posture-lift" ''
    set -u
    PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.util-linux config.systemd.package ]}
    # Ready again with a clean boot report: Absent and Crashed lift.
    # Integrity needs an administrator (planarian-ack).
    [ -e /run/planarian/failed-integrity ] && exit 0
    # Wanted by the ready target and ordered after it, this also runs when
    # the target's start failed (After= orders, it does not require).
    systemctl is-active --quiet planarian-ready.target || exit 0
    systemctl is-active --quiet planariad.service || exit 0
    # A respond that has marked its class but not yet written the alarm
    # counts: both are cleared together, so they cannot diverge.
    if [ -e /run/planarian/alarm ] || [ -e /run/planarian/failed-absent ] || [ -e /run/planarian/failed-crashed ]; then
      rm -f /run/planarian/alarm /run/issue.d/50-planarian.issue /run/planarian/failed-absent /run/planarian/failed-crashed
      rm -f /run/planarian/sshd/posture.conf
      ${optionalString config.services.openssh.enable "systemctl try-reload-or-restart sshd.service || true"}
      systemctl stop 'planarian-failed@*.target' 'planarian-respond@*.service' || true
      ${optionalString (cfg.agentUnits != [ ]) "systemctl start --no-block ${concatStringsSep " " cfg.agentUnits} || true"}
      logger -p auth.notice -t planarian-posture "Planarian is ready again; restrictions lifted"
    fi
  '';

  ack = pkgs.writeShellScriptBin "planarian-ack" ''
    set -u
    PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.util-linux pkgs.gnugrep pkgs.shadow config.systemd.package ]}:$PATH
    if [ "$(id -u)" != 0 ]; then
      echo "planarian-ack: run it as an administrator: sudo planarian-ack" >&2
      exit 1
    fi
    who="''${SUDO_USER:-root}"
    if [ "$who" != root ] && ! id -nG "$who" | tr ' ' '\n' | grep -qx '${cfg.adminGroup}'; then
      echo "planarian-ack: $who is not an administrator (${cfg.adminGroup})" >&2
      logger -p auth.warning -t planarian-posture "acknowledgement refused for $who (not an administrator)"
      exit 1
    fi
    if [ ! -e /run/planarian/alarm ]; then
      echo "planarian-ack: no alarm is raised"
      exit 0
    fi
    class="$(head -n1 /run/planarian/alarm)"
    # Journaled with identity (§12d).
    logger -p auth.notice -t planarian-posture "alarm ($class) acknowledged by $who"
    rm -f /run/planarian/alarm /run/issue.d/50-planarian.issue /run/planarian/failed-* /run/planarian/sshd/posture.conf
    ${optionalString config.services.openssh.enable "systemctl try-reload-or-restart sshd.service || true"}
    systemctl stop 'planarian-failed@*.target' 'planarian-respond@*.service' || true
    ${optionalString (cfg.agentUnits != [ ]) "systemctl is-active --quiet planarian-ready.target && systemctl start --no-block ${concatStringsSep " " cfg.agentUnits} || true"}
    echo "acknowledged ($class); restrictions lifted"
  '';

  # ExecStopPost of planariad and planarian-recovery: route how it ended.
  stopPost = name: pkgs.writeShellScript "planarian-${name}-stopped" ''
    PATH=${lib.makeBinPath [ pkgs.coreutils config.systemd.package ]}
    state="$(systemctl is-system-running 2>/dev/null || true)"
    case "$state" in stopping|offline) exit 0 ;; esac
    if [ "''${EXIT_STATUS:-}" = 78 ]; then
      systemctl start --no-block planarian-failed@integrity.target
    elif [ "''${SERVICE_RESULT:-}" = success ] && [ ${if name == "planariad" then "1" else "0"} = 1 ]; then
      # Stopped on purpose, outside a shutdown: Absent (§12d).
      systemctl start --no-block planarian-failed@absent.target
    fi
  '';

  check = pkgs.writeShellScript "planarian-posture-check" ''
    PATH=${lib.makeBinPath [ pkgs.coreutils config.systemd.package ]}
    # P16: a longer timeout in a generation switched live waits for its
    # boot: the shorter of this one's and the booted generation's.
    t=${toString cfg.bootReadyTimeout}
    b="$(cat /run/booted-system/etc/planarian/boot-ready-timeout 2>/dev/null || echo "$t")"
    case "$b" in ""|*[!0-9]*) b="$t" ;; esac
    [ "$b" -lt "$t" ] && t="$b"
    deadline=$(( $(date +%s) + t ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      systemctl is-active --quiet planarian-ready.target && exit 0
      sleep 2
    done
    systemctl is-active --quiet planarian-ready.target && exit 0
    systemctl start --no-block planarian-failed@absent.target
  '';

  # §12d "Network security fails closed": the hold. `apply <unit>` holds the
  # machine's traffic for a failed network-security unit; `lift <unit>` ends
  # that unit's hold; `reapply` rebuilds the table (after nftables.service
  # starts or reloads, which may flush every table); `condition <unit>` is the
  # ExecCondition: it skips a hold an administrator released, and one for a
  # network tool whose footprint shows it was not protecting traffic.
  #
  # The table drops all traffic in and out except loopback, address
  # assignment (DHCP, DHCPv6, ICMPv6 neighbour and router discovery), the held
  # units' holdAllow endpoints and their own interfaces (a tunnel's traffic is
  # protected; owner decision, Nov 2), and the established connections of
  # administrator sessions. Those are taken when the hold is applied: every
  # socket held by a process in the scope of a logind session whose user is
  # root or in the administrators' group, matched by its exact addresses and
  # ports. New connections are refused for the whole hold, so no
  # administrator session can begin after the snapshot: the snapshot is the
  # whole set (coordinator, Nov 2). Root-owned daemons and an administrator's
  # processes outside a session scope are not sessions, and are held.
  # Tuples rather than conntrack marks: a flow that predates the hold may
  # have no conntrack entry to mark (no rule needed tracking before).
  hold = pkgs.writeShellScript "planarian-hold" ''
    set -u
    PATH=${lib.makeBinPath [ pkgs.coreutils pkgs.gnugrep pkgs.gawk pkgs.nftables pkgs.iproute2 pkgs.findutils pkgs.getent config.systemd.package ]}
    dir=/run/planarian/hold
    released=/run/planarian/hold-released
    footprint=/run/planarian/footprint
    mkdir -p "$dir" "$released"
    cmd="$1"; unit="''${2:-}"
    log() { echo "planarian-hold: $*"; }

    is_admin() {
      [ "$1" = 0 ] && return 0
      name="$(getent passwd "$1" | cut -d: -f1)"
      [ -n "$name" ] && id -nG "$name" 2>/dev/null | tr ' ' '\n' | grep -qx ${lib.escapeShellArg cfg.adminGroup}
    }

    # Administrator sessions' sockets, as nft set elements, added to the
    # ones a previous apply took (a second hold takes the union).
    snapshot() {
      pids=" "
      for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
        uid="$(loginctl show-session "$s" -p User --value 2>/dev/null)"
        [ -n "$uid" ] && is_admin "$uid" || continue
        scope="$(loginctl show-session "$s" -p Scope --value 2>/dev/null)"
        [ -n "$scope" ] || continue
        # Bounded: a session scope sits at user.slice/user-UID.slice/, and
        # at most 4096 of its processes are taken. Beyond either bound the
        # rest are not taken, i.e. held (fail closed).
        for d in $(find /sys/fs/cgroup -maxdepth 4 -type d -name "$scope" 2>/dev/null | head -n 4); do
          pids="$pids$(find "$d" -maxdepth 8 -name cgroup.procs -exec cat {} + 2>/dev/null | head -n 4096 | tr '\n' ' ')"
        done
      done
      ss -tunpH state established 2>/dev/null | awk -v pids="$pids" '
        # An IPv4 peer of a dual-stack socket shows as [::ffff:a.b.c.d]; on
        # the wire it is IPv4, so it is matched as IPv4.
        function split_ap(s, r,  i) { i = match(s, /:[0-9]+$/); r[1] = substr(s, 1, i - 1); r[2] = substr(s, i + 1); gsub(/^\[|\]$/, "", r[1]); sub(/%.*/, "", r[1]); if (r[1] ~ /^::ffff:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) sub(/^::ffff:/, "", r[1]) }
        {
          ok = 0; line = $0
          while (match(line, /pid=[0-9]+/)) { p = substr(line, RSTART + 4, RLENGTH - 4); if (index(pids, " " p " ")) ok = 1; line = substr(line, RSTART + RLENGTH) }
          if (!ok) next
          split_ap($4, l); split_ap($5, r)
          fam = (index(l[1], ":") ? 6 : 4)
          print fam, $1, l[1], l[2], r[1], r[2]
        }' >> "$dir/.admin"
      sort -u -o "$dir/.admin" "$dir/.admin"
    }

    build() {
      units="$(ls "$dir" 2>/dev/null)"
      if [ -z "$units" ]; then
        nft delete table inet planarian-hold 2>/dev/null
        rm -f "$dir/.admin"
        return 0
      fi
      a4=""; a6=""; i4=""; o4=""; i6=""; o6=""; ifs=""
      for u in $units; do
        # What it passes: the footprint's interfaces and endpoints (§12d),
        # and the manifest's holdInterfaces and holdAllow.
        allow="$(cat "/etc/planarian/hold/$u.allow" 2>/dev/null
                 awk '$1 == "iface" { print "iface", $2 } $1 == "endpoint" { print $2, $3, $4 }' "$footprint/$u" 2>/dev/null)"
        [ -n "$allow" ] || continue
        while read -r proto addr port; do
          if [ "$proto" = iface ]; then ifs="$ifs \"$addr\","; continue; fi
          [ -n "$port" ] || continue
          case "$addr" in *:*) a6="$a6 $proto . $addr . $port," ;; *) a4="$a4 $proto . $addr . $port," ;; esac
        done <<ALLOW
    $allow
    ALLOW
      done
      if [ -f "$dir/.admin" ]; then
        while read -r fam proto la lp ra rp; do
          if [ "$fam" = 6 ]; then
            i6="$i6 $proto . $ra . $rp . $la . $lp,"; o6="$o6 $proto . $la . $lp . $ra . $rp,"
          else
            i4="$i4 $proto . $ra . $rp . $la . $lp,"; o4="$o4 $proto . $la . $lp . $ra . $rp,"
          fi
        done < "$dir/.admin"
      fi
      el() { [ -n "$1" ] && echo "elements = { $1 }"; }
      nft -f - <<NFT
    table inet planarian-hold
    delete table inet planarian-hold
    table inet planarian-hold {
      set allow4 { type inet_proto . ipv4_addr . inet_service; $(el "$a4") }
      set allow6 { type inet_proto . ipv6_addr . inet_service; $(el "$a6") }
      set admin_in4 { type inet_proto . ipv4_addr . inet_service . ipv4_addr . inet_service; $(el "$i4") }
      set admin_out4 { type inet_proto . ipv4_addr . inet_service . ipv4_addr . inet_service; $(el "$o4") }
      set admin_in6 { type inet_proto . ipv6_addr . inet_service . ipv6_addr . inet_service; $(el "$i6") }
      set admin_out6 { type inet_proto . ipv6_addr . inet_service . ipv6_addr . inet_service; $(el "$o6") }
      set ifaces { type ifname; $(el "$ifs") }
      chain input {
        type filter hook input priority -300; policy drop;
        iif lo accept
        iifname @ifaces accept
        udp sport 67 udp dport 68 accept
        udp sport 547 udp dport 546 accept
        icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } accept
        meta l4proto . ip saddr . th sport @allow4 accept
        meta l4proto . ip6 saddr . th sport @allow6 accept
        meta l4proto . ip saddr . th sport . ip daddr . th dport @admin_in4 accept
        meta l4proto . ip6 saddr . th sport . ip6 daddr . th dport @admin_in6 accept
      }
      chain output {
        type filter hook output priority -300; policy drop;
        oif lo accept
        oifname @ifaces accept
        udp sport 68 udp dport 67 accept
        udp sport 546 udp dport 547 accept
        icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
        meta l4proto . ip daddr . th dport @allow4 accept
        meta l4proto . ip6 daddr . th dport @allow6 accept
        meta l4proto . ip saddr . th sport . ip daddr . th dport @admin_out4 accept
        meta l4proto . ip6 saddr . th sport . ip6 daddr . th dport @admin_out6 accept
      }
      chain forward {
        type filter hook forward priority -300; policy drop;
      }
    }
    NFT
    }

    # Fail closed: when the full table does not load (and a hold stands),
    # hold everything but loopback rather than nothing. apply, lift (other
    # holds may stand) and reapply (after a flush) all go through it.
    build_or_lock() {
      build && return 0
      log "the hold table did not load; holding all traffic but loopback"
      nft -f - <<NFT
    table inet planarian-hold
    delete table inet planarian-hold
    table inet planarian-hold {
      chain input { type filter hook input priority -300; policy drop; iif lo accept; }
      chain output { type filter hook output priority -300; policy drop; oif lo accept; }
      chain forward { type filter hook forward priority -300; policy drop; }
    }
    NFT
    }

    case "$cmd" in
      condition)
        # ExecCondition (exit 0: hold; 1: skip, the unit stays inactive).
        #
        # 1. An unexpired release stands: skip. The marker is `boot` (until
        #    the next boot; /run never survives one), or `<unix> <boottime>`:
        #    the administrator's --until as wall-clock seconds, and the same
        #    deadline in CLOCK_BOOTTIME seconds (/proc/uptime). It expires at
        #    whichever passes first, so a stepped wall clock cannot lengthen
        #    it. Anything else is no release: hold.
        m="$released/$unit"
        if [ -f "$m" ]; then
          read -r until deadline < "$m"
          num() { case "''${1:-}" in ""|*[!0-9]*) return 1 ;; esac; }
          if [ "$until" = boot ] || { num "$until" && num "$deadline" \
               && [ "$until" -gt "$(date +%s)" ] && [ "$deadline" -gt "$(cut -d. -f1 /proc/uptime)" ]; }; then
            log "hold on $unit not applied: released until $until"
            exit 1
          fi
        fi
        # 2. Is the failed network tool a network-security unit, i.e. was it
        #    protecting traffic (§12d)? Its kernel-attributed footprint says.
        #    Fail closed: a watch heartbeat missing, failed or older than 30 s;
        #    no footprint (netwatch keeps the footprints it has across its own
        #    restarts, charges steering it finds on attach but did not see
        #    made to .unattributed, and writes `protecting no` only for a
        #    network tool with no claim, so a missing file was never seen by
        #    a healthy watch); `protecting yes`; or a change the kernel could
        #    not attribute, here or anywhere (.unattributed); a footprint not
        #    confirmed within the window (`at`): hold. Only a fresh watch, no
        #    standing unattributed change, and a fresh `protecting no` skip.
        w="$footprint/.watch"
        # Timestamps are CLOCK_BOOTTIME seconds (/proc/uptime's first field),
        # so a stepped wall clock cannot make one fresh. Fresh: at most 30 s
        # old, and not more than 5 s ahead.
        fresh() {
          case "''${1:-}" in ""|*[!0-9]*) return 1 ;; esac
          now=$(cut -d. -f1 /proc/uptime); age=$(( now - $1 ))
          [ "$age" -le 30 ] && [ "$age" -ge -5 ]
        }
        state=missing; ts=""
        [ -f "$w" ] && read -r state ts < "$w"
        if [ "$state" = attached ] && ! fresh "$ts"; then
          state=stale
        fi
        if [ "$state" != attached ]; then
          log "holding for $unit: the network watch is $state, so whether it protected traffic is unknown"
          exit 0
        fi
        # A steering change netwatch could not attribute to any unit (or a
        # lost event it could not place) stands: any network tool's failure
        # holds while it does.
        if [ -e "$footprint/.unattributed" ]; then
          log "holding for $unit: an unattributed change to how traffic leaves stands"
          exit 0
        fi
        f="$footprint/$unit"
        if [ ! -f "$f" ]; then
          log "holding for $unit: no footprint"
          exit 0
        fi
        # Each footprint is confirmed current by netwatch (`at`, refreshed
        # with the heartbeat); one older than the watch window is stale.
        if ! fresh "$(awk '$1 == "at" { print $2; exit }' "$f")"; then
          log "holding for $unit: its footprint is stale"
          exit 0
        fi
        if grep -qx 'protecting yes' "$f" || grep -qx 'unattributed' "$f"; then
          exit 0
        fi
        # 3. The footprint must be this run's (owner decision, Nov 3): netwatch
        #    records the unit's InvocationID (its cgroup's
        #    trusted.invocation_id) as `invocation <32 hex>`, and systemd keeps
        #    the failed run's ID until the next start. A footprint from an
        #    earlier run (a restart that steered and died before netwatch
        #    rewrote it), or an ID missing on either side, says nothing about
        #    this run: hold.
        want=$(systemctl show -P InvocationID "$unit.service" 2>/dev/null || true)
        got=$(awk '$1 == "invocation" { print $2; exit }' "$f")
        if [ -z "$want" ] || [ -z "$got" ] || [ "$got" != "$want" ]; then
          log "holding for $unit: its footprint is not this run's (footprint ''${got:-none}, unit ''${want:-none})"
          exit 0
        fi
        log "$unit failed but was not protecting traffic: not held"
        exit 1 ;;
      apply)
        touch "$dir/$unit"
        snapshot
        build_or_lock && log "traffic held: $unit has failed" ;;
      lift)
        rm -f "$dir/$unit"
        build_or_lock && log "hold on $unit lifted" ;;
      reapply)
        build_or_lock ;;
      *) echo "usage: planarian-hold apply|lift|condition UNIT | reapply" >&2; exit 2 ;;
    esac
  '';

  # §12d: the OnFailure= hold on each network-security unit, and the
  # re-application after nftables.service (re)loads, as drop-ins. A drop-in
  # for a unit this system does not define is inert, where a
  # systemd.services entry would define a stub unit.
  #
  # §12d (owner decision, Nov 2): with netwatch, every network tool also
  # starts after it (After= only: if netwatch fails, the tool still starts
  # and its failure holds). With Type=notify, after its attach. In the same
  # drop-in, so a template orders every instance, a tool shipped as unit
  # files is covered, and a socket- or timer-activated tool is ordered by
  # its service.
  holdDropins = lib.listToAttrs (map (u: {
    name = "${u}.service.d/50-planarian-hold.conf";
    # %N: the failed unit's name, per instance for a template's drop-in.
    value = "[Unit]\nOnFailure=planarian-hold@%N.service\n"
      + lib.optionalString (netwatchOn && !(builtins.elem u unordered.cycle)) "After=planarian-netwatch.service\n";
  }) cfg.holdUnits) // {
    "nftables.service.d/50-planarian-hold.conf" = "[Service]\nExecStartPost=${hold} reapply\nExecReload=${hold} reapply\n";
  };
  netwatchOn = cfg.package.netwatch or false;
  unordered = import ./netwatch-unordered.nix;
  # With the systemd initrd, the tools it starts and keeps across
  # switch-root: the upstream list, and any unit declared for the initrd
  # with IgnoreOnIsolate= and no Conflicts= on initrd-switch-root.
  initrdSurvives = v:
    let uc = v.unitConfig or { }; ign = uc.IgnoreOnIsolate or false;
        conf = (v.conflicts or [ ]) ++ ordWords v "conflicts" "Conflicts";
    in (ign == true || ign == "yes" || ign == "true") && !(lib.any (c: builtins.elem c [ "initrd-switch-root.target" "initrd-switch-root.service" ]) conf);
  initrdSurvivors = lib.optionals config.boot.initrd.systemd.enable
    (unordered.initrdSurvivors ++ lib.attrNames (lib.filterAttrs (_: initrdSurvives) config.boot.initrd.systemd.services));
  # Every service the systemd initrd runs: the upstream list, the
  # configuration's additional upstream units, and those it declares.
  initrdRuns = lib.optionals config.boot.initrd.systemd.enable (unordered.initrdUpstream
    ++ map (lib.removeSuffix ".service") (lib.filter (lib.hasSuffix ".service") (config.boot.initrd.systemd.additionalUpstreamUnits or [ ]))
    ++ lib.attrNames config.boot.initrd.systemd.services);
  unorderedTools = lib.unique (unordered.cycle ++ lib.optionals netwatchOn initrdSurvivors);
  # The units ordered before planarian-netwatch.service in this
  # configuration, transitively (its After=, and every unit whose Before=
  # names one already found). A network tool among them, ordered after
  # netwatch, would be an ordering cycle. An instance's edges include its
  # template's. Unit files outside the module system are checked at build
  # time (module-eval, systemd-analyze verify).
  unitKinds = { service = config.systemd.services; target = config.systemd.targets; socket = config.systemd.sockets; timer = config.systemd.timers; path = config.systemd.paths; slice = config.systemd.slices; };
  ordWords = v: f: F: (v.${f} or [ ]) ++ lib.concatMap (w: lib.filter (x: x != "") (lib.splitString " " (toString w))) (lib.toList (v.unitConfig.${F} or [ ]));
  unitDefs = lib.concatLists (lib.mapAttrsToList (k: us: lib.mapAttrsToList (n: v: { name = "${n}.${k}"; after = ordWords v "after" "After"; before = ordWords v "before" "Before"; }) us) unitKinds);
  templateOf = n: let m = builtins.match "([^@]+@).+(\\.[a-z]+)" n; in if m == null then null else "${builtins.elemAt m 0}${builtins.elemAt m 1}";
  afterOf = lib.foldl' (acc: d: acc // { ${d.name} = (acc.${d.name} or [ ]) ++ d.after; }) { } unitDefs;
  # Reversed Before=: x.before has y means x is ordered before y.
  beforeOf = lib.foldl' (acc: d: lib.foldl' (a: y: a // { ${y} = (a.${y} or [ ]) ++ [ d.name ]; }) acc d.before) { } unitDefs;
  predsOf = n: let t = templateOf n; ns = [ n ] ++ lib.optional (t != null) t; in
    lib.concatMap (x: (afterOf.${x} or [ ]) ++ (beforeOf.${x} or [ ])) ns;
  beforeNetwatch = map (i: i.key) (builtins.genericClosure {
    startSet = map (key: { inherit key; }) (predsOf "planarian-netwatch.service");
    operator = i: map (key: { inherit key; }) (predsOf i.key);
  });
  cyclicTools = lib.filter (t: lib.any (n: n == "${t}.service" || templateOf n == "${t}.service") beforeNetwatch) cfg.holdUnits;
  holdDropinPackage = pkgs.runCommand "planarian-hold-dropins" { passthru.planarianHoldDropins = true; } (lib.concatStrings (lib.mapAttrsToList (n: t: ''
    mkdir -p "$out/etc/systemd/system/$(dirname ${lib.escapeShellArg n})"
    printf '%s' ${lib.escapeShellArg t} > "$out/etc/systemd/system/"${lib.escapeShellArg n}
  '') holdDropins));

  # I2 in A-D (§12d, B-12): every Planarian binary and script this
  # generation installs, hashed at build. The watchdog checks each against
  # the record; any mismatch is an Integrity failure. (Signatures in E.)
  coreFiles = [
    "${cfg.package}/bin/planariad"
    "${cfg.package}/bin/planarian-recovery"
    "${cfg.package}/bin/planarian"
    "${respond}"
    "${lift}"
    "${ack}/bin/planarian-ack"
    "${stopPost "planariad"}"
    "${stopPost "planarian-recovery"}"
    "${check}"
    "${hold}"
  ] ++ lib.optionals (cfg.package.netwatch or false) [
    "${cfg.package}/share/planarian/netwatch.bpf.o"
    "${cfg.package}/bin/planarian-netwatch"
  ];
  coreHash = pkgs.runCommand "planarian-core-hash" { } ''
    for f in ${lib.escapeShellArgs coreFiles}; do
      printf '%s %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"
    done > $out
  '';
in
{
  options.services.planarian = {
    bootReadyTimeout = mkOption {
      type = types.ints.between 15 600;
      default = 60;
      description = "Seconds planariad has to reach ready at boot before the Absent responses (§12d). Shortening it is a Tested change; lengthening it is Security-sensitive.";
    };
    agentUnits = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "my-assistant.service" ];
      description = "Units that run an agent principal (§11). They start only after planarian-ready.target and are stopped by every failure class (I20).";
    };
    holdAllowsOwnInterface = mkOption {
      type = types.bool;
      default = true;
      internal = true;
      description = "Whether a hold passes traffic over the held units' own interfaces (`holdInterfaces`), as a kill switch does: the tunnel's own traffic is protected traffic (owner decision, Nov 2; §12d).";
    };
    holdUnits = mkOption {
      type = types.listOf types.str;
      readOnly = true;
      internal = true;
      description = "The network-security units (§12d): a failure of any holds the machine's traffic.";
    };
    networkToolsUnordered = mkOption {
      type = types.listOf types.str;
      readOnly = true;
      internal = true;
      description = "The network tools that do not start after planarian-netwatch.service (nix/netwatch-unordered.nix: its startup chain, and the systemd initrd's survivors), for the export.";
    };
    networkToolsInitrd = mkOption {
      type = types.listOf types.str;
      readOnly = true;
      internal = true;
      description = "The network tools the systemd initrd also runs, before netwatch exists (a template covers its instances), for the export.";
    };
    netwatchInitrdSurvivors = mkOption {
      type = types.listOf types.str;
      readOnly = true;
      internal = true;
      description = "The network tools the systemd initrd starts and keeps across switch-root (for module-eval).";
    };
    netwatchCycle = mkOption {
      type = types.listOf types.str;
      readOnly = true;
      internal = true;
      description = "The network tools ordered before planarian-netwatch.service in this configuration (for module-eval).";
    };
    holdDropins = mkOption {
      type = types.attrsOf types.str;
      readOnly = true;
      internal = true;
      description = "The hold's systemd drop-ins, by path under /etc/systemd/system (for module-eval).";
    };
    adminGroup = mkOption {
      type = types.str;
      default = "planarian-admin";
      internal = true;
      description = "The administrators' group.";
    };
  };

  config = mkIf cfg.enable (lib.mkMerge [ {
    # §12h: authenticated time is recommended; unauthenticated NTP is a
    # notice, not an error (nothing Planarian times depends on it, B-7).
    warnings = lib.optional (!(config.services.chrony.enable && config.services.chrony.enableNTS))
      "planarian: the clock is set by unauthenticated NTP; authenticated time (NTS) is recommended: services.chrony.enable = true; services.chrony.enableNTS = true; (SPEC §12h).";
    environment.systemPackages = [ ack ];
    environment.etc."planarian/core.sha256".source = coreHash;
    environment.etc."planarian/boot-ready-timeout".text = toString cfg.bootReadyTimeout;

    systemd.targets.planarian-ready = {
      description = "Planarian is ready";
      wantedBy = [ "multi-user.target" ];
      # BindsTo, not Requires: a required unit that fails (rather than is
      # stopped) leaves its dependents up, which would read as ready with
      # planariad dead. Every exit of planariad takes the target down, a
      # restart within the budget included: RestartMode=direct skips only the
      # failed state and OnFailure= (so Crashed waits for the budget), not
      # BindsTo= (observed on systemd 260.5, the pinned one; the man page
      # reads otherwise). The declared agent units require it (below), and
      # launched agents each require it (`start_agent`), so they stop with
      # it too; the slice itself is only ordered after it. The target, with
      # planarian-posture-lift, comes back once planariad is active again
      # (its Wants=). An in-budget crash raises no failure
      # class by itself. Absent follows any stop of planariad outside a
      # shutdown, `systemctl restart` included (ExecStopPost sees result
      # `success`), and lifts once it is ready again. (VM run 41288596484:
      # vm-posture's SIGSEGVs; crash-slow-worker-overlap's SIGKILL, then a
      # restart of the restarting unit.)
      bindsTo = [ "planariad.service" ];
      after = [ "planariad.service" ];
      unitConfig.StopWhenUnneeded = false;
    };

    systemd.targets."planarian-failed@" = {
      description = "Planarian failure: %i";
      wants = [ "planarian-respond@%i.service" ];
      # I20 is held by the respond unit (it stops the agents) and by the
      # agents' own condition, not Conflicts=: that is symmetric, so an agent
      # started by a later planarian-ready.target would stop this target.
      unitConfig.DefaultDependencies = false;
    };

    systemd.services."planarian-respond@" = {
      description = "Planarian failure posture: respond to %i";
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${respond} %i";
      };
    };

    systemd.services.planarian-posture-check = {
      description = "Planarian failure posture: ready within the boot-ready timeout";
      wantedBy = [ "multi-user.target" ];
      unitConfig.DefaultDependencies = false;
      after = [ "sysinit.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = check;
        TimeoutStartSec = cfg.bootReadyTimeout + 30;
      };
    };

    systemd.services.planarian-posture-lift = {
      description = "Planarian failure posture: lift restrictions once ready";
      wantedBy = [ "planarian-ready.target" ];
      # After the responses it lifts: a restart of planariad queues Absent
      # (stopPost, --no-block) and reaches ready again before respond has
      # finished; unordered, lift ran first, found nothing, and Absent
      # stayed raised (VM run 41507137168, P16).
      after = [ "planarian-ready.target" "planarian-respond@absent.service" "planarian-respond@crashed.service" ];
      serviceConfig = { Type = "oneshot"; ExecStart = lift; };
    };

    systemd.services.planariad = {
      # Starting planariad again (after a stop) brings the target back with it.
      wants = [ "planarian-ready.target" ];
      before = [ "planarian-ready.target" ];
      onFailure = [ "planarian-failed@crashed.target" ];
      startLimitBurst = 5;
      startLimitIntervalSec = 300;
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        # Reconciliation may run a revert before ready; the boot-ready timeout
        # belongs to planarian-posture-check, which raises Absent and lifts it
        # again once ready is reached.
        TimeoutStartSec = "infinity";
        # Restarts within the budget skip the failed state, so OnFailure=
        # (Crashed) fires only once the budget is spent (systemd ≥ 254).
        RestartMode = "direct";
        # 78: an integrity failure; not restarted, routed by ExecStopPost.
        SuccessExitStatus = [ 78 ];
        RestartPreventExitStatus = [ 78 ];
        ExecStopPost = stopPost "planariad";
      };
    };

    systemd.services.planarian-recovery = {
      environment.PLANARIAN_CORE_HASH = "/etc/planarian/core.sha256";
      # P15: a crash-looping watchdog is Crashed, as planariad is: restarts
      # within the budget skip the failed state, then OnFailure= fires.
      onFailure = [ "planarian-failed@crashed.target" ];
      startLimitBurst = 5;
      startLimitIntervalSec = 300;
      serviceConfig = {
        RestartMode = "direct";
        SuccessExitStatus = [ 78 ];
        RestartPreventExitStatus = [ 78 ];
        ExecStopPost = stopPost "planarian-recovery";
      };
    };

    services.openssh.extraConfig = mkIf config.services.openssh.enable ''
      Include /run/planarian/sshd/*.conf
    '';
  }
  {
    # Admit no principal before the monitor (§12d); under Standard they follow
    # the target (after) but do not require it, so local login proceeds.
    systemd.services = lib.genAttrs (map (lib.removeSuffix ".service") principalUnits) (_: {
      after = [ "planarian-ready.target" ];
    });
  }
  {
    # §12d "Network security fails closed": the hold unit, its drop-ins
    # and each held unit's holdAllow endpoints.
    services.planarian.holdDropins = holdDropins;
    services.planarian.networkToolsUnordered = lib.filter (u: builtins.elem u unorderedTools) cfg.holdUnits;
    services.planarian.netwatchInitrdSurvivors = lib.filter (u: builtins.elem u initrdSurvivors) cfg.holdUnits;
    services.planarian.networkToolsInitrd = lib.optionals netwatchOn (lib.filter (u: builtins.elem u initrdRuns) cfg.holdUnits);
    services.planarian.netwatchCycle = if netwatchOn then cyclicTools else [ ];
    assertions = lib.optional netwatchOn {
      assertion = lib.all (u: builtins.elem u unordered.cycle) cyclicTools;
      message = "planarian: network tools are ordered before planarian-netwatch.service, so ordering them after it (owner decision, Nov 2; SPEC §12d) would be a cycle: ${toString (lib.filter (u: !(builtins.elem u unordered.cycle)) cyclicTools)}. Remove that ordering.";
    };
    systemd.packages = [ holdDropinPackage ];
    environment.etc = lib.listToAttrs (map (u: {
      name = "planarian/hold/${u}.allow";
      value.text = lib.concatMapStrings (a: "${a.protocol} ${a.address} ${toString a.port}\n") cfg.units.${u}.holdAllow
        + lib.optionalString cfg.holdAllowsOwnInterface (lib.concatMapStrings (i: "iface ${i}\n") cfg.units.${u}.holdInterfaces);
    # Keyed by the manifest, not by holdUnits: the network tools are computed
    # from every service's configuration, and a service may read
    # environment.etc.
    }) (lib.attrNames (lib.filterAttrs (_: u: u.scope == "system" && (u.holdAllow != [ ] || u.holdInterfaces != [ ])) cfg.units)));
    # The footprints' directory outlives planarian-netwatch's restarts.
    systemd.tmpfiles.rules = [ "d /run/planarian/footprint 0755 root root -" ];
    # §12d: netwatch, attributing every routing, interface, rule and
    # nftables change to the unit that made it, from inside the kernel, and
    # keeping each network tool's footprint (crates/backends/netwatch).
    # Before networking starts, so early changes are attributed. It writes
    # `.watch failed` when it stops or cannot attach (every network tool's
    # failure then holds), and is restarted.
    # nfnetlink is a module (CONFIG_NETFILTER_NETLINK=m): until it is loaded
    # its functions do not exist, and netwatch cannot attach to them. A boot
    # module, loaded in the initrd so it is present when netwatch starts:
    # not by systemd-modules-load, which is a network tool and starts after
    # netwatch, nor by the first nftables use, which comes after it too. A
    # configuration that removes it from boot.kernelModules removes it from
    # the initrd as well (netwatch then reports `failed` and retries).
    boot.kernelModules = mkIf netwatchOn [ "nfnetlink" ];
    boot.initrd.kernelModules = mkIf netwatchOn (lib.intersectLists [ "nfnetlink" ] config.boot.kernelModules);
    systemd.services.planarian-netwatch = mkIf netwatchOn {
      description = "Planarian: attribute network changes to the units that make them";
      # At the front of boot: ordered after nothing, so every network tool,
      # early-boot ones included, can start after it (owner decision,
      # Nov 2). It needs only what is there before systemd starts: the
      # store, /etc, /sys (BTF), /run, the initrd's nfnetlink. Wanted by
      # sysinit.target, so a rescue boot attaches too.
      wantedBy = [ "sysinit.target" ];
      wants = [ "network-pre.target" ];
      # Before the firewall too: its boot batch would otherwise land before
      # the attach and read as unattributed pre-attach steering, and every
      # network tool's failure would hold.
      before = [ "network-pre.target" "firewall.service" "nftables.service" ];
      unitConfig.DefaultDependencies = false;
      restartIfChanged = false;
      serviceConfig = {
        # Ready (READY=1) once attached, snapshotted and its first files
        # written, so "before the firewall and networking" means something;
        # on a failed attach it writes `.watch failed` and notifies or exits
        # promptly. Bounded, so boot never stalls on it.
        Type = "notify";
        NotifyAccess = "main";
        TimeoutStartSec = 30;
        ExecStart = "${cfg.package}/bin/planarian-netwatch --export /etc/planarian/export.json --object ${cfg.package}/share/planarian/netwatch.bpf.o --dir /run/planarian/footprint";
        Restart = "always";
        RestartSec = 1;
        # /run/planarian/footprint without waiting for tmpfiles (the
        # footprints outlive netwatch's restarts).
        RuntimeDirectory = "planarian/footprint";
        RuntimeDirectoryPreserve = true;
        # CAP_SYS_PTRACE: netwatch refuses to start outside the host's
        # network namespace, checked against /proc/1/ns/net; reading it is
        # a ptrace READ access, which a bounded root passes only with this
        # (its permitted set is not a superset of pid 1's).
        CapabilityBoundingSet = [ "CAP_BPF" "CAP_PERFMON" "CAP_SYS_ADMIN" "CAP_NET_ADMIN" "CAP_DAC_READ_SEARCH" "CAP_SYS_PTRACE" ];
      };
    };
    systemd.services."planarian-hold@" = {
      description = "Planarian: hold network traffic while %i has failed";
      # An activation (a repair rollback, `undo`) must not stop and start a
      # running hold: that would open traffic while the unit is still down.
      restartIfChanged = false;
      stopIfChanged = false;
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecCondition = "${hold} condition %i";
        ExecStart = "${hold} apply %i";
        ExecStop = "${hold} lift %i";
        # Rebuild the table in place (after a flush), never lifting it: a
        # restart would run lift then apply, passing traffic between them.
        ExecReload = "${hold} reapply";
      };
    };
  }
  {
    # The launched agents' slice (§12d, R05): `planarian agent run` puts
    # every agent here, and the posture stops it as a whole.
    systemd.slices.planarian-agents = {
      description = "Agents started by planarian agent run";
      after = [ "planarian-ready.target" ];
    };
    # I20: agents start only once Planarian is ready, and never while a
    # failure class is raised.
    systemd.services = lib.genAttrs (map (lib.removeSuffix ".service") cfg.agentUnits) (_: {
      requires = [ "planarian-ready.target" ];
      after = [ "planarian-ready.target" ];
      unitConfig.ConditionPathExistsGlob = "!/run/planarian/failed-*";
    });
  }
  ]);
}
