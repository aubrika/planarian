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
    ++ lib.optional (config.services.xserver.enable || config.services.displayManager.enable or false) "display-manager.service"
    ++ [ "user@.service" "getty@.service" "autovt@.service" ];

  coreHash = pkgs.runCommand "planarian-core-hash" { } ''
    sha256sum ${cfg.package}/bin/planariad | cut -d' ' -f1 > $out
  '';

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
    # ConditionPathExistsGlob keeps them from starting again).
    ${optionalString (cfg.agentUnits != [ ]) "systemctl stop ${concatStringsSep " " cfg.agentUnits} || true"}
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
        printf 'Match all\n  AllowGroups ${cfg.adminGroup} wheel\n' > /run/planarian/sshd/posture.conf
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
    if [ -e /run/planarian/alarm ]; then
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
    deadline=$(( $(date +%s) + ${toString cfg.bootReadyTimeout} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      systemctl is-active --quiet planarian-ready.target && exit 0
      sleep 2
    done
    systemctl is-active --quiet planarian-ready.target && exit 0
    systemctl start --no-block planarian-failed@absent.target
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
    adminGroup = mkOption {
      type = types.str;
      default = "planarian-admin";
      internal = true;
      description = "The administrators' group.";
    };
  };

  config = mkIf cfg.enable (lib.mkMerge [ {
    environment.systemPackages = [ ack ];
    environment.etc."planarian/core.sha256".source = coreHash;

    systemd.targets.planarian-ready = {
      description = "Planarian is ready";
      wantedBy = [ "multi-user.target" ];
      # BindsTo, not Requires: a required unit that fails (rather than is
      # stopped) leaves its dependents up, which would read as ready with
      # planariad dead. Restarts within the budget keep planariad activating
      # (RestartMode=direct), so they do not take the target down.
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
      after = [ "planarian-ready.target" ];
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
      environment.PLANARIAN_CORE_BINARY = "${cfg.package}/bin/planariad";
      serviceConfig = {
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
