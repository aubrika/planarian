# The gym's network-security fixture (§12d "Network security fails closed"):
# a WireGuard tunnel from the machine (10.77.0.1) to a peer node
# (10.77.0.2), shared by the gym VM's netsec-* entries and vm-netsec.
#
# The machine's end is `wireguard-gym`, a userspace WireGuard daemon
# (wireguard-go) in its own unit, so a kill fails the unit as it would a VPN
# daemon (NixOS's kernel wg-quick units are oneshots with nothing to kill).
# Restart=no: restarting is Planarian's repair. It is a network-security unit
# (Security and External); its hold still lets it reach the peer's endpoint.
# Markers: /run/wireguard-gym-slow holds the seconds its start takes (to keep
# a restart in progress long enough to observe the hold);
# /run/wireguard-gym-broken makes its start fail.
#
# The peer's end is a kernel wg-quick interface listening on 51820. The
# caller's peer must serve TCP 9000 (the Readiness probe's target) on the
# tunnel address; neither end runs a server itself. The keys are test-only.
{ pkgs, lib }:

let
  keys = {
    machine = { priv = "cP6KjFs6ETrMbtGOUa5iicYlJfIeiO5YfUM9kE/UImA="; pub = "1yKBJKBQ4Pvx9s9TFx+CTdA4nr+WBoVAFDVQTzuB9F8="; };
    peer = { priv = "cNk4txfT3ovozycRTDaecu2vEpRnGpg4406CWwi+nXU="; pub = "l7HFMh19jc6/K32cwArdHyKr/tgskXKDvmM3wutKvA0="; };
  };
  port = 51820;
in
{
  machineAddress = "10.77.0.1";
  peerAddress = "10.77.0.2";
  inherit port;

  # The machine's module. `endpoint`: the peer node's LAN address.
  machine = { endpoint }: {
    systemd.services.wireguard-gym = {
      description = "WireGuard tunnel to the gym peer (wireguard-go)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      path = [ pkgs.wireguard-tools pkgs.iproute2 pkgs.coreutils ];
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        Environment = "WG_PROCESS_FOREGROUND=1";
        ExecStartPre = [
          "${pkgs.bash}/bin/bash -c '! test -e /run/wireguard-gym-broken'"
          "${pkgs.bash}/bin/bash -c 'sleep $(cat /run/wireguard-gym-slow 2>/dev/null || echo 0)'"
        ];
        # A VPN daemon that exits on its own has failed, whatever its exit
        # status (wireguard-go exits cleanly when wg0 is deleted): the unit
        # exits 1, so OnFailure= fires. A stop kills the whole unit and is
        # clean.
        ExecStart = pkgs.writeShellScript "wireguard-gym" ''
          ${pkgs.wireguard-go}/bin/wireguard-go -f wg0
          echo "wireguard-go exited (status $?)" >&2
          exit 1
        '';
        ExecStartPost = pkgs.writeShellScript "wireguard-gym-up" ''
          for _ in $(seq 100); do [ -S /var/run/wireguard/wg0.sock ] && break; sleep 0.1; done
          wg set wg0 private-key ${pkgs.writeText "wg-machine.key" keys.machine.priv} \
            peer ${keys.peer.pub} endpoint ${endpoint}:${toString port} \
            allowed-ips 10.77.0.2/32 persistent-keepalive 5
          ip address add 10.77.0.1/24 dev wg0
          ip link set wg0 up
        '';
      };
    };
    # A templated network tool (§12d: templates are classified like any
    # unit), instantiated as gym-tpl@a: its failure holds as
    # planarian-hold@gym-tpl@a. Root with no bounding set, so a network
    # tool; its start adds a firewall table that drops 203.0.113.78 (no test
    # traffic), so netwatch sees it protecting traffic. Restart=no.
    # Markers: /run/gym-tpl-<instance>-slow (seconds its start takes) and
    # /run/gym-tpl-<instance>-broken (its start fails).
    systemd.services."gym-tpl@" = {
      description = "Gym templated network tool %i";
      path = [ pkgs.nftables pkgs.coreutils ];
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        ExecStartPre = [
          "${pkgs.bash}/bin/bash -c '! test -e /run/gym-tpl-%i-broken'"
          "${pkgs.bash}/bin/bash -c 'sleep $(cat /run/gym-tpl-%i-slow 2>/dev/null || echo 0)'"
        ];
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        ExecStartPost = "${pkgs.nftables}/bin/nft 'add table inet gymtpl_%i; add chain inet gymtpl_%i out { type filter hook output priority 0; }; add rule inet gymtpl_%i out ip daddr 203.0.113.78 drop'";
        ExecStopPost = "-${pkgs.nftables}/bin/nft delete table inet gymtpl_%i";
      };
    };
    systemd.targets.multi-user.wants = [ "gym-tpl@a.service" ];

    # netwatch's attribution (§12d "Which units"), for its VM case. Each is a
    # network tool (root, no bounding set) and a daemon, so a kill fails it;
    # none starts at boot: the case starts them once the watch is attached.
    # gym-steer creates a dummy interface carrying a default route (metric
    # 9999, so it diverts no test traffic): protecting. gym-quiet changes
    # nothing: not protecting. gym-legacy adds an iptables-legacy rule that
    # drops 203.0.113.79 (no test traffic): protecting.
    systemd.services.gym-steer = {
      description = "Gym: a dummy interface carrying a default route";
      path = [ pkgs.iproute2 ];
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        ExecStartPre = [ "${pkgs.iproute2}/bin/ip link add gsteer0 type dummy" "${pkgs.iproute2}/bin/ip link set gsteer0 up" "${pkgs.iproute2}/bin/ip route add default dev gsteer0 metric 9999" ];
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        ExecStopPost = "-${pkgs.iproute2}/bin/ip link delete gsteer0";
      };
    };
    systemd.services.gym-quiet = {
      description = "Gym: a network tool that changes nothing";
      serviceConfig = { Type = "simple"; Restart = "no"; ExecStart = "${pkgs.coreutils}/bin/sleep infinity"; };
    };
    systemd.services.gym-legacy = {
      description = "Gym: an iptables-legacy rule that drops";
      serviceConfig = {
        Type = "simple";
        Restart = "no";
        ExecStartPre = "${pkgs.iptables}/bin/iptables-legacy -A OUTPUT -d 203.0.113.79 -j DROP";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        ExecStopPost = "-${pkgs.iptables}/bin/iptables-legacy -D OUTPUT -d 203.0.113.79 -j DROP";
      };
    };

    services.planarian.units.wireguard-gym = {
      sensitivity = [ "Security" "External" ];
      holdAllow = [ { address = endpoint; inherit port; protocol = "udp"; } ];
      # Its own interface passes the hold (owner decision, Nov 2), so the
      # Readiness probe can cross the tunnel: the hold lifts only once the
      # tunnel carries traffic again. The peer serves 10.77.0.2:9000.
      holdInterfaces = [ "wg0" ];
      probes = [ { id = "wireguard-gym-tunnel"; type = "tcp"; addr = "10.77.0.2:9000"; establishes = "the tunnel carries traffic to the peer"; } ];
    };
  };

  # The peer node's module.
  peer = {
    networking.wg-quick.interfaces.wg0 = {
      address = [ "10.77.0.2/24" ];
      listenPort = port;
      privateKeyFile = "${pkgs.writeText "wg-peer.key" keys.peer.priv}";
      peers = [ { publicKey = keys.machine.pub; allowedIPs = [ "10.77.0.1/32" ]; persistentKeepalive = 5; } ];
    };
  };
}
