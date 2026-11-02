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
