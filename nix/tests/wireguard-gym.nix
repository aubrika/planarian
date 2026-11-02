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
# A full-tunnel VPN, as §12d's network tools are: its start sends all
# traffic it is not more specifically routed through wg0 (0.0.0.0/1 and
# 128.0.0.0/1, as wg-quick and OpenVPN's def1 do), after a host route to the
# peer's endpoint by the path it had, so the tunnel's own UDP does not
# loop. The unit adds those routes itself, so they are its claims and its
# footprint reads `protecting yes`. Connected subnets (the LAN, the user
# network's DHCP) stay direct; the hold decides them.
#
# The peer's end is a kernel wg-quick interface listening on 51820; it
# forwards and masquerades what the tunnel brings. The caller's peer must
# serve TCP 9000 (the Readiness probe's target) on the tunnel address;
# neither end runs a server itself. The keys are test-only.
{ pkgs, lib }:

let
  keys = {
    machine = { priv = "cP6KjFs6ETrMbtGOUa5iicYlJfIeiO5YfUM9kE/UImA="; pub = "1yKBJKBQ4Pvx9s9TFx+CTdA4nr+WBoVAFDVQTzuB9F8="; };
    peer = { priv = "cNk4txfT3ovozycRTDaecu2vEpRnGpg4406CWwi+nXU="; pub = "l7HFMh19jc6/K32cwArdHyKr/tgskXKDvmM3wutKvA0="; };
  };
  port = 51820;
  # An address beyond the LAN, held by the peer: what a full tunnel exists
  # to carry. The machine's plain default route reaches it too (via the
  # peer on the LAN), so with wg0 gone only the hold keeps it from leaving.
  upstream = "198.51.100.1";
  # The machine's tunnel up, after wireguard-go has made wg0 (its
  # ExecStartPost); module-eval reads this text.
  machineUp = endpoint: ''
    for _ in $(seq 100); do [ -S /var/run/wireguard/wg0.sock ] && break; sleep 0.1; done
    wg set wg0 private-key ${pkgs.writeText "wg-machine.key" keys.machine.priv} \
      peer ${keys.peer.pub} endpoint ${endpoint}:${toString port} \
      allowed-ips 0.0.0.0/0 persistent-keepalive 5
    ip address add 10.77.0.1/24 dev wg0
    ip link set wg0 up
    # The endpoint by the path it has now, before the tunnel takes the rest.
    path=$(ip -o route get ${endpoint} | sed -E 's/^[^ ]+ //; s/ (src|uid|cache) .*//')
    ip route replace ${endpoint}/32 $path
    ip route replace 0.0.0.0/1 dev wg0
    ip route replace 128.0.0.0/1 dev wg0
  '';
in
{
  inherit machineUp upstream;
  machineAddress = "10.77.0.1";
  peerAddress = "10.77.0.2";
  inherit port;

  # The machine's module. `endpoint`: the peer node's LAN address.
  machine = { endpoint }: {
    systemd.services.wireguard-gym = {
      description = "WireGuard tunnel to the gym peer (wireguard-go)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      path = [ pkgs.wireguard-tools pkgs.iproute2 pkgs.coreutils pkgs.gnused ];
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
        ExecStartPost = pkgs.writeShellScript "wireguard-gym-up" (machineUp endpoint);
        # The /1 routes go with wg0; the endpoint's host route does not.
        ExecStopPost = "-${pkgs.iproute2}/bin/ip route del ${endpoint}/32";
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
    # dhcpcd (10.3.1) segfaults when an interface it manages is deleted,
    # which the crash subtest does to wg0; the tunnel's address is the
    # unit's own (ExecStartPost), so its footprint carries it.
    networking.dhcpcd.denyInterfaces = [ "wg*" ];
    # The plain default route, via the peer on the LAN (below dhcpcd's on
    # the user network): the tunnel's /1 routes are more specific while it
    # is up; with wg0 gone, upstream would leave this way, unless held.
    networking.defaultGateway = { address = endpoint; interface = "eth1"; metric = 10; };

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
    networking.dhcpcd.denyInterfaces = [ "wg*" ];
    # The tunnel's upstream: what the machine sends through it is forwarded
    # and masqueraded out of the peer's other interfaces.
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    networking.interfaces.lo.ipv4.addresses = [ { address = upstream; prefixLength = 32; } ];
    networking.nftables.enable = true;
    networking.nftables.tables.wg-gym-nat = {
      family = "ip";
      content = ''
        chain post { type nat hook postrouting priority srcnat; policy accept; iifname "wg0" oifname != "wg0" masquerade; }
      '';
    };
    networking.wg-quick.interfaces.wg0 = {
      address = [ "10.77.0.2/24" ];
      listenPort = port;
      privateKeyFile = "${pkgs.writeText "wg-peer.key" keys.peer.priv}";
      peers = [ { publicKey = keys.machine.pub; allowedIPs = [ "10.77.0.1/32" ]; persistentKeepalive = 5; } ];
    };
  };
}
