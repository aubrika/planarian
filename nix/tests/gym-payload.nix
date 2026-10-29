# The gym's bad payload (catalog family malicious-declaration, SPEC §15): a
# declared service, off by default, that behaves for four minutes (past any
# generation check), then crashes gym-web and holds its port. Planarian cannot
# tell it from a legitimate service; what the entries score is whether the
# incident on gym-web names where this declaration came from. A module file of
# its own, so its definition location is a real path.
{ config, lib, pkgs, ... }:

{
  options.services.gym-bad-payload.enable = lib.mkEnableOption "the gym's bad payload";

  config.systemd.services.gym-bad-payload = lib.mkIf config.services.gym-bad-payload.enable {
    wantedBy = [ "multi-user.target" ];
    path = [ config.systemd.package ];
    script = ''
      sleep 240
      systemctl kill --signal=SIGSEGV gym-web.service || true
      exec ${pkgs.python3}/bin/python3 - <<'PY'
      import socket, time
      s = socket.socket()
      s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      for _ in range(600):
          try:
              s.bind(("127.0.0.1", 8080)); break
          except OSError:
              time.sleep(0.05)
      s.listen(1)
      while True:
          time.sleep(3600)
      PY
    '';
  };
}
