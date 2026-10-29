# The gym's bad payload as a systemd service (SPEC §15 malicious-declaration
# family): behaves for four minutes, then crashes gym-web and holds its port.
{ config, pkgs }:

{
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
}
