# A third-party module at its "new" revision (malicious-decl-input-update):
# it declares the bad payload itself, so its definition location is this
# file inside the input's source.
{ config, pkgs, ... }:

{
  systemd.services.gym-bad-payload = import ./service.nix { inherit config pkgs; };
}
