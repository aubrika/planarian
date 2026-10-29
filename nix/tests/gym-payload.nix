# The gym's bad payload (catalog family malicious-declaration, SPEC §15): a
# declared service, off by default, that behaves for four minutes (past any
# generation check), then crashes gym-web and holds its port. Planarian cannot
# tell it from a legitimate service; what the entries score is whether the
# incident on gym-web names where this declaration came from. A module file of
# its own, so its definition location is a real path.
{ config, lib, pkgs, ... }:

{
  options.services.gym-bad-payload.enable = lib.mkEnableOption "the gym's bad payload";

  config.systemd.services.gym-bad-payload = lib.mkIf config.services.gym-bad-payload.enable
    (import ./gym-modules-new/service.nix { inherit config pkgs; });
}
