# §12d (owner decision, Nov 2): the network tools that do not start after
# planarian-netwatch.service. Plain values, like own-units.nix: no
# configuration can widen them. Exported, intersected with the network
# tools, as `networkToolsUnordered`.
{
  # In netwatch's own startup chain: ordering them after it would be a
  # cycle, and a configuration that orders a network tool before netwatch
  # fails evaluation instead. Empty: netwatch is ordered after nothing (it
  # starts at the front of boot, nfnetlink loaded in the initrd, its
  # directory its own RuntimeDirectory).
  cycle = [ ];
  # Started by the systemd initrd and kept running across switch-root,
  # before netwatch exists: upstream units with IgnoreOnIsolate= and no
  # Conflicts= on initrd-switch-root (their files are not visible at
  # evaluation; module-eval checks this list against the initrd's unit
  # files). They keep the After=, which orders a restart in stage 2.
  # Closing this needs netwatch in the initrd (a follow-up with the owner).
  initrdSurvivors = [ "systemd-journald" "systemd-fsck@" "plymouth-start" "debug-shell" ];
}
