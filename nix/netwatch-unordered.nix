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
  # Every upstream service the systemd initrd ships (beside those the
  # configuration declares for it, which evaluation sees). A network tool
  # among them may act in the initrd, before netwatch exists; one that
  # starts again in stage 2 is ordered there, one that does not (a
  # condition-skipped modprobe@) keeps its initrd start. Exported as
  # `networkToolsInitrd`. Not a fail-open: steering such a unit leaves
  # standing at switch-root is in netwatch's pre-attach snapshot
  # (`.unattributed`, which holds). module-eval checks this list against
  # the initrd's unit files.
  initrdUpstream = [
    "breakpoint-pre-basic" "breakpoint-pre-mount" "breakpoint-pre-switch-root" "breakpoint-pre-udev"
    "debug-shell" "initrd-cleanup" "initrd-udevadm-cleanup-db" "kmod-static-nodes"
    "systemd-ask-password-console" "systemd-ask-password-plymouth" "systemd-bsod"
    "systemd-factory-reset-complete" "systemd-fsck@" "systemd-halt" "systemd-hibernate-resume"
    "systemd-journald" "systemd-kexec" "systemd-modules-load" "systemd-poweroff" "systemd-reboot"
    "systemd-sysctl" "systemd-tmpfiles-setup-dev" "systemd-tmpfiles-setup-dev-early"
    "systemd-tpm2-setup-early" "systemd-udev-trigger" "systemd-udevd" "systemd-vconsole-setup"
  ];
}
