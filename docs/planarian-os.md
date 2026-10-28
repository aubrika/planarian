# PlanarianOS (prototype)

A demo VM, a live USB image and an installer: NixOS with Planarian, the
COSMIC desktop and the reference configuration (`nix/reference.nix`). They
are prototypes for trying Planarian, not a supported distribution.

## A VM (one command)

On any Linux machine with Nix (flakes enabled):

```sh
nix run github:aubrika/planarian#vm        # COSMIC desktop with the console, in a window
nix run github:aubrika/planarian#vm-text   # no desktop: a shell in your terminal
```

The first run builds Planarian and downloads NixOS from cache.nixos.org;
later runs start in seconds.

The VM logs in as `demo` (password `planarian`; `sudo` needs none) and
prints what to try: `planarian status`, `ask "make text bigger"`, and
`demo-fault kill-web` / `corrupt-state` / `crash-loop` to break the fixture
services and watch Planarian respond. Its `/etc/nixos` is a flake that
evaluates to exactly the system you booted, so changes Planarian makes inside
are real rebuilds (they download from cache.nixos.org, so the VM needs the
host's network).

- It uses KVM when `/dev/kvm` is available and falls back to emulation
  (slow, especially the desktop) when not. It takes 6 GB of RAM (3 GB for
  `vm-text`), since Planarian evaluates the whole system inside the VM when
  it makes a change.
- State lives in `planarian-vm.qcow2` in the directory you ran it from.
  Delete it to start over. Delete it too after updating Planarian, since the
  old disk's `/etc/nixos` still points at the old version.
- Generations built inside survive a restart of the VM, but the VM has no
  boot loader: it always boots the system it was launched with, not the
  newest generation Planarian published.
- The text variant's terminal is the serial console: `Ctrl-a x` quits QEMU.

## What to try in the VM

| Try | What should happen |
| --- | --- |
| `demo-fault kill-web` | Within about 15 s: an incident, a restart, and `planarian log` shows it. |
| `demo-fault corrupt-state` | `gym-state` cannot start: Planarian tries, then hands it to you. `demo-fault fix-state` undoes it. |
| `demo-fault crash-loop` | systemd restarts `gym-restartful` itself; Planarian stays out of the way. |
| `ask "stop gym-web until I say"` | It stops and stays stopped; Planarian won't "repair" it. `ask "start gym-web again"` undoes it. |
| `ask "make text bigger"` | A configuration change: built, activated, health-checked, then committed. `planarian log` shows each step. |
| `planarian apply service-enable service=gym-extra enabled=true` | Another configuration change: turns on a service. |

## A live USB stick

```sh
nix build github:aubrika/planarian#iso
```

Write `result/iso/planarian-live.iso` to a USB stick with an image writer
(GNOME Disks, Fedora Media Writer, …). **Writing the image erases the
stick**; check that you picked the stick and not a disk you need.

Boot from it (UEFI or BIOS) and you get the same demo as the VM: COSMIC, the
console, the welcome terminal, `demo-fault`. It runs entirely in RAM, so
changes Planarian makes are real rebuilds (with a network), and everything
is gone at the next boot. Give it at least 8 GB of RAM if you want to try
configuration changes. Like the VM, its users have the published password
`planarian`; it runs no SSH server.

It boots quietly behind the planarian splash. Press Esc during boot to see
the messages, or pick **verbose boot** in the boot menu.

## Installing it

**The installer erases the whole disk you choose.** It is a prototype:
install it on a machine or disk with nothing you want to keep.

From the live system, open **Install Planarian** (or run `sudo
planarian-install` in a terminal). It asks for a disk, a filesystem (ext4 or
btrfs), a computer name, your user name and a password, shows what it will
do, and asks you to type `yes` before it erases anything. It then installs
NixOS with Planarian, COSMIC and the reference configuration. Your user is
an administrator (`planarian-admin`): you approve the changes Planarian asks
about.

- `/etc/nixos` is the installed computer's flake: edit `configuration.nix`;
  Planarian edits only `planarian/overrides.nix`. It is pinned to the nixpkgs
  and Planarian the stick was built from, and both sources stay on disk, so
  Planarian can rebuild without a network.
- Installing copies most of the system from the stick; anything missing
  (firmware, drivers for your hardware) comes from cache.nixos.org, so plug
  in a network.
- UEFI machines boot with systemd-boot, BIOS machines with GRUB.
- On btrfs, the installer turns off copy-on-write for Planarian's journal
  directory, which its recovery guarantee needs (SPEC §12c). ZFS isn't offered.
- Unattended (no questions, no confirmation): `planarian-install --disk
  /dev/… --fs btrfs --hostname laptop --user ana --password-file pw --yes`.
