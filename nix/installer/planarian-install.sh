# planarian-install: erase a disk and install NixOS with Planarian and the
# reference desktop on it (nix/installer/default.nix provides the
# environment: PLANARIAN_SEED, PLANARIAN_URL, NIXPKGS_URL).
#
#   planarian-install                         asks for everything
#   planarian-install --disk /dev/nvme0n1 --fs btrfs --hostname laptop \
#     --user ana --password-file pw --yes     asks for nothing
#   ... --no-install                          stop before nixos-install

usage() {
  cat <<EOF
usage: planarian-install [--disk DEV] [--fs ext4|btrfs] [--hostname NAME]
                         [--user NAME] [--password-file FILE] [--timezone TZ]
                         [--root DIR] [--yes] [--no-install]
EOF
  exit 2
}

disk="" fs="" host="" user="" pwfile="" tz="" root=/mnt yes=0 install=1
while [ $# -gt 0 ]; do
  case "$1" in
    --disk) disk=$2; shift ;;
    --fs) fs=$2; shift ;;
    --hostname) host=$2; shift ;;
    --user) user=$2; shift ;;
    --password-file) pwfile=$2; shift ;;
    --timezone) tz=$2; shift ;;
    --root) root=$2; shift ;;
    --yes) yes=1 ;;
    --no-install) install=0 ;;
    -h|--help) usage ;;
    *) echo "planarian-install: unknown argument $1" >&2; usage ;;
  esac
  shift
done

if [ "$(id -u)" != 0 ]; then
  exec sudo "$0" "$@"
fi

ask() { # ask VAR "question" DEFAULT
  local answer
  read -r -p "$2${3:+ [$3]}: " answer
  printf -v "$1" '%s' "${answer:-$3}"
}

echo "Planarian installer: NixOS with Planarian and the COSMIC desktop."
echo

if [ -z "$disk" ]; then
  echo "Disks:"
  lsblk -dpno NAME,SIZE,TYPE,MODEL | awk '$3 == "disk" { print "  " $0 }'
  ask disk "Disk to install on (everything on it is erased)" ""
fi
[ -b "$disk" ] || { echo "planarian-install: $disk is not a block device" >&2; exit 1; }
if lsblk -no MOUNTPOINTS "$disk" | grep -qE '^/(iso|nix/\.ro-store)?$'; then
  echo "planarian-install: $disk holds the running system" >&2; exit 1
fi

[ -n "$fs" ] || ask fs "Filesystem: ext4 or btrfs" ext4
case "$fs" in ext4|btrfs) ;; *) echo "planarian-install: --fs is ext4 or btrfs" >&2; exit 1 ;; esac

[ -n "$host" ] || ask host "Computer name" planarian
[[ "$host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] \
  || { echo "planarian-install: '$host' is not a valid hostname" >&2; exit 1; }

[ -n "$user" ] || ask user "Your user name" ""
[[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && [ "$user" != root ] \
  || { echo "planarian-install: '$user' is not a valid user name" >&2; exit 1; }

if [ -n "$pwfile" ]; then
  password=$(head -n1 "$pwfile")
else
  while :; do
    read -r -s -p "Password for $user: " password; echo
    read -r -s -p "Again: " again; echo
    [ -n "$password" ] && [ "$password" = "$again" ] && break
    echo "They differ (or are empty); once more."
  done
fi
hash=$(printf '%s\n' "$password" | mkpasswd -m yescrypt -s)

[ -n "$tz" ] || tz=$(timedatectl show -p Timezone --value 2>/dev/null || true)
[ -n "$tz" ] || tz=UTC

if [ -d /sys/firmware/efi ]; then firmware=uefi; else firmware=bios; fi

echo
echo "  disk        $disk ($(lsblk -dno SIZE "$disk"), $firmware boot)"
echo "  filesystem  $fs"
echo "  computer    $host"
echo "  user        $user (administrator: approves Planarian's changes)"
echo "  time zone   $tz"
echo
if [ "$yes" != 1 ]; then
  confirm=""
  ask confirm "Erase $disk and install? Type yes" ""
  [ "$confirm" = yes ] || { echo "Nothing changed."; exit 1; }
fi

set -x
# Partitions: BIOS boot (for GRUB on BIOS machines), the EFI system
# partition, the root filesystem.
umount -R "$root" 2>/dev/null || true
wipefs -af "$disk"
parted -s "$disk" -- mklabel gpt \
  mkpart bios 1MiB 2MiB set 1 bios_grub on \
  mkpart ESP fat32 2MiB 1026MiB set 2 esp on \
  mkpart nixos 1026MiB 100%
udevadm settle
case "$disk" in *[0-9]) p="${disk}p" ;; *) p="$disk" ;; esac

mkfs.fat -F 32 -n BOOT "${p}2"
case "$fs" in
  ext4)
    mkfs.ext4 -F -L nixos "${p}3"
    mkdir -p "$root"
    mount "${p}3" "$root"
    ;;
  btrfs)
    mkfs.btrfs -f -L nixos "${p}3"
    mkdir -p "$root"
    mount "${p}3" "$root"
    btrfs subvolume create "$root/@"
    btrfs subvolume create "$root/@home"
    btrfs subvolume create "$root/@nix"
    umount "$root"
    mount -o subvol=@,compress=zstd "${p}3" "$root"
    mkdir -p "$root/home" "$root/nix"
    mount -o subvol=@home,compress=zstd "${p}3" "$root/home"
    mount -o subvol=@nix,compress=zstd,noatime "${p}3" "$root/nix"
    ;;
esac
mkdir -p "$root/boot"
mount -o umask=077 "${p}2" "$root/boot"

# Planarian's journal is preallocated so recovery never needs new space
# (SPEC §12c). On btrfs that holds only without copy-on-write, which files
# inherit from their directory when they are created.
mkdir -p "$root/var/lib/planarian"
chmod 700 "$root/var/lib/planarian"
[ "$fs" = btrfs ] && chattr +C "$root/var/lib/planarian"

nixos-generate-config --root "$root"
etc="$root/etc/nixos"
rm -f "$etc/configuration.nix"
mkdir -p "$etc/planarian"
install -m644 "$PLANARIAN_SEED/overrides.nix" "$etc/planarian/overrides.nix"
install -m644 "$PLANARIAN_SEED/flake.lock" "$etc/flake.lock"

if [ "$firmware" = uefi ]; then
  loader='boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;'
else
  dev=$disk
  for l in /dev/disk/by-id/*; do
    case "$l" in *-part*) continue ;; esac
    [ "$(readlink -f "$l")" = "$(readlink -f "$disk")" ] && { dev=$l; break; }
  done
  loader="boot.loader.grub = { enable = true; device = \"$dev\"; };"
fi

cat > "$etc/flake.nix" <<EOF
# This computer's configuration. You edit ./configuration.nix; Planarian
# changes only ./planarian/overrides.nix, and only through transactions.
{
  inputs = {
    nixpkgs.url = "$NIXPKGS_URL";
    planarian.url = "$PLANARIAN_URL";
    planarian.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, planarian, ... }: {
    nixosConfigurations.$host = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        ./planarian/overrides.nix
        planarian.nixosModules.default
        planarian.nixosModules.reference
        {
          services.planarian.enable = true;
          services.planarian.owner = "/etc/nixos";
          # The pinned sources stay on disk, so Planarian can rebuild this
          # configuration without a network.
          system.extraDependencies = [ nixpkgs.outPath planarian.outPath ];
        }
      ];
    };
  };
}
EOF

cat > "$etc/configuration.nix" <<EOF
# Yours to edit. Planarian never changes this file.
{ ... }:
{
  imports = [ ./hardware-configuration.nix ];

  $loader

  networking.hostName = "$host";
  time.timeZone = "$tz";

  users.users.$user = {
    isNormalUser = true;
    # planarian-admin: approves Planarian's changes, restarts system services.
    extraGroups = [ "wheel" "networkmanager" "planarian-admin" ];
    initialHashedPassword = "$hash";
  };

  nix.settings.experimental-features = [ "nix-command" "flakes" ];
  system.stateVersion = "26.05";
}
EOF

# A git flake sees only tracked files (Planarian checks that overrides.nix is).
git -C "$etc" init -q -b main
git -C "$etc" add -A
git -C "$etc" -c user.name=planarian-install -c user.email=root@localhost commit -qm "Installed by planarian-install"
set +x

if [ "$install" = 1 ]; then
  nixos-install --root "$root" --flake "$etc#$host" --no-root-passwd --no-channel-copy
  echo
  echo "Installed. Remove the USB drive and reboot."
  echo "For its first 10 minutes Planarian says \"no baseline yet\"; then this"
  echo "first boot becomes the known-good generation."
else
  echo "Prepared $root (--no-install): nixos-install --root $root --flake $etc#$host"
fi
