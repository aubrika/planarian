# The gym's Firecracker microVM target (SPEC §4 Phase A, non-gating: allowed
# to stay red). A NixOS system with Planarian, packaged for Firecracker: an
# uncompressed vmlinux, the NixOS initrd (virtio-mmio, which is how
# Firecracker attaches its disk), and an ext4 root filesystem. In the guest,
# `fc-gym` waits for planarian-ready.target, crashes a watched service, waits
# for Planarian to repair it, prints `FC-GYM PASS` or `FC-GYM FAIL: …` on the
# serial console and powers off.
#
#   nix build .#firecracker-target && result/bin/run-firecracker-target
{ nixpkgs, self, system }:

let
  pkgs = nixpkgs.legacyPackages.${system};
  guest = nixpkgs.lib.nixosSystem {
    modules = [
      self.nixosModules.default
      ({ config, lib, pkgs, modulesPath, ... }: {
        nixpkgs.hostPlatform = system;
        imports = [ (modulesPath + "/profiles/minimal.nix") ];
        boot.loader.grub.enable = false;
        boot.initrd.availableKernelModules = [ "virtio_mmio" "virtio_blk" "virtio_net" "ext4" ];
        boot.kernelParams = [ "console=ttyS0" "reboot=k" "panic=1" ];
        fileSystems."/" = { device = "/dev/vda"; fsType = "ext4"; };
        networking.hostName = "planarian-fc";
        networking.useDHCP = false;
        documentation.enable = false;
        system.stateVersion = "26.05";

        services.planarian.enable = true;
        services.planarian.bootReadyTimeout = 300;
        services.planarian.units.fc-web = { };
        systemd.services.fc-web = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
        };

        systemd.services.fc-gym = {
          wantedBy = [ "multi-user.target" ];
          after = [ "planarian-ready.target" "fc-web.service" ];
          path = [ config.systemd.package pkgs.coreutils pkgs.gnugrep config.services.planarian.package ];
          serviceConfig = { Type = "oneshot"; StandardOutput = "journal+console"; };
          script = ''
            set -u
            say() { echo "FC-GYM $*" > /dev/console; echo "FC-GYM $*"; }
            for _ in $(seq 120); do systemctl is-active --quiet planarian-ready.target && break; sleep 2; done
            if ! systemctl is-active --quiet planarian-ready.target; then
              say "FAIL: planarian-ready.target not reached"; systemctl poweroff; exit 0
            fi
            for _ in $(seq 120); do planarian status 2>/dev/null | grep -Eq 'ok +service:fc-web' && break; sleep 2; done
            systemctl kill --signal=SIGSEGV fc-web.service
            for _ in $(seq 150); do
              if planarian log -n 200 2>/dev/null | grep -q 'restart service:fc-web' && systemctl is-active --quiet fc-web.service; then
                say "PASS"; systemctl poweroff; exit 0
              fi
              sleep 2
            done
            say "FAIL: fc-web was not repaired"; planarian status > /dev/console 2>&1 || true
            systemctl poweroff
          '';
        };
      })
    ];
  };
  cfg = guest.config;
  rootfs = pkgs.callPackage (nixpkgs + "/nixos/lib/make-ext4-fs.nix") {
    storePaths = [ cfg.system.build.toplevel ];
    volumeLabel = "planarian-fc";
    populateImageCommands = ''
      mkdir -p ./files/sbin ./files/etc
      ln -s ${cfg.system.build.toplevel}/init ./files/sbin/init
      touch ./files/etc/NIXOS
    '';
  };
  vmConfig = pkgs.writeText "firecracker.json" (builtins.toJSON {
    boot-source = {
      kernel_image_path = "${cfg.boot.kernelPackages.kernel.dev}/vmlinux";
      initrd_path = "${cfg.system.build.initialRamdisk}/${cfg.system.boot.loader.initrdFile}";
      boot_args = "${toString cfg.boot.kernelParams} init=${cfg.system.build.toplevel}/init root=/dev/vda rw";
    };
    drives = [ { drive_id = "root"; path_on_host = "ROOTFS"; is_root_device = false; is_read_only = false; } ];
    machine-config = { vcpu_count = 2; mem_size_mib = 1536; };
  });
in
pkgs.runCommand "planarian-firecracker-target" { } ''
  mkdir -p $out/bin
  ln -s ${rootfs} $out/rootfs.img
  cp ${vmConfig} $out/firecracker.json
  cat > $out/bin/run-firecracker-target <<EOF
  #!${pkgs.runtimeShell}
  # Boot the target on a writable copy of the root filesystem; exit 0 on
  # FC-GYM PASS, 1 otherwise (a hang is cut off after 20 minutes).
  set -u
  work=\$(mktemp -d)
  cp --sparse=always ${rootfs} \$work/rootfs.img && chmod u+w \$work/rootfs.img
  sed "s#ROOTFS#\$work/rootfs.img#" ${vmConfig} > \$work/vm.json
  ${pkgs.coreutils}/bin/timeout 1200 ${pkgs.firecracker}/bin/firecracker --no-api --config-file \$work/vm.json 2>&1 | tee \$work/console.log
  grep -q 'FC-GYM PASS' \$work/console.log
  EOF
  chmod +x $out/bin/run-firecracker-target
''
