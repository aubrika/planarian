# A NixOS VM test of generation changes on real NixOS: a cataloged change is
# staged, evaluated, built, activated, checked and committed (boot entry
# published, override promoted); a bad one is activated, fails its checks and
# is reverted.
#
# The owner's flake is a shim. Building a NixOS system inside the VM would
# need every build input offline, so the candidate systems are built
# beforehand as this VM's own specialisations (its modules plus the change)
# and the shim picks one by what `planarian/overrides.nix` says. Everything
# Planarian does is real: staging, `nix eval` of the export, `nix build`,
# dry-activate, activation through switch-to-configuration, the probes,
# publishing to the system profile, promoting the override, reverting. What
# this does not cover is evaluating a real owner flake.
{ pkgs, self }:

pkgs.testers.runNixOSTest (
  { config, ... }:
  let
    m = config.nodes.machine;
    variant = name: m.specialisation.${name}.configuration;
    facts = c: {
      services = {
        planarian.export = c.services.planarian.export;
        gym-extra.enable = c.services.gym-extra.enable;
        gym-web.listenAddress = c.services.gym-web.listenAddress;
      };
    };
    exports = pkgs.writeText "exports.json" (
      builtins.toJSON {
        base = facts m;
        good = facts (variant "good");
        bad = facts (variant "bad");
      }
    );
    shim = pkgs.writeText "flake.nix" ''
      # The owner flake, as a shim (see nix/tests/vm-generations.nix).
      {
        outputs = { self }:
          let
            text = builtins.readFile ./planarian/overrides.nix;
            has = re: builtins.length (builtins.split re text) > 1;
            pick =
              if has "192[.]0[.]2[.]10" then "bad"
              else if has "gym-extra\"?[.]enable = lib[.]mkOverride 90 true" then "good"
              else "base";
            all = builtins.fromJSON (builtins.readFile ./exports.json);
            systems = { base = ./sys-base; good = ./sys-good; bad = ./sys-bad; };
          in {
            nixosConfigurations.machine = {
              config = all.''${pick} // { system.build.toplevel = systems.''${pick}; };
              options = { };
            };
          };
      }
    '';
    base = m.system.build.toplevel;
    good = (variant "good").system.build.toplevel;
    bad = (variant "bad").system.build.toplevel;
  in
  {
    name = "planarian-generations";

    nodes.machine =
      { config, lib, pkgs, ... }:
      {
        imports = [ self.nixosModules.default ];

        options.services.gym-web.listenAddress = lib.mkOption {
          type = lib.types.str;
          default = "127.0.0.1";
        };
        options.services.gym-extra.enable = lib.mkEnableOption "the gym-extra fixture service";

        config = {
          services.planarian = {
            enable = true;
            owner = "/etc/nixos";
            flakeAttr = "nixosConfigurations.machine";
            catalog.services.gym-extra = "services.gym-extra.enable";
            catalog.listenAddresses.gym-web = {
              option = "services.gym-web.listenAddress";
              permitted = [ "127.0.0.1" "192.0.2.10" ];
            };
            units.gym-web.probes = [
              { id = "gym-web-http"; type = "http"; url = "http://127.0.0.1:8080/hostname"; establishes = "gym-web serves HTTP"; }
            ];
          };

          systemd.services.gym-web = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8080 --bind ${config.services.gym-web.listenAddress} --directory /etc";
          };
          systemd.services.gym-extra = lib.mkIf config.services.gym-extra.enable {
            wantedBy = [ "multi-user.target" ];
            serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          };

          # The candidates: this system plus each change.
          specialisation.good.configuration.services.gym-extra.enable = true;
          specialisation.bad.configuration = {
            services.gym-extra.enable = true;
            services.gym-web.listenAddress = "192.0.2.10";
          };

          environment.systemPackages = [ pkgs.util-linux pkgs.curl ];
          virtualisation.diskSize = 8192;
          virtualisation.memorySize = 2048;
        };
      };

    testScript = ''
      machine.wait_for_unit("planariad.service")
      machine.wait_until_succeeds("planarian status | grep -E 'ok +service:gym-web'", timeout=900)

      machine.succeed(
          "mkdir -p /etc/nixos/planarian",
          "install -m644 ${shim} /etc/nixos/flake.nix",
          "install -m644 ${exports} /etc/nixos/exports.json",
          "install -m644 ${../template/planarian/overrides.nix} /etc/nixos/planarian/overrides.nix",
          "ln -s ${base} /etc/nixos/sys-base",
          "ln -s ${good} /etc/nixos/sys-good",
          "ln -s ${bad} /etc/nixos/sys-bad",
      )

      with subtest("the running generation becomes the baseline"):
          # mark-good wants an interactive terminal; script(1) gives it one.
          print(machine.succeed("script -qec 'planarian mark-good' /dev/null 2>&1"))
          machine.wait_until_succeeds("planarian status | grep -E 'known-good [0-9]+'", timeout=300)

      with subtest("a cataloged change is built, activated, checked and committed"):
          print(machine.succeed("planarian apply service-enable service=gym-extra enabled=true 2>&1 || true"))
          machine.wait_until_succeeds("systemctl is-active gym-extra.service", timeout=1800)
          machine.wait_until_succeeds("test \"$(readlink -f /nix/var/nix/profiles/system)\" = ${good}", timeout=1800)
          machine.succeed("test \"$(readlink -f /run/current-system)\" = ${good}")
          machine.succeed("grep -q 'gym-extra' /etc/nixos/planarian/overrides.nix")
          print(machine.succeed("planarian log -n 40"))

      with subtest("a change that breaks a service is reverted"):
          print(machine.succeed("planarian apply listen-address service=gym-web addr=192.0.2.10 2>&1 || true"))
          machine.wait_until_succeeds("planarian log -n 80 | grep -q Reverted", timeout=1800)
          print(machine.succeed("planarian log -n 40"))
          machine.succeed("test \"$(readlink -f /run/current-system)\" = ${good}")
          machine.succeed("test \"$(readlink -f /nix/var/nix/profiles/system)\" = ${good}")
          machine.fail("grep -q 192.0.2.10 /etc/nixos/planarian/overrides.nix")
          machine.wait_until_succeeds("curl -sf http://127.0.0.1:8080/hostname", timeout=600)
          machine.succeed("systemctl is-active gym-extra.service")
    '';
  }
)
