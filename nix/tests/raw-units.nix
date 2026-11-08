# B-23 (docs/raw-unit-classification.md): the network tools that exist only as
# unit files in `systemd.packages` are classified at build time, by the same
# rule as a declared unit, and their hold is in force in the merged unit tree.
# No VM: it evaluates a NixOS system and builds its raw-unit classification,
# its export and its unit tree.
#
#   1. Agreement matrix: every combination of the rule's inputs is declared as
#      a `systemd.services` entry and written as a raw unit file; the declared
#      classifier (nix/module.nix) and the raw one (crates/unitclass) must call
#      each pair the same. The inputs are exactly those `isNetworkToolUnchecked`
#      reads, each at values covering its classes:
#        user:      root (unset) | nobody | DynamicUser | %i | 00 | +0
#        bounding:  unset | "" | one network cap | one other cap | `~` of one
#                   network cap (the other still granted) | `~` of both
#        ambient:   none | a network cap | another cap
#        NoNewPrivileges: unset | yes
#        device:    none | DeviceAllow=/dev/net/tun | BindPaths=/dev/ppp
#      6 x 6 x 3 x 2 x 3 = 648 pairs. (Syntax is the crate's property tests'.)
#   2. The B-23 case: an undeclared raw unit is a network tool in the built
#      export and carries the hold and ordering drop-ins; a hardened one, a
#      masked one and an unparsable one are classified as they should be; the
#      export is read by the consumer's own parser.
#   3. The hold stays in force: a later drop-in or overrides.conf with an empty
#      OnFailure= or After= makes `verify-hold` (which fails the system build)
#      fail, and a clean tree passes.
#   4. The boundary: a nonzero exit or unparsable output is never "no tools".
{ pkgs, self, nixpkgs }:

let
  inherit (pkgs) lib;
  users = [
    { n = "root"; cfg = { }; text = ""; }
    { n = "nobody"; cfg = { User = "nobody"; }; text = "User=nobody\n"; }
    { n = "dyn"; cfg = { DynamicUser = true; }; text = "DynamicUser=yes\n"; }
    # A specifier (expanded at start: the instance may be root) and numeric
    # zeros in other spellings read as possibly root.
    { n = "spec"; cfg = { User = "%i"; }; text = "User=%i\n"; }
    { n = "zz"; cfg = { User = "00"; }; text = "User=00\n"; }
    { n = "plus0"; cfg = { User = "+0"; }; text = "User=+0\n"; }
  ];
  boundings = [
    { n = "bunset"; cfg = { }; text = ""; }
    { n = "bempty"; cfg = { CapabilityBoundingSet = ""; }; text = "CapabilityBoundingSet=\n"; }
    { n = "bnet"; cfg = { CapabilityBoundingSet = "CAP_NET_ADMIN"; }; text = "CapabilityBoundingSet=CAP_NET_ADMIN\n"; }
    { n = "bother"; cfg = { CapabilityBoundingSet = "CAP_CHOWN"; }; text = "CapabilityBoundingSet=CAP_CHOWN\n"; }
    { n = "binvone"; cfg = { CapabilityBoundingSet = "~CAP_NET_ADMIN"; }; text = "CapabilityBoundingSet=~CAP_NET_ADMIN\n"; }
    { n = "binvboth"; cfg = { CapabilityBoundingSet = "~CAP_NET_ADMIN CAP_NET_RAW"; }; text = "CapabilityBoundingSet=~CAP_NET_ADMIN CAP_NET_RAW\n"; }
  ];
  ambients = [
    { n = "anone"; cfg = { }; text = ""; }
    { n = "anet"; cfg = { AmbientCapabilities = "CAP_NET_RAW"; }; text = "AmbientCapabilities=CAP_NET_RAW\n"; }
    { n = "aother"; cfg = { AmbientCapabilities = "CAP_KILL"; }; text = "AmbientCapabilities=CAP_KILL\n"; }
  ];
  nnps = [
    { n = "nunset"; cfg = { }; text = ""; }
    { n = "nyes"; cfg = { NoNewPrivileges = true; }; text = "NoNewPrivileges=yes\n"; }
  ];
  devices = [
    { n = "dnone"; cfg = { }; text = ""; }
    { n = "dtun"; cfg = { DeviceAllow = "/dev/net/tun rw"; }; text = "DeviceAllow=/dev/net/tun rw\n"; }
    { n = "dppp"; cfg = { BindPaths = "/dev/ppp"; }; text = "BindPaths=/dev/ppp\n"; }
  ];
  combos = lib.concatMap (u: lib.concatMap (b: lib.concatMap (a: lib.concatMap (n: map (d: {
    name = lib.concatStringsSep "-" [ u.n b.n a.n n.n d.n ];
    serviceConfig = u.cfg // b.cfg // a.cfg // n.cfg // d.cfg;
    text = "[Service]\nExecStart=/bin/true\n" + u.text + b.text + a.text + n.text + d.text;
  }) devices) nnps) ambients) boundings) users;

  matrixPkg = pkgs.runCommand "raw-matrix" { } (''
    mkdir -p $out/lib/systemd/system
  '' + lib.concatMapStrings (c: ''
    printf '%s' ${lib.escapeShellArg c.text} > $out/lib/systemd/system/r-${c.name}.service
  '') combos);

  # The B-23 fixtures.
  hard = "[Service]\nExecStart=/bin/true\nUser=nobody\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n";
  fixturePkg = pkgs.runCommand "b23-fixtures" { } ''
    d=$out/lib/systemd/system
    mkdir -p $d $d/b23-dropin.service.d
    printf '[Service]\nExecStart=/bin/true\n' > $d/b23-raw.service
    printf '%s' ${lib.escapeShellArg hard} > $d/b23-hard.service
    printf '[Service\nUser=nobody\n' > $d/b23-bad.service
    ln -s /dev/null $d/b23-masked.service
    printf '%s' ${lib.escapeShellArg hard} > $d/b23-dropin.service
  '';
  # A second package adds a drop-in that grants a network capability.
  dropinPkg = pkgs.runCommand "b23-dropin" { } ''
    d=$out/lib/systemd/system/b23-dropin.service.d
    mkdir -p $d
    printf '[Service]\nAmbientCapabilities=CAP_NET_ADMIN\n' > $d/10-grant.conf
  '';

  sys = nixpkgs.lib.nixosSystem {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      self.nixosModules.default
      ({ lib, ... }: {
        networking.hostName = "planarian-raw-units";
        system.stateVersion = "26.05";
        boot.loader.grub.enable = false;
        fileSystems."/" = { device = "/dev/vda"; fsType = "ext4"; };
        services.planarian.enable = true;
        systemd.packages = [ matrixPkg fixturePkg dropinPkg ];
        systemd.services = builtins.listToAttrs (map (c: {
          name = "m-${c.name}";
          value = { script = "true"; serviceConfig = c.serviceConfig; };
        }) combos) // {
          # The declared template plus instance shape: NixOS writes overrides.conf
          # for the instance, and the template carries the hold's drop-in too
          # (the reviewer's reproduction of the drop-in precedence bug).
          "gym-tpl@" = { script = "true"; };
          "gym-tpl@a" = { overrideStrategy = "asDropin"; serviceConfig.Environment = "X=1"; };
        };
      })
    ];
  };
  cfg = sys.config;
  declared = cfg.services.planarian.holdUnits;
  # The declared classifier's verdict on each pair, as the raw names it wants.
  want = lib.filter (n: n != null) (map (c: if builtins.elem "m-${c.name}" declared then "r-${c.name}" else null) combos);
  unitclass = "${cfg.services.planarian.package}/bin/planarian-unitclass";
  rawUnits = cfg.services.planarian.rawUnits;
  exportFile = cfg.environment.etc."planarian/export.json".source;
  units = cfg.environment.etc."systemd/system".source;
in
pkgs.runCommand "planarian-raw-units-check" {
  nativeBuildInputs = [ pkgs.jq pkgs.coreutils pkgs.diffutils ];
  wantJson = builtins.toJSON (lib.sort (a: b: a < b) want);
  passAsFile = [ "wantJson" ];
} ''
  set -eu
  raw=${rawUnits}/share/planarian/raw-network-tools.json

  # 1. Agreement matrix: both classifiers, every pair.
  jq -S 'map(select(startswith("r-")))' "$raw" > got-matrix
  jq -S . "$wantJsonPath" > want-matrix
  diff want-matrix got-matrix || { echo "raw-units: the declared and the raw classifier disagree (above: declared wants, raw says)" >&2; exit 1; }
  echo "ok: the declared and raw classifiers agree on all ${toString (builtins.length combos)} pairs ($(jq length want-matrix) tools)"
  [ "$(jq length want-matrix)" -gt 0 ] && [ "$(jq length want-matrix)" -lt ${toString (builtins.length combos)} ]

  # 2. The B-23 case.
  has() { jq -e --arg n "$2" 'index($n) != null' "$1" > /dev/null; }
  has "$raw" b23-raw
  has "$raw" b23-bad
  has "$raw" b23-dropin
  ! has "$raw" b23-hard
  ! has "$raw" b23-masked
  echo "ok: an undeclared raw unit, an unparsable one and one a second package's drop-in grants are tools; a hardened and a masked one are not"
  export=${exportFile}
  jq -e '.networkTools | index("b23-raw") != null and index("b23-bad") != null and index("b23-dropin") != null and index("b23-hard") == null' "$export" > /dev/null
  jq -e '.networkTools == (.networkTools | unique)' "$export" > /dev/null
  ${cfg.services.planarian.package}/bin/planariad --check-export "$export" > /dev/null
  echo "ok: the built export lists them and planariad reads the merged file"
  for u in b23-raw b23-bad b23-dropin; do
    grep -qx 'OnFailure=planarian-hold@%N.service' ${units}/$u.service.d/50-planarian-hold.conf
  done
  [ ! -e ${units}/b23-hard.service.d/50-planarian-hold.conf ]
  echo "ok: the raw tools carry the hold drop-in in the unit tree and the hardened one does not"
  ${unitclass} check "$raw"

  # 3. The hold stays in force.
  tools=$TMPDIR/tools
  { printf '%s\n' ${lib.escapeShellArgs declared} gym-tpl@a; jq -r '.[]' "$raw"; } > "$tools"
  ${unitclass} verify-hold --units ${units} --tools "$tools" ${lib.optionalString (cfg.services.planarian.package.netwatch or false) "--netwatch"}
  echo "ok: verify-hold passes on the built tree"
  strip() {
    rm -rf "$TMPDIR/tree"; cp -r --no-dereference ${units} "$TMPDIR/tree"; chmod -R u+w "$TMPDIR/tree"
    mkdir -p "$TMPDIR/tree/$1.service.d"
    printf '%s' "$2" > "$TMPDIR/tree/$1.service.d/$3"
    if ${unitclass} verify-hold --units "$TMPDIR/tree" --tools "$tools" ${lib.optionalString (cfg.services.planarian.package.netwatch or false) "--netwatch"} 2> err; then
      echo "raw-units: verify-hold passed with $3 stripping $2 from $1" >&2; exit 1
    fi
    grep -q "$1" err
  }
  strip b23-raw '[Unit]
OnFailure=
' 90-strip.conf
  strip b23-dropin '[Unit]
OnFailure=
' overrides.conf
  strip m-root-bunset-anone-nunset-dnone '[Unit]
OnFailure=
' overrides.conf
  ${lib.optionalString (cfg.services.planarian.package.netwatch or false) ''
  strip b23-raw '[Unit]
After=
' 90-strip.conf
  ''}
  echo "ok: an empty OnFailure= (and After=) in a later drop-in or overrides.conf, on a raw or a declared tool, fails verify-hold"

  # 4. The boundary: bad output or a bad read is never "no tools".
  printf 'not json' > bad.json
  if ${unitclass} check bad.json 2> /dev/null; then echo "raw-units: check accepted unparsable output" >&2; exit 1; fi
  printf '["b","a"]' > unsorted.json
  if ${unitclass} check unsorted.json 2> /dev/null; then echo "raw-units: check accepted an unsorted list" >&2; exit 1; fi
  if ${unitclass} check /nonexistent 2> /dev/null; then echo "raw-units: check accepted a missing file" >&2; exit 1; fi
  if ${unitclass} verify-hold --units ${units} --tools /nonexistent 2> /dev/null; then echo "raw-units: verify-hold accepted a missing tools file" >&2; exit 1; fi
  echo "ok: unparsable or unreadable input is a nonzero exit, never an empty list"
  echo ok > $out
''
