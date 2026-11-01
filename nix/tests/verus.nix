# Runs the Verus proofs (docs/verification.md): `decide` is verified and the
# policy lemmas proved, along with the `schema` code they rely on. Fails if
# any obligation fails.
{ pkgs }:

let
  verus = pkgs.callPackage ../verus.nix { };
in
pkgs.stdenv.mkDerivation {
  name = "planarian-verus";

  src = pkgs.lib.fileset.toSource {
    root = ../..;
    fileset = pkgs.lib.fileset.unions [
      ../../Cargo.toml
      ../../Cargo.lock
      ../../crates
      ../../share
      ../../docs/verification-ratio.toml
      ../template/planarian/overrides.nix
    ];
  };

  cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ../../Cargo.lock; };
  nativeBuildInputs = [ verus verus.toolchain pkgs.rustPlatform.cargoSetupHook ];

  buildPhase = ''
    runHook preBuild
    export HOME=$TMPDIR
    cargo-verus verify -p planarian-schema -p planarian-policy -p planarian-txn --offline 2>&1 | tee verus.log
    status=''${PIPESTATUS[0]}
    if [ "$status" -ne 0 ] || grep -q "verification results:: .* [1-9][0-9]* errors" verus.log; then
      echo "Verus failed (exit $status)"; exit 1
    fi
    # R14: the accounting's [verifier] counts are this run's ("N verified").
    want=$(awk '/^\[verifier\]/{f=1;next} /^\[/{f=0} f && /=/{print $3}' docs/verification-ratio.toml | sort -n | paste -sd' ')
    # Only Planarian's crates: in the sandbox vstd is verified too, and
    # cargo names the crate ("Checking <crate> v…") before its results.
    got=$(awk '/(Checking|Compiling|Fresh) [A-Za-z0-9_-]+ v/ {for (i = 1; i < NF; i++) if ($i ~ /^(Checking|Compiling|Fresh)$/) c = $(i + 1)}
               /verification results:: [0-9]+ verified/ && c ~ /^planarian-/ {for (i = 1; i <= NF; i++) if ($i == "verified,") print $(i - 1)}' verus.log | sort -n | paste -sd' ')
    if [ "$want" != "$got" ]; then
      echo "Verus verified ($got) but docs/verification-ratio.toml [verifier] records ($want)"; exit 1
    fi
    runHook postBuild
  '';

  installPhase = ''
    grep "verification results" verus.log > $out
  '';
}
