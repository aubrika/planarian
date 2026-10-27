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
      ../template/planarian/overrides.nix
    ];
  };

  cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ../../Cargo.lock; };
  nativeBuildInputs = [ verus verus.toolchain pkgs.rustPlatform.cargoSetupHook ];

  buildPhase = ''
    runHook preBuild
    export HOME=$TMPDIR
    cargo-verus verify -p planarian-policy -p planarian-txn --offline 2>&1 | tee verus.log
    status=''${PIPESTATUS[0]}
    if [ "$status" -ne 0 ] || grep -q "verification results:: .* [1-9][0-9]* errors" verus.log; then
      echo "Verus failed (exit $status)"; exit 1
    fi
    runHook postBuild
  '';

  installPhase = ''
    grep "verification results" verus.log > $out
  '';
}
