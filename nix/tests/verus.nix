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
      ../../assets/identity/animations/keyframes.json
      ../../assets/identity/marks/planarian-mark-micro-currentcolor.svg
      ../../rust-toolchain.toml
      ../../docs/assumptions.md
      ../../docs/verification-ratio.toml
      ../../docs/proof-obligations.toml
      ../gym/proofs.py
      ../template/planarian/overrides.nix
    ];
  };

  cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ../../Cargo.lock; };
  nativeBuildInputs = [ verus verus.toolchain pkgs.python3 pkgs.rustPlatform.cargoSetupHook ];

  buildPhase = ''
    runHook preBuild
    export HOME=$TMPDIR
    python3 nix/gym/proofs.py run --engine verus --output proof-results/verus.json
    runHook postBuild
  '';

  installPhase = ''
    mkdir -p $out
    cp proof-results/verus.json proof-results/verus.log $out/
  '';
}
