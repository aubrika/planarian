{ lib, rustPlatform, nix }:

rustPlatform.buildRustPackage {
  pname = "planarian";
  version = "0.0.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      ../share
      ../assets/identity/animations/keyframes.json
      ../assets/identity/marks/planarian-mark-micro-currentcolor.svg
      ../nix/template/planarian/overrides.nix
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # Install the daemon, the watchdog and the CLI; the gym is a developer tool.
  cargoBuildFlags = [ "-p" "planarian-daemon" "-p" "planarian-watchdog" "-p" "planarian-cli" ];
  # …but run every crate's tests.
  cargoTestFlags = [ "--workspace" ];

  # The staging test hashes a directory with nix-hash, as the real backend does.
  nativeCheckInputs = [ nix ];

  postInstall = ''
    install -Dm644 share/canonical.json $out/share/planarian/canonical.json
    ln -s planarian $out/bin/ask
  '';

  meta = {
    description = "A self-healing layer for declaratively configured computers";
    license = lib.licenses.mpl20;
    mainProgram = "planarian";
    platforms = lib.platforms.linux;
  };
}
