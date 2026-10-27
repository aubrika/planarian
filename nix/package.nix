# `gymHooks`: the gym's VM harness build (fault injection and the gym binary;
# nix/tests/gym-vm.nix). Never the shipped package.
{ lib, rustPlatform, nix, gymHooks ? false }:

rustPlatform.buildRustPackage {
  pname = if gymHooks then "planarian-gym-hooks" else "planarian";
  version = "0.0.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      ../share
      ../assets/identity/animations/keyframes.json
      ../nix/template/planarian/overrides.nix
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # Install the daemon, the watchdog and the CLI; the gym is a developer tool.
  cargoBuildFlags = [ "-p" "planarian-daemon" "-p" "planarian-watchdog" "-p" "planarian-cli" ]
    ++ lib.optionals gymHooks [ "-p" "planarian-gym" ];
  buildFeatures = lib.optionals gymHooks [ "planarian-daemon/gym-hooks" ];
  # …but run every crate's tests (in the shipped package).
  cargoTestFlags = [ "--workspace" ];
  doCheck = !gymHooks;

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
