# The read-only visual console (§16a), packaged apart from the daemon so a
# server's closure carries no GUI libraries. Software rendering (tiny-skia):
# no GPU stack. winit loads X11 or Wayland libraries at run time.
{ lib, rustPlatform, makeWrapper, libxkbcommon, wayland, libx11, libxcursor, libxrandr, libxi, libxcb }:

rustPlatform.buildRustPackage {
  pname = "planarian-console";
  version = "0.0.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      ../share
      ../nix/template/planarian/overrides.nix
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [ "-p" "planarian-console" ];
  # The workspace's tests run in the main package.
  doCheck = false;

  nativeBuildInputs = [ makeWrapper ];
  postInstall = ''
    wrapProgram $out/bin/planarian-console \
      --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath [ libxkbcommon wayland libx11 libxcursor libxrandr libxi libxcb ]}
  '';

  meta = {
    description = "Planarian's read-only visual console";
    license = lib.licenses.mpl20;
    mainProgram = "planarian-console";
    platforms = lib.platforms.linux;
  };
}
