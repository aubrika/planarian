# Verus and the Rust toolchain it is built against, for the `verus` flake
# check (docs/verification.md). x86_64-linux only: Verus publishes binaries
# for it, and nixpkgs does not package Verus.
#
# Verus's driver links the compiler's own libraries (`rustc-dev`) of exactly
# the toolchain it names, 1.99.1, newer than nixpkgs 26.05's 1.95; so the
# toolchain is fetched from the official distribution, pinned by the hashes
# in its channel manifest (https://static.rust-lang.org/dist/channel-rust-1.99.1.toml).
{ lib, stdenv, fetchurl, fetchzip, autoPatchelfHook, makeWrapper, zlib }:

let
  rustVersion = "1.99.1";
  rustDate = "2026-10-15";
  target = "x86_64-unknown-linux-gnu";
  component = name: hash: fetchurl {
    url = "https://static.rust-lang.org/dist/${rustDate}/${name}-${rustVersion}-${target}.tar.xz";
    sha256 = hash;
  };
  components = [
    (component "rustc" "2ff05ff9c08a90861e7f6e4065b40a8b87463b4576186fd613871c3e37f2091f")
    (component "rust-std" "109b074225bf5b9ea3820890876bfdf4ed161adbfaf94b2b4b5984c85ee5d958")
    (component "cargo" "53f3521949404d595efb06a55c12c5658d4ed1c75566f33d3d514eaebe70bd8a")
    (component "rustc-dev" "e2b1c9ffe50910d5274339b52774eec05433682835219566449cd09c67c1d1d2")
  ];

  toolchain = stdenv.mkDerivation {
    pname = "rust-toolchain-for-verus";
    version = rustVersion;
    srcs = components;
    sourceRoot = ".";
    nativeBuildInputs = [ autoPatchelfHook ];
    buildInputs = [ stdenv.cc.cc.lib zlib ];
    dontConfigure = true;
    dontBuild = true;
    installPhase = ''
      runHook preInstall
      for d in */; do
        bash "$d/install.sh" --prefix="$out" --disable-ldconfig --without=rust-docs
      done
      rm -f "$out/lib/rustlib/install.log" "$out/lib/rustlib/uninstall.sh"
      runHook postInstall
    '';
    # rustc invokes the system linker through `cc`.
    meta.platforms = [ "x86_64-linux" ];
  };

  verusVersion = "0.2026.10.26.d17fbd0";
in
stdenv.mkDerivation {
  pname = "verus";
  version = verusVersion;

  src = fetchzip {
    url = "https://github.com/verus-lang/verus/releases/download/release/${verusVersion}/verus-${verusVersion}-x86-linux.zip";
    hash = "sha256-u5DxhWAIBdNgpK+oRHQh8MvC3s4OokbcpaUL4pqcDtk=";
  };

  nativeBuildInputs = [ autoPatchelfHook makeWrapper ];
  buildInputs = [ toolchain stdenv.cc.cc.lib zlib ];

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib/verus $out/bin
    for f in verus rust_verify cargo-verus z3 version.json vstd.vir \
             libverus_builtin.rlib libverus_builtin_macros.so \
             libverus_state_machines_macros.so libvstd.rlib; do
      cp "$f" $out/lib/verus/
    done
    for b in verus cargo-verus; do
      makeWrapper $out/lib/verus/$b $out/bin/$b \
        --set VERUS_USE_RUSTUP 0 \
        --set VERUS_Z3_PATH $out/lib/verus/z3 \
        --prefix PATH : ${lib.makeBinPath [ toolchain stdenv.cc ]}:$out/bin
    done
    runHook postInstall
  '';

  passthru = { inherit toolchain; };

  meta = {
    description = "Verus, a verifier for Rust, from its published release";
    homepage = "https://github.com/verus-lang/verus";
    license = lib.licenses.mit;
    platforms = [ "x86_64-linux" ];
  };
}
