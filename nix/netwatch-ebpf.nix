# The eBPF half of netwatch (§12d "Which units"; crates/backends/netwatch):
# `src` is a no_std aya-ebpf crate, built for bpfel-unknown-none to
# $out/share/planarian/netwatch.bpf.o (core package, coreFiles; I2).
#
# Built with the pinned rustc (nixpkgs) and RUSTC_BOOTSTRAP=1 for
# -Z build-std=core, and nixpkgs' bpf-linker (coordinator, Nov 2;
# docs/pins.md): no second toolchain. bpf-linker must use rustc's LLVM:
# the build fails if their majors differ, rather than producing a broken
# object. -Z build-std resolves the standard library's own lockfile, so its
# crates are vendored next to the crate's.
{ lib, stdenv, rustPlatform, rustc, cargo, bpf-linker, lndir, src, name ? "netwatch" }:

let
  library = rustPlatform.rustLibSrc;
  vendorCrate = rustPlatform.importCargoLock { lockFile = "${src}/Cargo.lock"; };
  vendorStd = rustPlatform.importCargoLock { lockFile = "${library}/Cargo.lock"; };
  rustcLlvm = lib.versions.major (rustc.llvm.version or rustc.llvmPackages.llvm.version);
  linkerLlvm = lib.versions.major (lib.findFirst (d: lib.hasPrefix "llvm-" (d.name or "")) { version = "none"; } (bpf-linker.buildInputs ++ bpf-linker.nativeBuildInputs)).version;
in
assert lib.assertMsg (rustcLlvm == linkerLlvm)
  "netwatch-ebpf: rustc's LLVM (${rustcLlvm}) and bpf-linker's (${linkerLlvm}) differ; the eBPF object would be broken";
stdenv.mkDerivation {
  pname = "${name}-ebpf";
  version = "0";
  inherit src;
  nativeBuildInputs = [ rustc cargo bpf-linker lndir ];
  dontConfigure = true;
  buildPhase = ''
    runHook preBuild
    # A sysroot carrying the library sources, for -Z build-std.
    mkdir -p sysroot/lib/rustlib/src/rust
    for d in ${rustc.unwrapped or rustc}/lib/rustlib/*; do ln -s "$d" sysroot/lib/rustlib/; done
    ln -s ${library} sysroot/lib/rustlib/src/rust/library
    printf '#!${stdenv.shell}\nexec ${rustc}/bin/rustc --sysroot %s "$@"\n' "$PWD/sysroot" > rustc-sysroot
    chmod +x rustc-sysroot
    # One vendor directory for the crate's and the library's dependencies.
    mkdir vendor
    lndir -silent ${vendorCrate} vendor
    lndir -silent ${vendorStd} vendor
    mkdir -p .cargo
    cat > .cargo/config.toml <<CFG
    [source.crates-io]
    replace-with = "vendored"
    [source.vendored]
    directory = "$PWD/vendor"
    CFG
    export CARGO_HOME=$PWD/.cargo-home RUSTC=$PWD/rustc-sysroot RUSTC_BOOTSTRAP=1
    cargo build --offline --frozen --release --target bpfel-unknown-none -Z build-std=core
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    obj=$(find target/bpfel-unknown-none/release -maxdepth 1 -type f ! -name '*.d' | head -n1)
    install -Dm444 "$obj" $out/share/planarian/${name}.bpf.o
    runHook postInstall
  '';
  # An eBPF object: nothing to patch, and stripping would drop its BTF.
  dontFixup = true;
  meta.description = "The eBPF object of Planarian's netwatch";
}
