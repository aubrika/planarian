# `gymHooks`: the gym's VM harness build (fault injection and the gym binary;
# nix/tests/gym-vm.nix). Never the shipped package.
{ lib, rustPlatform, nix, callPackage, gymHooks ? false }:

let
  # §12d: netwatch's eBPF object (nix/netwatch-ebpf.nix), once its crate
  # exists. It is its own cargo workspace, outside this one's (no_std,
  # bpfel-unknown-none, RUSTC_BOOTSTRAP for -Z build-std).
  # The loader (crates/backends/netwatch, `planarian-netwatch`), in this
  # workspace, once it exists.
  netwatchLoader = builtins.pathExists ../crates/backends/netwatch/Cargo.toml;
  netwatchCrate = ../crates/backends/netwatch-ebpf;
  # The programs the loader attaches (lane-change-path's contract).
  netwatchSections = [
    "fentry/rtnetlink_rcv_msg"
    "kprobe/nfnetlink_rcv_msg"
    "kprobe/nfnetlink_rcv_batch"
    "fentry/nf_setsockopt"
    "fentry/genl_rcv_msg"
    "fentry/register_netdevice"
  ];
  netwatchEbpf =
    if builtins.pathExists (netwatchCrate + "/Cargo.toml")
    then callPackage ./netwatch-ebpf.nix { sections = netwatchSections; src = lib.fileset.toSource { root = netwatchCrate; fileset = lib.fileset.difference netwatchCrate (lib.fileset.maybeMissing (netwatchCrate + "/target")); }; }
    else null;
in
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
      ../assets/identity/marks/planarian-mark-micro-currentcolor.svg
      ../nix/template/planarian/overrides.nix
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # Install the daemon, the watchdog and the CLI; the gym is a developer tool.
  cargoBuildFlags = [ "-p" "planarian-daemon" "-p" "planarian-watchdog" "-p" "planarian-cli" ]
    ++ lib.optionals netwatchLoader [ "-p" "planarian-backend-netwatch" ]
    ++ lib.optionals gymHooks [ "-p" "planarian-gym" ];
  buildFeatures = lib.optionals gymHooks [ "planarian-daemon/gym-hooks" ]
    ++ lib.optionals netwatchLoader [ "planarian-backend-netwatch/loader" ];
  # …but run every crate's tests (in the shipped package).
  cargoTestFlags = [ "--workspace" ];
  doCheck = !gymHooks;

  # The staging test hashes a directory with nix-hash, as the real backend does.
  nativeCheckInputs = [ nix ];

  postInstall = ''
    install -Dm644 share/canonical.json $out/share/planarian/canonical.json
    ln -s planarian $out/bin/ask
  '' + lib.optionalString (netwatchEbpf != null) ''
    # Read at runtime next to the running binary, never from the
    # generation, like canonical.json (I10); hashed in coreFiles (I2).
    install -Dm444 ${netwatchEbpf}/share/planarian/netwatch.bpf.o $out/share/planarian/netwatch.bpf.o
  '';

  # §12d, §15 (B-13): the module refuses a test build outside the gym.
  passthru.testBuild = gymHooks;
  # Whether the package carries netwatch: its loader and its eBPF object
  # (the module runs planarian-netwatch; coreFiles hashes both).
  passthru.netwatch = netwatchEbpf != null && netwatchLoader;

  meta = {
    description = "A self-healing layer for declaratively configured computers";
    license = lib.licenses.mpl20;
    mainProgram = "planarian";
    platforms = lib.platforms.linux;
  };
}
