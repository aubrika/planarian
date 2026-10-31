#!/usr/bin/env bash
# `nix run .#gym-vm -- [ID ...]`: build and validate every requested VM case.
set -euo pipefail
flake=${GYM_FLAKE:-.}
catalog=${GYM_CATALOG:-crates/gym/catalog/phase-a.toml}
acceptance=${GYM_ACCEPTANCE:-nix/gym/acceptance.py}
waivers=${GYM_WAIVERS:-docs/acceptance-waivers.toml}
out=${GYM_RESULTS_DIR:-$(mktemp -d)}
mkdir -p "$out"
# Never leave a previous success report behind when a fresh run is interrupted.
rm -f "$out/acceptance.json"
sys=$(nix eval --raw --impure --expr builtins.currentSystem)
selection=()
for id in "$@"; do selection+=(--id "$id"); done
# A failed selector/evaluation must not become an empty successful run.
requested=$(python3 "$acceptance" ids --catalog "$catalog" --harness vm "${selection[@]}")
mapfile -t ids <<< "$requested"
features="nixos-test benchmark big-parallel uid-range kvm"
echo "running ${#ids[@]} entries on the VM harness; results in $out"
attrs=()
for id in "${ids[@]}"; do
  attrs+=("$flake#legacyPackages.$sys.gym-vm.$id")
  rm -f "$out/$id.json"
done
build_failed=0
if ! nix build --no-link --keep-going --option system-features "$features" "${attrs[@]}"; then
  build_failed=1
fi
verdicts=()
for id in "${ids[@]}"; do
  verdict="$out/$id.json"
  # A failed build remains a failure even if a retry obtains a verdict from
  # a previously built output.
  if p=$(nix build --no-link --print-out-paths --option system-features "$features" "$flake#legacyPackages.$sys.gym-vm.$id"); then
    if [ -f "$p/verdict.json" ]; then cp "$p/verdict.json" "$verdict"; fi
  else
    build_failed=1
  fi
  verdicts+=("$verdict")
done
verdict_failed=0
if ! python3 "$acceptance" check --catalog "$catalog" --harness vm --waivers "$waivers" \
  --report "$out/acceptance.json" "${selection[@]}" "${verdicts[@]}"; then
  verdict_failed=1
fi
if [ "$build_failed" -ne 0 ] || [ "$verdict_failed" -ne 0 ]; then exit 1; fi
