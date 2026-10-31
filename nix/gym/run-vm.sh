#!/usr/bin/env bash
# `nix run .#gym-vm -- [ID ...]`: run catalog entries on the VM harness
# (nix/tests/gym-vm.nix), then score them with the fake harness's results
# for the entries that only run there. No IDs: every VM-capable entry.
set -euo pipefail
flake=${GYM_FLAKE:-.}
sys=$(nix eval --raw --impure --expr builtins.currentSystem)
ids=("$@")
if [ ${#ids[@]} -eq 0 ]; then
  mapfile -t ids < <(nix eval --json "$flake#legacyPackages.$sys.gym-vm" --apply builtins.attrNames | jq -r '.[]')
fi
features="nixos-test benchmark big-parallel uid-range kvm"
out=$(mktemp -d)
echo "running ${#ids[@]} entr(y|ies) on the VM harness; results in $out"
attrs=()
for id in "${ids[@]}"; do attrs+=("$flake#legacyPackages.$sys.gym-vm.$id"); done
# Build them all (Nix runs as many in parallel as --max-jobs allows); a test
# that fails to run leaves no verdict and counts as an error.
nix build --no-link --keep-going --option system-features "$features" "${attrs[@]}" || true
for id in "${ids[@]}"; do
  p=$(nix build --no-link --print-out-paths --option system-features "$features" "$flake#legacyPackages.$sys.gym-vm.$id" 2>/dev/null || true)
  if [ -n "$p" ] && [ -f "$p/verdict.json" ]; then cp "$p/verdict.json" "$out/$id.json"; else echo "{\"id\":\"$id\",\"result\":\"ERROR\",\"notes\":[\"the test did not run\"]}" > "$out/$id.json"; fi
done
catalog=${GYM_CATALOG:-crates/gym/catalog/phase-a.toml}
# R12: exits nonzero on ERROR, FAIL or PARTIAL, and on an UNSUPPORTED the
# catalog does not waive for the VM harness (`waive_unsupported.vm`).
python3 - "$out" "$catalog" <<'PY'
import json, sys, os, collections, tomllib
d = sys.argv[1]
waived = {e["id"] for e in tomllib.load(open(sys.argv[2], "rb"))["fault"] if "vm" in e.get("waive_unsupported", {})}
rs = [json.load(open(os.path.join(d, f))) for f in sorted(os.listdir(d))]
t = collections.Counter(r["result"] for r in rs)
for r in rs:
    print(f'{r["result"]:<12} {r["id"]}')
    if r["result"] != "PASS":
        for n in r.get("notes", [])[:6]:
            print(f"             {n}")
print()
print(dict(t))
print(f'cleared on the VM harness: {t["PASS"]} of {len(rs)} run')
bad = [r["id"] for r in rs if not (r["result"] == "PASS" or (r["result"] == "UNSUPPORTED" and r["id"] in waived))]
if bad:
    print(f"not cleared ({len(bad)}): {' '.join(bad)}")
    sys.exit(1)
PY
