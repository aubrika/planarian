#!/usr/bin/env bash
# Export exactly the applicable verdict set, then apply reviewed scoped waivers.
set -euo pipefail
out=${GYM_RESULTS_DIR:-$(mktemp -d)}
mkdir -p "$out"
# Old verdicts must never make an interrupted new run look complete.
rm -f "$out"/*.json
catalog=${GYM_CATALOG:-crates/gym/catalog/phase-a.toml}
acceptance=${GYM_ACCEPTANCE:-nix/gym/acceptance.py}
waivers=${GYM_WAIVERS:-docs/acceptance-waivers.toml}
status=0
echo "fake harness results in $out"
cargo run -p planarian-gym -- run --catalog "$catalog" --verdict-dir "$out" || status=$?
python3 "$acceptance" check --catalog "$catalog" --harness fake --waivers "$waivers" \
  --report "$out/acceptance.json" "$out"/*.json
# Only the dedicated unsupported-coverage status can be waived. Failures and
# crashes cannot become success merely because some verdicts were written.
if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then exit "$status"; fi
