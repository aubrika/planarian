#!/usr/bin/env bash
# GA demonstration (SPEC §4 GA(1), §18.1).
#
#   1. fault → repaired                       svc-killed
#   2. bad configuration → reverted           svc-misconfig-listen-address
#   3. kill planariad during Activating;
#      the watchdog reverts                   crash-activating-bad
#   4. restart the daemon; it reconciles the
#      journal and explains what happened     crash-daemon-restart-reconciles
#
# Each step is a catalog entry in catalog/phase-a.toml, scored on its
# required_post. Pass/fail never comes from the absence of errors (§18.4).
# The reconciliation record from step 4 is printed at the end.
#
# Usage: crates/gym/demo.sh [--harness fake|vm]   (default: vm)
set -euo pipefail

harness=vm
while [[ $# -gt 0 ]]; do
  case "$1" in
    --harness) harness="$2"; shift 2 ;;
    *) echo "usage: $0 [--harness fake|vm]" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
catalog="$root/crates/gym/catalog/phase-a.toml"
steps=(
  svc-killed
  svc-misconfig-listen-address
  crash-activating-bad
  crash-daemon-restart-reconciles
)

cd "$root"
cargo build --quiet --release -p planarian-gym
gym="$root/target/release/planarian-gym"

failed=0
for id in "${steps[@]}"; do
  if "$gym" run --catalog "$catalog" --harness "$harness" --id "$id"; then
    echo "PASS  $id"
  else
    echo "FAIL  $id"
    failed=1
  fi
done

echo
echo "Reconciliation record (crash-daemon-restart-reconciles):"
"$gym" show-reconciliation --harness "$harness" --id crash-daemon-restart-reconciles

exit "$failed"
