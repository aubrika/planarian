#!/usr/bin/env bash
# The dependency rule (SPEC §5, §17), checked on the sources:
# - schema, policy, txn, exec, diagnose, incident, state do not depend on the
#   backends, use std::process, or read /proc, /sys or /nix;
# - schema, policy, txn, exec use no `dyn`;
# - no crate lifts the workspace's `unsafe_code = "forbid"`.
# Test code (tests.rs, tests/, and a file's trailing #[cfg(test)] module) is exempt.
set -euo pipefail
root=${1:-.}
cd "$root"
fail=0
say() { echo "boundary: $*"; fail=1; }

# A file's non-test code: everything before its first top-level
# #[cfg(test)], without comment lines.
body() { awk '/^#\[cfg\(test\)\]/ { exit } !/^[[:space:]]*\/\// { print }' "$1"; }
sources() { find "crates/$1/src" -name '*.rs' ! -name 'tests.rs' ! -path '*/tests/*'; }

for c in schema policy txn exec diagnose incident state; do
  if grep -q 'planarian-backend' "crates/$c/Cargo.toml"; then
    say "$c depends on a backend crate"
  fi
  for f in $(sources "$c"); do
    if body "$f" | grep -nE 'std::process|"/proc|"/sys|"/nix' >/dev/null; then
      say "$f uses std::process or reads /proc, /sys or /nix: $(body "$f" | grep -nE 'std::process|"/proc|"/sys|"/nix' | head -1)"
    fi
  done
done
for c in schema policy txn exec; do
  for f in $(sources "$c"); do
    if body "$f" | grep -nE '\bdyn\b' >/dev/null; then
      say "$f uses dyn: $(body "$f" | grep -nE '\bdyn\b' | head -1)"
    fi
  done
done
if grep -rnE 'allow\(unsafe_code\)|unsafe_code *= *"(allow|warn)"' crates --include='*.rs' --include=Cargo.toml; then
  say "a crate lifts unsafe_code = forbid"
fi
[ "$fail" = 0 ] && echo "boundaries: ok"
exit "$fail"
