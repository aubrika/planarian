#!/usr/bin/env bash
# The dependency rule (SPEC §5, §17), checked on the sources:
# - schema, policy, txn, exec, diagnose, incident, state, and every workspace
#   crate they depend on, directly or through another (changes, state: H9),
#   do not depend on the backends, use std::process, or read /proc, /sys or
#   /nix;
# - schema, policy, txn, exec use no `dyn`;
# - no crate lifts the workspace's `unsafe_code = "forbid"`.
# Test code (tests.rs, tests/, and every #[cfg(test)] item wherever it sits)
# is exempt; so are dev-dependencies.
set -euo pipefail
root=${1:-.}
cd "$root"
fail=0
say() { echo "boundary: $*"; fail=1; }

# A file's non-test code without comment lines: each #[cfg(test)] item is
# dropped, to its closing brace or, for a braceless item, its `;`. Code after
# a test module is still checked (H9).
body() {
  awk '
    function skipping(line,   n, m) {
      n = gsub(/\{/, "{", line); m = gsub(/\}/, "}", line)
      depth += n - m
      if (n > 0) opened = 1
      if ((opened && depth <= 0) || (!opened && line ~ /;[[:space:]]*$/)) skip = 0
    }
    skip { skipping($0); next }
    /^[[:space:]]*#\[cfg\(test\)\]/ {
      skip = 1; depth = 0; opened = 0
      rest = $0; sub(/^[[:space:]]*#\[cfg\(test\)\]/, "", rest)
      if (rest ~ /[^[:space:]]/) skipping(rest)
      next
    }
    /^[[:space:]]*\/\// { next }
    { print }
  ' "$1"
}
sources() { find "$1/src" -name '*.rs' ! -name 'tests.rs' ! -path '*/tests/*'; }

# A workspace crate's directory, and its normal dependencies on other
# workspace crates (the [dependencies] tables only, not dev- or build-).
dir_of() {
  case "$1" in
    planarian-backend-*) echo "crates/backends/${1#planarian-backend-}" ;;
    *) echo "crates/${1#planarian-}" ;;
  esac
}
deps() {
  awk '
    /^\[/ { on = ($0 ~ /^\[(target\..*\.)?dependencies\]/) ; next }
    on && match($0, /^planarian-[a-z-]+/) { print substr($0, RSTART, RLENGTH) }
  ' "$1/Cargo.toml" | sort -u
}

# The restricted crates and everything they depend on, with the path by
# which each is reached (for the message).
declare -A via=()
queue=()
for c in schema policy txn exec diagnose incident state; do
  via[planarian-$c]="planarian-$c"
  queue+=("planarian-$c")
done
while [ "${#queue[@]}" -gt 0 ]; do
  c=${queue[0]}
  queue=("${queue[@]:1}")
  for d in $(deps "$(dir_of "$c")"); do
    if [ -z "${via[$d]:-}" ]; then
      via[$d]="${via[$c]} -> $d"
      queue+=("$d")
    fi
  done
done

pattern='std::process|/proc\b|/sys\b|/nix\b'
for c in $(printf '%s\n' "${!via[@]}" | sort); do
  case "$c" in
    planarian-backend-*)
      say "a restricted crate depends on a backend: ${via[$c]}"
      continue
      ;;
  esac
  for f in $(sources "$(dir_of "$c")"); do
    if hit=$(body "$f" | grep -nE "$pattern" | head -1) && [ -n "$hit" ]; then
      say "$f (${via[$c]}) uses std::process or reads /proc, /sys or /nix: $hit"
    fi
  done
done
for c in schema policy txn exec; do
  for f in $(sources "crates/$c"); do
    if hit=$(body "$f" | grep -nE '\bdyn\b' | head -1) && [ -n "$hit" ]; then
      say "$f uses dyn: $hit"
    fi
  done
done
if grep -rnE 'allow\(unsafe_code\)|unsafe_code *= *"(allow|warn)"' crates --include='*.rs' --include=Cargo.toml; then
  say "a crate lifts unsafe_code = forbid"
fi
[ "$fail" = 0 ] && echo "boundaries: ok"
exit "$fail"
