#!/usr/bin/env bash
# Acceptance for boundaries.sh's wider scan (H9, #8): a clean copy passes,
# and a violation planted in each place the old scan missed fails it.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "${1:-$here/../..}" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fresh() {
  rm -rf "$tmp/t" && mkdir -p "$tmp/t"
  cp -r "$src/crates" "$tmp/t/crates"
}
check() { bash "$here/boundaries.sh" "$tmp/t" > "$tmp/out" 2>&1; }
fail=0

fresh
check || { echo "a clean copy fails:"; cat "$tmp/out"; exit 1; }

plant() {
  local name=$1 want=$2
  if check; then
    echo "missed: $name"; fail=1
  elif ! grep -q -- "$want" "$tmp/out"; then
    echo "caught $name, but not as \"$want\":"; cat "$tmp/out"; fail=1
  else
    echo "caught: $name"
  fi
}

# 1. Code after a #[cfg(test)] module.
fresh
cat >> "$tmp/t/crates/txn/src/kernel.rs" <<'RS'

#[cfg(test)]
mod planted_tests {
    #[test]
    fn t() {}
}

pub fn planted() { let _ = std::process::id(); }
RS
plant "code after a test module" "kernel.rs"

# 2. /proc, /sys, /nix without a leading quote.
for p in proc sys nix; do
  fresh
  echo "pub fn planted(root: &str) -> String { format!(\"{root}/$p/x\") }" >> "$tmp/t/crates/policy/src/lib.rs"
  plant "/$p without a leading quote" "policy/src/lib.rs"
done

# 3. A crate reached only through changes or state.
for via in changes state; do
  fresh
  echo "pub fn planted() { let _ = std::process::id(); }" >> "$tmp/t/crates/$via/src/lib.rs"
  plant "std::process in $via" "$via/src/lib.rs"
  fresh
  sed -i 's/^\[dependencies\]$/[dependencies]\nplanarian-backend-linux.workspace = true/' "$tmp/t/crates/$via/Cargo.toml"
  plant "a backend dependency of $via" "depends on a backend"
done

# A dev-dependency on a backend and std::process inside a test item stay allowed.
fresh
sed -i 's/^\[dev-dependencies\]$/[dev-dependencies]\nplanarian-backend-linux.workspace = true/' "$tmp/t/crates/state/Cargo.toml"
printf '\n#[cfg(test)]\nfn planted() { let _ = std::process::id(); }\n' >> "$tmp/t/crates/txn/src/kernel.rs"
check || { echo "a test item or dev-dependency is flagged:"; cat "$tmp/out"; fail=1; }

[ "$fail" = 0 ] && echo "boundaries-test: ok"
exit "$fail"
