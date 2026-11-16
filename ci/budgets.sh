#!/usr/bin/env bash
# Static release binary: size <= QB_MAX_BINARY_BYTES (default 2.5 MiB) and static linking.
# The daemon's budgets are measured by the acceptance lane (see docs/design.md, "Budgets").
# Usage: ci/budgets.sh [path/to/qb]   (default: target/x86_64-unknown-linux-musl/release/qb)
set -euo pipefail

bin="${1:-target/x86_64-unknown-linux-musl/release/qb}"
max_bytes="${QB_MAX_BINARY_BYTES:-2621440}"
fail=0

size=$(stat -c %s "$bin")
echo "binary: $bin $size bytes (budget $max_bytes)"
if [ "$size" -gt "$max_bytes" ]; then
  echo "::error::binary size $size > budget $max_bytes"; fail=1
fi
if file "$bin" | grep -q 'dynamically linked'; then
  echo "::error::binary is dynamically linked, expected static"; fail=1
fi
exit "$fail"
