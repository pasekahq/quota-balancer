#!/usr/bin/env bash
# Static release binary: size <= QB_MAX_BINARY_BYTES (default 4 MiB) and static linking, for the one
# binary that runs as qbd, qb agent, the CLI and qb gateway.
# The budgets CI job then runs the acceptance lane, crates/qb/tests/acceptance.rs, on this binary
# (docs/design.md, "Budgets"):
#   qbd: VmHWM <= 4 MiB after 10^4 picks, pick p99 <= 1 ms, no writes with journal = off,
#     no context switch while idle;
#   qb gateway: VmHWM <= 4 MiB idle and <= 4 MiB + 1 MiB + twice the request body with one turn
#     in flight, no context switch while idle with the loopback listener, p99 <= 5 ms from a
#     client request to its upstream request.
# Usage: ci/budgets.sh [path/to/qb]   (default: target/x86_64-unknown-linux-musl/release/qb)
set -euo pipefail

bin="${1:-target/x86_64-unknown-linux-musl/release/qb}"
max_bytes="${QB_MAX_BINARY_BYTES:-4194304}"
# 4 MiB since 2026-11-17 (owner decision): room to wire the qb-anthropic and qb-openai
# gateway fronts; it was 2.5 MiB (2621440) before.
fail=0

size=$(stat -c %s "$bin")
echo "binary (qbd, agent, CLI, gateway): $bin $size bytes (budget $max_bytes)"
if [ "$size" -gt "$max_bytes" ]; then
  echo "::error::binary size $size > budget $max_bytes"; fail=1
fi
if file "$bin" | grep -q 'dynamically linked'; then
  echo "::error::binary is dynamically linked, expected static"; fail=1
fi
exit "$fail"
