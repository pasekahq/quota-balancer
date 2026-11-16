#!/usr/bin/env bash
# Resource budgets, enforced in CI (see docs/design.md, "Budgets").
#   1. static release binary size  <= QB_MAX_BINARY_BYTES (default 2.5 MiB)
#   2. daemon RSS after N requests <= QB_MAX_RSS_KB      (default 4096 kB), N = QB_REQUESTS (10000)
# Usage: ci/budgets.sh [path/to/qb]   (default: target/x86_64-unknown-linux-musl/release/qb)
set -euo pipefail

bin="${1:-target/x86_64-unknown-linux-musl/release/qb}"
config="$(dirname "$0")/../deploy/examples/qbd.toml"
max_bytes="${QB_MAX_BINARY_BYTES:-2621440}"
max_rss_kb="${QB_MAX_RSS_KB:-4096}"
requests="${QB_REQUESTS:-10000}"
fail=0

size=$(stat -c %s "$bin")
echo "binary: $bin $size bytes (budget $max_bytes)"
if [ "$size" -gt "$max_bytes" ]; then
  echo "::error::binary size $size > budget $max_bytes"; fail=1
fi
if file "$bin" | grep -q 'dynamically linked'; then
  echo "::error::binary is dynamically linked, expected static"; fail=1
fi

dir=$(mktemp -d)
sock="$dir/qb.sock"
"$bin" --socket "$sock" daemon --config "$config" 2>"$dir/qbd.log" &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$dir"' EXIT
for _ in $(seq 100); do [ -S "$sock" ] && break; sleep 0.05; done
[ -S "$sock" ] || { echo "::error::daemon did not start"; cat "$dir/qbd.log"; exit 1; }

python3 - "$sock" "$requests" <<'PY'
import socket, sys, time
path, n = sys.argv[1], int(sys.argv[2])
pick = b'{"role":"worker","difficulty":1}'
reqs = [
    b"POST /v1/pick HTTP/1.1\r\nHost: qb\r\nContent-Length: %d\r\n\r\n%s" % (len(pick), pick),
    b"GET /v1/state HTTP/1.1\r\nHost: qb\r\n\r\n",
    b"GET /v1/health HTTP/1.1\r\nHost: qb\r\n\r\n",
]
lat = []
for i in range(n):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    t = time.perf_counter()
    s.connect(path)
    s.sendall(reqs[i % 3])
    data = b""
    while chunk := s.recv(4096):
        data += chunk
    lat.append(time.perf_counter() - t)
    s.close()
    if not data.startswith(b"HTTP/1.1 200 "):
        sys.exit(f"request {i}: unexpected response {data[:80]!r}")
lat.sort()
print(f"requests: {n}, p50 {lat[n // 2] * 1e6:.0f} us, p99 {lat[n * 99 // 100] * 1e6:.0f} us (client in Python)")
PY

rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")
hwm=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status")
echo "daemon: VmRSS ${rss} kB, VmHWM ${hwm} kB (budget ${max_rss_kb} kB)"
if [ "$hwm" -gt "$max_rss_kb" ]; then
  echo "::error::daemon peak RSS ${hwm} kB > budget ${max_rss_kb} kB"; fail=1
fi
exit "$fail"
