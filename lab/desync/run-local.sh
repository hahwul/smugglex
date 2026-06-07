#!/usr/bin/env bash
# Run the real-desync lab WITHOUT docker (pure-stdlib Python), then print the
# smugglex commands to scan it. Ctrl-C stops everything.
set -euo pipefail
cd "$(dirname "$0")"

VULN_FE_PORT="${VULN_FE_PORT:-8080}"
SAFE_FE_PORT="${SAFE_FE_PORT:-8081}"

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Vulnerable chain: CL frontend (:VULN_FE_PORT) -> TE backend (:8000)
FRAMING=te BIND_PORT=8000 python3 backend.py & pids+=("$!")
# Patched chain: CL frontend (:SAFE_FE_PORT) -> CL backend (:8001)
FRAMING=cl BIND_PORT=8001 python3 backend.py & pids+=("$!")
sleep 0.5
BIND_PORT="$VULN_FE_PORT" BACKEND_PORT=8000 python3 frontend.py & pids+=("$!")
BIND_PORT="$SAFE_FE_PORT" BACKEND_PORT=8001 python3 frontend.py & pids+=("$!")
sleep 0.8

cat <<EOF

Lab is up. Scan it with smugglex (build it first: cargo build --release):

  vulnerable:  ./target/release/smugglex http://127.0.0.1:${VULN_FE_PORT}/   # -> findings, exit 1
  patched:     ./target/release/smugglex http://127.0.0.1:${SAFE_FE_PORT}/   # -> clean,    exit 0

Press Ctrl-C to stop.
EOF
wait
