#!/usr/bin/env bash
# Run the real-desync lab WITHOUT docker (pure Crystal), then print the
# smugglex commands to scan it. Ctrl-C stops everything.
#
# Needs Crystal: https://crystal-lang.org/install
set -euo pipefail
cd "$(dirname "$0")"

VULN_FE_PORT="${VULN_FE_PORT:-8080}"
SAFE_FE_PORT="${SAFE_FE_PORT:-8081}"

bin="$(mktemp -d)/desync_lab"
echo "building desync_lab (crystal build --release)…"
crystal build --release desync_lab.cr -o "$bin"

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Vulnerable chain: CL frontend (:VULN_FE_PORT) -> TE backend (:9001)
FRAMING=te FRONTEND_PORT="$VULN_FE_PORT" BACKEND_PORT=9001 "$bin" & pids+=("$!")
# Patched chain: CL frontend (:SAFE_FE_PORT) -> CL backend (:9002)
FRAMING=cl FRONTEND_PORT="$SAFE_FE_PORT" BACKEND_PORT=9002 "$bin" & pids+=("$!")
sleep 0.8

cat <<EOF

Lab is up. Scan it with smugglex (build it first: cargo build --release):

  vulnerable:  ./target/release/smugglex http://127.0.0.1:${VULN_FE_PORT}/         # -> findings, exit 1
  solve:       ./target/release/smugglex --exploit smuggle http://127.0.0.1:${VULN_FE_PORT}/
  patched:     ./target/release/smugglex http://127.0.0.1:${SAFE_FE_PORT}/         # -> clean,    exit 0

Press Ctrl-C to stop.
EOF
wait
