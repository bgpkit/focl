#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT_DIR/scripts/interop/.runtime"
mkdir -p "$RUNTIME_DIR"

GOBGPD_BIN="${GOBGPD_BIN:-$HOME/go/bin/gobgpd}"
GOBGP_BIN="${GOBGP_BIN:-$HOME/go/bin/gobgp}"

if [[ ! -x "$GOBGPD_BIN" ]]; then
	echo "gobgpd not found at $GOBGPD_BIN" >&2
	exit 1
fi

if [[ ! -x "$GOBGP_BIN" ]]; then
	echo "gobgp not found at $GOBGP_BIN" >&2
	exit 1
fi

GOBGPD_CFG="$ROOT_DIR/scripts/interop/gobgpd-md5.toml"
FOCL_CFG="$ROOT_DIR/scripts/interop/focl-interop-md5.toml"
FOCL_SOCKET="$ROOT_DIR/focld-interop.sock"
GOBGPD_LOG="$RUNTIME_DIR/gobgpd-md5.log"
FOCLD_LOG="$RUNTIME_DIR/focld-md5.log"
GOBGP_API_HOST="${GOBGP_API_HOST:-127.0.0.1}"
GOBGP_API_PORT="${GOBGP_API_PORT:-50052}"

cleanup() {
	set +e
	if [[ -n "${FOCLD_PID:-}" ]]; then
		kill "$FOCLD_PID" 2>/dev/null || true
		wait "$FOCLD_PID" 2>/dev/null || true
	fi
	if [[ -n "${GOBGPD_PID:-}" ]]; then
		kill "$GOBGPD_PID" 2>/dev/null || true
		wait "$GOBGPD_PID" 2>/dev/null || true
	fi
	rm -f "$FOCL_SOCKET"
}
trap cleanup EXIT

pkill -f "gobgpd.*$GOBGPD_CFG" >/dev/null 2>&1 || true
pkill -f "focld.*$FOCL_CFG" >/dev/null 2>&1 || true
rm -f "$FOCL_SOCKET"

# Check if running on Linux (TCP-MD5 requires Linux)
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
	echo "WARNING: TCP-MD5 authentication is only supported on Linux." >&2
	echo "Current platform: $OSTYPE" >&2
	echo "This test requires Linux. Skipping..." >&2
	exit 0
fi

echo "Starting GoBGP with MD5 authentication..."
"$GOBGPD_BIN" \
	-f "$GOBGPD_CFG" \
	--log-level debug \
	--api-hosts "${GOBGP_API_HOST}:${GOBGP_API_PORT}" \
	--pprof-disable \
	>"$GOBGPD_LOG" 2>&1 &
GOBGPD_PID=$!

echo "Starting focld with MD5 authentication..."
cargo run --bin focld -- --config "$FOCL_CFG" >"$FOCLD_LOG" 2>&1 &
FOCLD_PID=$!

wait_for_established() {
	local tries=40
	for ((i = 1; i <= tries; i++)); do
		if "$GOBGP_BIN" -u "$GOBGP_API_HOST" -p "$GOBGP_API_PORT" neighbor 2>/dev/null | grep -Eqi "establ|established|bgp_fsm_established"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

wait_for_prefix() {
	local tries=40
	for ((i = 1; i <= tries; i++)); do
		if "$GOBGP_BIN" -u "$GOBGP_API_HOST" -p "$GOBGP_API_PORT" global rib -a ipv4 2>/dev/null | grep -q "203.0.113.0/24"; then
			return 0
		fi
		sleep 1
	done
	return 1
}

if ! wait_for_established; then
	echo "BGP session with MD5 did not reach Established" >&2
	echo "--- gobgpd.log ---" >&2
	tail -n 200 "$GOBGPD_LOG" >&2 || true
	echo "--- focld.log ---" >&2
	tail -n 200 "$FOCLD_LOG" >&2 || true
	exit 1
fi

echo "BGP session with MD5 authentication established successfully!"

if ! wait_for_prefix; then
	echo "GoBGP did not learn 203.0.113.0/24" >&2
	echo "--- gobgp global rib -a ipv4 ---" >&2
	"$GOBGP_BIN" -u "$GOBGP_API_HOST" -p "$GOBGP_API_PORT" global rib -a ipv4 >&2 || true
	echo "--- gobgpd.log ---" >&2
	tail -n 200 "$GOBGPD_LOG" >&2 || true
	echo "--- focld.log ---" >&2
	tail -n 200 "$FOCLD_LOG" >&2 || true
	exit 1
fi

echo "Interop OK: MD5 authentication + Established + prefix 203.0.113.0/24 received by GoBGP"
