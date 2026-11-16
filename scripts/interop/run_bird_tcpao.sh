#!/usr/bin/env bash
# TCP-AO (RFC 5925) interop between focld and BIRD (2.17+ / 3.1+) on Linux.
#
# Runs two sessions over loopback, each checked for Established, TCP-AO and a
# route in both directions:
#   1. focld active, BIRD passive, HMAC-SHA-1-96
#   2. BIRD active, focld passive, AES-128-CMAC-96
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="$ROOT_DIR/scripts/interop/.runtime"
mkdir -p "$RUNTIME_DIR"

BIRD_BIN="${BIRD_BIN:-$(command -v bird || true)}"
BIRDC_BIN="${BIRDC_BIN:-$(command -v birdc || true)}"
FOCL_PORT="${FOCL_PORT:-2179}"
BIRD_PORT="${BIRD_PORT:-3179}"
SECRET="focl-bird-tcp-ao"
# Separate loopback addresses: BIRD rejects a NEXT_HOP equal to its own
# address, which focld's next hop would be if both used 127.0.0.1.
FOCL_ADDR="127.0.0.1"
BIRD_ADDR="127.0.0.2"

if [[ "$OSTYPE" != "linux-gnu"* ]]; then
	echo "TCP-AO is only supported on Linux; skipping on $OSTYPE" >&2
	exit 0
fi
if ! grep -q TCPAOGood /proc/net/netstat; then
	echo "this kernel has no TCP-AO (needs Linux 6.7+ built with CONFIG_TCP_AO)" >&2
	exit 1
fi
if [[ ! -x "$BIRD_BIN" || ! -x "$BIRDC_BIN" ]]; then
	echo "bird/birdc not found; set BIRD_BIN and BIRDC_BIN (BIRD 2.17+ or 3.1+)" >&2
	exit 1
fi

cargo build --bin focld --bin focl
FOCLD_BIN="$ROOT_DIR/target/debug/focld"
FOCL_BIN="$ROOT_DIR/target/debug/focl"

FOCL_SOCKET="$RUNTIME_DIR/focld-tcpao.sock"
BIRD_SOCKET="$RUNTIME_DIR/bird-tcpao.ctl"

stop_daemons() {
	set +e
	if [[ -n "${FOCLD_PID:-}" ]]; then
		kill "$FOCLD_PID" 2>/dev/null
		wait "$FOCLD_PID" 2>/dev/null
		FOCLD_PID=""
	fi
	if [[ -n "${BIRD_PID:-}" ]]; then
		kill "$BIRD_PID" 2>/dev/null
		wait "$BIRD_PID" 2>/dev/null
		BIRD_PID=""
	fi
	rm -f "$FOCL_SOCKET" "$BIRD_SOCKET"
	set -e
}
trap stop_daemons EXIT

# write_bird_config <file> <passive: on|off> <bird algorithm>
write_bird_config() {
	cat >"$1" <<EOF
log stderr all;
router id $BIRD_ADDR;

# No "protocol device": a multihop session over loopback doesn't need it, and
# it needs netlink, which sandboxes often block.
protocol static {
	ipv4;
	route 198.51.100.0/24 blackhole;
}

protocol bgp focl {
	local $BIRD_ADDR port $BIRD_PORT as 65002;
	neighbor $FOCL_ADDR port $FOCL_PORT as 65001;
	multihop;
	passive $2;
	authentication ao;
	keys {
		key {
			send id 2;
			recv id 1;
			secret "$SECRET";
			algorithm $3;
		};
	};
	ipv4 {
		import all;
		export all;
	};
}
EOF
}

# write_focl_config <file> <listen: true|false> <passive: true|false> <focl algorithm>
write_focl_config() {
	cat >"$1" <<EOF
[global]
asn = 65001
router_id = "$FOCL_ADDR"
listen = $2
listen_addr = "$FOCL_ADDR:$FOCL_PORT"
control_socket = "$FOCL_SOCKET"
log_level = "debug"

[[peers]]
name = "bird-tcp-ao"
address = "$BIRD_ADDR"
remote_as = 65002
remote_port = $BIRD_PORT
connect_retry_secs = 2
passive = $3

[[peers.tcp_ao_keys]]
send_id = 1
recv_id = 2
algorithm = "$4"
secret = "$SECRET"

[[prefixes]]
network = "203.0.113.0/24"
next_hop = "$FOCL_ADDR"

[archive]
enabled = false
EOF
}

wait_for() {
	local description="$1"
	shift
	for ((i = 1; i <= 40; i++)); do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "timed out waiting for: $description" >&2
	return 1
}

focl_session_up() {
	local show
	show="$("$FOCL_BIN" --socket "$FOCL_SOCKET" peer show "$BIRD_ADDR")"
	grep -q '"state": "established"' <<<"$show" && grep -q '"auth_mode": "tcp-ao"' <<<"$show"
}

# Output is captured before grepping: with pipefail, `cmd | grep -q` fails
# when grep exits early and the writer gets SIGPIPE.
focl_learned_bird_route() {
	local rib
	rib="$("$FOCL_BIN" --socket "$FOCL_SOCKET" rib in "$BIRD_ADDR")"
	grep -q "198.51.100.0/24" <<<"$rib"
}

bird_learned_focl_route() {
	local routes
	routes="$("$BIRDC_BIN" -s "$BIRD_SOCKET" show route 203.0.113.0/24)"
	grep -q "203.0.113.0/24" <<<"$routes"
}

dump_logs() {
	echo "--- birdc show protocols all focl ---" >&2
	"$BIRDC_BIN" -s "$BIRD_SOCKET" show protocols all focl >&2 || true
	echo "--- kernel TCP-AO counters ---" >&2
	nstat -az 2>/dev/null | grep -E 'TCPAO' >&2 || true
	echo "--- $1 ---" >&2
	tail -n 100 "$1" >&2 || true
	echo "--- $2 ---" >&2
	tail -n 100 "$2" >&2 || true
}

# run_scenario <name> <focl listen> <focl passive> <focl algorithm> <bird passive> <bird algorithm>
run_scenario() {
	local name="$1"
	local bird_cfg="$RUNTIME_DIR/bird-$name.conf"
	local focl_cfg="$RUNTIME_DIR/focl-$name.toml"
	local bird_log="$RUNTIME_DIR/bird-$name.log"
	local focld_log="$RUNTIME_DIR/focld-$name.log"
	write_bird_config "$bird_cfg" "$5" "$6"
	write_focl_config "$focl_cfg" "$2" "$3" "$4"

	echo "[$name] starting BIRD and focld..."
	"$BIRD_BIN" -f -c "$bird_cfg" -s "$BIRD_SOCKET" >"$bird_log" 2>&1 &
	BIRD_PID=$!
	"$FOCLD_BIN" --config "$focl_cfg" >"$focld_log" 2>&1 &
	FOCLD_PID=$!

	if ! wait_for "focld session Established over TCP-AO" focl_session_up ||
		! wait_for "focld learning 198.51.100.0/24 from BIRD" focl_learned_bird_route ||
		! wait_for "BIRD learning 203.0.113.0/24 from focld" bird_learned_focl_route; then
		dump_logs "$bird_log" "$focld_log"
		exit 1
	fi
	"$BIRDC_BIN" -s "$BIRD_SOCKET" show protocols all focl | grep -iE 'key|packets' || true
	echo "[$name] OK: Established over TCP-AO, routes exchanged both ways"
	stop_daemons
}

run_scenario focl-active-hmac-sha1 false false hmac-sha1-96 on "hmac sha1"
run_scenario bird-active-cmac-aes128 true true aes-128-cmac-96 off "cmac aes128"

echo "Interop OK: focld <-> BIRD over TCP-AO in both directions, both RFC 5926 algorithms"
