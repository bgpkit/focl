#!/usr/bin/env bash
# Does a real bgpviews archiving a real focl session produce the session's routes?
#
# Three processes, one chain, nothing simulated:
#   focld "b"  AS65002 originates two networks toward a peer
#   focld "a"  AS65001 is that peer; it exports what it received over BMP
#   bgpviews   listens as the station and writes MRT
#
# The check is the archive, not the daemon: what bgpviews wrote must contain the two networks
# with focld b's origin AS, and `bgpviews verify` must call the tree clean.
set -euo pipefail
cd "$(dirname "$0")"

FOCL_REPO=${FOCL_REPO:-/root/Git/bgpkit-git/focl}
VIEWS_REPO=${VIEWS_REPO:-/root/Git/bgpkit-git/bgpviews}
A_PORT=${A_PORT:-17961}
STATION_PORT=${STATION_PORT:-17962}

echo "== building =="
# Each repository decides its own target directory, so read the path cargo reports instead of
# assuming `<repo>/target`.
built() {
  (cd "$1" && cargo build --release --bin "$2" --message-format=json 2>/dev/null)     | grep -o "\"executable\":\"[^\"]*\"" | tail -1 | sed 's/.*:"//; s/"$//'
}
FOCLD=$(built "$FOCL_REPO" focld)
FOCL_CLI=$(built "$FOCL_REPO" focl)
VIEWS=$(built "$VIEWS_REPO" bgpviews)
test -x "$FOCLD" || { echo "FAIL: no focld at $FOCLD"; exit 1; }
test -x "$VIEWS" || { echo "FAIL: no bgpviews at $VIEWS"; exit 1; }

echo "== fresh run tree =="
rm -rf run
mkdir -p run/a run/b run/station
RUN=$PWD/run

cat > run/a/focl.toml <<TOML
[global]
asn = 65001
router_id = "192.0.2.1"
listen = true
listen_addr = "127.0.0.1:${A_PORT}"
control_socket = "${RUN}/a/focld.sock"
log_level = "info"

[[peers]]
name = "router-b"
address = "127.0.0.1"
remote_as = 65002
hold_time_secs = 30
connect_retry_secs = 1
remote_port = ${A_PORT}
passive = true
enabled = true

[bmp]
enabled = true
station = "127.0.0.1:${STATION_PORT}"
sys_name = "focl-a"
stats_interval_secs = 5
queue_frames = 65536

[archive]
enabled = false
TOML

cat > run/b/focl.toml <<TOML
[global]
asn = 65002
router_id = "192.0.2.2"
listen = false
control_socket = "${RUN}/b/focld.sock"
log_level = "info"

[[peers]]
name = "focl-a"
address = "127.0.0.1"
remote_as = 65001
hold_time_secs = 30
connect_retry_secs = 1
remote_port = ${A_PORT}
local_address = "127.0.0.1"
passive = false
enabled = true

[[prefixes]]
network = "192.0.2.0/24"

[[prefixes]]
network = "2001:db8:99::/48"
# The session is IPv4-addressed, so an IPv6 announcement needs an IPv6 next hop of its own;
# without it focld warns and announces nothing.
next_hop = "2001:db8:99::1"
TOML

cat > run/station/bgpviews.toml <<TOML
[archive]
root = "${RUN}/station/archive"

[[clients]]
name = "focl"
listen = "127.0.0.1:${STATION_PORT}"
allow_from = ["127.0.0.1/32"]
feed = "bmp"

[clients.view]
name = "adj-in-pre"
updates_interval_minutes = 1
rib = true
TOML

echo "== starting the station =="
"$VIEWS" run --config run/station/bgpviews.toml > run/station/bgpviews.log 2>&1 &
VIEWS_PID=$!
sleep 1
kill -0 "$VIEWS_PID" 2>/dev/null || { echo "FAIL: bgpviews did not start"; cat run/station/bgpviews.log; exit 1; }

echo "== starting focld a (exporter) =="
"$FOCLD" --config run/a/focl.toml > run/a/focld.log 2>&1 &
A_PID=$!
sleep 1

echo "== starting focld b (originator) =="
"$FOCLD" --config run/b/focl.toml > run/b/focld.log 2>&1 &
B_PID=$!

cleanup() {
  kill "$B_PID" "$A_PID" "$VIEWS_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "== waiting for the session =="
ESTABLISHED=0
for _ in $(seq 1 40); do
  if "$FOCL_CLI" --socket "$RUN/a/focld.sock" peer list 2>/dev/null | grep -q '"established"'; then
    ESTABLISHED=1
    break
  fi
  sleep 0.5
done
if [ "$ESTABLISHED" != "1" ]; then
  echo "FAIL: focld a never reported an established session"
  tail -5 run/a/focld.log
  exit 1
fi
echo "session established"

# Long enough for both the announcement and the End-of-RIB markers to cross the BMP connection,
# plus the exporter's own statistics heartbeat.
sleep 4
echo "== stopping the originator first, so the peer-down path runs =="
kill "$B_PID" 2>/dev/null || true
sleep 2
echo "== stopping the exporter, which ends the BMP session =="
kill "$A_PID" 2>/dev/null || true
sleep 2
kill "$VIEWS_PID" 2>/dev/null || true
wait 2>/dev/null || true
trap - EXIT

echo "== bgpviews log =="
VIEWS_LOG=$(cat run/station/bgpviews.log)
tail -20 run/station/bgpviews.log

# The station's own counters are the pass condition for everything before the file exists: a Peer
# Up it refused would leave records at zero, and a missing End-of-RIB would leave that at zero.
echo "$VIEWS_LOG" | grep -q 'records           4' || { echo "FAIL: expected four records (two routes, two End-of-RIB)"; exit 1; }
echo "$VIEWS_LOG" | grep -q 'end of rib        2' || { echo "FAIL: the End-of-RIB markers did not reach the station"; exit 1; }
echo "$VIEWS_LOG" | grep -q 'peer_vanished' || { echo "FAIL: no Peer Down reached the station"; exit 1; }

echo "== archive tree =="
find run/station/archive -name '*.gz' | sort | head -20

UPDATES=$(find run/station/archive -name 'updates.*.gz' | sort | tail -1)
if [ -z "$UPDATES" ]; then
  echo "FAIL: the station wrote no updates segment"
  exit 1
fi
echo "== parsing $UPDATES =="
monocle parse "$UPDATES" 2>&1 | head -20

echo "== the archived records must carry the originator's networks =="
PARSED=$(monocle parse "$UPDATES" 2>&1)
echo "$PARSED" | grep -q '192.0.2.0/24' || { echo "FAIL: ipv4 network missing from the station's archive"; exit 1; }
echo "$PARSED" | grep -q '2001:db8:99::/48' || { echo "FAIL: ipv6 network missing from the station's archive"; exit 1; }
echo "$PARSED" | grep -q '65002' || { echo "FAIL: originator AS missing from the archived path"; exit 1; }

echo "== bgpviews verify =="
"$VIEWS" verify --config run/station/bgpviews.toml
echo "PASS"
