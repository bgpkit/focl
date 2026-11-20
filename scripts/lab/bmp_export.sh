#!/usr/bin/env bash
# Does a real bgpviews archive both directions of a real focl session, and keep them apart?
#
# Three processes, one chain, nothing simulated:
#   focld "b"  AS65002 originates two networks toward its peer
#   focld "a"  AS65001 is that peer, originates two of its own, and exports both directions
#   bgpviews   listens twice: one client records what a received (adj-in-pre), one what a sent
#              (adj-out, the RFC 8671 O flag)
#
# The check is the archive, not the daemon, and the two directions carry *different* networks on
# purpose: an archive that mixed them would still parse, so only the content proves the split.
set -euo pipefail
cd "$(dirname "$0")"

FOCL_REPO=${FOCL_REPO:-$(cd ../.. && pwd)}
VIEWS_REPO=${VIEWS_REPO:-/root/Git/bgpkit-git/bgpviews}
A_PORT=${A_PORT:-17961}
IN_PORT=${IN_PORT:-17962}
OUT_PORT=${OUT_PORT:-17963}

echo "== building =="
# Each repository decides its own target directory, so read the path cargo reports instead of
# assuming `<repo>/target`.
built() {
  (cd "$1" && cargo build --release --bin "$2" --message-format=json 2>/dev/null) | grep -o '"executable":"[^"]*"' | tail -1 | sed 's/.*:"//; s/"$//'
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

# This daemon's own announcements: what the adj-out station is supposed to see.
[[prefixes]]
network = "203.0.113.0/24"

[[prefixes]]
network = "2001:db8:aa::/48"
next_hop = "2001:db8:aa::1"

[bmp]
enabled = true
sys_name = "focl-a"
stats_interval_secs = 2
queue_frames = 65536

# One entry per station connection: a station records one view per listening port, so the two
# directions are two connections.
[[bmp.stations]]
address = "127.0.0.1:${IN_PORT}"

[[bmp.stations]]
address = "127.0.0.1:${OUT_PORT}"
rib_out = true
# An outbound connection describes what this daemon sends, so there is no table to ask a peer for.
redump_on_connect = false

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
name = "focl-in"
listen = "127.0.0.1:${IN_PORT}"
allow_from = ["127.0.0.1/32"]
feed = "bmp"

[clients.view]
name = "adj-in-pre"
updates_interval_minutes = 1
rib = true

[[clients]]
name = "focl-out"
listen = "127.0.0.1:${OUT_PORT}"
allow_from = ["127.0.0.1/32"]
feed = "bmp"

[clients.view]
name = "adj-out"
updates_interval_minutes = 1
rib = true
TOML

echo "== starting the station =="
"$VIEWS" run --config run/station/bgpviews.toml > run/station/bgpviews.log 2>&1 &
VIEWS_PID=$!
sleep 1
kill -0 "$VIEWS_PID" 2>/dev/null || { echo "FAIL: bgpviews did not start"; cat run/station/bgpviews.log; exit 1; }

echo "== starting focld a (exporter of both directions) =="
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

# Long enough for both tables, both End-of-RIB pairs and a statistics heartbeat to cross each BMP
# connection.
sleep 5

# ---- the reconnect: the station goes away while the session stays up ----
#
# This is the case the redump exists for. The station comes back with no idea what the tables were,
# and the daemon cannot replay frames it never kept, so it asks the peers for their tables again
# (RFC 2918). Without that, this second session would record nothing at all.
echo "== restarting the station while the session stays up =="
kill "$VIEWS_PID" 2>/dev/null || true
# Long enough for the exporter to notice the dead socket on its next heartbeat and fail to connect;
# shorter than that and it would reconnect only after the peer is gone, which is a different case.
sleep 6
"$VIEWS" run --config run/station/bgpviews.toml >> run/station/bgpviews.log 2>&1 &
VIEWS_PID=$!
sleep 8

echo "== stopping the originator first, so the peer-down path runs =="
kill "$B_PID" 2>/dev/null || true
sleep 2
echo "== stopping the exporter, which ends both BMP sessions =="
kill "$A_PID" 2>/dev/null || true
sleep 3
kill "$VIEWS_PID" 2>/dev/null || true
wait 2>/dev/null || true
trap - EXIT

echo "== bgpviews log =="
VIEWS_LOG=$(cat run/station/bgpviews.log)
tail -45 run/station/bgpviews.log

echo "== archive tree =="
find run/station/archive -name '*.gz' | sort

IN_SEG=$(find run/station/archive/focl-in-adj-in-pre -name 'updates.*.gz' 2>/dev/null | sort | tail -1)
OUT_SEG=$(find run/station/archive/focl-out-adj-out -name 'updates.*.gz' 2>/dev/null | sort | tail -1)
[ -n "$IN_SEG" ] || { echo "FAIL: the adj-in-pre station wrote no updates segment"; exit 1; }
[ -n "$OUT_SEG" ] || { echo "FAIL: the adj-out station wrote no updates segment"; exit 1; }

# Every segment of a view, oldest first: the restart makes two sessions, and both directions have
# to add up to what was seen rather than to whichever segment happens to be newest.
parse_all() {
  find "$1" -name 'updates.*.gz' 2>/dev/null | sort | while read -r segment; do
    monocle parse "$segment" 2>&1
  done
}

echo "== what the station recorded as received (adj-in-pre, every segment) =="
IN_PARSED=$(parse_all run/station/archive/focl-in-adj-in-pre)
echo "$IN_PARSED"
echo "== what the station recorded as sent (adj-out, every segment) =="
OUT_PARSED=$(parse_all run/station/archive/focl-out-adj-out)
echo "$OUT_PARSED"

echo "== the peer's networks arrive on the inbound view, and only there =="
echo "$IN_PARSED" | grep -q '192.0.2.0/24' || { echo "FAIL: ipv4 network the peer sent is missing from adj-in-pre"; exit 1; }
echo "$IN_PARSED" | grep -q '2001:db8:99::/48' || { echo "FAIL: ipv6 network the peer sent is missing from adj-in-pre"; exit 1; }
if echo "$IN_PARSED" | grep -q '203.0.113.0/24'; then
  echo "FAIL: adj-in-pre carries a network this daemon announced"
  exit 1
fi

echo "== our own networks are on the outbound view, and only there =="
echo "$OUT_PARSED" | grep -q '203.0.113.0/24' || { echo "FAIL: announced ipv4 network is missing from adj-out"; exit 1; }
echo "$OUT_PARSED" | grep -q '2001:db8:aa::/48' || { echo "FAIL: announced ipv6 network is missing from adj-out"; exit 1; }
if echo "$OUT_PARSED" | grep -q '192.0.2.0/24'; then
  echo "FAIL: adj-out carries a network the peer sent us"
  exit 1
fi

echo "== the reconnect produced a fresh table, not an empty session =="
# The station was restarted while the session stayed up, so its last session can only report routes
# if the daemon asked the peer to resend them. Segment names are no help here (a crash-recovery part
# can sort after the live one), so the station's own summary of that session is the evidence.
IN_BLOCK=$(grep -A5 '^client            focl-in$' run/station/bgpviews.log | tail -6)
echo "$IN_BLOCK"
echo "$IN_BLOCK" | grep -q 'records           4' || {
  echo "FAIL: the session created after the reconnect recorded no routes; the table was never resent"
  exit 1
}
echo "$IN_BLOCK" | grep -q 'end of rib        2' || {
  echo "FAIL: the resent table arrived without its End-of-RIB markers"
  exit 1
}
# Two connections for the inbound view means the station really did go away and come back.
[ "$(echo "$VIEWS_LOG" | grep -c 'accepted a connection from 127.0.0.1 for focl-in')" -ge 2 ] || {
  echo "FAIL: the inbound station never reconnected"
  exit 1
}

echo "== the station counted the End-of-RIB markers, the peer-down and no stray view on both =="
echo "$VIEWS_LOG" | grep -q 'client            focl-in' || { echo "FAIL: no adj-in-pre session in the log"; exit 1; }
echo "$VIEWS_LOG" | grep -q 'client            focl-out' || { echo "FAIL: no adj-out session in the log"; exit 1; }
# The End-of-RIB count for the inbound session is asserted above, on the session that came after the
# restart; here only the counts that every session must have.
[ "$(echo "$VIEWS_LOG" | grep -c 'unconfigured view 0')" -ge 2 ] || {
  echo "FAIL: a station counted frames that belong to the other direction"
  exit 1
}
[ "$(echo "$VIEWS_LOG" | grep -c 'peer_vanished')" -ge 1 ] || {
  echo "FAIL: no Peer Down reached a station"
  exit 1
}

echo "== bgpviews verify =="
"$VIEWS" verify --config run/station/bgpviews.toml
echo "PASS"
