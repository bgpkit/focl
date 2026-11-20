# BMP export: handing this daemon's sessions to a monitoring station

focl is a speaker, and a station is a collector. This document is about the wire between them:
focl dials a station, announces the peers it is monitoring, and forwards what those peers sent it,
as BMP version 3 (RFC 7854).

The station role is filled by [bgpviews](https://bgpviews.org): focl does not listen for BMP. That
split is deliberate. A station owns per-router identity, an archive transaction, a catalog and
recovery; a speaker owns sessions, announcements and a control socket. Putting the station inside
the speaker is how one daemon ends up with two writers on one archive root.

## What is exported

A station records one view per connection, so each direction of the same session is its own
`[[bmp.stations]]` entry: what the peers sent us (Adj-RIB-In) and, if you ask for it, what we sent
them (Adj-RIB-Out, RFC 8671).

Per live peer, and only this:

* **Peer Up** when the session reaches Established, carrying both OPEN PDUs exactly as they crossed
  the socket, plus the local address and both TCP ports. A station derives the peer's address
  families, BGP identifier and add-path negotiation from those OPENs.
* **Route Monitoring** for every inbound UPDATE, verbatim. The PDU keeps its own 19-byte BGP header
  and is never re-encoded: an encoder that rebuilt it from parsed fields would drop every attribute
  this build does not model. The End-of-RIB markers travel the same way, which is what tells the
  station a peer's initial table finished.
* **Peer Down** when the session stops being Established (RFC 7854 reason 4, "the remote system
  closed without a notification", which covers an unexpected transport end). Without it a station
  keeps reporting the last table it knew, which reads as a quiet peer rather than a lost session.
* **Statistics Report** with no counters, on a timer. BMP has no keepalive and no hold timer, so this
  is the only thing that distinguishes a silent daemon from a dead socket.

Everything is per-peer pre-policy Adj-RIB-In: focl applies no import policy, so the `L` flag is never
set. The `V` flag follows the peer's address family, and the `A` flag follows the session's own
AS_PATH width, because a station reads the AS_PATH using that flag and a wrong one misreads every
path.

On a `rib_out = true` connection the same frames describe the other direction: every UPDATE we
send a peer, one frame per peer, flagged `O` (RFC 8671) so the station knows the peer fields mean
"the peer this was sent to", and `L` because the PDU is exactly what went out (focl applies no
outbound policy, so its Adj-RIB-Out is already post-policy). Peer Up, Peer Down and Statistics
Reports keep `O` clear: RFC 8671 has receivers ignore it there and requires it zero on a
Statistics Report.

## Reconnecting: the station asks, the peer answers

A station that attaches while sessions are already up has no baseline: the tables it would have
recorded arrived before it was listening, and focl kept no copy of them. Rather than spooling every
PDU in case that happens (which duplicates the archive inside the daemon, and would have to reach
back to session start to be correct), focl asks the peers for their tables again: one ROUTE-REFRESH
per family (RFC 2918), whose answer arrives as ordinary UPDATEs and is forwarded verbatim, End-of-RIB
included.

* It happens when a station connects and at least one peer is already established, which is exactly
  the case with no baseline.
* It needs route refresh negotiated in both directions; a peer that never offered it is not asked,
  because a request nobody answers leaves the station waiting for a table that is not coming.
* It is rate limited per peer (`[bmp].redump_cooldown_secs`, default 300 s): a station in a
  reconnect loop must not be able to make this daemon pull a full table from every peer each time.
* It applies to inbound connections only. An Adj-RIB-Out connection describes what this daemon sends
  and has no table to rebuild, so pairing it with `redump_on_connect` is a configuration error.

The cost is one table transfer per reconnect event. For a peer with a full table that is tens of
megabytes; the alternative, a station with no baseline for that peer, cannot be repaired later
because BMP has no way to ask for a table after the fact.

## Configuration

```toml
[bmp]
enabled = true
sys_name = "focl-edge01"       # what the station records as this feed's identity
stats_interval_secs = 60       # shorter than any idle timeout on the path
queue_frames = 65536           # frames that may wait before the session is dropped
redump_cooldown_secs = 300     # shortest interval between two table requests for one peer

# What the peers sent us.
[[bmp.stations]]
address = "203.0.113.20:1790"   # the station's address; focl dials
peers = ["edge-router"]        # optional: peer names or addresses; empty exports them all
# redump_on_connect = true     # default: ask peers to resend when this station attaches late

# What we sent them. A separate connection, because the station records one view per port.
[[bmp.stations]]
address = "203.0.113.20:1791"
rib_out = true
```

The station side, for a `bgpviews.toml`:

```toml
[[clients]]
name = "focl"
listen = "203.0.113.20:1790"
allow_from = ["198.51.100.10/32"]   # the daemon's source address; BMP has no authentication
feed = "bmp"

[clients.view]
name = "adj-in-pre"
updates_interval_minutes = 1

[[clients]]
name = "focl-out"
listen = "203.0.113.20:1791"
allow_from = ["198.51.100.10/32"]
feed = "bmp"

[clients.view]
name = "adj-out"
updates_interval_minutes = 1
```

## What it does not do, and why

* **No synthesized tables.** focl never rebuilds a table from its RIB for a station: the RIB holds
  only next hop, AS path and origin, and a station cannot tell a reconstructed path from an observed
  one. When a table is needed again it is asked for on the wire, as "Reconnecting" describes.
* **No pre-policy Adj-RIB-Out.** The `L` flag is always set on an outbound frame because focl
  transmits everything it builds, so there is no pre-policy stage to describe.
* **No Route Mirroring, no add-path marking.** The station decides what it can accept from the
  OPENs it is given.
* **No authentication.** RFC 7854 defines none: the credential is the source address, which the
  station allowlists. Keep the path private (a tunnel or a management network) or the feed is
  writable by anyone who can reach the port.

## Failure behaviour

* **A station that cannot keep up.** Frames are handed over with a non-blocking send. A full queue
  ends the connection instead of blocking a BGP session, so the station records a gap and the
  sessions keep running. Dropping frames quietly, or stalling the session, would hide the same
  problem in a place nobody can see.
* **A station that is down.** The exporter retries with a 1 s backoff doubling to 30 s, and the BGP
  sessions are unaffected.
* **A daemon that is stopped.** The connection closes; the station publishes what it holds and
  marks the interval partial.

## Proving it

`scripts/lab/bmp_export.sh` runs the whole chain on loopback: one focld originates two networks (one per
address family), a second focld is its peer and exports the session, and a real `bgpviews` listens,
archives and verifies. The pass conditions are the station's own counters (four records, two
End-of-RIB markers, a Peer Down) and the parsed archive, which must contain both networks with the
originator's AS in the path.
