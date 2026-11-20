# BMP export: handing this daemon's sessions to a monitoring station

focl is a speaker, and a station is a collector. This document is about the wire between them:
focl dials a station, announces the peers it is monitoring, and forwards what those peers sent it,
as BMP version 3 (RFC 7854).

The station role is filled by [bgpviews](https://bgpviews.org): focl does not listen for BMP. That
split is deliberate. A station owns per-router identity, an archive transaction, a catalog and
recovery; a speaker owns sessions, announcements and a control socket. Putting the station inside
the speaker is how one daemon ends up with two writers on one archive root.

## What is exported

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

## Configuration

```toml
[bmp]
enabled = true
station = "203.0.113.20:1790"   # the station's address; focl dials
sys_name = "focl-edge01"       # what the station records as this feed's identity
stats_interval_secs = 60       # shorter than any idle timeout on the path
peers = ["edge-router"]        # optional: peer names or addresses; empty exports them all
queue_frames = 65536           # frames that may wait before the session is dropped
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
```

## What it does not do, and why

* **No table replay after a reconnect.** focl does not keep the raw PDUs of a peer's initial table,
  so a station that attaches while a session is already up receives Peer Up and then live changes.
  The interval before the reconnect is a hole, and the honest thing is to leave it visible: the
  station's own coverage record shows the peer without a baseline. Synthesising the table from
  focl's RIB would be worse than the hole, because the RIB holds only next hop, AS path and origin,
  and a station cannot tell a reconstructed path from an observed one.
* **No Adj-RIB-Out.** Our own announcements are archived locally with the `*_LOCAL` BGP4MP subtype;
  exporting them as BMP would need the `O` flag (RFC 8671) and a station-side view of its own.
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
