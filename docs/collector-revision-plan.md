# focl revision plan: the easiest way to run your own MRT archive

Revision 4 (2026-08-20). Addresses the delegated review (needs-rework
verdict: 3 blockers, 10 majors; see docs/review-2026-08-20.md). Direction:
focl is a **self-hosted BGP data
collector**, not a router. It ingests BGP data through two modes and archives
both into the same MRT pipeline that already exists:

- **BMP station mode** (primary for operators): focl listens on TCP, routers
  (Juniper, Cisco, Nokia, FRR, GoBGP) connect and stream monitoring data. No
  peering session, no policy risk, sees pre-policy Adj-RIB-In. This is usually
  the politically easy path inside an org.
- **BGP peering mode** (labs, VMs, research): focl speaks BGP itself and peers
  with a willing neighbor (transit, IX route server, another focl/GoBGP).

Both modes emit RouteViews/RIS-**compatible** MRT (`updates.*` + `rib.*`
— compatible naming and record types, not byte-identical provenance), so
every downstream BGPKIT tool (bgpkit-parser, monocle, Broker, bgp.fyi)
works on a private archive with zero glue. Segment manifests record source,
plane, completeness, timestamp source, and config version so consumers can
distinguish private archives from RV/RIS originals.

## Standing engineering rules (from review, apply everywhere)

1. **bgpkit-parser 0.20.0**, not 0.15. focl currently pins `bgpkit-parser =
   "0.15"`; latest is 0.20.0 (published 2026-08-16). 0.15 predates the
   fallible-encoder rework (UPDATE/OPEN `encode` now returns
   `Result<Bytes, EncodingError>` and takes `asn_len`), so the upgrade is also
   the moment to make focl's encode paths fallible everywhere (no
   `unwrap`/`expect` on encode). BMP module, TableDumpV2, BGP4MP encoding all
   come from the same upgrade. Parser 0.20 `parser` feature pulls chrono +
   regex + zerocopy; MSRV 1.87; dev-dep bzip2 moved to 0.6.
2. **ipnet-trie for all prefix storage.** Adj-RIB-In, RIB snapshots, future
   RPKI validation: use `ipnet-trie = "0.3"` (BGPKIT's own crate, built on
   prefix-trie 0.6, same `ipnet::IpNet` type focl already uses). One trie per
   peer; LPM lookup for monitoring/containment queries. No hand-rolled
   HashMap-of-prefixes.
3. **All archive cadence, location, and naming is config-driven.** The
   foundation already exists (`layout_profile = routeviews | ris | custom`
   with `{collector}/{yyyy}/{mm}/{dd}/{yyyymmdd}/{hhmm}/{ext}` templates,
   per-stream intervals, compression choice, root/tmp paths). What's missing
   is applying it consistently: BMP router identity must flow into
   `collector_id`, custom templates must not allow `..` or absolute paths
   (security guard), and every knob must be documented in the config
   reference.
4. **Built-in file-notification triggers.** When a segment finalizes, focl
   itself notifies downstream consumers. See Phase 3.

## Target architecture

```
                     ┌─ BMP listener (TCP :1790, per-router MD5, many routers)
feed sources ────────┤
                     └─ BGP speaker (existing FSM, per-peer sessions)
        │
        ▼  normalized UpdateRecordInput / PeerStateRecordInput (raw BGP bytes)
   ArchiveService (existing: rotation, compression, manifest, S3 + local replication)
        │
        ├─ on finalize → trigger dispatch (Phase 3)
        ▼
   updates.YYYYMMDD.HHMM.{gz,bz2,zst} / rib.YYYYMMDD.HHMM.*   ← standard MRT
        │
        ▼  downstream: monocle / broker / duckdb / S3 replication
```

Core refactor: introduce a `FeedSource` boundary. `BgpService` and the new
`BmpListener` both normalize into the archive input types
(BGP4MP_MESSAGE_AS4 / STATE_CHANGE_AS4 records). Neither source knows about
MRT; the archive knows nothing about BMP/BGP sessions.

## Phase 0 — foundations both modes need

1. **Dependency refresh.** `bgpkit-parser 0.15 → 0.20.0`, `bzip2 0.4 → 0.6`,
   add `ipnet-trie = "0.3"`. Fallible encode throughout; fix the
   `write_bgp_message` marker-fill path accordingly.
2. **Dual-stack archive records.** `UpdateRecordInput`,
   `PeerStateRecordInput`, `SnapshotPeer`, `SnapshotRoute` are IPv4-only
   (`Ipv4Addr` fields). Change to `IpAddr`; BGP4MP and TableDumpV2 encoding
   branches on family.
3. **IPv6 RIB snapshots.** `SnapshotRoute.prefix` is a bare `Ipv4Addr`; needs
   prefix + length + AFI/SAFI per RIB entry so TableDumpV2 v6 tables are
   valid. Group all RIB entries per (AFI/SAFI, prefix) into one
   `RibAfiEntries` record (multiple peer entries preserved), replacing
   one-record-per-route.
4. **Raw message passthrough.** Archive raw UPDATE bytes verbatim: a
   pass-through BGP4MP envelope encoder that writes peer/local metadata
   plus the original frame bytes unchanged. Parsed copies are for trie and
   state processing only, never the archive path. BMP gives raw bytes
   directly; for BGP sessions keep the original frame.
5. **Event-time discipline (from review blocker 3).** Record event time and
   archive partition/seal time are separate concerns:
   - MRT record timestamps use the event time (BMP PDU timestamp when
     nonzero, else receipt time with `timestamp_source = "arrival"` noted
     in the manifest).
   - Segments are partitioned by ingestion clock, not by per-record event
     time; a sealed segment's canonical path is never reopened. Late
     records land in the currently-open segment (event time preserved in
     the record) rather than reopening a sealed bucket.
6. **Golden-file round-trip tests.** Write MRT with focl, parse back with
   bgpkit-parser, assert element equality, v4 and v6; include unknown
   transitive attributes, MP_REACH/MP_UNREACH, four-octet AS path, and
   malformed-but-archivable frames.
7. **Path-template and collector-id hardening (from review major 13).**
   Custom templates and `collector_id` are validated before rendering:
   reject absolute paths, `..`, empty components, and characters outside a
   safe identifier charset. Containment is re-checked after rendering.

## Phase 1 — make BGP peering mode a real collector

1. **Adj-RIB-In store on ipnet-trie.** One trie per peer. Value model is
   `{interned attribute-blob id (u32), last_change_ts, path_id?}` — raw
   UPDATE bytes live only in MRT, never duplicated per prefix (fixes the
   review's inconsistent-representation finding). Memory-only v1 (rusqlite
   stays for the replication queue).
2. **Wire the archive.** Received UPDATEs → `ingest_update` (exists, never
   called); FSM transitions → `ingest_peer_state` (events already flow).
   Rx-only by convention (RouteViews/RIS never archive tx).
3. **Real RIB snapshots.** Dump adj-rib-in tries on the configured ribs
   interval as one collector snapshot (single peer-index table, entries
   grouped per prefix), replacing today's empty snapshot. **No RIB file is
   emitted before a valid baseline exists** (fixes empty-dump bug). Pre-
   policy semantics (`adj_rib_in` is already the config default).
4. **Capability negotiation.** Advertise and validate the intersection of
   locally configured and peer-advertised capabilities: MP-BGP v4+v6,
   route-refresh, AS4, extended-message, graceful-restart behavior, and
   per-AFI/SAFI ADD-PATH policy. A capability-less OPEN establishes plain
   IPv4 BGP; what it cannot do is IPv6/MP-BGP sessions — that is the real
   gap (corrects review major 6). UPDATEs enter the trie only after
   negotiated AFI/SAFI is known.
5. **Global passive listener** with per-peer match before any state
   mutation, connection-collision handling, separate v4/v6 bind
   configuration, and rejected-connection observability; replacing
   per-peer binds; the `listen` global config becomes real.
6. **Interop expansion.** Extend the GoBGP scripts: v6 session, capability
   matrix, flap → assert MRT files parse and contain expected elements.
   Negative tests (review minor 16): malformed UPDATE disposition, Peer
   Down clears the peer's trie, interrupted EoR yields no complete dump,
   duplicate Peer Up starts a new generation.

## Phase 2 — BMP station mode

1. **`BmpListener`** on a configurable port per station; per-router
   TCP-MD5 (TCP-AO is a documentation-level non-goal for v1; focl
   implements TCP-MD5 only); accept many routers concurrently. Parsing via
   bgpkit-parser 0.20's BMP module.
2. **Feed key (from review blocker 1).** Every route-monitoring feed is
   keyed by a canonical `BmpFeedKey`:
   ```
   router identity (trusted, from connection/matching)
   + BMP connection generation
   + peer type (Global | RD | Local | Local-RIB)
   + peer_distinguisher + peer_ip + peer_asn + peer_bgp_id
   + plane {pre_in | post_in | adj_out | local_rib}   // L and O flags
   + AFI/SAFI
   ```
   v1 accepts only `pre_in` (pre-policy Adj-RIB-In) by default; other
   planes are either rejected with a diagnostic or archived under
   separately named views (config), never merged. No feed is called
   "Adj-RIB-In" unless its flags say so.
3. **Feed lifecycle (from review major 4).**
   - `PeerUp`: new connection generation, parse both OPENs, record
     capabilities (incl. per-AFI/SAFI ADD-PATH policy), initialize walks
     for negotiated AFI/SAFIs.
   - `PeerDown`: implicit full withdraw for that feed — invalidate the
     generation, clear its trie, drop its routes from future snapshots;
     optionally archive a derived STATE_CHANGE with the reason code.
   - `Termination` / TCP EOF: all feeds on that connection become
     unavailable and all incomplete walks are invalid.
   - `RouteMirroring(MessageLost|ErroredPdu)`: mirrored data is
     diagnostic + archived raw; it never rebuilds a route-monitor trie.
     Mark feed completeness broken until a new RM baseline walk.
   - STATE_CHANGE records are synthetic mappings (Idle↔Established),
     documented as such, not native BMP FSM events.
4. **Snapshot coordinator (from review blocker 2).** Per router: track
   eligible feeds from PeerUp and EoR completion per feed × AFI/SAFI.
   Freeze all selected tries into **one** collector RIB segment (one
   peer-index table; entries grouped per (AFI, SAFI, prefix); multiple
   peer paths per prefix preserved) on: all-eligible-complete, or timeout
   with manifest-declared partiality, or a configured subset. No periodic
   RIB file until each included feed has a valid baseline.
5. **PDU mapping:**
   - Route Monitoring (pre_in) → feed trie + snapshot coordinator
   - Route Mirroring → raw updates stream + diagnostics
   - Peer Up/Down → feed lifecycle + optional STATE_CHANGE records
   - Stats Reports → operational counters (Prometheus, ops-only)
   - Init Message → operational metadata only; never trusted for
     filesystem identity or `collector_id`
6. **Peer identity.** One `collector_id` per router, mapped from trusted
   config (`[[bmp.routers]]` entry matched by source address/identity),
   not from untrusted BMP Init sysName. Keeps layout identical to RV/RIS
   and downstream tooling unchanged; `view_name` stays "main".
7. **ADD-PATH guard (from review major 5).** When a feed negotiated
   ADD-PATH receive, v1 either keys tries by `(prefix, path_id)` and
   writes `*_ADD_PATH` TableDumpV2 records, or degrades that feed to
   `ribs_mode = off` with raw updates retained, with an operator-visible
   status (`archive_raw=yes, derived_rib=no, reason=add_path_unsupported`).
8. **Event-time discipline** per Phase 0 rule 5: PDU timestamps are record
   event times; partition/seal uses the ingestion clock; zero timestamps
   fall back to arrival time and are marked in the manifest.
9. **Tests from captured BMP streams** (fixture corpus) → golden MRT
   output, including delayed/reordered PDUs, zero timestamps, Peer Down
   mid-walk, Termination mid-walk, duplicate PeerUp, and both-planes
   streams (must not merge).

## Phase 3 — "easiest setup" UX and file triggers

1. **Trigger mechanism on segment finalize.** ArchiveService already emits
   `ArchiveSegmentFinalized` events; formalize dispatch:
   - `exec` triggers: run a command with the finalized path, sha256, size,
     and record count passed as env vars and JSON on stdin. Built-in example
     recipes: POST to a webhook, move/copy, publish to SNS/SQS.
   - Config: `[[archive.triggers]]` with `stream = "updates" | "ribs" | "both"`.
   - **Delivery records (from review major 12):** per-trigger durable
     records keyed by (segment checksum, trigger id, attempt) with states
     `pending / running / acknowledged / unknown`. Exit 0 = acknowledged;
     crash before state write = `unknown`, which is retriable. Delivery is
     at-least-once, documented as such; never exactly-once.
   - **Completion policy:** `local_finalized` (default), `all_required`
     (every primary+required destination acked), or a named destination
     set. Replication events are per-destination today; the trigger
     dispatcher aggregates them per segment.
   - `focl trigger list` / `focl trigger test` CLI for inspection.
2. `focl init` wizard: pick mode, answer 4 questions, get a working TOML.
3. `focl doctor`: reachability, MD5 mismatch detection, session watch,
   first-archive-file check by parsing it back with bgpkit-parser.
4. `focl tail`: live NDJSON of archived elements (extend `events_subscribe`
   to updates).
5. Docker image: `docker run -p 1790:1790 -v $PWD/data:/data focl --bmp`
   one-liner; compose example with S3 replica and a trigger example.
6. Docs: copy-paste BMP stanza snippets for Juniper/Cisco/FRR/GoBGP, plus
   peering snippets for BIRD/GoBGP. Document every archive knob.

## Phase 4 — differentiators (later, on demand)

- RPKI validity computed at ingest (ipnet-trie LPM over ROA VRPs) and stored
  alongside elements
- Live streaming mode (BMP → websocket, ris-live-like) for real-time feeds
- Broker-compatible index publication so internal discovery uses the same
  API as public collectors
- ADD-PATH / graceful restart as real deployments require them
- `focl announce` lab features stay, but are not the product

## RIB dumps from a BMP stream (design, revised)

RIB and updates are different products and are treated differently
end-to-end: separate config (`ribs_mode`, `ribs_interval_secs`), separate
files, separate memory policy.

RIB dumps under BMP are **derived, not received**. BMP route-monitor PDUs
arrive as a walk of the router's RIB; a dump file must be assembled from the
stream — assembled by the per-router **snapshot coordinator** (Phase 2 item
4), not per-peer EoR writes. Design:

1. **EoR-triggered baseline (v1).** Per feed (canonical feed key): start an
   empty ipnet-trie at the first Route Monitoring PDU, insert routes until
   End-of-RIB marker per AFI/SAFI. When the coordinator's policy is
   satisfied (all eligible feeds complete, or timeout with declared
   partiality), freeze all tries into one collector TableDumpV2. This is
   the standard way monitor tables are materialized; focl's output is
   RV/RIS-**compatible**, not provenance-identical.
2. **Trie-maintained dumps (v2 default, `ribs_mode = "trie"`).** Keep the
   trie hot after the walk, apply subsequent updates (announce/withdraw) as
   they arrive, dump all tries via the coordinator on each
   `ribs_interval_secs` boundary — one collector snapshot, not per-peer
   files. Memory cost is the trie; storage cost is one dump per interval.
3. **Initial-only (`ribs_mode = "initial-only"`).** Dump the EoR snapshot,
   drop the trie, stream updates only. Near-zero steady-state memory; RIB
   snapshots then exist only at session start.
4. **Rebuild markers.** Mirroring PDUs or post-policy re-walks can
   invalidate trie state; emit a diagnostic event and re-walk rather than
   emitting a silently wrong dump. Peer Down invalidates the feed's
   generation entirely (implicit full withdraw). A dump is always
   internally consistent (single freeze point); it may be partial if the
   walk was interrupted, and the manifest says so.
5. **RIB retention is a config decision**, because dump frequency dominates
   storage: 2 h dumps ~ 900 MB/day/peer vs 24 h ~ 76 MB/day/peer (bz2, full
   feed). `retention_days` prunes local files after replication; remote
   retention is the destination's concern (e.g. R2 lifecycle rules).

## Scale engineering: fleet of routers, bounded memory (new)

Goal: many hundreds of concurrent writers (BMP sessions and peers) on one
box. Anchors: ~950k v4 + ~200k v6 routes per full feed; RV2 rib file 76 MB
bz2; naive in-memory full-table representation is 150-250 MB/peer and does
not scale to a fleet. Strategy, in order:

1. **Per-peer trie, interned values (default).** Value stored per prefix =
   `u32` attribute-blob id, not bytes. A process-wide interner dedups
   attribute sets (AS path, communities, etc.) across peers; similar feeds
   share blobs. Expected 60-120 MB per full-feed peer vs 150-250 MB naive,
   plus ~50-100 MB process-wide. Trie nodes themselves are compact
   (prefix-trie uses bit-path nodes, ~10-15 B/node region).
2. **Storage-for-memory trades.**
   - `ribs_mode = initial-only` removes the hot trie entirely.
   - **Spill-to-disk for cold peers.** When process RSS crosses a soft
     watermark (e.g. 70% of a configured budget), evict the
     least-recently-dumped peer's trie. The spilled state is an immutable
     point-in-time snapshot; it is never updated in place. Reload paths,
     pick by cost:
     - baseline: re-materialize from focl's own archive (last RIB dump +
       updates MRT since then). Zero new formats, replay uses the same
       parser we ship, and correctness of reload doubles as a round-trip
       test. Reload cost is a full parse.
     - fast path (optional, later): rkyv zero-copy image of the frozen
       trie for mmap-speed reload, same pattern as BGPKIT's static ROA
       serving. rkyv is strictly for static data here: churn since spill
       is replayed from the updates log into a fresh in-memory trie; the
       image is never mutated or re-serialized per change.
     Spill only pays for cold peers; hot peers stay in RAM or degrade to
     updates-only. If a genuinely mutable on-disk trie is ever required
     (continuous disk-backed updates), that is an LMDB-shaped problem,
     not rkyv.
   - **Log-structured updates:** updates are append-only and never need a
     trie to be archived; under memory pressure a peer can run updates-only
     (RIB dumps degraded or disabled) without data loss.
3. **Shard by router, not by prefix.** One archive service per BMP router
   (`collector_id` per router) keeps writers independent: no cross-router
   locks, per-router rotation, per-router S3 prefixes. Global process
   coordination is limited to the interner and the replication queue.
4. **Writer architecture.** Bounded mpsc channels per router -> single
   writer task per router (SegmentWriter is already single-writer per
   segment; compression already streams). **Backpressure (from review
   major 8):** writers receive via `recv().await` on bounded channels;
   senders use `send().await`, which suspends the per-connection read loop
   when the channel is full — the TCP receive window closes and the
   router's send buffer fills (a stall, not a retransmit promise). On
   connection loss, parser error, queue abort, or Route Mirroring
   `MessageLost`, increment durable counters, mark the feed's generation
   incomplete, and require a new Peer Up + EoR baseline before derived
   RIBs resume. Overload limits (max channel capacity per router) are
   config; exceeding them is an operator-visible degradation, never a
   silent drop. The acceptor loop is never blocked.
5. **Spill durability (from review major 9).** Spill is Phase 3 and
   requires a per-router replay manifest first: baseline RIB path +
   checksum, feed key + generation, update segment range (sealed segments
   only — an open compressed segment is not a valid replay input), seal
   watermark, pin count. Retention must not prune pinned replay ancestry.
   Updates are durable before eviction (seal the current segment on spill,
   or WAL). The rkyv image, if ever built, is cache acceleration only.
6. **Parquet as a derived tier (optional).** MRT stays the interchange
   format. A trigger-invoked converter (or `focl parquet` subcommand) turns
   finalized MRT into sorted, dictionary+delta-encoded Parquet (per peer or
   per day) for DuckDB analytics. This trades storage (Parquet of BGP elems
   is typically smaller than bz2 MRT for scans) for one more pipeline stage,
   and keeps DuckDB off the hot path. Ship as an example trigger recipe
   first, promote to built-in if it proves out.
7. **Config guardrails for fleets.** `max_peers`, `memory_budget_mb` (soft
   watermark driving spill), `retention_days`, per-router `ribs_mode`
   override. `focl status` reports per-peer RSS estimate, trie sizes,
   writer backlog, and projected storage/day so operators can see the
   trade before it bites.
8. **Memory numbers are estimates until measured (review major 10).** The
   trie value model is fixed (`{attribute_id: u32, last_change_ts,
   path_id?}`); the 60-120 MB/peer interned figure and fleet rows are
   planning estimates. A benchmark gate (captured v4+v6 full feeds) must
   run before any fleet sizing table is quoted as fact: measure trie RSS,
   intern-table cardinality, attributes/prefix, churn, queue high-water,
   cold-reload time. Published tables get ranges by workload, not linear
   promises.

Sequencing within the plan: interned tries land with Phase 1/2 (they are the
adj-rib-in store); spill-to-disk and Parquet tier are Phase 3/4, driven by
measured fleet numbers, not speculation. Sizing tables users can quote live
in `docs/examples.md`.

## Non-goals (explicit)

- No routing policy framework, best-path selection, or FIB programming.
  focl archives; it does not forward or decide.
- Not competing with BIRD/FRR/GoBGP as a router. GoBGP remains the interop
  reference implementation.
- No OpenBMP protocol integration; direct BMP only.

## Sequencing rationale

Phase 0 first because both modes write through the same record types; fixing
v6, raw bytes, and the parser upgrade once serves both. Phase 1 before Phase
2 because it forces the normalized update path and the ipnet-trie adj-rib-in
store into existence, which BMP then reuses wholesale. Phase 2 is the
operator wedge (every real router speaks BMP; config is one stanza; no
peering approval needed). Phase 3 turns "works" into "easiest", which is the
stated product goal, and the trigger mechanism is what makes the archive a
platform other tools can build on.

## Open design decisions

1. Raw-bytes passthrough: BMP gives raw UPDATE bytes directly; for BGP
   sessions, archive the original frame bytes via the pass-through BGP4MP
   envelope (Phase 0 item 4). Confirm no parser changes needed.
2. Adj-RIB-In persistence: memory + periodic MRT dump only, or SQLite-backed?
   Recommendation: memory-only v1; spill = frozen snapshot + updates-log
   replay (own MRT baseline, optional rkyv image) gated on the Phase 3
   replay-manifest contract. No on-disk mutable trie unless fleet numbers
   demand it.
3. BMP router identity: one collector_id per router (recommended), resolved
   from trusted `[[bmp.routers]]` config matched by source identity —
   never derived from untrusted BMP Init sysName.
4. BMP listener MD5: yes (focl implements Linux TCP-MD5 today; TCP-AO is
   not implemented and stays out of v1 docs).
5. Trigger delivery semantics: at-least-once with durable per-trigger
   delivery records (pending/running/acknowledged/unknown); exec exit 0 =
   acknowledged; `unknown` retriable. Document clearly, don't pretend
   exactly-once.
6. RIB dump policy under BMP: `ribs_mode` default. Recommendation: `trie`
   for small fleets, `initial-only` above ~50 full-feed peers unless
   `memory_budget_mb` allows more; decide from Phase 2 measurements.
7. Interner eviction: LRU with weak-handle resurrection, or generational
   (rebuild per dump cycle)? Decide in Phase 1 implementation.
