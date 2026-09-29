# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Fixes

* **TCP-MD5 on the passive listener** - the per-peer keys are installed on the listening socket (Linux `TCP_MD5SIG`) before the accept loop, because the kernel validates the digest on the SYN and `accept()` never returns for a peer whose key is missing; the key is still applied to the accepted socket as well.
* **RFC 4271 hold time** - OPEN advertises the configured hold time unchanged (0 disables the timers instead of being raised to 3), the remote OPEN's hold time is taken into account (0 on either side disables the timers, otherwise the smaller value wins), and the keepalive and hold timers are driven by that negotiated value.
* **RFC 6793 AS4_PATH fallback** - a session that did not negotiate the four-octet AS capability now carries `AS_TRANS` in AS_PATH and the real local ASN in AS4_PATH instead of a truncated 2-octet AS_PATH.
* **RFC 2918 route refresh replay** - a received ROUTE-REFRESH for a negotiated family re-sends that family's Adj-RIB-Out followed by its End-of-RIB (the hold timer reset is unchanged); a refresh for a family the session does not carry is ignored, and the RFC 7313 BoRR/EoRR subtypes are not implemented.
* **End-of-RIB for a capability-less peer** - the IPv4 End-of-RIB decision now agrees with the announcement decision, so a plain RFC 4271 peer that negotiated no capabilities gets its IPv4 marker.
* **One initial table send** - the establishment table is sent exactly once, inside the registration critical section, with the End-of-RIB markers after it; the previous pre-lock send re-sent every copy after the EoR and archived it twice.
* The TCP-MD5 socket helpers are re-exported as `focl::bgp::{TcpSocketExt, TcpStreamExt}`.

### New features

* **Real peering collector (Phase 1)** - the established session loop no longer discards UPDATEs: raw frames go to the archive and parsed prefixes fill a per-peer Adj-RIB-In that `focl rib in` reads, cleared on session end. OPEN advertises MP-BGP IPv4 and IPv6 unicast plus four-octet AS (AS_TRANS on the wire for a 4-byte local ASN) and, when configured, route refresh; peer capabilities are parsed from the raw frame with negotiated families, ASN4 and route refresh tracked per session, and the remote ASN validated including AS_TRANS resolution. A peer that negotiates no capabilities still establishes plain IPv4 unicast. IPv4 prefixes are announced with classic NLRI and NEXT_HOP, IPv6 through MP_REACH_NLRI, and an invalid non-IPv6 configured next hop is rejected instead of malformed-encoded.
* **Global passive listener** - one bind of `global.listen_addr` serves every inbound connection; a connection is matched against the configured peers before any state change (unmatched ones are dropped with a log), TCP-MD5 is applied to accepted sockets, an inbound connection wins a collision with a simultaneous outbound attempt, and the active loop resumes once it ends.
* **Dual-stack archive with raw-frame passthrough (Phase 0)** - archive record types carry `IpAddr`/`IpNet` peers and prefixes, so both families share the update and RIB paths. An UPDATE is written as the original wire frame inside a `BGP4MP_MESSAGE_AS4` envelope instead of being parsed and re-encoded, preserving wire fidelity and unknown attributes. TABLE_DUMP_V2 groups IPv4 and IPv6 entries per (family, prefix) with snapshot-global sequence numbers and ADD-PATH subtypes when a path id is present. Dependencies move to `bgpkit-parser` 0.20 and `bzip2` 0.6, with a new `ipnet-trie` dependency.
* **Runtime prefix control** - `focl prefix add|remove|list` announces or withdraws an originated prefix on the running daemon without restarting it or resetting any session. The effective set is (configured `[[prefixes]]` + runtime additions) minus runtime suppressions: `prefix remove` suppresses a configured prefix (a runtime-only one is dropped), `prefix add` announces it again and clears the suppression, and `prefix list` shows each prefix as `announced`/`suppressed` with a `config`/`runtime` source. Runtime overrides are in-memory only and are never written back to the config file. Address family is inferred from the prefix, `--next-hop` defaults to the configured next hop of the same family, `--dry-run` reports what would be sent without changing state, and `--json` prints the control response.
* **`focl reload` applies the config's prefix delta** - reload re-reads the config file, announces prefixes added since the last read, withdraws removed ones, and clears runtime overrides; the response reports the delta and how many overrides were reset. Peer and archive settings still require a restart.
* **Attribute-255 clock on announcements** - a `[[prefixes]]` entry with `dev_attr255_interval_secs = N` attaches attribute 255 (reserved for development, RFC 2042) carrying a 13-byte BGPKIT clock payload (magic, version, refresh round, unix seconds) to that prefix's announcements, re-announced every N seconds. A runtime `prefix add` for a configured network keeps its clock, and an interval of 0 is rejected by config validation.

### Code improvements

* Outbound route changes are dispatched to established sessions through a per-session channel, and the session loop now selects between that channel and the socket read on split read/write halves. Update encoding for both directions is shared with the establishment path (`emit_updates`).
* Session framing moved to a dedicated reader task: the session loop selects between control operations and incoming messages, and `read_exact` is no longer cancelled mid-message by an operation.
* A session is registered as a runtime-change target only after it is serving, and its negotiated address families travel with the registration, so dispatch and `--dry-run` targets name only the peers that can carry the update.
* Runtime prefix mutations are serialized with their dispatch, so two concurrent control clients cannot enqueue a withdrawal before the announcement it reverses.
* `prefix add` treats a next-hop change as a change (peers keep the old next hop until re-announced), a runtime entry shadows the configured entry for the same network, and the default next hop is taken from the config baseline only.
* A session registers for runtime changes under the same lock as its initial table send, so a mutation racing with establishment cannot leave the new session advertising a stale set. `prefix remove` reports `source: null` for a network the state never knew instead of labelling it `config`.
* Socket-level acceptance tests cover the runtime path: `prefix_add`/`prefix_remove` reach an established peer on the wire (announcement, withdrawal, session stays established) and a prefix is not dispatched to a peer that did not negotiate its family.
* `focl --json` output now exits non-zero on a failed response; `--json` changes formatting only.
* Archive writers rotate on the ingestion clock only, so a record with a late or zero event timestamp stays in the current segment with its event time preserved in the MRT header, and a rollover with no routes no longer writes an empty RIB snapshot.
* The archive collector id and custom path templates are validated at config load: the id must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, templates reject absolute, backslash, control-character, empty and `..` components, and the rendered path is asserted to stay inside the archive root.

## v0.1.0 - 2025-02-21

### New features

* **Initial release of focl/focld** - A lightweight Rust-based BGP speaker built on BGPKIT libraries
  - `focld` - BGP speaker daemon for long-lived peer sessions and route exchange
  - `focl` - CLI frontend for control, inspection, and operational workflows

* **BGP Protocol Support**
  - IPv4 and IPv6 unicast support for static prefix announcements
  - Full BGP FSM implementation with proper state transitions (Idle → Connect → OpenSent → Established)
  - TCP-MD5 authentication (RFC 2385) for BGP session security on Linux
  - Active and passive peer connection modes
  - Route refresh capability negotiation
  - Configurable hold and keepalive timers
  - 4-octet ASN support

* **Configuration System**
  - TOML-based configuration with comprehensive validation
  - Per-peer configuration: AS number, timers, authentication, passive mode
  - Static prefix definitions with custom next-hop support
  - Support for multiple concurrent peers

* **Control Interface**
  - Unix Domain Socket (UDS) JSON/NDJSON protocol for CLI communication
  - CLI commands for daemon lifecycle: `start`, `stop`, `reload`
  - Peer inspection: `peer list`, `peer show`, `peer reset`
  - RIB inspection: `rib summary`, `rib in`, `rib out`

* **MRT Archival System**
  - Multiple layout profiles: RouteViews, RIPE RIS, and custom templates
  - Multiple compression formats: gzip, bzip2, zstd
  - Time-based file rotation with configurable intervals
  - SQLite-based replication queue for reliability
  - S3 and local replication destinations
  - JSON manifest sidecars with SHA256 checksums
  - Archive control commands: `archive status`, `archive rollover`, `archive snapshot`

* **Observability**
  - Structured logging with tracing
  - Configurable log levels (error, warn, info, debug, trace)
  - Peer state events and error tracking
  - Session establishment timestamps

### Testing

* Comprehensive test suite with 13+ unit tests
* GoBGP interoperability testing (basic session and MD5 authentication)
* Archive integration tests for MRT segment writing and manifest generation
* CI workflow with format checking, building, testing, and clippy linting

### Technical Details

* Built on bgpkit-parser for BGP message parsing and MRT encoding
* Async runtime using tokio with multi-threading support
* Actor-based peer isolation with independent FSM per peer
* Event-driven architecture with broadcast channels
* Platform-specific TCP-MD5 implementation using Linux socket options

### Platform Support

* **Linux**: Full feature support including TCP-MD5 authentication
* **macOS**: BGP speaker features (TCP-MD5 not supported)
* **FreeBSD**: BGP speaker features (TCP-MD5 not supported)

### Documentation

* README.md with quick start guide, configuration reference, and examples
* Example configurations: basic setup, dual-stack (IPv4/IPv6), production-style templates
* Interoperability test scripts for GoBGP
* Architecture and design documentation

### Known Limitations

* TCP-MD5 authentication requires Linux (RFC 2385 is Linux kernel-specific)
* No graceful restart capability yet
* No eBGP multihop support yet
* Policy framework not implemented (import/export filters)
* Only static prefix announcements (no dynamic routing)
