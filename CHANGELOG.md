# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### New features

* **Runtime prefix control** - `focl prefix add|remove|list` announces or withdraws an originated prefix on the running daemon without restarting it or resetting any session. The effective set is (configured `[[prefixes]]` + runtime additions) minus runtime suppressions: `prefix remove` suppresses a configured prefix (a runtime-only one is dropped), `prefix add` announces it again and clears the suppression, and `prefix list` shows each prefix as `announced`/`suppressed` with a `config`/`runtime` source. Runtime overrides are in-memory only and are never written back to the config file. Address family is inferred from the prefix, `--next-hop` defaults to the configured next hop of the same family, `--dry-run` reports what would be sent without changing state, and `--json` prints the control response.
* **`focl reload` applies the config's prefix delta** - reload re-reads the config file, announces prefixes added since the last read, withdraws removed ones, and clears runtime overrides; the response reports the delta and how many overrides were reset. Peer and archive settings still require a restart.

### Code improvements

* Outbound route changes are dispatched to established sessions through a per-session channel, and the session loop now selects between that channel and the socket read on split read/write halves. Update encoding for both directions is shared with the establishment path (`emit_updates`).
* Session framing moved to a dedicated reader task: the session loop selects between control operations and incoming messages, and `read_exact` is no longer cancelled mid-message by an operation.
* A session is registered as a runtime-change target only after it is serving, and its negotiated address families travel with the registration, so dispatch and `--dry-run` targets name only the peers that can carry the update.
* Runtime prefix mutations are serialized with their dispatch, so two concurrent control clients cannot enqueue a withdrawal before the announcement it reverses.
* `prefix add` treats a next-hop change as a change (peers keep the old next hop until re-announced), a runtime entry shadows the configured entry for the same network, and the default next hop is taken from the config baseline only.
* A session registers for runtime changes under the same lock as its initial table send, so a mutation racing with establishment cannot leave the new session advertising a stale set. `prefix remove` reports `source: null` for a network the state never knew instead of labelling it `config`.
* Socket-level acceptance tests cover the runtime path: `prefix_add`/`prefix_remove` reach an established peer on the wire (announcement, withdrawal, session stays established) and a prefix is not dispatched to a peer that did not negotiate its family.
* `focl --json` output now exits non-zero on a failed response; `--json` changes formatting only.

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
