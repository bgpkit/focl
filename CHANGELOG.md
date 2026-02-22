# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

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
