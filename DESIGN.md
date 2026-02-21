# focl / focld

*A lightweight, Rust-based BGP speaker built on BGPKIT*

---

## 0. Clear Summary (Implementation Baseline)

**What we are building now**

* `focld`: a Rust BGP daemon for long-lived peer sessions and route exchange.
* `focl`: a CLI for control, inspection, and operational workflows.
* Architecture: daemon/CLI split, actor-based peer isolation, UDS JSON control plane.

**Phase 1 scope (must be true before expansion)**

* IPv4 unicast, static prefix announce/withdraw.
* Full peer FSM and timer correctness (hold/keepalive).
* Interop-tested with FRR, BIRD, and GoBGP.
* Deterministic observability and basic RIB inspection.

**How `bgpkit-parser` is used**

* Primary use: UPDATE/attribute parsing and MRT injection pipeline.
* Data model reuse: BGP message/capability structs where practical.
* Not delegated: strict wire behavior for live sessions.

**What `focld` owns directly**

* TCP stream framing and strict message boundary enforcement.
* Session-level message handling and capability state.
* Wire-safe encode/decode path for OPEN/KEEPALIVE/NOTIFICATION/ROUTE-REFRESH.

This keeps the project simple while avoiding hidden protocol risk in live-speaker operation.

---

## 1. Project Vision

**focld** is a modern, lightweight BGP speaker written in Rust.
**focl** is its CLI frontend.

The goal is to build:

* A minimal, standards-compliant BGP speaker
* Built on top of `bgpkit-parser`
* Interoperable with FRR, BIRD, GoBGP
* Cleanly architected using an actor model (Actix)
* Designed for experimentation, simulation, and research
* Simple first, extensible later

This is not meant to replace FRR/BIRD.
It is intended as:

* A programmable BGP engine
* A clean reference implementation
* A research and experimentation platform
* A modern Rust-native BGP stack

---

## 2. Naming Philosophy

* **focl** — decision point, route convergence
* **focld** — long-running daemon
* **focl lens** — extensible inspection layer (read-only views, transforms)
* **monocle** — observation / analysis tool (existing project)

Optics metaphor consistency:

* monocle → observer
* focl → decision engine
* lens → inspection layer

---

## 3. High-Level Architecture

```
             +--------------------+
             |        focl        |
             |   CLI frontend     |
             +---------+----------+
                       |
                       | IPC (UDS)
                       |
             +---------v----------+
             |        focld       |
             |  BGP speaker daemon|
             +--------------------+
```

### focld responsibilities

* Manage BGP sessions
* Maintain Adj-RIB-In / Adj-RIB-Out
* Store configured prefixes
* Handle route injection (MRT, static)
* Emit events
* Provide control API

### focl responsibilities

* Configuration validation
* Status inspection
* Trigger control commands
* Stream logs/events
* Invoke lenses

---

## 4. Internal Architecture (Actix Actor Model)

Each BGP peer and subsystem is modeled as an actor.

### Core Actors

#### PeerActor (one per neighbor)

Owns:

* BGP FSM (Idle → Established)
* TCP session
* Capability negotiation
* Timers (keepalive, hold)
* Adj-RIB-In / Adj-RIB-Out

Handles:

* OPEN
* UPDATE
* KEEPALIVE
* NOTIFICATION

---

#### IoActor (optional split)

Owns:

* TCP framing
* Raw read/write
* Backpressure management

Keeps network IO separate from protocol logic.

---

#### RibActor

Owns:

* Route storage
* Lookup
* Diff logic
* Route injection
* Export decisions

---

#### ConfigActor

Owns:

* Parsed config
* Runtime reload
* Prefix definitions

---

#### EventBusActor

Optional:

* Emits structured events
* Supports streaming subscribers

---

## 5. BGP Protocol Scope (Phase 1)

Initial implementation:

* IPv4 unicast
* 4-octet ASN capability
* Route refresh capability negotiation and soft-reset workflow
* Static prefix announcements
* Full-session FSM compliance
* Proper hold/keepalive timers
* UPDATE parsing and attribute handling via bgpkit-parser
* Strict wire framing/validation in focld session layer

Not included initially:

* Route selection engine
* Policy framework
* Route reflection
* Multiprotocol (IPv6)
* Add-Path
* BMP

---

## 6. Use of bgpkit-parser

We reuse:

* `BgpUpdateMessage`
* Attribute parsing
* Encoding functionality
* Capability structures (where applicable)

We implement:

* TCP framing
* FSM transitions
* Timers
* Route storage logic
* Session capability state and wire-level safety checks
* Route-refresh message handling in live sessions

Practical boundary:

* `bgpkit-parser` is the parsing foundation for UPDATE + MRT workflows.
* `focld` remains the source of truth for live session wire correctness and interop behavior.

---

## 7. Configuration Model

Configuration via TOML (serde-based).

Example:

```toml
[global]
asn = 65001
router_id = "192.0.2.1"
listen = true

[[peers]]
address = "198.51.100.2"
remote_as = 65002

[[prefixes]]
network = "203.0.113.0/24"
```

Goals:

* Simple
* Static first
* Reloadable
* No complex policy initially

---

## 8. CLI Surface

### Daemon control

```
focl start -c focl.toml
focl stop
focl reload
```

### Peer inspection

```
focl peer list
focl peer show 192.0.2.2
focl peer reset 192.0.2.2 --soft
```

### RIB inspection

```
focl rib summary
focl rib in 192.0.2.2
focl rib out 192.0.2.2
```

### Injection

```
focl announce 203.0.113.0/24
focl withdraw 203.0.113.0/24
focl rib inject routeviews.mrt
```

### Lenses

```
focl lens list
focl lens attrs 203.0.113.0/24
focl lens aspath 203.0.113.0/24
focl lens diff --from A --to B
```

---

## 9. CLI ↔ Daemon Communication Strategy

### Chosen initial design

**Unix Domain Socket + JSON protocol (NDJSON)**

Reasons:

* Matches BIRD model
* Minimal dependencies
* Easy debugging
* Supports streaming
* Low implementation overhead
* Fast iteration

Example message:

```json
{"cmd":"peer_list"}
```

Response:

```json
{"type":"peer","addr":"192.0.2.2","state":"Established"}
```

Streaming:

```
{"event":"peer_state","peer":"192.0.2.2","state":"Established"}
{"event":"update_count","peer":"192.0.2.2","received":1000}
```

Future migration path:

* Upgrade to gRPC over UDS if API stabilizes
* Keep internal actor boundaries unchanged

We avoid premature complexity.

---

## 10. Interoperability Targets

Test matrix:

* FRR
* BIRD
* GoBGP
* ExaBGP (optional)

Validation goals:

* Session establishment
* Capability negotiation
* Route advertisement
* Route reception
* Soft reset via route refresh (handled in focld session/wire path)

---

## 11. Development Phases

### Phase 1 — Minimal Speaker

* Static config
* One peer
* Session up
* Announce static prefix
* Strict message framing and baseline wire validation

### Phase 2 — Multi-peer

* Multiple concurrent sessions
* Independent FSM per peer

### Phase 3 — Injection

* MRT replay via bgpkit-parser
* Rate limiting
* Progress streaming

### Phase 4 — Lenses

* RIB inspection framework
* Attribute analysis
* Diff tooling

### Phase 5 — Policy Engine

* Import/export filters
* Community manipulation
* Route selection logic

---

## 12. Are We Overcomplicating?

Current scope:

* Daemon + CLI separation
* Actor model
* Unix socket control plane
* bgpkit-based parsing

This is aligned with:

* BIRD (socket CLI)
* FRR (daemon + CLI)
* GoBGP (API-first control)

We are **not** overcomplicating because:

* BGP is inherently long-lived and stateful.
* Session management benefits from isolation.
* Actor model maps cleanly to peer-based design.
* IPC separation prevents coupling CLI to core engine.

What we intentionally avoid:

* Distributed message bus
* Early gRPC complexity
* Multi-process routing core
* Premature policy engine

The design is modern but restrained.

---

## 13. Long-Term Vision

focld becomes:

* A programmable BGP engine
* A research platform
* A simulation environment
* A controllable injection engine
* A companion to monocle

Possible extensions:

* BMP exporter
* Route analytics module
* RPKI validation integration
* gRPC control API
* Web UI

---

## 14. Core Principles

* Minimal but correct
* Observable
* Deterministic
* Modular
* Standards-compliant
* Rust-native
* Extensible

---

# Summary

focl/focld is:

* A modern Rust BGP speaker
* Built with bgpkit-parser for parsing-heavy workflows
* Actor-driven
* CLI-controlled
* Unix-socket managed
* Designed for experimentation and interoperability
* Explicit about wire/session ownership in focld
* Simple at first, extensible by design

---
