# focl / focld

![logo](./assets/focl-logo.png)

A lightweight, Rust-based BGP speaker built on [BGPKIT](https://bgpkit.com/) libraries.

The project consists of:

- **focld** - The BGP daemon that manages peer sessions and route exchange
- **focl** - CLI frontend for controlling and monitoring the daemon

> ⚠️ **EXPERIMENTAL SOFTWARE - NOT FOR PRODUCTION USE**
>
> This project is currently in early development and is intended for:
> - Research and experimentation
> - Testing and simulation environments
> - Demonstrating BGPKIT library capabilities
>
> **Do not use in production networks.** The codebase lacks comprehensive testing,
> security hardening, and operational features required for production BGP deployments.
> For production use, consider established solutions like BIRD, FRR, or GoBGP.

## Features

### Current (Phase 1)

- [x] IPv4 and IPv6 unicast support
- [x] TCP-MD5 authentication (RFC 2385) for BGP session security
- [x] TCP-AO authentication (RFC 5925) for BGP session security
- [x] Static prefix announcements
- [x] Runtime prefix announce/withdraw via `focl prefix` (in-memory overrides)
- [x] Full BGP FSM with proper timers (hold/keepalive)
- [x] Active and passive peer modes
- [x] Route refresh capability
- [x] MRT archive support (BGP4MP, TableDumpV2)
- [x] S3 and local replication destinations
- [x] CLI control via Unix Domain Socket

### In Progress / Planned

- [ ] Graceful restart capability
- [ ] eBGP multihop support
- [ ] Import/export policy framework
- [ ] Blackhole route support
- [ ] BMP exporter
- [ ] RPKI validation integration

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/bgpkit/focl.git
cd focl

# Build
cargo build --release

# Install binaries (optional)
cargo install --path .
```

### Basic Configuration

Create `focl.toml`:

```toml
[global]
asn = 65001
router_id = "192.0.2.1"
listen = true
listen_addr = "0.0.0.0:179"
control_socket = "/tmp/focld.sock"
log_level = "info"

[[peers]]
name = "upstream"
address = "192.0.2.2"
remote_as = 65002
remote_port = 179
hold_time_secs = 90
password = "secretpassword"  # Optional: TCP-MD5 authentication

[[prefixes]]
network = "203.0.113.0/24"
next_hop = "192.0.2.1"

[archive]
enabled = false
```

### Running

```bash
# Start the daemon
focld --config focl.toml

# Or using cargo
cargo run --bin focld -- --config focl.toml

# Control commands
focl peer list
focl peer show 192.0.2.2
focl rib summary
focl rib out 192.0.2.2

# Runtime announce/withdraw (no restart, no session reset)
focl prefix list
focl prefix add 203.0.113.0/24
focl prefix remove 203.0.113.0/24
```

## Example: Dual-Stack Configuration

Here's an example configuration demonstrating dual-stack (IPv4/IPv6) support with MD5 authentication. This is for **testing and learning purposes only** - not for production deployment:

```toml
[global]
asn = 65001
router_id = "192.0.2.1"
listen = true
listen_addr = "0.0.0.0:179"

# IPv4 peer with MD5
[[peers]]
name = "upstream-v4"
address = "192.0.2.2"
remote_as = 65002
password = "ChangeThisToStrongPassword123!"

# IPv6 peer with MD5
[[peers]]
name = "upstream-v6"
address = "2001:db8::1"
remote_as = 65002
password = "ChangeThisToStrongPassword123!"

# Announce IPv4 prefix
[[prefixes]]
network = "203.0.113.0/24"

# Announce IPv6 prefix
[[prefixes]]
network = "2001:db8:1000::/48"
next_hop = "2001:db8::2"
```

See `focl-vultr-example.toml` for a complete production-style example with documentation IPs.

## Architecture

```
┌─────────────────┐     IPC (Unix Domain Socket)      ┌─────────────────┐
│     focl        │  ───────────────────────────────> │     focld       │
│  CLI frontend   │        JSON/NDJSON protocol       │  BGP speaker    │
│                 │ <─────────────────────────────────│    daemon       │
└─────────────────┘                                   └─────────────────┘
                                                              │
                                    ┌─────────────────────────┼─────────────────────────┐
                                    │                         │                         │
                                    v                         v                         v
                              ┌──────────┐            ┌────────────┐            ┌────────────┐
                              │ Archive  │            │   BGP      │            │   Config   │
                              │ Service  │            │  Service   │            │   Store    │
                              └──────────┘            └────────────┘            └────────────┘
```

## Dependencies

- **bgpkit-parser** - BGP message parsing and MRT encoding
- **tokio** - Async runtime
- **serde/toml** - Configuration handling
- **libc** / **linux-raw-sys** - TCP-MD5 and TCP-AO socket options (Linux only)

## Platform Support

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| BGP Speaker | ✓ | ✓ | ✓ | ? |
| IPv4/IPv6 | ✓ | ✓ | ✓ | ? |
| TCP-MD5 Auth | ✓ | ✗ | ✗ | ✗ |
| TCP-AO Auth | ✓ | ✗ | ✗ | ✗ |
| MRT Archival | ✓ | ✓ | ✓ | ? |

*Note: TCP-MD5 (RFC 2385) requires Linux kernel support; TCP-AO (RFC 5925) requires Linux 6.7+ built with `CONFIG_TCP_AO`*

## TCP Authentication

A peer authenticates its TCP connection with either TCP-MD5 (`password`) or
TCP-AO (`tcp_ao_keys`), never both. TCP-AO takes one or more master key
tuples:

```toml
[[peers]]
name = "upstream"
address = "192.0.2.2"
remote_as = 65002

[[peers.tcp_ao_keys]]
send_id = 1                    # KeyID we sign with = the peer's recv id
recv_id = 2                    # KeyID the peer signs with = its send id
algorithm = "hmac-sha1-96"     # or "aes-128-cmac-96" (RFC 5926)
secret = "[REDACTED]"          # 1-80 bytes
```

On a connection focl opens, the key marked `current = true` (else the first)
signs and is the one focl asks the peer to sign with; the others stay
installed for the peer to use. On a connection the peer opens, the peer's SYN
picks both keys (Linux does not let a listener choose), so `current` has no
effect there and focl logs a warning when the session runs on other keys.

The keys are installed before `connect()` on active sessions and on the
listening socket, before it starts listening, for passive ones, so the kernel
verifies the very first SYN; an accepted connection from a TCP-AO peer is
also checked to really be TCP-AO protected. If the listening socket refuses a
peer's key, focl logs the error and `focl peer show` reports it as the peer's
`last_error`. Inbound connections from a peer the listener holds no key for
are dropped, as nothing would have verified them. Changing keys requires a
restart.
`focl peer show` reports `auth_mode` (`none`, `md5` or `tcp_ao`).

`focld` refuses to start when an enabled peer has `tcp_ao_keys` and the
kernel has no TCP-AO: such a peer could never get a session. Remove the keys
or set `enabled = false` on the peer to run the others.

A peer that never connects usually has mismatched keys: the kernel drops
segments that fail authentication silently. Its counters say why:

```bash
nstat -az | grep -E 'TCPAO(Good|Bad|KeyNotFound|Required)'
```

* `TCPAOBad`: a segment failed its MAC (wrong secret or algorithm).
* `TCPAOKeyNotFound`: no installed key matched the segment's KeyID. A listener
  without `ao_required` also counts an unsigned segment here.
* `TCPAORequired`: an unsigned segment arrived on a socket that requires
  TCP-AO, which is our active session side.

## Development

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests with GoBGP
cd scripts/interop
./run_gobgp_smoke.sh        # Basic test
./run_gobgp_md5.sh          # MD5 authentication test (Linux only)
./run_bird_tcpao.sh         # TCP-AO test against BIRD 2.17+/3.1+ (Linux only)
```

### Code Quality

```bash
# Formatting
cargo fmt

# Linting
cargo clippy --all-features -- -D warnings

# All checks (as run in CI)
cargo fmt --check
cargo build --no-default-features
cargo build
cargo test
cargo clippy --all-features -- -D warnings
cargo clippy --no-default-features
```

## Configuration Reference

### Global Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `asn` | u32 | required | Local AS number |
| `router_id` | string | required | Router ID (IPv4) |
| `listen` | bool | true | Accept incoming connections |
| `listen_addr` | string | "0.0.0.0:179" | Bind address; `[::]:179` accepts IPv4 and IPv6 peers |
| `control_socket` | path | "/tmp/focld.sock" | CLI socket path |
| `log_level` | string | "info" | Log level |

### Peer Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `address` | string | required | Peer IP address |
| `remote_as` | u32 | required | Peer AS number |
| `local_as` | u32 | global.asn | Override local AS |
| `remote_port` | u16 | 179 | Peer TCP port |
| `hold_time_secs` | u16 | 90 | BGP hold timer |
| `connect_retry_secs` | u16 | 5 | Reconnect interval |
| `passive` | bool | false | Wait for peer to connect |
| `password` | string | none | TCP-MD5 password (1-80 bytes) |
| `tcp_ao_keys` | array | none | TCP-AO keys: `send_id`, `recv_id`, `algorithm`, `secret`, optional `current` |
| `route_refresh` | bool | true | Enable route refresh |

A key that a `[[peers]]` or `[[peers.tcp_ao_keys]]` table does not know is a
config error, so a misspelled `password` cannot leave a peer unauthenticated.

### Prefix Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `network` | string | required | IP prefix (v4 or v6) |
| `next_hop` | string | auto | Next-hop address |
| `dev_attr255_interval_secs` | u32 | none | Attach attribute 255 (reserved for development) with a BGPKIT clock payload, re-announced every N seconds |

## License

MIT

## Related Projects

- [bgpkit-parser](https://github.com/bgpkit/bgpkit-parser) - MRT/BGP/BMP parsing library
- [monocle](https://github.com/bgpkit/monocle) - BGP looking glass and analysis tool
- [bgpkit-broker](https://github.com/bgpkit/bgpkit-broker) - BGP data indexing service

## Contributing

Contributions are welcome! This is an experimental project and we appreciate help making it more robust. Please ensure:

1. Code passes `cargo fmt` and `cargo clippy`
2. Tests pass: `cargo test`
3. Interop tests pass with at least one external BGP implementation
4. Documentation is updated for new features
5. Any production-readiness improvements are clearly documented

## Support

- GitHub Issues: https://github.com/bgpkit/focl/issues
- Discord: https://discord.com/invite/XDaAtZsz6b
