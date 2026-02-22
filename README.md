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
- [x] Static prefix announcements
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
- **libc** - TCP-MD5 socket options (Linux only)

## Platform Support

| Feature | Linux | macOS | FreeBSD | Windows |
|---------|-------|-------|---------|---------|
| BGP Speaker | ✓ | ✓ | ✓ | ? |
| IPv4/IPv6 | ✓ | ✓ | ✓ | ? |
| TCP-MD5 Auth | ✓ | ✗ | ✗ | ✗ |
| MRT Archival | ✓ | ✓ | ✓ | ? |

*Note: TCP-MD5 (RFC 2385) requires Linux kernel support*

## Development

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests with GoBGP
cd scripts/interop
./run_gobgp_smoke.sh        # Basic test
./run_gobgp_md5.sh          # MD5 authentication test (Linux only)
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
| `listen_addr` | string | "0.0.0.0:179" | Bind address |
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
| `password` | string | none | TCP-MD5 password |
| `route_refresh` | bool | true | Enable route refresh |

### Prefix Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `network` | string | required | IP prefix (v4 or v6) |
| `next_hop` | string | auto | Next-hop address |

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
