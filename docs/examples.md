# focl usage examples: zero-to-archival on a Linux box

Target-state documentation. Config shapes below are the spec the
implementation must satisfy (`docs/collector-revision-plan.md` rev 4). Every
example ends the same way: standard, RouteViews/RIS-**compatible** MRT files
on disk (naming and record types; private provenance declared in segment
manifests), parseable by bgpkit-parser / monocle / DuckDB with zero glue.

Common ground for all examples:

```bash
# Linux box, one binary, no runtime deps
curl -fsSL https://bgpkit.com/focl/install.sh | sh   # or: cargo install focl
focld --config focl.toml
focl status        # peers, sessions, open archive files, RSS
```

## Example 1: exporting to a monitoring station (the operator path)

A station collects; a speaker reports. focl is the speaker, so it does not listen for BMP: it dials
the station and forwards the sessions it is running, and the station
([bgpviews](https://bgpviews.org)) owns the archive. `docs/bmp-export.md` has the full contract,
including what the export deliberately does not do.

`focl.toml`:

```toml
[global]
asn = 65001
router_id = "198.51.100.10"        # this box
control_socket = "/run/focld.sock"

[[peers]]
name = "edge-router"
address = "203.0.113.6"
remote_as = 65000
passive = true
enabled = true

[bmp]
enabled = true
station = "198.51.100.20:1790"     # the station dials nobody; we dial it
sys_name = "focl-edge01"          # the identity the archive records
stats_interval_secs = 60
# peers = ["edge-router"]         # empty exports every established peer
```

Station side, `bgpviews.toml`:

```toml
[[clients]]
name = "focl"
listen = "198.51.100.20:1790"
allow_from = ["198.51.100.10/32"]  # the daemon's source address; BMP has no authentication
feed = "bmp"

[clients.view]
name = "adj-in-pre"
updates_interval_minutes = 1
```

Verify:

```bash
focl peer show                                    # our session to the router is established
ss -tnp | grep 1790                               # one established connection to the station
bgpviews status --config bgpviews.toml            # coverage, records and the End-of-RIB count
monocle parse /data/mrt/focl-adj-in-pre/bgpdata/2026.08/UPDATES/updates.*.gz
```

## Example 2: incoming BGP peering (the lab/research path)

focl accepts an inbound eBGP session and archives what the neighbor sends.

`focl.toml`:

```toml
[global]
asn = 65001
router_id = "198.51.100.10"
listen = true
listen_addr = "0.0.0.0:179"

[[peers]]
name = "lab-upstream"
address = "203.0.113.6"     # neighbor connects to us
remote_as = 65002
passive = true
password = "[REDACTED]"     # optional TCP-MD5
# or TCP-AO instead of password (Linux 6.7+):
# [[peers.tcp_ao_keys]]
# send_id = 1
# recv_id = 1
# algorithm = "hmac-sha1-96"  # or "aes-128-cmac-96"
# secret = "[REDACTED]"

[archive]
enabled = true
collector_id = "focl01"
layout_profile = "ris"       # rrc-style: updates.* + bview.*
updates_interval_secs = 300  # RIS-style 5-minute update files
ribs_interval_secs = 86400   # daily bview from adj-rib-in trie
compression = "gzip"
root = "/data/mrt"
```

Neighbor side (GoBGP): one `[[neighbors]]` block pointing here, or BIRD
`protocol bgp focl { local as 65002; neighbor 198.51.100.10 as 65001; }`.

## Example 3: fleet daemon (systemd) and Docker

```ini
# /etc/systemd/system/focld.service
[Service]
ExecStart=/usr/local/bin/focld --config /etc/focl/focl.toml
Restart=always
LimitNOFILE=65536
# sizing guardrail for large fleets
MemoryHigh=24G
MemoryMax=28G
```

```bash
# pin a release tag or digest; do not run :latest in production
docker run -d --name focld -p 198.51.100.10:1790:1790 -p 198.51.100.10:179:179 \
  -v $PWD/focl.toml:/etc/focl/focl.toml:ro \
  -v /data/mrt:/data/mrt \
  ghcr.io/bgpkit/focld:v0.2.0
```

## Sizing (anchored estimates, verify in Phase 1)

Anchors measured from public archives (2026-08, single full-Internet feed,
~950k v4 + 200k v6 routes): RouteViews rib file = 76 MB bz2 per dump;
15-minute updates file = 0.9 MB bz2. Numbers below scale linearly with peers
and are for full-Internet feeds only.

Per full feed peer per day:

| Stream | Cadence | Compressed/day |
|---|---|---|
| updates | 15 min | 50-100 MB (bz2/zstd) |
| RIB | 2 h | ~900 MB (12 dumps x 76 MB) |
| RIB | 6 h | ~300 MB |
| RIB | 24 h | ~76 MB |

Memory (RSS), per full feed peer held as adj-rib-in trie:

| Mode | Per peer | Notes |
|---|---|---|
| naive (bytes inline) | 150-250 MB | never ship this |
| interned attrs, u32 values | 60-120 MB | default |
| planned `ribs_mode = initial-only` | < 10 MB | dump only the post-EoR walk, then updates only; not implemented yet |

Plus one process-wide interned attribute store (~50-100 MB total; cross-peer
dedup for similar feeds). **All memory figures below are planning estimates
pending the Phase 1 benchmark gate** (measured trie RSS, intern-table
cardinality, churn; see plan §Scale item 8). Fleet sketch, interned mode,
2 h RIBs:

| Peers | RSS (estimate) | Storage/day | 30-day R2 (~$0.015/GB-mo) |
|---|---|---|---|
| 10 | 1-2 GB | ~10 GB | ~$5 |
| 50 | 3-6 GB | ~50 GB | ~$23 |
| 200 | 12-25 GB | ~200 GB | ~$90 |

Knobs that move the needle: `ribs_interval_secs` (biggest storage lever),
the planned `ribs_mode` (biggest memory lever), `retention_days`, compression choice
(zstd-3 recommended: ~bz2 size at ~10x speed).

## Reading the archive

```bash
# monocle on a private archive
monocle summary --path '/data/mrt/*/2026.08/UPDATES/*'

# DuckDB over the same files via bgpkit-companion tooling, or plain:
focl parquet /data/mrt/edge01/2026.08/   # optional: co-convert to Parquet
```

MRT stays the interchange format (ecosystem compatibility); Parquet is a
derived, optional destination.
