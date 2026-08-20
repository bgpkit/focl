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

## Example 1: BMP station (the operator path)

Router streams to focl; focl never peers, never announces, only archives.

`focl.toml`:

```toml
[global]
router_id = "198.51.100.10"        # this box
control_socket = "/run/focld.sock"

[bmp]
# bind a management address, not 0.0.0.0; restrict with a firewall
# allowlist so only known routers can connect
listen = "198.51.100.10:1790"
# optional per-router MD5; collector identity comes from this trusted
# mapping, never from the router's BMP Init sysName
# [[bmp.routers]]
# address = "203.0.113.6"
# collector_id = "edge01"
# password = "[REDACTED]"

[archive]
enabled = true
collector_id = "edge01"            # default when no [[bmp.routers]] match
layout_profile = "routeviews"
updates_interval_secs = 900        # RV-style 15-minute update files
ribs_interval_secs = 7200          # 2-hour RIB dumps, RV convention
ribs_mode = "trie"                 # trie | initial-only | off  (see plan §RIB)
compression = "zstd"
root = "/data/mrt"
retention_days = 30                # local auto-cleanup after replication

[[archive.destinations]]
type = "local"
mode = "primary"
path = "/data/mrt"
```

Router side, one stanza each:

```text
# FRR
bmp monitor all stats-all pre-policy vrf default
bmp station target 198.51.100.10 port 1790

# Juniper
set protocols bmp station focl connection-mode active test-route-station
set protocols bmp station focl station-address 198.51.100.10 station-port 1790
set protocols bmp station focl route-monitor post-policy false

# Cisco IOS-XR
bmp server 1 host 198.51.100.10 port 1790
router bgp 65000 bmp server 1 route-monitor pre-policy

# GoBGP (test lab)
[bmp-server.config]
  server-address = "198.51.100.10:1790"
```

Verify:

```bash
focl doctor          # router connected, Peer Up seen, EoR walk complete
focl tail --updates  # live NDJSON of archived elements
ls /data/mrt/edge01/2026.08/UPDATES/   # updates.20260820.1645.zst
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

[archive]
enabled = true
collector_id = "focl01"
layout_profile = "ris"       # rrc-style: updates.* + bview.*
updates_interval_secs = 300  # RIS-style 5-minute update files
ribs_interval_secs = 86400   # daily bview from adj-rib-in trie
ribs_mode = "trie"
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
| ribs_mode = initial-only | < 10 MB | dump only the post-EoR walk, then updates only |

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
`ribs_mode` (biggest memory lever), `retention_days`, compression choice
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
