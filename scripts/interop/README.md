# GoBGP Interop Smoke Test (macOS)

This verifies:
1. `focld` establishes a BGP session with `gobgpd`.
2. `gobgpd` learns `203.0.113.0/24` from `focld`.

## Prereqs

- `gobgpd` and `gobgp` installed (default lookup: `$HOME/go/bin`).
- Rust toolchain available for `cargo run --bin focld`.

## Run

```bash
cd /Users/mingwei/Warehouse/BGPKIT/bgpkit-git/focl
scripts/interop/run_gobgp_smoke.sh
```

Expected output:

```text
Interop OK: Established + prefix 203.0.113.0/24 received by GoBGP
```

## Files

- `scripts/interop/gobgpd.toml`: GoBGP daemon config.
- `scripts/interop/focl-interop.toml`: focld interop config (non-root ports).
- `scripts/interop/run_gobgp_smoke.sh`: end-to-end smoke script.

## TCP-AO against BIRD (Linux)

`scripts/interop/run_bird_tcpao.sh` checks TCP-AO (RFC 5925) against BIRD
2.17+ or 3.1+, over loopback, in two runs: focld active with HMAC-SHA-1-96,
then BIRD active with AES-128-CMAC-96. Each run waits for an Established
session that `focl peer show` reports as `tcp-ao`, and for a route in each
direction. focld uses 127.0.0.1 and BIRD 127.0.0.2. The configs are
generated into `scripts/interop/.runtime/`. Tested with BIRD 3.4.0.

Prereqs: Linux 6.7+ with `CONFIG_TCP_AO`, and `bird`/`birdc` on `PATH` (or
`BIRD_BIN`/`BIRDC_BIN`). The ports default to 2179 (focld) and 3179 (BIRD),
overridable with `FOCL_PORT`/`BIRD_PORT`. Both run unprivileged. BIRD does
not need to be installed; an unpacked distro package works:

```bash
dnf download --destdir /tmp/bird bird
rpm2cpio /tmp/bird/bird-*.rpm | cpio -idm -D /tmp/bird/root
BIRD_BIN=/tmp/bird/root/usr/bin/bird BIRDC_BIN=/tmp/bird/root/usr/bin/birdc \
  ./scripts/interop/run_bird_tcpao.sh
```

BIRD lists focld's route as `unreachable`. That is expected: with no device
or kernel protocol, BIRD has no IGP route to resolve the next hop with.

```text
Interop OK: focld <-> BIRD over TCP-AO in both directions, both RFC 5926 algorithms
```

## Useful overrides

```bash
GOBGPD_BIN=/custom/path/gobgpd \
GOBGP_BIN=/custom/path/gobgp \
GOBGP_API_HOST=127.0.0.1 \
GOBGP_API_PORT=50052 \
scripts/interop/run_gobgp_smoke.sh
```

Runtime logs are written to:

- `scripts/interop/.runtime/gobgpd.log`
- `scripts/interop/.runtime/focld.log`
