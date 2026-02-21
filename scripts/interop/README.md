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
