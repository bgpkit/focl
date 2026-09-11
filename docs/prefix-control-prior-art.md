# Prior art: runtime prefix announce/withdraw in software routers

Compiled 2026-09-11 from primary sources (vendor docs, man pages, project docs/source). Purpose: fix
the CLI/control design for `focl prefix add|remove|list` on evidence rather than taste. Claims and
their URLs are in the survey notes below; anything not confirmed by a primary source is marked
UNVERIFIED.

## Comparison

| Implementation | Per-prefix runtime verb | Exact commands | Scope | Persistence | Ack / output |
|---|---|---|---|---|---|
| OpenBGPD | **yes** (`bgpctl network add|delete`, since OpenBSD 4.6) | `bgpctl network add 192.0.2.0/24 [localpref 200 community 64500:1]`; `bgpctl network delete 192.0.2.0/24`; `network show inet`; `network bulk add\|delete` (stdin); `network flush` | global list of originated networks; FILTER rules still apply per peer | runtime-only, not written to `bgpd.conf` | `bgpctl -j` JSON; announcement still subject to policy |
| GoBGP | **yes** (`gobgp global rib add|del`) | `gobgp global rib add 10.33.0.0/16 -a ipv4 [nexthop X med N community C aspath "..."]`; `gobgp global rib del <prefix> [-a af]`; `del all` | global RIB or per-VRF; **no per-neighbor injection** (per-peer tailoring = policy); AF via `-a` flag only, default ipv4 | in-memory RIB; no config section for routes; re-add/inject after restart | table output; `-j/--json`; add/del print nothing on success; re-add = update, delete of absent = silent no-op (debug log); no dry-run |
| BIRD 2/3 | no verb; config-driven | static protocol route list + `birdc configure` (static protocol diffs in place, source-verified -> only that prefix's UPDATEs); `configure check`, `configure timeout N`, `configure confirm\|undo`; `reload filters in\|out`, `reload bgp out` (3.x) | per protocol/channel | config file is the only source of truth | no JSON (`birdc -v` numeric codes); `bird -p` validate-only; control protocol documented as stable/scriptable |
| FRR | no verb; config model | `conf t` -> `router bgp` -> `address-family` -> `network 203.0.113.0/24` / `no network ...` (immediate) | per process/AF; route-map decides per peer | running config volatile across restart -> `write file` / `vtysh -w`; `frr-reload.py` applies on-disk diff | `vtysh -c`, `-C` dry-run; append `json` for JSON; no confirm prompts |
| Junos | no verb; commit model | static route + export policy + `commit`; `commit check`, `commit confirmed N`, `rollback N`, `show\|compare` | policy maps per peer | commit **is** persistence; rollback files | `\| display json`; auto-rollback instead of prompts |
| RouterOS | no verb; config model | v7: address-list entry + `output.network=bgp-networks` (+ `output.network-blackhole`); needs a matching IGP route | per connection | persistent config (address-list `timeout` = RAM-only) | CLI/API/REST replies (`!done`/`!trap`); safe mode undoes on abnormal exit |
| ExaBGP | **yes** (text API over pipe) | `announce route 100.10.0.0/24 next-hop 192.0.2.1 [community ... as-path ... med ...]`; `withdraw route 100.10.0.0/24 [next-hop X]`; scoped via `neighbor <ip>[,<ip>]` or `neighbor *`; bulk/group forms | per neighbor via selectors | process-scoped; the API process must re-announce after restart | one ack per command (`done`/`error`/`shutdown`); group summary `group processed: N announced, M withdrawn`; mismatched withdraw = "Withdrawal doesn't match" |
| RustyBGP | yes (GoBGP-compatible gRPC + gobgp CLI) | same verbs as GoBGP | same as GoBGP | UNVERIFIED | same as GoBGP (UNVERIFIED for ack) |
| freeRtr | no verb; console config model | redistribution-driven: `conf t` -> `router bgp4 1` -> `no red conn` (withdraw) / `red conn` (announce); live, no session reset | per router VRF | UNVERIFIED | no machine-readable ack documented |

## Design conclusions for focl

1. **The capability is standard.** Two daemon+CLI implementations inject/withdraw prefixes at runtime
   over a control channel (GoBGP `global rib add|del`, OpenBGPD `network add|delete`), and ExaBGP does
   it over a pipe with an explicit ack per command. A runtime verb for focl is copying an established
   pattern, not inventing one.
2. **Verb and noun.** `focl prefix add|remove|list` keeps focl's own vocabulary (`[[prefixes]]` in the
   config) and its existing noun-group CLI style (`peer`, `rib`, `archive`). The closest precedent for
   the semantics is OpenBGPD `network add|delete`; GoBGP `rib add|del` is the same shape with RIB
   vocabulary.
3. **Address family is inferred from the prefix, not a flag.** GoBGP requires `-a` and rejects a
   mismatched prefix; focl's config already infers family from the `network` value. Inference removes a
   whole class of operator error. (Deliberate deviation, documented in `--help`.)
4. **Global scope in v1, no `--peer`.** Both GoBGP and OpenBGPD restrict runtime injection to the global
   originated set and leave per-peer selection to policy; focl has no export-policy framework yet, so a
   `--peer` flag would be a half-policy. Add it when policy exists.
5. **Runtime overrides are in-memory; `reload` resets them.** Matches GoBGP (in-memory RIB) and OpenBGPD
   (dynamic entries never written to `bgpd.conf`). Must be stated in `--help` and docs so nobody expects
   a runtime `remove` to survive a restart.
6. **Withdrawing a configured prefix is the point, not an error.** The demo (and normal ops) needs
   "stop announcing what the config says": `prefix remove` on a config prefix suppresses it and sends
   the withdraw; `prefix add` clears the suppression; `prefix list` shows `announced` / `suppressed`
   plus the source (`config` / `runtime`). Mirrors OpenBGPD's single originated-network list.
7. **Ack like ExaBGP, not like GoBGP.** GoBGP prints nothing on success; ExaBGP returns one ack per
   command and a summary for batches. For a demo and for scripting, print one line per command
   (`announced 2620:aa:a000::/48 to 2 peers (v6)`), and keep exit 0 for a no-op (GoBGP treats a delete
   of an absent prefix as a silent no-op; keep that, but say "no change").
8. **Validation and machine-readable output are cheap wins.** Validate the prefix and next-hop family
   before sending (`bgpd -n` / `bird -p` / `configure check` precedent), offer `--dry-run` to report
   what would be sent, and offer `--json` for both `list` and the mutation results (GoBGP `-j`,
   `bgpctl -j`, FRR `json` suffix).
9. **`remove all` (OpenBGPD `network flush` / GoBGP `del all`) is follow-up scope.** If added, it must
   only touch locally-originated prefixes, never anything learned from a peer (GoBGP's documented guard).

## Deliberately not copied

- Per-neighbor runtime injection (ExaBGP selectors): needs the policy framework first (conclusion 4).
- Candidate/commit staging (Junos) and safe mode (RouterOS): focl is a single-process daemon with a
  Unix socket, not an interactive console session; the equivalent guard is `--dry-run` plus the
  `reload` reset, and `focl peer list`/`rib out` for verification.
- Config write-back: runtime commands never edit `focl.toml` (GoBGP/OpenBGPD behavior; keeps the config
  file reviewable by hand).
