# Plan: IP/fwmark nfsets with ingress-mark, membership-gate, GRE tunnel-key sync — **nft-only**

## Context

A named nft **collection** of IP addresses (with optional per-IP `mark`
value) must support four apply-point semantics. **Everything is
expressed in nftables** — verdicts, sets, maps, and nft `tunnel`
statements. No tc, no per-packet eBPF, no runtime pyroute2 apply path
for this feature. The nft ruleset alone carries every rule; reload is
one `nft -f`.

1. **Ingress fwmark set** — inbound packet on a named interface is
   matched against the collection; fwmark is written either from a
   per-binding constant (set-style) or from the per-IP value (map-style),
   as early as possible (priority `mangle-prerouting`, -150).
2. **Membership gate** — the same binding may specify an `on_miss`
   verdict so packets that do **not** match the collection are
   dropped / rejected / redirected. Turns the collection into a
   firewall allow-list or deny-list.
3. **GRE tunnel-key egress** — when an IP packet leaves via a GRE
   `external`-mode device, the fwmark is written as the tunnel key
   using nft's `tunnel` verdict with a map from `meta mark` to a
   named nft tunnel object.
4. **GRE tunnel-key ingress** — the symmetric pendant: when a packet
   arrives on a GRE `external`-mode device, nft matches the tunnel
   metadata (`tunnel id`) and writes the value into `meta mark`.

Additionally: the collection must **reuse shorewalld's existing
`nfsets` infrastructure** (dnstap / resolver / ip-list / ip-list-plain
backends) so element lists are sourced, refreshed and API-queried the
same way as today's DNS-backed sets. Operators configure once; the same
machinery handles API sync.

The collection must also remain **usable by hand-written nft rules** —
it stays a normal named nft set/map and the bindings file is optional.

**Dual-stack IPv4 / IPv6 is first-class, not deferred.** Every
collection automatically gets a `_v4` **and** a `_v6` twin; every
binding emits rules for both families when the matched field has
content in that family; IPv4 (`gre`, `gretap`) and IPv6 (`ip6gre`,
`ip6gretap`) tunnel devices are supported symmetrically.

---

## Core design decision — extend `nfsets`, do NOT add a parallel file

`nfsets` stays the single source of truth. Extended with an optional
`VALUE_TYPE` via the backend-options string (`value=mark`), making the
set a map when set.

- **No new collection file** — `nfsets` carries every collection.
- **All backends continue to work**: dnstap / resolver / ip-list /
  ip-list-plain. `value=mark` is only valid with `ip-list-plain` (DNS
  cannot deliver per-IP values); parser rejects at build-ir time.
- **For `ip-list-plain` + `value=mark`**: file format extends to
  `<addr> : <hex-value>` per line. Existing plain-list tracker in
  shorewalld gets a `value_parser` hook (pass-through when None).
- **Dual-stack**: a single file mixing IPv4 and IPv6 literals routes
  into both `_v4` and `_v6` nft maps automatically.

---

## Set-style vs map-style (both supported)

**Pattern B — Set membership + constant mark**
The collection is a plain set (just IPs). Binding carries the constant
fwmark value. Works with every backend including DNS:
```nft
meta nfproto ipv4 iifname "bond1" ip  saddr @nfset_vpn_peers_v4 meta mark set 0x00000100 accept
meta nfproto ipv6 iifname "bond1" ip6 saddr @nfset_vpn_peers_v6 meta mark set 0x00000100 accept
```

**Pattern A — Map lookup (per-IP fwmark)**
The collection is a map (`VALUE_TYPE=mark`). Value comes from the set
data, not the binding. Only available with `ip-list-plain`:
```nft
meta nfproto ipv4 iifname "bond1" meta mark set ip  saddr map @nfset_tunnel_keys_v4
meta nfproto ipv6 iifname "bond1" meta mark set ip6 saddr map @nfset_tunnel_keys_v6
```

**Pattern C — Membership gate (independent of A/B)**
Extra `on_miss` behaviour: fall through to a drop / reject / jump on
mismatch. Stacks with A or B in the same binding, or stands alone.
Miss rule is family-scoped so IPv6 traffic is not dropped by an
IPv4-only match above it.

**Pattern D — Tunnel-key egress (fwmark → GRE key)**
Named nft tunnel objects — one per unique key value — plus a map
that dispatches by `meta mark`:
```nft
tunnel tun_0x100_v4 { type gre;    id 0x100; ip  saddr <local4>; ip  daddr <remote4> }
tunnel tun_0x100_v6 { type ip6gre; id 0x100; ip6 saddr <local6>; ip6 daddr <remote6> }

map mark_to_tunnel_v4 { type mark : tunnel; elements = { 0x100 : tun_0x100_v4, 0x200 : tun_0x200_v4 } }
map mark_to_tunnel_v6 { type mark : tunnel; elements = { 0x100 : tun_0x100_v6, 0x200 : tun_0x200_v6 } }

chain mangle-postrouting {
    type filter hook postrouting priority mangle;
    meta nfproto ipv4 oifname "gre0"    tunnel set meta mark map @mark_to_tunnel_v4
    meta nfproto ipv6 oifname "ip6gre0" tunnel set meta mark map @mark_to_tunnel_v6
}
```

**Pattern E — Tunnel-key ingress (GRE key → fwmark)**
Match on `tunnel id` (from skb tunnel metadata after kernel decap) and
assign fwmark via a vmap:
```nft
chain mangle-prerouting {
    type filter hook prerouting priority mangle;
    iifname "gre0"    tunnel id vmap { 0x100 : meta mark set 0x100, 0x200 : meta mark set 0x200 }
    iifname "ip6gre0" tunnel id vmap { 0x100 : meta mark set 0x100, 0x200 : meta mark set 0x200 }
}
```

The vmap values are `mark-set` statements inlined — a pattern nft
already supports (see DNAT concat-map emit at `emitter.py:751`). The
map elements are derived from the bindings' declared nfset: one
`(key, set-mark-stmt)` entry per element.

---

## Config surface

### `nfsets` file — extension (backward-compatible)

```
# NAME         BACKEND          HOSTS                                       OPTIONS
vpn_peers      dnstap           vpn.example.com                             refresh=300
vpn_plain      ip-list-plain    /etc/shorewall46/vpn.list                   inotify
tunnel_keys    ip-list-plain    /etc/shorewall46/tunnel_keys.map            inotify,value=mark
```

File lines for a `value=mark` source (mixed families routed automatically):
```
192.0.2.10  : 0x0100
192.0.2.20  : 0x0200
2001:db8::1 : 0x0100
```

### New file: `nfset_bindings`

Declarative mapping from a nfset (or the map twin) to an apply point.

```
# COLUMN       PURPOSE                                      ALLOWED VALUES
# SET          existing nfsets NAME                         required
# FIELD        L3 field to look up / match                  saddr | daddr | tunnel-id | -
# IFACE        restrict to iifname                          ifname | -
# TUNNEL       tunnel device (IPv4 or IPv6)                 ifname | -
# DIRECTION    apply-point direction                        ingress | egress | -
# ACTION       what to do on match                          mark=<hex> | maplookup | allow | tunnel-key | mark-from-key
# ON_MISS      verdict on non-match                         - | accept | drop | reject | jump:<chain>
# MARK_MASK    write-mask for the fwmark field              default | none | <hex>
```

Example rows (all valid and tested together):
```
# SET           FIELD        IFACE     TUNNEL      DIR        ACTION         ON_MISS      MASK
vpn_peers       saddr        bond1     -           -          mark=0x100     drop         default
vpn_plain       saddr        bond1     -           -          maplookup      -            default
corporate_nets  saddr        bond2     -           -          allow          reject       -
tunnel_keys     -            -         gre0        egress     tunnel-key     -            default
tunnel_keys     -            -         gre0        ingress    mark-from-key  -            default
tunnel_keys     -            -         ip6gre0     egress     tunnel-key     -            default
tunnel_keys     -            -         ip6gre0     ingress    mark-from-key  -            default
```

- Row 1 emits Pattern B into `mangle-prerouting` for both families + drop miss-rule.
- Row 2 emits Pattern A into `mangle-prerouting` for both families.
- Row 3 emits Pattern C (allow-list) into `mangle-prerouting`.
- Rows 4 & 6 emit Pattern D into `mangle-postrouting`. One nft `tunnel` object is generated per unique `(element, family)` pair. The `map` value per row is keyed on `meta mark`.
- Rows 5 & 7 emit Pattern E into `mangle-prerouting`. `tunnel id vmap { k : meta mark set k }` assembled from the nfset elements.
- `TUNNEL` device's kernel kind (checked at runtime by shorewalld
  before the nft reload) determines which family's set elements
  drive the nft tunnel objects / vmap.

### A NAME declared in `nfsets` without a binding row is untouched —
stays declared for reuse from hand-written rules, both families.

---

## nft emit shape — full worked example

Given the rows above plus two tunnel elements (`0x100`, `0x200`), the
emitter produces (abridged):

```nft
table inet shorewall {
    # ── nfsets (existing, maybe extended to map type) ─────────────────
    set nfset_vpn_peers_v4         { type ipv4_addr; flags timeout; size 4096 }
    set nfset_vpn_peers_v6         { type ipv6_addr; flags timeout; size 4096 }
    set nfset_corporate_nets_v4    { type ipv4_addr; flags interval; size 262144 }
    set nfset_corporate_nets_v6    { type ipv6_addr; flags interval; size 262144 }

    map nfset_vpn_plain_v4         { type ipv4_addr : mark; flags interval; size 262144 }
    map nfset_vpn_plain_v6         { type ipv6_addr : mark; flags interval; size 262144 }
    map nfset_tunnel_keys_v4       { type ipv4_addr : mark; flags interval; size 262144 }
    map nfset_tunnel_keys_v6       { type ipv6_addr : mark; flags interval; size 262144 }

    # ── nft tunnel objects, one per unique key+family ────────────────
    tunnel tun_0x100_v4 { type gre;    id 0x100; ip  saddr <local4>; ip  daddr <remote4> }
    tunnel tun_0x200_v4 { type gre;    id 0x200; ip  saddr <local4>; ip  daddr <remote4> }
    tunnel tun_0x100_v6 { type ip6gre; id 0x100; ip6 saddr <local6>; ip6 daddr <remote6> }
    tunnel tun_0x200_v6 { type ip6gre; id 0x200; ip6 saddr <local6>; ip6 daddr <remote6> }

    # ── dispatch maps for tunnel-key egress ──────────────────────────
    map nfset_tunnel_keys_egress_v4 {
        type mark : tunnel
        elements = { 0x100 : tun_0x100_v4, 0x200 : tun_0x200_v4 }
    }
    map nfset_tunnel_keys_egress_v6 {
        type mark : tunnel
        elements = { 0x100 : tun_0x100_v6, 0x200 : tun_0x200_v6 }
    }

    # ── mangle-prerouting (ingress work: Patterns B/A/C + E) ─────────
    chain mangle-prerouting {
        type filter hook prerouting priority mangle;

        # Row 1 — Pattern B + on-miss drop
        meta nfproto ipv4 iifname "bond1" ip  saddr @nfset_vpn_peers_v4 meta mark set 0x100 accept
        meta nfproto ipv6 iifname "bond1" ip6 saddr @nfset_vpn_peers_v6 meta mark set 0x100 accept
        meta nfproto ipv4 iifname "bond1" ip  saddr != @nfset_vpn_peers_v4 drop
        meta nfproto ipv6 iifname "bond1" ip6 saddr != @nfset_vpn_peers_v6 drop

        # Row 2 — Pattern A
        meta nfproto ipv4 iifname "bond1" meta mark set ip  saddr map @nfset_vpn_plain_v4
        meta nfproto ipv6 iifname "bond1" meta mark set ip6 saddr map @nfset_vpn_plain_v6

        # Row 3 — Pattern C allow-list (no mark set)
        meta nfproto ipv4 iifname "bond2" ip  saddr @nfset_corporate_nets_v4 accept
        meta nfproto ipv6 iifname "bond2" ip6 saddr @nfset_corporate_nets_v6 accept
        meta nfproto ipv4 iifname "bond2" ip  saddr != @nfset_corporate_nets_v4 reject
        meta nfproto ipv6 iifname "bond2" ip6 saddr != @nfset_corporate_nets_v6 reject

        # Rows 5 & 7 — Pattern E (tunnel-key ingress)
        iifname "gre0"    tunnel id vmap { 0x100 : meta mark set 0x100, 0x200 : meta mark set 0x200 }
        iifname "ip6gre0" tunnel id vmap { 0x100 : meta mark set 0x100, 0x200 : meta mark set 0x200 }
    }

    # ── mangle-postrouting (egress: Pattern D) ───────────────────────
    chain mangle-postrouting {
        type filter hook postrouting priority mangle;
        oifname "gre0"    tunnel set meta mark map @nfset_tunnel_keys_egress_v4
        oifname "ip6gre0" tunnel set meta mark map @nfset_tunnel_keys_egress_v6
    }
}
```

All of this is pure nft. Reload is one `nft -f`. shorewalld pushes
element updates to `nfset_tunnel_keys_v4` / `_v6` via its existing
`nft add element` / `nft delete element` path — and the compiler
**regenerates** the tunnel objects + egress/ingress maps on every
config reload because tunnel endpoints are part of the compiled
ruleset, not runtime-mutable.

---

## Existing infrastructure I reuse

| Building block | Path | Role |
|---|---|---|
| `NfSetRegistry` + `NfSetEntry` | `shorewall_nft/nft/nfsets.py:78-141` | Extend `NfSetEntry` with `value_type: str \| None`; payload round-trip preserves the field. |
| `emit_nfset_declarations()` | `shorewall_nft/nft/nfsets.py:437` | Extend: emit `type ipv4_addr : mark` + keyword `map` when `value_type=="mark"`. |
| `nfset_to_set_name()` v4/v6 sanitisation | `shorewall_nft/nft/nfsets.py:149` | Re-used for tunnel object names (`tun_<key>_<family>`) and dispatch-map names. |
| `NfSetsManager` | `packages/shorewalld/shorewalld/nfsets_manager.py:34` | Consume the extended payload; delegate to plain-list tracker with the new `value_parser` hook. |
| `PlainListTracker` | `packages/shorewalld/shorewalld/iplist/plain.py` | Extend: parse `<addr> : <value>` when the config carries a `value_type`. Fallback to current behaviour when None. |
| `SetWriter` | `packages/shorewalld/shorewalld/setwriter.py` | Emit map-element syntax `{ addr : value }` when a value is present. |
| `mangle-prerouting` chain | `compiler/providers.py:260` + `compiler/tc.py:828` | Ingress rules (Patterns B/A/C/E) land here. |
| `mangle-postrouting` chain | **new** — created by the new module if any Pattern D binding exists. Priority `mangle` (default 0 per nft docs; shorewall uses `-150` for prerouting, analogous `-150` for postrouting). |
| Inline-vmap emit pattern | `nft/emitter.py:1039-1070` (iifname/oifname vmap) + DNAT concat map at `:751` | Reference for emitting `vmap { KEY : STMT }` with inlined statements like `meta mark set 0x100`. |
| `MarkGeometry` | `compiler/ir/_data.py` (WP-C3) | Mask verification for constant marks to avoid provider / zone bit overlap (warn at compile time). |
| `sw_zone_tag` mask+map fallback | `nft/emitter.py:344-355` | Pattern for the `meta mark set (map) & mask` case — reuse the per-iface two-constant idiom when mask != 0xffffffff. |
| `NftCapabilities` probe | `nft/capabilities.py` | Extend with `has_tunnel_object`, `has_tunnel_set_verdict`, `has_tunnel_id_match` so the compiler can degrade gracefully / error clearly on older kernels. |

---

## Files to modify / create

**Extend (existing)**

| Path | Change |
|---|---|
| `shorewall_nft/nft/nfsets.py` | `NfSetEntry.value_type: str \| None`; parser option `value=mark`; `emit_nfset_declarations` emits `map` + `type K : V` when value_type set; payload round-trip covers the new field. |
| `shorewall_nft/nft/capabilities.py` | Probe `has_tunnel_object`, `has_tunnel_set_verdict`, `has_tunnel_id_match`. Runtime gate + clear error messages. |
| `shorewall_nft/config/parser.py` | Add `nfset_bindings: list[ConfigLine]` field + file-loop + `_merge_configs` mirror. |
| `shorewall_nft/config/schema.py` | Column schema for `nfset_bindings`. |
| `shorewall_nft/compiler/ir/_data.py` | `NfsetBinding` frozen dataclass; `FirewallIR.nfset_bindings: list[NfsetBinding]`. |
| `shorewall_nft/compiler/ir/__init__.py` | Call new `process_nfset_bindings` in `build_ir` after `_process_rules`. |
| `shorewall_nft/nft/emitter.py` | Emit the tunnel objects + dispatch maps (new inline section analogous to `sw_zone_tag`) + hook into `mangle-postrouting`. |
| `packages/shorewalld/shorewalld/nfsets_manager.py` | Propagate `value_type` from the payload into plain-list config; reject for non-plain backends. |
| `packages/shorewalld/shorewalld/iplist/plain.py` | `value_parser` hook: when non-None, each file line is parsed as `<addr> : <value>`. |
| `packages/shorewalld/shorewalld/setwriter.py` | Accept element-with-value tuples; emit `{ addr : 0xNN }` for nft map writes. |

**New**

| Path | Purpose |
|---|---|
| `shorewall_nft/compiler/nfset_bindings.py` | Parser + `process_nfset_bindings(ir, bindings)` — walks bindings, builds all ingress / egress nft rules, creates `mangle-postrouting` chain if Pattern D is used, synthesises tunnel objects + dispatch maps from nfset elements. |
| `tools/man/shorewall-nft-nfset_bindings.5` | Man page. |
| Extend `tools/man/shorewall-nft-nfsets.5` | New `value=mark` option documented. |
| `docs/features/nfset_bindings.md` | Feature page covering Patterns B/A/C/D/E with full nft examples. |

**Tests**

| Path | Focus |
|---|---|
| `tests/test_nfset_map_emit.py` | `NfSetEntry.value_type="mark"` → `map` + `type K : V` (both families). |
| `tests/test_nfset_bindings_parser.py` | Column parsing, error paths (map+dnstap, blank-iface+blank-tunnel, unknown SET, tunnel-key row without TUNNEL). |
| `tests/test_nfset_bindings_emit.py` | Every Pattern × family cell produces the expected nft fragment. |
| `tests/test_nfset_tunnel_objects.py` | For N elements × {v4, v6}, 2N tunnel objects + 2 dispatch maps emitted; mangle-postrouting chain created. |
| `packages/shorewalld/tests/test_plain_list_mapmode.py` | File parser yields `(addr, value)` for map-typed plain-list source. |
| `packages/shorewalld/tests/test_nfsets_manager_mapmode.py` | register-instance payload round-trips with `value_type`. |
| `tests/fixtures/ref-ha-minimal/shorewall46/nfsets` | Extended fixture with one `value=mark` entry plus a dual-stack plain-list source. |
| `tests/fixtures/ref-ha-minimal/shorewall46/nfset_bindings` | Rows exercising all five Patterns and both families. |

---

## Implementation order (single cluster-PR)

1. **nft capability probe** — `has_tunnel_object`, `has_tunnel_set_verdict`,
   `has_tunnel_id_match`. Gate the new emit paths behind these probes so an
   older kernel fails at `build_ir` time with a clear error rather than
   at `nft -f` time with an obscure parser error.
2. **Core data model** — `NfSetEntry.value_type` + payload round-trip + tests.
3. **Core emit** — map declarations in `emit_nfset_declarations`.
4. **shorewalld map-mode plain-list** — `value_parser` hook + SetWriter
   element-with-value path + tests.
5. **Bindings parser + IR fields**.
6. **Compile-time emit** — `compiler/nfset_bindings.py`:
   - ingress patterns (B / A / C) → `mangle-prerouting`.
   - tunnel egress (D) → `mangle-postrouting` + tunnel objects + dispatch maps.
   - tunnel ingress (E) → `mangle-prerouting` vmap.
   - Family-split on `meta nfproto` throughout.
7. **Tests** — parser, emit, fixture goldens regenerated.
8. **Docs** — man pages (new `nfset_bindings.5`; extend `nfsets.5`) +
   `docs/features/nfset_bindings.md` + CHANGELOG.

Effort estimate: **1.5–2 days** Sonnet-agent time. Smaller than the
tc-based approach because no runtime apply path, no pyroute2 tc action
schema wrestling, no per-element tc filter bookkeeping. The primary
unknown is the exact nft syntax for `tunnel set meta mark map @...` and
`tunnel id vmap { ... }`, resolved by the capability-probe spike in
step 1.

---

## Risks / open questions

1. **nft tunnel-statement syntax verification (priority #1 spike).**
   The plan assumes:
   - `tunnel <name> { type gre; id <int>; ip saddr ...; ip daddr ... }`
     declaration (well-documented in nft_tunnel(8)).
   - `tunnel set <expr>` verdict — accepted by nft recent versions.
   - `tunnel set meta mark map @map` — map with `type mark : tunnel`.
   - `tunnel id <matcher>` — match on skb tunnel metadata after decap.
   - `tunnel id vmap { k : meta mark set k, ... }` — vmap with inlined
     statements.

   A 30-minute nft-smoke test against the dev-box kernel at the start
   of implementation verifies each of these. If any syntax is rejected,
   fall back plan:
   - Missing `tunnel set ... map`: emit one rule per key value
     (`meta mark 0x100 tunnel set tun_0x100_v4` × N).
   - Missing `tunnel id vmap`: emit one rule per key
     (`tunnel id 0x100 meta mark set 0x100` × N).
   - Missing tunnel statement entirely: hard-fail with a clear error
     pointing operators at the required kernel version. tc-based
     fallback is explicitly OUT OF SCOPE per user directive.

2. **nft tunnel objects require static endpoints.** Each nft `tunnel`
   object binds to a specific `ip saddr / ip daddr` pair. Operators
   must declare these endpoints in `nfset_bindings` (new columns
   `TUNNEL_SRC` / `TUNNEL_DST`) — or shorewall-nft reads them from the
   kernel once at compile time via a pyroute2 `IPRoute.get_addr()` on
   the named device. Decision: read from kernel at compile time,
   warn if the device is not present (operator runs compile on a
   separate host).

3. **GRE external-mode prerequisite.** `ip link add dev gre0 type
   gretap external` — must be present on the host. shorewall-nft does
   not create the tunnel device itself. Document this in the man
   page; validate at compile time via `IPRoute.get_links()` and fail
   with a clear error if the device is absent or not in external mode.

4. **Runtime element updates for tunnel-bound collections.** When
   shorewalld refreshes a map-typed `ip-list-plain` (file changed on
   disk), the nft map receives `add element`. If that map is the
   **source** for a tunnel-key binding, the compiler must also
   regenerate the `mark_to_tunnel_v{4,6}` dispatch map and possibly
   new `tunnel` objects for any new keys — which means a full compile
   + `nft -f` reload, not just a set update.
   Mitigation v1: document that adding / removing map elements that
   change the tunnel-key set requires `shorewall-nft restart`, not
   just a dynamic set reload. Follow-up task: make the dispatch map
   also dynamic (element-mutable), which nft does allow for
   `type mark : tunnel` maps if the tunnels themselves are stable.

5. **Mask overlap.** When a constant mark or map value bit overlaps
   `ir.mark_geometry.provider_mask` or `zone_mask`, silent misrouting
   can follow. Compile-time warning emitted once per overlap.

6. **Bindings referencing missing nfsets.** Binding row points at a
   NAME that is not declared in `nfsets`. Build-ir error with file:line.

7. **on-miss emit ordering.** nft has no native "else"; the plan
   emits a second `!= @set drop` rule. Order matters: we emit
   the match-then-set rule first, the inverted drop second, so
   matching packets never reach the drop. Golden snapshot verifies.

---

## Verification

**Unit tests — regression gate**:
```bash
.venv/bin/pytest packages/shorewall-nft/tests \
                 packages/shorewalld/tests \
                 --ignore=packages/shorewall-nft/tests/test_config_gen.py -q
```
Target: 1616 (current) → ≥ 1655 after this feature lands.

**Golden snapshot**:
```bash
UPDATE_GOLDEN=1 .venv/bin/pytest packages/shorewall-nft/tests/golden/ -q
```
Expect diffs in `complex` and `minimal` cases.

**nft-smoke (integration, gated on `NETNS_TEST=1` + root)**:
```bash
sudo ip link add dev gre0 type gretap external
sudo ip link add dev ip6gre0 type ip6gretap external
shorewall-nft compile --config-dir tests/fixtures/nfset-map-dualstack
nft -c -f /var/lib/shorewall-nft/generated.nft    # syntax check
sudo nft -f /var/lib/shorewall-nft/generated.nft
# Emit a marked packet that hits Pattern D, capture with tcpdump on
# the underlay, verify GRE key in header.
# Receive an encapsulated packet with a known key, verify meta mark
# is set accordingly via nft trace.
```

**Smoke — no kernel required**:
```bash
shorewall-nft compile --config-dir tests/fixtures/nfset-map-dualstack
nft -c -f /var/lib/shorewall-nft/generated.nft   # parse-only check
grep -c "tunnel tun_" /var/lib/shorewall-nft/generated.nft
grep -c "tunnel set meta mark map" /var/lib/shorewall-nft/generated.nft
grep -c "tunnel id vmap" /var/lib/shorewall-nft/generated.nft
```

---

## Out of scope (explicit)

- Non-`mark` value types (`verdict`, `counter`, strings) — kept as
  field-type extension points for future work.
- Dynamic per-packet tunnel endpoint selection (different src/dst
  per key) — tunnel objects are static in nft; for truly dynamic
  endpoints an eBPF-based approach would be needed, explicitly out.
- eBPF / tc fallbacks — per user directive, tc is off the table even
  if an nft primitive is missing; compile-time hard-error instead.
- ct-mark persistence bridge (`ct mark set meta mark`) — separate
  existing feature (`sw_zone_tag`); not touched here.
- Map types keyed by `ifname` or `meta l4proto` — `FIELD` is
  `saddr` / `daddr` / `tunnel-id` only in v1.
- Field-column extensions for the `nfset_bindings` file
  (`TUNNEL_SRC` / `TUNNEL_DST`) — v1 auto-detects endpoints from
  kernel; follow-up task to allow explicit declaration.

---

## Status

**Saved 2026-04-24 as a pending TODO.** Implementation has not started.
The spike in Risk #1 (nft tunnel-statement syntax verification against
the target kernel's `nft` binary) is the first action whenever an
agent picks this up.

Tracking: see the TaskList entry titled "nfset value=mark +
nfset_bindings (Pattern A/B/C/D/E) — nft-only".
