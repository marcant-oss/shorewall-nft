# Plan: true stateless bidirectional rawnat — nft `ip[6] (s|d)addr set` + notrack

## Context

Shorewall has a `rawnat` config file for NAT actions applied **before
conntrack** (raw-table priority `-300`). Classic iptables-Shorewall
emits `iptables -t raw ... -j DNAT`/`SNAT` lines; those require the
conntrack zone trick to function and are awkward to use.

With **nftables**, the raw equivalent is simpler and genuinely
stateless: just rewrite the L3 fields in-place via `ip daddr set` /
`ip saddr set` (or the IPv6 twins) plus a `notrack` verdict to keep
the flow out of the conntrack table.

### Goals

1. **True stateless NAT in the raw chains** — no conntrack state created,
   no `dnat`/`snat` conntrack statements used, no connection-tracking
   zones required.
2. **Bidirectional 1:1**: a single declaration emits **both** directions
   (forward destination rewrite + return source rewrite) so operators
   write the mapping once.
3. **Single address, CIDR prefix, or range as the mapping unit.**
   A STATIC row may carry:
   - single IPs: `198.51.100.10 ↔ 192.0.2.10`
   - CIDR prefixes: `198.51.100.0/24 ↔ 192.0.2.0/24` (host bits preserved;
     `.5` → `.5`, `.42` → `.42`)
   - address ranges: `198.51.100.10-198.51.100.20 ↔ 192.0.2.10-192.0.2.20`
     (position-preserving; `.12` → `.12`)
   Both sides must describe an equal number of addresses — `/24` pairs
   with `/24`, not `/28`.
4. **Dual-stack IPv4 / IPv6 first-class** — v4 literals emit `ip` rules,
   v6 literals emit `ip6` rules, nfset references expand to both `_v4`
   and `_v6` twins.
5. **Pure nftables** — no tc, no userspace, no runtime apply path.
   Everything is in the compiled ruleset, reload is one `nft -f`.
6. **Keep the existing `rawnat` file name and column layout**; extend
   the set of valid ACTION tokens instead of adding a new file.
7. **Distinct from `netmap`** — the existing `netmap` file is stateful
   (conntrack-based 1:1 via `compiler/nat.py::process_netmap`).
   `rawnat STATIC` is the stateless counterpart: same semantic surface,
   no conntrack footprint, higher throughput, no RELATED/INVALID state
   filtering. Operators choose based on the trade-off. Documented in
   the man page with a "when to use which" paragraph.

### Non-goals (explicit)

- Port rewriting (would need conntrack to track reverse mapping).
- 1-to-N masquerade (conntrack-only semantic).
- Protocol-specific NAT helpers (FTP ALG etc — conntrack-only).
- Fragment reassembly semantics — documented as a prerequisite.

---

## Current state

`compiler/ir/_build.py::_process_rawnat` (lines 1289-1378) today
handles only three actions in the raw chains: `NOTRACK`, `ACCEPT`,
`DROP`. Chain creation (`raw-prerouting` + `raw-output` at priority
-300) and zone-spec parsing are already in place and correct. This
plan **extends** the existing function to recognise three additional
actions that produce the stateless-NAT emit, then threads a new
verdict type through the emitter.

---

## Action grammar — extended

Three new ACTION tokens join `NOTRACK` / `ACCEPT` / `DROP`:

| ACTION                        | Semantics                                                                                   |
|-------------------------------|---------------------------------------------------------------------------------------------|
| `STATIC(EXT,INT)`             | Bidirectional 1:1 NAT. EXT/INT may be a single IP, CIDR prefix, or range. Contributes one element to both `rawnat_fwd_vN` and `rawnat_rev_vN` interval maps; a single emit rule per family in each direction covers the union of all STATIC declarations. |
| `RAWDNAT(IP)`                 | One-way destination rewrite + notrack. Per-row single-literal rule in `raw-prerouting`. |
| `RAWSNAT(IP)`                 | One-way source rewrite + notrack. Lands in `raw-output` when source is the firewall, otherwise `raw-prerouting` with a source match. |

`STATIC` is the primary form. The two one-way forms handle ad-hoc
single-target rewrites.

### EXT / INT addresses in `STATIC(EXT,INT)`

Accepted forms for **each** side (sides must use size-equivalent shapes):

| Form        | Example                                      | Map-element shape             |
|-------------|----------------------------------------------|-------------------------------|
| Single IP   | `192.0.2.10`                                 | `192.0.2.10 : <mapped>`       |
| CIDR prefix | `192.0.2.0/24`                               | `192.0.2.0/24 : <prefix>`     |
| Range       | `192.0.2.10-192.0.2.20`                      | `192.0.2.10-192.0.2.20 : <range>` |
| nfset ref   | `@vpn_peers`                                 | per-element expansion from `_v4`/`_v6` twins (values ignored if map-typed) |

**Size-equivalence check** (compile-time, hard error):

- `/24` pairs only with a 256-address peer (another `/24`, or an
  equivalent range).
- `192.0.2.10-192.0.2.20` (11 addrs) pairs only with another 11-addr
  peer.
- Mixed forms are allowed where sizes match — e.g. `/24` ↔
  `198.51.100.0-198.51.100.255` is valid.
- nfset-ref on one side requires the other side to be an nfset-ref
  of identical `_v4` / `_v6` element count; elements pair by
  position within the family twin.

**Prefix / range rewrite semantics** (nft-native, well-defined):

- CIDR-pair `EXT/N : INT/N`: nft's interval-map performs a
  **prefix-preserving** rewrite — host bits are carried over from
  input to output. `198.51.100.5 → 192.0.2.5`, etc. Same mechanism
  the existing stateful `netmap` compiler uses, so no new kernel
  capability is required.
- Range-pair of equal length: **position-preserving** rewrite.
  `EXT.start+k → INT.start+k` for every `k ∈ [0, len)`.

### IPv6 caveat

IPv6 prefix-NAT is well-defined for any prefix length.
Privacy-extension / SLAAC implications are the operator's concern;
shorewall-nft emits the rewrite exactly as declared.

### Dual-stack example

```
# FILE: rawnat
# ACTION                                                                SOURCE    DEST    PROTO  DPORT
STATIC(198.51.100.10,192.0.2.10)                                        -         -       -      -
STATIC(198.51.100.0/24,192.0.2.0/24)                                    -         -       -      -
STATIC(198.51.100.100-198.51.100.149,10.0.0.0-10.0.0.49)                -         -       -      -
STATIC(2001:db8::10,fd00::10)                                           -         -       -      -
STATIC(2001:db8:abcd::/48,fd00:1234:5678::/48)                          -         -       -      -
STATIC(@ha_services,@internal_backends)                                 -         -       -      -
RAWDNAT(10.0.0.5)                                                       net       -       tcp    443
RAWSNAT(203.0.113.1)                                                    -         net     -      -
NOTRACK                                                                 -         1.1.1.1 udp    53
```

---

## nft emit shape

### One pair of interval-maps per family collects every STATIC row

All STATIC rows across the whole `rawnat` file contribute elements
into one pair of interval-maps per family. Emit stays compact
regardless of declaration count.

```nft
table inet shorewall {
    # Only emitted if >=1 STATIC row present in that family.
    map rawnat_fwd_v4 {
        type ipv4_addr : ipv4_addr
        flags interval
        elements = {
            198.51.100.10 : 192.0.2.10 ,
            198.51.100.0/24 : 192.0.2.0/24 ,
            198.51.100.100-198.51.100.149 : 10.0.0.0-10.0.0.49
        }
    }
    map rawnat_fwd_v6 {
        type ipv6_addr : ipv6_addr
        flags interval
        elements = {
            2001:db8::10 : fd00::10 ,
            2001:db8:abcd::/48 : fd00:1234:5678::/48
        }
    }
    map rawnat_rev_v4 {
        type ipv4_addr : ipv4_addr
        flags interval
        elements = {
            192.0.2.10 : 198.51.100.10 ,
            192.0.2.0/24 : 198.51.100.0/24 ,
            10.0.0.0-10.0.0.49 : 198.51.100.100-198.51.100.149
        }
    }
    map rawnat_rev_v6 {
        type ipv6_addr : ipv6_addr
        flags interval
        elements = {
            fd00::10 : 2001:db8::10 ,
            fd00:1234:5678::/48 : 2001:db8:abcd::/48
        }
    }

    chain raw-prerouting {
        type filter hook prerouting priority raw;
        # STATIC — forward + notrack
        ip  daddr @rawnat_fwd_v4 ip  daddr set ip  daddr map @rawnat_fwd_v4 notrack
        ip6 daddr @rawnat_fwd_v6 ip6 daddr set ip6 daddr map @rawnat_fwd_v6 notrack
        # STATIC — return + notrack
        ip  saddr @rawnat_rev_v4 ip  saddr set ip  saddr map @rawnat_rev_v4 notrack
        ip6 saddr @rawnat_rev_v6 ip6 saddr set ip6 saddr map @rawnat_rev_v6 notrack

        # RAWDNAT — per-row single-literal
        iifname "bond1" ip daddr != 10.0.0.5 tcp dport 443 ip daddr set 10.0.0.5 notrack

        # NOTRACK — unchanged existing semantics
        ip daddr 1.1.1.1 udp dport 53 notrack
    }

    chain raw-output {
        type filter hook output priority raw;
        # RAWSNAT — one-way, firewall-originated
        oifname "bond1" ip saddr set 203.0.113.1 notrack
    }
}
```

### Why the double `@rawnat_fwd_v4` reference

The expression `ip daddr set ip daddr map @rawnat_fwd_v4` performs the
rewrite only when the map lookup succeeds. Without a membership-guard,
nft raises a runtime error on map-miss (statement context does not
silently swallow it). The leading `ip daddr @rawnat_fwd_v4` uses the
**map-as-set** form — nft treats a map as an iterable keyset for the
membership test. Standard idiom in current nft (≥ 0.9.x).

**Capability-probe gate**: if the target kernel rejects map-as-set
membership, fallback is per-family sibling declarations — one `set`
for keys-only membership + one `map` for the rewrite. Same
semantics, one extra declaration per family. Documented in Risks.

### RAWDNAT / RAWSNAT stay per-row, no shared map

One-way rewrites don't benefit from a shared map because each row
already names its single target. Kept as a per-row rule with optional
source / port filters carried from the SOURCE / DEST / PROTO / DPORT /
SPORT columns.

---

## Design decisions (locked)

1. **No new config file.** `rawnat` stays the single source. Extend
   the action grammar. Backward-compatible for `NOTRACK` / `ACCEPT` /
   `DROP`.

2. **No new chain.** Reuse `raw-prerouting` and `raw-output`
   (already created by `_process_rawnat` and by the `notrack`
   processor). Priority `-300`.

3. **New verdict type: `StatelessNatVerdict`**:
   ```
   @dataclass(frozen=True)
   class StatelessNatVerdict:
       field: Literal["daddr", "saddr"]
       family: Literal["ip", "ip6"]
       # For single-literal (RAWDNAT/RAWSNAT) rows:
       target: str | None = None
       # For STATIC rows: name of the shared interval-map to look up.
       map_name: str | None = None
   ```
   Exactly one of `target` / `map_name` is set per instance. The
   emitter dispatches on which:
   - `target=X, map_name=None` → `<family> <field> set X notrack`
   - `target=None, map_name=M` → `<family> <field> set <family> <field> map @M notrack`

4. **notrack is emitted automatically, never authored separately.**
   Keeping `ip daddr set` and `notrack` linked at emit time prevents
   the split (stateless rewrite without notrack is a bug).

5. **STATIC elements collected into `ir.rawnat_static_v4` /
   `_v6`** during `_process_rawnat`, then the emitter synthesises the
   four interval maps (`rawnat_fwd_v4`, `rawnat_fwd_v6`,
   `rawnat_rev_v4`, `rawnat_rev_v6`) once per build at the top of the
   table body.

6. **Dual-stack via literals, not `meta nfproto`.** `ip daddr X`
   already restricts to IPv4; `ip6 daddr Y` to IPv6. Saves one match
   per rule.

7. **Size-equivalence validation at parse time.** For every STATIC
   row: parse both sides, compute address-count (1 for literal,
   `2^(32-N)` for `/N`, `end-start+1` for range), compare. Mismatch
   → build-ir error with `file:line` + both sides' sizes.

---

## Files to modify / create

**Extend (existing)**

| Path | Change |
|---|---|
| `shorewall_nft/compiler/verdicts.py` | Add `@dataclass(frozen=True) class StatelessNatVerdict(field, family, target, map_name)`. Add to `SpecialVerdict` union (18 → 19 members). |
| `shorewall_nft/nft/emitter.py` | Dispatcher for `StatelessNatVerdict` → emits the single-literal form or the map-lookup form + `notrack`. Add to `_TYPED_VERDICT_EMITTERS`. Also emits the top-of-table `map rawnat_{fwd,rev}_v{4,6} { type … : …; flags interval; elements = { … } }` blocks from `ir.rawnat_static_*` lists, gated on non-empty content. |
| `shorewall_nft/compiler/ir/_build.py` | Extend `_process_rawnat`: recognise `STATIC(a,b)`, `RAWDNAT(a)`, `RAWSNAT(a)`. STATIC adds `(EXT, INT)` pair to the appropriate family list. RAWDNAT/RAWSNAT emit per-row rules with `StatelessNatVerdict(target=…)`. |
| `shorewall_nft/compiler/ir/_data.py` | Add `FirewallIR.rawnat_static_v4: list[tuple[str,str]]`, `rawnat_static_v6: list[tuple[str,str]]`. Tuples are `(EXT, INT)` in canonical nft-element shape (single IP, `N.N.N.N/M`, or `start-end`). |
| `shorewall_nft/compiler/ir/_build.py` | `_parse_addr_spec(spec, family) -> (canonical_str, address_count)` helper. Accepts single IP / CIDR / range / `@nfset`. Returns shape suitable for direct nft emit. |
| `shorewall_nft/nft/capability_check.py` | New probe `has_map_as_set_membership` (probe `ip daddr @mapname` syntax). Gates the emit path; clean error + fallback documented. |
| `tools/man/shorewall-nft-rawnat.5` | Document `STATIC` / `RAWDNAT` / `RAWSNAT` with worked examples for single, prefix, range; dual-stack; nfset-ref pairing. Add a "stateful netmap vs stateless STATIC" decision paragraph. |
| `CHANGELOG.md` | `[Unreleased]` entry. |

**New**

| Path | Purpose |
|---|---|
| `tests/test_rawnat_stateless.py` | Unit tests — parser (valid + error paths), emit for each STATIC form (single/prefix/range/nfset), RAWDNAT/RAWSNAT per-row, dual-stack, size-mismatch error, map-as-set capability fallback path. |
| `tests/fixtures/ref-ha-minimal/shorewall46/rawnat` | Extend with one each of single-IP, CIDR, and range STATIC rows (v4 + v6) to exercise the golden snapshot. |

**Not touched**

- Simlab / netkit — stateless NAT is visible at the nft level; no new
  simulation primitives needed.
- shorewalld — zero runtime component.
- `compiler/nat.py` — stateful `netmap` and SNAT/DNAT stay exactly
  as-is. Cross-reference from the new rawnat man page only.

---

## Implementation order (single commit)

1. **`StatelessNatVerdict` dataclass** + `SpecialVerdict` union member
   count bumped. Update `tests/test_verdicts_du.py`.
2. **Parser helper `_parse_addr_spec`** — handles literal / CIDR /
   range / `@nfset`, returns canonical nft-element string + size.
3. **Parser extension in `_process_rawnat`** — STATIC / RAWDNAT /
   RAWSNAT dispatch; size-equivalence check; canonical-form
   collection into `ir.rawnat_static_*`.
4. **Emitter map-block synthesis** — at top of table body, for each
   non-empty `rawnat_static_*`, emit the `map` block.
5. **Emitter statement dispatch** — `StatelessNatVerdict` → rule
   statement with `notrack`.
6. **Capability probe** — `has_map_as_set_membership`; fallback to
   sibling set+map declarations when absent.
7. **Tests** — parser, emit, golden regeneration.
8. **Docs** — man-page extension + CHANGELOG + cross-ref from
   `netmap.5` to the new STATIC form.

Effort estimate: **6–8 h** Sonnet-agent time. Slightly bigger than
the single-IP-only version because of prefix/range canonicalisation
and size-equivalence arithmetic, but still a self-contained feature.

---

## Risks / open questions

1. **`ip daddr @mapname` map-as-set membership.** Need to verify
   the target nft version accepts this shorthand. Spike at impl
   start; fallback to sibling `set` + `map` with identical keys.
2. **Interval-map overlap detection.** If two STATIC rows have
   overlapping EXT (or INT) prefixes/ranges, nft rejects the map
   at load time. Emit-time validation: compute overlaps across all
   collected `(EXT, INT)` pairs per family; hard error at build
   with both offending rows' file:line.
3. **Prefix-map host-bit carry — verify for IPv6.** nft's interval
   maps are documented to preserve host bits for both families, but
   add an explicit integration-test case for a /64 v6 prefix to
   confirm behaviour on the target kernel.
4. **rp_filter with saddr-rewrite in PREROUTING.** When a packet
   arriving on iface X has its source rewritten via the reverse
   map to an address that doesn't route back via X, the kernel's
   rpfilter may drop the packet depending on the kernel's
   rpfilter-timing semantics. Document that `routefilter=0` on
   ingress interfaces is required when the INT→EXT rewrite would
   produce a source outside the iface's routing domain.
5. **CIDR /0 or range covering 0.0.0.0-255.255.255.255.** Valid
   but dangerous; warn-not-error to let pen-testers / all-to-one
   NAT rigs function.
6. **nfset-ref element pairing.** `STATIC(@a,@b)` pairs elements
   by position index in the `_v4` twin (and separately in `_v6`).
   Mismatched lengths → build error. Document the position-based
   pairing explicitly.
7. **Interaction with existing `notrack` file.** Both produce rules
   in the same `raw-prerouting`. Order: `_process_notrack` runs
   before `_process_rawnat` (existing order), so existing `notrack`
   rows match first. Add a comment separator between the two
   sections in the emitted chain for operator clarity.

---

## Verification

**Unit-test regression gate**:
```bash
.venv/bin/pytest packages/shorewall-nft/tests \
                 --ignore=packages/shorewall-nft/tests/test_config_gen.py -q
```
Target: 1625 → ≥ 1650 after landing.

**Golden snapshot**:
```bash
UPDATE_GOLDEN=1 .venv/bin/pytest packages/shorewall-nft/tests/golden/ -q
```
Expect diff in the `complex` case.

**Syntax check (no kernel)**:
```bash
shorewall-nft compile --config-dir tests/fixtures/ref-ha-minimal/
nft -c -f /var/lib/shorewall-nft/generated.nft
grep -c "map rawnat_fwd_v\|map rawnat_rev_v" /var/lib/shorewall-nft/generated.nft
grep -c "ip daddr set ip daddr map\|ip6 daddr set ip6 daddr map" /var/lib/shorewall-nft/generated.nft
grep -c "notrack" /var/lib/shorewall-nft/generated.nft
```

**Integration (rootless via `unshare --user --map-root-user --net --mount`)**:

Tests run inside an unprivileged user+net+mount namespace — same
pattern as `tools/run-tests.sh` and `tools/shorewall-compile.sh`.
`unshare --user --map-root-user` grants `CAP_NET_ADMIN` inside the
namespace without real root, so the test can `ip link add veth …`,
load nft rules, and run packet probes. Required-capability check
runs at the start of the test; missing kernel userns support → skip
with a clear message.

```bash
unshare --user --map-root-user --net --mount -- \
    .venv/bin/pytest packages/shorewall-nft/tests/test_rawnat_stateless_integration.py -q
```

The integration test:
1. Builds a 3-netns topology inside the unshared net namespace
   (src ↔ fw ↔ dst, veth pairs).
2. Compiles a minimal config with
   `STATIC(198.51.100.0/24,192.0.2.0/24)` and loads via `nft -f`.
3. Sends a TCP SYN from src to `198.51.100.42:80`; asserts the
   packet arrives at dst with `daddr=192.0.2.42` (host bits
   preserved per interval-map).
4. Sends the SYN-ACK back; asserts the packet leaves fw with
   `saddr=198.51.100.42`.
5. Verifies conntrack is empty for the flow:
   `conntrack -L 2>/dev/null | grep 198.51.100.42` → no match
   (or `NFCTSocket().dump()` if `conntrack` binary absent in the
   minimal namespace).
6. Repeats with the range form
   `STATIC(198.51.100.10-198.51.100.20,192.0.2.10-192.0.2.20)`.
7. Repeats dual-stack with `STATIC(2001:db8:abcd::/64,fd00::/64)`.

The `unshare` invocation is the same idiom already used by
`tools/run-tests.sh` (lines 30–39) and `tools/shorewall-compile.sh`,
so no new infrastructure is needed. CI runs it identically — no
`NETNS_TEST=1` env-gate, no root-on-runner requirement, just a
kernel with userns enabled (default on Debian trixie / AlmaLinux 10
/ Fedora ≥ 38).

---

## Status

**Saved 2026-04-24 as a pending TODO.** Implementation has not started.
The first action whenever an agent picks this up: spike the
`ip daddr @mapname` map-as-set membership syntax against the target
kernel (Risk #1).

Tracking: see TaskList entry titled "rawnat stateless bidirectional
nft (STATIC single/CIDR/range + RAWDNAT/RAWSNAT, dual-stack)".
