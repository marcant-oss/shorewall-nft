# Perl Shorewall vs shorewall-nft — flag coverage audit

Captured **2026-04-28** (refreshed; supersedes 2026-04-27 first-pass) against:

- `shorewall-nft` Python: `packages/shorewall-nft/shorewall_nft/`
- Classic Perl Shorewall: `../shorewall.old/Shorewall/Perl/Shorewall/Zones.pm`
  lines 354–448 (`%validinterfaceoptions`, `%validzoneoptions`).

**Methodology change vs. 2026-04-27 first pass.** The first-pass audit used
plain `grep` for the literal flag name and undercounted call sites that go
through `iface.options` / `iface.option_values` indirection — flags whose
emit branch reads the dict by key never trigger a literal-name match. This
refresh re-classifies each flag by ground truth (read the parse + emit
sites) using a four-state taxonomy:

| State | Meaning |
|-------|---------|
| **N (None)** | Not parsed; silently dropped or "unknown option" warning |
| **P (Parse-only)** | Parsed/stored in `Interface.options` or `option_values`, never consulted by emit logic |
| **S (Storage + partial)** | Parsed and consulted in *some* emit path but incomplete vs Perl |
| **F (Full)** | Matches Perl semantics |

False-positive filters used: `Optional[X]` type hints, `time.sleep`-style
hits for `wait`, `subnets`/`interfaces` for `nets`.

## Interface flags — verified state

| Flag | First-pass claim | Actual state | Parse site | Emit site | Notes |
|------|------------------|--------------|------------|-----------|-------|
| `accept_ra` | substantial | **F** | `zones.py` (option_values) | `sysctl.py:128-131` | IPv6 sysctl |
| `arp_filter` | substantial | **F** | `zones.py` | `sysctl.py:100-103` | sysctl |
| `arp_ignore` | thin (2) | **F** | `zones.py` | `sysctl.py:106-107` | sysctl, value-bearing 1–8 |
| `blacklist` | substantial | **F** | `zones.py` | dispatch + drop chain | dynamic-blacklist sibling done |
| `bridge` | thin (1) | **F** | `zones.py` | `_build.py:927` | DHCP forward-allow gate (covers all three Misc.pm cases); no other Perl-side filter behaviour beyond DHCP |
| `broadcast` | substantial | **F** | `zones.py` (column 3) | n/a | column-3 broadcast spec; not a flag-style option |
| `dhcp` | substantial | **F** | `zones.py` | `_build.py:_process_dhcp_interfaces` | three-case emit (zone↔fw, self-zone, bridge cross-zone) |
| `forward` | substantial | **F** | `zones.py` | `sysctl.py:122-125` | IPv4 forwarding sysctl |
| `logmartians` | thin (3) | **F** | `zones.py` | `sysctl.py:94-97` | sysctl |
| `maclist` | substantial | **F** | `zones.py` | mac-filter chain | |
| `mss=` | thin (2) | **F** | `_parse_option_values` | `_build.py:_emit_mss_clamp_rule` | mangle-forward TCP-MSS clamp |
| `nosmurfs` | thin (3) | **F** | `zones.py` | `_build.py:678-696` | broadcast-saddr drop in input |
| `optional` | thin (2) | **F** | `providers.py:28,106` | n/a | annotation only; downstream callers may consult it |
| `physical=` | none | **F (NEW)** | `option_values["physical"]` | `Interface.emit_name` | Logical→kernel name override; consumed in iifname/oifname matchers + zone-dispatch + ct-mark map |
| `proxyarp` | substantial | **F** | `zones.py` | `sysctl.py:116-119` | sysctl + proxyarp emit |
| `proxyndp` | substantial | **F** | `zones.py` | proxyarp.py | IPv6 sibling |
| `required` | none | **F (NEW)** | `zones.py` | n/a | parsed + stored; runtime fail-fast hook is a future TODO |
| `routeback` | substantial | **F** | `zones.py` | dispatch | |
| `routefilter` | substantial | **F** | `option_values["routefilter"]` | `sysctl.py:84-91` | rp_filter sysctl, value 0/1/2 |
| `sourceroute` | thin (3) | **F** | `option_values["sourceroute"]` | `sysctl.py:110-113` | accept_source_route sysctl |
| `tcpflags` | thin (3) | **F** | `zones.py` | `_build.py:636-676` | SYN+FIN, SYN+RST drop in input |
| `unmanaged` | none | **F (NEW)** | `zones.py` | filter at `build_zone_model` | iface skipped before any rule emit (mirrors Perl `find_interfaces_by_option` exclusion) |

## Interface flags — still missing

| Flag | State | Effort | Why deferred |
|------|-------|--------|--------------|
| `rpfilter` | **N** | Medium (filter-novel) | Perl emits a mangle-prerouting rule with `-m rpfilter --validmark --invert` (≈ nft `fib saddr . iif oif != 0`) — **not** the IPv4 sysctl `rp_filter` (that's `routefilter`). Needs disposition (RPFILTER_DISPOSITION), DHCP-broadcast exception, family-agnostic emit. |
| `sfilter=CIDR` | **N** | Medium (filter-novel) | Per-iface anti-spoof CIDR list. Misc.pm `sfilter` chain. nft equivalent: per-iface `ip saddr != @sfilter_<iface> drop`. Needs new IR set. |
| `nets=SUBNET` | **N** | Large (zone-dispatch redesign) | Inline subnet list per iface; affects `imatch_source_net()` and zone dispatch. Touches rule-dispatch architecture. |
| `dbl` / `nodbl` | **N** | Large (architectural) | Per-iface dynamic-blacklist switch. Needs blacklist plumbing extension. |
| `dynamic_shared` | **N** | Large (architectural) | Shared dynamic-blacklist set across zones. |
| `destonly` / `sourceonly` | **N** | Large (host-direction redesign) | Excludes rules in one direction. Touches every zone-pair dispatch. |
| `nomark` | **N** | Medium (mark allocator) | Skip mark for iface; multi-ISP/QoS interaction. |
| `upnp` / `upnpclient` | **N** | Medium (NAT-chain plumbing) | UPnP forwarding helper / client accept. |
| `wait` | **N** | Small (runtime) | Init-time wait for iface availability. Runtime concern, not compiler. |
| `detectnets` | **N** | n/a (OBSOLETE) | Deprecated in Perl. Don't implement. |
| `norfc1918` | **N** | n/a (OBSOLETE) | Deprecated in Perl. Don't implement. |

## Zone flags / options

Perl `%validzoneoptions` (Zones.pm:354–366):
`mss`, `nomark`, `blacklist`, `dynamic_shared`, `strict`, `next`,
`reqid`, `spi`, `proto`, `mode`, `tunnel-src`, `tunnel-dst`.

**State**:
- IPsec subset (`strict`, `next`, `reqid`, `spi`, `proto`, `mode`,
  `tunnel-src`, `tunnel-dst`) parsed in `zones.py:251–343`. Status **F**.
- `mss`, `nomark`, `dynamic_shared`, `blacklist` (zone-level) — **N**.
  See effort table above.

Zone *types* fully matched: `firewall`, `ipv4`, `ipv6`, `ipsec`, `ipsec4`,
`ipsec6`, `bport`, `bport4`, `bport6`, `vserver`, `loopback`, `local`
(zones.py:64–65 = Zones.pm:413–419 + v6).

## Reference-fixture relevance

The reference replay's `etc/shorewall/interfaces` uses only flags now in
state **F**: `tcpflags`, `nosmurfs`, `routefilter`, `arp_filter`,
`blacklist`, `dhcp`, `routeback`, `bridge`, `optional`, `logmartians`.
None of the **N**-state gaps above can affect the current loop's
fail_drop / fail_accept counts — they would only matter on a config that
declares them.

## IPv4/v6 parity

All three NEW additions are family-agnostic:

- `physical=` operates on `iifname`/`oifname` Match values — these are
  layer-3-protocol-independent in nft.
- `unmanaged` filters at `build_zone_model` — applies before family-specific
  rule expansion.
- `required` is parser/storage only — no emit dependency.

`rpfilter` (deferred) would require explicit per-family handling: the
`fib saddr . iif oif != 0` matcher itself is family-agnostic, but the
DHCP exception is IPv4-only (UDP 67/68 from 0.0.0.0) and the Perl
`rpfilter` chain conditionally adds it depending on the active family.
