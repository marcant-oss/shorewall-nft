# Perl Shorewall vs shorewall-nft — flag coverage audit

Captured 2026-04-27 against:

- `shorewall-nft` Python: `/home/avalentin/projects/marcant-fw/shorewall-nft/packages/shorewall-nft/shorewall_nft/`
- Classic Perl Shorewall: `/home/avalentin/projects/marcant-fw/shorewall.old/Shorewall/Perl/Shorewall/Zones.pm` lines 354–448 (`%validinterfaceoptions`, `%validzoneoptions`).

Method: grepped every Perl-defined option name as a quoted literal in
the Python source (excluding `__pycache__`, tests, docs, macros).
Hits = "appears in compiler/runtime code". 0 hits = definitely not
interpreted; 1–3 = parsed but likely not fully implemented; 4+ = at
least one real call site.

## Interface flags fully missing in shorewall-nft Python

These appear in classic `%validinterfaceoptions` (Zones.pm:369–448) but
have **0 hits** in shorewall-nft source — the parser would either
silently ignore them or trigger a "Unknown option" warning depending
on context.

| Flag | Effect in classic | Notes |
|---|---|---|
| `destonly` | Host marked dest-only — no rules in src direction | Used with `nets=` |
| `detectnets` | Auto-derive subnet from interface address | Marked OBSOLETE in Perl |
| `dbl` / `nodbl` | Dynamic-blacklist switch per iface | New 5.x Perl feature |
| `dynamic_shared` | Shared dynamic blacklist set | Zone-level option |
| `nets=` | Inline subnet list per iface | Common in customer setups |
| `nomark` | Skip mark for interface | Multi-ISP/QoS interaction |
| `norfc1918` | Drop RFC1918 src on iface | OBSOLETE in Perl |
| `physical=` | Real iface name when zone uses alias | Used with VLANs / dummies |
| `required` | Fail-fast if iface absent at start | vs `optional` |
| `rpfilter` | Kernel `rp_filter=1` (matches `routefilter`) | Already partially via `routefilter` |
| `sfilter=` | Source-filter list (anti-spoof) | Per-iface CIDR list |
| `sourceonly` | Host marked source-only (zone option) | Mirrors `destonly` |
| `unmanaged` | Skip iface entirely | Used with bond slaves |
| `upnp` / `upnpclient` | UPnP forwarding helper | shorewall-nft scope-out? |
| `wait` | Seconds to wait for iface at start | Probably init-only |

## Interface flags with thin coverage (1–3 hits — parse-only or partial)

| Flag | Python hits | Likely state |
|---|---:|---|
| `bridge` | 1 | Parsed in zones.py; no nft emit logic for bridge-aware rules |
| `arp_ignore` | 2 | Sysctl path only |
| `mss=` | 2 | Probably just stored, no clamping rule emitted |
| `optional` | 2 | Stored, no skip-at-load logic |
| `logmartians` | 3 | Sysctl path only |
| `nosmurfs` | 3 | sw_DropSmurfs exists; per-iface gating may be missing |
| `sourceroute` | 3 | Sysctl path only |
| `tcpflags` | 3 | sw_TCPFlags exists; per-iface gating unclear |

## Interface flags with substantial coverage (4+ hits)

`accept_ra`, `arp_filter`, `blacklist`, `broadcast`, `dhcp`,
`forward`, `maclist`, `proxyarp`, `proxyndp`, `routeback`,
`routefilter`. (May still have edge-case gaps but call sites exist.)

## Zone flags / options

Perl `%validzoneoptions` (Zones.pm:354–366):
`mss`, `nomark`, `blacklist`, `dynamic_shared`, `strict`, `next`,
`reqid`, `spi`, `proto`, `mode`, `tunnel-src`, `tunnel-dst`.

Of these, shorewall-nft's `zones.py:251–343` parses the IPsec subset
(`strict`, `next`, `reqid`, `spi`, `proto`, `mode`, `tunnel-src`,
`tunnel-dst`) for `ipsec` zones. `mss`, `nomark`, `dynamic_shared`,
`blacklist`(at zone level) → not parsed as zone options today.

Zone *types* fully matched: `firewall`, `ipv4`, `ipv6`, `ipsec`,
`ipsec4`, `ipsec6`, `bport`, `bport4`, `bport6`, `vserver`,
`loopback`, `local` (zones.py:64–65 = Zones.pm:413–419 + v6).

## Likely-relevant gaps for the marcant-fw reference replay

The rossini `etc/shorewall/interfaces` only uses flags that
shorewall-nft *does* recognise (`tcpflags`, `nosmurfs`, `routefilter`,
`arp_filter`, `blacklist`, `dhcp`, `routeback`, `bridge`, `optional`,
`logmartians`). So the loop's remaining 31 fail_drops + 6 fail_accept
are unlikely to be caused by missing-flag interpretation — except
possibly:

- **`sfilter=`** (used in `routefilter=2` style configs) — would
  affect anti-spoofing decisions.
- **`physical=`** when a zone aliases a real iface — none in rossini.
- **`mss=`** — affects MTU paths but not FILTER decisions.

Recommendation: prioritise the loop's Cluster B (Topologie/FRR
routes) and the DHCP-Auto-Emit cluster over flag-coverage gaps.

## Methodology limits

`grep` for the literal flag name catches most call sites but misses:

- variable-driven dispatchers (`getattr(iface, flag, None)`)
- options stored in a dict and accessed via key-string
- comments mentioning the flag without code

So "0 hits" overstates the gap slightly.  Confirm a "missing" flag
by running a config that uses it — the parser warning surfaces
quickly.
