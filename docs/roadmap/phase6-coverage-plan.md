# Phase 6 — Upstream-Shorewall Config Coverage

**Status: COMPLETE — 2026-04-24** (single-day execution).

15 of 17 WPs landed in 11 cluster commits, +539 tests
(1041 → 1580 passing), zero new production shell-outs (pyroute2
audit PASSED). Deferred: WP-F2 secmarks (low-value SELinux niche)
and WP-E1 Option C (LOGFORMAT + shorewalld nflog dispatcher —
tracked separately in `shorewalld-log-dispatcher-todo.md`).

**Goal**: close the remaining gaps between shorewall-nft's Python compiler
and the upstream Shorewall (Perl) compiler at v5.2.6.1 (the version this
repo originally forked from). Drive the work through self-contained work
packages (WPs) that a Sonnet agent can execute autonomously.

**Original status as of 2026-04-24**: Phases 1–5 (maintainability refactor) are
complete. Two open audit tasks (#44 full snat, #38 simlab alignment)
plus the gaps surfaced by the 2026-04-24 three-agent coverage audit
(file inventory, `shorewall.conf` options, per-file column OPTIONS) seed
this phase.

**Reference upstream tree**: `/home/avalentin/projects/marcant-fw/shorewall.old/`
checked out at tag `5.2.6.1`. Perl module paths below all live under
`Shorewall/Perl/Shorewall/<module>.pm`.

**Audience**: AI agents (Sonnet) executing the WPs and humans reviewing
their PRs.

---

## Coding standard for Phase 6 agents — `pyroute2`-first

**Hard rule for every WP**: when adding a runtime apply path (anything
called from `runtime/`, anything that touches the live kernel), use
**`pyroute2`** for kernel-state manipulation. Do **not** introduce new
`subprocess` calls to `ip` / `iptables` / `ip6tables` / `tc` /
`conntrack` / `ipset` / `sysctl` in production code.

| Need | Use this |
|---|---|
| Add/del routes, rules, links, addrs, neigh entries | `pyroute2.IPRoute` |
| Conntrack list / flush / count | `pyroute2.NFCTSocket` (already used in shorewalld) |
| Netns lifecycle (create, remove, exec-in) | `pyroute2.netns` + setns-fork pattern |
| nftables ruleset load | `NftInterface.run_script()` (in `nft/netlink.py`) — wraps libnftables when available, falls back to `nft` subprocess |
| sysctl writes | direct write to `/proc/sys/...` (no pyroute2 API for sysctl) |
| Any TC qdisc/class/filter | `pyroute2.IPRoute` (mirror `compiler/tc.py::apply_tc()`) |

Acceptable shell-out exceptions (already documented in the audit):
`nft monitor trace`, `modprobe`, `nft -f` ruleset load (no pyroute2
API for any of these).

For **operator-facing generated scripts** (e.g. `generate-tc`,
`generate-sysctl`, `generate-iproute2-rules`), shell-script output is
the right design and must stay. But every such generator should have
a companion `apply_*()` function in `runtime/` that uses pyroute2 for
the live path.

**Baseline audit**: `docs/roadmap/pyroute2-audit-2026-04-24.md` lists
every existing shell-out and where pyroute2 is already in use.
Re-audit after every cluster lands to ensure no regression.

---

## How a Sonnet agent should consume this doc

Each WP below is **self-contained** and includes:

- **Scope** — exactly what is in / out
- **Upstream reference** — Perl files + line ranges to study before coding
- **Files to touch** — Python paths in this repo
- **Test plan** — concrete `pytest` invocations and assertion ideas
- **Verification fixture** — which fixture to extend (or create)
- **Done when** — measurable exit criteria
- **Blocked by** — dependencies on other WPs

Spawn one sonnet agent per WP unless explicitly grouped. Use
`subagent_type=general-purpose` with `model=sonnet`. The agent must
**always** verify against the upstream Perl semantics before emitting nft
output — a guess that diverges silently from upstream is the worst
possible outcome (silent over-/under-blocking on the live firewall).

Expected agent prompt skeleton:

```
You are implementing WP-<id> from docs/roadmap/phase6-coverage-plan.md.
Read that section AND the "Coding standard for Phase 6 agents —
pyroute2-first" section above, then:
1. Study the upstream Perl reference (paths in the WP).
2. Implement the change in the listed Python files. For any runtime
   apply path, use pyroute2 — do NOT shell out to ip/iptables/tc/
   conntrack/ipset/sysctl. Generators may emit shell scripts but must
   have a companion apply_*() that uses pyroute2.
3. Add unit tests + (where applicable) extend the named fixture.
4. Run: pytest packages/shorewall-nft/tests -q
5. Report: scope, code changes, test results, any deviation from upstream
   semantics with reason, and any subprocess call you added (with
   justification — must match the documented exceptions).
Do NOT touch other WPs. Do NOT bump versions. Do NOT commit — leave
changes staged for human review.
```

---

## Cluster A — NAT / SNAT

### WP-A1 — Full `snat` file support (Task #44)

**Scope**: bring `_process_snat_line()` in
`packages/shorewall-nft/shorewall_nft/compiler/nat.py` to upstream
parity per `shorewall-snat(5)`.

In v1: `SNAT(addr)`, `MASQUERADE`, `CONTINUE` with
`oifname/iifname/saddr/daddr/proto/dport`. Missing:

| Feature | Upstream emit (iptables semantics) |
|---|---|
| `SNAT(a1,a2,…)` round-robin | `snat to numgen inc mod N map { 0:a1, 1:a2, … }` |
| `SNAT(a:port-range)` | `snat to a:p1-p2` |
| `SNAT(a:random)` / `:persistent` / `:fully-random` | nft flags on `snat to` |
| `MASQUERADE(p1-p2)` | `masquerade to :p1-p2` |
| `LOG[:level][:tag]` action prefix | prepend `log prefix "<tag> " level <level>` |
| `ACCEPT` / `NONAT` | `return` (skip-NAT) |
| PROBABILITY column | `meta random < N` |
| MARK column | `meta mark <op> <val>` (mask + negation) |
| USER column | `meta skuid <user>` / `meta skgid <group>` |
| IPSEC column | `policy in/out ipsec` (or `policy … none`) |
| SWITCH column | runtime-toggle via `ct mark` (Shorewall-specific) |
| ORIGDEST column | `ct original ip daddr` |
| Negation prefix `!` on most columns | nft `!=` / set negation |

**Upstream reference**: `Nat.pm` lines for `process_one_snat()`
(approx. 600–950 in 5.2.6.1).

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/nat.py`
  (`_process_snat_line`, helpers)
- `packages/shorewall-nft/shorewall_nft/compiler/verdicts.py`
  (extend `SnatVerdict` + `MasqueradeVerdict` for port-range / flags)
- `packages/shorewall-nft/shorewall_nft/nft/emitter.py`
  (verdict emit for new variants)

**Test plan**:
- Unit: per-feature `tests/test_snat_full.py` — one rule per feature,
  emitted nft fragment substring-checked.
- Fixture: extend `tests/fixtures/ref-ha-minimal/shorewall/snat` with
  one line per feature. Re-run golden snapshot via
  `UPDATE_GOLDEN=1 pytest tests/golden/`.

**Done when**: every column / action variant in `shorewall-snat(5)`
emits a documented nft fragment; `pytest packages/shorewall-nft -q`
green.

**Blocked by**: none.

---

### WP-A2 — Classic `nat` file (1:1 NAT aliases)

**Scope**: parse + emit Shorewall's `nat` file (per-IP 1:1 mapping with
optional `ALL`, `LOCAL`, `INTERFACES` qualifiers). Currently completely
absent.

**Upstream reference**: `Nat.pm::setup_one_nat()` (approx. 1100–1300).

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/config/parser.py` —
  add `nat: list[ConfigLine]` field, file loop entry, merge.
- `packages/shorewall-nft/shorewall_nft/compiler/nat.py` —
  new `process_static_nat()`.
- `packages/shorewall-nft/shorewall_nft/compiler/ir/__init__.py` —
  wire `process_static_nat(ir, config.nat)` after `process_netmap`.
- `packages/shorewall-nft/shorewall_nft/compiler/verdicts.py` —
  may need `StaticNatVerdict` (DNAT + SNAT pair).

**Test plan**:
- Unit: `tests/test_nat_static.py` — at least one EXTERNAL→INTERNAL
  pair with and without `ALL` flag; assert both `dnat to` (PREROUTING)
  and `snat to` (POSTROUTING) rules are emitted.
- Fixture: extend `ref-ha-minimal` with a `nat` file containing one
  test entry, regenerate golden.

**Done when**: 1:1 NAT round-trip works (probe sees DNAT inbound +
SNAT outbound).

**Blocked by**: none.

---

## Cluster B — Multi-ISP / Routing

### WP-B1 — `providers` file: full implementation

**Scope**: today only `mark` → `mangle-prerouting` rule is emitted.
Need full provider semantics.

**Upstream reference**: `Providers.pm` — `process_a_provider()`
(approx. 380–950).

**Out-of-band routing setup** (writing to `/etc/iproute2/rt_tables`,
`ip rule add`, `ip route add table <id>`) is **runtime** work — emit
shell commands into the start-script (or a separate
`generate-iproute2-rules` subcommand), not into the nft script.

Required column handling:
- `INTERFACE` — bind a routing table to an iface
- `MARK` — already done; preserve
- `DUPLICATE` — copy existing routing table
- `OPTIONS`: `track`, `balance=N`, `fallback=N`, `loose`,
  `optional`, `persistent`, `primary`, `tproxy`
- `COPY` — interfaces whose routes get copied into the provider table

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/providers.py` —
  full `parse_providers()` + new `emit_provider_routing_setup()`.
- `packages/shorewall-nft/shorewall_nft/runtime/cli/generate_cmds.py` —
  new `generate-iproute2-rules` subcommand.

**Test plan**:
- Unit: `tests/test_providers_full.py` — assert every `OPTIONS` token
  produces the expected `ip rule` / `ip route` line in the start-script
  output.

**Done when**: a two-provider config compiles to a complete set of
routing tables + balance rules + mark fwmark dispatches.

**Blocked by**: none. Coordinate with WP-B2 for shared `routes` file
parsing.

---

### WP-B2 — `routes` and `rtrules` files

**Scope**: parse and emit both. Today neither is consumed.

**Upstream reference**: `Providers.pm::process_routes()` and
`process_rtrules()` (approx. 1200–1500).

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/config/parser.py` — add
  `routes`, `rtrules` fields + file loop entries.
- `packages/shorewall-nft/shorewall_nft/compiler/providers.py` —
  `emit_extra_routes()`, `emit_extra_rtrules()`.

**Test plan**:
- Unit: assert generated `ip route add` / `ip rule add` lines match
  upstream-equivalent fixtures.

**Done when**: a config with `routes` + `rtrules` produces a complete
start-script section that, when executed on a clean host, builds the
expected routing geometry.

**Blocked by**: WP-B1 (shares parsing helpers).

---

### WP-B3 — Multi-ISP `shorewall.conf` options

**Scope**: honour `USE_DEFAULT_RT`, `BALANCE_PROVIDERS`,
`RESTORE_DEFAULT_ROUTE`, `OPTIMIZE_USE_FIRST` for provider behaviour.

**Upstream reference**: `Config.pm` settings table; `Providers.pm`
where each setting branches behaviour.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/providers.py`

**Test plan**:
- Unit: matrix tests over the four option combinations.

**Done when**: each setting toggles emitted rule shape per upstream
behaviour table.

**Blocked by**: WP-B1.

---

## Cluster C — TC / QoS

### WP-C1 — `tcinterfaces` flow classes

**Scope**: today only the shaping toggle is recognised. Need full
HTB/HFSC/cake setup per row.

**Upstream reference**: `Tc.pm::process_tcinterfaces()`
(approx. 2400–2700).

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/tc.py`
- `packages/shorewall-nft/shorewall_nft/runtime/cli/generate_cmds.py`
  (`generate-tc` already exists — extend it).

**Test plan**:
- Unit: `tests/test_tcinterfaces.py` — assert emitted `tc qdisc` /
  `tc class` / `tc filter` lines.

**Done when**: a tcinterfaces row produces a working HTB tree.

**Blocked by**: none.

---

### WP-C2 — `tcpri` DSCP→prio map

**Scope**: parse `tcpri` file and emit nft `meta priority set` map.

**Upstream reference**: `Tc.pm::process_tcpri()` (approx. 2800–2900).

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/tc.py`
- `packages/shorewall-nft/shorewall_nft/config/parser.py`

**Test plan**:
- Unit: `tests/test_tcpri.py` — emitted nft includes the expected
  DSCP→prio mapping.

**Done when**: a config with tcpri compiles to nft rules that classify
by DSCP into Linux priorities.

**Blocked by**: none.

---

### WP-C3 — Mark geometry settings

**Scope**: respect `WIDE_TC_MARKS`, `HIGH_ROUTE_MARKS`, `MASK_BITS`,
`PROVIDER_BITS`, `TC_BITS`, `ZONE_BITS`. Today the emitter assumes a
fixed mark layout — this can collide with provider marks under non-
default geometry.

**Upstream reference**: `Config.pm::initialize()` mark-geometry block
(approx. 4500–4700) + `Tc.pm` mark masking.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/ir/_data.py` —
  add `MarkGeometry` dataclass populated from settings.
- `packages/shorewall-nft/shorewall_nft/compiler/providers.py`
- `packages/shorewall-nft/shorewall_nft/compiler/tc.py`

**Test plan**:
- Unit: `tests/test_mark_geometry.py` — given a config with
  `WIDE_TC_MARKS=Yes`, assert emitted masks shift accordingly.

**Done when**: the geometry settings round-trip into emitted nft mark
masks.

**Blocked by**: none. Should land **before** WP-B1 lands the provider
mark-fwmark dispatcher to avoid double-rework.

---

### WP-C4 — `TC_ENABLED`, `TC_EXPERT`, `MARK_IN_FORWARD_CHAIN`,
`CLEAR_TC`

**Scope**: respect the four TC-mode toggles.

**Upstream reference**: scattered through `Tc.pm`; see grep for each
constant in `Config.pm`.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/tc.py`

**Test plan**:
- Unit: matrix tests over each toggle.

**Done when**: each setting selects the documented branch.

**Blocked by**: WP-C1 (shares emit helpers).

---

## Cluster D — Per-host / per-interface OPTIONS

### WP-D1 — `interfaces` OPTIONS extras

**Scope**: today honoured: `routeback`, `tcpflags`, `nosmurfs`,
`dhcp`, `physical`, `bridge`. Missing:

| Option | Effect |
|---|---|
| `mss=N` | TCP MSS clamp (`tcp option maxseg size set N`) |
| `sourceroute=0|1` | sysctl `accept_source_route` |
| `optional` | iface may be down at start (skip emit if down) |
| `proxyarp=1` | sysctl `proxy_arp` |
| `routefilter=0|1|2` | sysctl `rp_filter` |
| `logmartians=0|1` | sysctl `log_martians` |
| `arp_filter=0|1`, `arp_ignore=N` | sysctl `arp_filter`/`arp_ignore` |
| `forward=0|1` | sysctl `forwarding` |
| `accept_ra=0|1|2` | sysctl `accept_ra` (IPv6) |

**Upstream reference**: `Zones.pm::process_interface()` (approx.
1500–1900) + `Proc.pm` for the sysctl writers.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/ir/_build.py` —
  `_process_interface_options()` (extend existing).
- `packages/shorewall-nft/shorewall_nft/compiler/sysctl.py` —
  emit per-iface sysctl writes into the runtime helper.
- `packages/shorewall-nft/shorewall_nft/nft/emitter.py` — `mss=`
  needs MSS-clamp rule emit.

**Test plan**:
- Unit: per-option `tests/test_interface_options_extras.py`.

**Done when**: each option produces either an nft rule (mss) or a
sysctl write (everything else) at apply time.

**Blocked by**: none.

---

### WP-D2 — `hosts` OPTIONS

**Scope**: per-host options — currently **none** are honoured.

| Option | Effect |
|---|---|
| `routeback` | host-scoped routeback (per-zone) |
| `blacklist` | host source matched against blacklist set |
| `tcpflags`, `nosmurfs` | per-host invocations of the same chains |
| `maclist` | per-host MAC-list enforcement |
| `mss=N` | per-host MSS clamp |
| `ipsec` | match `policy in/out ipsec` |
| `broadcast`, `destonly`, `sourceonly` | direction filters |

**Upstream reference**: `Zones.pm::process_host()` (approx. 2100–2400).

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/config/zones.py`
- `packages/shorewall-nft/shorewall_nft/compiler/ir/_build.py`

**Test plan**:
- Unit: `tests/test_hosts_options.py`.

**Done when**: each per-host option produces the documented filter.

**Blocked by**: none.

---

### WP-D3 — `zones` IPsec OPTIONS

**Scope**: zones of type `ipsec`/`ipsec4`/`ipsec6` need OPTIONS
parsing: `mss=`, `strict`, `next`, `reqid=`, `spi=`, `proto=`,
`mode=`, `mark=`.

**Upstream reference**: `Zones.pm::process_zone()` (approx. 800–1100).

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/config/zones.py`
- `packages/shorewall-nft/shorewall_nft/compiler/ir/rules.py`
  (zone-pair chain emit needs to include `policy ipsec` matches when
  source / dest is an ipsec zone).

**Test plan**:
- Unit: `tests/test_ipsec_zones.py` — given an ipsec zone, every rule
  emitted into chains involving that zone carries the matching
  `policy in/out ipsec reqid X spi Y proto esp mode tunnel` clause.

**Done when**: ipsec zone rules emit with the upstream-equivalent
policy matches.

**Blocked by**: none.

---

## Cluster E — Logging / dispositions

### WP-E1 — Log infra knobs

**Scope**: respect `LOG_LEVEL`, `LOG_BACKEND`, `STARTUP_LOG`,
`LOGFILE`, `LOGFORMAT`. Today only per-rule LOG levels are emitted.

**Upstream reference**: `Config.pm` (settings) + `Chains.pm::log_rule()`.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/nft/emitter.py` — log fragment
  builder reads settings.

**Test plan**:
- Unit: `tests/test_log_settings.py` — verify default level + format
  flow into emitted `log prefix … level …` lines.

**Done when**: `LOG_BACKEND=netlink` produces `log group N`,
`LOG_BACKEND=LOG` produces `log prefix … level …`, etc.

**Blocked by**: none.

---

### WP-E2 — Disposition settings

**Scope**: `BLACKLIST_DISPOSITION`, `SMURF_DISPOSITION`,
`TCP_FLAGS_DISPOSITION` — replace hard-coded `drop` / `reject` in the
generated chains with the configured action (e.g. `A_DROP` = audit +
drop).

**Upstream reference**: `Chains.pm` — disposition macro lookup.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/actions.py` —
  `create_action_chains()` reads dispositions.
- `packages/shorewall-nft/shorewall_nft/compiler/ir/_build.py` —
  `_process_interface_options()` (smurf branch).

**Test plan**:
- Unit: matrix over `{DROP, REJECT, A_DROP, A_REJECT}` for each
  disposition setting.

**Done when**: each disposition setting changes the verdict in the
corresponding generated chain.

**Blocked by**: none.

---

### WP-E3 — `BLACKLIST` file + `DYNAMIC_BLACKLIST` modes

**Scope**: parse the standalone `BLACKLIST` file (vs `blrules` which
is already supported); honour `DYNAMIC_BLACKLIST=ipset-only`,
`ipset,disconnect`, `ipset,disconnect-src`, `Yes`, `No`.

**Upstream reference**: `Misc.pm::setup_blacklist()` and
`process_dynamic_blacklist()`.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/actions.py`
  (`create_dynamic_blacklist`).
- `packages/shorewall-nft/shorewall_nft/config/parser.py`
  (parse `BLACKLIST` file).

**Test plan**:
- Unit: per-mode test in `tests/test_blacklist_modes.py`.

**Done when**: each `DYNAMIC_BLACKLIST` mode produces the matching
nft set + chain shape.

**Blocked by**: none.

---

## Cluster F — proxyarp / secmarks / NAT-aliases

### WP-F1 — `proxyarp` / `proxyndp` nft emit

**Scope**: today only the `/proc/sys/.../proxy_arp` sysctl is set.
Upstream also installs `arp` rules and (for ndp) `ip6 nexthdr icmpv6
icmpv6 type neighbor-{solicit,advert}` filters.

**Upstream reference**: `Proxyarp.pm::setup_one_proxy_arp()`.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/proxyarp.py`
- `packages/shorewall-nft/shorewall_nft/runtime/apply.py` —
  proxyarp sysctl + neighbour-table writes at start.

**Test plan**:
- Unit: `tests/test_proxyarp.py` — assert sysctl + nft emit shape.
- Integration: simlab netns probe — proxyarp host receives ARP from
  outside zone.

**Done when**: a proxyarp config produces both the kernel state
changes and the nft filter rules.

**Blocked by**: none.

---

### WP-F2 — `secmarks` (SELinux labels)

**Scope**: parse `secmarks` and emit `secmark` set + `meta secmark
set …` rules. Currently the file is silently ignored.

**Upstream reference**: `Rules.pm::process_secmark_rule()`.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/config/parser.py`
- `packages/shorewall-nft/shorewall_nft/compiler/ir/_build.py` —
  new `_process_secmarks()`.
- `packages/shorewall-nft/shorewall_nft/nft/emitter.py`

**Test plan**:
- Unit: `tests/test_secmarks.py` — emitted nft contains
  `meta secmark set "<label>"`.

**Done when**: a secmarks line produces the matching nft secmark rule.

**Blocked by**: none. Low priority — most deployments don't use
SELinux on the firewall.

---

### WP-F3 — IP-alias setup options

**Scope**: respect `ADD_IP_ALIASES`, `ADD_SNAT_ALIASES`,
`RETAIN_ALIASES`, `DETECT_DNAT_IPADDRS`. These are runtime concerns —
auto-add IP aliases on the configured interface for SNAT/DNAT
addresses.

**Upstream reference**: `Nat.pm::setup_addresses()` and
`Misc.pm::compile_stop_firewall()`.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/runtime/apply.py` — alias
  lifecycle hooks.

**Test plan**:
- Unit: `tests/test_ip_aliases.py` — given a SNAT to a non-iface IP
  with `ADD_SNAT_ALIASES=Yes`, the apply step calls
  `ip addr add <ip>/32 dev <iface>`.

**Done when**: alias add / remove fires at start / stop per setting.

**Blocked by**: WP-A1 (full snat needed first to know which addrs
are SNAT targets).

---

## Cluster G — Policy column extras

### WP-G1 — `LIMIT:BURST` in policy + rules

**Scope**: per-rule rate limiting. Today the LIMIT column is
recognised in some branches but not consistently.

**Upstream reference**: `Rules.pm::process_rule()` LIMIT branch.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/compiler/ir/rules.py`
- `packages/shorewall-nft/shorewall_nft/nft/emitter.py` —
  `limit rate N/second burst M packets` fragment.

**Test plan**:
- Unit: `tests/test_rule_limit.py`.

**Done when**: `LIMIT:LOGIN,12,60` on a rule produces the equivalent
nft `limit rate 12/minute burst 60 packets` clause.

**Blocked by**: none.

---

### WP-G2 — `CONNLIMIT`

**Scope**: per-source connection limit (`-m connlimit`).

**Upstream reference**: `Rules.pm` CONNLIMIT branch.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/nft/emitter.py` — emit
  `ct count over N` fragment.

**Test plan**:
- Unit: `tests/test_connlimit.py`.

**Done when**: a rule with `CONNLIMIT 10:32` emits
`ct count over 10` (with /32 source mask).

**Blocked by**: none.

---

### WP-G3 — `synparams`

**Scope**: SYN-flood protection — `synparams` file.

**Upstream reference**: `Rules.pm::process_synparams()`.

**Files to touch**:
- `packages/shorewall-nft/shorewall_nft/config/parser.py`
- `packages/shorewall-nft/shorewall_nft/compiler/ir/_build.py`

**Test plan**:
- Unit: `tests/test_synparams.py`.

**Done when**: a synparams row generates the matching syn-rate-limit
chain.

**Blocked by**: none.

---

> **Note**: Simlab alignment (was WP-H1, Task #38) is tracked
> separately in `docs/roadmap/simlab-alignment-todo.md` — it is a
> standalone investigation, not part of this coverage phase.

---

## Recommended sequencing

```
WP-C3 ──┐
        ├── WP-B1 ── WP-B2 ── WP-B3        (multi-ISP runway)
        │
WP-A1 ──┴── WP-A2 ── WP-F3                  (NAT runway)
WP-C1 ──── WP-C2 ──── WP-C4                 (TC runway)
WP-D1, WP-D2, WP-D3                         (independent OPTIONS — parallel)
WP-E1, WP-E2, WP-E3                         (logging — parallel)
WP-F1, WP-F2                                (low priority — parallel)
WP-G1, WP-G2, WP-G3                         (rate limiting — parallel)
```

`WP-A1` and `WP-C3` are the two most load-bearing roots — they unblock
the largest follow-on chains. Do them first.

---

## Tracking

Open Tasks at the start of Phase 6:
- `#44` — covers WP-A1

The remaining WPs (A2, B1–B3, C1–C4, D1–D3, E1–E3, F1–F3, G1–G3)
have TaskCreate entries pointing to their section in this doc.

## Done criteria for the whole phase

1. Every WP closed with passing tests + documentation updates.
2. `tools/shorewall-compile.sh` against `ref-ha-minimal/` shows no
   diff against `shorewall-nft compile` for any feature in this doc.
3. Coverage-audit re-run (rerun the three sonnet audit agents from
   2026-04-24) reports no further gaps in the inventoried files /
   options / OPTIONS columns.
4. **pyroute2 audit re-run** — re-execute the audit recorded in
   `docs/roadmap/pyroute2-audit-2026-04-24.md` and verify:
   - No new shell-outs introduced by Phase 6 WPs (compare against
     baseline Category A / Category B counts).
   - At least one of the three highest-value migrations from the
     baseline recommendations has been completed (or filed as an
     explicit deferred ticket).
   - Save the new audit as `docs/roadmap/pyroute2-audit-<DATE>.md`
     for diff-against-baseline traceability.

## See also

- `docs/PRINCIPLES.md` — load-bearing rules (point-of-truth ranking,
  test-report invariants).
- `docs/roadmap/post-1.0-nft-features.md` — orthogonal nft feature
  wishlist (flowtable, ct mark zone tagging, vmap dispatch).
- `docs/testing/point-of-truth.md` — verification ground truth.
- Upstream Perl source: `/home/avalentin/projects/marcant-fw/shorewall.old/`
  at tag `5.2.6.1`.
