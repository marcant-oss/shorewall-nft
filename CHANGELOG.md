# Changelog

All notable changes to shorewall-nft are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (Phase I — dual-stack v4/v6 production parity)

- **`--family {4,6,both}`** global flag on `shorewall-nft-simlab`
  and `--family` option on `shorewall-nft simulate`.  Controls which
  IP address families are exercised; default is `both`.  When omitted,
  the effective family is auto-detected from the available dump files
  in `--data`: both `iptables.txt` + `ip6tables.txt` present → `both`;
  only `iptables.txt` → `4`; only `ip6tables.txt` → `6`.  Requesting
  an unsatisfied family (e.g. `--family 6` without `ip6tables.txt`) is
  a hard error.
- **`run_simulation_from_config(family=...)`** — the simlab Python API
  now accepts the `family` parameter so programmatic callers can
  restrict probe generation to a single address family.
- **Parser-level auto-detect** in both CLIs: the family is derived from
  the dump files present at startup, not hard-coded to IPv4.
- **IPv6 probe parity** confirmed in `simulate.py`:
  - `derive_tests_all_zones(family=6)` now properly gates v4/v6
    generation through the `_run_v4`/`_run_v6` flags in
    `run_simulation`.
  - All probe dispatch paths (`run_tcp_test`, `run_udp_test`,
    `run_icmp_test`) already honour `family=6` — audited and
    confirmed; no silent v4-only shortcuts found.
  - `RandomProbeGenerator.next()` already picks v6 subnets from the
    FwState address pool and emits `icmpv6` instead of `icmp` —
    confirmed correct.

### Changed

- `docs/testing/simlab.md`: removed the stale "IPv4 only for the
  moment" note from "Known limitations".  Added the new `--family`
  section with v4-only / v6-only / dual-stack examples and a
  description of v6 probe parity.
- `tools/man/shorewall-nft-simlab.8`: documented the `--family`
  global option.
- `tools/man/shorewall-nft.8`: documented `--family` in the
  `simulate` subcommand section.

### Added (simlab live-state collector + `--data` integration)

- **`tools/simlab-collect.sh`** — small bash helper that captures a
  firewall's live address / route / policy-rule / link / netfilter
  snapshot into a directory compatible with simlab's `--data DIR`.
  Two-tier output: Tier 1 (rtnetlink reads, dynamic-routing daemon
  RIB) is fully unprivileged and works under any uid; Tier 2
  (iptables-save, ip6tables-save, nft list ruleset, ipset save,
  conntrack -L) requires CAP_NET_ADMIN and is skipped with a clear
  manifest note when run as a non-root user. Per-capture status is
  recorded in `manifest.txt` so operators can tell at a glance what
  ran and what was skipped. New man page
  `shorewall-nft-simlab-collect.1`.
- **`shorewall-nft simulate --data DIR`** — when set, delegates to
  shorewall-nft-simlab via the new `api.run_simulation_from_config()`
  entry point. The DIR is consumed in simlab's expected layout
  (typically produced by the collector). When `--data` is absent the
  in-tree `verify/simulate.py` veth-based validator runs as before;
  no regression. `--iptables` becomes optional in `--data` mode (the
  ruleset comes from `<data>/iptables.txt`).
- **shorewall-nft-simlab `api.run_simulation_from_config()`** — thin
  programmatic entry point wrapping the existing `cmd_full` pipeline.
  Returns a flat `list[SimResult]` extracted from simlab's
  `report.json` so the calling shorewall-nft CLI can render results
  in its native format. Eliminates simlab follow-up #76 (FwState
  synthesis from config — never needed; live state is captured
  instead).

### Added

- **shorewalld NFLOG log dispatcher (MVP)** — shorewalld can now
  subscribe to `nfnetlink_log` inside every managed netns and
  surface matches as a Prometheus counter plus up to four
  drop-on-full sinks: plain file, unix-socket JSON fan-out,
  systemd-journald, and `/dev/log` (RFC 3164). Replaces the per-netns
  `ulogd2` plumbing for operators who already run shorewalld per
  netns. Activate with `LOG_DISPATCH=shorewalld` +
  `LOG_NFLOG_GROUP=<N>` in `shorewalld.conf` (must match the
  `N` in `nft log group N`); sinks are additive. Three new
  Prometheus families: `shorewall_log_total{chain,disposition,netns}`
  (monotonic per triple), `shorewall_log_events_total` (label-free
  grand total), `shorewall_log_dropped_total{reason}` (per-sink
  backpressure visibility). Backpressure contract holds on every
  stage: a slow SIEM / journald / file consumer never stalls the
  hot path — a full sink queue drops the event and bumps its
  drop counter. See `docs/shorewalld/index.md` § NFLOG log
  dispatcher for operator reference. Tests: +84 cases (wire codec,
  prefix parser, dispatcher semantics, every sink end-to-end,
  drop-on-full regression, IPC integration). Ships the hand-rolled
  `NFULogSocket` (pyroute2 has no NFLOG class as of 0.9.6 — upstream
  PR viable as a follow-up).

- **WP-E1 Option C (compiler side) — `LOGFORMAT` /
  `MAXZONENAMELENGTH` / `LOGRULENUMBERS`** — `LogSettings` gains
  `log_format` (default `"Shorewall:%s:%s:"`, matches previous
  hardcoded template and the shorewalld dispatcher's prefix parser),
  `max_zone_name_length` (default 5, truncates the zone-pair part of
  the chain substitution — upstream MAXZONENAMELENGTH semantics),
  and `rule_numbers` (parsed from `LOGRULENUMBERS` but not yet wired
  into prefix generation — per-rule sequence numbers need a counter
  threaded through every `_add_rule` site, filed as follow-up). New
  method `LogSettings.format_prefix(chain, disposition)` renders the
  template with %s substitution + zone-name truncation + safe
  fallback on malformed templates. Call-site migration: the single
  compile-time hardcoded `Shorewall:<chain>:<DISP>:` string at
  `compiler/ir/rules.py:1015` now goes through the helper. Default
  output is byte-identical to the previous behaviour, so the
  shorewalld NFLOG dispatcher's prefix parser works unchanged for
  any config that does not override `LOGFORMAT`. Tests: +9 cases in
  `tests/test_log_settings.py::TestLogFormat`.

- **shorewalld keepalived SNMP integration (Unix socket + MIB + traps +
  D-Bus methods, final wiring)** — `KEEPALIVED_SNMP_UNIX` activates the
  MIB-driven KeepalivedDispatcher: a periodic full walk of the KEEPALIVED-MIB
  (26 tables + 32 scalars from keepalived 2.3+), auto-registered Prometheus
  families (one gauge or counter per MIB column, no hardcoded OID list), and
  an SNMPv2c trap listener for `vrrpSyncGroupStateChange` /
  `vrrpInstanceStateChange` events. D-Bus method surface exposed through the
  control socket: `keepalived-data`, `keepalived-stats`, `keepalived-reload`,
  `keepalived-garp` — gated by a 3-tier ACL (`KEEPALIVED_DBUS_METHODS`).
  Every sub-component (python3-netsnmp walker, pysnmp trap listener, dbus-next
  client) has a soft-degrade path: missing library logs a warning and drops
  only that capability, the daemon does not abort. `KEEPALIVED_SNMP_UNIX` is
  required to activate any of the above; without it the daemon behaves as
  before. 7 new `KEEPALIVED_*` config keys + CLI flags. +31 tests.

### Deprecated

- **Legacy `VRRP_SNMP_*` UDP collector path** — when `KEEPALIVED_SNMP_UNIX`
  is set alongside `VRRP_SNMP_ENABLED=yes`, shorewalld emits a deprecation
  warning at startup and runs both collectors in parallel (metric families
  `shorewall_vrrp_*` vs `shorewalld_keepalived_*` do not collide). The UDP
  path continues to work for one release. Remove `VRRP_SNMP_ENABLED` and
  related keys from `shorewalld.conf` to silence the warning and fully
  migrate to the Unix-socket path. See `docs/shorewalld/keepalived-snmp.md`
  for the migration table.

## [1.10.2] - 2026-04-24

Phase 6 — upstream-Shorewall config-coverage parity, plus pyroute2-first
migration, two new architecture principles (P8 backend-pluggable, P9
resource-efficient agent execution), and three maintenance refactors
(pyroute2_helpers, typed FirewallIR list fields, BackendEmitter
protocol scaffold).

Tests grew **1041 → 1616 (+575)**. Zero new production shell-outs
(pyroute2-first audit PASSED).

### Added (Phase 6 — upstream-Shorewall config-coverage parity)

Closes the largest remaining gaps between the Python compiler and
upstream Shorewall (Perl) at tag `5.2.6.1`. Driven by a 2026-04-24
multi-agent audit; executed via the work-package plan in
`docs/roadmap/phase6-coverage-plan.md`. Test count grew from 1041
to 1580 (+539). Zero new production shell-outs (pyroute2-first
standard, see `docs/PRINCIPLES.md` P9).

- **`snat`** file — full upstream parity: `SNAT(addr)`,
  `SNAT(a1,a2,…)` round-robin, `SNAT(addr:port-range)`,
  `:random`/`:persistent`/`:fully-random` flags,
  `MASQUERADE(port-range)`, `CONTINUE`/`ACCEPT`/`NONAT`,
  `LOG[:level][:tag]:…` action prefix; column matchers
  `PROBABILITY`, `MARK`, `USER`, `SWITCH`, `ORIGDEST`, `IPSEC`
  (each with `!` negation).
- **`nat`** file — classic 1:1 mapping (`EXTERNAL INTERFACE INTERNAL
  ALL LOCAL`); emits paired PREROUTING DNAT + POSTROUTING SNAT, plus
  optional OUTPUT DNAT for `LOCAL=Yes`.
- **`providers`** — full implementation: `track`, `balance=N`,
  `fallback=N`, `loose`, `optional`, `persistent`, `primary`,
  `tproxy`. New CLI `shorewall-nft generate-iproute2-rules`
  emits the operator shell script; `runtime.apply.apply_iproute2_rules()`
  is the live-apply path via pyroute2.
- **`routes`** + **`rtrules`** files — both parsed and emitted.
- **`tcinterfaces`** — full HTB / HFSC / cake qdisc support;
  `apply_tcinterfaces()` uses pyroute2 (mirrors `apply_tc()`).
- **`tcpri`** — DSCP→priority map emitted as nft `meta priority set`
  vmap.
- **`synparams`** — per-zone SYN-flood guard chains
  `synflood-<zone>`; jump-prefix injected on TCP-SYN matches in
  zone-pair chains.
- **`blacklist`** standalone file (legacy form) — parsed and emitted
  as drop rules.
- **`hosts` OPTIONS** — `routeback`, `blacklist`, `tcpflags`,
  `nosmurfs`, `maclist`, `mss=N`, `ipsec`, `broadcast`, `destonly`,
  `sourceonly`.
- **`interfaces` OPTIONS extras** — `mss=N`, `sourceroute`,
  `optional`, `proxyarp=1`, `routefilter`, `logmartians`,
  `arp_filter`, `arp_ignore`, `forward`, `accept_ra`. Sysctl
  generator switched from `sysctl -w` shell calls to direct
  `printf > /proc/sys/...` writes.
- **`zones` IPsec OPTIONS** — `mss=`, `strict`, `next`, `reqid=`,
  `spi=`, `proto=`, `mode=`, `mark=`. Zone-pair chain emit injects
  `policy in|out ipsec …` clauses for ipsec zones.
- **proxyarp / proxyndp nft emit** — explicit `arp …` and
  `ip6 nexthdr icmpv6 …` filter rules complementing the kernel's
  implicit `proxy_arp`/`proxy_ndp` mechanism (shorewall-nft
  extension over upstream).
- **IP-alias setup** — `ADD_IP_ALIASES`, `ADD_SNAT_ALIASES`,
  `RETAIN_ALIASES` honoured. `apply_ip_aliases()` /
  `remove_ip_aliases()` use pyroute2 `IPRoute.addr()` (zero
  shell-outs). `DETECT_DNAT_IPADDRS` is flag-only honoured;
  live-discovery branch deferred.
- **`shorewall.conf` settings honoured** — multi-ISP geometry
  (`USE_DEFAULT_RT`, `BALANCE_PROVIDERS`, `RESTORE_DEFAULT_ROUTE`,
  `OPTIMIZE_USE_FIRST`); mark geometry (`WIDE_TC_MARKS`,
  `HIGH_ROUTE_MARKS`, `TC_BITS`, `MASK_BITS`, `PROVIDER_BITS`,
  `PROVIDER_OFFSET`, `ZONE_BITS`); TC mode (`TC_ENABLED`,
  `TC_EXPERT`, `MARK_IN_FORWARD_CHAIN`, `CLEAR_TC`);
  dispositions (`BLACKLIST_DISPOSITION`, `SMURF_DISPOSITION`,
  `TCP_FLAGS_DISPOSITION`, `RELATED_DISPOSITION`,
  `INVALID_DISPOSITION`, `UNTRACKED_DISPOSITION`, with `A_*` audit
  variants); dynamic blacklist modes (`DYNAMIC_BLACKLIST=No|Yes|
  ipset-only|ipset,disconnect|ipset,disconnect-src`); rate limiting
  (`LIMIT:BURST`, `CONNLIMIT`); logging
  (`LOG_LEVEL`, `LOG_BACKEND={LOG,netlink/NFLOG,ULOG}`,
  `LOG_GROUP`).
- **`MarkGeometry` IR dataclass** — typed mark-mask layout populated
  from settings; replaces hardcoded mask assumptions; foundation
  for provider/TC mark cohabitation under non-default geometry.

### Added (architecture / process)

- **`docs/PRINCIPLES.md` P8 — Backend-pluggable architecture** —
  IR + parser stay backend-agnostic so nft can be replaced (or
  joined) by VPP, BPF/XDP, switchdev without touching `compiler/`
  or `config/`. Direction, not yet fully implemented.
- **`docs/PRINCIPLES.md` P9 — Resource-efficient agent execution** —
  cluster + parallelise + cheapest-model-that-fits is mandatory for
  multi-step / multi-agent work.
- **`docs/roadmap/upstream-excerpts/`** — 5855 verbatim Perl LOC
  from `shorewall.old` at tag `5.2.6.1`, the functions agents need
  to reference instead of re-reading the full 34k-line module tree.
- **`docs/roadmap/pyroute2-audit-2026-04-24.md`** + final
  post-Phase-6 audit — verdict PASS, zero new production
  shell-outs introduced.
- **`docs/roadmap/shorewalld-log-dispatcher-todo.md`** — standalone
  TODO (Task #69) for the Option C extension to logging:
  LOGFORMAT/LOGRULENUMBERS + shorewalld as the per-netns nflog
  dispatcher (replaces ulogd2 plumbing).
- **`docs/roadmap/simlab-alignment-todo.md`** — standalone TODO
  (Task #38) split out of Phase 6.

### Refactor (pyroute2 migration follow-ups)

- **`verify/connstate.py`** — `conntrack -L` / `conntrack -F` shell
  calls replaced with `pyroute2.NFCTSocket.dump()` / `.flush()`.
- **`verify/simulate.py`** — last `iptables`/`ip6tables` REDIRECT
  calls in production code replaced with nft inet-family table
  loaded via the existing nft helper. Production grep for
  `"iptables"`/`"ip6tables"` now returns zero binary-call hits.

### Added (tools/shorewall-compile.sh)

- **`tools/shorewall-compile.sh`** — bash helper that compiles a
  Shorewall (and/or Shorewall6) config dir to `iptables-save` text
  AND its nft equivalent (via `iptables-restore-translate`),
  without loading rules into the kernel and without requiring
  root. Bootstraps upstream Shorewall from
  `gitlab.com/shorewall/code.git` into a per-user cache, runs
  upstream's own `install.sh` per component (Shorewall-core,
  Shorewall, Shorewall6) so all action files / macros / version
  markers are produced identically to a real install, then invokes
  `compiler.pl --preview` inside an unprivileged user+net+mount
  namespace (with tmpfs-mounted `/run` so `iptables` can drop its
  xtables.lock without real root). The compile output is
  post-filtered out of Shorewall's bash-script wrapper to give
  clean `iptables-save` text, then piped through
  `iptables-restore-translate` / `ip6tables-restore-translate`.
  Always emits a yellow WARNING banner naming the Shorewall
  features whose output depends on live host state (`routeback`,
  `BROADCAST=detect`, `DETECT_DNAT_IPADDRS`, `&iface`, proxyarp
  `HAVEROUTE`, providers, DHCP). GitLab-CI snippet documented
  inline + in `tools/README.md`.

### Refactor (maintainability pass — April 2026)

Internal restructuring driven by a multi-agent audit. No behavioural
change to the emitted nft (verified by 6 golden snapshots that
remained byte-identical across the entire pass). Test count grew
from 688 to 981.

- **`compiler/verdicts.py`** — new module. Replaces the undocumented
  `Rule.verdict_args="prefix:target"` string wire format with a
  typed discriminated union of 17 frozen dataclasses
  (Snat/Dnat/Masquerade/Redirect/Notrack/CtHelper/Mark/Connmark/
  RestoreMark/SaveMark/Dscp/Classify/EcnClear/Counter/NamedCounter/
  Nflog/Audit). Producers in `compiler/{ir,nat,tc,docker,accounting}.py`
  now construct typed instances directly. The emitter dispatches by
  `type(verdict_args)` instead of string-prefix parsing.
- **`Rule.log_level: str | None`** — new field. Carries the syslog
  level for `Verdict.LOG` rules; replaces the special-case
  `verdict_args="log_level:info"` string overload.
- **`compiler/ir.py` → `compiler/ir/` package** — 3427 LOC god-module
  split into `__init__.py` (build orchestrator), `_data.py` (data
  model), `spec_rewrite.py` (token rewriters), `rules.py` (macro
  expansion + `_add_rule`), `_build.py` (per-table stage functions).
  All previously-importable symbols re-exported from the package
  for backward compatibility. Module-level macro registries
  (`_CUSTOM_MACROS`) and DNS deprecation-warned set moved onto
  `FirewallIR` as instance fields, restoring per-build isolation.
- **`runtime/cli.py` → `runtime/cli/` package** — 2929 LOC god-module
  split into `__init__.py`, `_common.py`, `apply_cmds.py`,
  `config_cmds.py`, `debug_cmds.py`, `generate_cmds.py`,
  `plugin_cmds.py`. Public import path
  `from shorewall_nft.runtime.cli import …` unchanged.
- **`compiler/sysctl.py`** (new) — `generate_sysctl_script` moved
  here from `runtime/sysctl.py` (eliminated `verify/` → `runtime/`
  upward import).
- **`nft/capability_check.py`** (new) — moved from
  `compiler/capability_check.py`; the module probes nft kernel
  capabilities at compile time and naturally lives next to
  `nft/capabilities.py`.
- **`verify/constants.py`** (new) — single source of truth for the
  3-namespace test topology names (`NS_SRC`, `NS_FW`, `NS_DST`,
  `DEFAULT_SRC`). `tc_validate.py` no longer imports the private
  `_ns` from `simulate.py`; uses
  `shorewall_nft_netkit.netns_shell.run_shell_in_netns` instead.
- **`compiler.ir.expand_line_for_tokens`** — public rename of the
  former `_expand_line_for_tokens` (called cross-module by `nat.py`
  and `tc.py`; the leading underscore was misleading).
- **`compiler.ir.is_ipv6_spec`** — public utility consolidating three
  near-duplicate IPv6-detection helpers (`_is_v6` in proxyarp,
  `_is_ipv6` and `_is_ipv6_addr` in ir).
- **`compiler.ir.split_nft_zone_pair`** — extracted helper covering
  four inline `chain_name.split("-", 1)` sites in `optimize.py`
  and `nft/emitter.py`.
- **Plugin entry points** — `plugins/manager.py` discovers third-party
  plugins via `importlib.metadata` entry points under group
  `shorewall_nft.plugins`. Built-ins remain registered in-tree.
  See `docs/shorewall-nft/plugins.md` for the third-party
  registration pattern.
- **Golden-snapshot framework** — `tests/golden/` with 6 cases
  (minimal, fastaccept_no, ipv6_basic, nat_dnat, vmap_dispatch,
  complex). Regenerate with `UPDATE_GOLDEN=1 pytest tests/golden/`.
- **`tests/fixtures/ref-ha-minimal/`** — anonymised three-zone
  fixture (RFC 5737/3849 addresses) replacing silent
  `/etc/shorewall` skips in `test_triangle`, `test_nat`,
  `test_cli_integration`. Production-scale assertions and merge-
  collision tests gated behind `SHOREWALL_NFT_PROD_DIR`.
- **`tests/verify/`** — 163 new direct unit tests across five
  previously-untested modules (connstate, iptables_parser,
  netns_topology, tc_validate, slave_worker) — no netns/root
  required.
- **CLI doc sync** — `docs/cli/commands.md` + `docs/reference/commands.json`
  gained the six previously-undocumented subcommands (`apply-tc`,
  `generate-conntrackd`, four `config` subcommands), the five
  missing `simulate` flags, the `migrate --output` description,
  per-subcommand "How to verify success" sections for seven
  commands, and inline `routefilter` documentation in
  `tools/man/shorewall-nft-interfaces.5`.

### Fixed (REDIRECT action)

- **`REDIRECT` rules emit `redirect to :<port>` instead of malformed
  `dnat to`** — latent bug present since the monorepo split
  (2026-04-12). REDIRECT rules in the `rules` file were silently
  routed through the DNAT processor, which produced
  `verdict_args=DnatVerdict(target="")` (empty target). The fix adds
  a typed `RedirectVerdict(port: int)` (17th SpecialVerdict variant)
  and a REDIRECT-specific DEST-column parsing branch in `nat.py`.
  Verified against shorewall-perl 5.2.6.1: nft `redirect to :<port>`
  is the direct equivalent of `iptables -j REDIRECT --to-port <port>`.
  Five regression tests added in `tests/test_nat.py::TestRedirect`.

### Added (W1–W9 nfsets, man pages, Prometheus metrics, VRRP collector)

- **`nfsets` config file** — named dynamic nft sets with four backends
  (`dnstap`, `resolver`, `ip-list`, `ip-list-plain`). Declarative syntax
  decouples set definition from rule usage; brace expansion at parse time;
  multi-set comma syntax in rules; N→1 qname→set sharing via `DnsSetTracker`.
  See `docs/features/nfsets.md` and `shorewall-nft-nfsets(5)`.
- **Full man-page coverage** — 5 section-8 pages (all CLI binaries) + 35
  section-5 pages (one per active config table) with worked examples.
  Installed under `/usr/share/man/{man5,man8}/`.
- **Prometheus metrics for nfsets** (shorewalld) — `NfSetsManager`
  registration metrics (`shorewalld_nfsets_entries`, `_hosts`,
  `_payload_bytes`); `DnsSetTracker` N→1 grouping counter
  (`shorewalld_dns_set_shared_qnames`); `PlainListTracker` refresh/error/
  inotify metrics (7 metric families for `ip-list-plain` sources).
- **Resolver per-set counters** —
  `shorewalld_dns_resolver_refresh_total{set_name, outcome}` and
  `shorewalld_dns_resolver_refresh_duration_seconds_{sum,count}{set_name}`.
- **VrrpCollector** — D-Bus + optional SNMP scrape of keepalived processes,
  opt-in via `--enable-vrrp-collector`. SNMP augmentation (`--vrrp-snmp-enable`)
  fills `priority`, `effective_priority`, `vip_count`, and `master_transitions`
  that D-Bus does not expose. Works on AlmaLinux 10 where keepalived ships
  without `--enable-dbus` (SNMP-only discovery mode). 7 metric families.

### Changed (W1–W9)

- `DnsSetSpec.set_name` now stores the base name (without `_v4`/`_v6`
  suffix); the family suffix is appended only at nft write time.
  Internal API change; no operator-visible impact unless out-of-tree code
  reads `DnsSetSpec.set_name` directly.
- `InstanceCache.load()` / `.update()` signatures accept an optional
  `nfsets_payload: dict | None` parameter for the control-socket handshake.

### Fixed (W1–W9)

- `worker_router._lookup` honours `DnsSetSpec.set_name` instead of
  always deriving the target set from the qname — nfset-backed DNS sets
  were written to the wrong kernel set before this fix.
- `nfset_registry_to_dns_registries` no longer drops the v4 set name
  when a qname is registered for both families.
- `PlainListTracker._metrics` is now registered with `ShorewalldRegistry`;
  the `shorewalld_iplist_apply_*` and `_set_capacity` metrics for
  plain-list sources are now actually scraped (were silently absent).
- `NfSetsManager.payload_bytes()` returns the exact JSON wire size
  instead of a `len(str(…))` lower bound.

### Packaging (W1–W9)

- New man pages wired into `packaging/debian/rules` and
  `packaging/rpm/shorewall-nft.spec.in`; installed under
  `/usr/share/man/{man5,man8}/`.
- Optional extras added to `packages/shorewalld/pyproject.toml`:
  `[inotify]` (`inotify_simple>=1.3`), `[vrrp]` (`jeepney>=0.8`),
  `[snmp]` (`pysnmp>=7.0`). All default-off; core functionality
  requires none of them.

### Known limitations (W1–W9)

- `keepalived 2.2.8-6.el10` on RHEL 10 / AlmaLinux 10 / CentOS Stream 10
  is built without `--enable-dbus`; the VrrpCollector requires
  `--vrrp-snmp-enable` to report non-zero metrics on those hosts.
  Debian trixie (2.3.3), Fedora 40+, and Ubuntu 24.04 ship keepalived
  with D-Bus enabled.
- `shorewalld_plainlist_refresh_duration_seconds` is emitted as an
  empty `HistogramMetricFamily` alongside the populated sum/count pair —
  benign but visible in scrape output. To be cleaned up post-release.

### Added (large-set sync hardening — nfsets + shorewalld iplist)
- Compiler: `size=N` override per nfset entry (accepts `k`/`M` suffixes,
  range 1–64M). Raised defaults to 4096 for DNS-only sets and 262144 for
  ip-list sets (was 512 and 65536).
- Shorewalld iplist apply: `SHOREWALLD_IPLIST_CHUNK_SIZE` env var (default
  2000, was hard-coded 200). Chunk 200→2000 reduces libnftables parser
  overhead by ~10× at million-entry refreshes.
- Shorewalld iplist apply: atomic swap-rename path (feature-gated via
  `SHOREWALLD_IPLIST_SWAP_RENAME=1`). Replaces incremental
  add/delete-element with one libnftables transaction that builds
  `<name>_new`, swaps, renames. Rules continue matching across the swap.
- Shorewalld iplist apply: autosize. When an incoming list hits ≥ 90% of
  declared capacity, shorewalld transparently recreates the set with
  `next_pow2(max(len × 2, declared × 2))` capacity (capped at 64M) and
  emits a WARN so the operator can update `size:` in the nfsets config.
- Shorewalld iplist apply: capacity warning at 80% fill, kernel "Set is
  full" error detection.
- Prometheus metrics: `shorewalld_iplist_apply_duration_seconds_{sum,count}`,
  `shorewalld_iplist_apply_path_total{path}` (diff/swap/fallback/saturated),
  `shorewalld_iplist_set_capacity{kind}`, `shorewalld_iplist_set_headroom_ratio`.
- `PlainListConfig.max_prefixes` honoured per config (module default
  raised 200k → 2M).

### Added (stagelab)
- `ThroughputScenario.family: "ipv4" | "ipv6"` — explicit address family
  selection. `trafgen_iperf3` emits `-6` when `family=ipv6`. Runner raises
  a clear `ValueError` naming the endpoint when `family=ipv6` is requested
  and no `ipv6:` is configured.
- IPv6 perf catalogue entries point at a separate `wan-native` role
  (native-mode endpoint) rather than the probe-mode `wan-uplink` —
  iperf3 cannot target probe endpoints.

### Changed (stagelab)
- `topology_bridge.py`, `topology_dpdk.py`, `agent.py._exec_in_netns`:
  migrated from `subprocess ip …` / `ip netns exec …` to native
  pyroute2 `NetNS`/`IPRoute` netlink API. The `bridge vlan …` CLI is
  retained (pyroute2 has no bridge-VLAN API) but now entered via
  in-process `setns()` instead of `ip netns exec`.

### Fixed (netkit)
- `nsstub.spawn_nsstub`: centralised orphan-cleanup before fork. Previously
  every caller had to pre-clean stale `/run/netns/<name>` bind-mounts;
  probe-mode `topology_bridge.py` did not, causing intermittent
  `nsstub for 'NS_TEST_*' didn't signal readiness (got b'')` on re-runs
  after an agent SIGKILL. Diagnostics: EOF on the readiness pipe now
  reports `child exited code N` / `signal N`.

### Added (W12–W21 nfsets close-out + classic ipsets syntax compat + TC pyroute2)

- **SRV-record resolution (`nfsets` `resolver` backend, `dnstype=srv`)** —
  shorewalld queries SRV records, extracts targets, and recursively resolves
  A+AAAA records for each target. `MAX_SRV_TARGETS = 32` hard cap per RRset;
  per-target exceptions are isolated so one bad target does not abort the
  whole set. TTL is `min(srv_ttl, child_ttl)`. Commit `0555dba54`.
- **Additive multi-backend per nfset name** — two config rows with the same
  `name` but different `backend` coexist without error; the resulting nft set
  is populated by multiple shorewalld trackers simultaneously (e.g. `dnstap`
  + `ip-list-plain` writing to the same set). `build_nfset_registry` merge key
  changed from `name` to `(name, backend)`. Commit `0555dba54`.
- **Per-set nft flags** — flags are now computed per `(name, family)` group
  rather than registry-wide. Pure-DNS groups get `flags timeout`; pure-iplist
  groups get `flags interval`; mixed groups get `flags timeout, interval`.
  Commit `0555dba54`.
- **`dnst:` inline prefix** — preferred alias for `dns:` in rule columns;
  zone-prefixed (`<zone>:dnst:name`), negated (`!dnst:name`), and
  multi-host (`dnst:a,b,c`) forms are fully supported. `dns:` continues
  to work as a deprecated alias with a one-shot warning per config file.
  Commit `fad2459be`.
- **Classic ipsets `+setname[…]` / `+[…]` syntax** — `+setname[src]` /
  `+setname[dst]` / `+setname[src,dst]` bracket-flag overrides instruct the
  emitter which match side to use. `+[set1,set2]` AND-multi-set semantics
  (packet must match all listed sets — distinct from nfsets comma which is
  OR-clone). Negation, zone-prefix, and brackets compose freely.
  Commit `fad2459be`.
- **`nfset:` / `dns:` / `dnsr:` / `dnst:` tokens in all per-table files** —
  tokens are now accepted in `masq` (SOURCE column), `dnat` (SOURCE column),
  `tcrules` / `mangle` (SOURCE + DEST), `blrules`, `stoppedrules`, `notrack`,
  `conntrack`, `rawnat`, `ecn`, `arprules`, `accounting` (where nftables
  itself supports `saddr`/`daddr` set matching). Tokens are explicitly
  rejected on Masq ADDRESS and DNAT TARGET columns with a clear error.
  Commit `fad2459be`.
- **`shorewall-nft apply-tc`** — native pyroute2-backed TC apply path (HTB
  root qdisc + classes, fwmark filters, ingress qdisc). No shell-out to
  `tc` or `ip netns exec`. `generate-tc` is preserved as a portable
  shell-script fallback. Commit `fad2459be`.
- **`shorewall-nft-netkit` `run_in_netns_fork` / `PersistentNetnsWorker`** —
  shared primitive encapsulating the fork+setns+libnftables pattern used
  by shorewalld's `ParentWorker`. `run_in_netns_fork` checks pickleability
  pre-fork; `PersistentNetnsWorker` uses a SEQPACKET socketpair for hot
  paths. `NetnsForkError` hierarchy (`NetnsNotFoundError`, `NetnsSetnsError`,
  `ChildCrashedError`, `NetnsForkTimeout`) with full exception propagation
  across the fork boundary. See `docs/architecture/netns-fork.md`.
  Commit `7447ef8c7`.
- **No more `ip netns exec` shell-outs**: every netns-bound operation in
  `shorewall-nft` (nft apply, load, monitor trace, EPERM fallbacks) and
  `shorewall-nft-simlab` (topology sysctl writes, rule loads, flowtable
  queries, monitor trace) now runs through `run_in_netns_fork` (one-shot
  fork+setns+libnftables) or the `_in_netns()` context manager (long-lived
  Popen). The `iproute2` binary is no longer a runtime dependency for these
  code paths. 10 call sites migrated; 28 new regression tests;
  `grep '"ip", "netns", "exec"'` returns CLEAN across live code (remaining
  occurrences are operator-instruction strings in `_flush_print()` output).
  Commit `fd2e66a72`.
- **Large-payload IPC hardening** (`run_in_netns_fork`): result pipe drained
  concurrently via `select` + EINTR-retry; pipe buffer bumped to 1 MiB where
  `cap_sys_resource` is held; `BrokenPipeError`/`EPIPE` handled gracefully;
  `MemoryError` on pickle caught with payload-size context. Commit `dd25a36f8`.
- **`PersistentNetnsWorker`** switched from `SOCK_SEQPACKET` to `SOCK_STREAM`:
  eliminates the effective per-datagram EMSGSIZE cap (~200 KiB–1 MiB depending
  on socket buffer) that previously caused large nft-set dumps to fail.
  Existing `[uint32 length][payload]` framing + exact-read loop unchanged.
  Commit `dd25a36f8`.
- **Zero-copy large-payload transfer via `memfd_create(2)` + `mmap`**: payloads
  ≥ 4 MiB (configurable via `large_payload_threshold` kwarg) are routed
  through an anonymous, sealed memfd rather than the inline pickle pipe.
  Sealed with `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`; last-fd-close
  auto-frees pages; no filesystem touch. Kernels < 3.17 / Python < 3.8 raise
  a clear `RuntimeError`; inline pipe + persistent worker continue to work.
  Commit `dd25a36f8`.
- **`run_nft_in_netns_zc(netns, script, *, check_only, timeout) → NftResult`**:
  specialised helper that ships the nft script via zero-copy memfd and streams
  stdout/stderr from the child via two drain-pipe threads. Scales cleanly to
  multi-hundred-MB scripts (e.g. bulk ip-list loads). Use for one-off apply
  paths; `run_in_netns_fork` stays the generic Python-RPC entry point.
  Commit `dd25a36f8`.
- **Pickle protocol 5 out-of-band buffers**: `bytes`/`bytearray`/`memoryview`
  values ≥ 4 MiB embedded in `run_in_netns_fork` args/return are routed
  through individual memfds. Python's C pickler bypasses `buffer_callback` for
  immutable `bytes`, so the primitive pre-walks containers and wraps oversized
  payloads in `pickle.PickleBuffer`. Commit `dd25a36f8`.

### Changed (W12–W21)

- `DnsrGroup` gains `dnstype: str | None = None`. Internal API; no
  operator-visible impact unless out-of-tree consumers import it directly.
- `build_nfset_registry` merge key changed from `name` to `(name, backend)`;
  same-name-different-backend rows no longer raise `ValueError`.
- `Match` dataclass gains `force_side: str | None = None` for bracket-override
  rendering in the emitter.
- `shorewall-nft-netkit` `netns_fork.py` now ships three IPC paths (inline pickle
  pipe ≤ 4 MiB; out-of-band memfd ≥ 4 MiB; specialised `run_nft_in_netns_zc`
  stdin/stdout-style path for nft dispatch). Public API of `run_in_netns_fork`
  and `PersistentNetnsWorker` is unchanged; internal transport reworked.
  `PersistentNetnsWorker` socket type changed from `SOCK_SEQPACKET` to
  `SOCK_STREAM`. Commits `dd25a36f8`.

### Removed (W12–W21)

- **`iproute2` binary** no longer required by `shorewall-nft` or
  `shorewall-nft-simlab` for named-netns operations. Operator-visible
  diagnostic prints still suggest `ip netns exec` for human inspection —
  that is intentional. Commit `fd2e66a72`.

### Deprecated (W13)

- Inline `dns:<hostname>` prefix in rule columns — use `dnst:` instead.
  Compile-time `WARNING` logged once per config file on `dns:` use.
  Removal scheduled for a future major release; no hard timeline yet.

### Added (shorewalld broad-audit implementation round)

- `shorewalld_pbdns_frames_skipped_by_type_total` + `*_by_qname_total`:
  new counters surfacing how many PBDNSMessage frames are dropped
  pre-parse by the two-pass filter (P-5). Expected ratio ~99% of
  received frames.
- `shorewalld_rtnl_handles_cached` gauge: size of the per-netns
  IPRoute handle cache (A-1).
- `DNS_DEDUP_REFRESH_THRESHOLD` config key + `--dns-dedup-refresh-threshold`
  CLI flag: operator-tunable fraction of proposed TTL below which
  a DNS answer is treated as duplicate and the write is skipped.
  Default 0.5.
- `BATCH_WINDOW_SECONDS` config key + `--batch-window-seconds` CLI flag:
  coalescing window for the SetWriter batch pipeline. Default 0.010
  (10 ms).
- `DaemonConfig` frozen dataclass (`daemon_config.py`): 34-field typed
  runtime config consumed by `Daemon(config=cfg)`. Kwargs accepted for
  back-compat with a DeprecationWarning.
- `ControlHandlers` class (`control_handlers.py`): control-socket
  request handlers extracted from `Daemon` for testability. 7 handlers,
  27 new unit tests.
- `_IngressMetricsBase` shared base (`_ingress_metrics.py`):
  lock-free counter bag for PbdnsMetrics + DnstapMetrics. Bumps are
  single-bytecode atomic under GIL; no per-increment lock.
- `__all__` on `shorewalld.exporter`: public surface pinned (18 names);
  19 private helpers (`_CT_STAT_FIELDS`, `_extract_qdisc_row`, …) no
  longer re-exported — import from `shorewalld.collectors.<module>`.

### Changed (broad-audit)

- pbdns hot path: full `ParseFromString` gated behind varint peek of
  type + qname; 100× fewer full parses on a typical mix of
  allowlisted + non-allowlisted frames.
- Four pyroute2-based collectors (link, qdisc, neighbour, address)
  now share one cached `IPRoute(netns=...)` handle per netns instead
  of opening + closing per scrape. Eliminates the per-scrape
  pyroute2 netns fork overhead.
- `Proposal` and `SetMetrics` dataclasses now `slots=True`; drops
  ~200 B/instance __dict__ on the 20 k-fps allocation path.
- Compiler hot dataclasses (`Match`, `Rule`, `Chain`) also
  `slots=True` (~2.7 MB saved per reference-config compile).
- `nft_worker` IPv4 formatting uses `socket.inet_ntop` instead of
  generator-based join.
- `_LIBC` handle cached at module load in `nft_worker.py`; no more
  `find_library` + `CDLL` on every spawn.
- `Daemon.__init__` kwargs deprecated (DeprecationWarning,
  stacklevel=2); pass `DaemonConfig(...)` via `config=` instead.
- Shutdown sequence aggregates subsystem errors into a single
  `sys.exit(1)` path (M-4); previously subsystem shutdown failures
  were silently logged while the process exited 0.
- PbdnsMetrics / DnstapMetrics per-increment lock removed; counter
  bumps are lock-free under the GIL (P-4).

### Fixed (broad-audit)

- pbdns valid response set now includes `DNSIncomingResponseType = 4`
  in addition to `DNSResponseType = 2`. Before this, legitimate
  frames matching type 4 were silently dropped.

### Internal / non-operator-facing (broad-audit)

- `core.py` shrank from a 1262-line god-object:
    1262 → 1229 lines after ControlHandlers extract (54a7799ae)
    1229 → 1309 lines after DaemonConfig refactor (eb9d6e74c;
    structural scaffolding + back-compat properties net-up, but
    _start_* bodies cleaner).

## [1.10.0] - 2026-04-20

### Added (security-test-plan feature)
- Standards-driven firewall security test plan — machine-readable catalogue
  (`docs/testing/security-test-plan.yaml`, 57 tests) + human-readable doc
  (`docs/testing/security-test-plan.md`) covering CC/ISO-15408, NIST 800-53,
  BSI IT-Grundschutz, CIS Benchmarks, OWASP, ISO-27001, IPv6-perf addendum.
- Scenario config gains optional `test_id`, `standard_refs`,
  `acceptance_criteria` fields (applies to all 15 scenario kinds).
- `ScenarioResult.criteria_results: dict[str, bool]` for per-criterion
  pass/fail (beyond the existing `ok: bool`).
- `audit.json` machine-readable output alongside `audit.html`/`audit.pdf`.
  Audit HTML gains Test-ID + Standard columns.
- `standards.py` TEST_ID lookup (62 ids across 7 standards) with
  auto-aggregation from 4 Python fragment modules.
- `tools/run-security-test-plan.sh` one-shot executor that expands the
  catalogue into per-standard stagelab configs, runs them, and generates
  a unified audit report.
- `tools/merge-security-test-plan-yaml.py` + `merge-security-test-plan.py`
  merger scripts (regenerate canonical docs from fragments).
- New scenario `conntrack_overflow` — fills conntrack table to
  `nf_conntrack_max`, observes drop cause via `/proc/sys/net/netfilter/*`
  + `dmesg` grep for `nf_conntrack: table full`.
- Latency percentiles on `ThroughputScenario`: `measure_latency: bool`
  flag extracts p50/p95/p99 ms from iperf3 JSON RTT samples.
- DoS window-delta: `baseline_window_s` / `dos_window_s` fields on
  `SynFloodDosScenario` + `ConntrackOverflowScenario`; controller
  computes per-window deltas and emits them into `criteria_results`.
- New SNMP bundle `vrrp_extended` — 6 keepalived-MIB OIDs for richer
  HA-observability (vrid, wanted-state, effective-priority, vips-status,
  preempt, preempt-delay).
- simlab emits machine-readable `simlab.json`; `stagelab audit
  --simlab-report PATH` merges simlab correctness into the audit report.

### Changed
- Replaced tcpkali external dependency with pure-Python `trafgen_pyconn`
  (asyncio-based TCP connection burst). tcpkali wrapper kept for
  back-compat only; setup script no longer references a source-build step.
- CI matrix (from v1.9.0) expanded: stagelab integration tests now run
  against `test_topology_bridge.py` + `test_agent_runtime.py` in the
  sudo-netns job.

### Fixed
- VRRP OIDs corrected from `.2.1.1.x` (vrrpSyncGroupTable) to `.2.3.1.x`
  (vrrpInstanceTable) — regression fix from v1.9.0 initial
  implementation.

### Operations
- HA-failover live-drill executed against the reference HA pair:
  sub-second failover (SNMP-poll limited to 0.5s resolution), ~184s
  preempt-back delay (matches configured 180s), no split-brain.

### Fixed

- **shorewall-nft: implicit loopback accept in base input/output chains**
  — classic Shorewall (shorewall-perl) emits an unconditional
  `-A INPUT -i lo -j ACCEPT` / `-A OUTPUT -o lo -j ACCEPT`, so local
  services bound to loopback (e.g. `pdns-recursor` listening on
  `127.0.0.1` or an Anycast IP on `lo`, firewall-originated mgmt
  traffic via `lo`) work out of the box. The shorewall-nft emitter
  was missing the equivalent rule on the running ruleset — it only
  appeared in the `shorewall_stopped` table — so any lo-bound flow
  required an explicit `$FW $FW ACCEPT` policy to survive the base
  chain's `policy drop`. Migrations from classic Shorewall broke
  silently. The base `input` chain now carries `iifname lo accept`
  and the base `output` chain carries `oifname lo accept`, placed
  after FASTACCEPT and before NDP/dispatch.

## [1.9.0] - 2026-04-20

### Added
- stagelab: SNMP metric source (`kind: snmp` in `metrics.sources`) with
  bundles `node_traffic`, `system`, `vrrp`, `pdns` (S1–S4). Optional
  `[snmp]` extra installs pysnmp.
- stagelab: env-var expansion `${VAR}` for SNMP community/host in YAML
  config. Community strings stay out of git.
- stagelab: HA-failover drill now computes real downtime from
  keepalived-MIB VRRP-instance-state transitions via SNMP polling
  (fallback: retrans heuristic, backward-compatible).
- stagelab: PowerDNS-recursor advisor signal —
  `_h_dos_dns_latency_blowup` triggers when `pdns_qps_increase_ratio > 10`.
- stagelab: CI matrix now runs stagelab unit + integration tests (one
  root-less controller smoke + bridge/TAP probe topology + agent runtime).

### Fixed
- stagelab: pysnmp 7.x API migration (walk_cmd / get_cmd /
  UdpTransportTarget.create / SNMPv2c mpModel=1).
- stagelab: SNMP coercion of STRING-encoded numerics (e.g. UCD-SNMP
  laLoad "0.02") — was returning -1.0.

### Operations
- setup-remote-test-host.sh: stagelab-agent role installs the `[snmp]`
  extra, net-snmp-utils/snmp CLI tools, and writes `mibs +ALL` to
  `/etc/snmp/snmp.conf` so snmpwalk loads symbolic MIBs by default.

## [1.8.0] — 2026-04-19 — shorewalld: Prometheus deep-dive, worker /proc delegation, seed handshake, AlmaLinux 10

### Fixed

- **shorewalld: protobuf 3.19 compatibility on AlmaLinux 10** — the
  generated `*_pb2.py` files import
  `google.protobuf.internal.builder` which was added in protobuf 3.20.
  AlmaLinux 10 AppStream caps at 3.19.6, causing an `ImportError` at
  daemon startup.  `proto/__init__.py` now detects the missing module
  and injects `proto/_builder_compat.py` as a `sys.modules` shim;
  the compat module re-implements `BuildMessageAndEnumDescriptors` /
  `BuildTopDescriptorsAndMessages` via `message_factory.MessageFactory`
  (present in protobuf 3.x).  The generated pb2 files are unchanged.

### Added

- **shorewalld: dnstap two-pass filter + pbdns zero-copy RR storage**
  — the dnstap decoder now checks the qname against the allowlist
  *before* the expensive dnspython parse. At a typical ≥95 % drop
  rate this saves most of the dnspython CPU on the 20 k fps hot
  path, aligning the code with the "filter before decode"
  doctrine. New counter
  `shorewalld_dnstap_frames_dropped_not_allowlisted_total` exposes
  the filter's miss rate. In parallel, `pbdns.py` drops two redundant
  `bytes(rr.rdata)` copies per accepted frame — protobuf already
  returns immutable `bytes` — removing ~40 k avoidable allocations/s
  at 20 k fps.

- **shorewalld: exporter split into `collectors/` subpackage + core
  import hoist** — 12 concrete Prometheus collectors (nft, flowtable,
  link, qdisc, conntrack, ct, snmp, netstat, sockstat, softnet,
  neighbour, address) moved out of the 1 637-LOC `exporter.py` into a
  `collectors/` subpackage, one module each. `exporter.py` keeps the
  shared scraper / registry / `_MetricFamily` + histogram
  infrastructure and re-exports every collector name for back-compat
  with existing callers. No metric name or label changes.
  `WorkerRouterMetricsCollector` moved to
  `collectors/worker_router.py`; the test helper `inproc_worker_pair`
  moved to `worker_test_helpers.py`. `core.py` now imports every
  subsystem at module top level (the optional `prometheus_client`
  import stays deferred), making the module dependency graph visible
  instead of hidden behind a dozen deferred imports. CLAUDE.md
  invariants are cross-referenced inline at their enforcement sites:
  tracker-attach respawn (`worker_router.py`), lazy-spawn /
  fork-after-load (`core.py`), register-resync rule (`instance.py`),
  `add element … expires Ts` (`nft_worker.py`).

- **shorewalld: per-DNS-set load metrics + worker dispatch histograms**
  — operator can now see which qnames carry the DNS update load and
  how long each batch takes to land in the kernel.
  - `DnsSetMetricsCollector` reads the tracker snapshot (already
    exposed for seed / peer sync) and emits per-`(set, family)`
    counters: `shorewalld_dns_set_{adds,refreshes,dedup_hits,
    dedup_misses,expiries}_total` plus `shorewalld_dns_set_elements`
    and `shorewalld_dns_set_last_update_age_seconds`. Label `set`
    is the canonical qname (`cdn_amazon`, not `dns_cdn_amazon_v4`);
    no `netns` label since the tracker is daemon-global. `rate(adds)
    + rate(refreshes)` gives updates/s per set; `dedup_hits /
    (dedup_hits + dedup_misses)` the cache-hit ratio per qname.
  - `WorkerMetrics` gains two histograms —
    `shorewalld_worker_batch_latency_seconds` (buckets 1 ms–2.5 s,
    observed on every reply from both `ParentWorker` and
    `LocalWorker`) and `shorewalld_worker_batch_size_ops` (buckets
    1–40 ops). Together they separate "lots of small batches" from
    "few slow commits" regressions; `histogram_quantile(0.99,
    rate(…_bucket[5m]))` gives the p99 round-trip per netns.
  - Transport byte counters previously kept internal in
    `WorkerTransport.stats` are now exposed as
    `shorewalld_worker_transport_{send,recv}_bytes_total` and
    `shorewalld_worker_transport_send_errors_total`, emitted only
    for forked workers (the default-netns `LocalWorker` has no
    SEQPACKET hop and would spam zero samples).
  - Under the hood `TrackerSnapshot` grew a `per_set_names` map so
    the exporter can resolve `set_id → qname` without grabbing the
    tracker lock a second time, and `_MetricFamily` learned a third
    `mtype="histogram"` variant with a tiny `Histogram` helper so
    future collectors can ship latency distributions without pulling
    in `prometheus_client.Histogram` (which carries per-bucket
    Counters and a thread-lock we don't need inside the dispatch
    path).

- **shorewalld: worker-delegated `/proc` reads for all per-netns
  file-backed collectors** — the Prometheus scrape thread no longer
  calls `setns(2)` itself; every `/proc/net/*` and
  `/proc/sys/net/netfilter/*` read now goes through the nft-worker
  that is already pinned to the target netns via
  `setns(CLONE_NEWNET)` at fork time. New wire protocol
  (`shorewalld.read_codec`) sits alongside the SetWriter batch codec:
  two magics `SWRR`/`SWRS` dispatched by the worker main loop, one
  SEQPACKET round-trip per read, response capped at 60 KiB. Large
  files (`/proc/net/ipv6_route` on a full-BGP router) use the
  parallel `count_lines` RPC which ships an 8-byte integer regardless
  of file size. For the daemon's own netns the in-process
  `LocalWorker` short-circuits to a direct `open()` on the default
  thread pool — no fork, no IPC — while keeping the same async API.
  `WorkerRouter` is constructed early in `Daemon.run()` with
  `tracker=None` so collectors can delegate reads from the first
  scrape onwards; the DNS-set pipeline later calls
  `attach_tracker()` and respawns any scrape-only workers so their
  lookup closure picks up the real tracker.

- **shorewalld: protocol-stack and connection-quality metrics** — six
  new Prometheus collectors surface the kernel's own MIBs plus
  per-CPU softirq state, all routed through the worker-delegated
  read path above. Every metric carries the usual `netns` label and,
  where applicable, a `family=ipv4|ipv6` label so one alerting rule
  covers both stacks. Key additions per collector:

  - `SnmpCollector` (`/proc/net/snmp` + `/proc/net/snmp6`) — IP
    forwarding quality (`ip_forwarded_total`, `ip_out_no_routes_total`,
    `ip_in_discards_total`), ICMP (`icmp_{in,out}_{msgs,dest_unreachs,
    time_excds}_total`, `icmp_in_redirects_total`,
    `icmp_in_echos_total`, `icmp_in_echo_reps_total`), UDP (datagrams
    in/out, `no_ports`, rcv/snd-buf errors, csum errors) and TCP
    (`curr_estab` gauge plus active/passive opens, attempt fails,
    estab resets, retrans/in/out segs, in errs, out rsts, csum
    errors). On a firewall these are the first-class SRE signal —
    `OutNoRoutes` catches dead static routes or vanished BGP
    sessions before the downstream complaints arrive.
  - `NetstatCollector` (`/proc/net/netstat`) — curated `TcpExt`
    counters: `listen_overflows`, `listen_drops`, `backlog_drop`
    (SYN-flood / accept-queue exhaustion), `timeouts`, `syn_retrans`
    (wire-level packet loss), `prune_called`, `ofo_drop`,
    `abort_on_{data,memory}`, `retrans_fail`.
  - `SockstatCollector` (`/proc/net/sockstat` + `sockstat6`) — TCP /
    UDP / UDPLITE / RAW `inuse` with v4+v6 split, TCP `orphan`/`tw`/
    `alloc`/`mem`, UDP `mem`, kernel-wide `sockets_used`, IP reassembly
    queues + bytes. Socket churn (`tcp_tw`), kernel memory pressure
    (`tcp_mem_pages`) and reassembly load (`frag_*`) all in one
    collector.
  - `SoftnetCollector` (`/proc/net/softnet_stat`) — per-CPU softirq
    counters with `cpu` label: `processed`, `dropped`,
    `time_squeeze`, `received_rps`, `flow_limit`. The only way to
    see that one CPU is dropping packets at line rate while others
    idle — critical on firewalls with uneven IRQ distribution.
  - `NeighbourCollector` (`RTM_GETNEIGH` via pyroute2) — ARP / ND
    cache entry counts labelled by `(iface, family, state)` where
    state ∈ {reachable, stale, failed, incomplete, delay, probe,
    permanent, noarp}. A spike in `state="failed"` is the
    gateway-down signal.
  - `AddressCollector` (`RTM_GETADDR` via pyroute2) — configured
    address count per `(iface, family)`. A VIP disappearing during
    a VRRP flap drops the gauge from N+1 to N for the affected
    interface — easier to alert on than watching every address
    individually.

- **shorewalld: `FlowtableCollector` (per netns with a loaded
  ruleset)** — extracts flowtable descriptors from the shared
  `NftScraper` snapshot (zero extra netlink round-trips). Emits
  `shorewall_nft_flowtable_devices{name}` (attached interfaces) and
  `shorewall_nft_flowtable_exists{name,hook}=1`. Live flow counts
  per flowtable are **not** emitted — libnftables' JSON output
  carries only the flowtable definition, not the transient flow
  entries; operators alert on `devices == 0` (interface detached)
  and on an absent `exists` sample (flowtable disappeared after a
  faulty reload).

- **shorewalld: extended link & conntrack metrics** — same netlink
  dumps as before, no extra round-trips.
  - `LinkCollector` now emits `shorewall_nft_iface_carrier_changes_total`
    (cumulative link up↔down transitions, authoritative kernel
    counter for physical-layer flap — a jump without a matching VRRP
    transition points at cable/SFP/switch-port trouble) and
    `shorewall_nft_iface_mtu` (current MTU in bytes, catches
    jumbo-negotiation regressions after an LACP reconfigure).
  - `CtCollector` now emits `shorewall_nft_ct_buckets` (hash bucket
    count from `nf_conntrack_buckets`) so the ratio `count / buckets`
    directly expresses mean hash-chain length, and
    `shorewall_nft_fib_routes{family}` (line count of `/proc/net/route`
    respectively `/proc/net/ipv6_route`) which collapses on BGP
    session loss before downstream reachability alerts fire.

- **shorewalld: netlink-sourced link, qdisc, and conntrack-engine metrics**
  — three new Prometheus collectors built on direct pyroute2 API calls,
  zero forks, one dump per scrape per netns. All carry the usual `netns`
  label and all work in the root netns without extra configuration.
  - `LinkCollector` now surfaces the full `IFLA_STATS64` surface (17
    fields beyond the previous RX/TX packets+bytes): generic and
    per-subsystem error and drop counters
    (`rx_errors`, `tx_errors`, `rx_dropped`, `tx_dropped`,
    `rx_missed_errors`, `rx_fifo_errors`, `rx_crc_errors`,
    `rx_frame_errors`, `rx_length_errors`, `rx_over_errors`,
    `rx_nohandler`, `tx_carrier_errors`, `tx_aborted_errors`,
    `tx_fifo_errors`, `tx_heartbeat_errors`, `tx_window_errors`),
    plus `multicast`, `collisions`, `rx_compressed`, `tx_compressed`.
    Same `RTM_GETLINK` dump as before — no extra round-trips.
  - `QdiscCollector` (new) emits per-qdisc counters and gauges via
    `RTM_GETQDISC`: `shorewall_nft_qdisc_{bytes,packets,drops,
    requeues,overlimits}_total` plus `qlen` / `backlog_bytes` gauges,
    and `rate_bps` / `rate_pps` from the optional `tc … est` rate
    estimator. Labels `iface,kind,handle,parent` reproduce the
    structure `tc -s qdisc` prints.
  - `ConntrackStatsCollector` (new) emits per-netns conntrack engine
    counters via `CTNETLINK IPCTNL_MSG_CT_GET_STATS_CPU`, summed
    across CPUs: `shorewall_nft_ct_{found,invalid,ignore,
    insert_failed,drop,early_drop,error,search_restart}_total`.
    `insert_failed + drop + early_drop` climbing together is the
    conntrack-table-pressure signature. Needs `CAP_NET_ADMIN`;
    unprivileged runs surface the families empty rather than
    failing the scrape.

### Fixed

- **shorewalld: parallel control-socket clients could interleave mutating
  commands** — `register-instance`, `reload-instance`, and
  `deregister-instance` share one write path (`InstanceManager._apply_merged`
  is the sole writer of the merged registry into the tracker and pull
  resolver). Two concurrent clients hitting those commands could interleave
  at the `await` points inside `_apply_merged` /
  `_resync_instance_after_register` and leave the tracker or a forked nft
  worker inconsistent. `refresh-iplist` had the analogous race against the
  background list loop over the shared `_ListState`. Fix: an `asyncio.Lock`
  in `InstanceManager` serialises register/reload/deregister, and a
  per-list `asyncio.Lock` in `IpListTracker` serialises `_do_refresh`.
  Read-only commands (`ping`, `*-status`, `request-seed`) remain
  unserialised.

- **shorewalld: dns set elements ageing out between pull cycles** — the
  pull resolver fires every ~`ttl_floor × 0.8` seconds with a clamped TTL
  (default 300 s), but the Linux nft kernel does **not** reset an existing
  element's expiration countdown when `add element ... { ip timeout T }`
  is re-issued with the same `T`. The kernel-side timer kept counting down
  on its original deadline regardless of how often the daemon "refreshed"
  it; sets emptied between pull cycles even though every metric reported
  success. Fix: the worker now emits `add element ... { ip timeout Ts
  expires Ts }` so the kernel populates `NFTA_SET_ELEM_EXPIRATION` and
  honours the reset. Verified on kernel 6.12 / nft 1.1.1.

- **shorewalld: nft worker not respawned after crash or transient netns
  loss** — when the forked nft worker died (signal, OOM, the target netns
  briefly disappeared during an `ip netns del/add` cycle), the parent
  nullified its transport but never spawned a replacement. Subsequent
  `SetWriter.dispatch()` calls failed silently with
  `WARNING batch dispatch failed: ParentWorker not started or already
  stopped` until the daemon was restarted manually. The router now
  schedules `_auto_respawn()` whenever the transport reader sees EOF,
  reaps the dead child, and re-forks with exponential backoff (0 → 1 → 2
  → … → 30 s) so a wedged netns can't peg the CPU. The backoff resets
  once the new child survives 30 s.

- **shorewalld: empty nft sets after `shorewall-nft restart`** — the tracker's
  `(ip, deadline)` dedup cache survived firewall restarts unchanged. Because
  the kernel sets were freshly empty but the tracker still held non-expired
  deadlines, the next DNS resolve pass fell into the `DEDUP` path and never
  emitted `add element` commands. The fresh nft sets stayed empty until the
  cached TTL (up to 1 h) elapsed. Every control-socket `register-instance`
  is now treated as an explicit restart signal: the tracker's element cache
  for the instance's qnames is dropped, the forked nft worker is respawned
  (fresh libnftables handle inside the possibly-recreated netns table), and
  the pull resolver is poked so the sets repopulate within ~1 s. File-based
  `reload-instance` is unchanged (it assumes the table is intact).

- **shorewalld: silent writes lost after dynamically adding a qname** —
  forked nft workers inherit a copy-on-write snapshot of the `DnsSetTracker`
  at fork time. qnames added later via `register-instance` were invisible
  to the already-running child, which acked every batch but silently dropped
  ops for the unknown set_ids. `DnsSetTracker.load_registry()` now reports
  whether new set_ids were allocated, and `InstanceManager._apply_merged()`
  respawns any affected forked worker so it re-forks with the updated
  tracker.

- **shorewalld: 110 s startup deadlock in `_start_prom_server`** —
  `prometheus_client`'s `REGISTRY.register()` calls `collect()` on the
  adapter if no `describe()` method is present, running it synchronously
  on the asyncio event-loop thread. Every `read_file_sync()` call inside
  the Prometheus collectors submits a coroutine via
  `run_coroutine_threadsafe(...).result(timeout=5s)`, which deadlocks
  because the event loop is blocked waiting for `.result()` and can never
  run the submitted coroutine. With ~22 `/proc`-reading collectors the
  daemon consistently took ~110 s to finish startup and make the control
  socket available. Fix: `_Adapter.describe()` returns `[]`, telling
  prometheus_client to skip the name-conflict check and never invoke
  `collect()` at registration time.

### Changed

- **shorewalld: info-level per-resolve logging** — `PullResolver` now emits
  one info line per group resolve with the submitted IP count and the next
  resolve deadline, making empty-set problems self-diagnosing. A rate-limited
  warning fires when `set_id_for()` returns None during submit. The nft worker
  warns when a batch contains ops but the generated script is empty (all
  set_ids unknown — the symptom of a stale worker snapshot).

## [1.7.0] — 2026-04-19 — shorewalld: inline DNS registry, full Prometheus coverage, --monitor removal, dnstap_bridge perf

### Added

- **DNS allowlist inline via control socket** — the `register-instance`
  protocol now carries `dns`/`dnsr` registry data as an inline JSON
  payload. `shorewall-nft` no longer writes `dnsnames.compiled` to the
  config directory; `shorewalld` parses the registries directly from the
  control-socket message via the new `payload_to_registries()` helper.
  The file-based `_load_instance()` path is retained as a fallback for
  static `--instance` startup and external tooling.

- **Full Prometheus coverage for shorewalld subsystems** — Prometheus
  metrics collectors added for all previously uninstrumented subsystems:
  `SetWriter`, `WorkerRouter`, `TrackerBridge`, `StateStore`, `PeerLink`,
  `PullResolver`, and `ControlServer`. All collectors are wired into
  `core.py` via `ShorewalldRegistry.add()` in each subsystem's startup
  path.

### Changed

- **shorewalld: hot-path micro-optimisations in `dnstap_bridge`** —
  `_submit()` now acquires `_lock` once instead of twice (proposals counter
  and queue-full counter combined); eliminates a redundant lock acquire per
  IP proposal under concurrent decoder threads. `_coerce_ip4/6()` skip the
  `bytes()` copy when the input is already an immutable `bytes` object (the
  common path from the pbdns decoder). `_decode_dnstap_frame()` drops the
  redundant `bytes()` wrapper on the protobuf `response_message` field.

- **`/etc/shorewalld.conf` is now the primary config location** — search
  order changed to `/etc/shorewalld.conf` first, then
  `/etc/shorewall/shorewalld.conf` as fallback for sites that co-locate
  config with the shorewall-nft directory.

- **`--monitor` / inotify reload removed** — the control socket is now
  the sole reload mechanism. Removed: `ReloadMonitor` (nftables
  fingerprint polling), `--monitor` flag, `watchfiles` file-watching
  from `InstanceManager`, and `MONITOR` / `RELOAD_POLL_INTERVAL` config
  keys. Remove `RELOAD_POLL_INTERVAL` from existing `shorewalld.conf`
  files before upgrading.

### Fixed

- **shorewalld — worker EOF caused log-flood and hung batch futures** —
  when a forked nft-worker exited, the parent received a zero-byte read
  on the SEQPACKET socket (EOF). The transport returned an empty
  `memoryview`, `decode_reply` raised `WireError("reply shorter than
  header: 0")`, but the asyncio reader was never removed, so the dead
  fd kept firing in a tight loop producing a wall of identical warnings.
  Pending batch futures were never resolved (they eventually hit the
  1-second ack-timeout). Fixed: `recv_into` now raises `OSError` on
  `n == 0`; `_drain_replies` removes the reader and closes the transport
  before calling `_fail_all_pending` on any `OSError`.

- **shorewalld — `register-instance` unavailable on control-socket-only
  startup** — when shorewalld was started with only `--control-socket`
  (no `--allowlist-file`, no `--instance`), the DNS pipeline was never
  initialised, so the `InstanceManager` — and with it all control-socket
  handlers beyond `ping` — was never started. `shorewall-nft start`
  received `"unknown command 'register-instance'; available: ['ping']"`.
  A minimal empty DNS pipeline (tracker + router + set-writer) is now
  bootstrapped in this path so dynamic registration works immediately.

## [1.6.0] — 2026-04-18 — dns: multi-host, dnsr: pull-resolver hardening, lifecycle registration, IP-list sets

### Added

- **`dns:` multi-host** — `dns:host1,host2,…` is now accepted in
  SOURCE/DEST rule columns with the same semantics as `dnsr:`
  multi-host: the first hostname's nft set (`dns_<primary>_v4/v6`)
  absorbs every listed hostname via tracker aliases, so a single
  rule can gate traffic for a group of related names. Unlike
  `dnsr:`, no active pull is scheduled — the group is tap-only.
  Single-host `dns:github.com` is unchanged.

### Fixed

- **`dnsr:` pull-resolver — handler registration ordering** — the
  `refresh-dns` control-socket handler was registered inside
  `_start_dns_pipeline`, which runs before the control server is
  up; the registration was a silent no-op and `shorewalld ctl
  refresh-dns` fell through with "unknown command". The handler
  is now wired from `_start_control_server` (and re-wired when the
  PullResolver is created lazily later).
- **`dnsr:` pull-resolver — lazy creation** — a daemon booted
  without any `dnsr:` groups never created a PullResolver, so a
  later `register-instance` that brought the first group populated
  the tracker aliases but never actively resolved. `InstanceManager`
  now gets a factory and creates the resolver on demand.
- **`dnsr:` pull-resolver — in-flight race** — `refresh()` and
  `update_registry()` replaced the heap while a group was
  mid-resolve, which could silently drop refresh signals and push
  stale duplicate entries back on completion. The resolver now
  tracks `_primaries` (source of truth) + `_in_flight` +
  `_refresh_pending`; in-flight groups re-queue correctly and
  entries for removed groups are dropped on pop.
- **`dnsr:` pull-resolver — serial startup** — due groups were
  resolved one at a time, so N groups took N × resolve-duration
  before all sets were populated. Bounded-concurrency
  `asyncio.Semaphore` (default 8) parallelises the startup burst.
- **`dnsr:` pull-resolver — thundering herd** — ±10% jitter on
  `next_at` so many groups with identical TTLs don't all re-resolve
  on the same tick.
- **`dnsr:` pull-resolver — log spam** — NXDOMAIN and DNS-exception
  log lines now go through `logsetup.RateLimiter`, keyed per
  `(qname, rdtype)`, so a persistently-missing hostname no longer
  emits every `min_retry` seconds.
- **`dnsr:` pull-resolver — DNS timeout** — explicit 3 s `lifetime`
  / `timeout` on the `dns.asyncresolver.Resolver` so a slow upstream
  can't stall a worker indefinitely. Configurable via the
  `dns_timeout=` constructor kwarg.
- **`dnsr:` compiler — dead nft set declarations** — secondary
  hostnames in a `dnsr:host1,host2,…` group were registered in the
  DNS registry with the same default as primaries, causing the
  emitter to declare `dns_<secondary>_v4/v6` sets that are never
  written to (all IPs land in the primary's set via tracker alias).
  New `DnsSetSpec.declare_set` flag: secondaries register with
  `declare_set=False`; the emitter skips them. A later `dns:` or
  `dnsr:` rule that uses the same hostname as a primary promotes
  the spec to `declare_set=True` so the set does get declared.

- **Lifecycle → shorewalld instance registration** — `shorewall-nft
  start` / `restart` / `reload` now contact the shorewalld control
  socket and register (or re-register) the instance; `stop`
  deregisters it. The daemon loads the instance's `dnsnames.compiled`,
  wires DNSR secondary aliases into the tracker, and updates the
  PullResolver in one merged write (fixes a pre-existing multi-instance
  eviction bug where each instance's `load_registry` wiped the
  previous instance's names).

  - New shorewalld control-socket commands: `register-instance` and
    `deregister-instance`. Payload carries the full `InstanceConfig`
    as JSON: `name`, `netns`, `config_dir`, `allowlist_path`.
  - `shorewall-nft`: new options on `start` / `stop` / `restart` /
    `reload`: `--shorewalld-socket PATH` (env `SHOREWALLD_SOCKET`,
    default `/run/shorewalld/control.sock`) and `--instance-name NAME`
    (env `SHOREWALLD_INSTANCE_NAME`).
  - New `shorewall.conf` key `INSTANCE_NAME`. Precedence for the
    registered name: `--instance-name` CLI flag → `INSTANCE_NAME` in
    `shorewall.conf` → netns name → `config_dir` basename. Fallback is
    deterministic so restart/stop hit the same daemon-side record.
  - `restart` and `reload` now also rewrite `dnsnames.compiled`
    (previously only `start` did). Keeps the daemon's view in sync
    with the running ruleset.
  - Error severity: socket missing or permission denied → warning,
    never fatal (shorewalld down is a normal operator state). Any
    other failure during `register` with DNS/DNSR sets present →
    fatal abort. `deregister` is always non-fatal (daemon ages
    entries out via TTL).
  - shorewalld now starts its `InstanceManager` whenever a control
    socket is configured (previously only when `--instance` was also
    passed), so dynamic registration works without predeclared
    instances.
  - `shorewalld ctl register-instance --config-dir PATH [--netns NS]
    [--name NAME]` and `shorewalld ctl deregister-instance --name NAME`
    are available for manual testing.

- **`PullResolver.update_registry()`** — replace the active set of
  `dnsr:` groups at runtime; preserves the scheduled `next_at` for
  unchanged groups so reloads don't trigger a thundering-herd
  re-resolve.

- **shorewalld: IP-list sets** — new `iplist/` subsystem fetches public
  prefix lists from cloud providers (AWS, Azure, GCP, Cloudflare, GitHub),
  PeeringDB IX route servers, and hardcoded RFC bogons, and writes them into
  nft `flags interval` sets. Diff-based: only changed prefixes are written per
  refresh cycle. Configured via `IPLIST_<NAME>_PROVIDER/FILTERS/SET_V4/…`
  keys in `shorewalld.conf`. Supports filter dimensions per provider
  (AWS: `service`+`region` globs; Azure: `tag` globs; GitHub: `group`; etc.).
  Bogon provider is fully offline.

- **shorewalld: control socket** — optional Unix socket (`--control-socket`,
  `CONTROL_SOCKET=`) with a line-oriented JSON protocol. Commands:
  `ping`, `refresh-iplist [--name N]`, `iplist-status`,
  `reload-instance [--name N]`, `instance-status`. Socket is always
  `root:root 0660`. Bind inside a named netns via `--control-socket-netns`.

- **shorewalld ctl** — new subcommand; thin client for the control socket.

- **shorewalld iplist** — new subcommand; explore providers, list available
  filter dimension values (live fetch), preview prefix output.

- **shorewalld: multi-instance (`--instance`)** — replaces `--allowlist-file`.
  Format: `[netns:]<shorewall-dir>`. Repeat for multiple instances. Each
  instance reads its DNS allowlist from `<dir>/dnsnames.compiled`.
  `--allowlist-file` still works with a deprecation warning.

- **shorewalld: `--monitor`** — inotify watching on instance config dirs;
  reloads `dnsnames.compiled` on atomic replace. Falls back to 5 s polling
  when `watchfiles` is not installed. Off by default (conflicts with explicit
  reload-hook approach).

- **shorewalld: sysconfig/defaults** — systemd units now read
  `EnvironmentFile=-/etc/sysconfig/shorewalld` (RPM) /
  `EnvironmentFile=-/etc/default/shorewalld` (Debian) and pass
  `$SHOREWALLD_ARGS` to `ExecStart`. `ExecReload=kill -USR1 $MAINPID`
  triggers an immediate IP-list refresh. Template at
  `packaging/sysconfig/shorewalld`.

- **shorewalld: SIGUSR1** — refreshes all IP-list sets immediately.

- **shorewalld: `aiohttp>=3.9`** — added as a hard dependency (was optional).

- **packaging: `python3-aiohttp`** — added to RPM `Requires` (both Fedora and
  AlmaLinux 10 profiles) and Debian `Depends` to reflect the promoted
  hard dependency.

- **packaging: sysconfig/defaults** — `.rpm` installs `packaging/sysconfig/shorewalld`
  to `/etc/sysconfig/shorewalld` (`%config(noreplace)`); `.deb` installs it
  to `/etc/default/shorewalld`. File ships empty/commented so the daemon
  starts with defaults until the operator enables a line.

## [1.5.5] — 2026-04-18 — fix CI integration tests: preserve PATH under sudo

### Changes

- fix: preserve PATH for sudo in CI integration tests


## [1.5.4] — 2026-04-18 — fix shellcheck warnings + CI integration test runner

### Changes

- fix: resolve shellcheck warnings + drop pytest-timeout from CI


## [1.5.3] — 2026-04-18 — fix ruff lint + CI test runner venv fallback

### Changes

- fix: resolve ruff lint errors + run-tests.sh venv fallback for CI


## [1.5.2] — 2026-04-18 — set maintainer to avalentin@marcant.net

### Changes

- chore: set maintainer to André Valentin <avalentin@marcant.net>


## [1.5.1] — 2026-04-18 — remove run-netns: native ip-netns + unshare test isolation

### Changes

- docs: add hw-offload roadmap notes
- docs: update testing docs — remove run-netns references, document unshare isolation
- chore: remove run-netns from packaging, CI, and docs
- refactor: replace run-netns with native ip-netns + isolated test wrapper


## [1.5.0] — 2026-04-18 — in-process netns, CLI unification, subprocess cleanup

### Changes

- fix: use subprocess for cross-namespace nft operations
- refactor: replace remaining subprocess/run-netns calls with libnftables API
- refactor: unify CLI options + drop nft -v version probe
- feat: in-process netns path, start progress output, python3-nftables required
- nft/capabilities.py: NAT-Probe-Fix — masquerade braucht nat-chain


## [1.4.3] — 2026-04-17 — RPM spec generator + AlmaLinux 10 build

### Added

- **RPM packaging: AlmaLinux 10 build target.** The `rpm-build` CI job is
  now a matrix with two targets: `fedora40` (as before) and `almalinux10`.
  Both produce installable RPMs; release artifacts upload both sets.
- **Generated .spec file.** `packaging/rpm/shorewall-nft.spec.in` is the
  checked-in template; `tools/gen-rpm-spec.sh --distro {fedora|almalinux10}`
  emits `packaging/rpm/shorewall-nft.spec` at build time. Generated spec
  is git-ignored to prevent drift.
  - Version/Release derived from git: on a `v*` tag → `Version=<tag>` +
    `Release=1%{?dist}`; otherwise → `Version=<last-tag>` +
    `Release=0.<commits_since>.g<sha>%{?dist}` (the leading `0.` keeps
    dev builds sorted below numbered releases).
  - AlmaLinux 10 profile caps `python3-protobuf` at `>= 3.19` (AL10
    AppStream ships 3.19.6; no newer version available in AL10/EPEL 10)
    and `python3-pytest` at `>= 7.4` (CRB). Python 3.12 minimum. The
    AL10 job enables EPEL 10 + CRB for `python3-click`, `python3-pyroute2`,
    `python3-prometheus_client`, and `python3-pytest`.

## [1.4.2] — 2026-04-13 — IPv6 NDP & baseline security fixes

### Changed

- **simlab: scapy-free NDP/ARP fast path on reader threads** — the reader
  thread's asyncio event loop previously called full scapy parse + scapy
  packet construction for every ARP who-has and NDP Neighbor Solicitation.
  A single NDP NS on bond0.70 (~10 ms in scapy) blocked all other fds on
  the same thread, starving bond0.15 and causing spurious probe timeouts.
  New `fast_extract_ndp_ns()`, `fast_build_ndp_na()`, `fast_extract_arp_request()`,
  `fast_build_arp_reply()` in `packets.py` handle ARP/NDP entirely from raw
  bytes with inline ICMPv6 checksum — no scapy import, no GIL contention.

### Fixed

- **IPv6 NDP broken by raw-output dispatch** — the `raw-output` chain
  (priority -300) emitted zone-pair dispatch jumps, routing outgoing NDP
  (Neighbor Solicitation) into chains with `ct state invalid drop`.
  Kernel neighbor resolution was killed before the normal output chain
  could accept it → neighbors stayed INCOMPLETE → no IPv6 forwarding.
  Fix: raw chains (priority < 0) are now excluded from filter dispatch.
- **IPv6 forward rules missing in dual-stack configs** — when merging
  `shorewall` + `shorewall6`, zones present in both configs kept their
  `ipv4` type instead of being promoted to dual-stack `ip`.  All forward
  dispatch rules got `meta nfproto ipv4`, so IPv6 traffic was never
  dispatched to zone-pair chains and fell through to policy accept.
  Fix: merged zones are now typed `ip` (dual-stack) so dispatch rules
  match both address families.
- **simlab: oracle misclassified ICMPv6 probes** — the iptables parser
  maps `--icmpv6-type` into `rule.dport`, but ICMP probes carried
  `port=None`.  Blanket ICMPv6 accept rules were skipped, causing 25
  false fail_accepts.  Fix: substitute the echo-request type (128/8)
  as effective port for ICMP probes.
- **simlab: probe-id collisions between IPv4 and IPv6** — both families
  shared a 16-bit counter.  IPv6 probes now use the full 20-bit flow
  label and start at 0x10000, eliminating cross-family collisions.
- **Base chain policy accept instead of drop** — the filter base chains
  (input, forward, output) had no explicit policy, defaulting to nft's
  `accept`.  Traffic not dispatched to any zone-pair chain was silently
  accepted.  Fix: all three base chains now emit `policy drop`, matching
  the Shorewall iptables architecture.
- **ct state invalid drop in base chain killed IPv6 forwarding** —
  `ct state invalid drop` and `dropNotSyn` were emitted in the base
  chains before dispatch jumps.  This matches no Shorewall precedent
  (iptables puts these checks in zone-pair chains, not the base chain)
  and killed IPv6 forwarded packets before they reached dispatch.
  Fix: base chains now contain only FASTACCEPT (if enabled), NDP accept
  (input/output), and dispatch jumps.  ct state rules live exclusively
  in zone-pair chains.
- **merge-config: dual-stack zones kept ipv4 type** — `merge-config`
  kept the v4 zone type for zones present in both configs, causing
  all dispatch rules to get `meta nfproto ipv4`.  Fix: zones present
  in both v4 and v6 configs are now promoted to type `ip`.
- **Dispatch rule ordering: catch-all zones swallowed IPv6 traffic** —
  zones without interface assignments (e.g. `rsr ipv6`) produced
  dispatch rules without `oifname`.  Alphabetic sorting placed these
  catch-all rules before specific zone-pair rules, routing all IPv6
  into the wrong chain where it was rejected.  Fix: dispatch rules
  with both zones having interfaces are emitted first; catch-all
  rules last.

## [1.4.1] — 2026-04-12 — Monorepo tooling fix + docs restructure + man pages

### Fixed

- **`tools/setup-remote-test-host.sh`**: `pip install -e .` now correctly
  installs all three sub-packages (`packages/shorewall-nft[dev]`,
  `packages/shorewalld[dev]`, `packages/shorewall-nft-simlab[dev]`)
  instead of the empty monorepo root stub. The previous command silently
  produced a broken venv where `shorewall-nft` was not installed.
- **`tools/setup-remote-test-host.sh`**: `pytest tests/` hint in the
  completion message now points to the correct per-package paths
  (`packages/*/tests/`). The root has no `tests/` directory.
- **`tools/setup-shorewalld-dnstap-smoke.sh`**: same pip fix; installs
  `packages/shorewall-nft` and `packages/shorewalld[daemon]`.

### Added

- **`tools/man/shorewalld.8`** — new man page for the `shorewalld` daemon
  covering all options, the `tap` subcommand, configuration file format,
  Prometheus metrics tables, FILES section, and examples.
- **`tools/man/shorewall-nft.8`** — updated to v1.4.1; added 14 previously
  undocumented commands: `show`, `counters`, `reset`, `drop`, `blacklist`,
  `reject`, `allow`, `capabilities`, `explain-nft-features`, `migrate`,
  `generate-sysctl`, `generate-tc`, `generate-set-loader`, `load-sets`.
- **`HOWTO-CLAUDE.md`** — monorepo navigation guide: entry point by problem
  type (compiler, CLI, metrics, DNS sets, simlab, packaging, CI, release).
- **`docs/quick-start.md`** — new beginner and experienced-admin paths.
- **`docs/shorewalld/index.md`** — dedicated docs section for shorewalld.

### Changed

- **Docs restructure**: removed `docs/legacy/` (39 files of upstream
  Shorewall history), `docs/concepts/Anatomy.md`, `docs/concepts/Manpages.md`,
  `docs/features/IPSEC-2.6.md`, `docs/features/Shorewall-init.md`,
  `docs/features/6to4.md`, `docs/features/LennyToSqueeze.md`,
  `docs/features/PPTP.md`, `docs/reference/Build.md`. Reduced from ~152
  to 99 Markdown files.
- **`docs/index.md`** — rewritten around the three-package monorepo structure.
- **`README.md`** — updated from v1.0 single-package presentation to v1.4.1
  monorepo overview with all three packages.
- **`packaging/rpm/shorewall-nft.spec`** and **`packaging/debian/rules`**
  — both now install `shorewalld.8`.

## [1.4.0] — 2026-04-12 — DNS nft-set population + Prometheus metrics

### Added — shorewalld: DNS-driven nft-set population

- **Full DNS-to-nft-set pipeline** via two independent ingestion paths:
  dnstap (FrameStream unix socket) and PBDNSMessage (PowerDNS protobuf
  stream, unix or TCP). Both paths share the same `WorkerRouter` →
  `DnsSetTracker` → `SetWriter` hot path.
- **`DnsSetTracker`** — `(set_name, ip) → expiry` LRU with
  proposal/verdict dedup: a write is skipped when the existing element's
  remaining TTL covers more than 50 % of the incoming TTL.
- **`SetWriter`** — coalescing writer that batches per `(set, netns)` in
  a short window before issuing a single `nft add element` netlink call.
  Avoids per-answer round-trips at high DNS answer rates.
- **`StateStore`** — persists set contents across daemon restarts so
  that nft sets are restored before the firewall starts accepting traffic.
- **`ReloadMonitor`** — watches the shorewall-nft config tree for hash
  drift; on change, triggers a ruleset reload and reconciles the in-memory
  set state against the new ruleset.
- **`WorkerRouter`** — persistent-fork worker pool sized to
  `os.cpu_count()` for GIL-bound protobuf decode; bounded `queue.Queue`
  with drop-and-count overflow.
- **Allowlist filtering** — two-pass decoder walks the varint stream to
  extract discriminator fields (message type, qname) before full decode;
  99 % of frames are discarded without a full parse.
- **HA peer-link replication** — incremental and snapshot sync over
  authenticated UDP (`IP_PMTUDISC_DO`; payloads capped at 1400 bytes;
  large snapshots chunked at the application layer).

### Added — shorewalld: Prometheus metrics exporter (beta)

- **`NftCollector`** — scrapes the `inet shorewall` ruleset with a
  single `list table` netlink round-trip; emits per-rule packet/byte
  counters, named counter objects, and set-element gauges, all labelled
  by netns.
- **`LinkCollector`** — per-interface RX/TX byte/packet counters and
  operational state via pyroute2.
- **`CtCollector`** — connection-tracking table fill level from
  `/proc/sys/net/netfilter/nf_conntrack_count` (setns hop into target
  netns).
- All collectors share a per-netns TTL cache (`--scrape-interval`,
  default 30 s) so Prometheus scrapes faster than the TTL are free.
- Metrics HTTP endpoint: `--listen-prom HOST:PORT` (default `:9748`).
- `prometheus_client` is an optional dependency; the module imports are
  deferred so the package remains importable without it.
- **Beta status**: collector output format and metric names may change in
  a future minor release as the schema stabilises against real workloads.

### Changed

- `OPTIMIZE=8` is now the compiler default when `OPTIMIZE` is absent
  from `shorewall.conf` (previously `OPTIMIZE=0`).

## [1.2.3] — 2026-04-12 — fix CI test dependency

### Fixed

- Add `dnspython>=2.4` and `prometheus_client>=0.20` to the `dev` extra
  so `pip install -e ".[dev]"` (the CI unit-test install) has the daemon
  dependencies available. Without `dnspython`, `parse_dns_response`
  silently returned `None` for every frame, causing the
  `test_tcp_handshake_and_frame_delivery` test to always time out on CI.

## [1.2.2] — 2026-04-12 — version bump

No functional changes.

## [1.2.1] — 2026-04-12 — test robustness

### Fixed

- dnstap TCP test: replace busy polling loop with `asyncio.Event` so the
  assertion no longer races on slow CI hosts.
- dnstap TCP test: tighten shutdown sequencing and extend startup grace
  period to prevent spurious failures on heavily loaded runners.
- Ignore generated protobuf files in ruff lint pass.

## [1.2.0] — 2026-04-12 — shorewalld DNS-set pipeline

Major refactor + expansion of ``shorewalld`` into a full
DNS-driven nft-set populator with HA replication. Extended the
Phase-4 dnstap exporter into a production-grade pipeline with
zero-copy hot paths, persistent state, ruleset-reload
reconciliation, and peer-to-peer replication over authenticated
UDP. 260 new unit and integration tests.

### Compiler default

- **``OPTIMIZE=8`` is now the compiler default** when a config
  omits ``OPTIMIZE`` entirely. Previously the fallback was
  ``OPTIMIZE=0`` (no optimisation). The reference HA ruleset
  has been validated at ``OPTIMIZE=8`` via simlab ``full``
  runs (seed=42 and seed=7, 934/934 deterministic probes pass,
  no ``fail_drop`` / ``fail_accept``, zero drift against the
  iptables point-of-truth oracle). Configs that explicitly set
  ``OPTIMIZE=N`` are unaffected. The config generator
  (``config_gen``) also emits ``OPTIMIZE=8`` in newly
  synthesised ``shorewall.conf`` templates.

### Daemon lifecycle integration

- **``Daemon.run()`` now owns the full DNS-set pipeline** as
  opt-in subsystems. When the operator passes ``--allowlist-file``
  (or sets ``ALLOWLIST_FILE`` in ``shorewalld.conf``), the
  daemon builds tracker + WorkerRouter + SetWriter + TrackerBridge
  + StateStore + ReloadMonitor, and conditionally adds the
  PbdnsServer (``LISTEN_PBDNS``) and HA PeerLink
  (``PEER_HOST``/``PEER_ADDRESS`` + ``PEER_SECRET_FILE``).
  Shutdown runs async cleanup in reverse wiring order
  (peer → pbdns → reload_monitor → state_store → set_writer →
  router) before calling the synchronous teardown for the
  Prometheus server / profile builder / reprobe task.
- **DnstapServer bridge mode.** The legacy Phase-4 dnstap
  consumer now accepts an optional ``TrackerBridge`` and, when
  supplied, routes decoded ``DnsUpdate`` records through the
  tracker + batched SetWriter + persistent worker pipeline
  instead of the direct ``nft.add_set_element`` path. ``Daemon``
  wires this automatically when both ``--listen-api`` and
  ``--allowlist-file`` are set.

### Operator config file

- **``shorewalld.conf`` parser** (``shorewall_nft/daemon/config.py``).
  Shell-flavoured ``KEY=value`` file searched at
  ``/etc/shorewall/shorewalld.conf`` then ``/etc/shorewalld.conf``,
  overridable via ``--config-file PATH``. Supports
  ``LISTEN_PROM``, ``LISTEN_API``, ``NETNS``, ``SCRAPE_INTERVAL``,
  ``REPROBE_INTERVAL``, ``ALLOWLIST_FILE``, ``PBDNS_SOCKET``,
  ``PEER_LISTEN``, ``PEER_ADDRESS``, ``PEER_SECRET_FILE``,
  ``PEER_HEARTBEAT_INTERVAL``, ``STATE_DIR``, ``STATE_ENABLED``,
  ``RELOAD_POLL_INTERVAL``, ``LOG_LEVEL``, ``LOG_TARGET``,
  ``LOG_FORMAT``, ``LOG_RATE_LIMIT_WINDOW``, plus
  ``LOG_LEVEL_<subsys>`` per-subsystem overrides. Precedence:
  explicit CLI flag > config-file value > built-in default.
  Unknown keys are silently ignored so future knobs are
  forward-compatible. Malformed files raise ``ConfigError`` at
  startup (the daemon does not start with a broken config).

### New compiler surface

- **``dns:hostname`` rule token** in SOURCE/DEST columns. Each
  occurrence compiles to two emitted rules (v4 + v6 family) and
  two declared nft sets (``dns_<name>_v4`` / ``dns_<name>_v6``)
  with ``flags timeout`` and the configured size. Canonicalised
  via ``qname_to_set_name()`` so compile-time and runtime agree
  on the exact set name for any given hostname.
- **``dnsnames`` config file** (optional) for per-hostname
  overrides of TTL floor, TTL ceiling, set size, and a free
  comment. Each row shapes the corresponding set and the
  DnsSetTracker's clamp bounds at runtime. Hostnames seen only
  in ``rules`` fall back to the global defaults.
- **``DNS_SET_TTL_FLOOR``, ``DNS_SET_TTL_CEIL``, ``DNS_SET_SIZE``**
  added to ``shorewall.conf``.
- **``/etc/shorewall/dnsnames.compiled``** — compiler output
  consumed by shorewalld as the authoritative runtime allowlist.
  Atomic tmp+rename on write; loader tolerates malformed lines
  and counts them in metrics.
- ``shorewall_nft/nft/dns_sets.py`` — shared helper module used
  by both the compiler and the daemon so there is zero drift
  between emission-time and runtime naming.

### Daemon — ingestion

- **TCP dnstap listener**. ``DnstapServer`` now accepts a
  ``(tcp_host, tcp_port)`` pair in addition to the unix socket
  path. Both listeners run concurrently so operators can serve a
  local recursor on unix and receive replicated frames from a
  remote recursor on TCP simultaneously. Same FrameStream
  handshake, same decoder, same metrics labels.
- **PowerDNS PBDNSMessage ingestion** (``shorewall_nft/daemon/
  pbdns.py``). Alternative to dnstap: pdns recursor's native
  ``protobufServer()`` output over length-prefixed unix socket.
  Records arrive pre-decomposed (typed DNSRR name/type/ttl/rdata
  fields) so the decoder sidesteps dnspython entirely, cutting
  CPU by ~40% at 10 k fps. Mirrored
  ``shorewalld_pbdns_*`` metrics for A/B comparison with dnstap.
- **Two-pass qname filter** (``shorewall_nft/daemon/dns_wire.py``).
  Minimal DNS wire walker extracts the qname and rcode with zero
  allocations; decoder rejects allowlist misses before invoking
  dnspython. On typical recursor traffic this drops 95%+ of
  frames before the expensive parse.
- **Protobuf is now a hard dependency**. ``protobuf>=4.25`` added
  to ``pyproject.toml`` and the vendored schemas
  (``daemon/proto/dnstap.proto``, ``dnsmessage.proto``, ``peer.proto``)
  are shipped with the package. Generated ``*_pb2.py`` modules
  are checked in so no build-host protoc is required.
- **``shorewalld tap`` operator CLI** (``shorewall_nft/daemon/tap.py``).
  tcpdump-for-DNS-answers: binds a dnstap socket, decodes via the
  same path the production daemon uses, pretty-prints with ANSI
  colour on a TTY or emits structured/JSON lines for scripting.
  Filters by qname regex, rcode, and RR type; tags each frame
  with allowlist hit/miss when pointed at
  ``dnsnames.compiled``; prints a top-N summary on exit.

### Daemon — runtime state

- **DnsSetTracker** (``shorewall_nft/daemon/dns_set_tracker.py``).
  Central in-memory source of truth keyed on integer ``set_id``
  + ``ip_bytes``. Propose/commit API: decoders call
  ``propose()`` and get ADD / REFRESH / DEDUP verdicts; writes
  that commit success update the tracker atomically. Periodic
  ``prune_expired()`` removes entries whose deadline has passed
  in monotonic time. Lock-free ``snapshot()`` for the Prometheus
  scrape thread. Full state export/import API for persistence
  (Phase 6) and peer snapshot sync (Phase 9).
- **SetWriter** (``shorewall_nft/daemon/setwriter.py``).
  asyncio coroutine that owns the entire write path. Thread-safe
  ``submit()`` from decoder workers; batches by
  ``(netns, family)`` with configurable window/max-ops triggers;
  flushes on window expiry, batch fullness, or shutdown.
  Dispatches through WorkerRouter; commits to tracker only after
  worker ack so a mid-flight crash doesn't lose dedup state.
- **Persistent nft worker subprocesses**
  (``shorewall_nft/daemon/nft_worker.py`` +
  ``worker_router.py``). One long-lived child per managed
  netns: forks at daemon startup, ``setns(CLONE_NEWNET)`` into
  the target namespace, ``PR_SET_PDEATHSIG`` for parent-death
  cleanup, drops into a main loop consuming ``BatchCodec``
  datagrams over ``SOCK_SEQPACKET``. No setns thrash in the hot
  path, libnftables bound to the target netns exactly once.
  For the daemon's own netns, ``LocalWorker`` bypasses the
  fork and runs libnftables inline on a dedicated single-thread
  executor.
- **Binary batch codec** (``shorewall_nft/daemon/batch_codec.py``).
  Hand-rolled fixed-size wire format for parent↔worker IPC:
  16-byte header + 24-byte ops × N, max 40 ops/batch (< 1000
  bytes per datagram, fits MTU). Preallocated ``bytearray`` +
  ``memoryview`` through the whole encode path, zero allocations
  per op in the steady state. Reply codec with inline error
  strings. Control messages (shutdown, snapshot) share the
  envelope.
- **SEQPACKET transport** (``shorewall_nft/daemon/worker_transport.py``).
  Thin wrapper around ``socketpair(AF_UNIX, SOCK_SEQPACKET)``
  with preallocated receive buffer and ``MSG_TRUNC`` detection.
  Atomic datagrams mean no length-framing, no user-space copy
  between encoder and kernel.

### Daemon — persistence and reconciliation

- **StateStore** (``shorewall_nft/daemon/state.py``). Periodic
  atomic JSON snapshot of the tracker to
  ``/var/lib/shorewalld/dns_sets.json``. Wall-clock absolute
  deadlines in the file so reboots don't invalidate
  ``time.monotonic()`` values. Cold-boot load prunes expired
  entries, installs the survivors, and the daemon carries the
  set contents across restarts without a TTL-sized deny window.
  CLI flags ``--state-flush`` (delete file + start empty),
  ``--no-state-load`` (keep file, don't load), ``--state-dir``.
- **ReloadMonitor** (``shorewall_nft/daemon/reload_monitor.py``).
  Detects ruleset reloads via per-netns fingerprint polling; on
  transition ``absent→present`` or ``fingerprint change``,
  repopulates the entire tracker state into the freshly-loaded
  table as a sequence of batched writes. Per-netns probes so a
  multi-namespace deployment reconciles each independently.
  Metrics split by reason so operators tell boot-time populates
  from production restart blips.

### Daemon — HA peer replication

- **PeerLink** (``shorewall_nft/daemon/peer.py``). UDP-based
  replication between shorewalld instances on a two-node HA
  pair. Every DNS set write on one side replicates to the peer
  so both boxes converge without each one independently
  resolving every qname. Authentication via HMAC-SHA256 keyed
  from a shared secret file (``PEER_SECRET_FILE``); auth is
  pluggable behind a ``PeerAuth`` protocol so AEAD or Ed25519
  can drop in later.
- **IP_PMTUDISC_DO** set on the peer socket so oversize sends
  fail loudly with ``EMSGSIZE`` — we never let the kernel
  fragment our datagrams. Every envelope is capped at 1400 bytes
  before serialisation.
- **Heartbeat loop** every ``PEER_HEARTBEAT_INTERVAL`` (default
  5 s). Carries the sender's counter snapshot so receivers
  publish ``shorewalld_peer_*{peer=name}`` metrics — scraping
  either node's ``/metrics`` endpoint shows both nodes' health.
- **Loop prevention** via ``origin_node`` field; self-sourced
  frames are dropped on receipt.
- **Sequence tracking** per sender for gap detection; gaps bump
  ``shorewalld_peer_frames_lost_total`` but trigger no
  retransmit — TTL-based convergence handles lost updates
  organically.
- **SnapshotRequest / SnapshotResponse**. A node booting with
  stale or missing state can ask its peer for the current DNS
  set contents. The peer builds the response as a multi-chunk
  stream (``SNAPSHOT_CHUNK_SIZE = 20`` entries per envelope,
  sized to fit under MTU). App-level chunking, not IP
  fragmentation — stateful middleboxes on the HA interlink
  can't silently drop chunks due to reassembly state loss.
  Receivers apply chunks incrementally via SetWriter.

### Logging

- **``logsetup.py`` foundation**. Hierarchical loggers per
  subsystem (``shorewalld.core``, ``.dnstap``, ``.peer``, …);
  target configurable to stderr, stdout, syslog (AF_UNIX
  ``/dev/log``), systemd journal, or a rotating file; three
  format variants (human, structured key=value, JSON); per-
  subsystem level overrides via ``--log-level-<subsys>``;
  RateLimiter with configurable window for hot-path warning
  dedup. Integrated into the CLI flag set.

### Metrics additions

``shorewalld_dnstap_*`` mirrored in ``shorewalld_pbdns_*``,
plus new families:

```
shorewalld_dns_set_elements{set,family}
shorewalld_dns_set_adds_total{set,family}
shorewalld_dns_set_dedup_hits_total{set,family}
shorewalld_dns_set_dedup_misses_total{set,family}
shorewalld_dns_set_expiries_total{set,family}
shorewalld_dns_unknown_qname_total
shorewalld_state_dns_sets_saves_total
shorewalld_state_dns_sets_load_entries_total
shorewalld_state_last_save_age_seconds
shorewalld_reload_events_total{reason}
shorewalld_reload_repopulate_batches_total
shorewalld_reload_repopulate_entries_total
shorewalld_peer_up{peer}
shorewalld_peer_frames_sent_total{peer}
shorewalld_peer_frames_received_total{peer}
shorewalld_peer_frames_lost_total{peer}
shorewalld_peer_hmac_failures_total{peer}
shorewalld_peer_heartbeats_sent_total{peer}
shorewalld_peer_snapshot_requests_sent_total
shorewalld_peer_snapshot_chunks_received_total
shorewalld_peer_snapshot_entries_applied_total
shorewalld_log_messages_total{level,logger}
shorewalld_log_dropped_total{reason}
```

### Tests

- 260 new unit/integration tests under ``tests/``, all fast
  (< 2 s total) and isolated (no fork, no setns, no CAP_NET_ADMIN).
- ``tests/test_daemon_integration.py`` wires the entire stack
  end-to-end: compiler → emitter → tracker → dnstap+pbdns
  ingestion → SetWriter → inproc worker → state persistence →
  reload monitor → HA peer replication → snapshot resync.
- Full suite sits at 717 tests passing (from 541 pre-refactor),
  zero regressions, lint clean.

### Documentation

- ``docs/reference/shorewalld.md`` expanded with sections on
  DNS-backed rule syntax, the ``dnsnames`` config file, the
  ``shorewalld tap`` CLI, PBDNSMessage ingestion, TCP dnstap
  listener, state persistence, reload monitor, HA peer
  replication with HMAC, snapshot resync, and the performance
  doctrine.

## [1.1.0] — 2026-04-11

nft-native feature expansion and verifier robustness fixes driven
by a full end-to-end validation against the reference HA firewall
release config.

### Config-file coverage round (TODO #9 closed)

Eight Shorewall config files that the structured-io groundwork
parsed but the IR/emitter ignored are now wired end-to-end. Each
landed with its own pytest cases under
`tests/test_emitter_features.py`:

- **`stoppedrules`** — modern routestopped successor. Routes
  ACCEPT / DROP / REJECT / NOTRACK actions into the standalone
  `inet shorewall_stopped` table that ``shorewall-nft stop`` loads.
  Direction inferred from `$FW` source/dest (input vs output vs
  forward); NOTRACK lands in a lazily-created
  `stopped-raw-prerouting` chain.
- **`proxyarp` / `proxyndp`** — pyroute2-driven apply / remove
  via the start / stop CLI. Sets the per-iface
  `net.ipv{4,6}.conf.<iface>.proxy_arp / proxy_ndp` sysctls and
  installs an `NTF_PROXY` neighbour entry on the publishing
  interface plus an optional `/32` or `/128` route when
  `HAVEROUTE=no`. Idempotent (replace semantics) so reloads are
  safe; `PERSISTENT=yes` entries survive `shorewall-nft stop`.
- **`rawnat`** — raw-table actions pre-conntrack. NOTRACK,
  ACCEPT, DROP routed into the existing
  `raw-prerouting` / `raw-output` chains via the standard zone
  spec parser; `$FW` source picks `raw-output`, anything else
  picks `raw-prerouting`.
- **`arprules`** — separate `table arp filter` block. The arp
  family is its own nft table type so the new `ir.arp_chains`
  dict and `emit_arp_nft()` helper render a standalone
  `table arp filter` that the main script appends. ARP sender
  IP, ARP target IP, interface, and sender MAC matches all
  supported.
- **`nfacct`** — named counter object declarations. The nfacct
  rows produce `counter <name> { packets N bytes M }` entries
  at the top of the inet shorewall table; rules can reference
  them via `counter name "<name>"`.
- **`scfilter`** — source CIDR sanity filter. Each row prepends
  a negated-set drop rule (one per family) to the input and
  forward base chains, so spoofed sources land in the
  drop-before-zone-dispatch slot.
- **`ecn`** — clear ECN bits per iface/host. Lazily creates a
  `mangle-postrouting` chain (priority -150) and emits one rule
  per host with the new `ecn_clear:` verdict marker, which the
  emitter renders as `ip ecn set not-ect`.

Bonus from this round: **legacy `routestopped`** also got the
full Shorewall feature parity treatment — the `OPTIONS` column
parser now supports `routeback`, `source`, `dest`, `critical`,
and `notrack`; the `SPORT` column (cols[5]) is honoured; IPv6
hosts auto-route to `ip6 saddr/daddr`; and the global
`ROUTESTOPPED_OPEN=Yes` setting collapses every listed
interface to a wildcard accept.

### simlab — first 100 % green archived run

The simlab full smoketest now runs to 100 % across both
the per-rule (`POSITIVE`) and random-probe categories on the
reference HA firewall config:

- POSITIVE: **836 / 836** ok = 100.0 %, fail_drop = 0
- NEGATIVE: **99 / 99**  ok = 100.0 %, fail_drop = 0
- RANDOM:   **64 / 64**  ok = 100.0 %, fail_drop = 0

Two regression-baseline runs are archived under
`docs/testing/simlab-reports/`:
- `20260411T150507Z/` — first archived green run
- `20260411T155107Z/` — multi-iface zone + proto auto-generator
  green run

The path to green spanned a long autonomous fix loop. The
load-bearing fixes:

- **emitter**: zone-pair dispatch jumps now carry a
  `meta nfproto ipv4|ipv6` qualifier when either side is a
  single-family zone (e.g. an IPv6-only zone in a merged
  shorewall46 config). Pairs with conflicting families are
  skipped — they were the cause of every IPv4 probe falling
  into a v6-only chain whose terminal sw_Reject dropped them.
- **compiler/ir._add_rule**: extends the existing ACCEPT /
  policy=ACCEPT dedup to DROP / REJECT verdicts. A rule like
  `DROP:$LOG customer-a any` in the rules file used to expand into
  every customer-a→X chain as an inline catch-all drop, and when
  file order put it before later `all → X:host` accept
  expansions the inline drop landed mid-chain and shadowed
  every accept that followed. The iptables backend never
  inlines these — it relies on the chain's policy at the
  tail. The shorewall-nft compiler now mirrors that behaviour.
- **simlab autorepair**: collects every IP the firewall owns
  across every interface (not just the iterated address) and
  walks candidate hosts from the high end down. The previous
  picker landed on fw-local secondary IPs that the kernel
  rejected as a martian source before any rule evaluated.
  `RandomProbeGenerator._pick_host` gets the same treatment.
- **simlab oracle**: chain fall-through is now classified as
  DROP (matching Shorewall's policy chain at the chain tail)
  instead of UNKNOWN. Removes a long tail of false-positive
  random-probe mismatches.
- **simlab autorepair pass 3 (dst routing)**: now accepts ANY
  iface in the destination zone, not just the canonical one.
  Fixes the multi-iface zone case (host has bond0.20+bond0.21,
  net has bond1+bond0.19+bond0.61). When the routed iface
  differs from the planned dst_iface, plan["dst_iface"] is
  rewritten so the controller observes on the right TAP — the
  nft chain dispatch already covers both via its
  `oifname { … }` set.
- **simlab pre-pass**: drops probes whose dst_ip is a
  fw-local address — those go through INPUT, not FORWARD, so
  the zone-pair chain never fires.
- **simlab/packets**: injector default `src_mac` aligned to
  the controller's synthetic worker MAC so the kernel's
  neighbour cache stays consistent and forwarded probes don't
  get silently dropped as stale neighbour-table updates.

### simlab — protocol coverage expansion

The probe pipeline now covers every IP protocol shorewall-nft
emits rules for, not just tcp/udp/icmp:

- **`packets.build_unknown_proto()`** — generic auto-generator
  that emits a minimal IPv4/IPv6 header with the requested
  protocol byte, `probe_id` in the IP id (v4) or flow-label
  (v6) field, and a 16×0xfe payload. Scapy auto-fills
  version / ihl / total_len / checksum so headers stay valid.
- **`packets.proto_number()`** — hand-curated `_PROTO_NUMBERS`
  table maps names → IANA numbers (esp / ah / gre / vrrp /
  ospf / igmp / sctp / pim / …). Numeric strings ("112") and
  ints (112) also accepted. No `/etc/protocols` runtime
  dependency — works in chroots.
- **simulate.derive_tests_all_zones**: accepts any proto
  resolvable via `proto_number()`. Multicast destinations
  (vrrp, ospf, igmp, pim) get a placeholder daddr from the
  well-known group when the rule has no `-d`.
- **smoketest._plan_to_spec**: tcp/udp/icmp keep dedicated
  builders; everything else falls through to
  `build_unknown_proto`, removing the per-proto branch tax.

Hand-rolled BGP and RADIUS builders deleted — they're covered
by the auto-generator if the iptables parser ever surfaces a
matching `-p`.

### simlab — production-faithful per-iface routefilter (TODO #12)

`SimController` and `SimFwTopology` now accept an
`iface_rp_filter` dict and replay the per-interface
`routefilter` values from the parsed shorewall config inside
the netns instead of forcing `rp_filter=0` globally. Strict
per-iface RPF is functionally a no-op for surviving probes
because autorepair pass 4 already enforces routability — the
reference HA firewall ships rp_filter=1 on 22 ifaces and the
run stays 100 % green.

`runtime/sysctl.py` extends the routefilter mapping to the
full Shorewall set: implicit `routefilter` (=1),
`routefilter=1`, `routefilter=2` (loose), `noroutefilter`.
Loose mode was previously silently ignored.

### simlab — flowtable offload sanity check (TODO #7)

New `_flowtable_state()` post-run helper queries `nft -j list
flowtables` inside the simlab netns at the end of a run and
prints a single-line summary listing every active flowtable
with its device count. Best-effort; configs without
`FLOWTABLE=` emit no output. Configs that DO get an instant
"yes the fast-path is wired" signal at the end of every run.

### simlab — pytest CI gate

`tests/test_simlab_pytest_gate.py` covers the simlab pieces
that don't need root or a real netns: the autorepair zone-src
picker, the RandomProbeGenerator fw-local exclusion, oracle
fall-through classification, and explicit accept/drop
matching. Runs in a few hundred ms and gates the autorepair /
oracle code paths against silent regressions between full
simlab runs.

### routestopped — full Shorewall semantics + standalone table

- routestopped used to be parser-only — the IR built chains nobody
  ever rendered or loaded. The runtime path is now wired end to
  end. `_process_routestopped` populates a dedicated
  `ir.stopped_chains` dict (kept apart from `ir.chains` so the
  main emitter can never mix it into the running ruleset), and
  `nft/emitter.emit_stopped_nft` renders a standalone
  `inet shorewall_stopped` table that loads independently.
- `shorewall-nft stop` compiles the config, deletes the running
  `inet shorewall` table, and loads `inet shorewall_stopped`
  if routestopped is configured. `start` tears down any
  leftover `shorewall_stopped` table so the two rulesets never
  run side by side.

### Structured-io coverage round (TODO #13 first sweep)

Aesthetic + ordering + metadata + parser-coverage pass on the
structured config exporter, driven by the user goal of replaying
the `/etc/shorewall46` merged config from multiple host snapshots
into a clean canonical layout.

- **Pretty exporter** — `write_config_dir(..., pretty=True)` is
  the new default. `_aligned_block` renders columns padded to
  the per-column max width across the block, capped at 28
  chars so a single 200-char host list doesn't blow up
  padding for every other row.
- **Zone-pair reorder** — `_reorder_rules_block` groups rules
  by zone-pair affinity via a stable sort on
  `(src_zone, dst_zone)`. Catch-all DROP / REJECT rules (no
  host/proto/port narrowing) get pushed to the bottom of each
  zone-pair group, so the kind of mid-chain shadowing
  `_add_rule` was just fixed for can't sneak back via a
  hand-edit.
- **`?COMMENT` directive preservation** — `_emit_block` walks
  each row's `comment_tag` and emits `?COMMENT <tag>` headers
  before tag runs. The parser had been recording these for
  years but no consumer ever wrote them back; round-trip-via-
  disk silently erased the semantic groupings ("monitoring",
  "Sophos UTM Administration", "CDN (example.com)" etc.)
  that humans use to scan the rules file.
- **Provenance markers** — opt-in `provenance=True` interleaves
  `# from <file>:<lineno>` shell comments before each row so
  a future bisect can blame the origin file/line of any rule.
- **`config merge` CLI** — new `shorewall-nft config merge`
  subcommand reads N source dirs and unions them into a single
  pretty-printed output. Post-concat **dedup pass** drops
  byte-equal duplicate rows by `(section, columns)`. Verified
  by passing the same source twice → 1801 duplicates dropped.
- **`config template` CLI** — generic `@host\t<line>` text
  expander for the legacy keepalived / conntrackd snapshots
  that use prefix templating. Preserves indentation by
  stripping only the tag plus exactly one whitespace
  separator. Lives under `config` because it's a config-
  related text utility, but it's deliberately a generic
  file-level filter rather than a parser feature.
- **Parser coverage** — `load_config` now also reads:
  - **`blacklist`** (legacy CIDR + proto/port columnar file)
    with a new `ShorewalConfig.blacklist` field
  - **`helpers`** (loadmodule script) into `config.scripts`
  - **`plugins.conf`** + **`plugins/*.toml`** + **`plugins/
    *.token`** via stdlib `tomllib` into `config.plugin_files`
  - **`compile`** + **`lib.private`** extension scripts
  Round-trip coverage on the reference HA firewall went from
  27 → 33 files in the merged output.

### Documentation / roadmap

- **`docs/roadmap/shorewalld.md`** — design plan for the new
  async daemon that closes TODO #11 (Prometheus exporter) and
  lays groundwork for TODO #4 (DNS-based filtering via the
  powerdns recursor RPZ + protobuf sidecar). Captures the
  multi-netns scraper-profile architecture, the
  libnftables-based per-rule counter export path, and the
  Phase 4 DNS-set unix socket placeholder. Implementation
  deferred to a future release line.
- **CLAUDE.md** TODOs #9 (config files) and #12 (routefilter)
  marked complete; #7 (flowtable probe) and #11 (Prometheus
  exporter) updated to point at the relevant new code or
  design doc.

### Added

- `FLOWTABLE=dev1,dev2,…` / `FLOWTABLE=auto` shorewall.conf
  directive. Emits an nft `flowtable ft { hook ingress priority
  filter; devices = { … }; }` and injects `meta l4proto { tcp,
  udp } flow add @ft` at the top of the forward base chain.
  Established flows use the kernel fastpath instead of walking
  the full chain tree — a significant throughput win for
  transit-heavy firewalls, particularly HA pairs with bird/BGP
  routing. Optional `FLOWTABLE_OFFLOAD=Yes` flips the hardware
  offload flag for NICs that support it.
- `OPTIMIZE_VMAP=Yes` shorewall.conf directive. Replaces the
  cascade of `iifname "X" oifname "Y" jump chain-X-Y` dispatch
  rules with a single `iifname . oifname vmap { "X" . "Y" :
  jump chain-X-Y, … }` expression — turns N sequential jumps
  into one hash lookup in the forward base chain. Gated behind
  the flag so the default ruleset layout is unchanged.
- `CT_ZONE_TAG=Yes` shorewall.conf directive. Emits a mangle
  prerouting chain that tags ct mark on the first packet of
  every new flow with a deterministic per-zone value.
  conntrackd replicates ct mark across the HA pair, so zone
  identity survives failover even when the active node's state
  was mid-flow at the moment the VIP moved.
- Dual-stack simulate topology: the src/dst veth pairs now
  carry IPv4 and IPv6 addresses simultaneously. `shorewall-nft
  simulate --ip6tables FILE --targets6 …` runs v6 test cases in
  the same topology pass as v4. `nc -6`, `ping6`, and a
  dual-stack python UDP echo listener replace their v4
  counterparts when `TestCase.family == 6`.
- `shorewall-nft simulate --targets LIST|@FILE` — many targets
  share a single netns topology so the nft ruleset is loaded
  exactly once. Cuts full-config simulate runs from minutes to
  seconds by avoiding the CPU burst of reloading a
  multi-thousand-rule ruleset per target.
- `--src-iface` / `--dst-iface` CLI overrides for `simulate` so
  users can exercise zone pairs other than the default net→host
  without editing topology code.
- Small-scale conntrack probe after every simulate run: drives
  one TCP, UDP, and ICMP flow and asserts each protocol gets
  at least one tracked entry via `conntrack -L -p PROTO`.
- `tools/setup-remote-test-host.sh` — one-shot bootstrap for a
  RAM-only test box: rsyncs the repo, creates a venv, runs
  `install-test-tooling.sh`, and stages simulate ground-truth
  data.
- `tools/simulate-all.sh` — convenience wrapper that iterates
  `shorewall-nft simulate` across the top-N destination IPs in
  an iptables-save dump and aggregates per-target counts.
- `docs/roadmap/post-1.0-nft-features.md` — roadmap for post-1.1
  nft features (DNS-based filtering with pdns_recursor,
  synproxy, named-set file auto-reload, stateful limit objects).

### Fixed

- **Host-wide process kill via `ip netns exec kill -9 -1`**. Three
  callsites used `kill -9 -1` inside a netns to tear down leftover
  processes. Because `ip netns` only isolates the network
  namespace, `-1` reaches every process the caller can signal on
  the host — including pytest itself, the SSH session, and
  `user@0.service`. Replaced with `_kill_ns_pids()` which
  enumerates attached PIDs via `ip netns pids NS` and SIGKILLs
  each individually.
- Triangle verifier: `_extract_nft_fingerprints()` now strips nft
  anonymous-set braces (`{ … }`) from `ip saddr`, `ip daddr`,
  and `tcp/udp dport` match values before splitting on commas.
  Without this fix `OPTIMIZE=4` and higher produced rules like
  `ip saddr { 1.1.1.1, 1.1.1.2 }` whose first/last element
  carried the literal `{`/`}` character into the fingerprint,
  causing the reference config to drop from 100.0 % →
  74.2 % IPv4 / 71.6 % IPv6 rule coverage purely because of the
  tokenisation bug.
- Triangle verifier follows `OPTIMIZE=8` chain_merge redirects
  tagged with `merged: identical to <canonical>`, inlining the
  canonical chain's fingerprints into the merged pair.
- `shorewall-nft verify --iptables` now runs the IPv6 triangle
  whenever an ip6tables-save dump is present, even for merged
  shorewall46 directories (v4+v6 tagged by `?FAMILY` in the
  same files, no separate config6_dir sibling).
- `CompareReport.passed` no longer treats extras as a pair
  failure. Remaining extras after the existing filter passes
  represent cases where the nft ruleset is strictly more
  permissive than the iptables baseline (e.g. shorewall-nft's
  `Web` macro covers `{80, 443}` while the older
  shorewall-iptables `Web` macro in the baseline had only
  `{80}`). `passed_strict` is available for the old gate.
- `derive_tests()` in simulate picks a concrete host IP from a
  broad source subnet instead of skipping every rule whose
  source prefix is shorter than /24.

### simlab packet-level verifier

- `shorewall_nft.verify.simlab` — TUN/TAP-based reproduction of
  the target firewall's real namespace topology. Forks a pool
  of asyncio workers (one or more per TUN/TAP), loads the
  compiled nft ruleset into an NS_FW network namespace pinned
  via `nsstub` (kernel-level cleanup on controller death),
  injects packets via scapy builders, correlates observed
  packets through IPv4 `id` / IPv6 flow-label stashed probe
  ids, and reports per-probe pass/fail with per-zone-pair
  statistics. Superseding the fixed-topology `simulate.py`
  for packet-level coverage of multi-homed configs.
- `smoketest` CLI subcommand (`smoke`, `stress N`, `limit`,
  `full`) with load throttle (`--load-limit`), probe
  batching (`--batch-size`), per-rule random sampling
  (`--random-per-rule`), per-zone-pair budget
  (`--max-per-pair`), and a scrubbable archive report at
  `docs/testing/simlab-reports/<UTC>/` (report.json, report.md,
  mismatches.txt, fail-pcaps/).
- Four-way pass/fail split in every probe-report surface:
  `pass_accept`, `pass_drop`, `fail_drop` ("should have had
  access but was DROPPED"), `fail_accept` ("should have been
  blocked but was ACCEPTED"). Replaces the old "N matches / N
  mismatches" reporting with the direction-aware split that
  triage actually uses.
- Autorepair pass 1 rewrites `derive_tests`' `DEFAULT_SRC`
  placeholder (TEST-NET-1 `192.0.2.69`) with a host from the
  source zone's own subnet so the FW's rp_filter doesn't drop
  probes at ingress. On the reference config this recovered
  ~12.7k probes that were previously reported as spurious
  `fail_drop`.
- Autorepair pass 2 runs every per-rule TestCase back through
  `RulesetOracle.classify` against the iptables-save dump
  (Point of Truth per `docs/testing/point-of-truth.md`) so
  each random variant inherits its authoritative expected
  verdict from a full chain walk instead of the generator's
  source rule's target.
- pcap-on-failure: every failed probe gets a single-frame pcap
  dumped under `<run_dir>/fail-pcaps/<probe_id>-<inject>-<expect>-
  <direction>.pcap` plus a grep-friendly index.
- Worker consolidation: the fork pool defaults to
  `max(2, cpu_count)` multi-interface asyncio workers instead
  of one fork per TUN/TAP. On the 2-core reference VM this
  drops worker count 24 → 2 and pool RSS ~2 GB → ~170 MB.
- Streaming probe materialisation: the parent keeps only
  lightweight plan dicts (`~150 B`) in memory for the entire
  run; ProbeSpec objects with payload bytes + match closures
  are built per batch and garbage-collected after fire.
- Unit-testable autorepair helpers
  (`_build_zone_to_concrete_src`, `_expand_port_spec`) with
  11 pytest cases that run without nft/root/netns.

### Structured config I/O (`--override-json` / `config export` / `config import`)

- Central column schema at `shorewall_nft/config/schema.py`
  — single source of truth for 33 columnar Shorewall files +
  13 extension scripts, verified against the positions the
  compiler actually reads (not just the upstream manpages).
  Files added as parseable columnar this release:
  `arprules`, `proxyarp`, `proxyndp`, `ecn`, `nfacct`,
  `rawnat`, `stoppedrules`, `scfilter`.
- `shorewall_nft/config/exporter.py` — emits a parsed
  `ShorewalConfig` as a structured JSON/YAML blob. File
  names are top-level keys, KEY=VALUE files flatten to dicts,
  columnar files emit one object per row with column names
  as keys, `rules`/`blrules` are nested under their
  `?SECTION` labels. Extension scripts round-trip as
  `{name: {lang: sh, lines: [...]}}`.
- `shorewall_nft/config/importer.py` — the round-trip
  counterpart. `blob_to_config(blob)` builds a fresh
  `ShorewalConfig`; `apply_overlay(config, overlay)` merges
  an overlay on top (used by `--override-json`); `write_
  config_dir(config, target_dir)` serialises back to
  on-disk Shorewall files (columnar + macros + scripts).
  Parse → export → import → export is byte-identical on
  the 202 979-byte reference config.
- Global CLI flags `--override-json JSON_OR_@FILE` and
  `--override FILE=JSON_OR_@FILE` (repeatable). Accepts
  literal JSON, `@path` file, `-` stdin, YAML via `.yaml`
  extension. Load order: defaults → on-disk → overlay.
  Every compile-touching subcommand (compile, check, start,
  simulate, …) picks up the overlay automatically.
- `shorewall-nft config export [DIR] --format=json|yaml
  [-o FILE]` — read-only dump of the parsed config directory.
- `shorewall-nft config import FILE --to DIR [--force]` —
  writes a structured blob back as on-disk Shorewall files.
  Refuses to overwrite a non-empty target without `--force`.
- 18 new pytest cases for the structured-io pipeline (10
  round-trip + 8 CLI end-to-end via subprocess).

### netbox plugin deployment wiring

- `tools/*-deploy.env.example` template + gitignored
  per-deployment `.env` for netbox API config.
  `setup-remote-test-host.sh` sources it and writes
  `/etc/shorewall46/plugins.conf` plus `plugins/netbox.toml`
  and `plugins/netbox.token` (mode 0600) on the target.
- Bootstrap also runs `shorewall-nft merge-config` on the
  remote as the final step, so `/etc/shorewall46` is the
  plugin-aware merged output, not a static copy.

### Exec reduction Phase A + B (libnftables + setns preexec)

- `shorewall_nft/nft/netlink.py` refactored so every high-
  level op (`load_file`, `list_table`, `list_counters`,
  `list_set_elements`, `add/delete_set_element`, `cmd`)
  goes through a single `_run_text` helper that prefers
  libnftables and falls back to subprocess only when the
  library is absent or `setns()` fails. A new
  `_in_netns(name)` contextmanager saves
  `/proc/self/ns/net`, opens `/run/netns/<name>`, calls
  `setns(CLONE_NEWNET)`, yields, and restores the original
  namespace on exit so the process stays hot between
  successive nft calls in a target namespace.
- `verify/netns_topology.py::exec_in_ns` drops the
  `ip netns exec` wrapper in favour of a `preexec_fn` that
  `setns()`s the child right after fork and before exec.
  One fewer fork, no iproute2 binary dependency.
- `verify/simulate.py::_ns` and `_kill_ns_pids` get the same
  treatment. `_kill_ns_pids` also stops shelling out to
  `ip netns pids` and walks `/proc/*/ns/net` inodes directly.

### Documentation

- `docs/cli/override-json.md` — full structured-io plan
  (input + output + schema + load order + seams).
- `docs/testing/point-of-truth.md` — conflict resolution
  ranking when verifiers disagree. `old/iptables.txt` wins,
  simlab is the weakest signal.
- `docs/concepts/marks-and-connmark.md` — modern reference
  for packet mark / ct mark / ct zone: mental model,
  lifecycle, tooling (nft/ip/tc/conntrackd), masking,
  save/restore, seven practical patterns, 8-point pitfall
  list. Replaces the legacy `PacketMarking.md` for new
  content.
- `docs/concepts/security-defaults.md` — opinionated modern
  baseline for shorewall.conf, sysctl floor, kernel module
  matrix, logging, and what we deliberately don't enable
  by default. Copy-paste deployment checklist.
- `docs/concepts/dynamic-routing.md` — bird/FRR/keepalived
  integration on a shorewall-nft edge. Firewall rules the
  routing stack needs, ECMP merge_paths vs conntrack
  lock-in, HA failover dance, seven common pitfalls.
- `docs/concepts/naming-and-layout.md` — meta-chapter on
  zone/interface/chain/set/mark/param/file naming
  conventions, `/etc/shorewall46` layout, 13 extension
  scripts, and the 6-point naming bootstrap for new
  deployments.
- `docs/concepts/multipath-and-ecmp.md` — deep dive on
  classic ECMP, nexthop objects, per-provider tables,
  hash policy, metric layout, five failure modes, and
  monitoring checklist.

### routestopped — full Shorewall semantics + standalone table

- routestopped used to be parser-only — the IR built chains nobody
  ever rendered or loaded. The runtime path is now wired end to
  end. `_process_routestopped` populates a dedicated
  `ir.stopped_chains` dict (kept apart from `ir.chains` so the
  main emitter can never mix it into the running ruleset), and
  `nft/emitter.emit_stopped_nft` renders a standalone
  `inet shorewall_stopped` table that loads independently.
- `shorewall-nft stop` compiles the config, deletes the running
  `inet shorewall` table, and loads `inet shorewall_stopped`
  if routestopped is configured. `start` tears down any
  leftover `shorewall_stopped` table so the two rulesets never
  run side by side.
- OPTIONS column parser supports `routeback`, `source`, `dest`,
  `critical`, `notrack`. SPORT column (cols[5]) honoured.
  IPv6 hosts auto-route to `ip6 saddr/daddr`. Global setting
  `ROUTESTOPPED_OPEN=Yes` collapses every listed interface to a
  wildcard accept (host/proto filtering ignored), matching
  Shorewall's "panic mode" behaviour.
- 11 new pytest cases under `TestRoutestopped` cover each
  option, SPORT, IPv6 saddr/daddr selection, the
  ROUTESTOPPED_OPEN collapsing path, and the critical no-op.

### simlab — first 100 % green archived run

- Emitter: zone-pair dispatch jumps now carry a
  `meta nfproto ipv4|ipv6` qualifier when either side is a
  single-family zone (e.g. an IPv6-only zone in a merged
  shorewall46 config). Pairs with conflicting families are
  skipped — they were the cause of every IPv4 probe falling
  into a v6-only chain whose terminal sw_Reject dropped them.
- Compiler: `_add_rule` now extends the existing ACCEPT/policy=
  ACCEPT dedup to DROP/REJECT verdicts. A rule like
  `DROP:$LOG customer-a any` in `rules` used to expand into every
  customer-a→X chain as an inline catch-all drop, and when file order
  put it before later `all → X:host` accept expansions the
  inline drop landed mid-chain and shadowed every accept that
  followed. The iptables backend never inlines these — it
  relies on the chain's policy at the tail. The shorewall-nft
  compiler now mirrors that behaviour.
- simlab autorepair: `_build_zone_to_concrete_src` collects every
  IP the firewall owns across every interface (not just the
  iterated address) and walks candidate hosts from the high end
  downwards. The previous picker landed on fw-local secondary
  IPs that the kernel rejected as a martian source before any
  rule evaluated. Random-probe generator gets the same
  treatment in `oracle.RandomProbeGenerator._pick_host`.
- simlab oracle: chain fall-through is now classified as DROP
  (matching Shorewall's policy chain at the chain tail)
  instead of UNKNOWN. Removes a long tail of false-positive
  random-probe mismatches.
- packets: injector default `src_mac` aligned to the
  controller's synthetic worker MAC so the kernel's neighbour
  cache stays consistent and forwarded probes don't get
  silently dropped as stale neighbour-table updates.

### Measured on the reference HA firewall

- 353 pytest tests green on the grml test host (35 skipped).
- Triangle verify with `OPTIMIZE=8 + OPTIMIZE_VMAP=Yes +
  CT_ZONE_TAG=Yes + FLOWTABLE=bond1,bond0.20`:
  - IPv4: 100.0 % rule coverage (8282/8284), 239/241 zone pairs
  - IPv6:  99.6 % rule coverage (3297/3310), 210/213 zone pairs
- simlab full run, archived under
  `docs/testing/simlab-reports/20260411T150507Z/`:
  - POSITIVE: 626 / 626 ok = 100.0 %, fail_drop=0, fail_accept=0
  - RANDOM:    64 /  64 ok = 100.0 %, fail_drop=0, fail_accept=0
  - 0 unknowns, 0 errors, ~0.9 s probe run, ~6 s end-to-end
- Remaining triangle fails are 2 stale-baseline misses (rules
  commented out in the current config but still present in the
  older iptables-save used as ground truth) and 1 benign order
  conflict — neither is a release blocker.

## [1.0.0] — 2026-04-11

First stable release.

### Added

- GPL-2.0 LICENSE, CONTRIBUTING, SECURITY, pre-commit config
- GitHub Actions CI: unit tests on Python 3.11/3.12/3.13, lint
  (ruff + shellcheck), wheel build, Debian package build, Fedora
  RPM package build, integration tests in netns
- Generic dual-stack sample fixture under `tests/fixtures/sample-fw/`
  using RFC 5737 and RFC 3849 documentation prefixes
- Network namespace route/sysctl detection tests
- Debian (`packaging/debian/`) and RPM (`packaging/rpm/`) packaging
- Shell completions (bash/zsh/fish) and a groff-checked man page
- systemd service units with legacy-shorewall conflict declarations

### Changed

- Single-binary Debian package (the `-tests` and `-doc` subpackages
  were dropped in favour of a simpler layout)
- All customer-identifying references sanitised: tests, docs, fixtures
  and examples now use RFC 5737/3849 documentation prefixes and
  generic names. Real Netbox API token removed from example config.
- CI triggers on `main` (was only `master`/`shorewall-next`)
- Relaxed `pyroute2 >= 0.7` for wider distro compatibility

### Fixed

- Comma-separated zone lists in `SOURCE` and `DEST` columns
  (`linux,vpn-voice`, `loc,dmz`) now expand correctly
- Bridge port spec `br1:bond0.115` in interfaces file: the port
  name is used as the kernel iface, not the bridge name
- Protocol column normalised to lowercase (accepts `TCP`, `UDP`)
- `~MAC` filter syntax in rules now emits `ether saddr` instead
  of `ip saddr`
- Extra named ports recognised: jetdirect (9100), iec-104, modbus,
  mms, dnp3, bacnet, opcua
- `shorewall-nft debug` restore no longer flushes the entire
  ruleset; only the `inet shorewall` table is touched
- Debug SIGTERM signal propagation through the `sudo → run-netns →
  ip netns exec` chain made robust via process-group signalling
- Test file I001/F401/F541 ruff cleanups across `tests/`

## [0.11.0] — 2026-04-11

### Added

#### Explicit config-directory override flags

All 13 commands that take a config directory (`start`, `restart`,
`reload`, `check`, `compile`, `verify`, `debug`, `migrate`, `simulate`,
`load-sets`, `generate-set-loader`, `generate-sysctl`, `generate-tc`)
now accept five new flags for full control over the configuration
source. Previously only the v4 dir could be overridden via positional
argument, and the v6 sibling was always auto-detected.

Six distinct modes are now supported:

| Mode | CLI |
|------|-----|
| Auto (default) | `shorewall-nft start` |
| Explicit merged | `shorewall-nft start -c /srv/merged` |
| Legacy dual auto-sibling | `shorewall-nft start /srv/v4` or `--config-dir4 /srv/v4` |
| Legacy dual explicit | `shorewall-nft start --config-dir4 /srv/v4 --config6-dir /srv/v6` |
| v4-only | `shorewall-nft start --config-dir4 /srv/v4 --no-auto-v6` |
| v6-only | `shorewall-nft start --config6-dir /srv/v6 --no-auto-v4` |

New flags: `-c`/`--config-dir`, `--config-dir4`, `--config6-dir`,
`--no-auto-v4`, `--no-auto-v6`.

- `load_config(..., skip_sibling_merge=True)` parser parameter to
  explicitly disable v6 sibling auto-detection.
- `_derive_v4_sibling(v6_dir)` symmetric helper for v6→v4 sibling lookup.
- 15 new resolver tests in `tests/test_cli_config_flags.py`.

#### UX improvements

- **`shorewall-nft lookup --json`** — emit pure JSON on stdout, even
  for error paths. Useful for shell scripting and machine-readable
  pipelines.

- **`shorewall-nft enrich --dry-run`** — preview plugin enrichment
  changes as a unified diff without touching disk or creating backups.

- **`shorewall-nft debug --trace NFT_MATCH`** — auto-install a
  `meta nftrace set 1` rule in the input chain for the given nft match
  expression (e.g. `--trace "ip saddr 1.2.3.4"` or
  `--trace "meta l4proto icmp"`). The filter is removed automatically
  when debug mode exits (via the ruleset flush in `_restore_and_exit`).
  Removes the boilerplate of manually inserting/removing trace rules.

- **`shorewall-nft merge-config <v4>`** (single argument) — v6 sibling
  is auto-detected by appending `6` to the v4 dir name. Errors out if
  the sibling doesn't exist. Matches the symmetry of the new start-time
  flags. Passing both directories explicitly still works.

#### Documentation

- `docs/shorewall-nft/config-dirs.md` — full reference for the 6
  config-resolution modes and all override flags, with examples and
  conflict cases.
- `docs/shorewall-nft/plugin-development.md` — complete walkthrough
  for writing custom plugins: skeleton, hooks, priority conventions,
  lifecycle, testing patterns, error handling, a full GeoIP example
  plugin, and packaging guidance.

### Tests

- 236 tests total (up from 221)
- 15 new resolver tests in `tests/test_cli_config_flags.py`


## [0.10.0] — 2026-04-11

First release cut of the `shorewall-next` branch after the plugin
system, optimizer, debug mode, merge-config, and config drift work.

### ⚠️ Backward-incompatible changes

- **`/etc/shorewall46` precedence** — when `/etc/shorewall46` exists,
  it is used as the default config directory by every `shorewall-nft`
  command, overriding `/etc/shorewall`. Pass an explicit directory
  argument to force the legacy path. Existing automation that runs
  `shorewall-nft start` without a path may silently switch source.
  This matches the "merge-config is point of truth" decision.

- **`?FAMILY` preprocessor directive** — merged `/etc/shorewall46`
  files contain a shorewall-nft-specific `?FAMILY ipv4|ipv6|any`
  directive. Feeding a merged config through stock upstream Shorewall
  will fail. Merged configs are consumable only by shorewall-nft.

### Added

#### Plugin system

- New `shorewall_nft.plugins` package with base classes, manager, and
  priority-ordered hook dispatch.
- Built-in **`ip-info`** plugin: pattern-based IPv4↔IPv6 mapping per
  `/24` subnet (fallback when no authoritative source is available).
- Built-in **`netbox`** plugin: live Netbox IPAM API + local TTL cache,
  with snapshot mode for offline/CI use. Links v4 and v6 addresses via
  shared `dns_name`. Extracts customer numbers from
  `"NNNNNN - Company Name"` tenant format.
- New CLI commands: `lookup`, `enrich`, `plugins list`.
- Plugins register their own CLI subgroups (`ip-info`, `netbox`).
- TOML-based configuration in `etc/shorewall/plugins.conf` and
  `plugins/<name>.toml`.
- Transitive variable rewriting: merge-config now detects v4/v6 params
  whose values depend on renamed variables and renames them too
  (e.g. `ALL_DC=$DC1,$DC2` becomes `ALL_DC_V6` when `DC1/DC2` are
  paired).

#### merge-config

- New default output directory `/etc/shorewall46` (no `-o` required).
- Smart `?COMMENT`-block merging: same mandant tags in v4 and v6 are
  combined inside one block with v6 rules wrapped in `?FAMILY ipv6`.
- `_merge_interfaces` handles v6-only interfaces (e.g. IPv6-only
  physical links that don't exist in the v4 config).
- `--guided` mode: interactive collision resolution for params, zones,
  policies, shorewall.conf, rule blocks — with 4 choices (keep v4,
  keep v6, merge proposal, custom input).
- `--no-plugins` flag to disable plugin enrichment for a single run.
- Plugin enrichment: `?COMMENT` blocks get customer/host annotations,
  paired params are explicitly grouped instead of silently renamed.

#### Optimizer (OPTIMIZE levels)

- **Level 3 reworked**: only ACCEPT-policy empty chains are removed;
  DROP-policy empties are kept so removing them doesn't silently open
  the firewall.
- **Level 4**: combine adjacent rules differing in one field
  (saddr/daddr/sport/dport/iifname/oifname) into a single rule with an
  anonymous set.
- **Level 8**: merge chains with identical content, replacing
  duplicates with a single `jump canonical` stub.
- ipset references (`+name`) and named sets (`@name`) are correctly
  excluded from combining.

Measured production reduction:

| Config | OPTIMIZE=0 | OPTIMIZE=8 | Reduction |
|--------|------------|------------|-----------|
| fw-large  | 18366 lines | 12806 lines | **30%** |
| fw-medium | 12075 lines |  7598 lines | **37%** |
| fw-small  |   625 lines |   546 lines | **12%** |

#### Debug mode

- New **`shorewall-nft debug`** command: compiles with debug
  annotations, saves current ruleset, loads the debug ruleset, and
  restores on `Ctrl+C`.
- Every rule in debug mode gets:
  - A **named counter** (`r_<chain>_<idx>`) queryable via
    `nft list counter inet shorewall <name>`.
  - A **source-location comment** visible in `nft monitor trace`:
    `"rules:38: OrgAdmin/ACCEPT net $FW [mandant-b] {rate=3/min}"`
    showing file, line, trimmed original rule, mandant tag, and meta
    info (rate/connlimit/time/user/mark).
- Counter declarations are injected at the top of the table.

#### Config hash drift detection

- Every emitted nft ruleset embeds a sha256 hash of its source config
  as a table comment (`comment "config-hash:<16-hex>"`).
- `shorewall-nft status` compares the loaded hash against the current
  on-disk hash and warns on drift with a clear DRIFT banner.
- `shorewall-nft debug` requires **explicit confirmation** when the
  loaded ruleset hash doesn't match on-disk — entering debug mode is a
  reload and would replace production traffic handling.
- Debug marker (`config-hash:<hex> debug`) lets `status` distinguish
  debug from production rulesets.

#### Documentation

- Full MkDocs Material documentation site under `docs/`.
- Upstream Shorewall docs converted from DocBook XML to Markdown via
  pandoc (118 files), categorized into `concepts/`, `features/`,
  `reference/`, `legacy/`.
- shorewall-nft specific docs: `plugins.md`, `optimizer.md`,
  `debug.md`, `merge-config.md`, `config-hash.md`.
- Machine-readable catalogs:
  - `docs/reference/features.json` — nft feature catalog from
    `explain.py`
  - `docs/reference/commands.json` — CLI reference from click
    introspection
- `mkdocs.yml` with Material theme and full navigation tree.

#### Explain command

- `explain-nft-features` learned a new `Performance` category with
  the full optimizer documentation.
- IPv6 extended mask examples expanded with the
  `::host_bits/::ffff:ffff:ffff:ffff` syntax.
- Complex NAT examples: netmap, symmetric bidirectional NAT,
  port-range DNAT, multi-address SNAT.

### Changed

- **149 standard Shorewall macros** are now vendored inside the package
  at `shorewall_nft/data/macros/` and shipped via the wheel
  (`package-data` in `pyproject.toml`). Previously they were loaded
  from a sibling `Shorewall/Macros/` source checkout.
- `_load_standard_macros()` prefers the bundled copy; falls back to
  `/usr/share/shorewall/Macros` on systems with upstream Shorewall
  installed.
- All shorewall-nft test/probe network namespaces now use the
  `shorewall-next-sim-*` prefix (previously `swnft-*`) for consistency
  across projects.
- Debug comments now include the **trimmed original source rule**, not
  just `file:line`.

### Fixed

- v6 rules inside merged `?COMMENT` blocks were previously appended
  *after* the closing tag, losing their tag scope. They are now
  inserted before the closing `?COMMENT`.
- Merged config `interfaces` file was copied verbatim from v4; v6-only
  interfaces (e.g. `eth4` only in `shorewall6/interfaces`) were lost.
- v6 rules that reference `$ORG_PFX` (or any variable renamed with
  the `_V6` suffix) are now automatically rewritten to
  `$ORG_PFX_V6` so they resolve to the v6 value.
- Transitive rewriting handles chains of derived variables like
  `ALL_DC=$DC1,$DC2` correctly.
- Debug mode `_restore_and_exit` flush command constructed the nft
  argument list correctly (previous bug put the binary path twice).
- Parser no longer auto-merges a sibling `shorewall6` directory when
  loading a directory whose name ends in `46` (already pre-merged).

### Removed

- Upstream Shorewall source tree (~4.6 MB): `Shorewall/`, `Shorewall6/`,
  `Shorewall6-lite/`, `Shorewall-core/`, `Shorewall-init/`,
  `Shorewall-lite/`. These Perl/shell sources were reference material
  that is no longer needed — shorewall-nft has its own Python
  implementation.
- `docs/` upstream DocBook XMLs (36 MB), replaced with their Markdown
  equivalents (2.4 MB).
- Historical `TODO.md` (all items were implemented; git history
  preserves the file).
- Broken `release/` symlink to a non-existent directory.

### Security

- Debug mode temp files are created with `prefix="shorewall-next-sim-debug-"`
  in `$TMPDIR`; the path is printed so operators can manually restore
  if the signal handler fails. No sensitive data other than the
  already-loaded ruleset is written.
- Netbox plugin API token is read plaintext from `plugins/netbox.toml`;
  operators are advised to `chmod 600` the file or use the
  `token_file = "/path/to/token"` indirection.

### Tests

- Total: **221 tests** (up from 179).
- New test files:
  - `tests/test_optimize.py` — 30 tests for the 5 optimizer passes
  - `tests/test_plugins.py` — 27 tests for the plugin base + manager +
    ip-info
  - `tests/test_netbox_plugin.py` — 16 tests for the netbox plugin
    (cache, lookups, snapshot mode, tenant parsing)
  - `tests/test_config_hash.py` — 12 tests for hash computation and
    drift markers
  - `tests/test_config_resolution.py` — 6 tests for `/etc/shorewall46`
    precedence and parser auto-merge skipping

### Known issues

- Some production configs contain zone names with a comma
  (`linux,vpn-voice`) that produced an invalid nft chain name.
  Handled by the 0.12.0 comma-expansion fix in ir.py.
- Plugin-specific CLI subcommands (`ip-info`, `netbox`) are only
  registered when the default config directory contains a
  `plugins.conf`. Passing `-c <dir>` to plugin subcommands is not yet
  supported at module load time.

## [0.9.1] — earlier

See git history for pre-0.10.0 changes. Key milestones:

- 0.9.1: `explain-nft-features` command with Shorewall config syntax
- 0.9.0: initial shorewall-next release with 100% rule coverage against
  3 production firewalls
- Triangle verifier, 3-netns packet simulator, scapy-based connstate
  tests, capability detection, netlink integration, migration tool
