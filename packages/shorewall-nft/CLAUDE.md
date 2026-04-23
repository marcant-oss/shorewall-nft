# CLAUDE.md — shorewall-nft (core)

Compiler + emitter + config parser + runtime CLI.
Python package: `shorewall_nft`. Entry point: `shorewall-nft`.

**Development: use the repo-root venv at `../../.venv/` (Python 3.13).**
No per-package venv. See root `CLAUDE.md` for bootstrap.

## Key directories

- `shorewall_nft/compiler/` — config → IR:
  - `ir/` — IR package (was a single 3427-LOC `ir.py` until April 2026):
    - `__init__.py` — `build_ir()` orchestrator + re-exports
    - `_data.py` — enums, dataclasses (Rule/Chain/FirewallIR/Match/…),
      pure helpers (`is_ipv6_spec`, `split_nft_zone_pair`, …)
    - `spec_rewrite.py` — token rewriters (`expand_line_for_tokens`,
      `_rewrite_dns_spec`, `_rewrite_nfset_spec`, …)
    - `rules.py` — macro expansion, `_add_rule`, zone-pair builder
    - `_build.py` — per-table `_process_*` stages
  - `verdicts.py` — typed discriminated union for `Rule.verdict_args`
    (17 variants — Snat/Dnat/Masquerade/Redirect/Notrack/CtHelper/
    Mark/…). Replaces the old `"prefix:target"` string wire format.
  - `optimize.py`, `actions.py`, `proxyarp.py`, `nat.py`, `tc.py`,
    `accounting.py`, `docker.py`, `tunnels.py`, `macfilter.py`,
    `providers.py`, `sysctl.py` (sysctl-script generator, was in
    `runtime/`).
- `shorewall_nft/nft/` — IR → nft script emitter (`emitter.py`),
  flowtable, sets, capabilities probe (`capabilities.py`), capability
  check (`capability_check.py`, was in `compiler/`), explain engine,
  netlink glue (`netlink.py` — `in_netns` is the public netns context
  helper), DNS sets API (`dns_sets.py`).
- `shorewall_nft/config/` — config file parser (`parser.py`),
  importer (`importer.py`), schema consistency.
- `shorewall_nft/runtime/` — runtime helpers + CLI:
  - `cli/` — CLI package (was a single 2929-LOC `cli.py` until April 2026):
    - `__init__.py` — root `@click.group` + command registration
    - `_common.py` — shared helpers (config resolution, compile pipeline,
      shorewalld notify, seed handshake, progress reporting)
    - `apply_cmds.py` — start/stop/restart/reload/clear/status/check/
      compile/save/restore/show+aliases/reset/load-sets/apply-tc
    - `config_cmds.py` — `config` group (export/import/template/merge)
      + flat `merge-config`
    - `debug_cmds.py` — verify/trace/debug/counters/migrate/simulate/
      capabilities/explain-nft-features/blacklist commands
    - `generate_cmds.py` — generate-systemd/generate-tc/
      generate-conntrackd/generate-sysctl/generate-set-loader
    - `plugin_cmds.py` — plugins/lookup/enrich +
      `_register_plugin_commands` dynamic registration
  - `monitor.py`, `seed.py`, `conntrackd.py`, `topology.py`.
- `shorewall_nft/verify/` — post-compile verification:
  - `triangle.py` — static rule-coverage fingerprint vs iptables-save
  - `simulate.py` — 3-namespace veth test topology + per-pair packet
    probes. Used by `connstate.py` and the `shorewall-nft simulate`
    CLI. Long-term internal: simlab uses a different architecture
    (TUN/TAP + asyncio + live-dump replay) and currently has no
    `(config_dir, iptables_dump)` entry point that could replace
    this module. Do not add new callers; consider simlab first for
    new validation work.
  - `constants.py` — shared NS_FW/NS_SRC/NS_DST/DEFAULT_SRC names
    used by simulate.py and its peer validators.
  - `iptables_parser.py`, `connstate.py` — shared by simlab (public API).
  - `tc_validate.py` — uses `shorewall_nft_netkit.netns_shell.run_shell_in_netns`
    for shell-in-netns probes (no longer importing simulate's private `_ns`).
- `shorewall_nft/plugins/` — plugin loader + `builtin/` plugins. Loader
  also discovers third-party plugins via `importlib.metadata` entry
  points under group `shorewall_nft.plugins`.
- `shorewall_nft/netns/` — netns helper wrappers.
- `shorewall_nft/tools/` — `merge_config.py`, `migrate.py`.
- `tests/` — pytest:
  - `test_emitter_features.py` covers 1.1-era knobs (flowtable,
    vmap dispatch, ct zone tag, concat-map DNAT, ct mask)
  - `golden/` — snapshot suite (6 cases: minimal, fastaccept_no,
    ipv6_basic, nat_dnat, vmap_dispatch, complex). Regenerate with
    `UPDATE_GOLDEN=1 pytest tests/golden/`.
  - `verify/` — direct unit tests for connstate, iptables_parser,
    netns_topology, tc_validate, slave_worker (no netns required).
  - `fixtures/ref-ha-minimal/` — anonymised three-zone fixture used
    when `SHOREWALL_NFT_PROD_DIR` is unset (RFC 5737/3849 addresses).

## Release-blocker invariants

Release mechanics (version bump sync, tag, CHANGELOG) live in the root
`CLAUDE.md`. Shorewall-nft-specific things that must hold at every tag:

- **`/etc/shorewall46` precedence** — when both `/etc/shorewall` and
  `/etc/shorewall46` exist, the latter wins. Backward-incompatible with
  classic Shorewall; worth a release-notes line every time.
- **`?FAMILY` directive** — shorewall-nft extension; a merged
  `/etc/shorewall46` config will crash stock upstream Shorewall.
- **Examples in sync** — `examples/plugins/` matches `plugins/builtin/*.py`.
- **`generate-systemd --netns`** honours `/etc/shorewall46` as default.
- **Wheel contents** — `python -m build` wheel must include
  `plugins/builtin/` and `data/macros/`.
- **Man page `.TH` version strings** — `tools/man/*.8` and `tools/man/*.5`
  must have their `.TH` date and version updated to match the new release.

Deeper open items (not release-blockers):

- Debug-mode edge cases: fresh netns with no loaded ruleset during
  `debug` save → restore; SIGINT during `apply_nft`; unrelated tables
  (docker, fail2ban) in the save file.

## Packaging deps

Source of truth: `docs/reference/dependencies.md`. Tests run as root via
`tools/run-tests.sh` (unshare --mount --net — no sudoers, no
`netns-test` group, no helper binary).

## Open items (compiler/emitter)

- **3-firewall config-merge replay** — re-emit merged `/etc/shorewall46`
  with consistent column widths, zone-pair grouping, catch-all DROP at
  bottom, per-rule `?COMMENT` provenance markers. Requires `@host`
  directive support in parser first.

## Debug lessons (do not re-learn these)

- **If `nft monitor trace` shows nothing** — cause is routing / RPF /
  ARP, not firewall rules. nft trace only sees packets in the matching
  table.
- **FASTACCEPT=No** requires the emitter to put
  `ct state established,related accept` inside every zone-pair chain,
  not at the top of the base forward chain. The 1.1 emitter did this
  wrong — fix in commit `7e977f70e`.
- **CT mask emit** — cannot use `ct mark and C or iifname map {…}`.
  nft rejects `or` with a map on the right. Use per-iface rules:
  `iifname "bond1" ct mark set ct mark and INV or ZONE`.
- **Triangle verifier** skips "pure ct state" rules — a missing
  `established accept` shows up as 100 % coverage (misleading). Use
  simlab for packet-level validation of stateful paths.
- **Base chain architecture** — base chains (input/forward/output)
  must have `policy drop` and contain **only** FASTACCEPT (if enabled),
  NDP accept (input/output), and dispatch jumps. `ct state invalid
  drop` and `dropNotSyn` belong in zone-pair chains, not base chains.
  Putting ct state checks before dispatch kills IPv6 forwarding
  because conntrack may not track NDP-dependent flows correctly.
  Fixed in commit `eaff8dbad`.
- **Dispatch rule ordering** — zones without interface assignments
  (e.g. `rsr ipv6`) produce dispatch rules without `oifname`.
  These catch-all rules must be emitted **after** specific zone-pair
  rules, otherwise they swallow all IPv6 traffic into the wrong
  chain. The emitter sorts by interface specificity. Fixed in
  commit `e16d76031`.
- **Dual-stack zone merge** — when merging shorewall + shorewall6,
  zones in both configs must be promoted from `ipv4` to `ip`.
  Otherwise all dispatch rules get `meta nfproto ipv4` and IPv6
  traffic is never dispatched. Applies to both `_merge_configs()`
  in `parser.py` and `_merge_zones()` in `merge_config.py`.
  Fixed in commits `d5720c4a7` and `eaff8dbad`.
- **raw chains must not dispatch** — `raw-output` (priority -300) is
  for NOTRACK rules only. If the emitter adds zone-pair dispatch
  jumps to raw chains, NDP gets routed into chains with
  `ct state invalid drop` before the normal output chain can
  accept it. Fixed in commit `d5720c4a7`.
- **Implicit loopback accept** — classic Shorewall emits
  `-A INPUT -i lo -j ACCEPT` / `-A OUTPUT -o lo -j ACCEPT`
  unconditionally; shorewall-nft must mirror this on the running
  ruleset (not only the stopped chains). Without it, local services
  on `lo` (pdns-recursor on `127.0.0.1`, Anycast IPs on `lo`,
  firewall-originated mgmt) require an explicit `$FW $FW ACCEPT`
  policy or they hit `policy drop`. Emitted in `_create_base_chains`
  after FASTACCEPT and before NDP.
