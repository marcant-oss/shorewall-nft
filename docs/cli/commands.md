---
title: CLI command reference
description: All `shorewall-nft` subcommands with their options and arguments.
---

# CLI command reference

`shorewall-nft` v1.10.0 has subcommands spanning lifecycle, inspection, verification, generators, and structured config I/O.
Auto-generated from the CLI definition — a machine-readable
version is in [`reference/commands.json`](../reference/commands.json).

## Lifecycle

### `start`

Compile and apply firewall rules (like shorewall start).

```
shorewall-nft start [directory] [--netns <value>] [--shorewalld-socket PATH] [--instance-name NAME] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Network namespace name.
- **`--shorewalld-socket`** — Path to the shorewalld control socket
  (env `SHOREWALLD_SOCKET`, default `/run/shorewalld/control.sock`).
  After applying the ruleset, `start` sends a `register-instance`
  message so shorewalld picks up the updated `dnsnames.compiled`
  immediately (no reload hook required).
- **`--instance-name`** — Override the shorewalld instance name (env
  `SHOREWALLD_INSTANCE_NAME`). Default precedence: `INSTANCE_NAME`
  from `shorewall.conf` → `--netns` value → config directory basename.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### Progress output

`start` reports each phase. On a TTY the current step is overwritten
in-place with ANSI colour; piped or under systemd the same text is
emitted as plain lines suitable for journald:

```
[1/5] Parsing and compiling config …        ✓
[2/5] Probing kernel capabilities …         ⚠  (warnings logged; never aborts)
[3/5] Applying ruleset …                    ✓
[4/5] Configuring proxy-ARP / NDP …         ✓
[5/5] Cleaning up stopped-firewall table …  ✓
Firewall started.
```

Capability warnings in step 2 are **non-fatal** — they are collected
and shown, but `start` continues. Step 3 (`apply_nft`) is the
authoritative gate: if the kernel rejects a rule, that step fails with
a ✗ and the command exits non-zero. This means capability probing never
aborts a `start` that would otherwise succeed on the running kernel.

### `stop`

Stop the firewall (remove all rules).

```
shorewall-nft stop [--netns <value>] [--shorewalld-socket PATH] [--instance-name NAME]
```

- **`--netns`** — Network namespace name.
- **`--shorewalld-socket`** — Path to the shorewalld control socket
  (env `SHOREWALLD_SOCKET`). `stop` sends a `deregister-instance`
  message after removing the `inet shorewall` table. Deregistration
  failures are always non-fatal (socket down, daemon not running,
  etc.); the daemon will age entries out via their per-element TTL.
- **`--instance-name`** — Override the shorewalld instance name (env
  `SHOREWALLD_INSTANCE_NAME`). Must match the name used during
  `start`; precedence is the same (`INSTANCE_NAME` from `shorewall.conf`
  → netns → config dir basename).

### `restart`

Recompile and atomically replace the ruleset. Also rewrites
`dnsnames.compiled` and re-registers the instance with shorewalld.

```
shorewall-nft restart [directory] [--netns <value>] [--shorewalld-socket PATH] [--instance-name NAME] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Network namespace name.
- **`--shorewalld-socket`** — See `start`.
- **`--instance-name`** — See `start`.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `reload`

Reload rules (same as restart for nft — atomic replace). Also rewrites
`dnsnames.compiled` and re-registers the instance with shorewalld.

```
shorewall-nft reload [directory] [--netns <value>] [--shorewalld-socket PATH] [--instance-name NAME] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Network namespace name.
- **`--shorewalld-socket`** — See `start`.
- **`--instance-name`** — See `start`.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### How to verify success

Exit code 0 and `Firewall reloaded.` on stdout. Confirm with
`shorewall-nft status` — it should show the running table and a fresh
config-hash with no drift warning. The replacement is atomic at the nft
level so no packets are dropped between the old and new rulesets.

### `status`

Show firewall status.

```
shorewall-nft status [--netns <value>]
```

- **`--netns`** — Network namespace name.

### `clear`

Clear all firewall rules (accept all traffic).

```
shorewall-nft clear [--netns <value>]
```

- **`--netns`** — Network namespace name.

### `save`

Save current ruleset (like shorewall save).

```
shorewall-nft save [filename] [--counters] [--netns <value>]
```

- **`--counters`** — Include counters in the saved ruleset.
- **`--netns`** — Network namespace name.

### `restore`

Restore a saved ruleset (like shorewall restore).

```
shorewall-nft restore <filename> [--netns <value>]
```

- **`--netns`** — Network namespace name.

### `check`

Validate config without applying (like shorewall check).

```
shorewall-nft check [directory] [--skip-caps] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--skip-caps`** — Skip capability check.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### How to verify success

Exit code 0 and no output to stderr. On error the command exits 1 and prints the
failing file, line number, and a short reason. Use `--skip-caps` in containers or
CI environments without a live nftables instance to isolate config-parse errors
from capability-probe failures.

### `compile`

Compile config to nft script (like shorewall compile).

```
shorewall-nft compile [directory] [-o <value>] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-o, --output`** — Write the nft script to FILE instead of stdout.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### How to verify success

Exit code 0. The output is a valid nft script (begins with `#!/usr/sbin/nft -f`).
Confirm with `shorewall-nft compile | nft -c -f -` (dry-run syntax check) — any
kernel-rejected rule produces exit code 1 from nft.

## Inspection

### `show`

Show firewall info (like shorewall show). Subcommands: zones, policies, config, connections.

```
shorewall-nft show [what] [-x] [--netns <value>]
```

- **`-x`** — Show exact counters.
- **`--netns`** — Network namespace name.

### `counters`

List all counter values (packets/bytes).

```
shorewall-nft counters [--netns <value>]
```

- **`--netns`** — Network namespace name.

### `reset`

Reset counters (like shorewall reset).

```
shorewall-nft reset [chains] [--netns <value>]
```

- **`--netns`** — Network namespace name.

## Dynamic blacklist

### `drop`

Dynamically drop traffic from addresses (like shorewall drop).

```
shorewall-nft drop <addresses> [--netns <value>]
```

- **`--netns`** — Network namespace name.

### `blacklist`

Add address to dynamic blacklist with timeout (like shorewall blacklist).

```
shorewall-nft blacklist <address> [-t <value>] [--netns <value>]
```

- **`-t, --timeout`** — Timeout (e.g. 1h, 30m, 1d).
- **`--netns`** — Network namespace name.

### `reject`

Dynamically reject traffic from addresses (like shorewall reject).

```
shorewall-nft reject <addresses> [--netns <value>]
```

- **`--netns`** — Network namespace name.

### `allow`

Remove addresses from the blacklist (like shorewall allow).

```
shorewall-nft allow <addresses> [--netns <value>]
```

- **`--netns`** — Network namespace name.

## Capabilities & features

### `capabilities`

Detect nftables capabilities of the running kernel.

```
shorewall-nft capabilities [--netns <value>] [--json]
```

- **`--netns`** — Network namespace name.
- **`--json`** — Output as JSON.

### `explain-nft-features`

Show nft features with syntax examples and availability.

```
shorewall-nft explain-nft-features [--probe] [--category <value>] [--json]
```

- **`--probe`** — Probe kernel for feature availability.
- **`--category`** — Filter by category (e.g. 'Sets', 'NAT', 'IPv6').
- **`--json`** — Output as JSON.

## Verification

### `verify`

Verify compiled output against iptables baseline.

```
shorewall-nft verify [directory] [--iptables <value>] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--iptables`** — Path to iptables-save dump (ground truth).
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### How to verify success

Exit code 0 and a summary line showing 0 mismatches. On mismatch the
command exits 1 and prints each differing chain with the iptables rule that
was not found in the nft output. The triangle verifier skips rules that are
pure `ct state` checks (false coverage is expected); use `simulate` for
packet-level coverage of stateful paths.

### `simulate`

Run packet-level simulation in 3 network namespaces.

```
shorewall-nft simulate [directory] [--iptables <value>] [--ip6tables <value>] [--target <value>] [--targets <value>] [--targets-v6 <value>] [--src-iface <value>] [--dst-iface <value>] [--all-zones] [--max-tests <value>] [--seed <value>] [-v] [--parallel <value>] [--no-trace] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--iptables`** — iptables-save dump (ground truth). Required.
- **`--ip6tables`** — ip6tables-save dump for IPv6 tests.
- **`--target`** — Single target IP for tests (default: 203.0.113.5).
- **`--targets`** — Comma-separated list of target IPs, or `@FILE` with one IP per line. Bypasses `--target`; all targets share a single netns topology.
- **`--targets-v6`** — Comma-separated list or `@FILE` of IPv6 target addresses. Requires `--ip6tables`.
- **`--src-iface`** — Override the source-zone interface name in the firewall netns (default: `bond1`).
- **`--dst-iface`** — Override the destination-zone interface name in the firewall netns (default: `bond0.20`).
- **`--all-zones`** — Multi-zone topology: create one veth pair per zone and derive test cases across every `<src>→<dst>` chain in the iptables dump.
- **`--max-tests, -n`** — Max test cases per target.
- **`--seed`** — Random seed for sampling.
- **`-v, --verbose`** — Show all test results.
- **`--parallel, -j`** — Parallel test threads.
- **`--no-trace`** — Disable nft trace logging.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### How to verify success

Exit code 0 and a summary with `fail_drops=0  fail_accepts=0`. On mismatch the
command exits 1 and reports each category separately: `fail_drops` are packets
the iptables baseline accepted but the nft ruleset dropped (potential
false-negatives); `fail_accepts` are packets the baseline dropped but nft
accepted (potential false-positives). A non-zero mismatch count does not
indicate a bug by itself — random-probe results must be correlated against the
oracle rule that fired in the iptables dump to determine whether the mismatch
is intentional (e.g. a 1.1+ nft optimisation) or a compiler regression.

### `migrate`

Verify migration from Shorewall to shorewall-nft.

```
shorewall-nft migrate [directory] [--iptables <value>] [-o <value>] [--dry-run] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--iptables`** — iptables-save dump for verification. When supplied, runs the triangle verifier and reports rule-level mismatches.
- **`-o, --output`** — Write the compiled nft script to FILE. Without this flag the script is written to a temporary file and deleted after the check completes.
- **`--dry-run`** — Compile and run `nft -c` syntax check only; do not load rules into the kernel.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### How to verify success

Exit code 0: the configuration compiles cleanly and (if `--iptables` was
given) the nft output is semantically equivalent to the baseline. Exit code 1
indicates a compile error, nft syntax error, or verification mismatch. Exit
code 2 indicates an argument error. See also
[`shorewall-nft-migrate(8)`](../../tools/man/shorewall-nft-migrate.8) for the
standalone migration tool, which has the same semantics but accepts a mandatory
positional `CONFIG_DIR` for script use.

### `trace`

Start live packet tracing (nft monitor trace).

```
shorewall-nft trace [--netns <value>]
```

- **`--netns`** — Network namespace name.

## Generators

### `generate-sysctl`

Generate sysctl configuration script.

```
shorewall-nft generate-sysctl [directory] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `generate-systemd`

Generate systemd service files.

```
shorewall-nft generate-systemd [--with-netns] [-o <value>]
```

- **`--with-netns`** — Generate template for network namespace deployments (produces `shorewall-nft@.service` instead of `shorewall-nft.service`).
- **`-o, --output-dir`** — Write the generated unit file(s) to this directory instead of stdout.

### `generate-conntrackd`

Generate a `conntrackd.conf` fragment for an HA firewall pair. Honours
`CT_ZONE_TAG_MASK` to build a Mark filter that replicates only zone bits across
the sync link, keeping routing and policy marks local to each node.

```
shorewall-nft generate-conntrackd [directory] [--sync-iface <value>] [--peer-ip <value>] [--local-ip <value>] [--cluster-ip <value>] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--sync-iface`** — Interface used for the conntrackd sync link. Defaults to `CONNTRACKD_IFACE` from `shorewall.conf`.
- **`--peer-ip`** — IPv4 address of the peer HA node on the sync link.
- **`--local-ip`** — IPv4 address of this node on the sync link.
- **`--cluster-ip`** — Shared virtual IP that HA failover moves between nodes.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `generate-tc`

Generate tc (traffic control) commands.

```
shorewall-nft generate-tc [directory] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `apply-tc`

Apply TC (traffic control) config directly via pyroute2 netlink — no `tc(8)`
binary required. Reads `tcdevices` / `tcclasses` / `tcfilters` from the config
directory and configures kernel qdiscs, classes, and fwmark filters. Existing
qdiscs are deleted and re-added before each run (idempotent).

```
shorewall-nft apply-tc [directory] [--netns <value>] [--dry-run] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Apply inside this named network namespace (pyroute2 `IPRoute(netns=NAME)` — no `ip-netns-exec` fork).
- **`--dry-run`** — Parse and validate the TC config then print the planned operations as a bulleted list. Nothing is applied to the kernel.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `generate-set-loader`

Generate a shell script that loads external sets.

```
shorewall-nft generate-set-loader [directory] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

### `load-sets`

Load external sets (ipsets, GeoIP) into nft after apply.

```
shorewall-nft load-sets [directory] [--netns <value>] [--geoip-dir <value>] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Network namespace name.
- **`--geoip-dir`** — GeoIP prefix directory.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

## Dual-stack merge

### `merge-config`

Merge Shorewall + Shorewall6 configs into unified directory.

```
shorewall-nft merge-config <shorewall_dir> [shorewall6_dir] [-o <value>] [--guided] [--no-plugins]
```

- **`-o, --output`** — Output directory (default: <parent>/shorewall46)
- **`--guided`** — Interactive mode: ask on each collision
- **`--no-plugins`** — Disable plugin enrichment even if plugins.conf exists

## Plugins

### `plugins`

List shorewall-nft plugins. The only valid subcommand value is `list`
(default when omitted).

```
shorewall-nft plugins [list] [-c <value>]
```

- **`-c, --config-dir`** — Config directory containing `plugins.conf`.

### `lookup`

Lookup an IP address across all configured plugins.

```
shorewall-nft lookup <ip> [--config-dir <value>] [--json]
```

- **`--config-dir, -c`** — Config dir with plugins.conf
- **`--json`** — Output raw JSON (machine-readable).

### `enrich`

Run plugin enrichment in-place on a config directory.

```
shorewall-nft enrich [directory] [--no-backup] [--dry-run]
```

- **`--no-backup`** — Skip .bak file creation (dangerous)
- **`--dry-run`** — Preview changes without touching disk (shows a unified diff).

## Debug

### `debug`

Temporarily load a debug-annotated ruleset.

```
shorewall-nft debug [directory] [--netns <value>] [--no-restore] [--trace <value>] [-c <value>] [--config-dir-v4 <value>] [--config-dir-v6 <value>] [--no-auto-v4] [--no-auto-v6]
```

- **`--netns`** — Network namespace name.
- **`--no-restore`** — Do not restore the original ruleset on exit.
- **`--trace`** — Auto-install a `meta nftrace set 1` rule in the input chain for the given nft match (e.g. 'ip saddr 1.2.3.4' or 'meta l4proto icmp'). Removed on exit.
- **`-c, --config-dir`** — Explicit merged config directory (overrides /etc/shorewall46 default).
- **`--config-dir-v4`** — Explicit IPv4 config directory.
- **`--config-dir-v6`** — Explicit IPv6 config directory (use with --config-dir-v4 for dual mode).
- **`--no-auto-v4`** — Disable auto-detection of a v4 sibling directory.
- **`--no-auto-v6`** — Disable auto-detection of a v6 sibling directory.

#### How to verify success

The command prints a short usage summary and blocks until Ctrl+C. On exit it
prints `Restoring original ruleset…` (unless `--no-restore`) and exits 0.
Confirm the debug ruleset is active with `nft list ruleset | grep sw_debug` —
the debug chains carry named counters that `shorewall-nft counters` can poll.
If `nft monitor trace` shows nothing, the cause is routing/RPF or ARP, not
firewall rules — nft trace only sees packets that reach the matching table.

## Structured config I/O

### `config export`

Dump a Shorewall config directory as a structured JSON or YAML blob. Columnar
files emit one object per row; rules and policy are nested under their
`?SECTION` labels.

```
shorewall-nft config export [directory] [--format json|yaml] [-o <value>] [--include-trace] [--indent <value>]
```

- **`--format`** — Output format: `json` (default) or `yaml` (requires PyYAML).
- **`-o, --output`** — Write to FILE instead of stdout. Extension (`.yaml` / `.yml`) auto-selects YAML when `--format` is not given.
- **`--include-trace`** — Keep `_file` / `_lineno` / `_comment` diagnostic fields in the output (off by default for stable diffs).
- **`--indent`** — JSON indent level (ignored for YAML; default: 2).

### `config import`

Validate a structured JSON/YAML config blob and optionally write it back as
on-disk Shorewall files.

```
shorewall-nft config import <source> [--format json|yaml|auto] [--to <value>] [--force] [--dry-run]
```

- **`--format`** — Input format: `json`, `yaml`, or `auto` (selects by file extension; default).
- **`--to`** — Target directory. When given, the parsed blob is written back as on-disk Shorewall files.
- **`--force`** — Overwrite `--to` target even if it is not empty.
- **`--dry-run`** — Parse and validate only; print a summary. Implied when `--to` is absent.

### `config template`

Expand a multi-host text template against a target host name. Lines tagged with
`@<hostname>` at column 1 are kept (tag stripped) only when the hostname
matches `--host`; untagged lines pass through unchanged. Used for
keepalived/conntrackd configs that carry per-node variants in a single file.

```
shorewall-nft config template <source> --host <value> [-o <value>]
```

- **`--host`** — Target host name. Required.
- **`-o, --output`** — Write to FILE instead of stdout.

### `config merge`

Merge one or more Shorewall config directories into a single unified output
directory with pretty-printed column alignment, zone-pair grouping, and
catch-all DROPs tail-sorted.

```
shorewall-nft config merge <sources...> --to <value> [--force] [--provenance] [--config-dir-v6 <value>]
```

- **`--to`** — Target directory for the merged output. Required.
- **`--force`** — Overwrite target even if it exists and is non-empty.
- **`--provenance`** — Interleave `# from <file>:<lineno>` comments before each rule for audit traceability.
- **`--config-dir-v6`** — Optional v6 sibling for the first source directory.

## Plugin reference

### `ip-info` plugin

Pattern-based IPv4↔IPv6 mapping and IP metadata lookups. See
[`docs/shorewall-nft/plugins.md`](../shorewall-nft/plugins.md) for TOML
configuration, mapping rules, and CLI usage.

### `netbox` plugin

NetBox inventory integration: resolves IP addresses to device names, roles, and
tenants. See [`docs/shorewall-nft/plugins.md`](../shorewall-nft/plugins.md) for
API configuration and caching behaviour.

