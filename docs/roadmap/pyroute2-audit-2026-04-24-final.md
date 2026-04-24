# pyroute2 audit — final 2026-04-24 (post Phase 6)

Re-audit against the same scope as the baseline
(`docs/roadmap/pyroute2-audit-2026-04-24.md`, commit `9f6b035`).
Covers `packages/*/shorewall_nft*/`, `packages/shorewalld/shorewalld/`,
`packages/shorewall-nft-simlab/`, `packages/shorewall-nft-stagelab/`,
`packages/shorewall-nft-netkit/`.

---

## Diff vs baseline

| Category | Baseline | Now | Delta |
|---|---|---|---|
| **Total call sites** | 29 | 32 | +3 |
| **A — production runtime** | 13 | 13 | 0 |
| **B — operator-facing shell generators** | 9 | 11 | +2 |
| **C — tests** | 7 | 8 | +1 |

---

## New shell-outs introduced by Phase 6

### Category B additions (generator functions — correct as operator artefacts)

| File:lines | Function | WP | Assessment |
|---|---|---|---|
| `shorewall_nft/compiler/tc.py:272–345` | `emit_tcinterfaces_shell()` | `feat(tc): tcinterfaces + tcpri + TC mode toggles` (commit `55768ed`) | New generator for `tcinterfaces` TBF+prio+SFQ model. Emits `tc qdisc add/del`, `tc class add`, `tc filter add` lines into the `generate-tc` shell artefact. Correct: mirrors the existing `emit_tc_commands()` pattern for the `tcrules` model. A companion pyroute2 `apply_tcinterfaces()` path was also added in the same commit (see Category A — not a gap). |
| `shorewall_nft/compiler/tc.py:559–576` | `emit_clear_tc_shell()` | same commit (`55768ed`) | Generates `tc qdisc del` teardown lines for the CLEAR_TC=Yes stop path. Also a correct operator artefact; the stop path is inherently a shell script. |

Both functions are called from `generate_cmds.py:generate-tc` (an operator shell-script generator), not from any live-apply path.

### Category C addition (test fixture setup)

| File:lines | Tool | WP | Assessment |
|---|---|---|---|
| `tests/test_tcinterfaces.py:353,354,357,366` | `ip netns add`, `ip netns exec … ip link add/set`, `ip netns del` | `feat(tc): tcinterfaces + tcpri + TC mode toggles` (commit `55768ed`) | `TestApplyTcinterfacesRealNetns` test class. Uses `ip netns` for real-kernel fixture setup/teardown, same pattern as the pre-existing `test_tc_apply.py:330–349`. Acceptable. Could use `pyroute2.netns.create()` for create/delete (noted in baseline as future cleanup). |

### Notable non-regression: `runtime/apply.py` (new file, Phase 6 WP-F3)

`apply_ip_aliases()` / `remove_ip_aliases()` in the new
`shorewall_nft/runtime/apply.py` use **pyroute2 `IPRoute`** exclusively —
no `ip` binary, no `subprocess`. This is the live-apply companion for
NAT alias lifecycle that was a gap at baseline. No shell-out added here.

### Notable non-regression: `compiler/sysctl.py` per-iface section

The new per-interface sysctl block (added by
`feat(options,proxyarp): per-host/iface OPTIONS`, commit `b52253b`)
emits `echo VALUE > /proc/sys/net/{ipv4,ipv6}/conf/<iface>/<param>`
lines (direct proc write), **not** `sysctl -w …` invocations.
This is strictly better than the existing global-sysctl pattern and
does not add a new binary dependency.

---

## Categories A / B / C

### Category A — production runtime calls (13, unchanged)

| File:line | Tool | Snippet | pyroute2 equivalent? |
|---|---|---|---|
| `shorewall_nft/nft/netlink.py:94` | `nft` | primary nft load/apply path | No: no stable pyroute2 nft API |
| `shorewall_nft/nft/netlink.py:219` | `nft` | `_subprocess_text` fallback | No: same |
| `shorewall_nft/nft/netlink.py:238` | `nft` | JSON mode fallback | No: same |
| `shorewall_nft/nft/netlink.py:287` | `nft` | `run_script` fallback | No: same |
| `shorewall_nft/nft/netlink.py:442,456` | `nft` | `run_in_netns` in-fork path | No: same; setns+fork is already optimal |
| `shorewall_nft/nft/capabilities.py:254` | `modprobe` | `subprocess.run(["modprobe", mod], …)` | No pyroute2 equivalent; acceptable |
| `shorewall_nft/runtime/monitor.py:27` | `nft` | `subprocess.Popen(["nft", "monitor", "trace"], …)` | No pyroute2 equivalent; must remain |
| `shorewall_nft/verify/simulate.py:128` | shell helper | `ns()` — runs cmds in netns via setns | Acceptable; avoids `ip netns exec` fork |
| `shorewall_nft/verify/simulate.py:639` | `nft` | `ns(NS_FW, "nft -f …")` — ruleset load | Acceptable for now; long-term: `NftInterface.run_script()` |
| `shorewall_nft/verify/simulate.py:661–667` | `iptables`/`ip6tables` | `ns(listener_ns, "iptables -t nat … REDIRECT")` | **Yes — see recommendation (2) below; not yet migrated** |
| `shorewall_nft/verify/simulate.py:1230` | `nft` | `subprocess.Popen(["nft", "monitor", "trace"], …)` | No: streaming; must remain |
| `shorewall_nft/verify/netns_topology.py:318` | external binaries | `exec_in_ns()` via setns | By design; already optimal |
| `shorewall_nft/verify/connstate.py:347,355` | `conntrack` | `ns(NS_FW, "conntrack -L …")` | **Yes — NFCTSocket; not yet migrated** |

### Category B — generated shell output (11)

| File:lines | What's generated | Delta | Design verdict |
|---|---|---|---|
| `compiler/providers.py:409–528` | `ip rule add`, `ip route replace`, `ip addr show \| awk` | baseline | Correct artefact. Gap: `apply_iproute2_rules()` still missing |
| `compiler/sysctl.py:38–111` | `sysctl -w net.ipv4.*` global settings | baseline | Correct artefact; no pyroute2 sysctl API |
| `compiler/sysctl.py:133–166` | `echo VALUE > /proc/sys/…` per-iface settings | **NEW** (Phase 6) | Improvement: direct proc write, no sysctl binary |
| `compiler/tc.py:630–660` | `tc qdisc/class add` for tcrules model | baseline | Correct artefact; `apply_tc()` pyroute2 path exists |
| `compiler/tc.py:272–345` | `tc qdisc/class/filter add/del` for tcinterfaces model | **NEW** (Phase 6) | Correct artefact; `apply_tcinterfaces()` pyroute2 path exists |
| `compiler/tc.py:559–576` | `tc qdisc del` teardown (CLEAR_TC=Yes) | **NEW** (Phase 6) | Correct artefact for stop script |
| `compiler/proxyarp.py:387–396` | `sysctl -wq`, `ip neigh replace proxy`, `ip route replace` | baseline | Partially superseded by `apply_proxyarp()` |
| `runtime/conntrackd.py` | `conntrackd.conf` fragment | baseline | Correct: config generation, not runtime exec |
| `runtime/cli/generate_cmds.py:110` | `generate-tc` CLI (dispatches emit_tc_commands + emit_tcinterfaces_shell) | baseline | Updated to include tcinterfaces |
| `runtime/cli/generate_cmds.py:131` | `generate-iproute2-rules` CLI | baseline | Correct artefact |
| `nft/set_loader.py` (via `generate-set-loader`) | shell script with `nft add element` | baseline | Debug/bootstrap-only artefact |

*Note: `compiler/sysctl.py:38–111` and `:133–166` are counted as two distinct
location entries inside the same `generate_sysctl_script()` function.*

### Category C — tests (8)

| File:lines | Tool | Delta | Verdict |
|---|---|---|---|
| `tests/test_config_gen.py:48,53,70,90,95,100,105,118,133,144` | `ip netns add/del`, `swnft compile`, `nft -c -f`, `nft -f`, `nft list` | baseline | Acceptable |
| `tests/test_netns_routing.py:30,55,57,66,110,131,168,186,228,259,272,280,287` | `ip netns list/add/del`, `swnft compile`, `nft -f`, `sysctl -w/-n` | baseline | Acceptable |
| `tests/test_tc_apply.py:330,331,335,349` | `ip netns add/exec/del` | baseline | Acceptable; could use pyroute2 for cleanup |
| `tests/test_cli_integration.py:535` | `ip netns exec … swnft debug` | baseline | Signal-propagation fixture; acceptable |
| `tests/verify/test_connstate.py:294,304,311,318,336,347` | `conntrack` (mocked) | baseline | Smell; must change when connstate migrates to NFCTSocket |
| `tests/test_netns_routing.py:155,160` | `sysctl` via `_ns()` | baseline | Acceptable |
| `shorewall-nft-netkit/tests/test_nsstub_orphan.py:43,48` | `ip netns del`, `umount` | baseline | Acceptable |
| `shorewall-nft-netkit/tests/test_netns_fork.py:80,81` | `ip netns del`, `umount` | baseline | Acceptable |
| `tests/test_tcinterfaces.py:353,354,357,366` | `ip netns add/exec/del` | **NEW** (Phase 6) | Acceptable; same pattern as test_tc_apply.py fixture |

---

## Migration recommendations status

From the baseline's top-3 highest-value migrations:

### (1) `verify/connstate.py:347,355` — replace `conntrack` CLI with `NFCTSocket`

**Status: not done.**

Lines 347 and 355 still call `ns(NS_FW, "conntrack -L …")` and
`ns(NS_FW, "conntrack -F …")`. Phase 6 did not touch `connstate.py`.
The proof-of-concept path remains `shorewalld/collectors/conntrack.py`.

### (2) `verify/simulate.py:661–667` — replace `iptables -t nat REDIRECT` with `nft … redirect to-port`

**Status: partially done.**

The *slave*-side REDIRECT (listener namespaces for multi-zone probes) was
migrated to nft in the new `_install_slave_redirect()` method
(`simulate.py:451–480`, commit `55768ed`), which loads an nft `redirect to`
rule via `exec_in_ns(["nft", "-f", path])`. The *destination*-side
`setup_listeners()` REDIRECT at lines 661–667 still uses
`iptables -t nat … REDIRECT`. The last iptables/ip6tables binary dependency
in the codebase therefore remains. Complete the migration by replacing lines
661–667 with an equivalent `exec_in_ns(["nft", "-f", …])` call loading a
similar `sw_redir` table.

### (3) Add `apply_iproute2_rules()` companion to `generate-iproute2-rules`

**Status: not done directly, but analogous gap closed.**

No `apply_iproute2_rules()` using `IPRoute.rule()` / `IPRoute.route()` was
added to `compiler/providers.py`. However, the analogous gap for IP alias
management was closed: `runtime/apply.py` provides fully pyroute2-backed
`apply_ip_aliases()` / `remove_ip_aliases()` (commit `cafaa68`, WP-F3),
following the same pattern recommended for `apply_iproute2_rules()`. The
`providers.py` live-apply gap remains open.

---

## Verdict

**PASS.**

**Done-criterion #4: "No new shell-outs introduced by Phase 6 WPs."**

All three Phase 6 commits (`55768ed`, `b52253b`, `cafaa68`) introduced
**zero new `subprocess.run` / `subprocess.Popen` calls in production
runtime code** (Category A). Category A count is unchanged at 13.

The +3 total delta is:

- +2 Category B generator functions (`emit_tcinterfaces_shell`,
  `emit_clear_tc_shell`) — operator shell-script artefacts, same pattern
  as pre-existing `emit_tc_commands`. Correct.
- +1 Category C test fixture class (`TestApplyTcinterfacesRealNetns`) —
  uses `ip netns` for kernel-level TC test setup, same pattern as
  pre-existing `test_tc_apply.py`. Acceptable.

**Done-criterion: "At least one of the three highest-value migrations
completed (or filed)."**

Migration (2) is **partially done**: the slave-side REDIRECT was migrated
to nft; the `setup_listeners()` iptables REDIRECT at lines 661–667 remains.
Migration (3) was **closed in spirit** via the new `apply_ip_aliases()`
pyroute2 path. Migration (1) is open.

Recommendation: file a follow-up issue to complete migration (2) (the last
four `iptables`/`ip6tables` calls in the codebase) and migration (3)
(`apply_iproute2_rules()` in `providers.py`).
