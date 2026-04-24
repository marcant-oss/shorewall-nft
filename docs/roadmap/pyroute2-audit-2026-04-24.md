# pyroute2 audit — baseline 2026-04-24

Snapshot of where the codebase still shells out to legacy iproute2 /
iptables / netfilter command-line tools instead of using pyroute2.

This is the **baseline before Phase 6 WP completion**. The same audit
must be re-run at the end of Phase 6 (last item in
`docs/roadmap/phase6-coverage-plan.md` → "Done criteria") to verify
that no WP introduced new shell-outs and to track migration progress
on the recommendations below.

## Summary

- **29 call sites** total across **15 files**
- **13** in production runtime code (Category A)
- **9** in code that generates operator-facing shell scripts (Category B)
- **7** in tests (Category C)

pyroute2 is **already used** in:
- `shorewall_nft/compiler/tc.py` — `apply_tc()` via `IPRoute` (HTB qdisc/class)
- `shorewall_nft/compiler/proxyarp.py` — `apply_proxyarp()` / `remove_proxyarp()`
- `shorewall_nft/verify/netns_topology.py` — `NetnsTopology` via `NDB`/`NetNS`
- `shorewalld/collectors/_shared.py` — cached `IPRoute` handle pool
- `shorewalld/collectors/link.py` — `IPRoute.get_links()`
- `shorewalld/collectors/conntrack.py` — `NFCTSocket` via worker RPC
- `shorewalld/nft_worker.py` — `NFCTSocket` for per-ns conntrack counters

## Category A — runtime calls

| File:line | Tool | Snippet | pyroute2 equivalent? |
|---|---|---|---|
| `shorewall_nft/nft/netlink.py:94` | `nft` | `subprocess.run(args, **kwargs)` — primary nft load/apply path | **No**: nft has no stable pyroute2 API; libnftables C bindings are the right long-term target (already preferred when available) |
| `shorewall_nft/nft/netlink.py:219` | `nft` | `subprocess.run(cmd, capture_output=True, text=True)` — `_subprocess_text` fallback | No: same as above |
| `shorewall_nft/nft/netlink.py:238` | `nft` | `subprocess.run(...)` — JSON mode fallback | No: same |
| `shorewall_nft/nft/netlink.py:287` | `nft` | `subprocess.run(cmd, ...)` — `run_script` fallback | No: same |
| `shorewall_nft/nft/netlink.py:442,456` | `nft` | `subprocess.run(args, **kwargs)` — `run_in_netns` in-fork path | No: same; setns+fork already avoids `ip netns exec` |
| `shorewall_nft/nft/capabilities.py:254` | `modprobe` | `subprocess.run(["modprobe", mod], ...)` | No pyroute2 equivalent; shell-out acceptable |
| `shorewall_nft/runtime/monitor.py:27` | `nft` | `subprocess.Popen(["nft", "monitor", "trace"], ...)` | No pyroute2 equivalent for `nft monitor trace`; must remain shell-out |
| `shorewall_nft/verify/simulate.py:128` | shell helper | `subprocess.run(...)` — `ns()` helper running cmds in netns | Acceptable: this helper exists to run *non-Python* binaries; pyroute2 path is `exec_in_ns` in `netns_topology.py` |
| `shorewall_nft/verify/simulate.py:639` | `nft` | `ns(NS_FW, f"nft -f {nft_script_path}", ...)` — ruleset load | Acceptable for now (no pyroute2 nft); long term: `NftInterface.run_script()` |
| `shorewall_nft/verify/simulate.py:661–667` | `iptables`/`ip6tables` | `ns(listener_ns, "iptables -t nat -A PREROUTING ... REDIRECT")` | **Yes — replace with `nft add rule … redirect to-port`** (eliminates last iptables binary dependency) |
| `shorewall_nft/verify/simulate.py:1230` | `nft` | `subprocess.Popen([*IP_NETNS, "exec", NS_FW, "nft", "monitor", "trace"], ...)` | No: same as monitor.py |
| `shorewall_nft/verify/netns_topology.py:318` | external binaries | `subprocess.run(argv, ..., preexec_fn=_enter_ns)` — `exec_in_ns` wrapper | By design: runs non-Python tools via setns; already optimal |
| `shorewall_nft/verify/connstate.py:347,355` | `conntrack` | `ns(NS_FW, "conntrack -L -p tcp ...")` / `... -F ...` | **Yes — `pyroute2.NFCTSocket` is already used in shorewalld for the same purpose** |

## Category B — generated shell output

| File:line | What's generated | Design verdict |
|---|---|---|
| `shorewall_nft/compiler/providers.py:409–528` | `ip rule add`, `ip route replace`, `ip addr show \| awk` — multi-ISP setup (`generate-iproute2-rules`) | Correct as operator artefact. **Gap**: no companion `apply_iproute2_rules()` for live-apply path; should be added with `IPRoute.rule()` / `IPRoute.route()` |
| `shorewall_nft/compiler/sysctl.py:38–111` | `sysctl -w net.ipv4.*` lines for `generate-sysctl` | Correct as operator artefact. pyroute2 has no sysctl API; live-apply alternative is direct `/proc/sys/` writes |
| `shorewall_nft/compiler/tc.py:156–166` | `tc qdisc add/del`, `tc class add` lines for `generate-tc` | **Mixed**: `apply_tc()` already uses pyroute2 — the shell generator duplicates logic. Should delegate to the same `TcConfig` model |
| `shorewall_nft/compiler/proxyarp.py:387–396` | `sysctl -wq`, `ip neigh replace proxy`, `ip route replace` | Partially superseded: `apply_proxyarp()` already uses pyroute2 for neigh/route; only sysctl lines have no pyroute2 equivalent |
| `shorewall_nft/runtime/conntrackd.py` | `conntrackd.conf` fragment | Correct: config file generation, not runtime exec |
| `shorewall_nft/runtime/cli/generate_cmds.py:110` | `generate-tc` CLI | See tc.py verdict |
| `shorewall_nft/runtime/cli/generate_cmds.py:131` | `generate-iproute2-rules` (commit 79c4858) | Correct as operator-facing artefact |
| `shorewall_nft/runtime/cli/debug_cmds.py:271` | user-facing hint string `f"ip netns exec {netns} "` | Not a runtime call; advice text only |
| `shorewall_nft/nft/set_loader.py` (via `generate-set-loader`) | shell script with `nft add element` | Questionable: shorewalld loads sets via netlink; should be documented as debug/bootstrap-only |

## Category C — tests

| File:line | Tool | Verdict |
|---|---|---|
| `tests/test_config_gen.py:48,53` | `ip netns add/del` | fixture-setup — acceptable |
| `tests/test_config_gen.py:70,90,95,100,105,118,133,144` | `swnft compile`, `nft -c -f`, `nft -f`, `nft list` | assertion-about-state — acceptable |
| `tests/test_netns_routing.py:30,55,57,66` | `ip netns list/add/del` | fixture-setup — acceptable |
| `tests/test_netns_routing.py:110,121,131,138,168,186,228,240,259,267,272,280,287` | `swnft compile`, `nft -f`, `sysctl -w`, `sysctl -n` | assertion-about-state — acceptable |
| `tests/test_tc_apply.py:330,331,335,349` | `ip netns add/exec/del` | fixture-setup — acceptable; could use `pyroute2.netns.create()` for cleanup |
| `tests/test_cli_integration.py:535` | `ip netns exec … swnft debug` | fixture-setup for signal-propagation — acceptable |
| `tests/verify/test_connstate.py:294,304,311,318,336,347` | `conntrack` (mocked) | **Smell** — production-code-tested-via-shell. When `connstate.py` migrates to `NFCTSocket`, these tests must be re-written to mock pyroute2 instead |
| `tests/test_netns_routing.py:155,160` | `sysctl` via `_ns()` | assertion-about-state — acceptable |
| `shorewall-nft-netkit/tests/test_nsstub_orphan.py:43,48` | `ip netns del`, `umount` | fixture-setup — acceptable |
| `shorewall-nft-netkit/tests/test_netns_fork.py:80,81` | `ip netns del`, `umount` | fixture-setup — acceptable |

## Recommendations

### Top 3 highest-value migrations

1. **`verify/connstate.py:347,355` — replace `conntrack` CLI with `NFCTSocket`.** Already proven in `shorewalld/collectors/conntrack.py` and `shorewalld/nft_worker.py`. Eliminates a binary dependency, enables clean netns scoping without `ip netns exec`, and lets `tests/verify/test_connstate.py` mock pyroute2 instead of raw `CompletedProcess`.

2. **`verify/simulate.py:661–667` — replace `iptables -t nat REDIRECT` with `nft add rule … redirect to-port`.** These are the only remaining iptables calls in the entire codebase. Replacing them eliminates the iptables/ip6tables binary dependency entirely.

3. **Add `apply_iproute2_rules()` companion to the `generate-iproute2-rules` command** — using `IPRoute.rule("add", ...)` and `IPRoute.route("replace", ...)`, mirroring the pattern in `compiler/tc.py::apply_tc()`. Closes the live-apply gap so `start`/`restart` is fully shell-free for policy routing.

### Top 3 places where shell is correct and should stay

1. **`nft/netlink.py` — all `subprocess.run(["nft", …])` calls.** nftables has no stable pyroute2/netlink API for ruleset load + atomic replace. Already prefers libnftables C bindings when available; subprocess is the correct fallback. Invest in libnftables, not pyroute2.

2. **`runtime/monitor.py` + `verify/simulate.py:1230` — `nft monitor trace` Popen.** Streaming protocol with no netlink equivalent. Must remain subprocess. Existing in-process `setns()` is already optimal.

3. **`compiler/sysctl.py` — `sysctl -w` lines in generated scripts.** Operator artefact. pyroute2 has no sysctl API. Direct `/proc/sys/` writes can be the runtime-apply alternative, but the generator is the right tool for `generate-sysctl`.

### Gaps in `shorewall-nft-netkit`

- **No shared `link_add()` / `addr_add()` / `route_add()` primitives.** `nsstub.py` still shells out to `ip netns del` for cleanup instead of `pyroute2.netns.remove()`. A pyroute2-backed wrapper set should live in `netkit` so both simulation and test helpers share one implementation.
- **No `load_nft_script(path_or_text, netns)` helper.** `netns_fork.py` has nft plumbing as ad-hoc exception strings. A clean wrapper around `NftInterface.run_script()` should live in `netkit`, eliminating duplicated `exec_in_ns(["nft", "-f", …])` calls across `simulate.py` and tests.
