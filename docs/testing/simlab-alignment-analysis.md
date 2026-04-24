# Simlab Alignment Analysis — Task #38

**Date**: 2026-04-24
**Decision**: Option 1 — migrate conservatively with `--data DIR` delegation.
**Owner**: unassigned (follow-ups filed below).

## 1. Execution Models Side-by-Side

### simulate.py — veth + subprocess + synchronous

**Topology construction** (`simulate.py:178–727`):
`SimTopology` creates three named netns (`shorewall-next-sim-src/fw/dst`)
plus one slave netns per zone (prefix `sw-z-`) when `--all-zones` is
active. Physical connectivity uses `pyroute2`-backed veth pairs created
in the host namespace and moved into the target netns. Each zone's
FW-side veth end is renamed to the production interface name (`bond1`,
`bond0.20`, etc.) so nft rules match literally. The firewall namespace
is configured with IP forwarding, rp_filter=0, and the full nft ruleset
is loaded by `setup_fw()` (`simulate.py:633`).

**Probe dispatch** (`simulate.py:486–514`):
In multi-zone slave mode, each slave namespace runs a persistent
fork-worker process (`slave_worker.spawn_worker`) that accepts
`("probe", proto, src_ip, dst_ip, port, family, timeout)` tuples over a
`multiprocessing.Pipe`. The worker calls `socket()` / `connect()` /
`sendto()` natively and returns `("ok", verdict, ...)`. Single-pair
mode shells out to `nc`/`ping` via `subprocess.run` with a `preexec_fn`
that calls `setns(CLONE_NEWNET)` (`simulate.py:105–132`).

**Test derivation** (`simulate.py:798–985`):
`derive_tests_all_zones()` parses an iptables-save dump (via
`iptables_parser`), walks every `<src>2<dst>` chain, derives `TestCase`
objects with `expected` verdicts from rule targets. Tests are sampled
stochastically; DROP/REJECT rules are prioritised. Results are
`list[TestResult]` with `passed: bool`, `got: str`, `ms: int`.

**What runs the compile**: `run_simulation()` (`simulate.py:1236`) calls
`load_config()` + `build_ir()` + `emit_nft()` internally — it owns the
full compile-to-load pipeline.

### simlab — TUN/TAP + asyncio + live-dump replay

**State source** (`dumps.py:263–299`):
`load_fw_state(ip4add, ip4routes, ip6add, ip6routes)` parses plain-text
dumps of `ip addr show` and `ip route show` from the real firewall.
There is no shorewall config parse inside simlab itself. `FwState`
carries `Interface` (name, MTU, addresses) and `Route` lists.

**Topology construction** (`topology.py:59–382`):
`SimFwTopology.build()` creates a single `simlab-fw` netns, then
creates one TUN or TAP device per parsed interface (TAP for
Ethernet-like, TUN for PTP), moves it into the namespace with the
canonical name, applies addresses and routes. No veth pairs, no
`NS_SRC`/`NS_DST` — just one isolated namespace with the same
interface layout as the real box. The parent process retains all
TUN/TAP file descriptors.

**Probe dispatch** (`controller.py:337–376`):
`SimController.run_probes(probes)` is `async`. A persistent
reader/writer thread pool (one pair per CPU core) drains TUN/TAP file
descriptors continuously. Injecting a probe is `os.write(fd, payload)`
via the writer queue; observing it is a `probe_id` match in
`_on_observed_fast()` when the forwarded packet appears on the
expected egress fd. ARP/NDP resolution is answered inline by the
reader thread using fast byte-level extraction
(`packets.fast_extract_arp_request`, `fast_extract_ndp_ns`). No
subprocesses, no forks per probe.

**Test derivation** (`smoketest.py:850–1045`):
`_build_per_rule_probes()` calls `simulate.derive_tests_all_zones()`
directly (already imported from the core package, `smoketest.py:864`)
then runs three autorepair passes: replace `DEFAULT_SRC` placeholders
with zone-local IPs, re-classify via `RulesetOracle`, and drop probes
whose routing is incompatible with the source interface.

**What runs the compile**: `_compile_ruleset()` (`smoketest.py:396`)
shells out to `shorewall-nft compile`, producing a `.nft` file that
`SimController.load_nft()` (`controller.py:260`) loads via
`run_in_netns_fork` + libnftables.

**Where they are the same**: both call `derive_tests_all_zones()` for
test generation (simlab already imports it); both load the compiled
nft ruleset and rely on real kernel nft verdict; both express results
as `ACCEPT`/`DROP`/`timeout`.

**Where they are fundamentally different**:

| Dimension | simulate.py | simlab |
|---|---|---|
| Namespace count | 3 + N slaves per run | 1 (NS_FW only) |
| L2 simulation | veth (real kernel bridge) | TUN/TAP + inline ARP/NDP |
| Probe mechanism | socket/nc in slave NS | `os.write` raw bytes to fd |
| Async model | synchronous + `ThreadPoolExecutor` | asyncio + thread pool |
| State source | shorewall config compile | `ip addr/route` dumps |
| Connstate probes | yes (`connstate.py`) | no |
| Infrastructure validation | yes (`tc_validate.py`) | no |
| Per-run overhead | 3+ netns create + veth + listeners | 1 netns + TUN/TAP only |
| Process model | N fork-workers (one per zone) | single process, fd-owned |

## 2. Current Simlab Entry-Point Surface

**CLI**: `shorewall-nft-simlab` (entry point: `smoketest:cli`, but
`smoketest.py` only defines `main()` — `cli` symbol is absent, an
existing minor bug). Sub-commands: `smoke`, `stress`, `limit`, `full`.
All require `--data DIR` (the `ip addr/route` dump directory) and
`--config DIR` (the shorewall config dir).

**Python API**: no stable public functions. `cmd_full(args)`,
`cmd_smoke(args)`, `cmd_stress(args)`, `cmd_limit(args)` accept
`argparse.Namespace`, not a programmatic call signature.
`SimController` is importable but requires pre-parsed `FwState` dump
paths, not a `config_dir`.

**Does any surface already accept `(config_dir, iptables_dump)`?**
`_build_per_rule_probes(iptables_dump, fw_state, iface_to_zone, ...)`
(`smoketest.py:851`) is the closest — it takes an `iptables_dump` and
an `iface_to_zone` dict. But `fw_state` must be a parsed `FwState`
from live dumps, not derivable from `config_dir` alone. The
`iface_to_zone` map is read from the shorewall `interfaces` file by
`_iface_to_zone_map(config_dir)` (`smoketest.py:1048`).

**How simlab currently gets its firewall state**: pre-captured files:
`ip4add`, `ip4routes`, `ip6add`, `ip6routes` — plain-text snapshots
from a running firewall box. These are **not** derived from the
shorewall config; they represent the actual kernel's network state at
capture time. The nft ruleset is compiled fresh each run from the
config directory via `_compile_ruleset()`.

**What is missing for a `(config_dir, iptables_dump)` entry point**:
simlab has no mechanism to synthesise a `FwState` from a shorewall
config. `FwState` needs `Interface.mtu`, `Interface.addrs4/6` (real
secondaries, VRRP IPs), and the full route table — none of which are
inferable from a shorewall config alone without running the box. This
is the central gap.

## 3. Call-Site Constraints in `debug_cmds.py`

**What `shorewall-nft simulate` does today** (`debug_cmds.py:382–498`):

1. Resolves config path via `_resolve_config_paths`.
2. Calls `run_simulation(config_dir, iptables_dump, ...)` which
   internally compiles the config, creates the 3-namespace topology,
   loads nft, runs probes, and tears down.
3. Returns `list[TestResult]` — each with `passed: bool`, `got: str`,
   `test.src_ip/dst_ip/proto/port/expected`.
4. Prints `Results: N passed, M failed (total)` plus a failed-tests
   list.
5. Exits with code 1 on any failure.

**What the CLI surfaces to the user**: pass/fail counts, failed tuple
details (`src → dst proto:port expect=X got=Y`), and infrastructure
validation output (tc, routing, nft loaded). These are printed to
stdout by `run_simulation` itself (lines 1387–1468).

**Would a simlab replacement change the UX?** Yes, in several ways:

- simlab's report format (`write_report`/`write_json`, `report.py`)
  uses structured JSON/Markdown archives, not inline stdout lines.
- simlab does not run infrastructure validation (`tc_validate.py`) or
  connstate probes.
- simlab requires the `--data` dump directory in addition to
  `--config`; that directory must exist on disk before the command
  runs.
- simlab's exit codes are more nuanced (0/1/2) and its mismatches use
  four-way `fail_drop`/`fail_accept` semantics vs. simple `passed=False`.

The raw test tuple display (`src → dst expect=X got=Y`) could be
replicated from simlab's `ProbeSpec` data, but it would require a new
adapter layer.

## 4. Migration Cost Estimate (Option 1)

### Proposed new simlab entry point

```python
# shorewall_nft_simlab/api.py
def run_simulation_from_config(
    *,
    config_dir: Path,
    iptables_dump: Path,
    ip6tables_dump: Path | None = None,
    fw_state: FwState | None = None,          # caller provides or synthesised
    max_per_pair: int = 60,
    seed: int | None = 42,
    verbose: bool = False,
    parallel_batch: int = 512,
    probe_timeout: float = 0.25,
) -> list[SimResult]:
    ...
```

`SimResult` would need to carry
`src_ip, dst_ip, proto, port, expected, observed, passed, ms`
to match the current `TestResult` interface.

### Required refactors

1. **`FwState` synthesis from shorewall config** — the largest gap.
   Without live `ip addr/route` dumps the topology builder has no
   addresses or routes. Two sub-options:
   - (a) Let the caller supply the dump directory. Add `--data` to
     the `simulate` CLI. Reasonable for power users, not for the
     default UX.
   - (b) Synthesise `FwState` from the shorewall config: read
     `interfaces`, `hosts`, `subnets` files, derive addresses. This
     is a non-trivial parser with no existing code. Estimated 3–5
     days to cover the common cases plus VRRP secondaries.

2. **Programmatic `SimController` call** — wrap `cmd_full` logic into
   a callable. The `argparse.Namespace` pattern must be replaced by a
   proper function signature. Estimated 1 day.

3. **Unified result type** — `TestResult` (simulate.py) and simlab's
   `(cat, expected, ProbeSpec, meta)` 4-tuple are incompatible. A
   thin adapter struct is needed. Estimated 0.5 days.

4. **`debug_cmds.py` wiring** — replace the `run_simulation()` import
   with the new API call, adapt the output formatting. Estimated
   0.5 days.

5. **Test coverage** — simulate.py has no unit tests; simlab has
   `test_simlab_autorepair.py` and `test_simlab_pytest_gate.py` but
   neither covers the `(config_dir, iptables_dump)` path. Integration
   tests would require root and a real netns. Estimated 2–3 days.

**Total estimate**: 7–10 days for a clean migration, dominated by
item 1(b). With option 1(a) (require caller-supplied dumps), effort
drops to 3–4 days but the CLI UX regresses.

### Risk list

- **Timing differences**: simlab's TUN/TAP path has ~5–15 ms base
  latency per probe; simulate.py's socket-in-netns path has ~20–50 ms
  (fork + nc). Simlab is faster in batch but the timeout semantics
  differ.
- **Probe semantics**: simulate.py uses real TCP connect / UDP echo /
  ICMP ping — actual transport-layer handshakes. Simlab injects raw
  Ethernet frames; DROP is detected by timeout, not by connection
  refused or ICMP unreachable. Rules that REJECT (send RST/ICMP) will
  register as `ACCEPT` in simlab if the RST/ICMP is forwarded to the
  egress fd, or as `DROP` if it isn't — depending on where the simlab
  observer is placed. The `expected` field in `TestCase` already
  normalises REJECT→DROP (`simulate.py:942`), but the observed verdict
  may differ.
- **Connstate and infrastructure validation**: removing these from
  the CLI path is a capability regression.
- **Per-netns isolation**: simulate.py isolates every zone into its
  own slave netns; simlab uses a single `simlab-fw` netns with
  TUN/TAP only. Probes that test cross-zone policies work correctly
  in both models, but simlab cannot exercise zone-local INPUT rules
  (no source namespace to initiate from).
- **Missing `cli` symbol**: `pyproject.toml` references `smoketest:cli`
  but the symbol is `main()`. This pre-existing bug must be fixed
  before the CLI is integrated.

## 5. Permanent-Decision Rationale (Option 2)

The core architectural obstacle is that **simlab requires
pre-captured live-system dumps** (`ip addr show`, `ip route show`) as
its topology input, while `simulate.py` derives topology from the
shorewall config at runtime. These are not equivalent:

- The live dumps include VRRP secondary addresses, BGP-learned routes,
  interface MTUs, and secondary IPs that are absent from the shorewall
  config.
- A `shorewall-nft simulate` user runs the command on the firewall
  itself (or against a config + iptables dump), not against a
  separately collected network dump directory.
- Synthesising `FwState` from the config is feasible for simple
  topologies but will miss production-critical state (VRRP, BGP
  routes, interface secondaries) in the exact environments where
  correctness matters most.

Simlab also drops infrastructure validation (`tc_validate.py`) and
connstate probes, both of which are surfaced to the
`shorewall-nft simulate` user today. The simlab tool is designed for
long-running batch validation runs on a dedicated test VM (see
`smoketest.py:85`: `DEFAULT_SIM_DATA = "/root/simulate-data"`), not
for the interactive single-command workflow that `debug_cmds.py`
serves.

## 6. Recommendation

**Option 1 — Migration plan**, but scoped conservatively: add a
`--data DIR` argument to `shorewall-nft simulate` that, when
supplied, delegates to simlab's `cmd_full` logic via a new thin
`api.run_simulation_from_config()` wrapper. When `--data` is absent,
`simulate.py` continues as the default backend. This avoids the
`FwState` synthesis problem entirely, preserves backward
compatibility, and gives power users access to simlab's superior
batch throughput and oracle-reclassification pipeline. The
`simulate.py` deletion can be deferred until the `--data` path has
sufficient field exposure.

## 7. Follow-Up Tasks

1. Fix the missing `cli` symbol in `smoketest.py` — `entry_points.txt`
   and `pyproject.toml` reference `smoketest:cli` but only `main()`
   exists. Rename `main` to `cli` or add `cli = main` at the module
   level.
2. Add `api.py` to `shorewall_nft_simlab` with a stable
   `run_simulation_from_config(config_dir, iptables_dump, *, fw_state_dir, ...)`
   signature that wraps `cmd_full` logic without `argparse.Namespace`.
3. Add `--data DIR` option to `shorewall-nft simulate` in
   `debug_cmds.py`; when present, call the new
   `api.run_simulation_from_config()` and map `ProbeSpec` results to
   the existing `TestResult` display format.
4. Extract `_iface_to_zone_map()` and `_iface_rp_filter_map()` from
   `smoketest.py` into a shared utility module (both are needed by
   the new API and currently only exist as private helpers).
5. Remove the `/simulate` help text that hints at simlab as a
   replacement until the integration is working end-to-end (avoids
   confusing users who see the hint but find no `--data` flag yet).
6. File a separate task for `FwState` synthesis from config — a full
   implementation is not required for the conservative migration but
   would eventually allow `simulate.py` deletion.
7. Rename `simulate.ns()` (the `setns`-based subprocess runner at
   `simulate.py:105`) to `simulate.exec_in_ns()` before any migration
   to avoid shadowing the `ns` parameter name in several function
   signatures.

---

**Recommendation**: Option 1 — add a `--data DIR`-gated simlab
delegation path to `shorewall-nft simulate`, keeping `simulate.py`
as the default backend; full deletion deferred pending field
validation of the new path.
