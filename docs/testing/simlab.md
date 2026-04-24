# simlab — packet-level firewall test harness

`shorewall_nft.verify.simlab` is a TUN/TAP-based test lab that
rebuilds the target firewall's network namespace from on-disk
dumps of the real box, loads the compiled nft ruleset into it,
and injects + observes packets to verify forwarding behaviour.
It supersedes the older `simulate.py` runtime for packet-level
testing of production configs.

## Why a new runtime

The legacy `simulate.py` uses a fixed three-namespace topology
(src + fw + dst), a single veth pair per side, and shells out to
`nc`/`ping` for probe generation. That gave us enough fidelity
for 1.0's smoke tests, but the production marcant-fw box has:

- 24 network interfaces in 15 zones
- A real multi-homed routing table (224 v4 routes + 238 v6)
- FASTACCEPT=No (established traffic returns through the
  per-zone-pair chain)
- Rules that inspect iifname / oifname literally

The fixed-topology simulate couldn't route return traffic
through the correct interface pair, so any zone-pair beyond
the hard-coded net→host path reported spurious drops. simlab
fixes this by **reproducing the real interface topology**.

## Architecture

### Namespaces

- **host namespace** — where the controller lives. Owns every
  TUN/TAP file descriptor directly.
- **NS_FW** — named netns (default `simlab-fw`). Holds the
  emulated interfaces and the loaded shorewall nft ruleset.
  Kept alive via a stub process (see below) so the kernel
  reclaims it automatically if the controller crashes.

### Components

```
         ┌───────────────── host NS ─────────────────────┐
         │                                               │
         │   ┌──────────────────────────────────────┐    │
         │   │  SimController (asyncio)             │    │
         │   │                                      │    │
         │   │   ┌─ _iface_fds ─────────────────┐   │    │
         │   │   │  bond1    → fd1 ────────────┼───┼──┐ │
         │   │   │  bond0.20 → fd2 ────────────┼───┼──┤ │
         │   │   │  bond0.18 → fd3 ────────────┼───┼──┤ │
         │   │   │  …                          │   │  │ │
         │   │   └─────────────────────────────┘   │  │ │
         │   │                                      │  │ │
         │   │   add_reader(fdN, _on_tap_read)      │  │ │
         │   │   → inline ARP reply / NDP NA /      │  │ │
         │   │     observed-packet dispatch         │  │ │
         │   └──────────────────────────────────────┘  │ │
         │                                              │ │
         └──────────────────────────────────────────────┘ │
                                                          │
 ┌───────────────── NS_FW (netns pinned by nsstub) ───────┘
 │                                                        │
 │     bond1 (TAP)    bond0.20 (TAP)   bond0.18 (TAP) ... │
 │        │                │                │             │
 │        └───── nft shorewall ruleset ─────┘             │
 │                 + full routing table                   │
 │                                                        │
 └────────────────────────────────────────────────────────┘
```

- **Single-process design.** The controller owns every TUN/TAP
  fd directly in its own address space. No worker subprocesses,
  no multiprocessing pipes, no fork. One Python interpreter,
  one asyncio event loop, one ~200 MB RSS footprint regardless
  of how many interfaces the target firewall has.
- **Asyncio reader per fd.** On `run_probes`, the controller
  registers one `add_reader(fd, _on_tap_read, iface_name)` per
  TUN/TAP. Inject is `os.write(fd, payload)` directly — one
  syscall, no pipe roundtrip.
- **Inline ARP / NDP handling.** `_on_tap_read` parses every
  incoming frame via scapy. ARP who-has gets an immediate
  reply from `_WORKER_MAC = 02:00:00:5e:00:01` pretending to
  own the requested IP. IPv6 NDP Neighbor Solicitation gets a
  Neighbor Advertisement from a synthetic link-local. All of
  this runs inside the controller's event loop — no IPC.
- **Probe correlation in-process.** Observed IP packets go
  straight into `self._probes` / `self._probe_futures`. The
  primary match key is the probe id stashed in the IPv4 `id`
  field / IPv6 flow label; fallback is the per-probe
  `match()` closure for NAT-rewritten packets.

> **Why single-process?** Earlier versions spun up one worker
> subprocess per interface (24 workers on the reference VM).
> Each worker shipped ~80 MB of Python interpreter / stdlib /
> scapy — ~2 GB of RAM purely for interpreter overhead.
> Consolidating to N workers helped; removing workers entirely
> helped more. Single-process is simpler, smaller, and faster:
> on the reference VM the final run fires at **~125 probes/s
> with 215 MB RSS total**, vs ~20 probes/s and ~2 GB RSS under
> the subprocess model — a 6× throughput win and an 8× memory
> win from one architectural change.

### Kernel-level NS lifecycle

`simlab/nsstub.py` forks a tiny stub process that:

1. `unshare(CLONE_NEWNET)` — gets its own net namespace.
2. bind-mounts `/proc/self/ns/net` onto `/run/netns/<name>`
   so `pyroute2.NetNS` and `ip netns exec` can address it.
3. Sets `PR_SET_PDEATHSIG = SIGTERM` so the kernel signals
   the stub if the controller dies.
4. Reads from a keep-alive pipe until EOF or SIGTERM.
5. On exit: `umount` + `unlink` the bind mount → the kernel
   reclaims the netns.

Result: any controller-side crash (clean exit, Python traceback,
signal, SIGKILL) leaves no leftover `/run/netns/<name>` and no
leaked kernel net namespace. Verified on the test VM.

> **Runtime dependency note:** simlab no longer requires the `iproute2`
> binary (`ip netns exec`) at runtime.  All netns operations — sysctl
> writes, nft ruleset loads, flowtable queries, and the optional nft
> trace spawn — go through `shorewall-nft-netkit`'s `run_in_netns_fork`
> / `_in_netns` primitives (pyroute2 + libnftables + fork+setns).

### Packet construction

`simlab/packets.py` builds wire-format bytes via scapy:

| protocol        | builder                              |
|-----------------|--------------------------------------|
| TCP             | `build_tcp`                          |
| UDP             | `build_udp`                          |
| ICMP            | `build_icmp`                         |
| ICMPv6          | `build_icmpv6`                       |
| ARP             | `build_arp_request`, `build_arp_reply` |
| NDP NS/NA       | `build_ndp_ns`, `build_ndp_na`       |
| ESP             | `build_esp`                          |
| GRE             | `build_gre`                          |
| VRRPv2          | `build_vrrp`                         |
| BGP OPEN        | `build_bgp_open`                     |
| OSPFv2 HELLO    | `build_ospf_hello`                   |
| DNS A/AAAA      | `build_dns_query`                    |
| DHCP DISCOVER   | `build_dhcp_discover`                |
| RADIUS          | `build_radius`                       |
| **anything else** | `build_raw_ip(proto=N, payload=…)`  |

Every IP-bearing builder takes an optional `probe_id: int`.
The controller stashes the probe's identifier into the IPv4
`id` field (16 bits) or the IPv6 flow label (20 bits). The
worker's parser reads it back into `PacketSummary.probe_id`,
and the controller correlates observed packets by this single
primary key — resilient to DNAT, SNAT, or any tuple mangling.

### Test categories

| category   | source of expectation |
|------------|-----------------------|
| `POSITIVE` | iptables-save chain rule with target ACCEPT |
| `NEGATIVE` | iptables-save chain rule with target DROP / REJECT |
| `RANDOM`   | routable random (src, dst, proto, port) classified by a ruleset oracle |

`simlab/oracle.py` parses the iptables dump once and answers
`classify(src_zone, dst_zone, src_ip, dst_ip, proto, port)` by
walking the `<src>2<dst>` chain and returning the first rule
that matches. `simlab/random` picks tuples from the routable
FW subnets so no probe is silently dropped by rp_filter.

### Run archive

Every `smoketest full` invocation writes three files under
`docs/testing/simlab-reports/<UTC-timestamp>/`:

- `report.json` — structured dump of environment, topology,
  timings, resource peaks, per-category stats, and every probe
  with its expected/observed verdict. For machine diffing.
- `report.md` — human-readable markdown with the same data
  formatted as a table.
- `mismatches.txt` — one line per probe whose observed verdict
  didn't match expectation. Grep-friendly for "is this
  regression new this week?" queries.

Environment captured includes kernel, Python, scapy, nft,
shorewall-nft version, and the git HEAD at the time of the run.

## Usage

simlab now ships as the standalone `shorewall-nft-simlab` package,
installed alongside `shorewall-nft`. Two entry points are available:

- `shorewall-nft-simlab` — simlab-native CLI with four subcommands
  (`smoke`, `stress`, `limit`, `full`). Use this for deep-dive runs,
  stress-testing, or when you want the full JSON / Markdown report.
- `shorewall-nft simulate --data DIR` — delegates to simlab through
  the programmatic API (`shorewall_nft_simlab.api.run_simulation_from_config`).
  Use this from the normal shorewall-nft workflow when a live
  snapshot of the firewall is handy.

Both accept the same `--data DIR` snapshot produced by
`tools/simlab-collect.sh`. See the end-to-end example below.

### simlab-native CLI

```
shorewall-nft-simlab [--data DIR] [--config DIR] [--load-limit N]
                     [--report-dir DIR] COMMAND [OPTIONS]

Global:
  --data       Directory with ip4add/ip4routes/ip6add/ip6routes + iptables.txt
               (default /root/simulate-data)
  --config     shorewall config directory
               (default /etc/shorewall46)
  --load-limit Pause new cycles while 1-min loadavg >= this       (default 4.0)
  --report-dir Archive directory override                         (default docs/testing/simlab-reports)

Commands:
  smoke           one build, three representative probes, destroy
  stress N        N × (build + destroy) with per-cycle + overall peak sampling
  limit           run cycles until something breaks
  full [opts]     per-rule POSITIVE+NEGATIVE coverage + N random probes,
                  archives a report
    --max-per-pair N   cap probes per <src>2<dst> chain (default 10000 ≈ all)
    --random N         number of random probes (default 50)
    --seed SEED        random seed (default = wall clock)
    -v / --verbose     dump raw sysctl values before the run
```

### End-to-end workflow

Typical cycle: capture live state from the running firewall → ship it
to a simulation host → run probes → read the report. All four steps
are plain shell commands; simlab itself is the only moving piece.

```bash
# ─── On the source firewall (producer of the snapshot) ─────────────
# Tier 1 dumps (ip addr/route/rule/link + rt_tables + dynamic-routing
# daemon RIB) are unprivileged.  Tier 2 dumps (iptables-save /
# nft list ruleset / ipset save / conntrack) need root.  sudo grabs
# both tiers at once.
sudo /path/to/shorewall-nft/tools/simlab-collect.sh \
     --output /tmp/fw-snapshot
cat /tmp/fw-snapshot/manifest.txt       # per-capture status — every
                                         # line should say "captured"
                                         # after sudo
sudo tar -C /etc -czf /tmp/fw-config.tar.gz shorewall46
                                         # shorewall config is
                                         # root-owned; bundling needs
                                         # sudo

# ─── Transfer to the simulation host ───────────────────────────────
rsync -a /tmp/fw-snapshot       user@simlab-host:/var/tmp/
rsync -a /tmp/fw-config.tar.gz  user@simlab-host:/var/tmp/

# ─── On the simulation host (consumer) ─────────────────────────────
ssh user@simlab-host <<'EOF'
    sudo mkdir -p /etc/shorewall46
    sudo tar -C /etc -xzf /var/tmp/fw-config.tar.gz

    # Route 1 — delegate via the shorewall-nft CLI.  Prints the
    # classic "Results: N passed / M failed" summary familiar from
    # `shorewall-nft simulate`.
    shorewall-nft simulate \
        --config-dir /etc/shorewall46 \
        --data       /var/tmp/fw-snapshot

    # Route 2 — run simlab directly for the full JSON + Markdown
    # report (useful when triaging false-drop / false-accept
    # mismatches).
    shorewall-nft-simlab \
        --data   /var/tmp/fw-snapshot \
        --config /etc/shorewall46 \
        full --max-per-pair 30 --seed 42
EOF

# ─── Pull the report archive back for git / ticket attachments ────
rsync -a user@simlab-host:/root/shorewall-nft/docs/testing/simlab-reports/ \
        ./simlab-reports/
```

### Reading the output

**Route 1 (`shorewall-nft simulate --data`)** prints a one-line
summary plus one line per failing probe:

```
Simulating /etc/shorewall46 via simlab against /var/tmp/fw-snapshot

Results: 184 passed, 3 failed (187 total)
  FAIL   per_rule  eth0 -> eth1  expect=DROP    got=ACCEPT  14.2ms tcp 192.0.2.5 -> 203.0.113.10:22
  FAIL   random    eth1 -> eth0  expect=ACCEPT  got=NONE   250.0ms icmp echo
  FAIL   per_rule  eth0 -> eth2  expect=ACCEPT  got=DROP    11.8ms udp 198.51.100.1 -> 192.0.2.5:53
```

Exit code is 0 when every probe passed, 1 on any failure, so the
command slots cleanly into CI or pre-merge gates.

**Route 2 (`shorewall-nft-simlab full`)** additionally writes an
archive under `<report-dir>/<UTC>/`:

- `report.json` — structured record: per-probe tuples, per-category
  pass-accept / pass-drop / **fail-drop** / **fail-accept** split
  (see `docs/PRINCIPLES.md` P5), timings, peaks, resource delta,
  sysctl warnings.
- `report.md` — the same data rendered as Markdown for ticket
  attachments.
- `mismatches.txt` — failing tuples only, one per line.

Investigation workflow:

1. Open `report.md`; find the category with the highest `fail_accept`
   or `fail_drop` count.
2. Drill into the matching probe in `report.json` via `probe_id`;
   read `oracle_reason` (the rule the oracle believes should fire)
   and `desc` (source/dest tuple + proto/port).
3. On the real firewall, `nft trace` the same tuple to confirm
   whether the simulated verdict matches the live verdict. Match →
   genuine rule-ordering bug in the shorewall config. Mismatch →
   point-of-truth contract (`docs/testing/point-of-truth.md`) applies:
   the iptables dump wins over simlab, so update the fixture /
   compiler emit accordingly.

### When `simlab-collect.sh` cannot run as root

The snapshot is still useful — Tier 1 captures alone are enough for
simlab to build its topology (addresses + routes + rules). Only
the netfilter ruleset dumps are missing. Run the collector
unprivileged and separately have an operator produce the privileged
captures:

```bash
sudo sh -c '
    iptables-save  > /tmp/iptables.txt
    ip6tables-save > /tmp/ip6tables.txt
'
mv /tmp/iptables.txt /tmp/ip6tables.txt /tmp/fw-snapshot/
```

Simlab picks them up automatically — it reads by filename, not from
the manifest.

### Archive location

Reports land under `/root/shorewall-nft/docs/testing/simlab-reports/<UTC>/`
by default on the simulation host. Override via `--report-dir DIR`.
`rsync` them back to your workstation for git commit or ticket
attachment.

## Performance baseline (reference VM, 2 cores, 4.9 GB RAM)

Measured on the final run with the single-process asyncio
architecture (no worker subprocesses):

| metric            | value                                          |
|-------------------|------------------------------------------------|
| build time        | ~1.1 s per cycle                               |
| nft ruleset load  | ~3.0 s (24 ifaces, libnftables path)           |
| probe throughput  | **~125 probes/s** (batch-size 256, 2 s timeout)|
| RSS, total        | **~215 MB** (controller) + ~30 MB (nsstub)     |
| peak fd usage     | ~50 during run (24 TUN/TAP + pipes)            |
| peak procs        | 1 controller + 1 stub = **2 processes**        |
| fd leak           | 0                                              |
| netns leak        | 0                                              |
| interface leak    | 0                                              |

For reference, the pre-refactor subprocess-based architecture
measured:

| metric            | subprocess model | single-process model | Δ     |
|-------------------|-----------------:|---------------------:|-------|
| RSS (total)       | ~2 GB            | ~245 MB              | **8×** better |
| probe throughput  | ~20 probes/s     | ~125 probes/s        | **6×** better |
| peak procs        | 24 workers + stub + controller | 1 + 1 | **-24** |
| nft ruleset load  | ~7–9 s           | ~3.0 s               | ~2.5× |

The gains are from removing per-interface Python interpreter
overhead (~80 MB × 24 = ~2 GB) and replacing the
worker/pipe/asyncio indirection with a single event loop + a
direct `os.write(fd, payload)` inject path.

## sysctl health check

Before each `full` run the harness warns on the following:

- `/proc/sys/fs/file-max` below 65536
- `/proc/sys/fs/nr_open` below 65536
- `/proc/sys/kernel/pid_max` below 65536
- `/proc/sys/net/core/somaxconn` below 1024
- `/proc/sys/net/core/rmem_max` / `wmem_max` below 1 MiB
- `/proc/sys/net/netfilter/nf_conntrack_max` below 131072
- CPU governor anything other than `performance`
- `/proc/sys/net/ipv4/ip_forward != 1`
- `/proc/sys/net/ipv4/conf/all/rp_filter != 0`

Warnings are printed at the top of the run and stored in the
archived `report.json` / `report.md` under `sysctl_warnings`
so reviewers can attribute performance anomalies to
configuration rather than code.

## IP family selection (--family)

Both CLIs accept a `--family {4,6,both}` flag (default `both`) that
controls which IP families are exercised. When omitted the family is
**auto-detected** from the dump files present in `--data`:

| Files present | Effective family |
|---|---|
| `iptables.txt` only | `4` |
| `ip6tables.txt` only | `6` |
| Both | `both` |

Passing an explicit `--family` that is unsatisfied by the available
dumps is an error (e.g. `--family 6` with no `ip6tables.txt`).

### Examples

```bash
# IPv4-only run — faster when no ip6tables.txt is available
shorewall-nft-simlab --data /tmp/fw-snap --family 4 full

# IPv6-only run — target v6 rule regressions specifically
shorewall-nft-simlab --data /tmp/fw-snap --family 6 full --verbose

# Dual-stack (default) — both v4 and v6 probes in a single pass
shorewall-nft-simlab --data /tmp/fw-snap full

# Via the shorewall-nft CLI
shorewall-nft simulate --data /tmp/fw-snap --family 4
shorewall-nft simulate --data /tmp/fw-snap --family 6
shorewall-nft simulate --data /tmp/fw-snap               # auto-detects
```

### v6 probe parity

IPv6 probes run at the same quality level as IPv4:

- **Per-rule probes** (`_build_per_rule_probes`): derives test cases from
  ip6tables.txt chain rules, replaces placeholder source IPs with
  zone-local IPv6 addresses via `_build_zone_to_concrete_src(family=6)`,
  and re-classifies each probe via the ip6tables oracle.
- **Random probes** (`RandomProbeGenerator`): includes IPv6 subnets from
  the FwState address dump in the candidate pool.  v6 probes use
  `icmpv6` instead of `icmp` and 20-bit flow-label probe IDs.
- **NDP warmup** (`_ndp_warmup`): fires throw-away ICMPv6 probes to every
  unique v6 destination before the real batch so neighbor cache entries
  are warm and the first real batch does not flood the NDP path.

## Shared infrastructure (netkit validators)

Both `simulate.py` and simlab consume a shared validator layer that lives in
`shorewall-nft-netkit/shorewall_nft_netkit/validators/`.  Moving the
validators there (Phase II of the dual-stack plan) means:

- Any runtime that imports from `shorewall_nft_netkit` can run the same
  validators without duplicating code.
- Every validator accepts `ns_name` as a keyword argument, so it can operate
  inside any named network namespace — not just the fixed `simulate.py`
  names.
- The socket-based TCP/UDP/ICMP injector in `run_small_conntrack_probe`
  runs in the **calling process's network namespace**, removing the
  dependency on a separate NS_SRC namespace.

### API surface

```python
from shorewall_nft_netkit.validators import (
    validate_tc,          # TC script generation + device check
    validate_sysctl,      # sysctl conformance vs shorewall config
    validate_routing,     # IP forwarding + interface presence
    validate_nft_loaded,  # nft table loaded + base chains present
    run_all_validations,  # orchestrator (runs all four above)
    run_small_conntrack_probe,  # 4-probe conntrack sanity check
    ValidationResult,
    ConnStateResult,
)
```

All functions default `ns_name` to `"shorewall-next-sim-fw"` for
backward compatibility with `simulate.py` callers that don't pass it.

### `ns_name` parameter

Pass `ns_name=<your_fw_netns>` to run any validator inside a non-default
namespace:

```python
results = run_small_conntrack_probe(dst_ip="10.1.2.3", ns_name="simlab-fw")
warnings = [r for r in results if not r.passed]
```

### `validation_warnings` in simlab reports (Phase III)

Phase III of the dual-stack plan wires `validate_tc` and
`run_small_conntrack_probe` into simlab's `cmd_full` post-load hook.
Results will appear in `report.json` under `validation_warnings`:

```json
{
  "validation_warnings": [
    {"name": "ct:tcp_flow_tracked", "passed": false,
     "detail": "tcp conntrack entries after probe: 0", "ms": 12}
  ]
}
```

A non-empty `validation_warnings` list means the firewall is running but
conntrack or TC configuration may not match what the config expects.

### Back-compat shims

The original modules `shorewall_nft.verify.tc_validate` and
`shorewall_nft.verify.connstate` are now thin re-export shims.  Existing
callers continue to work unchanged.  New code should import directly from
`shorewall_nft_netkit.validators`.

## Known limitations

- **Single NS_FW.** HA pair simulation (two FW namespaces
  exchanging VRRP + conntrackd sync) is on the roadmap.
- **Flowtable offload** is not exercised by packet tests yet —
  the 1.1 FLOWTABLE directive emits the stanza, and `nft -c`
  validates it, but we don't actually test fastpath traversal.
- **pcap-on-failure** is wired on the packet-builder side
  (`packets.export_trace_pcap`) but not yet attached to the
  controller's post-run cleanup. Top item on the roadmap.
