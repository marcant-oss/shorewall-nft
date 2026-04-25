# shorewalld — monitoring + DNS-set API daemon

`shorewalld` is the long-running companion process to `shorewall-nft`.
It serves three jobs:

1. **Prometheus exporter** — scrapes per-rule packet/byte counters out
   of every `inet shorewall` table on the box, across multiple network
   namespaces, via a single libnftables round-trip per scrape.
2. **DNS-set API** *(opt-in)* — accepts a dnstap FrameStream from
   `pdns_recursor` and populates nft sets named `dns_<qname>_v4` /
   `dns_<qname>_v6` from DNS responses, so firewall rules can filter
   on hostname without runtime resolution.
3. **IP-list sets** *(opt-in)* — periodically fetches public prefix
   lists from cloud providers, CDNs, IX route servers, and RFC bogon
   definitions, and writes them into nft `flags interval` sets so
   firewall rules can match on cloud service, ASN, or IX membership.

Running `shorewalld` with no flags starts a pure exporter bound to `:9748`.

## Configuration file

Operator settings live in `shorewalld.conf`, searched at these
locations in order (first hit wins):

1. `--config-file PATH` on the CLI
2. `/etc/shorewalld.conf`
3. `/etc/shorewall/shorewalld.conf`

A missing file is a silent no-op; the daemon falls back entirely
to CLI flags + built-in defaults. **Precedence** is always:
explicit CLI flag > config-file value > built-in default, so an
operator can temporarily override a file value without editing
the file.

Shell-flavoured `KEY=value` lines, `#` comments, optional `'`/`"`
quoting:

```
# /etc/shorewall/shorewalld.conf

LISTEN_PROM=:9748
NETNS=fw,rns1,rns2
SCRAPE_INTERVAL=30
REPROBE_INTERVAL=300

# Multi-instance (repeat INSTANCE= for each directory)
INSTANCE=fw:/etc/shorewall
INSTANCE=rns1:/etc/shorewall-rns1

# Control socket
CONTROL_SOCKET=/run/shorewalld/control.sock
# CONTROL_SOCKET_NETNS=fw      # optional: bind inside netns

# IP-list sets (one block per set; see "IP-list sets" section)
IPLIST_BOGON_PROVIDER=bogon
IPLIST_BOGON_SET_V4=bogon_v4
IPLIST_BOGON_SET_V6=bogon_v6

# Legacy — use INSTANCE= instead
# ALLOWLIST_FILE=/var/lib/shorewalld/dns-allowlist.tsv
LISTEN_API=/run/shorewalld/dnstap.sock
PBDNS_SOCKET=/run/shorewalld/pbdns.sock
PBDNS_TCP=127.0.0.1:9999       # pdns protobufServer() is TCP-only

# Unix socket ownership applied to every daemon-owned socket
# (LISTEN_API, PBDNS_SOCKET). Typical production shape: 0660
# with SOCKET_GROUP=pdns so the recursor can connect as its
# normal non-root user. Owner defaults to the shorewalld
# process UID (usually root); group defaults to unchanged.
SOCKET_MODE=0660
SOCKET_OWNER=root
SOCKET_GROUP=pdns

PEER_LISTEN=0.0.0.0:9749
PEER_ADDRESS=10.0.0.2:9749
PEER_SECRET_FILE=/etc/shorewall/peer.key
PEER_HEARTBEAT_INTERVAL=5

STATE_DIR=/var/lib/shorewalld
STATE_PERSIST_INTERVAL=30

LOG_LEVEL=info
LOG_TARGET=syslog
LOG_FORMAT=structured
LOG_LEVEL_peer=debug   # per-subsystem override

# NFLOG log dispatcher — see "NFLOG log dispatcher" section below.
LOG_DISPATCH=shorewalld            # shorewalld | ulogd2 | none
LOG_NFLOG_GROUP=1                  # matches ``nft log group N``
LOG_DISPATCH_FILE=/var/log/shorewall-nft.log
LOG_DISPATCH_SOCKET=/run/shorewalld/log.sock
LOG_DISPATCH_JOURNALD=yes
LOG_DISPATCH_SYSLOG=/dev/log
```

Unknown keys are silently ignored so adding future knobs doesn't
break older deployments. Malformed lines or unparseable values
(e.g. `STATE_ENABLED=maybe`) raise an error at startup — the
daemon refuses to run with a broken config rather than silently
falling back.

## NFLOG log dispatcher

When a ruleset emits matches via `nft log group N` (or Shorewall's
`LOG_BACKEND=netlink`), something has to read the `nfnetlink_log`
netlink family and turn it into operator-visible output. Historical
choice: one `ulogd2` systemd unit per netns with its own
`ulogd.conf` — fine but a lot of plumbing at scale.

shorewalld can absorb this role: the daemon is already running
per-netns as the fork-and-setns host for stats, conntrack, and
DNS-set work, so each worker just opens a second `nfnetlink_log`
subscription inside its netns. Decoded events flow back to the
parent via the existing worker SEQPACKET pair, become a Prometheus
counter (always on), and optionally fan out to up to four sinks.

### Config

```
# Enable (default is ``none``). ``ulogd2`` means operator runs
# their own per-netns ulogd2; shorewalld does NOT subscribe.
LOG_DISPATCH=shorewalld

# nfnetlink_log group to subscribe to in every managed netns.
# Must match the ``N`` in ``nft log group N`` / the
# shorewall-nft ``LOG_BACKEND=netlink,<N>`` directive.
LOG_NFLOG_GROUP=1

# Optional plain-text sink (one line per event).
# Format: ``<ts> netns=<X> chain=<Y> disposition=<Z> [rule=<N>]``
LOG_DISPATCH_FILE=/var/log/shorewall-nft.log

# Optional unix-socket sink — any client connected over
# AF_UNIX/SOCK_STREAM receives newline-JSON events. Multi-subscriber;
# slow clients are disconnected, not throttled.
LOG_DISPATCH_SOCKET=/run/shorewalld/log.sock

# Optional systemd-journald sink (structured fields
# SHOREWALL_CHAIN, SHOREWALL_DISPOSITION, SHOREWALL_NETNS,
# SHOREWALL_RULE_NUM, SHOREWALL_NFLOG_TS, plus PRIORITY mapped
# from disposition: DROP/REJECT=4, ACCEPT=6, other=5).
LOG_DISPATCH_JOURNALD=yes

# Optional /dev/log sink (RFC 3164 datagrams). LOCAL0 facility;
# PRI byte maps severity from disposition.
LOG_DISPATCH_SYSLOG=/dev/log
```

Sinks are additive — enable any combination from none (counter-only)
to all four at once. Each has its own bounded queue; enabling more
sinks does not slow the Prometheus counter path.

### Metrics

* `shorewall_log_total{chain,disposition,netns}` — monotonic per
  observed triple.
* `shorewall_log_events_total` — label-free grand total.
* `shorewall_log_dropped_total{reason}` — backpressure drops,
  keyed on `reason="sink_file"|"sink_socket"|"sink_journald"|"sink_syslog"`.
  Non-zero means a downstream consumer is slow and events were
  dropped to keep the hot path running.

### Backpressure contract

Every sink is **drop-on-full, never block**. The ingest path is
hot-path-critical and runs on the asyncio event loop; a slow file or
SIEM consumer must never stall firewall event logging or (worse)
back-pressure into the per-netns worker. The guarantees:

* Worker-side NFLOG push uses `MSG_DONTWAIT` sendmsg — if the parent
  event loop is busy and the SEQPACKET rcvbuf fills, events drop at
  the worker (rate-limited warning log) rather than stalling batch +
  read RPCs.
* Parent-side `on_event` is synchronous on the event-loop thread;
  counter bumps and per-sink `put_nowait` are O(1) and never await.
* Each sink has its own bounded queue (1024 events default); on
  `QueueFull` the event is dropped and the per-sink counter bumps.
* Unix-socket sink has an additional per-client queue (256); slow
  clients are disconnected rather than dragging the broadcaster.

Check `shorewall_log_dropped_total` in Prometheus to detect slow
sinks. Sustained drops mean operator action: bigger
`LOG_NETLINK_RCVBUF` (follow-up), faster downstream consumer, or
dropping a sink that's not keeping up.

### Capability requirements

NFLOG subscription requires `CAP_NET_ADMIN` on the worker process —
already granted to the shipping `shorewalld.service` /
`shorewalld@.service` unit via `AmbientCapabilities`. No additional
sysconfig needed.

## keepalived integration

shorewalld can monitor keepalived (VRRP failover daemon) via SNMP over a
Unix socket, subscribe to keepalived SNMP traps, and surface the
state-changing keepalived D-Bus methods (`PrintData`, `PrintStats`,
`ReloadConfig`, `SendGarp`) through the control socket.

Enable with `KEEPALIVED_SNMP_UNIX=/run/snmpd/snmpd.sock` in
`shorewalld.conf`.  When set, the daemon performs a full MIB walk every
30 seconds (configurable), auto-registers one Prometheus family per MIB
column, and feeds SNMP traps into `shorewalld_keepalived_events_total`.
No code changes are needed when keepalived adds new OIDs — the committed
`mib.py` constants file is regenerated via `tools/gen_keepalived_mib.py`.

Requirements: `python3-netsnmp` (distro package — `apt install python3-netsnmp`
or `dnf install net-snmp-python3`) for SNMP walks; `pysnmp>=7.0` for trap
reception; `dbus-next>=0.2.3` for the D-Bus method surface.  All three
are optional: a missing library soft-degrades the corresponding subsystem
with a warning log at startup rather than aborting the daemon.

See [`docs/shorewalld/keepalived-snmp.md`](keepalived-snmp.md) for the
full operator reference including snmpd configuration, keepalived flags,
every `KEEPALIVED_*` knob, the D-Bus ACL, the Prometheus family naming
convention, control-socket commands, troubleshooting, and migration from
the legacy `VRRP_SNMP_*` UDP path.

## systemd integration

Both shipping unit files (`shorewalld.service`,
`shorewalld@.service`) declare:

```ini
Type=notify
NotifyAccess=main
WatchdogSec=30s
```

The daemon implements the `sd_notify(3)` protocol natively (pure
Python, no `libsystemd` link, no extra dependency). When
`$NOTIFY_SOCKET` is unset — dev runs, containers without systemd,
unit tests — every notification call is a silent no-op, so the
same binary works in both worlds.

### Startup ordering (`Type=notify`)

`READY=1` fires only after the daemon has finished initialising:

* Prometheus port bound
* netns profiles built and worker router live
* DNS pipeline + InstanceManager ready (when configured)
* dnstap / pbdns / log-dispatcher servers bound
* control socket accepting connections

Until that point systemd reports the unit as `activating`. Other
units that declare `After=shorewalld.service` start at the right
moment instead of racing daemon init. Without `Type=notify` systemd
would consider the unit `active` the instant the Python interpreter
forks — even if `bind(:9748)` crashes 200 ms later.

### Watchdog (`WatchdogSec=30s`)

The daemon runs a background task that pings `WATCHDOG=1` every
~10 s. If the asyncio event loop wedges (a sync call slipped into
the hot path, a netlink read hangs, a collector blocks) systemd
sees no ping inside 30 s and SIGKILLs + restarts the unit. Combined
with the existing per-netns `ParentWorker._auto_respawn` this
catches both the "one worker died" and the "main loop hung" failure
modes.

Tune the timeout via a drop-in if 30 s is too aggressive (e.g.
operators running with `--scrape-interval 60` and very wide netns
sets):

```ini
# /etc/systemd/system/shorewalld.service.d/watchdog.conf
[Service]
WatchdogSec=120s
```

Set `WatchdogSec=0` to disable entirely — the daemon's ping task
silently does nothing when systemd has not armed a watchdog.

### `systemctl status` one-liner (`STATUS=…`)

The same background task refreshes the `STATUS=` text shown by
`systemctl status shorewalld`:

```
$ systemctl status shorewalld
● shorewalld.service - shorewall-nft monitoring + DNS-set API daemon
     Active: active (running) since Fri 2026-04-25 14:01:23 UTC; 12s ago
     Status: "prom=:9748 netns=3 sets=8 elements=412 ingress=dnstap,pull,iplist,ctl"
   Main PID: 12345 (shorewalld)
```

Fields:

| Token | Meaning |
|---|---|
| `prom=HOST:PORT` | Prometheus scrape endpoint |
| `netns=N` | number of netns profiles being scraped |
| `sets=N` | DNS sets declared in the tracker |
| `elements=N` | live set elements across all DNS sets |
| `ingress=…` | comma list of active subsystems: `dnstap`, `pbdns`, `pull`, `peer`, `iplist`, `ctl` |

The line refreshes every ~10 s without contending with the hot
path — only cheap O(1) accessors are read.

### Reload semantics (`ExecReload=`)

The shipping unit uses `ExecReload=/bin/kill -USR1 $MAINPID`. The
SIGUSR1 handler triggers an iplist refresh and wraps it in
`RELOADING=1` / `READY=1` notifications, so `systemctl reload
shorewalld` reports correctly when the refresh finishes.

For operators who prefer the dynamic registration path
(`shorewall-nft start` notifies via the control socket — see
[Multi-instance operation](#multi-instance-operation--instance)),
SIGUSR1 / `systemctl reload` is optional.

### Shutdown (`STOPPING=1`)

`STOPPING=1` is sent as the first action of the async shutdown
sequence, before any subsystem teardown. systemd flips the unit
state to `deactivating` immediately so monitoring and dependent
units do not see a stale `active` while the daemon flushes set
writers, peer link, state store, and worker router.

## Install

Ships as part of the `shorewall-nft` package. The daemon itself is the
`shorewalld` script entry point:

```sh
# Pip install with optional deps.
pip install 'shorewall-nft[daemon]'

# Distro install — the binary is in the main shorewall-nft package.
apt install shorewall-nft
```

Runtime dependencies beyond `shorewall-nft` itself:

- `prometheus_client>=0.20` — scrape HTTP endpoint
- `dnspython>=2.4` — DNS wire parse (only needed when `--listen-api`
  is used)

Both live under the `[daemon]` extra in `pyproject.toml`. Debian and
RPM packages declare them as recommends, not hard depends, so the
main firewall compiler can still install on a minimal box.

## CLI

```
shorewalld [OPTIONS]

  --listen-prom HOST:PORT          Prometheus scrape endpoint (default :9748)
  --listen-api PATH                Unix socket for the dnstap consumer
  --netns SPEC                     Namespace selection:
                                      (empty)       → daemon's own netns
                                      auto          → walk /run/netns/
                                      fw,rns1,rns2  → explicit comma list
  --instance [NETNS:]DIR           shorewall-nft config directory (repeat
                                   for multiple instances). Replaces
                                   --allowlist-file.
  --control-socket PATH            Unix socket for the control API
                                   (refresh-iplist, reload-instance, …)
  --control-socket-netns NETNS     Bind the control socket inside this netns
  --scrape-interval SECS           Per-netns ruleset cache TTL (default 30)
  --reprobe-interval SECS          How often to re-check netns tables (default 300)
  --log-level LEVEL                debug, info, warning, error

Subcommands:
  shorewalld tap [OPTIONS]         Live dnstap inspection (see below)
  shorewalld ctl [OPTIONS] CMD     Control socket client
  shorewalld iplist [OPTIONS] CMD  IP-list provider explorer
```

## Metrics

All metrics carry a `netns` label (empty string = the daemon's own
namespace). Scrape endpoint is Prometheus plain-text at
`http://HOST:PORT/metrics`.

For the complete metric reference — including nfsets observability,
resolver per-set counters, and VRRP (keepalived D-Bus + SNMP) metrics —
see **[docs/shorewalld/metrics.md](metrics.md)**.

**VRRP observability** (`--enable-vrrp-collector`): the `VrrpCollector`
scrapes keepalived instance state, priority, and master-transition counts
from D-Bus (optionally augmented via SNMP with `--vrrp-snmp-enable`).
On AlmaLinux 10 / RHEL 10 where keepalived ships without D-Bus support,
enable SNMP-only mode. See [metrics.md](metrics.md) for the full flag
reference and PromQL alert examples.

### Rule and set metrics (one per netns with a loaded ruleset)

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_packets_total` | Counter | `netns,table,chain,rule_handle,comment` |
| `shorewall_nft_bytes_total` | Counter | `netns,table,chain,rule_handle,comment` |
| `shorewall_nft_named_counter_packets_total` | Counter | `netns,name` |
| `shorewall_nft_named_counter_bytes_total` | Counter | `netns,name` |
| `shorewall_nft_set_elements` | Gauge | `netns,set` |

The `comment` label carries the rule's `?COMMENT` tag verbatim, so you
can identify rules from the Shorewall config even though nft handles
are opaque.

### Per-interface metrics (one per netns, always emitted)

Sourced from `RTM_GETLINK` → `IFLA_STATS64` in one netlink dump per
scrape. All counters are zero for an interface that never flaps; fields
the running kernel does not populate (e.g. `rx_nohandler` on older
kernels) are silently skipped rather than reported as zero.

**Traffic**

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_iface_rx_packets_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_rx_bytes_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_tx_packets_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_tx_bytes_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_multicast_total` | Counter | `netns,iface` — RX multicast packets |
| `shorewall_nft_iface_rx_compressed_total` | Counter | `netns,iface` |
| `shorewall_nft_iface_tx_compressed_total` | Counter | `netns,iface` |

**Error / drop counters** — watch these for cable, NIC, or ring-buffer
trouble. `rx_missed_errors` climbing under steady traffic is the
canonical "ring buffer too small / IRQ coalescing wrong" signal;
`rx_crc_errors` points at cable or SFP integrity.

| Metric | Type | Labels | Source field |
|---|---|---|---|
| `shorewall_nft_iface_rx_errors_total` | Counter | `netns,iface` | generic RX error total |
| `shorewall_nft_iface_tx_errors_total` | Counter | `netns,iface` | generic TX error total |
| `shorewall_nft_iface_rx_dropped_total` | Counter | `netns,iface` | RX dropped (no buffer, filters) |
| `shorewall_nft_iface_tx_dropped_total` | Counter | `netns,iface` | TX dropped before transmit |
| `shorewall_nft_iface_collisions_total` | Counter | `netns,iface` | late collisions (legacy HDX) |
| `shorewall_nft_iface_rx_length_errors_total` | Counter | `netns,iface` | malformed frame length |
| `shorewall_nft_iface_rx_over_errors_total` | Counter | `netns,iface` | frame larger than NIC buffer |
| `shorewall_nft_iface_rx_crc_errors_total` | Counter | `netns,iface` | cable / SFP integrity |
| `shorewall_nft_iface_rx_frame_errors_total` | Counter | `netns,iface` | frame alignment errors |
| `shorewall_nft_iface_rx_fifo_errors_total` | Counter | `netns,iface` | RX FIFO overruns |
| `shorewall_nft_iface_rx_missed_errors_total` | Counter | `netns,iface` | ring-buffer drops the driver never saw |
| `shorewall_nft_iface_rx_nohandler_total` | Counter | `netns,iface` | no protocol handler registered (kernel 4.6+) |
| `shorewall_nft_iface_tx_aborted_errors_total` | Counter | `netns,iface` |  |
| `shorewall_nft_iface_tx_carrier_errors_total` | Counter | `netns,iface` | carrier lost (link flaps, negotiation) |
| `shorewall_nft_iface_tx_fifo_errors_total` | Counter | `netns,iface` |  |
| `shorewall_nft_iface_tx_heartbeat_errors_total` | Counter | `netns,iface` |  |
| `shorewall_nft_iface_tx_window_errors_total` | Counter | `netns,iface` |  |

**Oper state, carrier transitions, MTU**

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_iface_oper_state` | Gauge | `netns,iface` — 1=UP, 0=DOWN, 0.5=UNKNOWN |
| `shorewall_nft_iface_carrier_changes_total` | Counter | `netns,iface` — cumulative link up↔down transitions |
| `shorewall_nft_iface_mtu` | Gauge | `netns,iface` — current link MTU in bytes |

`carrier_changes_total` is the authoritative kernel counter for physical-
layer flap: a jump without a simultaneous VRRP transition points at a
cable/SFP/switch-port problem, a jump *with* a VRRP transition is the
expected signature of a failover drill. `iface_mtu` catches
jumbo-negotiation regressions after an LACP reconfigure.

### Qdisc metrics (one per netns, always emitted)

Sourced from `RTM_GETQDISC` via pyroute2. One dump per scrape per
netns — the same data `tc -s qdisc show` prints — but emitted as
structured Prometheus metrics rather than text. Every qdisc (root,
ingress, clsact, per-class) shows up as its own series labelled with
the interface name, the qdisc `kind` (`fq_codel`, `pfifo_fast`,
`noqueue`, …), and the tc `major:minor` handle.

Labels: `netns,iface,kind,handle,parent`. `parent="root"` means this
is a root qdisc (`TC_H_ROOT = 0xffffffff`); `parent="none"` means
unspecified (typical for ingress/clsact). `handle` and `parent` are
rendered in tc hex notation (`1:0`, `abc:1234`).

| Metric | Type | Description |
|---|---|---|
| `shorewall_nft_qdisc_bytes_total` | Counter | Bytes passed through the qdisc |
| `shorewall_nft_qdisc_packets_total` | Counter | Packets passed through the qdisc |
| `shorewall_nft_qdisc_drops_total` | Counter | Packets dropped (overflow + policing) |
| `shorewall_nft_qdisc_requeues_total` | Counter | Packets requeued after driver pushback |
| `shorewall_nft_qdisc_overlimits_total` | Counter | Rate/class ceiling hits |
| `shorewall_nft_qdisc_qlen` | Gauge | Current queue length (packets) |
| `shorewall_nft_qdisc_backlog_bytes` | Gauge | Current backlog (bytes) |
| `shorewall_nft_qdisc_rate_bps` | Gauge | Rate-estimator bytes/s (0 unless `tc … est` configured) |
| `shorewall_nft_qdisc_rate_pps` | Gauge | Rate-estimator packets/s (0 unless `tc … est` configured) |

Counter values come from `TCA_STATS2` when present (kernel 3.18+,
adds `requeues`), falling back to the legacy flat `TCA_STATS` for
bps/pps and on older kernels.

### Conntrack metrics (one per netns)

**Table occupancy + hash load + FIB size** — sourced from
`/proc/sys/net/netfilter/` and `/proc/net/{route,ipv6_route}`, all
reads delegated to the netns-pinned nft worker so the scrape thread
never runs `setns(2)` itself (see
[Architecture → netns-pinned reads](#architecture--netns-pinned-reads)).

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_ct_count` | Gauge | `netns` — current conntrack entries |
| `shorewall_nft_ct_max` | Gauge | `netns` — `nf_conntrack_max` sysctl |
| `shorewall_nft_ct_buckets` | Gauge | `netns` — hash bucket count (`nf_conntrack_buckets`) |
| `shorewall_nft_fib_routes` | Gauge | `netns,family` — line count of `/proc/net/route` (v4) / `/proc/net/ipv6_route` (v6) |

`count / buckets` is the mean conntrack hash-chain length: above 4 the
lookup cost pushes perceptibly; above 16 it dominates forwarding
latency — raise `nf_conntrack_buckets`. `fib_routes{family="ipv4"}`
collapsing on a BGP-speaking router is the canonical "session went
away" signal, cheaper to alert on than watching bird's state file.

**Engine counters** — sourced from `CTNETLINK IPCTNL_MSG_CT_GET_STATS_CPU`
via `NFCTSocket.stat()`. Per-CPU rows are summed into one value per
netns — the per-CPU identity is never a stable Prometheus label and
the aggregate is what alerting rules care about. Requires
`CAP_NET_ADMIN`; the daemon typically runs as root, an unprivileged
run surfaces the metric families with no samples rather than
erroring.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `shorewall_nft_ct_found_total` | Counter | `netns` | Lookups that matched an existing entry (most packets) |
| `shorewall_nft_ct_invalid_total` | Counter | `netns` | Packets whose state could not be tracked — malformed, bad seq |
| `shorewall_nft_ct_ignore_total` | Counter | `netns` | Packets not subjected to conntrack (e.g. `NOTRACK`) |
| `shorewall_nft_ct_insert_failed_total` | Counter | `netns` | Insertions that lost a race with a concurrent flow |
| `shorewall_nft_ct_drop_total` | Counter | `netns` | **Packets dropped because the conntrack table was full** |
| `shorewall_nft_ct_early_drop_total` | Counter | `netns` | Entries evicted early to make room in a full table |
| `shorewall_nft_ct_error_total` | Counter | `netns` | ICMP errors referring to untracked flows |
| `shorewall_nft_ct_search_restart_total` | Counter | `netns` | Hash-chain search restarts (table resize / bucket churn) |

**Operator watch list:** `insert_failed` + `drop` + `early_drop`
climbing simultaneously is the conntrack-table-pressure signature —
raise `nf_conntrack_max` or tune `nf_conntrack_tcp_timeout_*`.
`invalid` climbing in isolation usually means bogus traffic or a
state-machine mismatch (one-way traffic, asymmetric routing).

### Protocol-stack metrics — IP / ICMP / UDP (per netns, per family)

Sourced from `/proc/net/snmp` + `/proc/net/snmp6`, delegated to the
netns-pinned nft worker. On a firewall these are the first-class SRE
signal for forwarding quality: `ip_forwarded_total` is the raw
forwarding rate, `ip_out_no_routes_total` counts packets dropped
because nothing matched the FIB — a non-zero slope here usually
means a dead static route or a disappeared BGP session.

Every metric carries `netns` plus a `family` label (`ipv4` or `ipv6`)
so one alerting rule covers both stacks:

| Metric | Type | Description |
|---|---|---|
| `shorewall_nft_ip_forwarded_total` | Counter | Packets forwarded to another interface |
| `shorewall_nft_ip_out_no_routes_total` | Counter | Packets dropped: no route to destination |
| `shorewall_nft_ip_in_discards_total` | Counter | Input packets discarded (resource shortage etc.) |
| `shorewall_nft_ip_in_hdr_errors_total` | Counter | Input packets with header errors |
| `shorewall_nft_ip_in_addr_errors_total` | Counter | Input packets with invalid destination |
| `shorewall_nft_ip_in_delivers_total` | Counter | Packets delivered to upper layers |
| `shorewall_nft_ip_out_requests_total` | Counter | Output packets requested by upper layers |
| `shorewall_nft_ip_reasm_fails_total` | Counter | IP reassembly failures |
| `shorewall_nft_icmp_in_msgs_total` | Counter | ICMP messages received |
| `shorewall_nft_icmp_out_msgs_total` | Counter | ICMP messages sent |
| `shorewall_nft_icmp_in_dest_unreachs_total` | Counter | ICMP destination-unreachable received |
| `shorewall_nft_icmp_out_dest_unreachs_total` | Counter | ICMP destination-unreachable sent |
| `shorewall_nft_icmp_in_time_excds_total` | Counter | ICMP time-exceeded received |
| `shorewall_nft_icmp_out_time_excds_total` | Counter | ICMP time-exceeded sent |
| `shorewall_nft_icmp_in_redirects_total` | Counter | ICMP redirects received |
| `shorewall_nft_icmp_in_echos_total` | Counter | ICMP echo requests received |
| `shorewall_nft_icmp_in_echo_reps_total` | Counter | ICMP echo replies received |
| `shorewall_nft_udp_in_datagrams_total` | Counter | UDP datagrams received |
| `shorewall_nft_udp_no_ports_total` | Counter | UDP datagrams to closed port |
| `shorewall_nft_udp_in_errors_total` | Counter | UDP datagrams received with errors |
| `shorewall_nft_udp_out_datagrams_total` | Counter | UDP datagrams sent |
| `shorewall_nft_udp_rcvbuf_errors_total` | Counter | UDP dropped: receive buffer full |
| `shorewall_nft_udp_sndbuf_errors_total` | Counter | UDP dropped: send buffer full |
| `shorewall_nft_udp_in_csum_errors_total` | Counter | UDP datagrams with bad checksum |

### TCP stack metrics (per netns, kernel-wide v4+v6)

The kernel keeps one TCP MIB across both address families, so these
metrics carry only a `netns` label (no `family` split):

| Metric | Type | Description |
|---|---|---|
| `shorewall_nft_tcp_curr_estab` | Gauge | Current connections in ESTABLISHED / CLOSE_WAIT |
| `shorewall_nft_tcp_active_opens_total` | Counter | Active (local-initiated) connection opens |
| `shorewall_nft_tcp_passive_opens_total` | Counter | Passive (remote-initiated) opens |
| `shorewall_nft_tcp_attempt_fails_total` | Counter | Connection attempts that failed |
| `shorewall_nft_tcp_estab_resets_total` | Counter | Resets from ESTABLISHED / CLOSE_WAIT |
| `shorewall_nft_tcp_retrans_segs_total` | Counter | Retransmitted segments |
| `shorewall_nft_tcp_in_segs_total` | Counter | Segments received |
| `shorewall_nft_tcp_out_segs_total` | Counter | Segments sent |
| `shorewall_nft_tcp_in_errs_total` | Counter | Segments received with errors |
| `shorewall_nft_tcp_out_rsts_total` | Counter | Segments sent with RST |
| `shorewall_nft_tcp_in_csum_errors_total` | Counter | Segments with bad checksum |

### TCP extensions (`TcpExt`, per netns)

Sourced from `/proc/net/netstat`. `listen_overflows` +
`backlog_drop` are the canonical SYN-flood / accept-queue signals;
`timeouts` + `syn_retrans` track wire-level packet loss ahead of any
application-layer alarm.

| Metric | Type | Description |
|---|---|---|
| `shorewall_nft_tcpext_listen_overflows_total` | Counter | SYN arrived with a full accept queue |
| `shorewall_nft_tcpext_listen_drops_total` | Counter | SYNs dropped (all resource shortages) |
| `shorewall_nft_tcpext_backlog_drop_total` | Counter | Packets dropped: socket backlog full |
| `shorewall_nft_tcpext_timeouts_total` | Counter | Retransmission timeouts fired |
| `shorewall_nft_tcpext_syn_retrans_total` | Counter | SYN retransmissions |
| `shorewall_nft_tcpext_prune_called_total` | Counter | Socket memory pruning invocations |
| `shorewall_nft_tcpext_ofo_drop_total` | Counter | Out-of-order packets dropped |
| `shorewall_nft_tcpext_abort_on_data_total` | Counter | Connections aborted while data was pending |
| `shorewall_nft_tcpext_abort_on_memory_total` | Counter | Connections aborted due to memory pressure |
| `shorewall_nft_tcpext_retrans_fail_total` | Counter | Retransmission attempts that failed at send |

### Socket counts (`/proc/net/sockstat{,6}`, per netns)

TCP buckets get a `family` label split (v4/v6 inuse counters exist on
both stacks); kernel-wide or v4-only buckets (TCP `orphan`/`tw`/
`alloc`/`mem`, UDP `mem`, the `sockets_used` total) carry no family
label. `mem_pages` fields are in kernel pages — convert to bytes by
multiplying with `/proc/sys/vm/page_size` if you need byte units.

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_sockstat_tcp_inuse` | Gauge | `netns,family` |
| `shorewall_nft_sockstat_tcp_orphan` | Gauge | `netns` (v4 only) |
| `shorewall_nft_sockstat_tcp_tw` | Gauge | `netns` — TIME_WAIT sockets |
| `shorewall_nft_sockstat_tcp_alloc` | Gauge | `netns` — allocated TCP sockets |
| `shorewall_nft_sockstat_tcp_mem_pages` | Gauge | `netns` — TCP memory in kernel pages |
| `shorewall_nft_sockstat_udp_inuse` | Gauge | `netns,family` |
| `shorewall_nft_sockstat_udp_mem_pages` | Gauge | `netns` — UDP memory in kernel pages |
| `shorewall_nft_sockstat_udplite_inuse` | Gauge | `netns,family` |
| `shorewall_nft_sockstat_raw_inuse` | Gauge | `netns,family` |
| `shorewall_nft_sockstat_frag_inuse` | Gauge | `netns,family` — IP reassembly queues |
| `shorewall_nft_sockstat_frag_memory_bytes` | Gauge | `netns,family` — IP reassembly memory (bytes) |
| `shorewall_nft_sockstat_sockets_used` | Gauge | `netns` — kernel-wide socket count |

### Per-CPU softirq (`/proc/net/softnet_stat`, per netns, per CPU)

One row per CPU in the file becomes one sample per CPU in each
metric family — label `cpu` is the zero-based kernel CPU index as a
string. On a firewall with uneven IRQ distribution this is the
*only* way to see that one CPU is dropping packets at line rate
while the others idle.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `shorewall_nft_softnet_processed_total` | Counter | `netns,cpu` | Packets processed by softirq on this CPU |
| `shorewall_nft_softnet_dropped_total` | Counter | `netns,cpu` | Packets dropped: CPU input_pkt_queue full |
| `shorewall_nft_softnet_time_squeeze_total` | Counter | `netns,cpu` | NAPI polls cut short by budget/time |
| `shorewall_nft_softnet_received_rps_total` | Counter | `netns,cpu` | Packets received via an RPS IPI |
| `shorewall_nft_softnet_flow_limit_total` | Counter | `netns,cpu` | Packets dropped by flow-limit filter |

### Neighbour (ARP/ND) + address counts (per netns)

Sourced from `RTM_GETNEIGH` / `RTM_GETADDR` via pyroute2 — one dump
per scrape per netns. Count per `(iface, family, state)` (neighbour
cache) respectively `(iface, family)` (addresses). A spike in
`neigh_count{state="failed"}` is the gateway-down signal; an address
disappearing during a VRRP flap drops `addrs` for the relevant
interface from N+1 to N.

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_neigh_count` | Gauge | `netns,iface,family,state` — state ∈ {reachable, stale, failed, incomplete, delay, probe, permanent, noarp, none} |
| `shorewall_nft_addrs` | Gauge | `netns,iface,family` — number of configured addresses |

### Flowtable descriptors (per netns with a loaded ruleset)

Extracted from the same `list table inet shorewall` snapshot that
drives the rule/counter/set metrics — zero extra netlink round-trips.
Live flow counts per flowtable are **not** emitted: libnftables'
JSON view of a flowtable carries only its definition, not the
transient flow entries. Alert on `flowtable_devices == 0` (interface
detached) and on an absent `flowtable_exists` sample (flowtable
disappeared after a faulty reload).

| Metric | Type | Labels |
|---|---|---|
| `shorewall_nft_flowtable_devices` | Gauge | `netns,name` — attached interfaces |
| `shorewall_nft_flowtable_exists` | Gauge | `netns,name,hook` — always 1 for every configured flowtable |

### Architecture: netns-pinned reads

The Prometheus scrape thread never calls `setns(2)` directly. Every
`/proc` / `/sys` read performed by a collector is delegated to the
nft-worker process that is already pinned to the target netns via
`setns(CLONE_NEWNET)` at fork time:

```
Prometheus scrape thread
   └─ CtCollector / SnmpCollector / NetstatCollector /
      SockstatCollector / SoftnetCollector
         └─ WorkerRouter.read_file_sync / count_lines_sync
              └─ run_coroutine_threadsafe → asyncio loop
                   └─ ParentWorker (netns-pinned child)
                        └─ open(path).read()          # READ_KIND_FILE
                           or sum(1 for _ in f)       # READ_KIND_COUNT_LINES
                              ↩ SEQPACKET reply ↩
```

Wire protocol sits alongside the existing SetWriter batch codec:
two extra magics (`SWRR` request, `SWRS` response) dispatched by the
worker main loop, one SEQPACKET round-trip per file read, response
capped at 60 KiB (`/proc/net/ipv6_route` on a full-BGP box would
exceed that — callers use `count_lines` for line-count metrics
instead, which ships an 8-byte integer regardless of file size).

For the daemon's own netns (`netns=""`) the in-process `LocalWorker`
short-circuits to a direct `open()` on the default thread pool —
no fork, no IPC — while keeping the same async API.

Two collectors stay on the legacy `_in_netns()` setns hop because
they touch netlink sockets the worker protocol does not yet proxy:

* `ConntrackStatsCollector` — opens a fresh `NFCTSocket` per scrape
  bound to the target netns.
* `NeighbourCollector` / `AddressCollector` / `LinkCollector` /
  `QdiscCollector` — use pyroute2's `IPRoute(netns=…)` which forks
  internally to bind the socket in the target netns.

These remain safe under concurrent scrapes because Linux `setns(2)`
is per-thread, not per-process: the scrape thread's brief
name-space hop does not leak into the asyncio event-loop thread.

### dnstap pipeline metrics (only when `--listen-api` is set)

| Metric | Type |
|---|---|
| `shorewalld_dnstap_frames_accepted_total` | Counter |
| `shorewalld_dnstap_frames_decode_error_total` | Counter |
| `shorewalld_dnstap_frames_dropped_queue_full_total` | Counter |
| `shorewalld_dnstap_frames_dropped_not_client_response_total` | Counter |
| `shorewalld_dnstap_frames_dropped_not_a_or_aaaa_total` | Counter |
| `shorewalld_dnstap_frames_dropped_not_allowlisted_total` | Counter |
| `shorewalld_dnstap_connections` | Gauge |
| `shorewalld_dnstap_workers_busy` | Gauge |
| `shorewalld_dnstap_queue_depth` | Gauge |
| `shorewalld_dnstap_queue_capacity` | Gauge |

Watch `queue_depth / queue_capacity` — if it climbs toward 1.0 the
decoder is falling behind the recursor and you should increase
`--scrape-interval`-equivalent tuning or throw hardware at it.

`frames_dropped_not_allowlisted_total` is bumped by the two-pass
filter: when an allowlist is configured, an answer's qname is checked
against it before the expensive dnspython parse runs. A large ratio
of `frames_dropped_not_allowlisted_total` to `frames_accepted_total`
is healthy — it means the recursor is answering for plenty of names
the daemon has no interest in, and the cheap filter is saving CPU on
every one of them.

### DNS-set pipeline metrics (when DNS pipeline is active)

**Decoder → tracker bridge** (`shorewalld_bridge_*`):

| Metric | Type | Description |
|---|---|---|
| `shorewalld_bridge_updates_total` | Counter | DnsUpdate records seen |
| `shorewalld_bridge_updates_empty_total` | Counter | Records with no A/AAAA RRs, skipped |
| `shorewalld_bridge_early_filter_miss_total` | Counter | qname not in compiled allowlist, dropped |
| `shorewalld_bridge_early_filter_pass_total` | Counter | qname matched, forwarded to tracker |
| `shorewalld_bridge_proposals_total` | Counter | Individual (qname, ip) proposals submitted |
| `shorewalld_bridge_dropped_queue_full_total` | Counter | Proposals dropped — SetWriter queue saturated |

**Coalescing write buffer** (`shorewalld_setwriter_*`):

| Metric | Type | Description |
|---|---|---|
| `shorewalld_setwriter_queue_depth` | Gauge | Pending proposals in the write queue |
| `shorewalld_setwriter_queue_high_water` | Gauge | Peak queue depth since daemon start |
| `shorewalld_setwriter_submits_total` | Counter | Proposals accepted into the queue |
| `shorewalld_setwriter_dropped_queue_full_total` | Counter | Proposals rejected — queue at capacity |
| `shorewalld_setwriter_batches_flushed_total` | Counter | Batches handed to WorkerRouter |
| `shorewalld_setwriter_flush_reason_total{reason}` | Counter | Flush trigger: `window`, `full`, `shutdown` |
| `shorewalld_setwriter_commits_total` | Counter | Successful nft element-add commits |
| `shorewalld_setwriter_commit_errors_total` | Counter | Failed commits |

**Per-netns worker pool** (`shorewalld_worker_*`, label `{netns}`):

| Metric | Type | Description |
|---|---|---|
| `shorewalld_worker_spawned_total` | Counter | Workers ever started for this netns |
| `shorewalld_worker_restarts_total` | Counter | Worker restarts after crash |
| `shorewalld_worker_alive` | Gauge | 1 if the worker process is running |
| `shorewalld_worker_batches_sent_total` | Counter | Batches sent over the IPC socket |
| `shorewalld_worker_batches_applied_total` | Counter | Batches successfully applied by worker |
| `shorewalld_worker_batches_failed_total` | Counter | Batches the worker reported as failed |
| `shorewalld_worker_ipc_errors_total` | Counter | IPC transport errors |
| `shorewalld_worker_ack_timeout_total` | Counter | Batches that timed out waiting for ACK |
| `shorewalld_worker_batch_latency_seconds` | Histogram | End-to-end dispatch latency (send → reply), buckets 1 ms–2.5 s |
| `shorewalld_worker_batch_size_ops` | Histogram | Operations per batch at dispatch, buckets 1–40 ops |
| `shorewalld_worker_transport_send_bytes_total` | Counter | Bytes pushed down the parent→worker SEQPACKET |
| `shorewalld_worker_transport_recv_bytes_total` | Counter | Bytes received from the worker over SEQPACKET |
| `shorewalld_worker_transport_send_errors_total` | Counter | SEQPACKET send errors (one per event) |

Alert recipes:
`histogram_quantile(0.99, rate(shorewalld_worker_batch_latency_seconds_bucket[5m]))`
— tail latency per netns. A slow commit shows up here first.
`rate(shorewalld_worker_transport_send_bytes_total[1m])`
— absolute wire traffic; combined with `batch_size_ops` this separates
"lots of small batches" from "few big batches" regressions.
(Transport byte counters are only emitted for forked workers; the
default-netns `LocalWorker` has no SEQPACKET hop so its transport
rows are omitted by design.)

**Per-DNS-set load** (`shorewalld_dns_set_*`, labels `{set, family}`):

| Metric | Type | Description |
|---|---|---|
| `shorewalld_dns_set_elements` | Gauge | Current live element count for this set |
| `shorewalld_dns_set_adds_total` | Counter | New IPs inserted (ADD verdicts) |
| `shorewalld_dns_set_refreshes_total` | Counter | Existing IPs whose TTL was extended (REFRESH verdicts) |
| `shorewalld_dns_set_dedup_hits_total` | Counter | Proposals skipped — current TTL still covers |
| `shorewalld_dns_set_dedup_misses_total` | Counter | Proposals that became real writes (ADD + REFRESH combined) |
| `shorewalld_dns_set_expiries_total` | Counter | Entries evicted because their deadline passed |
| `shorewalld_dns_set_last_update_age_seconds` | Gauge | Seconds since the last write to this set (omitted if never written) |

`set` is the canonicalised qname (`cdn_amazon`, not `dns_cdn_amazon_v4`);
`family` is `ipv4` or `ipv6`. The tracker is daemon-global, so these
metrics do **not** carry a `netns` label — a single qname that routes
to two namespaces aggregates into one pair of counters. For per-netns
write volume correlate with `shorewalld_worker_batches_applied_total`.

Typical PromQL:
`rate(shorewalld_dns_set_adds_total[1m]) + rate(shorewalld_dns_set_refreshes_total[1m])`
— updates/s per set (what load each qname contributes).
`shorewalld_dns_set_dedup_hits_total / (shorewalld_dns_set_dedup_hits_total + shorewalld_dns_set_dedup_misses_total)`
— dedup ratio per set; close to 1.0 means most answers were cache hits.
`shorewalld_dns_set_last_update_age_seconds > 3600`
— staleness alarm: DNS pipeline still running but this set hasn't
been touched for an hour (likely: no clients querying the qname, or
the TTL is very long).

**Pull resolver** (`shorewalld_pull_resolver_*`):

| Metric | Type | Description |
|---|---|---|
| `shorewalld_pull_resolver_groups_active` | Gauge | `dnsr:` groups currently scheduled |
| `shorewalld_pull_resolver_in_flight` | Gauge | Resolves currently in progress |
| `shorewalld_pull_resolver_resolves_total` | Counter | Completed resolution passes |
| `shorewalld_pull_resolver_resolve_errors_total` | Counter | Resolves that returned no usable IPs |
| `shorewalld_pull_resolver_nxdomain_total` | Counter | NXDOMAIN responses |
| `shorewalld_pull_resolver_entries_submitted_total` | Counter | IP entries submitted to SetWriter |

**Control socket** (`shorewalld_control_*`, label `{cmd}`):

| Metric | Type | Description |
|---|---|---|
| `shorewalld_control_requests_total` | Counter | Requests dispatched per command |
| `shorewalld_control_errors_total` | Counter | Handler errors per command |

## Multi-netns operation

On a box with `fw`, `rns1`, `rns2` namespaces (the reference HA stack
shape), start with:

```sh
shorewalld --listen-prom :9748 --netns auto
```

`auto` walks `/run/netns/` and creates one collector profile per named
namespace, plus one for the daemon's own netns. Each profile always
includes a `LinkCollector` and a `CtCollector`; the `NftCollector` is
added only when `list table inet shorewall` succeeds in that netns,
and a periodic reprobe (default every 5 minutes) picks up tables that
appear or disappear after the daemon started.

This means you can run `shorewall-nft start` inside any netns
*after* shorewalld is already up, and the new ruleset shows up on the
next reprobe without a daemon restart.

## dnstap / DNS-set API

To enable the DNS-set machinery:

1. Start the daemon with `--listen-api /run/shorewalld/dnstap.sock`
   (the default path used in the systemd unit; pick any path writeable
   from the recursor's mount namespace).
2. Install the pdns_recursor Lua config from
   `packaging/pdns-recursor/shorewalld.lua.template` into
   `/etc/powerdns/recursor.d/shorewalld.lua` (adjust the socket path
   if different).
3. Reload the recursor: `systemctl reload pdns-recursor`.

shorewalld's unix socket is created with mode `0660`. The recursor
needs to be in the shorewall group, or chmod the socket `0666` at
daemon startup via a drop-in.

### How the pipeline works

```
  pdns_recursor
       │
       ▼  CLIENT_RESPONSE frame (FrameStream + protobuf)
  /run/shorewalld/dnstap.sock
       │
       ▼  reader coroutine (one per connection)
  bounded queue (default 10 000 frames)
       │
       ▼  os.cpu_count() decode threads
  dnstap.Dnstap → Message → response_message (DNS wire)
       │
       ▼  dnspython A/AAAA/TTL extraction
  DnsUpdate(qname, a_rrs, aaaa_rrs, ttl)
       │
       ▼  call_soon_threadsafe → SetWriter coroutine
  nft add element inet shorewall dns_github_com_v4 { 140.82.121.3 timeout 300s }
```

### Non-blocking guarantees

Three-stage backpressure chain:

1. **Recursor → socket**. pdns_recursor's dnstap writer is a bounded
   queue with drop-on-overflow. Resolver latency is never affected.
2. **Socket → shorewalld**. Kernel unix-socket recv buffer absorbs
   bursts.
3. **In-process queue → decode workers**. Bounded Python `queue.Queue`.
   On overflow we drop the frame and bump
   `shorewalld_dnstap_frames_dropped_queue_full_total`.

Drops only start at stage 3 if shorewalld can't keep up with the
recursor's sustained rate. Drops at stage 1 only start if shorewalld
is hung and the kernel socket buffer is also full. Either way, the
recursor hot path is untouched.

### Filtering

Two places you can filter qnames:

1. **Shorewalld-side** (recommended): use `QnameFilter` with an
   allowlist in the daemon's code, or accept everything and let the
   nft set lookup fail silently for qnames that don't have a set
   configured. Zero recursor impact.
2. **Producer-side**: uncomment the `postresolve` block in the Lua
   template. Runs a hash lookup inside the recursor's query thread —
   cheap (<1 µs per query) but it IS in the hot path, so benchmark it
   on a busy recursor before turning it on.

### Event type

shorewalld consumes `CLIENT_RESPONSE` only. This means every answer
the recursor sends to a client is seen — including cache hits — with
the TTL already clamped to the remaining cache lifetime. This is the
correct event: `RESOLVER_QUERY`/`RESOLVER_RESPONSE` would miss cache
hits entirely and produce stale/doubled updates.

## Multi-instance operation (`--instance`)

A single `shorewalld` process can manage multiple independent
`shorewall-nft` config directories — one per network namespace. Each
directory is called an *instance*.

```sh
shorewalld \
    --instance fw:/etc/shorewall \
    --instance rns1:/etc/shorewall-rns1 \
    --instance /etc/shorewall6          # root ns, colon optional
```

Format: `[netns:]<dir>`. Omitting the netns (or the colon entirely)
means the daemon's own (root) namespace. The instance name is derived
from the netns name, or from the directory basename when no netns is
given.

For each instance shorewalld expects a compiled DNS allowlist at
`<dir>/dnsnames.compiled` — the file produced by `shorewall-nft start`.
On startup (and on every explicit reload), shorewalld reads that file
and updates its in-memory DNS tracker.

`--instance` replaces the legacy `--allowlist-file` flag.
`--allowlist-file <path>` is still accepted but logs a deprecation
warning and is treated as `--instance <path>`.

### Dynamic registration from `shorewall-nft start` (recommended)

Since v1.6, `shorewall-nft start` / `restart` / `reload` contact the
shorewalld control socket and register the instance after applying
the ruleset. `shorewall-nft stop` deregisters it. No systemd hook is
required — the firewall CLI is the source of truth for what should
be tracked.

```
shorewall-nft start
  … Writing DNS name allowlist            ✓  (12 tap, 3 pull-resolver)
  … Registering instance 'fw' with shorewalld  ✓  (15 name(s))
```

The instance name precedence is:

1. `--instance-name NAME` (CLI) or `SHOREWALLD_INSTANCE_NAME` (env)
2. `INSTANCE_NAME=…` in `shorewall.conf`
3. `--netns` value, if set
4. basename of the config directory (deterministic fallback)

The register payload carries the full instance config as JSON:

```json
{
  "cmd": "register-instance",
  "name": "fw",
  "netns": "",
  "config_dir": "/etc/shorewall46",
  "allowlist_path": "/etc/shorewall46/dnsnames.compiled"
}
```

**Error handling.** Socket missing or permission denied → warning,
`shorewall-nft start` continues. Any other registration failure
**with DNS/`dnsr:` sets present** → hard abort (sets would otherwise
go unpopulated). Deregistration is always non-fatal; removed names
age out via their per-element TTL.

**Register-resync semantics.** Every `register-instance` is treated
as a potential `shorewall-nft start/restart/reload` signal, i.e. the
`inet shorewall` table in the target netns may have just been deleted
and recreated. On each register shorewalld therefore:

1. Drops the tracker's cached `(ip, deadline)` entries for the
   instance's qnames — otherwise `propose()` would keep returning
   `DEDUP` against deadlines that describe kernel state that no
   longer exists, leaving the fresh nft sets empty until the old
   TTL (up to 1 h) elapsed.
2. Respawns the forked nft worker for the instance's netns, so the
   next `add element` runs against a fresh libnftables handle.
3. Pokes the pull resolver to re-resolve the instance's pull-enabled
   groups immediately, so the kernel sets repopulate within a second
   rather than after the next scheduled resolve pass.

Operators see this in the journal as a single summary line:

```
instance fw: register resync — dropped 11 cached element(s) across
  4 set(s), respawned worker for netns 'fw'
```

File-based `reload-instance` (operator-invoked via `shorewalld ctl`)
does **not** trigger this — it assumes the nft table is unchanged
and only the allowlist moved. Use `register-instance` when the
firewall itself was restarted.

**Element refresh requires explicit `expires`.** Every `add element`
emitted by the worker carries both `timeout T` *and* `expires T`. The
Linux nft kernel does not reset the countdown on an existing element
when the same `timeout` is re-applied — it treats the redundant `add`
as a no-op and lets the original deadline run out. Setting `expires`
explicitly populates `NFTA_SET_ELEM_EXPIRATION` which the kernel always
honours, so a refresh genuinely refreshes. Without this, `dns_*_v4/v6`
sets emptied between pull cycles even though the daemon's
`worker_batches_applied_total` kept climbing. Verified on kernel 6.12 /
nft 1.1.1.

**Worker auto-respawn.** The forked nft worker is monitored by the
parent's reply pump. On EOF (worker crash, OOM, briefly absent target
netns during an `ip netns del/add` cycle, etc.) the parent reaps the
dead child, tears down the transport, and re-forks via
`_auto_respawn()` with exponential backoff: 0 → 1 → 2 → … → 30 s. The
backoff resets to zero once the new child survives 30 s. The
respawn-restart count appears as `shorewalld_worker_restarts_total`.

**Dynamic-only daemon.** You don't have to pre-declare
`--instance fw:/etc/shorewall46` on the shorewalld side. If only
`--control-socket` is configured, shorewalld starts its
`InstanceManager` with an empty list and accepts `register-instance`
from any `shorewall-nft start` that runs later.

### Manual reload (legacy hook path)

Still supported if you prefer an explicit post-start hook instead of
the built-in registration:

```sh
# Reload all instances (re-read dnsnames.compiled from every dir).
shorewalld ctl reload-instance

# Reload a single instance by name.
shorewalld ctl reload-instance --name fw
```

```ini
# /etc/systemd/system/shorewall-nft.service.d/shorewalld-notify.conf
[Service]
ExecStartPost=-/usr/bin/shorewalld ctl \
    --socket /run/shorewalld/control.sock \
    reload-instance --name fw
```

---

## IP-list sets

shorewalld can periodically fetch public prefix lists and write them
into nft `flags interval` sets. The sets are populated in every
network namespace that has a loaded `inet shorewall` table, diffed
against the current kernel state so only deltas are written.

### Declaring the sets (compiler side)

The operator declares the nft sets in their shorewall-nft config (the
same way `dns_*` sets are declared). shorewalld populates them; it
never creates or destroys sets.

Example set declaration in a shorewall-nft `nft-extras` snippet:

```nft
set cloud_aws_ec2_eu_v4 {
    type ipv4_addr
    flags interval
    comment "AWS EC2 eu-* — managed by shorewalld"
}
set cloud_cf_v4 {
    type ipv4_addr
    flags interval
    comment "Cloudflare CDN — managed by shorewalld"
}
set bogon_v4 {
    type ipv4_addr
    flags interval
    comment "RFC bogons — managed by shorewalld"
}
```

### Configuration

In `shorewalld.conf`, one block per set. Each block is identified by a
unique name (the middle part of the key: `IPLIST_<NAME>_…`).

```ini
# AWS EC2, EU regions only
IPLIST_AWS_EC2_EU_PROVIDER=aws
IPLIST_AWS_EC2_EU_FILTERS=service:EC2,region:eu-*
IPLIST_AWS_EC2_EU_SET_V4=cloud_aws_ec2_eu_v4
IPLIST_AWS_EC2_EU_REFRESH=3600

# Cloudflare (no filters — one global range)
IPLIST_CF_PROVIDER=cloudflare
IPLIST_CF_SET_V4=cloud_cf_v4
IPLIST_CF_SET_V6=cloud_cf_v6
IPLIST_CF_REFRESH=3600

# Azure Active Directory
IPLIST_AZURE_AD_PROVIDER=azure
IPLIST_AZURE_AD_FILTERS=tag:AzureActiveDirectory
IPLIST_AZURE_AD_SET_V4=cloud_azure_ad_v4
IPLIST_AZURE_AD_REFRESH=3600

# GCP europe-west3 and global
IPLIST_GCP_EU_PROVIDER=gcp
IPLIST_GCP_EU_FILTERS=scope:europe-west3,scope:global
IPLIST_GCP_EU_SET_V4=cloud_gcp_eu_v4
IPLIST_GCP_EU_REFRESH=3600

# GitHub Actions runners
IPLIST_GH_ACTIONS_PROVIDER=github
IPLIST_GH_ACTIONS_FILTERS=group:actions
IPLIST_GH_ACTIONS_SET_V4=cloud_github_v4
IPLIST_GH_ACTIONS_REFRESH=3600

# RFC bogons (offline, no HTTP)
IPLIST_BOGON_PROVIDER=bogon
IPLIST_BOGON_SET_V4=bogon_v4
IPLIST_BOGON_SET_V6=bogon_v6
IPLIST_BOGON_REFRESH=86400

# DE-CIX Frankfurt peering prefixes
IPLIST_DECIX_PROVIDER=peeringdb
IPLIST_DECIX_FILTERS=ix:DE-CIX Frankfurt
IPLIST_DECIX_SET_V4=ix_decix_v4
IPLIST_DECIX_SET_V6=ix_decix_v6
IPLIST_DECIX_REFRESH=86400
```

Keys per block:

| Key | Required | Description |
|---|---|---|
| `PROVIDER` | yes | Provider name (see below) |
| `FILTERS` | no | Comma-separated `dimension:value` pairs |
| `SET_V4` | no | nft set name for IPv4 prefixes |
| `SET_V6` | no | nft set name for IPv6 prefixes |
| `REFRESH` | no | Refresh interval in seconds (default 3600) |
| `MAX_PREFIXES` | no | Safety cap — skip write if exceeded (default 100 000) |

### Providers and filters

#### `aws` — AWS ip-ranges.json

Source: `https://ip-ranges.amazonaws.com/ip-ranges.json`

| Dimension | Values | Example |
|---|---|---|
| `service` | `EC2`, `S3`, `CLOUDFRONT`, `ROUTE53`, `GLOBALACCELERATOR`, `API_GATEWAY`, `AMAZON` (all), … | `service:EC2` |
| `region` | `eu-central-1`, `us-east-1`, `GLOBAL`, … — **glob patterns supported** | `region:eu-*` |

#### `azure` — Azure Service Tags

Source: Azure Service Tags weekly JSON (Microsoft CDN).

| Dimension | Values | Example |
|---|---|---|
| `tag` | `AzureCloud`, `Storage`, `Sql`, `AzureActiveDirectory`, `ActionGroup`, `AzureDevOps`, `AppService`, `AzureMonitor`, … (~200 tags) — **glob + region suffix** (`Storage.WestEurope`) | `tag:AzureActiveDirectory` |
| `url` | Override the source URL (Microsoft rotates it weekly) | `url:https://…` |

#### `gcp` — Google Cloud

Source: `https://www.gstatic.com/ipranges/cloud.json`

| Dimension | Values | Example |
|---|---|---|
| `service` | `Google Cloud` (coarse) | `service:Google Cloud` |
| `scope` | Region name or `global` | `scope:europe-west3` |

#### `cloudflare`

Sources: `https://www.cloudflare.com/ips-v4` and `ips-v6`

No filter dimensions. Both URLs are fetched and combined.

#### `github` — GitHub meta API

Source: `https://api.github.com/meta`

| Dimension | Values |
|---|---|
| `group` | `actions`, `api`, `copilot`, `dependabot`, `git`, `hooks`, `packages`, `pages`, `web` — **glob supported** |

#### `bogon` — RFC special-use ranges

No HTTP fetch — fully offline. Hardcoded from RFCs 1122, 1918, 6598,
5737, 3927, 2544, 4291, 6052, 3849, 4193.

| Dimension | Values |
|---|---|
| `type` | `bogon` (v4+v6, default), `ipv4_only`, `ipv6_only` |

IPv4: `0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15
198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
255.255.255.255/32`

IPv6: `::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 100::/64 2001::/32
2001:2::/48 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8`

#### `peeringdb` — PeeringDB IX prefixes

Source: `https://www.peeringdb.com/api/ixpfx`

| Dimension | Values | Example |
|---|---|---|
| `ix` | Internet Exchange name (case-insensitive substring) | `ix:DE-CIX Frankfurt` |
| `asn` | Numeric ASN | `asn:1299` |

### Exploring available filters

```sh
# List all providers and their filter dimensions (no network).
shorewalld iplist providers

# Show available values for a filter dimension (live fetch).
shorewalld iplist filters aws --dimension service
shorewalld iplist filters aws --dimension region
shorewalld iplist filters azure --dimension tag
shorewalld iplist filters github --dimension group
shorewalld iplist filters peeringdb --dimension ix

# Preview what a filter configuration would yield.
shorewalld iplist show aws --filters service:EC2,region:eu-* --family v4
```

### Manual refresh

```sh
# Immediate full refresh (all lists) via SIGUSR1.
kill -USR1 $(pidof shorewalld)
systemctl kill --signal=USR1 shorewalld

# Selective refresh via control socket.
shorewalld ctl --socket /run/shorewalld/control.sock refresh-iplist
shorewalld ctl --socket /run/shorewalld/control.sock refresh-iplist --name aws_ec2_eu

# Status of all lists.
shorewalld ctl --socket /run/shorewalld/control.sock iplist-status
```

### Metrics

```
shorewalld_iplist_prefixes_total{name,family}        # gauge — current prefix count
shorewalld_iplist_last_refresh_timestamp{name}       # gauge — unix timestamp
shorewalld_iplist_fetch_duration_seconds{name}       # summary
shorewalld_iplist_fetch_errors_total{name,reason}    # counter
shorewalld_iplist_updates_total{name,op}             # counter — op=add|remove
```

### Log output

Every refresh logs one `INFO` line:

```
iplist aws_ec2_eu: refresh complete — 312 v4 + 0 v6 prefixes
  (+5 added, -2 removed) across 3 netns [2.1s, ETag hit]
```

Level guide:

| Situation | Level |
|---|---|
| Refresh complete (delta or no-op) | `INFO` / `DEBUG` |
| Filter matched 0 prefixes | `WARNING` (rate-limited) |
| HTTP error, entering backoff | `WARNING` |
| max_prefixes exceeded, write skipped | `ERROR` |

---

## Control socket (`--control-socket`)

An optional Unix socket for operator control commands. Line-oriented
JSON protocol.

```ini
# shorewalld.conf
CONTROL_SOCKET=/run/shorewalld/control.sock
CONTROL_SOCKET_NETNS=fw        # optional: bind inside netns "fw"
```

Or via CLI: `--control-socket /run/shorewalld/control.sock`.

The socket is always created with `root:root 0660`. Only root can
connect by default; add the socket to a group via a drop-in if needed.

### `shorewalld ctl` — control client

```sh
shorewalld ctl --socket PATH <command> [options]

Commands:
  ping                                      Verify the daemon is alive.
  refresh-iplist [--name N]                 Force immediate IP-list refresh.
  iplist-status                             Show status of all IP-list configs.
  reload-instance [--name N]                Reload DNS allowlist from disk.
  register-instance --config-dir PATH       Dynamically register a
      [--netns N] [--name N] [--allowlist-path PATH]
      [--retry-delay SECONDS]               shorewall-nft instance.
  deregister-instance --name N              Deregister a dynamically
      [--config-dir PATH] [--netns N]       registered instance.
  instance-status                           Show status of all instances.
  refresh-dns [--hostname N]                Force immediate re-resolve
                                            of dnsr: groups.
```

The `--socket` flag defaults to `/run/shorewalld/control.sock`.

**Concurrency.** Multiple clients may connect in parallel; each connection
has its own session and processes one request at a time. Mutating commands
that share state are serialised inside the daemon:

- `register-instance`, `reload-instance`, `deregister-instance` serialise
  on a single `InstanceManager` lock (they all drive the same destructive
  `tracker.load_registry` + register-resync sequence).
- `refresh-iplist` serialises per list against the background refresh loop.

Read-only commands (`ping`, `iplist-status`, `instance-status`,
`request-seed`) are not serialised and stay responsive during a long
reload.

`register-instance` automatically retries up to 10 times when the control
socket is not yet available (daemon still starting).  The initial wait is
`--retry-delay` seconds (default `1.0`); each subsequent wait is multiplied
by 1.5 (≈ 1 s → 1.5 s → 2.25 s → … → 38 s, ~90 s total).  Use this
option in `ExecStartPost=` units that run before shorewalld is fully up:

```ini
ExecStartPost=/usr/bin/shorewalld ctl register-instance \
    --config-dir /etc/shorewall --retry-delay 2
```

Example:

```sh
$ shorewalld ctl ping
{"ok": true, "version": "1"}

$ shorewalld ctl refresh-dns
{"ok": true, "refreshed": 3}

$ shorewalld ctl refresh-dns --hostname github.com
{"ok": true, "refreshed": 1}

$ shorewalld ctl iplist-status
[
  {"name": "aws_ec2_eu", "prefixes_v4": 312, "prefixes_v6": 0,
   "last_refresh": "2026-04-18T14:23:01Z", "status": "ok"},
  {"name": "bogon", "prefixes_v4": 15, "prefixes_v6": 12,
   "last_refresh": "2026-04-18T14:20:00Z", "status": "ok"}
]
```

### Seed handshake (`request-seed`)

When `shorewall-nft start` or `restart` recreates the `inet shorewall`
table, all `dns_*` sets start empty. Without a seed, clients see
blackholes for up to the first DNS poll interval (default 10 s).

The seed handshake fixes this: before loading the nft script,
`shorewall-nft` sends a `request-seed` command to shorewalld, receives
live IP addresses from the daemon's in-memory state, and injects them
as `elements = { … }` blocks directly into the initial nft transaction.
DNS sets are populated **from second 0**.

#### Sources consulted by the coordinator

| Source | What it contributes |
|---|---|
| **tracker snapshot** | All IPs currently held in the in-process DNS tracker (fastest, always consulted) |
| **pull resolver** | On-demand re-resolve of every configured group (active DNS query) |
| **peer link** | Snapshot request to the HA peer; IPs the peer holds but this node hasn't seen yet |
| **IP-list sets** | Current prefixes from every configured IP-list provider |

When the same (qname, family, IP) tuple appears from more than one
source, the **higher TTL wins** (max-TTL merge).

#### Passive-wait mode

If dnstap or pbdns is active, `shorewall-nft` can optionally wait until
the deadline for IPs that arrive through the tap pipeline (not cached
yet). Set `wait_for_passive=true` (the default) to enable. The
coordinator polls the tracker every 250 ms until the deadline, capturing
any IPs committed during the window. Disable with `--no-seed-wait-passive`
if the dnstap pipeline is idle at startup and the extra wait is
undesirable.

#### Wire format

Request:

```json
{
  "cmd": "request-seed",
  "netns": "fw",
  "name": "fw",
  "timeout_ms": 10000,
  "qnames": ["github.com", "api.example.com"],
  "iplist_sets": ["aws_ec2_v4", "bogon_v4"],
  "wait_for_passive": true
}
```

Response:

```json
{
  "ok": true,
  "elapsed_ms": 320,
  "complete": true,
  "timeout_hit": false,
  "dnstap_waited": false,
  "sources_contributed": ["tracker", "pull"],
  "seeds": {
    "dns": {
      "github.com": {
        "v4": [{"ip": "140.82.121.4", "ttl": 58}],
        "v6": []
      }
    },
    "iplist": {
      "aws_ec2_v4": ["52.94.0.0/22", "54.240.0.0/18"]
    }
  }
}
```

TTL values in the response are **remaining seconds** (deadline − now).
`shorewall-nft` injects them as `timeout Xs expires Xs` in the nft
element syntax so the kernel countdown matches the daemon's live state.

`complete: false` means the request timed out before all active sources
finished; a partial seed was still returned and injected.

#### Configuration

Three `shorewall.conf` keys control the behaviour (all optional):

| Key | Default | Description |
|---|---|---|
| `SHOREWALLD_SEED_ENABLED` | `yes` | Set to `no` to disable the handshake entirely |
| `SHOREWALLD_SEED_TIMEOUT` | `10s` | Wall-clock budget for the seed request. Accepts `Ns` (seconds) or an integer in milliseconds. |
| `SHOREWALLD_SEED_WAIT_PASSIVE` | `yes` | Whether to hold the full timeout waiting for tap-pipeline IPs |

Corresponding CLI flags on `shorewall-nft start` / `restart`:

```
--seed / --no-seed                  Override SHOREWALLD_SEED_ENABLED
--seed-timeout DURATION             Override SHOREWALLD_SEED_TIMEOUT
--seed-wait-passive / --no-seed-wait-passive   Override SHOREWALLD_SEED_WAIT_PASSIVE
```

Precedence: CLI flag > `SHOREWALLD_SEED_*` env var > `shorewall.conf`
key > built-in default.

The seed step is **non-fatal** by design: if shorewalld is unreachable,
the socket is missing, or the response is malformed, `shorewall-nft`
logs a warning and continues without a seed. The firewall still loads;
DNS sets start empty and fill in as normal via pull/tap.

#### Metrics

| Metric | Type | Description |
|---|---|---|
| `shorewalld_seed_requests_total` | Counter | Total `request-seed` calls received |
| `shorewalld_seed_timeout_hit_total` | Counter | Requests where the deadline was reached before all sources finished |
| `shorewalld_seed_entries_served_total{source}` | Counter | IP entries returned, labelled by source (`tracker`, `pull`, `peer`, `iplist`) |

---

## sysconfig / defaults file

The systemd units read an optional `EnvironmentFile` before starting
the daemon. This is the standard way to pass multi-value flags (like
multiple `--instance`) that can't easily go in `shorewalld.conf`.

Locations (first present wins):

- RPM-based distros: `/etc/sysconfig/shorewalld`
- Debian-based distros: `/etc/default/shorewalld`

The file sets a single shell variable:

```bash
# /etc/sysconfig/shorewalld   (or /etc/default/shorewalld)
SHOREWALLD_ARGS="--instance fw:/etc/shorewall \
                 --instance rns1:/etc/shorewall-rns1 \
                 --control-socket /run/shorewalld/control.sock"
```

`$SHOREWALLD_ARGS` is appended to `ExecStart` in the systemd unit.
All existing `shorewalld.conf` knobs still work alongside it —
the two files serve different purposes: `shorewalld.conf` for
scalar settings, `SHOREWALLD_ARGS` for flags that repeat or that
are awkward in KEY=VALUE form.

The file is deployed automatically by the `.deb` and `.rpm` packages
(empty/commented-out, so the daemon starts with defaults until the
operator enables a line). The source template lives at
`packaging/sysconfig/shorewalld`.

`systemctl reload shorewalld` sends `SIGUSR1` (refreshes all IP
lists without restarting the daemon).

---

## systemd units

Two units ship under `packaging/systemd/`:

- **`shorewalld.service`** — single process serving all namespaces
  (`--netns auto`). Recommended for most deployments. No hard ordering
  dependency on `shorewall-nft.service`; shorewalld discovers nft tables
  at each scrape interval and gracefully skips namespaces whose tables
  are not yet loaded.
- **`shorewalld@.service`** — templated, one instance per netns
  (`systemctl enable shorewalld@rns1`). Use this if you want per-netns
  process isolation or distinct Prometheus ports per netns. Carries
  `After=shorewall-nft@%i.service` so the per-instance daemon starts
  only once the corresponding firewall ruleset is present.

Both require `CAP_NET_ADMIN` (nft writes) + `CAP_SYS_ADMIN` (the
`setns(2)` hop into a named netns) and create `/run/shorewalld` via
`RuntimeDirectory=`. `CAP_NET_RAW` is carried conservatively but is not
strictly required.

### Hardening

The shipped units already apply the standard systemd sandboxing
directives. Operators who drop-in-override the unit should preserve
them — removing any of these lines weakens the security posture
without buying the daemon anything:

```ini
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/shorewalld /var/lib/shorewalld /var/log

CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN

RuntimeDirectory=shorewalld
RuntimeDirectoryMode=0750
StateDirectory=shorewalld
StateDirectoryMode=0750
```

`ProtectSystem=strict` + `ReadWritePaths=` is load-bearing: the daemon
writes its state to `/var/lib/shorewalld/`, its runtime sockets to
`/run/shorewalld/`, and rate-limited warnings to `/var/log/`. If you
redirect state via `--state-dir=` or sockets via `--listen-api=` /
`--control-socket=`, extend `ReadWritePaths=` accordingly or the daemon
will fail to open the new path with `EROFS`.

The capability set is the kernel-enforced minimum:

- Dropping `CAP_SYS_ADMIN` breaks `setns(2)` → no named-netns worker
  can be forked → metrics + nft set writes in those namespaces fall
  back to silent drops. Default netns still works.
- Dropping `CAP_NET_ADMIN` breaks nft element writes and pyroute2
  link / qdisc / neighbour dumps → `set_writes_total` stops
  advancing and most collectors emit zeros.
- `CAP_NET_RAW` can be removed if you never plan to open a raw
  socket from a collector; no shipped code path requires it today.

Do not add `User=` / `Group=` without also providing the caps above
via file-based capabilities or `AmbientCapabilities=` — the ambient
set in the shipped unit only grants the caps because the process
starts as root and systemd applies them before the first exec.

Override the command line with a drop-in, not by editing the unit:

```sh
mkdir -p /etc/systemd/system/shorewalld.service.d
cat >/etc/systemd/system/shorewalld.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/shorewalld \
    --listen-prom 0.0.0.0:9748 \
    --listen-api /run/shorewalld/dnstap.sock \
    --netns auto \
    --scrape-interval 15
EOF
systemctl daemon-reload
systemctl restart shorewalld
```

## Troubleshooting

- **Metrics endpoint returns 500 or nothing** — check
  `systemctl status shorewalld` and the journal. If
  `prometheus_client` is missing, the exporter logs a warning and
  returns cleanly — install it via `pip install shorewall-nft[daemon]`.
- **`netns="fw"` has no nft metrics** — either the table isn't loaded
  in that netns (`ip netns exec fw nft list table inet shorewall`) or
  the daemon lacks `CAP_SYS_ADMIN` to `setns(2)` into the target
  namespace. Check `AmbientCapabilities=` in the effective unit
  (`systemctl cat shorewalld`) and look for
  `setns(...) failed: Operation not permitted` in the journal.
- **Queue depth climbing toward capacity** — the decode workers can't
  keep up. Check `workers_busy` gauge; if it stays at `cpu_count`, the
  bottleneck is nft set writes, not decoding. Consider tightening the
  Lua-side filter or reducing the set churn.
- **dnstap frames dropped as `not_client_response`** — your recursor
  config has `logQueries=true` or is sending non-client events. Set
  `logQueries=false` in the Lua config.
- **`Failed to add element: …`** — the nft set doesn't exist yet;
  the rule compiler has to declare `set dns_<name>_v4 { type ipv4_addr;
  flags timeout; }` before shorewalld can populate it.

## DNS-backed nft sets (`dns:` and `dnsr:` rule syntax)

> **See also**: [nfsets](../features/nfsets.md) — when you need multiple hostnames per
> set, non-DNS backends (URL blocklists, cloud prefix lists), or explicit set naming
> for tooling/monitoring, use the `nfsets` config file and `nfset:<name>` rule syntax
> instead of inline `dns:`/`dnsr:`.

shorewalld can populate nftables sets with the answers to DNS
queries so a Shorewall rule can match on hostname instead of
literal IP. The compiler declares the sets, the daemon populates
them, and the result looks like a first-class rule to the user.

### Two modes: tap (`dns:`) and pull (`dnsr:`)

| Token | Set population | When to use |
|---|---|---|
| `dns:github.com` | Tap — set is populated passively from dnstap/pbdns answers as clients resolve the name | You have a local resolver sending dnstap; the host is queried frequently enough that its IPs stay fresh |
| `dns:github.com,microsoft.com` | Tap — both hostnames share the **same** set via tracker alias | Multiple CNAMEs or related hosts that should share one firewall rule, tap-only (no active pull) |
| `dnsr:github.com` | Pull — shorewalld actively resolves the name on a TTL-driven schedule | No local resolver, outbound-only host, or names that are rarely queried by clients |
| `dnsr:github.com,mail.github.com` | Pull — both hostnames resolved into the **same** set | Multiple CNAMEs or sub-domains that should share one firewall rule with active pull |

Both modes use **identical nft sets** (`dns_<qname>_v4/v6`) and
can be combined: if a hostname is referenced by both a `dns:` and
a `dnsr:` rule it gets tap-populated *and* pull-populated, with
each mechanism refreshing the other's entries.

```
# /etc/shorewall46/rules

# Tap mode — recursor feeds the set passively
ACCEPT      fw      net:dns:github.com               tcp     443
DROP        fw      net:!dns:badhost.example          -       -

# Tap mode, multi-host — both names share dns_github_com_v4/v6 via
# tracker alias; only the first hostname's set is declared
ACCEPT      fw      net:dns:github.com,microsoft.com  tcp     443

# Pull mode — shorewalld resolves on a TTL schedule
ACCEPT      fw      net:dnsr:github.com               tcp     443

# Pull mode, multi-host — all IPs land in dns_github_com_v4/v6
ACCEPT      fw      net:dnsr:github.com,api.github.com  tcp   443
```

The `dns:` / `dnsr:` prefix is recognised in SOURCE/DEST columns
and triggers three things at compile time:

1. The hostname is registered with `FirewallIR.dns_registry`.
2. Two sets are declared in the generated nft script —
   `dns_github_com_v4` (type `ipv4_addr`) and `dns_github_com_v6`
   (type `ipv6_addr`), both with `flags timeout` and the
   configured size.
3. The rule is emitted twice — once for v4, once for v6 —
   matching `ip daddr @dns_github_com_v4` /
   `ip6 daddr @dns_github_com_v6`.

For `dns:host1,host2,…` and `dnsr:host1,host2,…`, the set name
is derived from the first hostname (`dns_host1_v4/v6`). All
secondary hostnames are registered as tracker aliases so the tap
pipeline routes their dnstap/pbdns answers into the primary's set.
`dnsr:` additionally schedules active resolution for every listed
hostname; `dns:` is tap-only. Single-host `dns:host` is a pure set
reference and declares no alias.

Name sanitisation is deterministic: `qname_to_set_name()` in
`shorewall_nft/nft/dns_sets.py` is the single source of truth and
both the compiler and shorewalld import it, so there is no room
for naming drift between compile-time and runtime.

### Pull-resolver scheduling

The pull resolver maintains a min-heap of `(next_resolve_at,
primary_qname)` entries. At startup every group is resolved
immediately, with up to 8 resolves in flight concurrently
(bounded by an `asyncio.Semaphore`) so N groups populate in
O(1) waves rather than N serial stalls. After each resolve:

```
next_resolve_at = now + max(min_retry, int(min_ttl * 0.8)) * (1 ± 0.1)
```

capped at `max_ttl` (default 3600 s). The 0.8 fraction means a
re-resolve fires before any element actually expires, so there is
no window where the set is empty due to TTL drift. The ±10%
jitter spreads groups with identical TTLs across the scheduling
tick. `min_retry` (default 30 s) prevents tight loops after
NXDOMAIN or network errors.

Each individual DNS query has an explicit 3 s lifetime so a
slow upstream can't stall a worker indefinitely. NXDOMAIN and
DNS-exception log lines are rate-limited per `(qname, rdtype)`
through `shorewalld.logsetup.RateLimiter`, so a permanently
missing hostname produces at most one line per rate-limit window
rather than one every `min_retry` seconds.

In-flight groups are tracked so `shorewalld ctl refresh-dns` and
`update_registry()` (called on instance reload) never drop a
refresh signal or push duplicate entries for a group that's
currently being resolved — the resolver re-queues the group as
soon as its current pass completes.

### `dnsnames` config file (optional)

If you want per-host overrides for the TTL floor/ceil or set
size, drop a `dnsnames` file in `/etc/shorewall46/`:

```
# NAME            TTL_FLOOR  TTL_CEIL  SIZE   COMMENT
github.com        300        86400     256    GitHub web+API
api.stripe.com    60         3600      32     Payment webhooks
cdn.example.com   -          -         -      Uses defaults
```

Columns: hostname, TTL floor seconds, TTL ceiling seconds, set
size, free-text comment. `-` means "inherit the global default
from shorewall.conf". Any hostname not listed falls back to the
defaults too.

Hostnames seen only in `rules` (without an explicit `dnsnames`
entry) still get registered with default settings, so the file
is purely for operators who want fine-grained control.

### Global defaults (shorewall.conf)

```
DNS_SET_TTL_FLOOR=300        # clamp minimum TTL (s)
DNS_SET_TTL_CEIL=86400       # clamp maximum TTL (s)
DNS_SET_SIZE=512             # element capacity per set
```

### Compiled allowlist

After `shorewall-nft start`, the compiler writes the resolved
set of hostnames + per-name overrides to
`/etc/shorewall/dnsnames.compiled`. shorewalld reads that file
at startup to build its in-memory allowlist. It's the contract
between compile-time and runtime — if you want to know whether a
hostname made it past the compiler, grep the compiled file.

## `shorewalld tap` — operator inspection tool

`shorewalld tap` is a `tcpdump`-for-DNS-answers CLI that binds a
dnstap unix socket and pretty-prints every frame it sees. Useful
for:

* verifying pdns_recursor is actually sending frames before
  anyone looks at Prometheus
* tuning the `dnsnames` allowlist (shows in-allowlist / not tags)
* debugging per-rcode filtering without grepping journald

```sh
shorewalld tap --socket /tmp/shorewalld-test.sock \
               --format pretty \
               --allowlist /etc/shorewall/dnsnames.compiled \
               --filter-rcode NXDOMAIN
```

Flags:

| Flag | Purpose |
|---|---|
| `--socket PATH` | required — unix socket path to listen on |
| `--format pretty\|structured\|json` | pretty (TTY default), key=value for grep, JSON for `jq` |
| `--filter-qname REGEX` | show only matching qnames |
| `--filter-rcode NAME` | filter by rcode (`NOERROR`, `NXDOMAIN`, ...) |
| `--show-queries` | include CLIENT_QUERY frames (default: responses only) |
| `--allowlist PATH` | path to `dnsnames.compiled` — frames are tagged with `[allowlist ✓]` / `[unknown]` |
| `--count N` | exit after N matching frames |
| `--no-color` | force plain output even on a TTY |

Pretty output example:

```
TIME           TYPE            RCODE      QNAME                         LEN   TAG
20:58:12.123   CLIENT_RESPONSE NOERROR    github.com                    47    [allowlist ✓]
20:58:12.201   CLIENT_RESPONSE NXDOMAIN   nonexistent.example.invalid   52    [unknown]
20:58:12.301   CLIENT_RESPONSE NOERROR    api.stripe.com                44    [allowlist ✓]
```

On exit (Ctrl-C or `--count`), a summary lists totals by type,
rcode, top-10 qnames, and the allowlist hit rate — the fastest
way to tell if your allowlist covers the real traffic.

Tap runs as its own *listener* on the configured path; point
pdns_recursor at that same path if you want to observe the live
stream without stopping shorewalld itself.

## Ingestion path: dnstap vs PBDNSMessage

shorewalld ships with two DNS answer ingestion paths. **dnstap
is the recommended default** and the only path activated by the
smoke test (`tools/setup-shorewalld-dnstap-smoke.sh`); the
PBDNSMessage path stays in-tree as an opt-in alternative.

### Why dnstap is preferred

| Property | dnstap | PBDNSMessage |
|---|---|---|
| Standard | fstrm / dnstap (multi-vendor) | pdns-specific |
| Producers | pdns-recursor, unbound, dnsdist, knot-resolver | pdns-recursor only |
| Transports | **unix socket + TCP** | **TCP only** (pdns refuses unix) |
| Wire format | raw DNS bytes in envelope | pre-decomposed DNSRR records |
| Consumer cost | ~100 µs dnspython parse per frame | ~20 µs skip-parse per frame |
| Framing | fstrm FrameStream (handshake) | 2-byte length prefix |
| Netns story | unix socket crosses mount NS cleanly | loopback TCP port per netns |

The ~80 µs per-frame difference in shorewalld's decoder is well
within the latency budget at realistic DNS QPS (< 20 k/s), so
the performance advantage of PBDNSMessage rarely matters in
practice. Meanwhile dnstap's unix-socket support, multi-vendor
reach, and zero-port-management story win on every operational
dimension. Prefer dnstap unless you have a specific reason to
pick PBDNSMessage.

### dnstap (recommended)

```
# /etc/shorewall/shorewalld.conf
LISTEN_API=/run/shorewalld/dnstap.sock
```

pdns-recursor side, in a file loaded via `lua_config_file`:

```lua
dnstapFrameStreamServer({"/run/shorewalld/dnstap.sock"},
    {logQueries = false, logResponses = true})
```

Or via the pdns 5.x YAML config (`logging.dnstap_framestream_servers`)
if you prefer the native path — but not alongside `lua_config_file`,
pdns refuses that combination.

### PBDNSMessage (opt-in alternative)

```
# /etc/shorewall/shorewalld.conf
PBDNS_TCP=127.0.0.1:9999
```

pdns-recursor side:

```lua
protobufServer("127.0.0.1:9999",
    {logQueries = false, logResponses = true})
```

Note the TCP-only restriction: pdns-recursor's `protobufServer()`
and the YAML `protobuf_servers` field both refuse unix sockets
(`Unable to convert presentation address 'unix:/...'`). If an
out-of-tree producer speaks the PBDNSMessage wire format over a
unix socket, shorewalld can still consume it via
`PBDNS_SOCKET=/run/shorewalld/pbdns.sock`; the two transports
can be enabled simultaneously on the same PbdnsServer instance.

Both ingestion paths feed the same Phase 2 pipeline:
`DnsSetTracker.propose → SetWriter → WorkerRouter → nft worker →
libnftables`. Metrics are mirrored (`shorewalld_pbdns_*` vs
`shorewalld_dnstap_*`) so a Grafana dashboard can compare them
side-by-side during a migration.

## TCP dnstap listener

For cases where the recursor is on a different host, in a
different mount namespace, or inside a container that can't
reach a unix socket, shorewalld's dnstap listener also accepts
TCP connections:

```sh
shorewalld ... --dnstap-tcp 10.0.0.1:9900
```

The TCP listener runs alongside the unix listener, not instead
of it — operators can receive local recursor frames via unix and
replicated frames from a remote recursor via TCP simultaneously.
Same FrameStream handshake, same decoder, same metrics labels.

## State persistence across restarts

Without persistence, a `systemctl restart shorewalld` or a reboot
would leave the DNS sets empty until the recursor happens to
re-answer for each name — which for a fail-closed rule is a
TTL-sized deny window. The `StateStore` (in `state.py`) fixes
that by:

1. Saving the tracker's live entries as atomic JSON every
   `STATE_PERSIST_INTERVAL` seconds (default 30 s) and once more
   synchronously at shutdown.
2. On startup, loading that file, pruning expired entries, and
   asking the tracker to replay the surviving ones.

Deadlines are stored as wall-clock absolute timestamps in the
file so a monotonic clock reset (which happens on every reboot)
doesn't throw off the TTL remaining.

### Directory management

`/var/lib/shorewalld` is created and owned by the systemd units via
`StateDirectory=shorewalld` (mode `0750`). No manual `mkdir` is needed;
the directory appears before the first `ExecStart`. Distro packages
declare it as `%dir %{_sharedstatedir}/shorewalld` (RPM) or
`install -d debian/shorewall-nft/var/lib/shorewalld` (Debian).

### Config (shorewalld.conf)

```
STATE_DIR=/var/lib/shorewalld           # default
STATE_PERSIST_INTERVAL=30               # seconds between periodic saves
```

### CLI flags

```
shorewalld --state-flush        # ignore and delete state file on start
shorewalld --no-state-load      # ignore state file but keep it
shorewalld --state-dir /tmp/x   # alternative directory (tests)
```

### Metrics

```
shorewalld_state_saves_total
shorewalld_state_save_errors_total
shorewalld_state_load_entries_total
shorewalld_state_load_expired_total
shorewalld_state_last_save_age_seconds
shorewalld_state_file_bytes
```

## HA peer replication (two-node cluster)

In an active/passive HA setup, both boxes run shorewalld and
both talk to their own local pdns_recursor. The peer link
replicates every DNS set update from whichever side saw it
first to the other side, so both boxes have identical set
contents without each box needing to independently resolve
every qname.

### Protocol

* **Transport**: UDP with `IP_MTU_DISCOVER=IP_PMTUDISC_DO` set
  so the kernel refuses fragmentation — oversized sends fail
  loudly rather than getting silently fragmented.
* **Framing**: one `PeerEnvelope` protobuf per datagram, capped
  at 1400 bytes before serialisation.
* **Auth**: HMAC-SHA256 trailer, keyed from a shared-secret
  file. The auth interface is pluggable behind a `PeerAuth`
  protocol so AEAD or Ed25519 can drop in later without
  touching the sender or receiver.
* **Loop prevention**: every envelope carries `origin_node` —
  receivers drop their own frames in case of any misconfigured
  routing.
* **Sequence tracking**: monotonic per-sender sequence numbers,
  gaps are counted into `shorewalld_peer_frames_lost_total` but
  not retransmitted — the TTL-cache on both sides converges
  organically.
* **Heartbeat**: every `PEER_HEARTBEAT_INTERVAL` seconds
  (default 5 s) a Heartbeat envelope carries the sender's
  counter snapshot. Receivers publish them as
  `shorewalld_peer_*` gauges, so scraping either node's
  `/metrics` endpoint shows *both* nodes' health.

### Config (shorewalld.conf)

```
PEER_LISTEN=0.0.0.0:9749
PEER_ADDRESS=10.0.0.2:9749
PEER_SECRET_FILE=/etc/shorewall/peer.key
PEER_HEARTBEAT_INTERVAL=5
```

Ingestion from the local recursor is *never* authenticated
(both dnstap and pbdns are local unix sockets, protected by
filesystem permissions). Only the peer-to-peer network traffic
carries HMAC.

### Metrics

| Metric | Type | Description |
|---|---|---|
| `shorewalld_peer_up` | Gauge | 1 if the peer sent a heartbeat within 3× the heartbeat interval |
| `shorewalld_peer_frames_sent_total` | Counter | Envelopes sent to the peer |
| `shorewalld_peer_frames_received_total` | Counter | Envelopes received from the peer |
| `shorewalld_peer_frames_lost_total` | Counter | Sequence gaps detected in received stream |
| `shorewalld_peer_hmac_failures_total` | Counter | Envelopes rejected due to HMAC mismatch |
| `shorewalld_peer_decode_errors_total` | Counter | Envelopes that failed protobuf decode |
| `shorewalld_peer_bytes_sent_total` | Counter | Bytes sent over the peer socket |
| `shorewalld_peer_bytes_received_total` | Counter | Bytes received from the peer |
| `shorewalld_peer_dns_updates_applied_total` | Counter | DNS set updates applied from peer frames |
| `shorewalld_peer_heartbeats_sent_total` | Counter | Heartbeat envelopes sent |
| `shorewalld_peer_heartbeats_received_total` | Counter | Heartbeat envelopes received |
| `shorewalld_peer_send_errors_total` | Counter | Send failures (UDP write errors) |
| `shorewalld_peer_rtt_seconds` | Gauge | Last measured round-trip time |
| `shorewalld_peer_snapshot_complete_total` | Counter | Snapshot sync exchanges completed |

### Cold-boot snapshot resync

When a node boots and its state file is stale (or
`--state-flush` was used), it can ask its peer for the current
DNS set contents via a `SnapshotRequest`. The peer replies with
a `SnapshotResponse` stream split into chunks (each
`SNAPSHOT_CHUNK_SIZE = 20` entries, ≤ 1400 bytes per envelope).
The receiving side applies chunks incrementally via the local
`SetWriter` — convergence is immediate, not "next TTL".

Chunking uses **app-level** splitting, not IP fragmentation —
stateful middleboxes on the HA interlink can't accidentally
drop chunks due to reassembly state loss.

Operators don't need to trigger this explicitly; it fires once
at daemon startup after the StateStore load completes.

## Performance doctrine

shorewalld follows the hot-path discipline documented in
`CLAUDE.md`. Key principles:

* **Preallocated buffers everywhere.** Every `BatchBuilder`,
  every worker's receive buffer, every SEQPACKET transport gets
  a single `bytearray` allocated at startup and reused forever.
  No per-frame allocations in the steady state.
* **Zero-copy decode.** `memoryview` aliases the original frame
  buffer through the entire decode path. Qname extraction via
  `dns_wire.extract_qname()` reads bytes directly without
  building intermediate string objects.
* **Two-pass filter.** Decoders peel off just enough of a frame
  to check the qname against the allowlist before running the
  full parse. At typical deployment rates this drops >95% of
  frames before they touch dnspython.
* **Batch at the netlink boundary.** `SetWriter` accumulates
  `(netns, family)`-keyed updates in a 10 ms window and fires
  one `add element` per batch via the `WorkerRouter`. Single
  updates at 10 k fps would melt the scheduler.
* **Dedup via tracker.** `DnsSetTracker.propose()` returns
  `DEDUP` for entries whose current deadline covers the proposed
  TTL — 95%+ of cache-hit DNS answers never become nft writes.
* **Threading matched to workload.** Decode is GIL-bound Python,
  so the decoder pool uses real `threading.Thread` × cpu_count.
  Sockets are asyncio. libnftables runs on a dedicated
  single-thread executor inside the LocalWorker (or in a forked
  subprocess for target netns via `nft_worker.py` + `WorkerRouter`).
* **Zero-fork in the hot path.** Never shell out. libnftables
  in-process via `NftInterface`, direct netlink for scrape-time
  stats, `/proc` for conntrack counters.
* **Logging rate-limited on hot paths.** The `logsetup.RateLimiter`
  dedups repeated warnings within a configurable window so a
  broken upstream can't flood journald.

## Design notes

Full design memory lives at `docs/roadmap/shorewalld.md`. Source
docstrings:

- `shorewall_nft/daemon/logsetup.py` — logging foundation
- `shorewall_nft/daemon/core.py` — daemon lifecycle
- `shorewall_nft/daemon/exporter.py` — collector and scraper cache
- `shorewall_nft/daemon/discover.py` — netns profile builder
- `shorewall_nft/daemon/framestream.py` — fstrm reader
- `shorewall_nft/daemon/dnstap.py` — unix + tcp dnstap server
- `shorewall_nft/daemon/dns_wire.py` — zero-alloc DNS wire helpers
- `shorewall_nft/daemon/dnstap_bridge.py` — ingestion → SetWriter adapter
- `shorewall_nft/daemon/pbdns.py` — PBDNSMessage ingestion
- `shorewall_nft/daemon/dns_set_tracker.py` — central state of truth
- `shorewall_nft/daemon/batch_codec.py` — parent↔worker binary wire codec
- `shorewall_nft/daemon/worker_transport.py` — SEQPACKET transport
- `shorewall_nft/daemon/nft_worker.py` — per-netns forked worker
- `shorewall_nft/daemon/worker_router.py` — worker pool management
- `shorewall_nft/daemon/setwriter.py` — batching coroutine
- `shorewall_nft/daemon/state.py` — persistence store
- `shorewall_nft/daemon/peer.py` — HA peer replication link
- `shorewall_nft/daemon/tap.py` — operator inspection CLI
- `shorewall_nft/nft/dns_sets.py` — shared qname/set helpers
