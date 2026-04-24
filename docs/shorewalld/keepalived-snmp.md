# shorewalld keepalived integration

shorewalld can talk to a running keepalived instance via SNMP over a Unix
socket, receive SNMP traps when VRRP state changes, and expose the
state-changing keepalived D-Bus methods through the control socket.  All
three are opt-in and independently optional.

## What it does

| Path | What it provides |
|------|-----------------|
| **SNMP Unix walker** | Full MIB walk every `KEEPALIVED_WALK_INTERVAL` seconds. Auto-registers one Prometheus gauge or counter family per MIB column — no code changes when keepalived adds new OIDs. |
| **SNMPv2c trap listener** | Receives `vrrpSyncGroupStateChange` and `vrrpInstanceStateChange` traps forwarded by snmpd; increments `shorewalld_keepalived_events_total{type=...}`. |
| **D-Bus method surface** | Exposes `PrintData`, `PrintStats[Clear]`, `ReloadConfig`, `SendGarp` (and optional `CreateInstance`/`DestroyInstance`) through the control socket as `keepalived-data`, `keepalived-stats`, `keepalived-reload`, `keepalived-garp`. |

The legacy UDP-based `VrrpCollector` (`VRRP_SNMP_*` knobs) continues to
work for one release alongside this path.  Both sets of Prometheus families
coexist cleanly because they use different name prefixes (`shorewall_vrrp_*`
vs `shorewalld_keepalived_*`).

---

## snmpd configuration

Add to `/etc/snmp/snmpd.conf` (or a drop-in under `/etc/snmp/snmpd.conf.d/`):

```
# See docs/shorewalld/snmpd.conf.example for a self-commented snippet.

# Bind snmpd to a Unix DGRAM socket in addition to the UDP port.
# shorewalld connects to this socket for SNMP walks.
agentAddress unix:/run/snmpd/snmpd.sock,udp:127.0.0.1:161

# Forward traps received by snmpd to shorewalld's trap listener.
trap2sink unix:/run/shorewalld/snmp-trap.sock

# Enable AgentX so keepalived's built-in sub-agent can register.
master agentx
agentXSocket unix:/var/run/agentx.sock

# Allow reads from localhost (community string).
rocommunity public default
```

Restart snmpd after editing:

```sh
systemctl restart snmpd
```

The Unix socket at `/run/snmpd/snmpd.sock` must be readable by the
shorewalld process (typically root).

---

## keepalived configuration

Start keepalived with `-x` (AgentX) so it registers with snmpd:

```
# /etc/keepalived/keepalived.conf — global_defs block
global_defs {
    enable_snmp_vrrp
    # Optional — enables the LVS/virtual-server MIB tables:
    enable_snmp_checker
    # Optional D-Bus method surface:
    enable_dbus
}
```

Or pass flags on the command line:

```sh
keepalived -x   # AgentX SNMP
keepalived -D   # D-Bus (requires --enable-dbus at compile time)
```

---

## shorewalld configuration

Add to `shorewalld.conf` (or pass as CLI flags):

```
# ── keepalived SNMP/MIB integration ──────────────────────────────────

# Path to snmpd's Unix DGRAM socket.
# Setting this enables the MIB-driven walker.
KEEPALIVED_SNMP_UNIX=/run/snmpd/snmpd.sock

# Path for the Unix DGRAM trap socket.
# snmpd forwards traps here via trap2sink (above).
KEEPALIVED_TRAP_SOCKET=/run/shorewalld/snmp-trap.sock

# Enable high-cardinality tables (vrrpRouteTable, virtualServerTable,
# vrrpRuleTable). Off by default to cap Prometheus cardinality.
KEEPALIVED_WIDE_TABLES=no

# Include LVS virtualServerTable metrics.  Default yes.
# Disable on deployments that don't use LVS.
KEEPALIVED_SCRAPE_VIRTUAL_SERVERS=yes

# D-Bus method ACL tier.
#   readonly — print_data + print_stats only (default)
#   all      — also allows reload_config + send_garp
#   none     — all D-Bus method calls disabled
KEEPALIVED_DBUS_METHODS=readonly

# Enable CreateInstance / DestroyInstance D-Bus methods.
# Requires keepalived built with --enable-dbus-create-instance.
KEEPALIVED_DBUS_CREATE_INSTANCE=no

# Walk cadence (seconds between full MIB walks).
KEEPALIVED_WALK_INTERVAL=30
```

### CLI flags

Every knob is also available as a CLI flag:

```
--keepalived-snmp-unix PATH
--keepalived-trap-socket PATH
--keepalived-wide-tables / --no-keepalived-wide-tables
--keepalived-scrape-virtual-servers / --no-keepalived-scrape-virtual-servers
--keepalived-dbus-methods {none,readonly,all}
--keepalived-dbus-create-instance / --no-keepalived-dbus-create-instance
--keepalived-walk-interval SECONDS
```

---

## Complete trio deployment

This section walks through a minimum viable single-netns deployment —
snmpd + keepalived + shorewalld + D-Bus policy configured together in one
place, with explicit start ordering and reload semantics.  Multi-netns
variants are covered in the next section.

### Minimum viable config (single-netns, host-network, root-run daemons)

Four files, copy-paste ready.  Annotated with the load-bearing lines and
why each one matters.

**`/etc/snmp/snmpd.conf`** (see also `docs/shorewalld/snmpd.conf.example`
for a self-commented reference):

```ini
# Bind snmpd to a Unix DGRAM socket (mode 0660, group shorewalld)
# AND keep the UDP port for ad-hoc snmpwalk.
agentAddress unix:/run/snmpd/snmpd.sock,0660,root,shorewalld
agentAddress udp:127.0.0.1:161

# Forward every received trap to shorewalld's trap listener.
trap2sink unix:/run/shorewalld/snmp-trap.sock

# AgentX master so keepalived can register its sub-agent.
master agentx
agentXSocket unix:/var/run/agentx.sock

# Community string — "public" is acceptable when the Unix socket's
# filesystem mode is the real access control.
rocommunity public default
```

The `0660,root,shorewalld` comma-extension requires net-snmp ≥ 5.8.
On older net-snmp, omit the comma fields and use the `ExecStartPost`
`chgrp` workaround documented in
[Filesystem ACLs and socket permissions](#filesystem-acls-and-socket-permissions).

**`/etc/keepalived/keepalived.conf`** — minimum keepalived 2.3 config that
enables SNMP AgentX, D-Bus, and a single VRRP instance:

```
global_defs {
    # Write PrintData / PrintStats output to a path shorewalld can
    # read despite PrivateTmp=yes.  /tmp is private to shorewalld;
    # /run is not.
    tmp_config_directory /run/keepalived

    # Enable keepalived's AgentX sub-agent (also requires -x flag or
    # enable_snmp_vrrp below).
    enable_snmp_vrrp

    # Register keepalived on the system D-Bus.  Requires keepalived
    # compiled with --enable-dbus (see D-Bus pitfalls §1).
    enable_dbus

    # Optional: match the agentXSocket path in snmpd.conf.
    # Defaults to /var/agentx/master if omitted.
    # agentx_socket /var/run/agentx.sock
}

vrrp_instance VI_1 {
    state BACKUP          # or MASTER on the primary node
    interface eth0        # WAN-facing interface carrying the VIP
    virtual_router_id 51  # VRID — must be unique per L2 segment (1-255)
    priority 100          # 100 primary / 90 secondary
    authentication {
        auth_type PASS
        auth_pass changeme   # replace in production
    }
    virtual_ipaddress {
        203.0.113.1/24
    }
}
```

Start keepalived with `-x` to activate AgentX (the `enable_snmp_vrrp`
`global_defs` flag is a config-level synonym; both are needed when using
distro packages that do not pass `-x` by default):

```sh
# /etc/systemd/system/keepalived.service.d/agentx.conf
[Service]
ExecStart=
ExecStart=/usr/sbin/keepalived -x -n -l
```

`-x` = AgentX, `-n` = don't fork (systemd manages the lifecycle),
`-l` = log to syslog.

**`/etc/shorewall/shorewalld.conf`** — the three KEEPALIVED keys that matter
for this minimum deployment:

```ini
KEEPALIVED_SNMP_UNIX=/run/snmpd/snmpd.sock
KEEPALIVED_TRAP_SOCKET=/run/shorewalld/snmp-trap.sock
KEEPALIVED_DBUS_METHODS=readonly
```

`/run/keepalived` must be readable by shorewalld.  Add it to the systemd
unit's `ReadOnlyPaths`:

```ini
# /etc/systemd/system/shorewalld.service.d/keepalived-paths.conf
[Service]
ReadOnlyPaths=/run/keepalived
```

Also ensure `/run/keepalived` exists at boot:

```text
# /etc/tmpfiles.d/keepalived-run.conf
d /run/keepalived 0750 root shorewalld -
```

**D-Bus policy drop-in** — allows shorewalld to call keepalived's
read-only methods and receive its signals.  For the full defence-in-depth
policy (interface + member restrictions), see the restricted drop-in in
[Filesystem ACLs and socket permissions → D-Bus system-bus policy](#d-bus-system-bus-policy).
Use the permissive form below only during initial setup; switch to the
restricted form in production:

```xml
<!-- /etc/dbus-1/system.d/shorewalld-keepalived.conf -->
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="shorewalld">
    <allow send_destination="org.keepalived.Vrrp1"/>
    <allow receive_sender="org.keepalived.Vrrp1"/>
  </policy>
</busconfig>
```

Which methods are read-only vs state-changing:

| Method | ACL tier needed | State-changing? |
|--------|-----------------|-----------------|
| `PrintData` | `readonly` (default) | No — writes `/run/keepalived/keepalived.data`, no side effect |
| `PrintStats[Clear]` | `readonly` | `PrintStatsClear` resets per-instance counters — minor |
| `ReloadConfig` | `all` | Yes — equivalent to `SIGHUP` |
| `SendGarp` | `all` | Yes — sends GARP packets on the wire |

Reload D-Bus policy after installing the file:

```sh
systemctl reload dbus    # or: systemctl restart dbus
```

### Service start sequence

Order matters.  Encode it in systemd unit dependencies rather than relying
on wall-clock sleeps.

**Dependency graph:**

```
dbus.service ←── keepalived.service
                         ↑
snmpd.service ←── shorewalld.service
```

- **`dbus.service`** must be up before keepalived, or keepalived starts
  without registering on the bus.  It silently falls back to non-D-Bus
  mode — `keepalived --help 2>&1 | grep -i dbus` shows D-Bus compiled in,
  but `DBUS_SESSION_BUS_ADDRESS` / `DBUS_SYSTEM_BUS_ADDRESS` env may not
  be set, or the system socket may not yet exist.  On systemd systems
  `dbus.service` starts at `basic.target` and is almost always up before
  any `multi-user.target` service, so this dependency is normally
  implicit.  Make it explicit anyway.
- **`snmpd.service`** must be up before shorewalld's first walk.  If snmpd
  is absent, shorewalld logs a warning and marks that walk as an error; the
  next walk fires after `KEEPALIVED_WALK_INTERVAL` (default 30 s).
  Operators see up to 30 s of missing `shorewalld_keepalived_*` metrics
  after a cold boot if snmpd is slow to start.
- **`keepalived.service`** can start before or after shorewalld.
  shorewalld's trap listener and D-Bus client both tolerate keepalived
  being absent at startup (see reload semantics below).

Recommended shorewalld unit override:

```ini
# /etc/systemd/system/shorewalld.service.d/keepalived-ordering.conf
[Unit]
After=snmpd.service keepalived.service dbus.service
Wants=snmpd.service
```

`Wants=snmpd.service` rather than `Requires=` — shorewalld degrades
gracefully when snmpd is absent and keeps exporting all non-keepalived
metrics.  A hard `Requires=` would bring down shorewalld whenever snmpd
is stopped for maintenance.

### Reload semantics

What operators should expect when reloading or restarting each component:

**`systemctl reload snmpd`**

Safe.  snmpd re-reads its config but keeps the Unix socket open.
shorewalld's next walk (`walk_all()`) creates a fresh `netsnmp.Session`
and connects to the same socket path — the session is stateless (one
session object per walk, no persistent TCP connection).  Walk continues
uninterrupted.

**`systemctl reload keepalived`**

Safe.  keepalived re-reads `keepalived.conf` and emits `VrrpReloaded` +
`VrrpStatusChange` signals on the D-Bus.  shorewalld counts each signal
under `shorewalld_keepalived_events_total{type="dbus_signal_VrrpReloaded"}`
and `{type="dbus_signal_VrrpStatusChange"}`.  VRID state is preserved
across reload — the SNMP walk returns the same data immediately after.

**`systemctl restart keepalived`**

Partially safe.  The keepalived bus name (`org.keepalived.Vrrp1`) goes
away for the duration of the restart.  shorewalld's `KeepalivedDbusClient`
holds a connection to the **system bus daemon** (not to keepalived
directly) — this connection remains alive.  Signal subscription
(`add_message_handler`) is bus-level and automatically resumes receiving
`VrrpStatusChange` / `VrrpStarted` signals once keepalived re-registers.

However, **method calls during the outage window fail.**  `print_data()` /
`print_stats()` call `bus.call(Message(...))` with no explicit timeout;
if a control-socket caller (`shorewalld-ctl keepalived-data`) issues a
request while keepalived is restarting, the call raises a D-Bus error
(`NameHasNoOwner`).  shorewalld propagates the error to the
control-socket caller as a JSON error response.

Known issue: **no automatic reconnect for method calls.**  Once keepalived
restarts and re-registers its bus name, shorewalld's next method call
succeeds immediately — there is no reconnect step needed at the
transport level.  But shorewalld does not retry a failed method call
automatically; the control-socket caller receives the error and must
retry.  The `print_stats(clear=True)` fallback flag
(`_print_stats_clear_unavailable`) is also a one-way ratchet: if
`PrintStatsClear` fails during the restart window, the client permanently
falls back to `PrintStats` for the rest of shorewalld's lifetime.  A
shorewalld restart clears this flag.  This is a known limitation — see
[D-Bus pitfalls → Method timeouts and missing retry](#d-bus-method-timeouts-and-missing-retry).

**`systemctl restart snmpd`**

Safe.  snmpd re-creates the Unix socket.  shorewalld creates a new
`netsnmp.Session` on each walk — there is no persistent session to
reconnect.  The walk after snmpd restarts just works.  If keepalived's
AgentX sub-agent loses and re-gains its connection during the snmpd
restart, there may be one walk that returns empty results; the following
walk returns full data once AgentX re-registers (typically within a few
seconds).

**`systemctl restart shorewalld`**

Safe from the perspective of the other daemons.  The walker loop, trap
listener, and D-Bus client all restart cleanly.  keepalived and snmpd see
no state change.  The `_print_stats_clear_unavailable` fallback flag is
reset.  Prometheus counters (`shorewalld_keepalived_events_total`) reset
to zero.

### Smoke test

After deploying, verify each layer in order:

```bash
# 1. Sockets exist with the right permissions
ls -l /run/snmpd/snmpd.sock
#   Expected: srw-rw---- 1 root shorewalld ...  (mode 0660, group shorewalld)

ls -l /run/shorewalld/snmp-trap.sock
#   Expected: srw-rw---- 1 shorewalld shorewalld ...

# 2. keepalived AgentX registered — walk returns KEEPALIVED-MIB data
snmpwalk -v2c -c public unix:/run/snmpd/snmpd.sock 1.3.6.1.4.1.9586.100.5.1.1
#   Expected: one or more lines like:
#     KEEPALIVED-MIB::vrrpVersion.0 = STRING: "2.3.x"
#   Empty output → keepalived not started with -x, or AgentX path mismatch.

# 3. D-Bus method reachable from the shorewalld user
sudo -u shorewalld dbus-send --system \
    --dest=org.keepalived.Vrrp1 \
    --type=method_call --print-reply \
    /org/keepalived/Vrrp1/Vrrp \
    org.keepalived.Vrrp1.Vrrp.PrintData
#   Expected: method return (no body) + /run/keepalived/keepalived.data written.
#   "org.freedesktop.DBus.Error.NameHasNoOwner" → keepalived not running or
#     not compiled with --enable-dbus.
#   "org.freedesktop.DBus.Error.AccessDenied" → D-Bus policy not reloaded.

# 4. shorewalld picked up the walk data
curl -s localhost:9748/metrics | grep shorewalld_keepalived_version
#   Expected: shorewalld_keepalived_version{value="2.3.x"} 1
#   Absent → walk hasn't completed yet (wait up to KEEPALIVED_WALK_INTERVAL=30s)
#             or snmpd socket unreachable.

# 5. Control-socket command round-trips
shorewalld-ctl keepalived-data | head -5
#   Expected: first lines of /run/keepalived/keepalived.data content.
#   "KeepalivedDbusAclDenied" → KEEPALIVED_DBUS_METHODS=none.
#   "NameHasNoOwner" → keepalived not running.

# 6. Event counters increment on VRRP state change (trigger a failover or
#    restart keepalived and check the counter bumped)
curl -s localhost:9748/metrics | grep shorewalld_keepalived_events_total
#   Expected after any VRRP state change:
#     shorewalld_keepalived_events_total{type="dbus_signal_VrrpStatusChange"} N
```

**Diagnosing a silent failure (metrics absent but no error logged):**

- Walk counter stuck at 0: `snmpd` socket not found or `python3-netsnmp` not
  installed.
- Walk counter incrementing but `vrrpInstanceState` absent: keepalived not
  registered as AgentX sub-agent.  Check `snmpwalk` step above.
- D-Bus signals not arriving: `dbus-next` not installed, or shorewalld
  started before `dbus.service` was ready.
- `keepalived-data` returns empty bytes: `tmp_config_directory` not set
  and `PrivateTmp=yes` is active — keepalived wrote to host `/tmp` but
  shorewalld reads from its private tmpfs.  Fix: set
  `tmp_config_directory /run/keepalived`.

---

## Multi-netns deployment

The default config (a single keepalived + snmpd pair running in the host
network namespace) is covered in the sections above.  This section
documents the less-common topologies where network namespaces are in play.

### A. Per-netns firewall stack (recommended for HA firewalls with routing-table separation)

Each firewall netns runs its own keepalived + snmpd; a single shorewalld
process on the host reads all of them via per-netns Unix sockets.

**Topology:**

```text
┌─── host netns ────────────────────────────────────────────────────┐
│  shorewalld                                                        │
│    KEEPALIVED_SNMP_UNIX=/run/shorewalld/netns/fw-blue/snmpd.sock  │
│    (future: multi-netns walker — see note below)                  │
│                                                                    │
│  ┌── fw-blue netns ──────────────┐  ┌── fw-green netns ─────────┐ │
│  │  keepalived -x -D            │  │  keepalived -x -D          │ │
│  │  snmpd → /run/shorewalld/    │  │  snmpd → /run/shorewalld/ │ │
│  │          netns/fw-blue/      │  │          netns/fw-green/  │ │
│  │          snmpd.sock          │  │          snmpd.sock       │ │
│  └──────────────────────────────┘  └───────────────────────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

**Why Unix sockets cross netns boundaries but not mount-ns boundaries.**
Named network namespaces (created via `ip netns add`) share the host's
mount namespace by default — there is no separate filesystem tree.  A Unix
socket path is resolved against the mount namespace of the process that
opens it, not the network namespace it lives in.  Consequently, a socket
created by snmpd inside `fw-blue`'s network namespace at
`/run/shorewalld/netns/fw-blue/snmpd.sock` is visible to shorewalld on
the host at exactly that path, because both processes share the same
`/run` tmpfs.  The network namespace context does not affect socket-path
resolution at all.

This breaks down only when a separate mount namespace is also applied (as
with `unshare -m` or `systemd-nspawn`).  In that case, use a bind-mount
to project the socket into the host path (see Scenario C).

**snmpd invocation per netns:**

```bash
ip netns exec fw-blue /usr/sbin/snmpd \
    -f -Lo \
    -C -c /etc/snmp/fw-blue.conf \
    -p /run/snmpd-fw-blue.pid
```

`fw-blue.conf` sets an in-netns socket path (the directory must exist
before snmpd starts):

```ini
# /etc/snmp/fw-blue.conf
agentAddress unix:/run/shorewalld/netns/fw-blue/snmpd.sock,0660,root,shorewalld
trap2sink unix:/run/shorewalld/netns/fw-blue/snmp-trap.sock
master agentx
agentXSocket unix:/run/shorewalld/netns/fw-blue/agentx.sock
rocommunity public default
```

Create the runtime directory before starting snmpd (or use a systemd
`tmpfiles.d` drop-in):

```bash
install -d -m 0750 -o root -g shorewalld /run/shorewalld/netns/fw-blue
```

**shorewalld-side — current constraint.**  shorewalld currently supports
one `KEEPALIVED_SNMP_UNIX` per daemon instance.  For multi-netns coverage
today, run one shorewalld instance per netns, each with its own
`--control-socket` and `--listen-prom` port:

```bash
# host (default netns) — covers fw-blue keepalived
shorewalld \
    --listen-prom :9748 \
    --keepalived-snmp-unix /run/shorewalld/netns/fw-blue/snmpd.sock \
    --keepalived-trap-socket /run/shorewalld/netns/fw-blue/snmp-trap.sock \
    --control-socket /run/shorewalld/control-fw-blue.sock

# host (default netns) — covers fw-green keepalived
shorewalld \
    --listen-prom :9749 \
    --keepalived-snmp-unix /run/shorewalld/netns/fw-green/snmpd.sock \
    --keepalived-trap-socket /run/shorewalld/netns/fw-green/snmp-trap.sock \
    --control-socket /run/shorewalld/control-fw-green.sock
```

Open follow-up: a future multi-netns walker will allow a single shorewalld
instance to scrape sockets from all managed netns via one
`KEEPALIVED_SNMP_UNIX` per netns block.  Until then, the per-instance
approach above is the supported path.

**Alternative workaround (not recommended).**  Symlinking or bind-mounting
all per-netns sockets under a single path prefix and rotating
`KEEPALIVED_SNMP_UNIX` via per-netns control-socket reconfig works in
principle but requires external orchestration and makes the socket inventory
implicit.  Document the approach in internal runbooks rather than relying
on it in production.

**Production systemd units**: prefer `NetworkNamespacePath=` in the
keepalived and snmpd unit files over `ExecStartPre=ip netns exec` —
`ip netns exec` requires `CAP_SYS_ADMIN` in the invoking unit and drops
no privileges of its own, while `NetworkNamespacePath=` lets systemd
pin the unit to a pre-existing named netns and apply `User=` / capability
restrictions normally:

```systemd
# /etc/systemd/system/keepalived-fw-blue.service
[Service]
NetworkNamespacePath=/var/run/netns/fw-blue
ExecStart=/usr/sbin/keepalived -x -D -n
```

### B. Shared netns (host-global keepalived + snmpd, simplest)

Single keepalived + single snmpd both running in the host network
namespace.  shorewalld reads from `/run/snmpd/snmpd.sock`.  This is the
default config; see the [snmpd configuration](#snmpd-configuration) and
[shorewalld configuration](#shorewalld-configuration) sections above.

### C. Containerised deployment (Docker / Podman / systemd-nspawn)

**snmpd container.**  Bind-mount the socket directory from the host so
shorewalld on the host can still reach the socket:

```bash
docker run -d --name snmpd \
    -v /run/snmpd:/run/snmpd \
    -v /var/run/agentx.sock:/var/run/agentx.sock \
    my-snmpd-image
```

shorewalld on the host reads `/run/snmpd/snmpd.sock` as normal.

**shorewalld container.**  Mount the snmpd socket directory read-only and
the shorewalld runtime directory read-write:

```bash
docker run -d --name shorewalld \
    -v /run/snmpd:/run/snmpd:ro \
    -v /run/shorewalld:/run/shorewalld:rw \
    my-shorewalld-image \
    shorewalld --keepalived-snmp-unix /run/snmpd/snmpd.sock
```

**keepalived container.**  keepalived uses VRRP (IP protocol 112,
multicast 224.0.0.18), which requires raw network access — use
`--network=host`.  D-Bus requires the system bus socket:

```bash
docker run -d --name keepalived \
    --network=host \
    --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -v /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket:ro \
    my-keepalived-image
```

**`/tmp/keepalived.*` in containers.**  keepalived writes
`/tmp/keepalived.data` and `/tmp/keepalived.stats` to its own container's
`/tmp`, which is not the host's `/tmp`.  If shorewalld's `keepalived-data`
/ `keepalived-stats` control-socket commands are needed, either:
- Mount a shared volume at `/tmp/keepalived/` in both containers and set
  `global_defs { tmp_config_directory /tmp/keepalived/ }` in
  `keepalived.conf`, or
- Rely entirely on D-Bus + SNMP paths and skip the `/tmp/keepalived.*`
  file reads.  The D-Bus methods still return the data; the issue is
  only the intermediate file that keepalived writes before shorewalld
  reads it.

### D. Security caveats for multi-netns

- **SNMP AgentX sees only the netns it runs in.**  A keepalived AgentX
  sub-agent registered inside `fw-blue` sees only that netns's interfaces,
  routing table, and conntrack state.  This is correct isolation; but if
  an operator runs one global snmpd and expects one AgentX registration to
  cover all netns, it will not.  Run one snmpd per netns.
- **Trap forwarding across netns.**  `trap2sink unix:<path>` resolves the
  path at snmpd startup against the mount namespace.  For per-netns snmpd
  instances (Scenario A), point each `trap2sink` at a per-netns socket
  path under `/run/shorewalld/netns/<name>/` — the same `/run` tmpfs is
  visible to all because only the network namespace differs, not the mount
  namespace.
- **`ip netns exec` vs. `NetworkNamespacePath=`.**  `ip netns exec` calls
  `setns(2)` and requires `CAP_SYS_ADMIN` in the invoking process.  Using
  `NetworkNamespacePath=` in a systemd unit avoids this requirement in the
  service's own ExecStart — systemd holds the `CAP_SYS_ADMIN` needed for
  `setns(2)` internally, and the service process itself can run without it.
  Prefer `NetworkNamespacePath=` for all production netns-pinned services.

---

## Filesystem ACLs and socket permissions

shorewalld, snmpd, and keepalived each own a socket or output file.
Getting the permissions right is necessary when any of these processes
runs as a non-root user.  This section works through each surface.

### snmpd agent socket (`/run/snmpd/snmpd.sock`)

snmpd creates the Unix socket at startup.  The default mode is `0600
root:root` — no other process can connect.  shorewalld needs read/write
access to send SNMP requests.

**Net-SNMP 5.8+ comma-extension syntax (preferred).**  The `agentAddress`
line accepts `<mode>,<owner>,<group>` after the path:

```ini
agentAddress unix:/run/snmpd/snmpd.sock,0660,root,shorewalld
```

This creates the socket mode `0660`, owned `root:shorewalld`.  Any process
running as the `shorewalld` group can connect.  The existing UDP address
can be appended with a space-separated additional line or by using the
`agentAddress` directive twice:

```ini
agentAddress unix:/run/snmpd/snmpd.sock,0660,root,shorewalld
agentAddress udp:127.0.0.1:161
```

**Older net-snmp (pre-5.8) fallback.**  Use a `systemd-tmpfiles` drop-in
to pre-create the directory with the right group, and a systemd override
to `chgrp` the socket after bind.

`/etc/tmpfiles.d/shorewalld-snmp.conf`:

```text
d /run/snmpd 0750 root shorewalld -
```

Systemd override for snmpd (`/etc/systemd/system/snmpd.service.d/socket-perms.conf`):

```systemd
[Service]
ExecStartPost=/bin/chgrp shorewalld /run/snmpd/snmpd.sock
ExecStartPost=/bin/chmod 0660 /run/snmpd/snmpd.sock
```

Apply: `systemd-tmpfiles --create && systemctl daemon-reload && systemctl restart snmpd`.

### shorewalld trap socket (`/run/shorewalld/snmp-trap.sock`)

shorewalld creates this socket in `KeepalivedTrapListener.start()` with
mode `0o660` (hard-coded default).  The socket is owned by the shorewalld
process UID and the group that shorewalld runs under.

snmpd must be able to write to this socket to forward traps.  The simplest
fix is to add snmpd's user to the `shorewalld` group:

```bash
# Debian/Ubuntu — snmpd runs as Debian-snmp
usermod -aG shorewalld Debian-snmp

# RHEL/Fedora/Alma — snmpd runs as snmp (or root)
usermod -aG shorewalld snmp
```

Then restart snmpd so the new group membership takes effect.

The `/run/shorewalld/` directory itself is created by the systemd unit's
`RuntimeDirectory=shorewalld` directive (mode `0750`, owned by the
shorewalld user).  A `tmpfiles.d` drop-in that pre-creates it with the
right group is only needed if shorewalld runs outside of systemd:

```text
# /etc/tmpfiles.d/shorewalld.conf
d /run/shorewalld 0750 shorewalld shorewalld -
```

**RHEL/Alma note.**  On RHEL-family systems snmpd often runs as root, in
which case the `0660` socket mode grants access automatically — no group
membership change is required.  Verify with `systemctl show snmpd -p User`.

### keepalived output files (`/tmp/keepalived.data`, `/tmp/keepalived.stats`)

keepalived writes these files world-readable (`0644 root:root`) in
response to `PrintData()` / `PrintStats()` D-Bus calls.  shorewalld reads
them back and returns the content to the control-socket caller.

**Race condition.**  keepalived overwrites the file on each call.  Two
concurrent callers (e.g. shorewalld's control socket and a manual
`dbus-send PrintData`) can produce a partial read.  shorewalld serialises
all D-Bus method calls through the control-socket handler, so
daemon-internal races are not possible.  External callers (`dbus-send`,
scripts) are not serialised — avoid running them in parallel with
shorewalld in production.

**Safer alternative path.**  Move the output files out of `/tmp` to a
mode-restricted tmpfs directory:

```
# /etc/keepalived/keepalived.conf — global_defs block
global_defs {
    tmp_config_directory /run/keepalived
}
```

Create the directory with restricted permissions:

```bash
install -d -m 0750 -o root -g shorewalld /run/keepalived
```

keepalived will write `/run/keepalived/keepalived.data` and
`/run/keepalived/keepalived.stats`, readable only by root and the
shorewalld group.

**PrivateTmp interaction.**  The shorewalld.service unit ships with
`PrivateTmp=yes`.  When keepalived writes to `/tmp/keepalived.data` (in
the **host's** `/tmp`) and shorewalld reads it (from its **private** `/tmp`),
the read will fail — shorewalld sees an empty private tmpfs, not the host
`/tmp`.  Two options:

1. Use `tmp_config_directory /run/keepalived` as above (recommended) — the
   `/run/` filesystem is not affected by `PrivateTmp`.
2. Drop `PrivateTmp=yes` from the shorewalld.service override (weakens
   sandbox; not recommended unless option 1 is impractical).

### D-Bus system-bus policy

keepalived's default D-Bus policy (`/etc/dbus-1/system.d/org.keepalived.Vrrp1.conf`)
allows only `root` to call its methods.  For non-root shorewalld
deployments, add a policy drop-in.

**Permissive drop-in** (`/etc/dbus-1/system.d/shorewalld-keepalived.conf`)
— allows the shorewalld user to call any keepalived method and receive its
signals:

```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="shorewalld">
    <allow send_destination="org.keepalived.Vrrp1"/>
    <allow receive_sender="org.keepalived.Vrrp1"/>
  </policy>
</busconfig>
```

Reload: `systemctl reload dbus` (or `systemctl restart dbus` on systems
that do not support hot-reload of policy files).

**Restricted drop-in** — if `KEEPALIVED_DBUS_METHODS=readonly` (the
default), only `PrintData` and `PrintStats[Clear]` are ever called.  The
permissive policy above still allows `ReloadConfig` and `SendGarp` at the
D-Bus layer; shorewalld's own `method_acl` tier blocks them in software.
For defence-in-depth, restrict the D-Bus policy to only the methods
shorewalld actually needs:

```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="shorewalld">
    <!-- signals — always needed for VrrpStatusChange and lifecycle signals -->
    <allow receive_sender="org.keepalived.Vrrp1"/>
    <!-- read-only methods only -->
    <allow send_destination="org.keepalived.Vrrp1"
           send_interface="org.keepalived.Vrrp1.Vrrp"
           send_member="PrintData"/>
    <allow send_destination="org.keepalived.Vrrp1"
           send_interface="org.keepalived.Vrrp1.Vrrp"
           send_member="PrintStats"/>
    <allow send_destination="org.keepalived.Vrrp1"
           send_interface="org.keepalived.Vrrp1.Vrrp"
           send_member="PrintStatsClear"/>
  </policy>
</busconfig>
```

If `KEEPALIVED_DBUS_METHODS=all`, also add `ReloadConfig` and `SendGarp`
to the `<policy>` block.

**Layered ACL model.**  shorewalld's `KEEPALIVED_DBUS_METHODS` tier is a
second enforcement layer on top of the D-Bus policy — neither replaces the
other.  With `KEEPALIVED_DBUS_METHODS=readonly` and the restricted policy
above, `ReloadConfig` is blocked at two independent points: the D-Bus bus
daemon refuses the message before it reaches keepalived, and shorewalld
would refuse to send it anyway.  This is defence-in-depth; both layers
should be configured consistently.

Cross-reference: shorewalld's control-socket permissions
(`/run/shorewalld/control.sock`) are documented in `docs/shorewalld/index.md`.

**SELinux / AppArmor.**  Confinement profiles for keepalived and shorewalld
are outside the scope of this document.  If your distribution ships SELinux
policy for keepalived, ensure the shorewalld domain has `dbus_send` and
`dbus_receive` permissions for `org.keepalived.Vrrp1`.

### systemd hardening for shorewalld.service

The packaged `shorewalld.service` already includes:

```systemd
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/shorewalld /var/lib/shorewalld /var/log
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN
```

Notes on each directive:

- **`ProtectSystem=strict`** — mounts the entire filesystem read-only
  except for `ReadWritePaths`.  Effective as-is; no action needed.
- **`ProtectHome=yes`** — blocks access to `/home`, `/root`, `/run/user`.
  Correct for daemon use.
- **`PrivateTmp=yes`** — gives shorewalld its own private `/tmp`.
  Interacts with keepalived's `/tmp/keepalived.*` files — see
  [keepalived output files](#keepalived-output-files-tmpkeepaliveddata-tmpkeepalivedstats)
  above.
- **`ReadWritePaths=/run/shorewalld /var/lib/shorewalld /var/log`** —
  covers the control socket, trap socket, DNS-set state, and log file.
  If `tmp_config_directory` is set to `/run/keepalived`, add
  `/run/keepalived` here (read-only suffices for shorewalld):
  `ReadOnlyPaths=/run/keepalived`.
- **`CAP_NET_ADMIN`** — required for nft writes inside netns and for
  binding the `nfnetlink_log` socket when `LOG_DISPATCH=shorewalld`.
- **`CAP_NET_RAW`** — retained conservatively; not strictly required
  by current code paths.
- **`CAP_SYS_ADMIN`** — required for `setns(2)` into named network
  namespaces.  If shorewalld manages only the default netns (no named
  netns in `NETNS=`), this capability can be dropped to reduce the
  attack surface:
  ```systemd
  # /etc/systemd/system/shorewalld.service.d/no-setns.conf
  [Service]
  CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
  AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
  ```
  For multi-netns deployments, `CAP_SYS_ADMIN` is required and cannot
  be dropped.

### Defence-in-depth ordering

The full permission stack from outermost to innermost:

1. **Unix socket permissions** — who can open the snmpd agent socket or
   the shorewalld trap socket.  Controlled by socket mode + group
   ownership (this section).  No UDP port exposed to the network by
   default.
2. **D-Bus system-bus policy** — who can send messages to
   `org.keepalived.Vrrp1` and receive its signals.  Controlled by the
   drop-in policy file above.
3. **shorewalld `KEEPALIVED_DBUS_METHODS` ACL tier** — which D-Bus
   methods shorewalld itself will call on behalf of a control-socket
   caller.  Controlled by `shorewalld.conf`.
4. **Control-socket permissions** — who can send commands to shorewalld's
   control socket (`/run/shorewalld/control.sock`).  Controlled by the
   socket's Unix permissions; see `docs/shorewalld/index.md` for the
   `SOCKET_MODE` / `SOCKET_GROUP` knobs.

Each layer is independently enforceable.  A misconfiguration at layer 3
(e.g. `KEEPALIVED_DBUS_METHODS=all` when you intended `readonly`) is
still bounded by the D-Bus policy at layer 2.

---

## D-Bus ACL explainer

`KEEPALIVED_DBUS_METHODS` controls which D-Bus method calls the control
socket will forward to keepalived:

| Tier | Allowed methods | Notes |
|------|----------------|-------|
| `none` | — | All D-Bus method calls denied |
| `readonly` (default) | `print_data`, `print_stats` | Safe: read-only file dump |
| `all` | All of the above + `reload_config`, `send_garp` | State-changing |

`reload_config` causes keepalived to reload its configuration file —
equivalent to `SIGHUP` but synchronous over D-Bus.  `send_garp` sends a
Gratuitous ARP for a named VRRP instance (useful after manual failover
testing).

`CreateInstance` / `DestroyInstance` are gated separately by
`KEEPALIVED_DBUS_CREATE_INSTANCE` because they require keepalived to be
compiled with `--enable-dbus-create-instance`.

---

## D-Bus pitfalls

OS-level D-Bus gotchas that can silently break the integration even when
file permissions and policy files look correct.

### keepalived build-time D-Bus flag

Not all distro packages compile keepalived with D-Bus support.  A missing
build flag causes shorewalld's D-Bus client to raise
`KeepalivedDbusUnavailable` silently and fall back to SNMP walk + trap
listener only — all three `shorewalld_keepalived_*` metric families still
work, but the `keepalived-data` / `keepalived-stats` control-socket
commands fail.

Check before deploying:

```bash
keepalived --help 2>&1 | grep -i dbus
# Expected when compiled in: "--enable-dbus" or "-D" in the help text.
# Nothing → D-Bus not compiled; shorewalld D-Bus client will be a no-op.

keepalived -v 2>&1
# Some builds include a "Build options: ..." line listing --enable-dbus.
```

Distro notes:

- **Debian / Ubuntu bookworm+** — `keepalived` from Debian main ships with
  `--enable-dbus`.  Ubuntu focal and later: same.  Check with
  `dpkg -l keepalived` + `keepalived --help`.
- **Fedora** — `keepalived` spec typically enables D-Bus; verify with
  `rpm -qi keepalived | grep -i dbus` (or the `--help` check above).
- **AlmaLinux 10 / RHEL 9** — D-Bus may or may not be enabled depending
  on the AppStream version.  The SNMP-only fallback path (walker + trap
  listener) is fully supported and is the recommended path for these
  platforms if keepalived D-Bus is unavailable.
- **RHEL/CentOS 7/8 (legacy)** — rarely compiled with D-Bus.  Use the
  SNMP-only path.

When D-Bus is unavailable, the integration still provides full SNMP MIB
coverage (`shorewalld_keepalived_*` gauges and counters from the walker)
and trap-driven event counters.  Only the `keepalived-data` /
`keepalived-stats` / `keepalived-reload` / `keepalived-garp`
control-socket commands are absent.

### System bus vs session bus

keepalived always registers on the **system bus** (`BusType.SYSTEM` in
`dbus_client.py`).  Testing with `--session` returns
`No such interface` or `NameHasNoOwner` — it is looking at the wrong bus.
Always use `--system`:

```bash
# Wrong — queries the session bus:
dbus-send --session --dest=org.keepalived.Vrrp1 ...

# Correct:
dbus-send --system --dest=org.keepalived.Vrrp1 ...
```

The same applies to `busctl` and `gdbus`: always pass `--system` or
`system` as the bus specifier.

### D-Bus service activation vs imperative registration

keepalived does **not** install a `.service` file in
`/usr/share/dbus-1/system-services/` — there is no D-Bus service
activation.  keepalived registers its bus name (`org.keepalived.Vrrp1`)
imperatively at startup.  The bus name exists only while keepalived is
running.

When keepalived is stopped, any attempt to send a method call to
`org.keepalived.Vrrp1` returns:

```
Error org.freedesktop.DBus.Error.NameHasNoOwner:
  Name "org.keepalived.Vrrp1" does not exist
```

shorewalld catches this and returns a JSON error to the control-socket
caller.  `dbus-send` users see the bare error text above — it is not a
policy problem, it is not a permission problem; keepalived is simply not
running.

`busctl` gives the same answer in a slightly different format:

```bash
busctl --system status org.keepalived.Vrrp1
# "Failed to get information: Unit not found" or similar — not helpful.

busctl --system list | grep keepalived
# Empty → keepalived not running.  One line → it is.
```

### D-Bus method timeouts and missing retry

`KeepalivedDbusClient._call_method()` calls `bus.call(Message(...))` with
no explicit timeout configured.  The dbus-next default reply timeout is
25 seconds.  `PrintData()` on a busy keepalived instance — 50+ VRRP
instances, many virtual-server entries — can take over 1 second to write
`/run/keepalived/keepalived.data` to disk.  Under normal load this is not
a problem, but during a keepalived state storm (many simultaneous
transitions) the call may block the asyncio event loop for the full
reply-wait duration.

**There is currently no configurable timeout knob** for the D-Bus call
in shorewalld.  If `PrintData()` or `PrintStats()` blocks for longer
than the dbus-next internal timeout (25 s), dbus-next raises an
exception that propagates to the control-socket caller.  Adding a
per-call timeout (via `asyncio.wait_for`) is a follow-up item.

**`PrintStatsClear` fallback is a one-way ratchet.**  `print_stats(clear=True)`
first tries `PrintStatsClear` (keepalived ≥ 2.2.7).  If that call fails
— for example because keepalived is restarting and the bus name is briefly
absent — `_print_stats_clear_unavailable` is set to `True` and all
subsequent `print_stats(clear=True)` calls use `PrintStats` instead (no
clear).  The flag is never reset during a shorewalld lifetime; restart
shorewalld to restore `PrintStatsClear` behaviour.

**Method calls do not auto-retry.**  If `print_data()` fails with
`NameHasNoOwner` (keepalived restarting), the error propagates
immediately to the control-socket caller.  There is no backoff-and-retry
loop.  Callers that need reliability should poll.

### AppArmor and SELinux interactions

**AppArmor (Debian/Ubuntu).**  If the `usr.sbin.keepalived` AppArmor
profile is in enforce mode, it may restrict writes to
`/run/keepalived/keepalived.data` (the `tmp_config_directory` path).
`PrintData()` silently succeeds on D-Bus but writes nothing — shorewalld
reads an empty or stale file.

Check profile status:

```bash
aa-status | grep keepalived
# "keepalived (enforce)" → profile active.
```

Work-around options (in order of preference):

1. Extend the profile to allow writes to `/run/keepalived/`:
   ```
   # /etc/apparmor.d/local/usr.sbin.keepalived
   /run/keepalived/ rw,
   /run/keepalived/** rw,
   ```
   Then `apparmor_parser -r /etc/apparmor.d/usr.sbin.keepalived`.
2. Set the profile to complain mode for debugging:
   `aa-complain /usr/sbin/keepalived` (do not leave in production).

Do **not** run keepalived unconfined in production.

**SELinux (RHEL / AlmaLinux).**  `keepalived_t` is a defined SELinux type.
`PrintData()` may hit an AVC denial when writing to `tmp_config_directory`
if the target path has a different file context than keepalived's default
write paths:

```bash
# Check for recent AVC denials:
ausearch -m AVC -ts recent | grep keepalived
```

If `/run/keepalived` shows `var_run_t` but keepalived needs `keepalived_var_run_t`:

```bash
semanage fcontext -a -t keepalived_var_run_t '/run/keepalived(/.*)?'
restorecon -Rv /run/keepalived
```

D-Bus itself has its own SELinux domain (`system_dbusd_t`).  If shorewalld
runs in a confined SELinux domain (not `unconfined_t`), it needs permission
to send D-Bus messages to keepalived:

```
# What to look for in AVC denials:
# avc:  denied  { send_msg } for  scontext=shorewalld_t
#   tcontext=system_dbusd_t  tclass=dbus
```

Writing the full SELinux policy module is outside the scope of this
document.  Reference: `shorewall-nft` RPM packaging ships no SELinux
policy module at this time — operators on SELinux-enforcing systems should
run shorewalld as `unconfined_t` until a policy module is provided, or
contribute one upstream.

### Signal flood at startup

When keepalived starts or reloads on an N-instance HA firewall, it emits
`VrrpStatusChange` for every VRRP instance in quick succession as each
instance transitions from `init` → `backup` or `init` → `master`.  On a
firewall with 10 VRRP instances, this produces 10 signals within a
sub-second window.

shorewalld counts each one:

```
shorewalld_keepalived_events_total{type="dbus_signal_VrrpStatusChange"} 10
```

If your alerting rule fires on a rate-of-change threshold (e.g.,
`rate(shorewalld_keepalived_events_total{type=~".*VrrpStatusChange.*"}[1m]) > 1`),
the startup burst triggers a false alarm.

Recommendation: suppress the alert for 60 seconds after
`shorewalld_keepalived_walks_total` begins rising from zero (proxy for
"shorewalld just started").  Example Prometheus inhibit rule:

```yaml
- alert: VrrpFlapping
  expr: |
    rate(shorewalld_keepalived_events_total{type="dbus_signal_VrrpStatusChange"}[5m]) > 0.1
  for: 2m    # 2-minute hold suppresses the startup burst
  labels:
    severity: warning
```

The `for: 2m` hold absorbs the typical startup burst (all signals arrive
within 5 s) without delaying detection of genuine sustained flapping.

### keepalived version differences

**Signal and method availability** varies by keepalived version.
shorewalld subscribes to four signals and exposes one optional method:

| Feature | First available in | Notes |
|---------|-------------------|-------|
| `VrrpStarted` signal | keepalived ≥ 2.2.7 | Not emitted by older builds |
| `VrrpReloaded` signal | keepalived ≥ 2.2.7 | Not emitted by older builds |
| `VrrpStopped` signal | keepalived ≥ 2.2.7 | Not emitted by older builds |
| `VrrpStatusChange` signal | keepalived ≥ 2.0.x | Long-established |
| `PrintStatsClear` method | keepalived ≥ 2.2.7 | shorewalld falls back to `PrintStats` if absent (one-way ratchet — see above) |

On keepalived < 2.2.7, `print_stats(clear=True)` is permanently downgraded
to `print_stats(clear=False)` after the first call (due to the one-way
ratchet).  Upgrade to keepalived ≥ 2.2.7 and restart shorewalld to
restore the clear behaviour.

The SNMP walk uses the **KEEPALIVED-MIB** (enterprise OID
`1.3.6.1.4.1.9586.100.5`) — this is the keepalived v1 SNMP MIB, not
VRRPv3-MIB (`1.3.6.1.2.1.207`).  VRRPv3-MIB coverage is out of scope
for the current shorewalld integration.

### D-Bus message size limit

keepalived's `PrintData()` on a large configuration (50+ VRRP instances,
many virtual-server table entries) can produce multi-kilobyte output.
D-Bus itself has a `max_message_size` limit in `/etc/dbus-1/system.conf`.
The default on most distributions is 128 MB — never reached in practice.

Some hardened distributions (Alpine Linux, certain NixOS configurations)
reduce `max_message_size` to 32 KB or lower.  If `PrintData()` fails with:

```
org.freedesktop.DBus.Error.LimitsExceeded: Message size limit exceeded
```

The limit is the `<limits>` stanza in the system bus policy:

```xml
<!-- /etc/dbus-1/system.conf or /etc/dbus-1/system.d/*.conf -->
<limit name="max_message_size">1048576</limit>   <!-- 1 MB — raise if needed -->
```

Note: the keepalived D-Bus reply body for `PrintData()` is typically in
the range of 2–20 KB even for large configs; the file written to
`/run/keepalived/keepalived.data` carries the full data.  The D-Bus
message itself only contains a return code.  If `ExceededMaximumSize`
appears, the config is unusually large or the limit has been set
extremely low — check `PrintData()`'s reply body size with `dbus-monitor`.

---

## Prometheus metrics

Metric families are auto-registered from the committed MIB tables at startup.
No hardcoded OID list — adding a new keepalived version means regenerating
`mib.py` (see `tools/gen_keepalived_mib.py`).

### Naming convention

| MIB object type | Family name pattern | Prometheus type |
|-----------------|---------------------|-----------------|
| Scalar (`DisplayString`, `Gauge32`, …) | `shorewalld_keepalived_<name>` | gauge |
| Table column (`Gauge32`, `Integer32`, `Unsigned32`) | `shorewalld_keepalived_<colname>` | gauge |
| Table column (`Counter32`, `Counter64`) | `shorewalld_keepalived_<colname>_total` | counter |
| Trap / D-Bus event | `shorewalld_keepalived_events_total{type=<name>}` | counter |

**Example gauge family** (scalar):

```
# HELP shorewalld_keepalived_version keepalived version string
# TYPE shorewalld_keepalived_version gauge
shorewalld_keepalived_version{value="2.3.4"} 1
```

**Example table gauge family** (per-row):

```
# HELP shorewalld_keepalived_vrrpInstanceState VRRP instance state (0=init,1=backup,2=master,3=fault)
# TYPE shorewalld_keepalived_vrrpInstanceState gauge
shorewalld_keepalived_vrrpInstanceState{index="1"} 2
```

**Example counter family** (table column):

```
# HELP shorewalld_keepalived_vrrpInstanceBecomeMaster_total Master-transitions total
# TYPE shorewalld_keepalived_vrrpInstanceBecomeMaster_total counter
shorewalld_keepalived_vrrpInstanceBecomeMaster_total{index="1"} 4
```

**Event counter** (traps + D-Bus signals combined):

```
# HELP shorewalld_keepalived_events_total keepalived events by type
# TYPE shorewalld_keepalived_events_total counter
shorewalld_keepalived_events_total{type="vrrpInstanceStateChange"} 3
shorewalld_keepalived_events_total{type="VrrpStatusChange"} 3
```

### Cardinality guard

Tables with 30+ columns (`vrrpRouteTable`, `virtualServerTable`,
`vrrpRuleTable`) are excluded by default.  Set `KEEPALIVED_WIDE_TABLES=yes`
to enable them.  Cardinality scales as `rows × columns`; a keepalived
instance with 10 virtual servers and `KEEPALIVED_WIDE_TABLES=yes` can emit
~800 time series from `virtualServerTable` alone.

---

## Control-socket commands

These are available when `CONTROL_SOCKET` is configured and
`KEEPALIVED_DBUS_METHODS` is not `none`:

```sh
# Print keepalived data (calls PrintData D-Bus method).
shorewalld-ctl keepalived-data

# Print keepalived stats.
shorewalld-ctl keepalived-stats

# Print and reset stats atomically (preferred; falls back to PrintStats).
shorewalld-ctl keepalived-stats '{"clear": true}'

# Reload keepalived config (requires KEEPALIVED_DBUS_METHODS=all).
shorewalld-ctl keepalived-reload

# Send Gratuitous ARP for a VRRP instance (requires KEEPALIVED_DBUS_METHODS=all).
shorewalld-ctl keepalived-garp '{"instance": "vrrp-wan"}'
```

Using the raw control protocol (`nc -U /run/shorewalld/control.sock`):

```json
{"cmd": "keepalived-stats"}
{"cmd": "keepalived-garp", "instance": "vrrp-wan"}
```

---

## Troubleshooting

**`keepalived SNMP disabled (python3-netsnmp not installed)`**

Install the distro package:
```sh
apt install python3-netsnmp          # Debian/Ubuntu
dnf install net-snmp-python3         # Fedora/RHEL/Alma
```

**`keepalived trap listener disabled (pysnmp not installed)`**

```sh
pip install 'shorewalld[snmp]'       # pip path
apt install python3-pysnmp           # Debian (if packaged)
```

**`keepalived D-Bus disabled (dbus-next not installed)`**

```sh
pip install dbus-next
```

**Socket not found / permission denied on `/run/snmpd/snmpd.sock`**

Check `agentAddress` in `snmpd.conf` includes the Unix path and snmpd has
been restarted.  Verify socket exists: `ls -la /run/snmpd/snmpd.sock`.

**No SNMP data after enabling `KEEPALIVED_SNMP_UNIX`**

Verify keepalived registered its AgentX sub-agent:
```sh
snmpwalk -v2c -c public unix:/run/snmpd/snmpd.sock 1.3.6.1.4.1.9586
```
If this returns data, the walker can reach keepalived.  If empty, check
keepalived was started with `-x` (AgentX) and that `agentXSocket` in
`snmpd.conf` matches `keepalived.conf`'s `agentx_socket` path.

**Walk returns partial data / wide-table rows missing**

Some tables are excluded by the cardinality guard.  Set
`KEEPALIVED_WIDE_TABLES=yes` to include them.

---

## Migration from legacy `VRRP_SNMP_*` config

| Old key | New key | Notes |
|---------|---------|-------|
| `VRRP_SNMP_ENABLED=yes` | `KEEPALIVED_SNMP_UNIX=/run/snmpd/snmpd.sock` | Replace the flag with the socket path |
| `VRRP_SNMP_HOST=127.0.0.1` | *(removed)* | Unix socket transport has no separate host |
| `VRRP_SNMP_PORT=161` | *(removed)* | Unix socket transport has no separate port |
| `VRRP_SNMP_COMMUNITY=public` | *(not configurable yet)* | Defaults to `public`; hardcoded for the Unix socket path |
| `VRRP_SNMP_TIMEOUT=1.0` | *(not configurable yet)* | Defaults to 1 s |

The old keys remain valid for one release.  When both `VRRP_SNMP_ENABLED`
and `KEEPALIVED_SNMP_UNIX` are set simultaneously, shorewalld emits a
deprecation warning at startup and runs both collectors in parallel (the
metric family names do not collide).  Remove `VRRP_SNMP_*` from
`shorewalld.conf` to silence the warning.
