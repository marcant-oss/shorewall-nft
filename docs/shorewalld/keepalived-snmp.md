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
