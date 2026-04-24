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
