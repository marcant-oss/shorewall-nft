"""Fully-resolved runtime configuration for shorewalld's Daemon.

Built by :mod:`shorewalld.cli` by merging :class:`~shorewalld.config.ConfDefaults`
(from shorewalld.conf) with argparse CLI flags. Pass to
:class:`~shorewalld.core.Daemon` as a single ``config=`` argument instead of
~25 kwargs.

Fields mirror :class:`~shorewalld.config.ConfDefaults` but every value is
concrete (no ``| None``): the CLI layer is responsible for resolving defaults
before instantiating.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class DaemonConfig:
    """All knobs the daemon needs at runtime.

    Every field is typed and non-optional.  The CLI layer resolves
    argparse defaults + shorewalld.conf values before constructing this
    object so the Daemon itself never has to guess about missing config.

    Fields are ordered to match the :class:`~shorewalld.core.Daemon`
    ``__init__`` signature, making the migration mechanical.

    Subsystem groups
    ----------------
    * **Prometheus** — ``prom_host``, ``prom_port``
    * **Core** — ``api_socket``, ``netns_spec``
    * **Scrape timing** — ``scrape_interval``, ``reprobe_interval``
    * **DNS-set pipeline** — ``allowlist_file`` … ``batch_window_seconds``
    * **Unix socket permissions** — ``socket_mode``, ``socket_owner``,
      ``socket_group``
    * **HA peer link** — ``peer_bind_host`` … ``peer_heartbeat_interval``
    * **State persistence** — ``state_dir`` … ``state_flush``
    * **Multi-instance / iplist / control** — ``instances`` …
      ``iplist_configs``
    * **VRRP SNMP** — ``enable_vrrp_collector`` … ``vrrp_snmp_timeout``
    """

    # ── Prometheus endpoint ───────────────────────────────────────────
    prom_host: str
    prom_port: int

    # ── Core ─────────────────────────────────────────────────────────
    api_socket: str | None
    netns_spec: list[str] | str

    # ── Scrape timing ─────────────────────────────────────────────────
    scrape_interval: float
    reprobe_interval: float

    # ── DNS-set pipeline ──────────────────────────────────────────────
    allowlist_file: Path | None = None
    pbdns_socket: str | None = None
    pbdns_tcp: str | None = None

    # ── Unix socket permissions ───────────────────────────────────────
    socket_mode: int | None = None
    socket_owner: str | int | None = None
    socket_group: str | int | None = None

    # ── HA peer link ──────────────────────────────────────────────────
    peer_bind_host: str | None = None
    peer_bind_port: int | None = None
    peer_host: str | None = None
    peer_port: int | None = None
    peer_auth_key_file: Path | None = None
    peer_heartbeat_interval: float = 5.0

    # ── State persistence ─────────────────────────────────────────────
    state_dir: Path | None = None
    state_enabled: bool = True
    state_no_load: bool = False
    state_flush: bool = False

    # ── Multi-instance / iplist / control ────────────────────────────
    instances: tuple[str, ...] = field(default_factory=tuple)
    control_socket: str | None = None
    control_socket_netns: str | None = None
    iplist_configs: tuple[Any, ...] = field(default_factory=tuple)

    # ── VRRP SNMP augmentation ────────────────────────────────────────
    enable_vrrp_collector: bool = False
    vrrp_snmp_enabled: bool = False
    vrrp_snmp_host: str = "127.0.0.1"
    vrrp_snmp_port: int = 161
    vrrp_snmp_community: str = "public"
    vrrp_snmp_timeout: float = 1.0

    # ── DNS-set pipeline tuning ───────────────────────────────────────
    dns_dedup_refresh_threshold: float = 0.5
    batch_window_seconds: float = 0.010

    # ── NFLOG log dispatcher ──────────────────────────────────────────
    # When ``log_dispatch == "shorewalld"``, workers subscribe to
    # ``log_nflog_group`` inside each managed netns and push decoded
    # LogEvents to the parent via MAGIC_NFLOG. See
    # :mod:`shorewalld.log_dispatcher`. The sinks are all optional;
    # ``shorewall_log_total`` Prometheus counter is always emitted
    # when the dispatcher runs.
    #
    # ``ulogd2`` / ``none`` — no worker-side subscription; operator
    # either runs their own ulogd2 (per-netns) or has no dispatcher.
    log_dispatch: str = "none"
    log_nflog_group: int | None = None
    log_dispatch_file: str | None = None     # path; plain-line append
    log_dispatch_socket: str | None = None   # path; unix-socket JSON fan-out
    log_dispatch_journald: bool = False      # structured journal entries
    log_dispatch_syslog: str | None = None   # path to /dev/log (RFC 3164)

    # ── keepalived SNMP / MIB integration ────────────────────────────
    # Unix-socket SNMP transport (python3-netsnmp) + trap listener.
    # When ``keepalived_snmp_unix`` is set the new MIB-driven walker
    # starts; when unset the legacy UDP VrrpCollector path is used
    # (if enabled via ``enable_vrrp_collector``).
    keepalived_snmp_unix: str | None = None      # e.g. "/run/snmpd/snmpd.sock"
    keepalived_trap_socket: str | None = None    # e.g. "/run/shorewalld/snmp-trap.sock"

    # Coverage knobs
    keepalived_wide_tables: bool = False          # enables vrrpRouteTable / virtualServerTable / vrrpRuleTable
    keepalived_scrape_virtual_servers: bool = True  # LVS stats (moderate cardinality)

    # D-Bus method exposure
    keepalived_dbus_methods: str = "readonly"     # "none" | "readonly" | "all"
    keepalived_dbus_create_instance: bool = False  # opt-in; needs --enable-dbus-create-instance build

    # Walk cadence
    keepalived_walk_interval_s: float = 30.0
