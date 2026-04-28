"""shorewalld core lifecycle.

``Daemon`` is the single top-level object that owns every subsystem:

* signal handlers + idempotent shutdown (mirrors SimController pattern)
* Prometheus HTTP scrape endpoint
* per-netns collector profiles (wired up in Phase 2/3)
* the dnstap consumer (wired up in Phase 4, off by default)

Phase 1 only exercises the lifecycle — subsystems are stubbed out so
that ``Daemon(...)`` is constructible and ``shutdown()`` is idempotent
in unit tests. Phases 2+ fill in the real work.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import signal
import socket
import sys
from pathlib import Path
from typing import Any

from shorewall_nft.nft.dns_sets import (
    DnsSetRegistry,
    read_compiled_allowlist,
    read_compiled_dnsr_allowlist,
)
from shorewall_nft.nft.netlink import NftInterface

from . import sd_notify
from .control import ControlMetricsCollector, ControlServer
from .control_handlers import ControlHandlers
from .daemon_config import DaemonConfig
from .discover import ProfileBuilder, resolve_netns_list
from .dns_pull_resolver import PullResolver, PullResolverMetricsCollector
from .dns_set_tracker import (
    FAMILY_V4,
    FAMILY_V6,
    DnsSetMetricsCollector,
    DnsSetTracker,
)
from .dnstap import DnstapMetricsCollector, DnstapServer
from .dnstap_bridge import BridgeMetricsCollector, TrackerBridge
from .exporter import NftScraper, ShorewalldRegistry
from .instance import InstanceManager, parse_instance_spec
from .iplist.plain import PlainListTracker
from .iplist.tracker import IpListTracker
from .nfsets_manager import NfSetsManager
from .pbdns import PbdnsMetricsCollector, PbdnsServer
from .peer import HmacSha256Auth, PeerLink
from .seed import SeedCoordinator, SeedMetricsCollector
from .setwriter import SetWriter, SetWriterMetricsCollector
from .state import (
    DEFAULT_STATE_DIR,
    InstanceCache,
    StateConfig,
    StateMetricsCollector,
    StateStore,
)
from .worker_router import WorkerRouter, WorkerRouterMetricsCollector

log = logging.getLogger("shorewalld")


def _merge_dns_registries(
    primary: "DnsSetRegistry",
    secondary: "DnsSetRegistry",
    primary_dnsr: "Any | None" = None,
    secondary_dnsr: "Any | None" = None,
) -> "tuple[DnsSetRegistry, Any | None]":
    """Merge two :class:`~shorewall_nft.nft.dns_sets.DnsSetRegistry` objects.

    When the same qname appears in both *primary* and *secondary*, the
    *primary* spec wins (instance-provided specs override nfset defaults).

    Returns ``(merged_dns_reg, merged_dnsr_reg)`` where the dnsr registry
    is ``None`` when both inputs are ``None``.
    """
    from shorewall_nft.nft.dns_sets import DnsrRegistry

    merged = DnsSetRegistry(
        default_ttl_floor=primary.default_ttl_floor,
        default_ttl_ceil=primary.default_ttl_ceil,
        default_size=primary.default_size,
    )
    # Add secondary first (lower priority) then primary (overwrites).
    for spec in secondary.iter_sorted():
        merged.add_spec(spec)
    for spec in primary.iter_sorted():
        merged.add_spec(spec)

    # Merge dnsr registries.
    if primary_dnsr is None and secondary_dnsr is None:
        return merged, None

    merged_dnsr = DnsrRegistry()
    for reg in (secondary_dnsr, primary_dnsr):
        if reg is None:
            continue
        for group in reg.iter_sorted():
            if group.primary_qname not in merged_dnsr.groups:
                merged_dnsr.groups[group.primary_qname] = group
            # else: primary wins — already added (secondary comes first).

    return merged, merged_dnsr


class Daemon:
    """shorewalld top-level. One instance per process."""

    def __init__(self, config: DaemonConfig) -> None:
        self._config = config

        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_done = False
        self._cleanup_registered = False
        self._stop_event: asyncio.Event | None = None
        self._sd_notify_task: asyncio.Task[None] | None = None

        # Subsystems wired up in run().
        self._nft: NftInterface | None = None
        self._registry: ShorewalldRegistry | None = None
        self._scraper: NftScraper | None = None
        self._profile_builder: ProfileBuilder | None = None
        self._reprobe_task: asyncio.Task[None] | None = None

        self._prom_server: Any | None = None
        self._dnstap_server: Any | None = None
        self._log_dispatcher: Any | None = None

        # DNS-set pipeline subsystems (opt-in via allowlist_file).
        self._tracker: Any | None = None
        self._router: Any | None = None
        self._set_writer: Any | None = None
        self._tracker_bridge: Any | None = None
        self._state_store: Any | None = None
        self._pbdns_server: Any | None = None
        self._peer_link: Any | None = None

        self._pull_resolver: Any | None = None
        self._pull_resolver_netns: str = ""

        # New subsystems.
        self._iplist_tracker: Any | None = None
        self._iplist_task: asyncio.Task[None] | None = None
        self._instance_manager: Any | None = None
        self._control_server: Any | None = None
        # Plain-list tracker (nfsets ip-list-plain backend).
        self._plain_tracker: PlainListTracker | None = None
        self._plain_task: asyncio.Task[None] | None = None

        # keepalived SNMP/MIB integration subsystems.
        self._keepalived_dispatcher: Any | None = None
        self._keepalived_trap_listener: Any | None = None
        self._keepalived_dbus: Any | None = None

    # ── config accessor (read-only pass-through) ──────────────────────
    # Kept for back-compat so existing code/tests can still read
    # ``daemon.prom_port`` etc. without being changed all at once.
    # New code should prefer ``daemon._config.<field>`` or pass the
    # DaemonConfig object around directly.

    @property
    def prom_host(self) -> str:
        return self._config.prom_host

    @property
    def prom_port(self) -> int:
        return self._config.prom_port

    @property
    def api_socket(self) -> str | None:
        return self._config.api_socket

    @property
    def netns_spec(self) -> list[str] | str:
        return self._config.netns_spec

    @property
    def scrape_interval(self) -> float:
        return self._config.scrape_interval

    @property
    def reprobe_interval(self) -> float:
        return self._config.reprobe_interval

    @property
    def allowlist_file(self) -> Path | None:
        return self._config.allowlist_file

    @property
    def instances(self) -> tuple[str, ...]:
        return self._config.instances

    @property
    def control_socket(self) -> str | None:
        return self._config.control_socket

    @property
    def iplist_configs(self) -> tuple[Any, ...]:
        return self._config.iplist_configs

    # ── lifecycle ────────────────────────────────────────────────────

    async def run(self) -> int:
        """Build subsystems, install signal handlers, block until shutdown."""
        self._loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()
        self._register_cleanup()

        log.info(
            "shorewalld starting: prom=%s:%d api=%s netns=%s",
            self._config.prom_host, self._config.prom_port,
            self._config.api_socket or "(disabled)",
            self._config.netns_spec,
        )

        netns_list = self._build_scrape_stack()
        self._register_optional_vrrp_collectors()

        # keepalived SNMP/MIB integration — only when KEEPALIVED_SNMP_UNIX
        # is configured. Falls through to the legacy VrrpCollector path
        # (above) for operators who have not migrated yet.
        if self._config.keepalived_snmp_unix:
            await self._start_keepalived_subsystems()

        # Prometheus HTTP scrape endpoint. Deferred import so
        # ``--help`` works without prometheus_client installed.
        self._start_prom_server()

        # Periodic re-probe to pick up rulesets that appear/disappear
        # after the daemon started (e.g. an operator running
        # `shorewall-nft start` in a recursor netns).
        self._reprobe_task = asyncio.create_task(
            self._reprobe_loop(), name="shorewalld.reprobe")

        # Optional DNS-set pipeline (Phase 5–10). Requires a compiled
        # allowlist file to bootstrap the tracker; everything else
        # (pbdns / peer link / state / reload monitor) layers on top.
        # Started BEFORE the dnstap server so the DnstapServer can
        # pick up the tracker bridge for its routing path.
        bootstrap_allowlist = self._resolve_bootstrap_allowlist()
        if bootstrap_allowlist is not None:
            await self._start_dns_pipeline(netns_list, bootstrap_allowlist)

        # When only a control socket is configured and no allowlist was
        # available to bootstrap from, seed an empty pipeline so the
        # InstanceManager starts and register-instance is available.
        if self._tracker is None and self._config.control_socket:
            await self._start_empty_dns_pipeline(netns_list)

        # Multi-instance manager: layers on the DNS pipeline.
        # When --instance is used, the InstanceManager takes over
        # allowlist management from the reload monitor.  It is also
        # started (with an empty instance list) when a control socket
        # is configured — this lets ``shorewall-nft start`` dynamically
        # register itself without operators needing to repeat the path
        # in both shorewalld's ``--instance`` and shorewall-nft's
        # config directory.
        if self._tracker is not None and (
            self._config.instances or self._config.control_socket
        ):
            await self._start_instance_manager()

        # IP-list tracker (fetches cloud prefix lists into nft sets).
        if self._config.iplist_configs:
            await self._start_iplist_tracker(netns_list)

        # Optional dnstap consumer (Phase 4). Off by default.
        if self._config.api_socket:
            await self._start_dnstap_server(netns_list)

        # Optional NFLOG log dispatcher. Off unless an operator opts in
        # via LOG_DISPATCH=shorewalld + LOG_NFLOG_GROUP=<N>. Must start
        # AFTER the worker router exists (which is created at line 323)
        # so attach_log_dispatcher can wire the parent-side sink in.
        if (self._config.log_dispatch == "shorewalld"
                and self._config.log_nflog_group is not None):
            await self._start_log_dispatcher(netns_list)

        # Control socket server.
        if self._config.control_socket:
            await self._start_control_server()

        # Install SIGUSR1 handler for manual iplist refresh.
        self._install_sigusr1()

        # Tell systemd we are live + start the watchdog/status loop.
        # No-ops when $NOTIFY_SOCKET is not set (unit tests, dev runs).
        sd_notify.ready(self._build_sd_status())
        if sd_notify.enabled():
            self._sd_notify_task = asyncio.create_task(
                self._sd_notify_loop(), name="shorewalld.sd_notify")

        try:
            await self._stop_event.wait()
        finally:
            await self._async_shutdown()
        return 0

    def _build_scrape_stack(self) -> list[str]:
        """Build the always-on scrape stack and return the resolved netns list.

        The worker router is created early (tracker attaches later during
        DNS-pipeline bootstrap) so the exporter's /proc-reading collectors
        can delegate their reads to netns-pinned workers from the first
        scrape onwards. Workers are forked lazily on first use.
        """
        assert self._loop is not None

        self._nft = NftInterface()
        self._registry = ShorewalldRegistry()
        self._scraper = NftScraper(self._nft, ttl_s=self._config.scrape_interval)
        self._router = WorkerRouter(loop=self._loop)
        self._profile_builder = ProfileBuilder(
            self._nft, self._registry, self._scraper, self._router)

        netns_list = resolve_netns_list(self._config.netns_spec)
        self._profile_builder.build(netns_list)
        self._profile_builder.reprobe()
        log.info(
            "shorewalld built %d netns profile(s): %s",
            len(self._profile_builder.profiles),
            list(self._profile_builder.profiles),
        )

        from .collectors._shared import RtnlHandlesCollector
        self._registry.add(RtnlHandlesCollector())  # type: ignore[arg-type]
        return netns_list

    def _register_optional_vrrp_collectors(self) -> None:
        """Register the VRRP D-Bus collector if opt-in via config."""
        if not self._config.enable_vrrp_collector:
            return
        assert self._registry is not None

        from .collectors.vrrp import VrrpCollector as _VrrpCollector
        from .collectors.vrrp import VrrpSnmpConfig as _VrrpSnmpConfig
        snmp_cfg: _VrrpSnmpConfig | None = None
        if self._config.vrrp_snmp_enabled:
            snmp_cfg = _VrrpSnmpConfig(
                host=self._config.vrrp_snmp_host,
                port=self._config.vrrp_snmp_port,
                community=self._config.vrrp_snmp_community,
                timeout=self._config.vrrp_snmp_timeout,
            )
            log.info(
                "shorewalld VRRP SNMP augmentation enabled: "
                "%s:%d community=%r timeout=%.1fs",
                self._config.vrrp_snmp_host, self._config.vrrp_snmp_port,
                self._config.vrrp_snmp_community, self._config.vrrp_snmp_timeout,
            )
        self._registry.add(_VrrpCollector(
            snmp_config=snmp_cfg,
            keepalived_snmp_unix=self._config.keepalived_snmp_unix,
        ))
        log.info("shorewalld VRRP D-Bus collector registered")

    def _resolve_bootstrap_allowlist(self) -> Path | None:
        """Pick the allowlist file to bootstrap the DNS-set pipeline.

        Prefers ``--allowlist-file`` when set. Otherwise, when only
        ``--instance`` specs are given, falls back to the first instance's
        allowlist path so the tracker is available for the InstanceManager
        without operators having to repeat the path on the CLI.
        """
        if self._config.allowlist_file is not None:
            return self._config.allowlist_file
        if not self._config.instances:
            return None
        first_spec = parse_instance_spec(self._config.instances[0])
        if first_spec.allowlist_path.exists():
            return first_spec.allowlist_path
        return None

    async def _start_dns_pipeline(
        self,
        netns_list: list[str],
        allowlist_file: Path,
    ) -> None:
        """Wire up tracker + router + setwriter + optional ingress/peer.

        All subsystems are optional; this is only called when the
        caller passed ``allowlist_file`` because without a compiled
        allowlist the tracker has nothing to dedup against.
        """
        assert self._nft is not None

        try:
            registry = read_compiled_allowlist(allowlist_file)
        except Exception:
            log.exception(
                "failed to read allowlist file %s", allowlist_file)
            return

        self._tracker = DnsSetTracker(
            refresh_threshold=self._config.dns_dedup_refresh_threshold)
        self._tracker.load_registry(registry)
        log.info(
            "dns pipeline: loaded allowlist (%d qnames)",
            sum(1 for _ in registry.iter_sorted()),
        )

        # Load pull-resolver groups and wire secondary qnames as tracker
        # aliases so the tap pipeline also populates dnsr: sets.
        try:
            dnsr_registry = read_compiled_dnsr_allowlist(allowlist_file)
        except Exception:
            log.exception(
                "failed to read dnsr section from allowlist %s",
                allowlist_file)
            dnsr_registry = None

        if dnsr_registry and dnsr_registry.groups:
            pull_count = 0
            for group in dnsr_registry.iter_sorted():
                for secondary in group.qnames[1:]:
                    for family in (FAMILY_V4, FAMILY_V6):
                        self._tracker.add_qname_alias(
                            secondary, group.primary_qname, family)
                if group.pull_enabled:
                    pull_count += 1
            log.info(
                "dns pipeline: loaded %d dns-set group(s) "
                "(%d pull, %d tap-only)",
                len(dnsr_registry.groups),
                pull_count,
                len(dnsr_registry.groups) - pull_count,
            )

        loop = asyncio.get_running_loop()
        # Router was created early in run() so the exporter could start
        # using it; here we just attach the freshly-built tracker so
        # newly spawned workers get the right set-name lookup closure.
        # Any workers already forked for read-only scrape traffic must
        # be respawned so their captured (None) tracker gets replaced.
        assert self._router is not None
        already_spawned = list(self._router.iter_workers())
        self._router.attach_tracker(self._tracker)
        for worker in already_spawned:
            try:
                await self._router.respawn_netns(worker.netns)
            except Exception:
                log.exception(
                    "router: tracker-attach respawn failed for %r",
                    worker.netns)
        for netns in netns_list:
            try:
                await self._router.add_netns(netns)
            except Exception:
                log.exception(
                    "router: failed to add netns %r", netns)

        self._set_writer = SetWriter(
            self._tracker, self._router, loop=loop,
            batch_window_sec=self._config.batch_window_seconds)
        await self._set_writer.start()

        self._tracker_bridge = TrackerBridge(
            self._tracker, self._set_writer,
            default_netns=netns_list[0] if netns_list else "",
        )

        assert self._registry is not None
        self._registry.add(SetWriterMetricsCollector(self._set_writer))
        self._registry.add(WorkerRouterMetricsCollector(self._router))
        self._registry.add(BridgeMetricsCollector(self._tracker_bridge))
        self._registry.add(DnsSetMetricsCollector(self._tracker))

        # State persistence.
        if self._config.state_enabled:
            state_cfg = StateConfig(
                state_dir=self._config.state_dir or StateConfig().state_dir,
                enabled=True,
                load_on_start=not self._config.state_no_load,
                flush_on_start=self._config.state_flush,
            )
            self._state_store = StateStore(self._tracker, state_cfg)
            try:
                self._state_store.load()
            except Exception:
                log.exception("state load failed")
            await self._state_store.start(loop)
            self._registry.add(StateMetricsCollector(self._state_store))

        # PBDNSMessage (PowerDNS recursor protobuf logger) ingress.
        # Accepts unix socket (for out-of-tree producers) and/or TCP
        # (required for pdns-recursor's Lua protobufServer() which
        # speaks TCP only). Both can be enabled simultaneously.
        if self._config.pbdns_socket or self._config.pbdns_tcp:
            tcp_host, tcp_port = None, None
            if self._config.pbdns_tcp:
                host, _, port_s = self._config.pbdns_tcp.rpartition(":")
                tcp_host = host or "0.0.0.0"
                try:
                    tcp_port = int(port_s)
                except ValueError:
                    log.error(
                        "pbdns tcp spec %r: bad port", self._config.pbdns_tcp)
                    tcp_port = None
            pbdns_kwargs: dict = {
                "socket_path": self._config.pbdns_socket,
                "bridge": self._tracker_bridge,
                "tcp_host": tcp_host,
                "tcp_port": tcp_port,
                "socket_owner": self._config.socket_owner,
                "socket_group": self._config.socket_group,
            }
            if self._config.socket_mode is not None:
                pbdns_kwargs["socket_mode"] = self._config.socket_mode
            self._pbdns_server = PbdnsServer(**pbdns_kwargs)
            try:
                await self._pbdns_server.start()
            except Exception:
                log.exception(
                    "pbdns server failed to bind "
                    "(socket=%s tcp=%s)",
                    self._config.pbdns_socket, self._config.pbdns_tcp)
                self._pbdns_server = None
            else:
                assert self._registry is not None
                self._registry.add(PbdnsMetricsCollector(self._pbdns_server))

        # HA peer link.
        if (self._config.peer_host and self._config.peer_port
                and self._config.peer_auth_key_file is not None):
            try:
                auth = HmacSha256Auth.from_file(self._config.peer_auth_key_file)
            except Exception:
                log.exception(
                    "peer auth key load failed from %s",
                    self._config.peer_auth_key_file)
                auth = None
            if auth is not None:
                self._peer_link = PeerLink(
                    tracker=self._tracker,
                    writer=self._set_writer,
                    auth=auth,
                    bind_host=self._config.peer_bind_host or "0.0.0.0",
                    bind_port=self._config.peer_bind_port or 9749,
                    peer_host=self._config.peer_host,
                    peer_port=self._config.peer_port,
                    origin_node=socket.gethostname(),
                    heartbeat_interval=self._config.peer_heartbeat_interval,
                )
                try:
                    await self._peer_link.start(loop)
                except Exception:
                    log.exception(
                        "peer link start failed on %s:%d → %s:%d",
                        self._config.peer_bind_host, self._config.peer_bind_port,
                        self._config.peer_host, self._config.peer_port)
                    self._peer_link = None
                else:
                    from .peer import PeerMetricsCollector
                    self._registry.add(PeerMetricsCollector(self._peer_link))

        # Pull resolver — active DNS resolution for dnsr: groups.
        # Created eagerly iff groups are known at bootstrap; otherwise
        # InstanceManager may create it lazily when the first dnsr group
        # arrives via register-instance (see _ensure_pull_resolver).
        self._pull_resolver_netns = netns_list[0] if netns_list else ""
        if dnsr_registry and dnsr_registry.groups:
            await self._ensure_pull_resolver(dnsr_registry)

        log.info(
            "dns pipeline: ready (pbdns=%s peer=%s state=%s pull=%s)",
            "on" if self._pbdns_server else "off",
            "on" if self._peer_link else "off",
            "on" if self._state_store else "off",
            "on" if self._pull_resolver else "off",
        )

    async def _ensure_pull_resolver(self, dnsr_registry: Any) -> Any | None:
        """Create the PullResolver on first use, or return the existing one.

        Called both at bootstrap (from :meth:`_start_dns_pipeline` when
        the initial allowlist already contains a ``dnsr:`` group) and
        lazily from :class:`InstanceManager` when a dynamically
        registered instance brings the first one. Idempotent.

        Tap-only groups (``pull_enabled=False``, created by multi-host
        ``dns:`` tokens) do not trigger creation — their secondaries
        are wired via ``tracker.add_qname_alias`` alone.
        """
        if self._pull_resolver is not None:
            return self._pull_resolver
        if self._tracker is None or self._set_writer is None:
            return None
        if not dnsr_registry:
            return None
        pull_groups = [
            g for g in dnsr_registry.groups.values() if g.pull_enabled
        ]
        if not pull_groups:
            return None
        self._pull_resolver = PullResolver(
            dnsr_registry,
            self._tracker,
            self._set_writer,
            default_netns=self._pull_resolver_netns,
        )
        await self._pull_resolver.start()
        if self._registry is not None:
            self._registry.add(PullResolverMetricsCollector(self._pull_resolver))
        # Wire the refresh-dns control handler now if the control server
        # is up; otherwise _start_control_server does it later.
        self._register_refresh_dns_handler()
        log.info(
            "dns pipeline: pull resolver started (%d group(s))",
            len(pull_groups),
        )
        return self._pull_resolver

    def _register_refresh_dns_handler(self) -> None:
        """Register the refresh-dns handler if both server and resolver exist."""
        if self._control_server is None or self._pull_resolver is None:
            return
        # Rebuild ControlHandlers with the now-available pull resolver
        # and re-register only the refresh-dns slot so the existing
        # instance/iplist slots are not overwritten.
        h = ControlHandlers(pull_resolver=self._pull_resolver)
        self._control_server.register_handler(
            "refresh-dns", h.handle_refresh_dns)

    async def _start_iplist_tracker(self, netns_list: list[str]) -> None:
        """Start the IP-list tracker for cloud prefix sets."""
        assert self._nft is not None
        assert self._profile_builder is not None

        profiles = self._profile_builder.profiles
        self._iplist_tracker = IpListTracker(
            configs=list(self._config.iplist_configs),
            nft=self._nft,
            profiles=profiles,
            registry=self._registry,
        )
        self._iplist_task = asyncio.create_task(
            self._iplist_tracker.run(),
            name="shorewalld.iplist",
        )
        log.info(
            "iplist tracker: started with %d list(s)",
            len(self._config.iplist_configs),
        )

    async def _start_empty_dns_pipeline(self, netns_list: list[str]) -> None:
        """Bootstrap a minimal empty DNS pipeline for the control-socket path.

        Called when a control socket is configured but no allowlist is
        available at start time.  The InstanceManager will populate the
        tracker via register-instance on first shorewall-nft start.
        """
        assert self._nft is not None

        self._tracker = DnsSetTracker(
            refresh_threshold=self._config.dns_dedup_refresh_threshold)
        self._tracker.load_registry(DnsSetRegistry())

        loop = asyncio.get_running_loop()
        # Router was pre-created in run(); attach the empty tracker now
        # and respawn any scrape-only workers so the lookup closure
        # picks up the new (empty) tracker. Real content is injected
        # later by the InstanceManager.
        assert self._router is not None
        already_spawned = list(self._router.iter_workers())
        self._router.attach_tracker(self._tracker)
        for worker in already_spawned:
            try:
                await self._router.respawn_netns(worker.netns)
            except Exception:
                log.exception(
                    "router: tracker-attach respawn failed for %r",
                    worker.netns)
        # INVARIANT (CLAUDE.md §"Lazy spawn rule" / "fork-after-load"):
        # do NOT pre-start workers here. Workers for non-empty netns fork
        # a child that inherits a copy of the tracker at fork time. If
        # we fork before the InstanceManager populates the tracker, the
        # child's lookup closure captures an empty registry and silently
        # drops every set-mutating op. WorkerRouter.dispatch() spawns
        # lazily on first use — by then the allowlist is loaded.

        self._set_writer = SetWriter(
            self._tracker, self._router, loop=loop,
            batch_window_sec=self._config.batch_window_seconds)
        await self._set_writer.start()

        self._tracker_bridge = TrackerBridge(
            self._tracker, self._set_writer,
            default_netns=netns_list[0] if netns_list else "",
        )

        assert self._registry is not None
        self._registry.add(SetWriterMetricsCollector(self._set_writer))
        self._registry.add(WorkerRouterMetricsCollector(self._router))
        self._registry.add(BridgeMetricsCollector(self._tracker_bridge))
        self._registry.add(DnsSetMetricsCollector(self._tracker))

        log.info("dns pipeline: empty pipeline ready for dynamic registration")

    async def _start_instance_manager(self) -> None:
        """Start the multi-instance allowlist manager."""
        assert self._tracker is not None
        assert self._router is not None

        configs = [parse_instance_spec(spec) for spec in self._config.instances]

        cache = None
        if self._config.state_enabled:
            state_dir = self._config.state_dir or Path(DEFAULT_STATE_DIR)
            cache = InstanceCache(state_dir)

        self._instance_manager = InstanceManager(
            configs=configs,
            tracker=self._tracker,
            router=self._router,
            pull_resolver=self._pull_resolver,
            pull_resolver_factory=self._ensure_pull_resolver,
            cache=cache,
        )
        try:
            await self._instance_manager.start()
        except Exception:
            log.exception("instance manager start failed")
            self._instance_manager = None
            return

        # Gather nfsets configs from all initially-loaded instances and start
        # the PlainListTracker for any ip-list-plain sources.
        await self._apply_nfsets_from_instances()

    async def _apply_nfsets_from_instances(self) -> None:
        """Gather nfsets payloads from all current instances and wire backends.

        Called once after :meth:`_start_instance_manager` completes, and
        again from the dynamic ``register-instance`` handler whenever an
        instance with a new ``nfsets_payload`` is registered.

        Steps:

        1. Collect all ``nfsets_payload`` dicts from managed instances.
        2. Build :class:`~shorewalld.nfsets_manager.NfSetsManager` for each
           and merge their DNS registries into the tracker via
           :func:`_merge_dns_registries`.
        3. Merge ip-list configs with the existing :attr:`iplist_configs` and
           (re-)start the :class:`~shorewalld.iplist.tracker.IpListTracker`
           if the list changed.
        4. Collect ip-list-plain configs and (re-)start the
           :class:`~shorewalld.iplist.plain.PlainListTracker`.
        """
        if self._tracker is None or self._instance_manager is None:
            return

        from shorewall_nft.nft.dns_sets import DnsrRegistry, DnsSetRegistry

        # Accumulate nfsets-sourced DNS registries and plain-list configs.
        nfsets_dns = DnsSetRegistry()
        nfsets_dnsr = DnsrRegistry()
        plain_cfgs: list = []
        extra_iplist_cfgs: list = []

        for state in self._instance_manager._states.values():
            payload = getattr(state.cfg, "nfsets_payload", None) or {}
            if not payload:
                continue
            mgr = NfSetsManager(payload)
            dns_reg, dnsr_reg = mgr.dns_registries()
            # Merge nfsets DNS specs into the accumulator (last-write wins
            # across instances; the tracker merge below uses instance regs
            # as the authoritative source).
            for spec in dns_reg.iter_sorted():
                nfsets_dns.add_spec(spec)
            for group in dnsr_reg.iter_sorted():
                if group.primary_qname not in nfsets_dnsr.groups:
                    nfsets_dnsr.groups[group.primary_qname] = group
            extra_iplist_cfgs.extend(mgr.iplist_configs())
            plain_cfgs.extend(mgr.plain_list_configs())

        # Load nfsets DNS registries into the tracker as additional specs.
        # This uses the tracker's existing load_registry path; nfsets specs
        # that share a set_name with an instance spec will be grouped via the
        # N→1 logic in DnsSetTracker.load_registry().
        if nfsets_dns.specs:
            from shorewall_nft.nft.dns_sets import DnsSetRegistry as _DSR
            # Merge with whatever is currently in the tracker by re-loading
            # through a merged registry (non-destructive for existing names).
            current_dns = _DSR()
            # We don't have direct read access to tracker internals here;
            # instead, register the nfsets specs on top via add_spec which
            # merges on the DnsSetRegistry side before passing to tracker.
            # Build a combined registry: existing instance regs + nfsets.
            combined = _DSR()
            for state in self._instance_manager._states.values():
                if state.last_dns_registry is not None:
                    for spec in state.last_dns_registry.iter_sorted():
                        combined.add_spec(spec)
            for spec in nfsets_dns.iter_sorted():
                if spec.qname not in combined.specs:
                    combined.add_spec(spec)
            self._tracker.load_registry(combined)
            log.info(
                "nfsets: merged %d dns spec(s) into tracker",
                len(nfsets_dns.specs),
            )

        # Append nfsets ip-list configs to the daemon's iplist_configs and
        # (re-)start the IpListTracker if needed.
        if extra_iplist_cfgs:
            log.info(
                "nfsets: %d ip-list config(s) from nfsets", len(extra_iplist_cfgs))
            # IpListTracker is already running; dynamic config append is a
            # future enhancement. For now, log the configs as discovered.
            # Operators restart shorewalld to activate new ip-list entries.

        # Start or restart the PlainListTracker for ip-list-plain sources.
        if plain_cfgs:
            await self._start_plain_tracker(plain_cfgs)

    async def _start_plain_tracker(self, configs: list) -> None:
        """Start (or restart) the PlainListTracker for ip-list-plain sources.

        If a tracker is already running it is cancelled first so we don't
        accumulate duplicate tasks.  Graceful shutdown: task.cancel() then
        await so existing nft writes complete before the new tracker starts.
        """
        assert self._nft is not None
        assert self._profile_builder is not None

        if self._plain_task is not None and not self._plain_task.done():
            self._plain_task.cancel()
            try:
                await self._plain_task
            except (asyncio.CancelledError, Exception):
                pass
            self._plain_task = None
            self._plain_tracker = None

        profiles = self._profile_builder.profiles
        self._plain_tracker = PlainListTracker(
            configs=configs,
            nft=self._nft,
            profiles=profiles,
        )
        # Register PlainListTracker metrics so they appear on the scrape
        # endpoint.  Two collectors are needed:
        #
        # 1. _metrics (IpListMetrics) — nft apply-path / capacity /
        #    write-error counters accumulated inside _apply_set().
        # 2. NfsetsCollector(plain_tracker=…) — fetch/parse latency,
        #    refresh success/failure totals, entry counts, inotify status.
        if self._registry is not None:
            from .collectors import NfsetsCollector
            self._registry.add(self._plain_tracker._metrics)  # type: ignore[arg-type]
            self._registry.add(
                NfsetsCollector("", plain_tracker=self._plain_tracker)
            )
        self._plain_task = asyncio.create_task(
            self._plain_tracker.run(),
            name="shorewalld.plain",
        )
        log.info(
            "plain list tracker: started with %d source(s)", len(configs))

    async def _start_keepalived_subsystems(self) -> None:
        """Bootstrap the keepalived SNMP walker, trap listener, and D-Bus client.

        Called from :meth:`run` when ``KEEPALIVED_SNMP_UNIX`` is set.
        Every sub-component has an *Unavailable* soft-degrade path so a
        missing puresnmp, pysnmp, or dbus-next never aborts startup
        — it just drops that capability with a warning log.
        """
        assert self._config.keepalived_snmp_unix is not None
        assert self._registry is not None

        from .keepalived.dispatcher import KeepalivedDispatcher
        from .keepalived.metrics import KeepalivedCollector
        from .keepalived.snmp_client import (
            KeepalivedSnmpClient,
            KeepalivedSnmpClientUnavailable,
        )

        # ── SNMP client + walker ──────────────────────────────────────
        try:
            _client = KeepalivedSnmpClient(
                unix_path=self._config.keepalived_snmp_unix,
            )
        except KeepalivedSnmpClientUnavailable as e:
            log.warning(
                "keepalived SNMP disabled (puresnmp not installed): %s", e)
            return

        self._keepalived_dispatcher = KeepalivedDispatcher(
            client=_client,
            walk_interval_s=self._config.keepalived_walk_interval_s,
            enable_wide_tables=self._config.keepalived_wide_tables,
        )
        await self._keepalived_dispatcher.start()
        log.info(
            "keepalived SNMP walker started: unix=%s interval=%.0fs wide_tables=%s",
            self._config.keepalived_snmp_unix,
            self._config.keepalived_walk_interval_s,
            self._config.keepalived_wide_tables,
        )

        self._registry.add(
            KeepalivedCollector(self._keepalived_dispatcher))

        # ── Trap listener ─────────────────────────────────────────────
        if self._config.keepalived_trap_socket:
            from .keepalived.trap_listener import (
                KeepalivedTrapListener,
                KeepalivedTrapListenerUnavailable,
            )
            try:
                self._keepalived_trap_listener = KeepalivedTrapListener(
                    socket_path=self._config.keepalived_trap_socket,
                    dispatcher=self._keepalived_dispatcher,
                )
                await self._keepalived_trap_listener.start()
                log.info(
                    "keepalived trap listener started: %s",
                    self._config.keepalived_trap_socket,
                )
            except KeepalivedTrapListenerUnavailable as e:
                log.warning(
                    "keepalived trap listener disabled (pysnmp not installed): %s",
                    e)
            except OSError as e:
                log.warning(
                    "keepalived trap listener failed to bind %s: %s",
                    self._config.keepalived_trap_socket, e)
                self._keepalived_trap_listener = None

        # ── D-Bus client ──────────────────────────────────────────────
        if self._config.keepalived_dbus_methods != "none":
            from .keepalived.dbus_client import (
                KeepalivedDbusClient,
                KeepalivedDbusUnavailable,
            )
            try:
                self._keepalived_dbus = KeepalivedDbusClient(
                    dispatcher=self._keepalived_dispatcher,
                    method_acl=self._config.keepalived_dbus_methods,
                    enable_create_instance=self._config.keepalived_dbus_create_instance,
                )
                await self._keepalived_dbus.start()
                log.info(
                    "keepalived D-Bus client started: acl=%s create_instance=%s",
                    self._config.keepalived_dbus_methods,
                    self._config.keepalived_dbus_create_instance,
                )
            except KeepalivedDbusUnavailable as e:
                log.warning(
                    "keepalived D-Bus disabled (dbus-next not installed): %s", e)
                self._keepalived_dbus = None

    async def _start_control_server(self) -> None:
        """Bind the control Unix socket and register handlers."""
        assert self._config.control_socket is not None

        self._control_server = ControlServer(
            socket_path=self._config.control_socket,
            netns=self._config.control_socket_netns,
            socket_mode=self._config.socket_mode,
        )

        # Build the handler object with the subsystem references it needs.
        handlers = ControlHandlers(
            instance_mgr=self._instance_manager,
            iplist_tracker=self._iplist_tracker,
            pull_resolver=self._pull_resolver,
            nfsets_hook=self._apply_nfsets_from_instances,
            keepalived_dbus=self._keepalived_dbus,
        )

        # Register iplist handlers if the tracker is running.
        if self._iplist_tracker is not None:
            self._control_server.register_handler(
                "refresh-iplist", handlers.handle_refresh_iplist
            )
            self._control_server.register_handler(
                "iplist-status", handlers.handle_iplist_status
            )

        # Register instance handlers if the manager is running.
        if self._instance_manager is not None:
            self._control_server.register_handler(
                "reload-instance", handlers.handle_reload_instance
            )
            self._control_server.register_handler(
                "instance-status", handlers.handle_instance_status
            )
            self._control_server.register_handler(
                "register-instance", handlers.handle_register_instance
            )
            self._control_server.register_handler(
                "deregister-instance", handlers.handle_deregister_instance
            )

        # keepalived D-Bus command handlers — registered regardless of
        # whether the D-Bus client started; the handler methods degrade
        # cleanly when keepalived_dbus=None (they return {"error": ...}).
        self._control_server.register_handler(
            "keepalived-data", handlers.handle_keepalived_data)
        self._control_server.register_handler(
            "keepalived-stats", handlers.handle_keepalived_stats)
        self._control_server.register_handler(
            "keepalived-reload", handlers.handle_keepalived_reload)
        self._control_server.register_handler(
            "keepalived-garp", handlers.handle_keepalived_garp)

        # Seed coordinator — answers request-seed commands from shorewall-nft.
        if self._tracker is not None:
            _seed = SeedCoordinator(
                tracker=self._tracker,
                pull_resolver=self._pull_resolver,
                peer_link=self._peer_link,
                iplist_tracker=self._iplist_tracker,
                dnstap_active=self._dnstap_server is not None,
                pbdns_active=self._pbdns_server is not None,
            )
            self._control_server.register_handler("request-seed", _seed.handle)
            if self._registry is not None:
                self._registry.add(SeedMetricsCollector(_seed))

        try:
            await self._control_server.start()
        except Exception:
            log.exception(
                "control server failed to start on %s", self._config.control_socket
            )
            self._control_server = None
            return

        # Now that the control server is up, register handlers for
        # subsystems that came online before it.
        self._register_refresh_dns_handler()
        if self._registry is not None:
            self._registry.add(ControlMetricsCollector(self._control_server))

    def _install_sigusr1(self) -> None:
        """Install a SIGUSR1 handler that triggers iplist refresh_all."""
        if self._loop is None:
            return
        loop = self._loop
        tracker = self._iplist_tracker

        async def _refresh() -> None:
            sd_notify.reloading()
            try:
                if tracker is not None:
                    await tracker.refresh_all()
            finally:
                sd_notify.ready(self._build_sd_status())

        def _handler() -> None:
            log.info("shorewalld caught SIGUSR1 — triggering iplist refresh")
            loop.create_task(
                _refresh(), name="shorewalld.iplist.sigusr1_refresh")

        try:
            loop.add_signal_handler(signal.SIGUSR1, _handler)
        except (ValueError, OSError, NotImplementedError):
            pass

    async def _sd_notify_loop(self) -> None:
        """Periodically ping the systemd watchdog and refresh ``STATUS=``.

        Cadence is :func:`sd_notify.status_interval_sec` — short enough
        to stay under any reasonable ``WatchdogSec=`` while updating
        the ``systemctl status`` one-liner often enough that operators
        see live numbers.
        """
        interval = sd_notify.status_interval_sec()
        try:
            while not (self._stop_event and self._stop_event.is_set()):
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),  # type: ignore[union-attr]
                        timeout=interval)
                    return  # stop_event fired
                except asyncio.TimeoutError:
                    pass
                sd_notify.watchdog_ping()
                try:
                    sd_notify.status(self._build_sd_status())
                except Exception:
                    log.debug("sd_notify status build failed", exc_info=True)
        except asyncio.CancelledError:
            pass

    def _build_sd_status(self) -> str:
        """One-liner shown by ``systemctl status shorewalld``.

        Cheap accessors only — must not contend with the hot path.
        """
        parts: list[str] = [
            f"prom={self._config.prom_host}:{self._config.prom_port}",
        ]
        if self._profile_builder is not None:
            parts.append(f"netns={len(self._profile_builder.profiles)}")
        if self._tracker is not None:
            try:
                snap = self._tracker.snapshot()
                parts.append(
                    f"sets={snap.sets_declared} elements={snap.totals.elements}")
            except Exception:
                pass
        flags: list[str] = []
        if self._dnstap_server is not None:
            flags.append("dnstap")
        if self._pbdns_server is not None:
            flags.append("pbdns")
        if self._pull_resolver is not None:
            flags.append("pull")
        if self._peer_link is not None:
            flags.append("peer")
        if self._iplist_tracker is not None:
            flags.append("iplist")
        if self._control_server is not None:
            flags.append("ctl")
        if flags:
            parts.append("ingress=" + ",".join(flags))
        return " ".join(parts)

    def _start_prom_server(self) -> None:
        """Stand up a prometheus_client-backed HTTP scrape endpoint.

        Uses a custom ``Collector`` that funnels our Registry into the
        default prometheus_client REGISTRY, so the stock
        ``start_http_server`` helper works unchanged.
        """
        try:
            from prometheus_client import (  # type: ignore[import-untyped]
                REGISTRY,
                start_http_server,
            )
        except ImportError:
            log.warning(
                "prometheus_client not installed — install with "
                "'pip install shorewall-nft[daemon]' to enable metrics")
            return

        outer = self

        class _Adapter:
            def describe(self):
                # Empty so prometheus_client skips the name-conflict check
                # during register() and does not call collect() from the
                # event-loop thread (which would deadlock read_file_sync).
                return []

            def collect(self):
                assert outer._registry is not None
                return outer._registry.to_prom_families()

        REGISTRY.register(_Adapter())
        try:
            server, thread = start_http_server(
                self._config.prom_port, addr=self._config.prom_host)
        except Exception as e:
            log.error("failed to bind prom endpoint %s:%d: %s",
                      self._config.prom_host, self._config.prom_port, e)
            return
        self._prom_server = server
        log.info("shorewalld prom endpoint live on %s:%d",
                 self._config.prom_host, self._config.prom_port)

    async def _start_dnstap_server(self, netns_list: list[str]) -> None:
        """Bind the dnstap unix socket and start the decode worker pool."""
        assert self._nft is not None and self._config.api_socket is not None
        assert self._registry is not None
        dnstap_kwargs: dict = {
            # If the DNS pipeline was initialised first, route every
            # decoded DnsUpdate through the tracker-aware bridge
            # (dedup + batch + persistent worker) instead of the
            # legacy direct-nft SetWriter.
            "bridge": self._tracker_bridge,
            "socket_owner": self._config.socket_owner,
            "socket_group": self._config.socket_group,
        }
        if self._config.socket_mode is not None:
            dnstap_kwargs["socket_mode"] = self._config.socket_mode
        self._dnstap_server = DnstapServer(
            self._config.api_socket, self._nft, netns_list,
            **dnstap_kwargs,
        )
        try:
            await self._dnstap_server.start()
        except Exception:
            log.exception("failed to start dnstap server on %s",
                          self._config.api_socket)
            self._dnstap_server = None
            return
        # Register the metrics collector so queue depth / frame
        # counters show up on the Prometheus endpoint.
        self._registry.add(DnstapMetricsCollector(self._dnstap_server))
        # serve_forever runs as a background task; shutdown() closes
        # the server which makes it return.
        asyncio.create_task(
            self._dnstap_server.serve_forever(),
            name="shorewalld.dnstap")

    async def _start_log_dispatcher(self, netns_list: list[str]) -> None:
        """Wire up the NFLOG log dispatcher + per-netns worker subscription.

        Creates the :class:`LogDispatcher`, attaches it to the worker
        router (which propagates the NFLOG group to all per-netns
        workers — existing ones get their pointer updated, future
        spawns inherit the group), registers the
        :class:`LogCollector`, and eagerly spawns workers for the
        operator-requested netns list so subscriptions start on
        daemon boot instead of waiting for the first scrape to
        lazy-spawn them.
        """
        assert self._router is not None
        assert self._registry is not None
        assert self._config.log_nflog_group is not None

        from .collectors.log import LogCollector
        from .log_dispatcher import LogDispatcher

        self._log_dispatcher = LogDispatcher(
            drop_file=self._config.log_dispatch_file,
            drop_socket_path=self._config.log_dispatch_socket,
            journald=self._config.log_dispatch_journald,
            syslog_path=self._config.log_dispatch_syslog,
        )
        await self._log_dispatcher.start()

        self._router.attach_log_dispatcher(
            self._log_dispatcher,
            nflog_group=self._config.log_nflog_group,
        )

        # Eagerly spawn workers so NFLOG subscriptions start on boot.
        # add_netns is idempotent and safe for the default ("") netns
        # (LocalWorker path, no fork).
        for netns in netns_list:
            try:
                await self._router.add_netns(netns)
            except Exception:
                log.exception(
                    "log dispatcher: failed to spawn worker for netns %r",
                    netns)

        self._registry.add(LogCollector(self._log_dispatcher))

        log.info(
            "shorewalld log dispatcher enabled: group=%d sinks=[%s]",
            self._config.log_nflog_group,
            ",".join(filter(None, [
                "file" if self._config.log_dispatch_file else None,
                "socket" if self._config.log_dispatch_socket else None,
                "journald" if self._config.log_dispatch_journald else None,
                "syslog" if self._config.log_dispatch_syslog else None,
            ])) or "counter-only",
        )

    async def _reprobe_loop(self) -> None:
        """Tick every ``reprobe_interval`` seconds and refresh profiles."""
        try:
            while not (self._stop_event and self._stop_event.is_set()):
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),  # type: ignore[union-attr]
                        timeout=self._config.reprobe_interval)
                    return  # stop_event fired
                except asyncio.TimeoutError:
                    pass
                if self._profile_builder is not None:
                    try:
                        self._profile_builder.reprobe()
                    except Exception:
                        log.exception("reprobe failed")
        except asyncio.CancelledError:
            pass

    def request_stop(self) -> None:
        """Ask the ``run()`` coroutine to return cleanly."""
        if self._stop_event is not None and self._loop is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)

    # ── shutdown (pattern lifted from simlab/controller.py) ──────────

    def _register_cleanup(self) -> None:
        if self._cleanup_registered:
            return
        atexit.register(self._shutdown)
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self._sig_handler)
            except (ValueError, OSError):
                pass
        self._cleanup_registered = True

    def _sig_handler(self, signum: int, frame: Any) -> None:  # noqa: ARG002
        log.info("shorewalld caught signal %d, shutting down", signum)
        self._shutdown()
        os._exit(128 + signum)

    def shutdown(self) -> None:
        """Public idempotent shutdown entry point (for tests)."""
        self._shutdown()

    async def _async_shutdown(self) -> None:
        """Shutdown path called from ``run()`` while the loop is alive.

        Tears down the async DNS-pipeline subsystems in reverse wiring
        order, then delegates the synchronous parts to :meth:`_shutdown`.

        Every step is attempted even if earlier steps fail.  Any step
        failures are aggregated; after all steps run the list is logged
        as a summary and the process exits with code 1 so monitoring
        tools do not see a spurious "clean shutdown".
        """
        if self._shutdown_done:
            return

        # Tell systemd before we start tearing things down so the
        # service state shows STOPPING throughout the teardown phase.
        sd_notify.stopping()

        if self._sd_notify_task is not None:
            self._sd_notify_task.cancel()
            try:
                await self._sd_notify_task
            except (asyncio.CancelledError, Exception):
                pass
            self._sd_notify_task = None

        errors: list[tuple[str, BaseException]] = []

        async def _safe_async(step: str, coro: Any) -> None:
            try:
                await coro
            except BaseException as exc:
                errors.append((step, exc))
                log.exception("shutdown step %r failed", step)

        def _safe_sync(step: str, fn: Any) -> None:
            try:
                fn()
            except BaseException as exc:
                errors.append((step, exc))
                log.exception("shutdown step %r failed", step)

        # Control server: close before tearing down subsystems it references.
        if self._control_server is not None:
            await _safe_async(
                "control_server", self._control_server.shutdown())
            self._control_server = None

        # keepalived D-Bus client: must shut down before the dispatcher
        # (it holds a reference and may still be dispatching signals).
        if self._keepalived_dbus is not None:
            await _safe_async(
                "keepalived_dbus", self._keepalived_dbus.stop())
            self._keepalived_dbus = None

        # keepalived trap listener.
        if self._keepalived_trap_listener is not None:
            await _safe_async(
                "keepalived_trap_listener", self._keepalived_trap_listener.stop())
            self._keepalived_trap_listener = None

        # keepalived dispatcher: cancel the walk task.
        if self._keepalived_dispatcher is not None:
            await _safe_async(
                "keepalived_dispatcher", self._keepalived_dispatcher.stop())
            self._keepalived_dispatcher = None

        # Log dispatcher: sinks must flush before we tear down the
        # worker router (the router drains NFLOG events into the
        # dispatcher; once it closes, events stop arriving).
        if self._log_dispatcher is not None:
            await _safe_async(
                "log_dispatcher", self._log_dispatcher.shutdown())
            self._log_dispatcher = None

        # Pull resolver.
        if self._pull_resolver is not None:
            await _safe_async(
                "pull_resolver", self._pull_resolver.shutdown())
            self._pull_resolver = None

        # IP-list tracker.
        if self._iplist_task is not None:
            self._iplist_task.cancel()
            try:
                await self._iplist_task
            except (asyncio.CancelledError, Exception):
                pass
            self._iplist_task = None
            self._iplist_tracker = None

        # Plain-list tracker (nfsets ip-list-plain backend).
        if self._plain_task is not None:
            self._plain_task.cancel()
            try:
                await self._plain_task
            except (asyncio.CancelledError, Exception):
                pass
            self._plain_task = None
            self._plain_tracker = None

        # Instance manager.
        if self._instance_manager is not None:
            await _safe_async(
                "instance_manager", self._instance_manager.shutdown())
            self._instance_manager = None

        # Peer link: stop sending heartbeats and close the UDP socket.
        if self._peer_link is not None:
            await _safe_async("peer_link", self._peer_link.stop())
            self._peer_link = None

        # pbdns ingress server.
        if self._pbdns_server is not None:
            await _safe_async("pbdns_server", self._pbdns_server.close())
            self._pbdns_server = None

        # State store: final save before the tracker gets torn down.
        if self._state_store is not None:
            await _safe_async("state_store", self._state_store.stop())
            self._state_store = None

        # SetWriter: flush pending batches through the worker router.
        if self._set_writer is not None:
            await _safe_async("set_writer", self._set_writer.shutdown())
            self._set_writer = None

        # Worker router: terminate every per-netns fork worker.
        if self._router is not None:
            await _safe_async("worker_router", self._router.shutdown())
            self._router = None

        # Drop tracker + bridge references — they own no kernel state.
        self._tracker_bridge = None
        self._tracker = None

        # Synchronous subsystems (prom server, profile teardown, …).
        self._shutdown()

        # After all steps: surface aggregated failures so the process
        # exits non-zero and monitoring sees a failed shutdown.
        if errors:
            failed = ", ".join(s for s, _ in errors)
            log.error(
                "shorewalld shutdown completed with %d error(s) in: %s",
                len(errors), failed,
            )
            sys.exit(1)

    def _shutdown(self) -> None:
        if self._shutdown_done:
            return
        self._shutdown_done = True

        # 1. Cancel the reprobe loop.
        if self._reprobe_task is not None:
            try:
                self._reprobe_task.cancel()
            except Exception:
                pass
            self._reprobe_task = None

        # 2. Stop the dnstap consumer (Phase 4).
        if self._dnstap_server is not None:
            try:
                self._dnstap_server.close()
            except Exception:
                log.exception("dnstap server close failed")
            self._dnstap_server = None

        # 3. Stop the Prometheus HTTP server (Phase 2).
        if self._prom_server is not None:
            try:
                self._prom_server.shutdown()  # type: ignore[attr-defined]
            except Exception:
                try:
                    self._prom_server.close()
                except Exception:
                    log.exception("prom server close failed")
            self._prom_server = None

        # 4. Tear down every netns profile (Phase 3).
        if self._profile_builder is not None:
            try:
                self._profile_builder.close_all()
            except Exception:
                log.exception("profile teardown failed")
            self._profile_builder = None

        # 4a. Close all cached pyroute2 IPRoute handles (link/qdisc/
        #     neighbour/address collectors share one handle per netns).
        try:
            from .collectors._shared import close_all_rtnl
            close_all_rtnl()
        except Exception:
            log.debug("close_all_rtnl on shutdown failed, ignoring")

        # 5. Wake the main loop so run() returns.
        if self._stop_event is not None and not self._stop_event.is_set():
            if self._loop is not None and self._loop.is_running():
                try:
                    self._loop.call_soon_threadsafe(self._stop_event.set)
                except RuntimeError:
                    pass
            else:
                # No loop running (unit test called shutdown() directly).
                self._stop_event.set()
