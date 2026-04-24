"""Control-socket request handlers, separated from Daemon for testability.

Each handler is an async method receiving the decoded request dict and
returning the reply dict.  The handlers receive the subsystem references
they need via the constructor — they do NOT hold a reference to the whole
Daemon object.

Handler method names match the control-socket command names with hyphens
replaced by underscores and a ``handle_`` prefix.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from .dns_pull_resolver import PullResolver
    from .instance import InstanceManager
    from .iplist.tracker import IpListTracker
    from .keepalived.dbus_client import KeepalivedDbusClient

log = logging.getLogger("shorewalld.control_handlers")


class ControlHandlers:
    """Control-socket request handlers, separated from Daemon for testability.

    Each handler is an async method receiving decoded request args and
    returning the reply dict.  The handlers receive the subsystem references
    they need via the constructor — they do NOT hold a reference to the
    whole Daemon.

    The optional *nfsets_hook* callback is called after
    ``register-instance`` to wire nfsets backends; it should be
    ``Daemon._apply_nfsets_from_instances``.

    The optional *keepalived_dbus* collaborator handles the four
    ``keepalived-*`` control-socket commands (data, stats, reload, garp).
    When ``None``, those handlers return ``{"error": "keepalived-dbus disabled"}``.
    Daemon wiring (passing the real client) lands in Commit 4 (P8).
    """

    def __init__(
        self,
        *,
        instance_mgr: "InstanceManager | None" = None,
        iplist_tracker: "IpListTracker | None" = None,
        pull_resolver: "PullResolver | None" = None,
        nfsets_hook: "Callable[[], Awaitable[None]] | None" = None,
        keepalived_dbus: "KeepalivedDbusClient | None" = None,
    ) -> None:
        self._instance_mgr = instance_mgr
        self._iplist_tracker = iplist_tracker
        self._pull_resolver = pull_resolver
        self._nfsets_hook = nfsets_hook
        self._keepalived_dbus = keepalived_dbus

    # ── iplist handlers ───────────────────────────────────────────────

    async def handle_refresh_iplist(self, req: dict) -> dict:
        """Trigger a refresh of one or all IP-list entries."""
        if self._iplist_tracker is None:
            return {"ok": False, "error": "iplist tracker not running"}
        name = req.get("name")
        if name:
            await self._iplist_tracker.refresh_one(name)
        else:
            await self._iplist_tracker.refresh_all()
        return {"ok": True}

    async def handle_iplist_status(self, req: dict) -> dict:  # noqa: ARG002
        """Return the status of all IP-list entries."""
        if self._iplist_tracker is None:
            return {"ok": False, "error": "iplist tracker not running"}
        return {"ok": True, "lists": self._iplist_tracker.status()}

    # ── instance handlers ─────────────────────────────────────────────

    async def handle_reload_instance(self, req: dict) -> dict:
        """Reload one or all instances from disk."""
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}
        name = req.get("name")
        await self._instance_mgr.reload(name)
        return {"ok": True}

    async def handle_instance_status(self, req: dict) -> dict:  # noqa: ARG002
        """Return the status of all managed instances."""
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}
        return {"ok": True, "instances": self._instance_mgr.status()}

    async def handle_register_instance(self, req: dict) -> dict:
        """Register (or re-register) a shorewall-nft instance.

        Required keys: ``config_dir``.
        Optional: ``netns``, ``name``, ``allowlist_path``, ``nfsets``,
        ``dns``, ``dnsr``.
        """
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}

        from .instance import InstanceConfig

        config_dir = req.get("config_dir")
        netns = req.get("netns") or ""
        if not config_dir:
            return {"ok": False, "error": "missing 'config_dir'"}
        dir_path = Path(config_dir)
        # Client-supplied name wins (from INSTANCE_NAME / CLI);
        # otherwise derive deterministically.
        name = (req.get("name") or netns or dir_path.name).strip()
        allowlist_path = Path(
            req.get("allowlist_path")
            or (dir_path / "dnsnames.compiled")
        )
        nfsets_payload = req.get("nfsets") or None
        cfg = InstanceConfig(
            name=name,
            netns=netns,
            config_dir=dir_path,
            allowlist_path=allowlist_path,
            nfsets_payload=nfsets_payload,
        )
        dns_payload: dict[str, Any] | None = None
        if "dns" in req or "dnsr" in req:
            dns_payload = {
                k: req[k] for k in ("dns", "dnsr") if k in req
            }
        n = await self._instance_mgr.register(
            cfg,
            dns_payload=dns_payload,
            nfsets_payload=nfsets_payload,
        )
        # Wire nfsets backends (PlainListTracker etc.) after register.
        if self._nfsets_hook is not None:
            await self._nfsets_hook()
        return {"ok": True, "name": cfg.name, "qnames": n}

    async def handle_deregister_instance(self, req: dict) -> dict:
        """Deregister a shorewall-nft instance by name or config_dir."""
        if self._instance_mgr is None:
            return {"ok": False, "error": "instance manager not running"}

        name = req.get("name")
        if not name:
            config_dir = req.get("config_dir")
            netns = req.get("netns") or ""
            if config_dir:
                name = netns or Path(config_dir).name
        if not name:
            return {
                "ok": False,
                "error": "missing 'name' or 'config_dir'",
            }
        await self._instance_mgr.deregister(name)
        return {"ok": True, "name": name}

    # ── refresh-dns handler ───────────────────────────────────────────

    async def handle_refresh_dns(self, req: dict) -> dict:
        """Trigger an immediate DNS refresh for one hostname or all."""
        if self._pull_resolver is None:
            return {"ok": False, "error": "pull resolver not running"}
        hostname = req.get("hostname")
        n = await self._pull_resolver.refresh(hostname)
        return {"ok": True, "rescheduled": n}

    # ── keepalived D-Bus handlers ────────────────────────────────────
    #
    # These handlers are additive only — the daemon dispatch table wiring
    # lands in Commit 4 (P8).  Tests call the handler methods directly.
    # When keepalived_dbus=None, every handler returns {"error": ...} so
    # partial builds degrade cleanly.

    async def handle_keepalived_data(self, req: dict) -> dict:  # noqa: ARG002
        """Return keepalived.data contents (calls PrintData D-Bus method).

        Response: ``{"data": "<utf-8 str>"}`` on success,
        ``{"error": "..."}`` when disabled or on error.
        """
        if self._keepalived_dbus is None:
            return {"error": "keepalived-dbus disabled"}
        try:
            raw = await self._keepalived_dbus.print_data()
            return {"data": raw.decode("utf-8", "replace")}
        except Exception as exc:  # noqa: BLE001
            log.debug("handle_keepalived_data: %s", exc)
            return {"error": str(exc)}

    async def handle_keepalived_stats(self, req: dict) -> dict:
        """Return keepalived.stats contents (calls PrintStats[Clear]).

        Request: optional ``{"clear": true}`` to prefer PrintStatsClear.
        Response: ``{"data": "<utf-8 str>"}`` on success.
        """
        if self._keepalived_dbus is None:
            return {"error": "keepalived-dbus disabled"}
        clear = bool(req.get("clear", False))
        try:
            raw = await self._keepalived_dbus.print_stats(clear=clear)
            return {"data": raw.decode("utf-8", "replace")}
        except Exception as exc:  # noqa: BLE001
            log.debug("handle_keepalived_stats: %s", exc)
            return {"error": str(exc)}

    async def handle_keepalived_reload(self, req: dict) -> dict:  # noqa: ARG002
        """Trigger keepalived config reload (calls ReloadConfig D-Bus method).

        Requires ``KEEPALIVED_DBUS_METHODS=all``.
        Response: ``{"ok": true}`` on success.
        """
        if self._keepalived_dbus is None:
            return {"error": "keepalived-dbus disabled"}
        try:
            await self._keepalived_dbus.reload_config()
            return {"ok": True}
        except Exception as exc:  # noqa: BLE001
            log.debug("handle_keepalived_reload: %s", exc)
            return {"error": str(exc)}

    async def handle_keepalived_garp(self, req: dict) -> dict:
        """Send a Gratuitous ARP for a named VRRP instance.

        Request: ``{"instance": "<name>"}`` (required).
        Response: ``{"ok": true}`` on success or ``{"error": "..."}`` on failure.
        Requires ``KEEPALIVED_DBUS_METHODS=all``.
        """
        if self._keepalived_dbus is None:
            return {"error": "keepalived-dbus disabled"}
        instance = req.get("instance")
        if not instance:
            return {"error": "missing 'instance' in request"}
        try:
            await self._keepalived_dbus.send_garp(instance)
            return {"ok": True}
        except Exception as exc:  # noqa: BLE001
            log.debug("handle_keepalived_garp: %s", exc)
            return {"error": str(exc)}
