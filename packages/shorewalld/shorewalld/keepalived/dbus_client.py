"""Async D-Bus client for keepalived's Vrrp1 interface.

Subscribes to the four keepalived D-Bus signals (VrrpStarted, VrrpReloaded,
VrrpStopped, VrrpStatusChange) and exposes the state-changing D-Bus methods
(PrintData, PrintStats[Clear], ReloadConfig, SendGarp, and opt-in
CreateInstance / DestroyInstance) with ACL-tier enforcement.

Architecture
------------
Uses ``dbus-next`` (asyncio-native, ``pip install dbus-next>=0.2.3``) when
available.  Falls back to :exc:`KeepalivedDbusUnavailable` at construction
time when the library is absent — same degradation pattern as
:exc:`~shorewalld.keepalived.snmp_client.KeepalivedSnmpClientUnavailable`.

The existing :class:`~shorewalld.collectors.vrrp.VrrpCollector` (jeepney-based)
is **not** modified in this commit — both coexist.  The new client is additive;
the old collector is phased out in Commit 4 (P8).

Signal fan-out
--------------
Signals are received via ``MessageBus.add_message_handler()`` (low-level) so
we don't need introspection of the keepalived node at start-up.  We match on
``interface='org.keepalived.Vrrp1.Instance'`` and ``member`` in the known
set of signal names.  Each signal is converted to a
:class:`KeepalivedDbusEvent` and handed to
:meth:`~shorewalld.keepalived.dispatcher.KeepalivedDispatcher.on_dbus_event`.

VrrpStatusChange carries ``(name: s, new_state: u)`` args per the keepalived
source (``vrrp_dbus.c``).  State int→str mapping:
  0 = "init"
  1 = "backup"
  2 = "master"
  3 = "fault"

ACL tiers
---------
``method_acl`` controls which methods are callable:

* ``"none"`` — all method calls raise :exc:`KeepalivedDbusAclDenied`.
* ``"readonly"`` (default) — ``print_data``, ``print_stats`` permitted;
  ``reload_config``, ``send_garp`` denied.
* ``"all"`` — all 5 core methods permitted.

``create_instance`` / ``destroy_instance`` require
``enable_create_instance=True`` regardless of ACL tier.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

log = logging.getLogger("shorewalld.keepalived.dbus_client")

# ---------------------------------------------------------------------------
# Optional dbus-next import
# ---------------------------------------------------------------------------

try:
    from dbus_next import BusType, Message, MessageType  # type: ignore[import-untyped]
    from dbus_next.aio import MessageBus  # type: ignore[import-untyped]

    _DBUS_AVAILABLE = True
except ImportError:
    _DBUS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class KeepalivedDbusUnavailable(RuntimeError):
    """Raised when ``dbus-next`` is not installed."""


class KeepalivedDbusAclDenied(PermissionError):
    """Raised when a method is blocked by the configured ACL tier."""


class KeepalivedDbusInstanceNotFound(LookupError):
    """Raised when ``send_garp`` cannot resolve the instance object path."""


# ---------------------------------------------------------------------------
# State int → string mapping (from keepalived vrrp_dbus.c)
# ---------------------------------------------------------------------------

_STATE_MAP: dict[int, str] = {
    0: "init",
    1: "backup",
    2: "master",
    3: "fault",
}

# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

_KA_INSTANCE_IFACE = "org.keepalived.Vrrp1.Instance"
_KA_VRRP_IFACE = "org.keepalived.Vrrp1.Vrrp"
_KA_INSTANCE_METHODS_IFACE = "org.keepalived.Vrrp1.Instance"
_KA_VRRP_OBJ = "/org/keepalived/Vrrp1/Vrrp"
_KA_BUS_NAME = "org.keepalived.Vrrp1"
_KA_INSTANCE_ROOT = "/org/keepalived/Vrrp1/Instance"

# Signals emitted on org.keepalived.Vrrp1.Instance
_SIGNAL_VRRP_STATUS_CHANGE = "VrrpStatusChange"
_SIGNAL_VRRP_STARTED = "VrrpStarted"
_SIGNAL_VRRP_RELOADED = "VrrpReloaded"
_SIGNAL_VRRP_STOPPED = "VrrpStopped"
_ALL_SIGNALS = frozenset({
    _SIGNAL_VRRP_STATUS_CHANGE,
    _SIGNAL_VRRP_STARTED,
    _SIGNAL_VRRP_RELOADED,
    _SIGNAL_VRRP_STOPPED,
})

# D-Bus match rule for all keepalived instance signals
_MATCH_RULE = "type='signal',interface='org.keepalived.Vrrp1.Instance'"


@dataclass(frozen=True, slots=True)
class KeepalivedDbusEvent:
    """Decoded keepalived D-Bus signal event.

    Attributes
    ----------
    signal:
        Signal name: one of ``"VrrpStatusChange"``, ``"VrrpStarted"``,
        ``"VrrpReloaded"``, ``"VrrpStopped"``.
    instance:
        Instance name carried in the signal args for signals that include one
        (``VrrpStatusChange``, ``VrrpStarted``).  Empty string otherwise.
    new_state:
        State name for ``VrrpStatusChange`` (``"master"``, ``"backup"``,
        ``"fault"``, ``"init"``).  Empty string for other signals.
    received_at:
        Wall-clock time at receive (``time.time()``).
    source:
        Fixed tag ``"dbus-signal"`` for dispatcher event-stream filtering.
    """

    signal: str
    instance: str
    new_state: str
    received_at: float
    source: str = field(default="dbus-signal")


# ---------------------------------------------------------------------------
# ACL tiers
# ---------------------------------------------------------------------------

# Methods in each tier (cumulative: "all" ⊇ "readonly" ⊇ ∅)
_READONLY_METHODS = frozenset({"print_data", "print_stats"})
_ALL_METHODS = _READONLY_METHODS | frozenset({"reload_config", "send_garp"})
_CREATE_INSTANCE_METHODS = frozenset({"create_instance", "destroy_instance"})


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class KeepalivedDbusClient:
    """Async D-Bus client covering keepalived's SNMPv2-exposed methods + signals.

    Uses ``dbus-next`` (asyncio-native) if importable; raises
    :exc:`KeepalivedDbusUnavailable` at construction time otherwise.

    Parameters
    ----------
    dispatcher:
        Receives :class:`KeepalivedDbusEvent` objects on each signal.
    method_acl:
        One of ``"none"``, ``"readonly"`` (default), ``"all"``.
    enable_create_instance:
        Permit ``create_instance`` / ``destroy_instance`` (requires keepalived
        built with ``--enable-dbus-create-instance``).
    """

    BUS_NAME = _KA_BUS_NAME
    INSTANCE_PATH = "/org/keepalived/Vrrp1/Vrrp"
    INSTANCE_IFACE = "org.keepalived.Vrrp1.Vrrp"
    INSTANCE_OBJ_PATH_FMT = "/org/keepalived/Vrrp1/Instance/{nic}/{vrid}/{family}"
    INSTANCE_OBJ_IFACE = "org.keepalived.Vrrp1.Instance"

    ACL_NONE = "none"
    ACL_READONLY = "readonly"
    ACL_ALL = "all"

    def __init__(
        self,
        *,
        dispatcher: "KeepalivedDispatcher",
        method_acl: str = ACL_READONLY,
        enable_create_instance: bool = False,
    ) -> None:
        if not _DBUS_AVAILABLE:
            raise KeepalivedDbusUnavailable(
                "dbus-next is not installed; run: pip install dbus-next>=0.2.3"
            )
        if method_acl not in (self.ACL_NONE, self.ACL_READONLY, self.ACL_ALL):
            raise ValueError(
                f"method_acl must be 'none', 'readonly', or 'all'; got {method_acl!r}"
            )
        self._dispatcher = dispatcher
        self._method_acl = method_acl
        self._enable_create_instance = enable_create_instance
        self._bus: "MessageBus | None" = None

        # Cache: has PrintStatsClear been found to be unavailable?
        self._print_stats_clear_unavailable: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Connect to the system bus and subscribe to keepalived signals."""
        bus = MessageBus(bus_type=BusType.SYSTEM)
        await bus.connect()

        # Register match rule so the bus routes signals to us.
        await bus._add_match_rule(_MATCH_RULE)  # noqa: SLF001

        # Low-level message handler: avoids introspection + proxy setup,
        # which would require keepalived to be running at daemon start.
        bus.add_message_handler(self._on_message)
        self._bus = bus
        log.info("keepalived D-Bus client connected; subscribed to signals")

    async def stop(self) -> None:
        """Disconnect from the system bus cleanly."""
        if self._bus is None:
            return
        try:
            self._bus.disconnect()
        except Exception as exc:
            log.debug("keepalived D-Bus: disconnect error: %s", exc)
        self._bus = None
        log.info("keepalived D-Bus client disconnected")

    # ------------------------------------------------------------------
    # Signal handler (internal)
    # ------------------------------------------------------------------

    def _on_message(self, msg: "Message") -> None:
        """Low-level message handler for D-Bus signals."""
        if msg.message_type != MessageType.SIGNAL:
            return
        if msg.interface != _KA_INSTANCE_IFACE:
            return
        member = msg.member
        if member not in _ALL_SIGNALS:
            return

        try:
            event = self._build_event(member, msg.body)
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "keepalived D-Bus: error building event for %s: %s", member, exc
            )
            return

        self._dispatcher.on_dbus_event(event)

    def _build_event(self, signal: str, body: list) -> KeepalivedDbusEvent:
        """Build a :class:`KeepalivedDbusEvent` from a raw signal body."""
        instance = ""
        new_state = ""

        if signal == _SIGNAL_VRRP_STATUS_CHANGE:
            # Args: (name: s, new_state: u)
            if body and len(body) >= 2:
                instance = str(body[0])
                state_int = int(body[1]) if body[1] is not None else 0
                new_state = _STATE_MAP.get(state_int, f"unknown({state_int})")
        elif signal == _SIGNAL_VRRP_STARTED:
            # Args: (name: s)
            if body:
                instance = str(body[0])
        # VrrpReloaded and VrrpStopped carry no args

        return KeepalivedDbusEvent(
            signal=signal,
            instance=instance,
            new_state=new_state,
            received_at=time.time(),
        )

    # ------------------------------------------------------------------
    # ACL enforcement
    # ------------------------------------------------------------------

    def _check_acl(self, method: str) -> None:
        """Raise :exc:`KeepalivedDbusAclDenied` if *method* is blocked.

        Parameters
        ----------
        method:
            Logical method name (``"print_data"``, ``"reload_config"``, etc.).
        """
        if method in _CREATE_INSTANCE_METHODS:
            if not self._enable_create_instance:
                raise KeepalivedDbusAclDenied(
                    f"{method} requires enable_create_instance=True"
                )
            return
        if self._method_acl == self.ACL_NONE:
            raise KeepalivedDbusAclDenied(
                f"{method} blocked by method_acl='none'"
            )
        if self._method_acl == self.ACL_READONLY and method not in _READONLY_METHODS:
            raise KeepalivedDbusAclDenied(
                f"{method} blocked by method_acl='readonly' (requires 'all')"
            )
        # ACL_ALL permits everything in _ALL_METHODS

    def _require_bus(self) -> "MessageBus":
        """Return the connected bus or raise RuntimeError."""
        if self._bus is None:
            raise RuntimeError(
                "KeepalivedDbusClient is not connected; call start() first"
            )
        return self._bus

    # ------------------------------------------------------------------
    # Method wrappers
    # ------------------------------------------------------------------

    async def print_data(self) -> bytes:
        """Call ``PrintData()`` D-Bus method.

        Side effect: keepalived writes state information to
        ``/tmp/keepalived.data`` then returns.  This method reads and returns
        that file's contents.

        Requires ``method_acl in ("readonly", "all")``.
        """
        self._check_acl("print_data")
        bus = self._require_bus()
        await self._call_method(
            bus, _KA_VRRP_OBJ, _KA_VRRP_IFACE, "PrintData", "", [],
        )
        return self._read_file("/tmp/keepalived.data")

    async def print_stats(self, clear: bool = False) -> bytes:
        """Call ``PrintStats()`` or ``PrintStatsClear()`` D-Bus method.

        When *clear* is ``True`` (default: ``False``), prefers
        ``PrintStatsClear()`` (atomic; keepalived ≥ 2.2.7).  Falls back
        to ``PrintStats()`` on the first ``DBusError``/``NoSuchMethod``
        for the clear variant; caches the fallback decision so subsequent
        calls don't retry.

        Reads and returns ``/tmp/keepalived.stats`` after the call.

        Requires ``method_acl in ("readonly", "all")``.
        """
        self._check_acl("print_stats")
        bus = self._require_bus()

        if clear and not self._print_stats_clear_unavailable:
            try:
                await self._call_method(
                    bus, _KA_VRRP_OBJ, _KA_VRRP_IFACE, "PrintStatsClear", "", [],
                )
            except Exception as exc:  # noqa: BLE001
                log.info(
                    "keepalived D-Bus: PrintStatsClear unavailable (%s), "
                    "falling back to PrintStats for all future calls",
                    exc,
                )
                self._print_stats_clear_unavailable = True
                await self._call_method(
                    bus, _KA_VRRP_OBJ, _KA_VRRP_IFACE, "PrintStats", "", [],
                )
        else:
            await self._call_method(
                bus, _KA_VRRP_OBJ, _KA_VRRP_IFACE, "PrintStats", "", [],
            )

        return self._read_file("/tmp/keepalived.stats")

    async def reload_config(self) -> None:
        """Call ``ReloadConfig()`` D-Bus method (no args).

        Requires ``method_acl="all"``.
        """
        self._check_acl("reload_config")
        bus = self._require_bus()
        await self._call_method(
            bus, _KA_VRRP_OBJ, _KA_VRRP_IFACE, "ReloadConfig", "", [],
        )

    async def send_garp(self, instance: str) -> None:
        """Call ``SendGarp()`` on the named VRRP instance.

        Resolves the instance D-Bus object path via the dispatcher's last-good
        walker snapshot.  Iterates ``vrrpInstanceTable`` rows to find the entry
        whose ``vrrpInstanceName`` matches *instance*, then builds
        ``/org/keepalived/Vrrp1/Instance/{nic}/{vrid}/{family}``.

        Raises
        ------
        KeepalivedDbusInstanceNotFound
            When the dispatcher has no snapshot yet, or when no row in
            ``vrrpInstanceTable`` has a matching ``vrrpInstanceName``.
        KeepalivedDbusAclDenied
            When ``method_acl != "all"``.
        """
        self._check_acl("send_garp")
        # Resolve instance path first — raises KeepalivedDbusInstanceNotFound
        # (cleaner than RuntimeError from _require_bus) if not in snapshot.
        obj_path = self._resolve_instance_path(instance)
        bus = self._require_bus()
        await self._call_method(
            bus, obj_path, _KA_INSTANCE_IFACE, "SendGarp", "", [],
        )

    async def create_instance(self, name: str, config: str) -> None:
        """Call ``CreateInstance(name, config)`` on the keepalived bus.

        Requires ``enable_create_instance=True``; keepalived must be built
        with ``--enable-dbus-create-instance``.
        """
        self._check_acl("create_instance")
        bus = self._require_bus()
        await self._call_method(
            bus, _KA_VRRP_OBJ, _KA_VRRP_IFACE, "CreateInstance", "ss",
            [name, config],
        )

    async def destroy_instance(self, name: str) -> None:
        """Call ``DestroyInstance(name)`` on the keepalived bus.

        Requires ``enable_create_instance=True``.
        """
        self._check_acl("destroy_instance")
        bus = self._require_bus()
        await self._call_method(
            bus, _KA_VRRP_OBJ, _KA_VRRP_IFACE, "DestroyInstance", "s", [name],
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _call_method(
        self,
        bus: "MessageBus",
        obj_path: str,
        interface: str,
        method: str,
        signature: str,
        body: list,
    ) -> list:
        """Send a D-Bus method call and return the reply body."""
        reply = await bus.call(
            Message(
                destination=_KA_BUS_NAME,
                path=obj_path,
                interface=interface,
                member=method,
                signature=signature,
                body=body,
            )
        )
        if reply.message_type == MessageType.ERROR:
            raise RuntimeError(
                f"D-Bus error calling {interface}.{method}: "
                f"{reply.error_name}: {reply.body}"
            )
        return reply.body if reply.body else []

    def _resolve_instance_path(self, instance: str) -> str:
        """Build the D-Bus object path for a named VRRP instance.

        Looks up ``vrrpInstanceTable`` in the dispatcher's last-good snapshot.
        The column names used for path construction follow keepalived's
        ``/org/keepalived/Vrrp1/Instance/{nic}/{vrid}/{family}`` scheme.
        We map MIB columns:
          - ``vrrpInstanceName``           → match key
          - ``vrrpInstanceInterface``      → {nic}  (col 3 in mib)
          - ``vrrpInstanceVirtualRouterId``→ {vrid}
          - we default family to "IPv4" since it is not in the MIB

        Raises :exc:`KeepalivedDbusInstanceNotFound` when the instance
        is not found.
        """
        snap = self._dispatcher.snapshot()
        if snap is None:
            raise KeepalivedDbusInstanceNotFound(
                f"No keepalived snapshot available; cannot resolve instance {instance!r}"
            )

        rows = snap.tables.get("vrrpInstanceTable") or []
        for row in rows:
            name = row.get("vrrpInstanceName", "")
            if name == instance:
                # Try to get nic and vrid from the row.
                nic = row.get("vrrpInstanceInterface", "")
                vrid = row.get("vrrpInstanceVirtualRouterId", "")
                # Use IPv4 as default family (keepalived exposes both IPv4/IPv6
                # but we can't determine it from the vrrpInstanceTable alone).
                family = "IPv4"
                if nic and vrid:
                    return (
                        f"/org/keepalived/Vrrp1/Instance/{nic}/{vrid}/{family}"
                    )
                # If we can't build a proper path, raise rather than guess.
                raise KeepalivedDbusInstanceNotFound(
                    f"Instance {instance!r} found but nic/vrid not available in snapshot"
                )

        raise KeepalivedDbusInstanceNotFound(
            f"Instance {instance!r} not found in vrrpInstanceTable snapshot"
        )

    @staticmethod
    def _read_file(path: str) -> bytes:
        """Read a file and return its contents as bytes.

        Returns empty bytes if the file does not exist or is unreadable.
        """
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as exc:
            log.debug("keepalived D-Bus: cannot read %s: %s", path, exc)
            return b""
