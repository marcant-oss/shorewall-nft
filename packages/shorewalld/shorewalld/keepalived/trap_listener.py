"""Unix DGRAM trap receiver for keepalived SNMPv2c traps.

snmpd is configured with::

    trap2sink unix:/run/shorewalld/snmp-trap.sock

which forwards every SNMPv2c trap it receives to our socket as a raw
BER-encoded SNMP message.  This module:

1. Binds a ``SOCK_DGRAM`` Unix socket at *socket_path*.
2. Decodes each datagram via ``pysnmp.proto.api.v2c``.
3. Resolves the ``snmpTrapOID.0`` varbind against
   :data:`shorewalld.keepalived.mib.NOTIFICATIONS`.
4. Builds a :class:`KeepalivedTrapEvent` and hands it to the dispatcher.

Performance doctrine
--------------------
The receive path calls :meth:`~shorewalld.keepalived.dispatcher.KeepalivedDispatcher.on_trap_event`
synchronously — it must be O(1) and allocation-bounded.  The dispatcher
does lock-free counter bumps internally; no blocking allowed in this loop.
Malformed datagrams are logged at DEBUG and dropped — they never kill the
recv loop.

Availability
------------
``pysnmp`` is an optional dependency (installed via ``pip install shorewalld[snmp]``).
When the module is absent, :exc:`KeepalivedTrapListenerUnavailable` is raised
at construction time — same pattern as
:exc:`~shorewalld.keepalived.snmp_client.KeepalivedSnmpClientUnavailable`.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

log = logging.getLogger("shorewalld.keepalived.trap_listener")

# ---------------------------------------------------------------------------
# Optional pysnmp import
# ---------------------------------------------------------------------------

try:
    from pyasn1.codec.ber import decoder as _ber_decoder  # type: ignore[import-untyped]
    from pysnmp.proto import api as _snmp_api  # type: ignore[import-untyped]

    _PYSNMP_AVAILABLE = True
except ImportError:
    _PYSNMP_AVAILABLE = False


class KeepalivedTrapListenerUnavailable(RuntimeError):
    """Raised when pysnmp is not installed and the trap listener is requested."""


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

# OID for sysUpTime.0 — first varbind in every v2c trap
_OID_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
# OID for snmpTrapOID.0 — second varbind in every v2c trap
_OID_SNMPTRAPOID = "1.3.6.1.6.3.1.1.4.1.0"

# Maximum datagram size — matches max UDP payload
_RECV_BUFSIZE = 65507


@dataclass(frozen=True, slots=True)
class KeepalivedTrapEvent:
    """Decoded keepalived SNMPv2c trap.

    Attributes
    ----------
    name:
        Human-readable trap name resolved from
        :data:`~shorewalld.keepalived.mib.NOTIFICATIONS`.
        ``"unknown"`` when the OID is not in the MIB.
    trap_oid:
        Numeric OID, dot-separated, no leading dot.
    objects:
        Payload varbinds (everything after sysUpTime.0 + snmpTrapOID.0),
        keyed by column name (from the MIB's OBJECTS clause if the trap
        is known, or by OID string for unknown traps).
    received_at:
        Wall-clock time at receive (``time.time()``).
    source:
        Fixed tag ``"snmp-trap"`` for dispatcher event-stream filtering.
    """

    name: str
    trap_oid: str
    objects: dict[str, str]
    received_at: float
    source: str = field(default="snmp-trap")


# ---------------------------------------------------------------------------
# Trap listener
# ---------------------------------------------------------------------------


class KeepalivedTrapListener:
    """Async Unix DGRAM receiver for keepalived SNMPv2c traps.

    Parameters
    ----------
    socket_path:
        Filesystem path for the Unix DGRAM socket.  Created by
        :meth:`start`; removed by :meth:`stop`.
    dispatcher:
        The :class:`~shorewalld.keepalived.dispatcher.KeepalivedDispatcher`
        that receives decoded :class:`KeepalivedTrapEvent` objects.
    socket_mode:
        chmod applied to the socket after creation.  Default ``0o660``
        so that snmpd (typically running as its own group) can write to it.

    Raises
    ------
    KeepalivedTrapListenerUnavailable
        If ``pysnmp`` is not installed.
    """

    def __init__(
        self,
        *,
        socket_path: str,
        dispatcher: "KeepalivedDispatcher",
        socket_mode: int = 0o660,
    ) -> None:
        if not _PYSNMP_AVAILABLE:
            raise KeepalivedTrapListenerUnavailable(
                "pysnmp is not installed; run: pip install shorewalld[snmp]"
            )
        self._socket_path = socket_path
        self._dispatcher = dispatcher
        self._socket_mode = socket_mode
        self._sock: socket.socket | None = None
        self._recv_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Bind the Unix DGRAM socket and spawn the receive loop."""
        # Remove stale socket if present.
        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass

        # Ensure parent directory exists.
        os.makedirs(os.path.dirname(self._socket_path), exist_ok=True)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.bind(self._socket_path)
            os.chmod(self._socket_path, self._socket_mode)
        except Exception:
            sock.close()
            raise

        self._sock = sock
        self._recv_task = asyncio.create_task(
            self._recv_loop(), name="keepalived-trap-recv",
        )
        log.info("keepalived trap listener bound to %s", self._socket_path)

    async def stop(self) -> None:
        """Cancel the receive loop, close and unlink the socket."""
        if self._recv_task is not None:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
            self._recv_task = None

        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass

        log.info("keepalived trap listener stopped")

    # ------------------------------------------------------------------
    # Internal receive loop
    # ------------------------------------------------------------------

    async def _recv_loop(self) -> None:
        """Drain datagrams from the Unix socket until cancelled."""
        loop = asyncio.get_running_loop()
        sock = self._sock

        fut: asyncio.Future[None] = loop.create_future()

        def _readable_cb() -> None:
            if not fut.done():
                fut.set_result(None)

        loop.add_reader(sock.fileno(), _readable_cb)
        try:
            while True:
                # Wait for socket to become readable.
                await fut
                fut = loop.create_future()
                loop.add_reader(sock.fileno(), _readable_cb)

                # Drain all pending datagrams without blocking.
                while True:
                    try:
                        raw = sock.recv(_RECV_BUFSIZE)
                    except BlockingIOError:
                        break
                    except OSError as exc:
                        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            break
                        log.debug(
                            "keepalived trap recv error: %s", exc,
                        )
                        break

                    if not raw:
                        break

                    event = self._decode_trap(raw)
                    if event is not None:
                        self._dispatcher.on_trap_event(event)
        finally:
            loop.remove_reader(sock.fileno())

    def _decode_trap(self, raw: bytes) -> KeepalivedTrapEvent | None:
        """BER-decode one SNMPv2c trap datagram.

        Returns a :class:`KeepalivedTrapEvent` on success, or *None* if
        the datagram is malformed / not a v2c trap.  Any exception is
        caught and logged at DEBUG.
        """
        try:
            return self._decode_trap_inner(raw)
        except Exception as exc:  # noqa: BLE001
            log.debug("keepalived trap: decode error (%s): %s", type(exc).__name__, exc)
            # Signal the dispatcher so counters stay accurate.
            self._dispatcher.on_trap_decode_error()
            return None

    def _decode_trap_inner(self, raw: bytes) -> KeepalivedTrapEvent | None:
        """Inner decode — may raise; caller handles all exceptions."""
        from shorewalld.keepalived import mib as _mib

        pMod = _snmp_api.v2c

        # BER-decode the outer SNMP message.
        msg, _ = _ber_decoder.decode(raw, asn1Spec=pMod.Message())

        # Extract PDU.
        pdu = pMod.apiMessage.get_pdu(msg)
        # Ensure it's an SNMPv2TrapPDU (type name check).
        if type(pdu).__name__ != "SNMPv2TrapPDU":
            log.debug(
                "keepalived trap: unexpected PDU type %s, skipping",
                type(pdu).__name__,
            )
            return None

        varbinds = pMod.apiTrapPDU.get_varbinds(pdu)
        # v2c traps always have at least 2 varbinds: sysUpTime.0, snmpTrapOID.0
        if len(varbinds) < 2:
            log.debug(
                "keepalived trap: fewer than 2 varbinds (%d), skipping",
                len(varbinds),
            )
            return None

        # Find snmpTrapOID.0 — should be varbinds[1] but scan to be safe.
        trap_oid_str: str | None = None
        for oid, val in varbinds:
            oid_s = oid.prettyPrint()
            if oid_s == _OID_SNMPTRAPOID:
                trap_oid_str = val.prettyPrint()
                break

        if trap_oid_str is None:
            log.debug("keepalived trap: snmpTrapOID.0 not found in varbinds")
            return None

        # Resolve name from MIB.
        mib_entry = _mib.NOTIFICATIONS.get(trap_oid_str)
        if mib_entry is not None:
            trap_name, object_names = mib_entry
        else:
            trap_name = "unknown"
            object_names = []

        # Build objects dict from payload varbinds (index 2+).
        objects: dict[str, str] = {}
        payload_vbs = varbinds[2:]
        for idx, (oid, val) in enumerate(payload_vbs):
            oid_s = oid.prettyPrint()
            val_s = val.prettyPrint()
            if idx < len(object_names):
                key = object_names[idx]
            else:
                key = oid_s
            objects[key] = val_s

        return KeepalivedTrapEvent(
            name=trap_name,
            trap_oid=trap_oid_str,
            objects=objects,
            received_at=time.time(),
        )
