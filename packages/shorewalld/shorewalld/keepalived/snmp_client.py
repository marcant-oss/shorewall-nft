"""python-netsnmp wrapper around ``unix:/run/snmpd/snmpd.sock``.

Thin async adapter — the actual transport, retries, and BER handling
all live in ``libnetsnmp`` (via the ``netsnmp`` Python bindings).
We sit on top and:

1. Present an ``asyncio``-friendly surface (``asyncio.to_thread`` bridge
   so walks don't block the event loop).
2. Accept the net-snmp ``unix:<path>`` Peername convention transparently,
   with a UDP ``host:port`` back-compat path when the Unix socket is
   absent (covers pip-only installs lacking ``python3-netsnmp``).
3. Yield (OID, index, value, syntax) tuples instead of net-snmp's
   ``Varbind`` objects — decouples consumers from the net-snmp Python
   binding's quirks (``.tag`` / ``.iid`` / ``.val`` / ``.type`` with
   ``bytes``-vs-``str`` unpredictability).

The MIB-driven ``walk_all()`` is in a later commit; this module ships
the transport primitive + its tests.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

try:
    import netsnmp  # type: ignore[import-untyped]
    _NETSNMP_AVAILABLE = True
except ImportError:
    netsnmp = None  # type: ignore[assignment]
    _NETSNMP_AVAILABLE = False


@dataclass(frozen=True, slots=True)
class SnmpVarbind:
    """One SNMP varbind decoded into pure-Python types.

    Kept deliberately small: enough for the MIB-driven walker to route
    values (``oid`` / ``index`` identifies the column+row, ``syntax``
    drives the Prometheus mapping, ``value`` is the stringified
    payload).
    """
    oid: str        # Column base OID, e.g. "1.3.6.1.4.1.9586.100.5.2.3.1.4"
    index: str      # Row index portion (after the column), e.g. "1" or "2.192.168.1.1"
    value: str      # Decoded value as a UTF-8 string (caller interprets per syntax)
    syntax: str     # net-snmp type name (INTEGER, OCTETSTR, Counter64, ...)


class KeepalivedSnmpClientUnavailable(RuntimeError):
    """Raised when ``netsnmp`` (python3-netsnmp) isn't installed.

    We distinguish this from generic :class:`ImportError` so the
    control path can emit an actionable ``apt install python3-netsnmp``
    hint rather than a bare traceback. Declared unconditionally so
    consumers can reference it even when netsnmp is absent.
    """


class KeepalivedSnmpClient:
    """SNMPv2c client over a Unix socket (snmpd's ``agentAddress unix:...``).

    Transport selection:

    * ``unix_path`` set **and** the socket exists → ``unix:<path>``
      transport (net-snmp decodes the scheme itself).
    * ``unix_path`` set but the socket missing → fall back to UDP
      (``udp_host``:``udp_port``) with a warning; keeps the daemon
      running while the operator fixes their snmpd.conf.
    * ``unix_path`` unset → UDP only.

    All methods that hit the wire (``walk``, later ``get``) are ``async``
    and wrap ``netsnmp.Session`` synchronous calls in
    :func:`asyncio.to_thread`. The wrapper cost is ≈100 µs per call vs.
    multi-millisecond SNMP round-trips — negligible.
    """

    def __init__(
        self,
        *,
        unix_path: str | None = None,
        udp_host: str = "127.0.0.1",
        udp_port: int = 161,
        community: str = "public",
        timeout_s: float = 1.0,
    ) -> None:
        if not _NETSNMP_AVAILABLE:
            raise KeepalivedSnmpClientUnavailable(
                "python3-netsnmp is not installed. "
                "Install with: apt install python3-netsnmp (Debian/Ubuntu) "
                "or dnf install net-snmp-python3 (Alma/Fedora)."
            )
        self._peername = self._choose_peername(
            unix_path, udp_host, udp_port)
        self._community = community
        # netsnmp.Session expects Timeout in microseconds.
        self._session = netsnmp.Session(
            Peername=self._peername,
            Version=2,
            Community=community,
            Timeout=int(timeout_s * 1_000_000),
            Retries=0,
        )

    @staticmethod
    def _choose_peername(
        unix_path: str | None, udp_host: str, udp_port: int,
    ) -> str:
        """Pick the transport prefix net-snmp will use.

        Pre-checks socket existence so we can fall back cleanly to UDP
        at construction time — avoids a confusing "Timeout" error
        later when the socket actually isn't there.
        """
        if unix_path:
            import os
            if os.path.exists(unix_path):
                return f"unix:{unix_path}"
        return f"udp:{udp_host}:{udp_port}"

    @property
    def peername(self) -> str:
        """Return the net-snmp-formatted peer (``unix:<path>`` or ``udp:host:port``)."""
        return self._peername

    # ------------------------------------------------------------------
    # Async walk
    # ------------------------------------------------------------------
    async def walk(self, root_oid: str) -> list[SnmpVarbind]:
        """Walk the subtree below *root_oid*, return decoded varbinds.

        Blocking net-snmp call is hopped into a worker thread via
        :func:`asyncio.to_thread` — net-snmp releases the GIL during
        the syscall, so other event-loop tasks progress.
        """
        return await asyncio.to_thread(self._sync_walk, root_oid)

    def _sync_walk(self, root_oid: str) -> list[SnmpVarbind]:
        """Synchronous walk implementation — extracted for testability.

        Tests can monkey-patch ``_sync_walk`` directly instead of
        having to stand up a full netsnmp session.
        """
        vars_ = netsnmp.VarList(netsnmp.Varbind(root_oid))
        self._session.walk(vars_)
        return [self._varbind_to_tuple(v, root_oid) for v in vars_]

    @staticmethod
    def _varbind_to_tuple(vb: "object", walked_root: str) -> SnmpVarbind:
        """Coerce a netsnmp.Varbind into our stable SnmpVarbind shape.

        net-snmp's ``.tag`` for a column varbind is the column OID
        *without* the row index — e.g. walking the instance table
        gives ``tag='.1.3.6.1.4.1.9586.100.5.2.3.1.2'`` (the
        vrrpInstanceName column) and ``iid='1'`` (the row index
        ``1``). Some versions return ``tag`` in name form
        (``'vrrpInstanceName'``) instead of numeric OID — we
        normalise by stripping the leading dot and keeping whatever
        net-snmp gave us; the walker can resolve names→OIDs via
        :mod:`shorewalld.keepalived.mib` if needed.

        ``.val`` can be ``bytes`` (OCTET STRING, IpAddress) or a
        string repr of a number depending on SYNTAX. We always emit a
        ``str`` (UTF-8 replace on invalid bytes) — the caller uses
        the ``syntax`` field to decide how to parse.
        """
        tag = getattr(vb, "tag", "") or ""
        if tag.startswith("."):
            tag = tag[1:]
        iid = getattr(vb, "iid", "") or ""
        raw_val = getattr(vb, "val", None)
        if isinstance(raw_val, (bytes, bytearray)):
            value = raw_val.decode("utf-8", "replace")
        elif raw_val is None:
            value = ""
        else:
            value = str(raw_val)
        syntax = getattr(vb, "type", "") or ""
        return SnmpVarbind(
            oid=tag, index=iid, value=value, syntax=syntax,
        )
