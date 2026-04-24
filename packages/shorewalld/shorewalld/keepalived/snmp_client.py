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

The MIB-driven :meth:`KeepalivedSnmpClient.walk_all` collects every
scalar and table defined in :mod:`shorewalld.keepalived.mib` in one
pass and returns a :class:`KeepalivedSnapshot`.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

try:
    import netsnmp  # type: ignore[import-untyped]
    _NETSNMP_AVAILABLE = True
except ImportError:
    netsnmp = None  # type: ignore[assignment]
    _NETSNMP_AVAILABLE = False


# ---------------------------------------------------------------------------
# Snapshot dataclass — pure-data output of walk_all()
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeepalivedSnapshot:
    """Immutable MIB snapshot returned by :meth:`KeepalivedSnmpClient.walk_all`.

    Attributes:
        scalars: Mapping of scalar name → stringified value for every
            scalar OID in :data:`shorewalld.keepalived.mib.SCALARS`.
        tables: Mapping of table name → list of row dicts.  Each row dict
            maps column name → stringified value and also carries two
            special keys:

            * ``"__index__"`` — a :class:`tuple` of index component strings
              (split on ``"."`` when the dot-count matches the number of index
              fields; falls back to a single-element tuple otherwise).
            * ``"__index_raw__"`` — the raw OID suffix string before splitting
              (always present; useful for debugging multi-level indexes).

        collected_at: :func:`time.time` timestamp when the walk finished.
        walk_errors: Per-root error messages captured during the walk.
            Empty tuple on a clean run.  Errors are non-fatal — partial
            data in ``scalars`` / ``tables`` is valid.
    """

    scalars: dict[str, str]
    tables: dict[str, list[dict[str, str]]]
    collected_at: float
    walk_errors: tuple[str, ...]

    @staticmethod
    def empty() -> "KeepalivedSnapshot":
        """Return a snapshot with no data (used for pre-start state)."""
        from shorewalld.keepalived import mib as _mib  # local import avoids cycle
        return KeepalivedSnapshot(
            scalars={},
            tables={name: [] for name in _mib.TABLES},
            collected_at=time.time(),
            walk_errors=(),
        )


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

    # ------------------------------------------------------------------
    # MIB-driven full walk
    # ------------------------------------------------------------------

    async def walk_all(self) -> KeepalivedSnapshot:
        """Walk every scalar and table root defined in the committed MIB.

        Populates a :class:`KeepalivedSnapshot` with:

        * **scalars** — one entry per OID in
          :data:`~shorewalld.keepalived.mib.SCALARS`.  A scalar walk
          returns at most one varbind (the ``.0`` instance); we pick
          the first and discard the rest.
        * **tables** — one list-of-rows per table in
          :data:`~shorewalld.keepalived.mib.TABLES`.  Rows are grouped
          by the OID index suffix returned by net-snmp; each row is a
          dict ``{col_name: value, "__index__": tuple, "__index_raw__": str}``.

        Per-root errors are caught, appended to ``walk_errors``, and the
        walk continues with the next root — callers see partial data
        rather than nothing.

        Walks are issued sequentially; parallel walks would reduce wall
        time but add complexity — at a 30 s interval the sequential
        multi-millisecond latency is negligible.
        """
        from shorewalld.keepalived import mib as _mib  # avoid import cycle

        scalars: dict[str, str] = {}
        tables: dict[str, list[dict[str, str]]] = {
            name: [] for name in _mib.TABLES
        }
        errors: list[str] = []

        # --- Scalars ---------------------------------------------------
        for scalar_oid, (name, _syntax, _access) in _mib.SCALARS.items():
            try:
                varbinds = await self.walk(scalar_oid)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"scalar {name} ({scalar_oid}): {exc}")
                continue
            if varbinds:
                scalars[name] = varbinds[0].value

        # --- Tables ----------------------------------------------------
        for table_name, tbl in _mib.TABLES.items():
            table_oid: str = tbl["oid"]
            entry_oid: str = tbl["entry_oid"]
            index_fields: list[str] = tbl["index"]
            columns: dict[int, tuple[str, str, str]] = tbl["columns"]
            n_index = len(index_fields)

            # Build a reverse-lookup: column OID prefix → col_num
            # entry_oid + "." + col_num is the column OID prefix.
            col_oid_to_num: dict[str, int] = {
                f"{entry_oid}.{col_num}": col_num
                for col_num in columns
            }

            try:
                varbinds = await self.walk(table_oid)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"table {table_name} ({table_oid}): {exc}")
                continue

            # Group varbinds by index suffix into rows.
            # vb.oid = column OID e.g. "...entry_oid.COL_NUM"
            # vb.index = row index suffix e.g. "1" or "1.2"
            rows: dict[str, dict[str, str]] = {}
            for vb in varbinds:
                # Identify column number from the varbind OID.
                # net-snmp returns tag as the column OID (without the index).
                col_num = _resolve_col_num(vb.oid, col_oid_to_num, entry_oid)
                if col_num is None:
                    continue
                col_info = columns.get(col_num)
                if col_info is None:
                    continue
                col_name, _col_syntax, _col_access = col_info
                row_key = vb.index
                if row_key not in rows:
                    rows[row_key] = {
                        "__index_raw__": row_key,
                        "__index__": _parse_index(row_key, n_index),
                    }
                rows[row_key][col_name] = vb.value

            tables[table_name] = list(rows.values())

        return KeepalivedSnapshot(
            scalars=scalars,
            tables=tables,
            collected_at=time.time(),
            walk_errors=tuple(errors),
        )

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


# ---------------------------------------------------------------------------
# Module-level helpers for walk_all()
# ---------------------------------------------------------------------------


def _resolve_col_num(
    vb_oid: str,
    col_oid_to_num: dict[str, int],
    entry_oid: str,
) -> int | None:
    """Extract the column number from a varbind's OID.

    net-snmp's ``Varbind.tag`` for a table walk is the column OID
    (``entry_oid + "." + col_num``).  We look it up directly from the
    pre-built ``col_oid_to_num`` map.  Falls back to a string-prefix
    scan when the OID in the varbind has already been stripped of the
    leading dot (handled upstream in ``_varbind_to_tuple``).
    """
    col_num = col_oid_to_num.get(vb_oid)
    if col_num is not None:
        return col_num
    # Some net-snmp versions return only the last component.
    # Try to match by stripping entry_oid prefix.
    if vb_oid.startswith(entry_oid + "."):
        suffix = vb_oid[len(entry_oid) + 1:]
        # suffix may be "COL_NUM" or "COL_NUM.index..." — we want only col.
        first = suffix.split(".")[0]
        try:
            return int(first)
        except ValueError:
            pass
    return None


def _parse_index(raw: str, n_index: int) -> tuple[str, ...]:
    """Split a row-index OID suffix into a tuple of index components.

    The number of dot-separated fields in ``raw`` is compared to
    ``n_index``.  When they match, we split on ``"."`` and return all
    components.  When there are more dots (e.g. an ``InetAddress``
    index component contains dots), we cannot safely split — the whole
    suffix is returned as a single-element tuple.

    Examples::

        _parse_index("1", 1)        → ("1",)
        _parse_index("1.5", 2)      → ("1", "5")
        _parse_index("1.4.192.168.1.1", 2)  → ("1.4.192.168.1.1",)  # InetAddr
    """
    if not raw:
        return (raw,)
    parts = raw.split(".")
    if len(parts) == n_index:
        return tuple(parts)
    # Mismatch — InetAddress or other variable-length index.
    return (raw,)
