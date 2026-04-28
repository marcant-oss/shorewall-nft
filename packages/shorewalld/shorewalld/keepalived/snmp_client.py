"""puresnmp-backed SNMPv2c client for ``agentaddress unix:/run/snmpd/snmpd.sock``.

Pure-Python — kein C-Build, kein ``net-snmp-devel``. Funktioniert auf
AlmaLinux 10 / RHEL 10 wo ``python3-netsnmp`` nicht paketiert ist.

Aufbau:

1. ``puresnmp.api.raw.Client`` als asyncio-natives BER-Frontend (kein
   ``asyncio.to_thread``-Wrapper nötig — die Lib ist async by design).
2. ``send_unix_dgram`` als ``sender=``-Parameter ersetzt den Default
   ``send_udp`` und routet die SNMP-Pakete über einen ``AF_UNIX``-
   ``SOCK_DGRAM``-Socket. Endpoint.ip wird als Pfad interpretiert.
3. Fallback-Pfad: fehlt der Unix-Socket-Pfad bzw. existiert er nicht,
   wird automatisch UDP ``host:port`` benutzt — analog zum Verhalten
   der alten netsnmp-basierten Implementation.

Output bleibt :class:`SnmpVarbind` (oid + index + value + syntax) —
:meth:`walk_all` und alle Konsumenten sind library-agnostisch.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from dataclasses import dataclass

try:
    import puresnmp  # noqa: F401  (module-level availability check)
    from puresnmp.api.raw import Client as _PuresnmpClient
    from puresnmp.credentials import V2C
    from x690.types import ObjectIdentifier
    _PURESNMP_AVAILABLE = True
except ImportError:
    _PuresnmpClient = None  # type: ignore[assignment]
    V2C = None  # type: ignore[assignment]
    ObjectIdentifier = None  # type: ignore[assignment]
    _PURESNMP_AVAILABLE = False


def _make_udp_sender(host: str, port: int):
    """Build a puresnmp-compatible UDP sender that bypasses the
    library's broken ``SNMPClientProtocol.datagram_received`` (puresnmp
    2.0.1 calls ``future.set_result`` without checking ``future.done()``,
    so a late-arriving datagram after a timeout raises
    ``asyncio.InvalidStateError`` — which kills the shorewalld asyncio
    loop on every retry/timeout interaction).

    Our replacement uses a blocking ``AF_INET/SOCK_DGRAM`` socket in a
    worker thread (``asyncio.to_thread``). One round-trip per call,
    no future state to mismanage.
    """
    async def send_udp_safe(
        endpoint,  # noqa: ARG001 (signature compat with send_udp)
        packet: bytes,
        timeout: int = 1,
        loop=None,  # noqa: ARG001
        retries: int = 1,
    ) -> bytes:
        def _blocking_round_trip(left: int) -> bytes:
            last_exc: Exception | None = None
            while left > 0:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.settimeout(timeout)
                    sock.sendto(packet, (host, port))
                    data, _ = sock.recvfrom(65535)
                    return data
                except (TimeoutError, OSError) as exc:
                    last_exc = exc
                    left -= 1
                finally:
                    sock.close()
            raise last_exc or TimeoutError(
                "udp round-trip exhausted retries")

        return await asyncio.to_thread(_blocking_round_trip, retries)

    return send_udp_safe


def _make_unix_stream_sender(socket_path: str):
    """Build a puresnmp sender bound to ``socket_path`` (Unix STREAM).

    net-snmp's ``agentaddress unix:<path>`` creates a ``SOCK_STREAM``
    listener (verified via ``ss -lx``). For each request we connect,
    send the BER-encoded SNMP message in a single ``sendall``, then
    read the reply until we've consumed a complete BER SEQUENCE
    (``0x30 + length + body``). One PDU per connection — snmpd does
    not pipeline replies on AF_UNIX/STREAM.

    puresnmp's :class:`Client` validates ``ip`` as IPv4/IPv6 — we
    can't smuggle a Unix path through ``Endpoint``. The path lives in
    this closure; ``endpoint.ip`` is ignored. Blocking socket I/O is
    hopped to :func:`asyncio.to_thread` so the event loop stays
    responsive.
    """
    async def send_unix_stream(
        endpoint,  # noqa: ARG001  (signature compat with send_udp)
        packet: bytes,
        timeout: int = 1,
        loop=None,  # noqa: ARG001
        retries: int = 1,
    ) -> bytes:
        def _blocking_round_trip(left: int) -> bytes:
            last_exc: Exception | None = None
            while left > 0:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.settimeout(timeout)
                    sock.connect(socket_path)
                    sock.sendall(packet)
                    return _read_ber_sequence(sock)
                except (TimeoutError, OSError, ValueError) as exc:
                    last_exc = exc
                    left -= 1
                finally:
                    sock.close()
            raise last_exc or TimeoutError(
                "unix stream round-trip exhausted retries")

        return await asyncio.to_thread(_blocking_round_trip, retries)

    return send_unix_stream


def _read_ber_sequence(sock) -> bytes:
    """Read exactly one BER SEQUENCE (0x30) from a connected stream socket.

    BER tag-length-value: first byte is the tag, next is the length
    (short form < 0x80 → that byte is the length; long form ≥ 0x80 →
    low 7 bits give the count of length-bytes that follow). Once the
    length is decoded, read the body in one or more ``recv`` calls.
    """
    head = _recv_exactly(sock, 2)
    if head[0] != 0x30:
        raise ValueError(f"unexpected BER tag 0x{head[0]:02x}, expected 0x30")
    length = head[1]
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or nbytes > 4:
            raise ValueError(f"invalid BER long-form length: {nbytes} bytes")
        ext = _recv_exactly(sock, nbytes)
        length = int.from_bytes(ext, "big")
        head = head + ext
    body = _recv_exactly(sock, length)
    return head + body


def _recv_exactly(sock, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*; raise on short close."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(
                f"unix stream peer closed after {n - remaining}/{n} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


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
    """Raised when ``puresnmp`` isn't installed.

    Distinguished from generic :class:`ImportError` so the control path
    can emit an actionable ``pip install puresnmp`` hint rather than a
    bare traceback. Declared unconditionally so consumers can reference
    it even when puresnmp is absent.
    """


class KeepalivedSnmpClient:
    """SNMPv2c client over a Unix socket (snmpd's ``agentaddress unix:...``).

    Transport selection:

    * ``unix_path`` set **and** the socket exists → ``AF_UNIX/SOCK_DGRAM``
      using :func:`send_unix_dgram` as the puresnmp sender.
    * ``unix_path`` set but the socket missing → fall back to UDP
      (``udp_host``:``udp_port``); keeps the daemon running while the
      operator fixes their snmpd.conf.
    * ``unix_path`` unset → UDP only.

    All wire methods are ``async`` (puresnmp is async-native — no
    :func:`asyncio.to_thread` bridge for SNMP round-trips).
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
        if not _PURESNMP_AVAILABLE:
            raise KeepalivedSnmpClientUnavailable(
                "puresnmp is not installed. "
                "Install with: pip install puresnmp"
            )
        self._timeout_s = timeout_s
        self._community = community

        if unix_path and os.path.exists(unix_path):
            # puresnmp's Client validates ip as IPv4/IPv6, so we can't
            # smuggle the Unix path via Endpoint.ip — the path lives in
            # the sender closure instead. ``ip``/``port`` here are dead
            # weight passed only to satisfy the constructor.
            self._client = _PuresnmpClient(
                ip="127.0.0.1",
                port=0,
                credentials=V2C(community),
                sender=_make_unix_stream_sender(unix_path),
            )
            self._peername = f"unix:{unix_path}"
        else:
            # Avoid puresnmp 2.0.1's default UDP transport — its
            # SNMPClientProtocol.datagram_received does not guard
            # ``future.set_result`` with a ``future.done()`` check, so a
            # late datagram after a timeout raises asyncio.InvalidStateError
            # which propagates out of the event loop and crashes the daemon.
            # Our own sender uses a blocking socket in to_thread; same
            # effect as upstream but no future-state mismanagement.
            self._client = _PuresnmpClient(
                ip=udp_host,
                port=udp_port,
                credentials=V2C(community),
                sender=_make_udp_sender(udp_host, udp_port),
            )
            self._peername = f"udp:{udp_host}:{udp_port}"

    @property
    def peername(self) -> str:
        """Return the formatted peer (``unix:<path>`` or ``udp:host:port``)."""
        return self._peername

    # ------------------------------------------------------------------
    # Async walk
    # ------------------------------------------------------------------
    async def walk(self, root_oid: str) -> list[SnmpVarbind]:
        """Walk the subtree below *root_oid*, return decoded varbinds.

        puresnmp's ``walk`` is an async generator yielding
        :class:`puresnmp.varbind.VarBind`. We materialise into a list
        and convert to library-neutral :class:`SnmpVarbind` records,
        splitting the column-OID off the row-index suffix so consumers
        keep the existing ``oid``/``index`` decomposition contract.
        """
        oid = ObjectIdentifier(root_oid)
        out: list[SnmpVarbind] = []
        async with asyncio.timeout(self._timeout_s + 1.0):
            async for vb in self._client.walk(oid):
                out.append(_convert_varbind(vb, root_oid))
        return out

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

            # Group varbinds by index suffix into rows. puresnmp delivers
            # vb.oid as the full OID (entry_oid + ".<col>.<row_index...>"),
            # vb.index is empty. We derive (col_num, row_key) by stripping
            # the entry_oid + "." prefix and splitting at the first dot —
            # the column number is one component, the rest is the row
            # index (which may itself contain dots, e.g. InetAddress).
            rows: dict[str, dict[str, str]] = {}
            for vb in varbinds:
                if not vb.oid.startswith(entry_oid + "."):
                    continue
                suffix = vb.oid[len(entry_oid) + 1:]
                parts = suffix.split(".", 1)
                try:
                    col_num = int(parts[0])
                except ValueError:
                    continue
                col_info = columns.get(col_num)
                if col_info is None:
                    continue
                col_name, _col_syntax, _col_access = col_info
                row_key = parts[1] if len(parts) > 1 else ""
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



# ---------------------------------------------------------------------------
# puresnmp VarBind → library-neutral SnmpVarbind conversion
# ---------------------------------------------------------------------------


def _convert_varbind(vb, walked_root: str) -> SnmpVarbind:
    """Coerce a :class:`puresnmp.varbind.VarBind` into our :class:`SnmpVarbind`.

    puresnmp delivers ``vb.oid`` as a **full** OID (table-entry column
    + row index suffix) and ``vb.value`` as a typed X690 object
    (``OctetString``, ``Integer``, ``Counter``, ``Gauge``, …). We do
    *no* OID-splitting here — :meth:`walk_all` knows the entry-OID
    of the table being walked and handles col/row decomposition there
    via :func:`_resolve_col_num` plus a one-line suffix split. Keeping
    this converter MIB-agnostic means scalar walks (where there is no
    column/row split to do) work identically.

    Value stringification: bytes → UTF-8 (replace on invalid), ints →
    ``str()``. The caller uses the ``syntax`` field (puresnmp class
    name) to decide how to parse.
    """
    full_oid = str(vb.oid)
    if full_oid.startswith("."):
        full_oid = full_oid[1:]

    raw = vb.value
    raw_pyval = getattr(raw, "pythonize", lambda: raw)()
    if isinstance(raw_pyval, (bytes, bytearray)):
        value = raw_pyval.decode("utf-8", "replace")
    elif raw_pyval is None:
        value = ""
    else:
        value = str(raw_pyval)
    syntax = type(raw).__name__

    return SnmpVarbind(
        oid=full_oid, index="", value=value, syntax=syntax,
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
