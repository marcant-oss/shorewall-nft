"""Parent-side subsystem for NFLOG events received from per-netns workers.

Sits at the ``MAGIC_NFLOG`` end of the worker → parent IPC channel
(see :mod:`shorewalld.log_codec`). Receives one :class:`LogEvent` per
NFLOG frame observed in any managed netns, maintains the
Prometheus-labelled counter ``shorewall_log_total``, and fans out to
up to four optional external sinks:

1. **file** — append-only plain-text log at ``log_dispatch_file``.
2. **unix socket** — newline-JSON broadcast to any client connected
   to ``log_dispatch_socket`` (multi-subscriber; slow clients dropped).
3. **journald** — structured entries into ``/run/systemd/journal/socket``
   (if ``log_dispatch_journald`` is set).
4. **syslog** — RFC 3164 datagrams to ``log_dispatch_syslog``
   (typically ``/dev/log``).

Backpressure contract (user directive 2026-04-24)
-------------------------------------------------
**Every sink is drop-on-full, never block.** The :meth:`on_event`
hot path is invoked synchronously from ``ParentWorker._drain_replies``
on the asyncio event-loop thread — it MUST NOT block. Every sink is
therefore fed via a bounded :class:`asyncio.Queue`; ``put_nowait`` on
:class:`asyncio.QueueFull` increments the sink's
``shorewall_log_dropped_total{reason=...}`` counter and drops the event.

This contract is maintained all the way down:

* The **worker side** (``nft_worker._worker_main_loop_with_nflog``)
  uses ``transport.send_nowait`` for NFLOG push datagrams — a full
  parent SEQPACKET buffer drops events at the worker instead of
  stalling, so batch + read RPCs stay hot.
* The **dispatcher on_event** is lock-free and allocation-free in the
  counter-only path (GIL-atomic ``dict[k] = dict.get(k, 0) + 1``).
* **Per-sink queues** cap at :data:`SINK_QUEUE_DEPTH` entries.
* **External sinks** (file/journald/syslog) use non-blocking writes;
  kernel EAGAIN drops at the sink, unix-socket clients that don't
  drain are disconnected.

A slow sink consumer NEVER back-pressures the counter, another sink,
or the upstream worker. All drops are visible as Prometheus counters.

Threading / event-loop contract
-------------------------------
:meth:`on_event` is called synchronously from
``ParentWorker._drain_replies`` via ``add_reader`` — i.e. on the
asyncio event-loop thread. ``queue.put_nowait`` is sync and thread-
agnostic. Sink consumer tasks run on the same event loop.

The scrape thread calls :meth:`snapshot` / :meth:`snapshot_dropped` /
``events_total`` via :class:`LogCollector`; these read the backing
dicts with ``dict.copy()`` which is a single GIL-atomic C call.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from dataclasses import dataclass
from typing import Any

from .log_prefix import LogEvent
from .logsetup import get_logger

log = get_logger("log_dispatcher")

# Public types.
_LabelKey = tuple[str, str, str]  # (chain, disposition, netns)

# Per-sink queue depth. 1024 events ≈ ~30 KiB of encoded payload at
# typical sizes — small enough to not hide a prolonged stall, large
# enough that a ~50 ms GC pause doesn't drop events in a quiet
# firewall.
SINK_QUEUE_DEPTH = 1024

# Connected-client queue for the unix-socket fan-out. Smaller than the
# dispatcher's own queue: if a client is slow enough to fill this,
# they get disconnected rather than making the broadcaster drag the
# dispatcher's queue.
CLIENT_QUEUE_DEPTH = 256

# syslog facility + severity. We pick LOCAL0 (16) to keep it out of
# the generic "user" facility, matching shorewall's traditional
# output. Severity maps from disposition: DROP/REJECT = WARNING,
# ACCEPT/LOG/CONTINUE = INFO, else NOTICE.
_SYSLOG_FACILITY_LOCAL0 = 16
_SYSLOG_SEVERITY_INFO = 6
_SYSLOG_SEVERITY_NOTICE = 5
_SYSLOG_SEVERITY_WARNING = 4

_JOURNAL_PRIORITY_WARNING = "4"
_JOURNAL_PRIORITY_NOTICE = "5"
_JOURNAL_PRIORITY_INFO = "6"


def _severity_for(disposition: str) -> int:
    d = disposition.upper()
    if d in ("DROP", "REJECT", "BLACKLIST", "A_DROP", "A_REJECT"):
        return _SYSLOG_SEVERITY_WARNING
    if d in ("ACCEPT", "LOG", "CONTINUE", "A_ACCEPT", "NFLOG"):
        return _SYSLOG_SEVERITY_INFO
    return _SYSLOG_SEVERITY_NOTICE


def _journal_priority_for(disposition: str) -> str:
    d = disposition.upper()
    if d in ("DROP", "REJECT", "BLACKLIST", "A_DROP", "A_REJECT"):
        return _JOURNAL_PRIORITY_WARNING
    if d in ("ACCEPT", "LOG", "CONTINUE", "A_ACCEPT", "NFLOG"):
        return _JOURNAL_PRIORITY_INFO
    return _JOURNAL_PRIORITY_NOTICE


def _rfc3339(ns: int) -> str:
    """Format a nanosecond timestamp as RFC 3339 UTC with millis.

    ``ns == 0`` → use the current wall-clock. Wall-clock fallback lets
    operators still get a timestamp if the kernel did not attach
    NFULA_TIMESTAMP to the NFLOG frame.
    """
    if ns == 0:
        t = time.time()
    else:
        t = ns / 1_000_000_000
    # ``time.strftime`` is faster than ``datetime`` + doesn't allocate
    # a timezone object per call; we pay for formatting only when the
    # file or socket sink is enabled.
    secs = int(t)
    msec = int((t - secs) * 1000)
    return time.strftime(
        f"%Y-%m-%dT%H:%M:%S.{msec:03d}Z", time.gmtime(secs))


# ---------------------------------------------------------------------------
# Event-formatting helpers (pure; one allocation per format)
# ---------------------------------------------------------------------------


_PROTO_NAME = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6"}


def _format_packet_suffix(ev: LogEvent) -> str:
    """Render the optional 5-tuple + iface suffix for plain-text sinks."""
    if not ev.packet_family:
        return ""
    proto = _PROTO_NAME.get(ev.packet_proto, str(ev.packet_proto) if ev.packet_proto else "?")
    parts: list[str] = []
    if ev.indev:
        parts.append(f"in={ev.indev}")
    if ev.outdev:
        parts.append(f"out={ev.outdev}")
    parts.append(f"proto={proto}")
    if ev.packet_saddr:
        if ev.packet_sport:
            parts.append(f"src={ev.packet_saddr}:{ev.packet_sport}")
        else:
            parts.append(f"src={ev.packet_saddr}")
    if ev.packet_daddr:
        if ev.packet_dport:
            parts.append(f"dst={ev.packet_daddr}:{ev.packet_dport}")
        else:
            parts.append(f"dst={ev.packet_daddr}")
    if ev.packet_len:
        parts.append(f"len={ev.packet_len}")
    return " " + " ".join(parts)


def _format_plain_line(ev: LogEvent) -> bytes:
    """Build the file-sink line. ASCII, newline-terminated."""
    ts = _rfc3339(ev.timestamp_ns)
    rule_part = f" rule={ev.rule_num}" if ev.rule_num is not None else ""
    return (
        f"{ts} netns={ev.netns or '-'} chain={ev.chain} "
        f"disposition={ev.disposition}{rule_part}{_format_packet_suffix(ev)}\n"
    ).encode("ascii", "replace")


def _format_json_line(ev: LogEvent) -> bytes:
    """Build the unix-socket-sink JSON line. UTF-8, newline-terminated.

    Schema is deliberately minimal (MVP). Operator-facing doc
    (``docs/cli/shorewall.conf.md``, M7) pins ``schema_version=1``;
    field additions are always safe, field removals/renames bump the
    major.
    """
    payload: dict[str, Any] = {
        "schema_version": 1,
        "ts": _rfc3339(ev.timestamp_ns),
        "netns": ev.netns,
        "chain": ev.chain,
        "disposition": ev.disposition,
    }
    if ev.rule_num is not None:
        payload["rule_num"] = ev.rule_num
    # ``separators`` drops whitespace → compact line. ``ensure_ascii=False``
    # lets chain names with exotic characters round-trip correctly; the
    # prefix parser already enforces ASCII, so this is insurance.
    return (
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _format_journal_datagram(ev: LogEvent) -> bytes:
    """Build a systemd-journald native datagram.

    Format: simple short-form ``KEY=value\\n`` for lines without
    newlines. Journald's native wire requires all-lowercase binary
    fields or mixed-case uppercase text fields; we use the standard
    ``MESSAGE=``, ``PRIORITY=``, ``SYSLOG_IDENTIFIER=`` plus custom
    ``SHOREWALL_*`` fields.

    The MESSAGE line embeds the 5-tuple inline so ``journalctl`` users
    see context without needing to enable verbose-output mode; the
    structured ``SHOREWALL_*`` fields stay separate for filtering.
    """
    lines = [
        f"MESSAGE=shorewall {ev.chain} {ev.disposition} "
        f"netns={ev.netns or '-'}{_format_packet_suffix(ev)}",
        f"PRIORITY={_journal_priority_for(ev.disposition)}",
        "SYSLOG_IDENTIFIER=shorewalld",
        f"SHOREWALL_CHAIN={ev.chain}",
        f"SHOREWALL_DISPOSITION={ev.disposition}",
        f"SHOREWALL_NETNS={ev.netns}",
    ]
    if ev.rule_num is not None:
        lines.append(f"SHOREWALL_RULE_NUM={ev.rule_num}")
    if ev.timestamp_ns:
        lines.append(f"SHOREWALL_NFLOG_TS={ev.timestamp_ns}")
    if ev.packet_family:
        lines.append(f"SHOREWALL_PROTO={_PROTO_NAME.get(ev.packet_proto, str(ev.packet_proto))}")
        if ev.packet_saddr:
            lines.append(f"SHOREWALL_SADDR={ev.packet_saddr}")
        if ev.packet_daddr:
            lines.append(f"SHOREWALL_DADDR={ev.packet_daddr}")
        if ev.packet_sport:
            lines.append(f"SHOREWALL_SPORT={ev.packet_sport}")
        if ev.packet_dport:
            lines.append(f"SHOREWALL_DPORT={ev.packet_dport}")
        if ev.packet_len:
            lines.append(f"SHOREWALL_PKT_LEN={ev.packet_len}")
    if ev.indev:
        lines.append(f"SHOREWALL_INDEV={ev.indev}")
    if ev.outdev:
        lines.append(f"SHOREWALL_OUTDEV={ev.outdev}")
    # Trailing newline required by journald.
    return ("\n".join(lines) + "\n").encode("utf-8")


def _format_syslog_datagram(ev: LogEvent, pid: int) -> bytes:
    """Build a RFC 3164 syslog datagram — ``<PRI>MSG`` shape.

    We skip the RFC 3164 TIMESTAMP HOSTNAME preamble (local syslog
    daemons re-stamp both), and send just the tag + structured-ish
    fields. rsyslog / syslog-ng / journald-forwarded all tolerate this.
    """
    pri = (_SYSLOG_FACILITY_LOCAL0 << 3) | _severity_for(ev.disposition)
    rule_part = f" rule={ev.rule_num}" if ev.rule_num is not None else ""
    msg = (
        f"<{pri}>shorewalld[{pid}]: netns={ev.netns or '-'} "
        f"chain={ev.chain} disposition={ev.disposition}{rule_part}"
    )
    return msg.encode("ascii", "replace")


# ---------------------------------------------------------------------------
# Sink implementations
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _SinkStats:
    """Per-sink counter snapshot — updated in place."""
    enqueued: int = 0
    written: int = 0
    dropped: int = 0    # QueueFull on enqueue OR write error on flush


class _FileSink:
    """Append-only plain-text log file.

    Opened with ``O_APPEND|O_CREAT|O_CLOEXEC|O_NONBLOCK``. Writes run
    synchronously on the event loop (``os.write`` is typically <100 µs
    for a block-aligned 128-byte append on ext4). On EAGAIN (rare
    — only if the backing store is a FIFO or a very slow network
    filesystem) the event is dropped and the counter incremented.
    """

    __slots__ = ("_path", "_fd", "_queue", "_task", "stats")

    def __init__(self, path: str) -> None:
        self._path = path
        self._fd = -1
        self._queue: asyncio.Queue[LogEvent] = asyncio.Queue(
            maxsize=SINK_QUEUE_DEPTH)
        self._task: asyncio.Task[None] | None = None
        self.stats = _SinkStats()

    async def start(self) -> None:
        self._fd = os.open(
            self._path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT
            | os.O_CLOEXEC | os.O_NONBLOCK,
            0o640,
        )
        self._task = asyncio.create_task(
            self._loop(), name="shorewalld.log.file")

    def enqueue(self, ev: LogEvent) -> bool:
        try:
            self._queue.put_nowait(ev)
        except asyncio.QueueFull:
            self.stats.dropped += 1
            return False
        self.stats.enqueued += 1
        return True

    async def _loop(self) -> None:
        while True:
            ev = await self._queue.get()
            line = _format_plain_line(ev)
            try:
                os.write(self._fd, line)
                self.stats.written += 1
            except BlockingIOError:
                self.stats.dropped += 1
            except OSError as e:
                self.stats.dropped += 1
                log.warning("log-dispatcher file sink write error: %s", e)

    async def shutdown(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1


class _DgramSink:
    """Shared implementation for journald + syslog (both UNIX DGRAM).

    Opens a connected ``AF_UNIX``/``SOCK_DGRAM`` socket to the given
    path, sends datagrams with ``MSG_DONTWAIT``. On EAGAIN or any
    other OSError the event is dropped + counted — never retried,
    never throttled.
    """

    __slots__ = ("_path", "_formatter", "_reason", "_sock",
                 "_queue", "_task", "stats")

    def __init__(self, path: str, formatter, reason: str) -> None:
        self._path = path
        self._formatter = formatter
        self._reason = reason
        self._sock: socket.socket | None = None
        self._queue: asyncio.Queue[LogEvent] = asyncio.Queue(
            maxsize=SINK_QUEUE_DEPTH)
        self._task: asyncio.Task[None] | None = None
        self.stats = _SinkStats()

    async def start(self) -> None:
        s = socket.socket(
            socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
        # SOCK_DGRAM connect == default destination; subsequent sends
        # use that without a sockaddr arg.
        s.connect(self._path)
        s.setblocking(False)
        self._sock = s
        self._task = asyncio.create_task(
            self._loop(), name=f"shorewalld.log.{self._reason}")

    def enqueue(self, ev: LogEvent) -> bool:
        try:
            self._queue.put_nowait(ev)
        except asyncio.QueueFull:
            self.stats.dropped += 1
            return False
        self.stats.enqueued += 1
        return True

    async def _loop(self) -> None:
        assert self._sock is not None
        while True:
            ev = await self._queue.get()
            datagram = self._formatter(ev)
            try:
                self._sock.send(datagram)
                self.stats.written += 1
            except BlockingIOError:
                # Receiver buffer full — drop, don't retry.
                self.stats.dropped += 1
            except OSError as e:
                self.stats.dropped += 1
                log.warning(
                    "log-dispatcher %s sink write error: %s",
                    self._reason, e)

    async def shutdown(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


class _UnixSocketSink:
    """Fan-out unix-socket server — any number of subscribers.

    Clients connect to the socket; every ``enqueue``'d event is
    broadcast to every connected client. Each client has its own
    small bounded queue; slow clients are silently disconnected
    (and counted under the ``reason="sink_socket_client_slow"`` label
    if we ever split the drop reason — current MVP lumps all
    socket-sink drops under ``sink_socket``).
    """

    __slots__ = ("_path", "_server", "_clients", "_queue",
                 "_broadcast_task", "stats")

    def __init__(self, path: str) -> None:
        self._path = path
        self._server: asyncio.base_events.Server | None = None
        # Clients: write queue + writer pair.
        self._clients: list[
            tuple[asyncio.Queue[bytes], asyncio.StreamWriter]
        ] = []
        self._queue: asyncio.Queue[LogEvent] = asyncio.Queue(
            maxsize=SINK_QUEUE_DEPTH)
        self._broadcast_task: asyncio.Task[None] | None = None
        self.stats = _SinkStats()

    async def start(self) -> None:
        # Unlink stale socket if present (from a previous run that
        # didn't shut down cleanly).
        try:
            os.unlink(self._path)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self._path)
        os.chmod(self._path, 0o660)
        self._broadcast_task = asyncio.create_task(
            self._broadcast_loop(), name="shorewalld.log.socket")

    def enqueue(self, ev: LogEvent) -> bool:
        try:
            self._queue.put_nowait(ev)
        except asyncio.QueueFull:
            self.stats.dropped += 1
            return False
        self.stats.enqueued += 1
        return True

    async def _handle_client(
        self,
        _reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=CLIENT_QUEUE_DEPTH)
        self._clients.append((q, writer))
        try:
            while True:
                line = await q.get()
                writer.write(line)
                try:
                    await writer.drain()
                except ConnectionError:
                    return
        except asyncio.CancelledError:
            return
        finally:
            # Remove from registry.
            for i, (cq, cw) in enumerate(self._clients):
                if cw is writer:
                    del self._clients[i]
                    break
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _broadcast_loop(self) -> None:
        while True:
            ev = await self._queue.get()
            line = _format_json_line(ev)
            # Snapshot the client list — concurrent connects / slow-
            # client disconnects should not dereference a stale index.
            for q, writer in list(self._clients):
                try:
                    q.put_nowait(line)
                except asyncio.QueueFull:
                    # Slow client: drop this event AND close the client
                    # to free the server from having to carry it.
                    self.stats.dropped += 1
                    try:
                        writer.close()
                    except Exception:  # noqa: BLE001
                        pass
            self.stats.written += 1

    async def shutdown(self) -> None:
        if self._broadcast_task is not None:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._broadcast_task = None
        # Close every client writer.
        for _q, writer in list(self._clients):
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
        self._clients.clear()
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._server = None
        try:
            os.unlink(self._path)
        except FileNotFoundError:
            pass
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class LogDispatcher:
    """Per-daemon NFLOG event collator.

    One instance per :class:`~shorewalld.core.Daemon`. Multiplexes
    events from every managed netns (each worker stamps its own netns
    label at the IPC decode).

    Lifecycle::

        dispatcher = LogDispatcher(
            drop_file="/var/log/shorewall-nft.log",
            drop_socket_path="/run/shorewalld/log.sock",
            journald=True,
            syslog_path="/dev/log",
        )
        await dispatcher.start()
        router.attach_log_dispatcher(dispatcher)
        ...
        await dispatcher.shutdown()
    """

    __slots__ = (
        "_counters", "_dropped", "_events_total", "_started",
        "_file_sink", "_socket_sink", "_journal_sink", "_syslog_sink",
    )

    def __init__(
        self,
        *,
        drop_file: str | None = None,
        drop_socket_path: str | None = None,
        journald: bool = False,
        syslog_path: str | None = None,
    ) -> None:
        self._counters: dict[_LabelKey, int] = {}
        self._events_total: int = 0
        self._dropped: dict[str, int] = {}
        self._started = False

        self._file_sink = _FileSink(drop_file) if drop_file else None
        self._socket_sink = (
            _UnixSocketSink(drop_socket_path) if drop_socket_path else None)
        self._journal_sink: _DgramSink | None = None
        if journald:
            self._journal_sink = _DgramSink(
                "/run/systemd/journal/socket",
                _format_journal_datagram,
                "journald",
            )
        self._syslog_sink: _DgramSink | None = None
        if syslog_path:
            pid = os.getpid()
            self._syslog_sink = _DgramSink(
                syslog_path,
                lambda ev: _format_syslog_datagram(ev, pid),
                "syslog",
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Open all enabled sinks. Failures degrade gracefully.

        If a sink fails to open (e.g. /dev/log missing on a non-systemd
        container, or the parent dir of a log file doesn't exist), we
        log the error and continue with that sink disabled rather than
        aborting daemon startup. The operator sees the warning; other
        sinks + the Prom counter keep working.
        """
        self._started = True
        for name, sink in self._iter_enabled_sinks():
            try:
                await sink.start()
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "log dispatcher: %s sink disabled (start failed: %s)",
                    name, e)
                self._disable_sink(name)

    async def shutdown(self) -> None:
        for _name, sink in self._iter_enabled_sinks():
            try:
                await sink.shutdown()
            except Exception:  # noqa: BLE001
                log.exception("log dispatcher: sink shutdown raised")
        self._started = False

    def _iter_enabled_sinks(self):
        if self._file_sink is not None:
            yield "file", self._file_sink
        if self._socket_sink is not None:
            yield "socket", self._socket_sink
        if self._journal_sink is not None:
            yield "journald", self._journal_sink
        if self._syslog_sink is not None:
            yield "syslog", self._syslog_sink

    def _disable_sink(self, name: str) -> None:
        if name == "file":
            self._file_sink = None
        elif name == "socket":
            self._socket_sink = None
        elif name == "journald":
            self._journal_sink = None
        elif name == "syslog":
            self._syslog_sink = None

    # ------------------------------------------------------------------
    # Worker → dispatcher callback (sync, on the asyncio thread)
    # ------------------------------------------------------------------
    def on_event(self, ev: LogEvent, netns: str) -> None:
        """Record an event. Cheap — called once per NFLOG frame.

        Called synchronously from ``ParentWorker._drain_replies``
        (an ``add_reader`` callback) — i.e. we are already on the
        event-loop thread. All sink queue operations are
        ``put_nowait`` so this method never awaits and never blocks.

        *netns* is stamped from the worker's label
        (``ParentWorker.netns``); ``ev.netns`` from the wire is
        ignored so the collector label matches operator config.
        """
        # Re-stamp netns — the wire field may be empty or stale.
        if ev.netns != netns:
            ev = LogEvent(
                chain=ev.chain,
                disposition=ev.disposition,
                rule_num=ev.rule_num,
                timestamp_ns=ev.timestamp_ns,
                netns=netns,
            )
        key: _LabelKey = (ev.chain, ev.disposition, netns)
        self._counters[key] = self._counters.get(key, 0) + 1
        self._events_total += 1

        # Fan out to every enabled sink via non-blocking enqueue.
        # Sink-local drop counters live on each sink's ``.stats``;
        # see snapshot_dropped() for the aggregated Prometheus view.
        if self._file_sink is not None:
            self._file_sink.enqueue(ev)
        if self._socket_sink is not None:
            self._socket_sink.enqueue(ev)
        if self._journal_sink is not None:
            self._journal_sink.enqueue(ev)
        if self._syslog_sink is not None:
            self._syslog_sink.enqueue(ev)

    # ------------------------------------------------------------------
    # Collector-facing accessors (sync; from any thread)
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[_LabelKey, int]:
        """Point-in-time copy of the labelled counter dict."""
        return self._counters.copy()

    def snapshot_dropped(self) -> dict[str, int]:
        """Per-sink drop snapshot, keyed on ``reason`` label value.

        ``"queue_full"`` drops (where :meth:`on_event` bumped a
        counter because a sink's queue was full at ``put_nowait``)
        are lumped per-sink-kind; write-time drops (the sink's
        own ``.stats.dropped`` counter past the queue) are merged in.
        The Prometheus surface does not distinguish between enqueue
        vs dequeue drop — from the operator's perspective both mean
        "this sink couldn't keep up".
        """
        out: dict[str, int] = dict(self._dropped)
        for name, sink in self._iter_enabled_sinks():
            out[f"sink_{name}"] = sink.stats.dropped
        return out

    @property
    def events_total(self) -> int:
        return self._events_total
