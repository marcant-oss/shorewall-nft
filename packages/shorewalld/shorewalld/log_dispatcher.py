"""Parent-side subsystem for NFLOG events received from per-netns workers.

Sits at the ``MAGIC_NFLOG`` end of the worker → parent IPC channel
(see :mod:`shorewalld.log_codec`). Receives one :class:`LogEvent` per
NFLOG frame that the worker observed in its netns, maintains a
Prometheus-labelled counter dict keyed on
``(chain, disposition, netns)``, and (in Commit 3 / M5) fans out to the
optional plain-file and unix-socket sinks.

Threading / event-loop contract
-------------------------------
:meth:`on_event` is called synchronously from ``ParentWorker._drain_replies``
which itself runs on the asyncio event-loop thread via ``add_reader``.
We therefore treat the counter bump as a plain dict mutation with
GIL-atomic ``dict[key] = dict.get(key, 0) + 1`` — no lock, no async
handoff. This is the same fast-path shape as
:class:`shorewalld._ingress_metrics._IngressMetricsBase`; the only
difference is that log counters are labelled (tuple key) rather than
flat (string key), so we cannot reuse the base as-is.

Sinks (file + unix socket, M5) get their own bounded
:class:`asyncio.Queue` so the counter stays hot even when an external
consumer is slow; in this commit the sink slot is a placeholder and
``shorewall_log_dropped_total{reason=...}`` is always zero.
"""

from __future__ import annotations

from .log_prefix import LogEvent
from .logsetup import get_logger

log = get_logger("log_dispatcher")

_LabelKey = tuple[str, str, str]  # (chain, disposition, netns)


class LogDispatcher:
    """Per-daemon NFLOG event collator.

    One instance per :class:`~shorewalld.core.Daemon` — it multiplexes
    events from every managed netns (each worker delivers events with
    the worker's own netns label stamped on the decoded
    :class:`LogEvent`).

    Lifecycle:
        ``dispatcher = LogDispatcher()``
        ``router.attach_log_dispatcher(dispatcher)``
        ...
        ``await dispatcher.shutdown()``   # at daemon teardown

    :meth:`start` is a no-op in this commit (the counter path needs no
    background task); M5 adds the sink fan-out task.
    """

    __slots__ = ("_counters", "_dropped", "_events_total", "_started")

    def __init__(self) -> None:
        self._counters: dict[_LabelKey, int] = {}
        # One total-events counter so operators can see the dispatcher
        # is receiving, even before they've configured any specific
        # (chain, disposition) rule. Bumped once per on_event call
        # regardless of label cardinality.
        self._events_total: int = 0
        # Per-reason drop counter. Reasons added in M5 when sinks land
        # ("sink_file", "sink_socket"); "queue_full" is reserved for
        # when we add the async consumer queue.
        self._dropped: dict[str, int] = {}
        self._started = False

    async def start(self) -> None:
        """Lifecycle hook. No-op in Commit 2 — M5 wires sinks here."""
        self._started = True

    async def shutdown(self) -> None:
        """Lifecycle hook. No-op in Commit 2 — M5 drains sinks here."""
        self._started = False

    # ------------------------------------------------------------------
    # Worker → dispatcher callback (sync, on the asyncio thread)
    # ------------------------------------------------------------------
    def on_event(self, ev: LogEvent, netns: str) -> None:
        """Record an event. Must be cheap — called once per NFLOG frame.

        This is called synchronously from ``ParentWorker._drain_replies``
        (itself an ``add_reader`` callback) — i.e. we are already on the
        event-loop thread, no thread-hop and no lock needed.

        *netns* is stamped from the worker's own label (``ParentWorker.netns``);
        the :class:`LogEvent`'s own ``netns`` field is ignored here so
        the collector's label is always the operator-configured netns
        name, not whatever the worker might have cached.
        """
        key: _LabelKey = (ev.chain, ev.disposition, netns)
        # dict[k] = dict.get(k, 0) + 1 — two GIL-atomic dict ops, no
        # allocation in steady state (Python interns small integers).
        self._counters[key] = self._counters.get(key, 0) + 1
        self._events_total += 1

    # ------------------------------------------------------------------
    # Collector-facing accessors (sync; called from the scrape thread)
    # ------------------------------------------------------------------
    def snapshot(self) -> dict[_LabelKey, int]:
        """Return a point-in-time copy of the counter dict.

        Callers must treat the result as read-only. ``dict.copy()`` is
        a single C call and GIL-safe — no lock needed even though the
        scrape thread ≠ the event-loop thread.
        """
        return self._counters.copy()

    def snapshot_dropped(self) -> dict[str, int]:
        """Per-reason drop counter snapshot (zero-filled until M5)."""
        return self._dropped.copy()

    @property
    def events_total(self) -> int:
        """Total events received by the dispatcher since start.

        Independent of label cardinality — even if every event went to
        a new ``(chain, disposition)`` pair, this monotonic counter
        would keep climbing at the same rate as the NFLOG frames.
        """
        return self._events_total
