"""Parent-side keepalived SNMP dispatcher.

Owns a periodic MIB-walk loop (default every 30 s) and atomically
publishes the result as a :class:`KeepalivedSnapshot`.  The snapshot
is readable at any time from the scrape thread via :meth:`snapshot`.

Commit 2 ships the walk loop + wide-table cardinality guard.
Commit 3 (P4+P5) adds:

- :meth:`on_trap_event` — ingress from the Unix-DGRAM trap listener.
- :meth:`on_dbus_event` — ingress from the async D-Bus client.
- :meth:`on_trap_decode_error` — frame dropped by the trap listener.
- :meth:`recent_events` — bounded ring of recent trap + D-Bus events.
- Per-event-type counters in :attr:`events_total`.

Threading model
---------------
The walk loop runs as an asyncio :class:`asyncio.Task`.  ``snapshot``
is a plain synchronous method — the scrape thread reads the *reference*
to the last snapshot, which is an atomic Python object swap (GIL-safe).
No mutex needed for reads; the dispatcher holds an ``asyncio.Lock``
only around the swap itself to avoid partial writes from concurrent
walkers (there is only one, but the lock makes the invariant explicit).

Event ingress methods (:meth:`on_trap_event`, :meth:`on_dbus_event`,
:meth:`on_trap_decode_error`) are synchronous and non-blocking — they
perform only GIL-safe counter increments and a :meth:`deque.appendleft`
(O(1)).  They may be called from the asyncio event-loop thread (trap
listener recv loop, D-Bus signal handlers) without holding any lock.
"""

from __future__ import annotations

import asyncio
import collections
import time
from typing import TYPE_CHECKING, Any

from shorewalld.keepalived.snmp_client import KeepalivedSnapshot

if TYPE_CHECKING:
    from shorewalld.keepalived.dbus_client import KeepalivedDbusEvent
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    from shorewalld.keepalived.trap_listener import KeepalivedTrapEvent

# Tables with >= 30 columns that default off when enable_wide_tables=False.
# vrrpInstanceTable is also large (36 cols) but is the core MVP table —
# it is always included regardless of this guard.
WIDE_TABLES: frozenset[str] = frozenset({
    "vrrpRouteTable",
    "virtualServerTable",
    "vrrpRuleTable",
})

# Maximum number of events retained in the recent-events ring buffer.
_RECENT_EVENTS_MAX = 256


class KeepalivedDispatcher:
    """Periodic MIB-walk loop with atomic snapshot publish.

    Parameters
    ----------
    client:
        A :class:`~shorewalld.keepalived.snmp_client.KeepalivedSnmpClient`
        instance — or any object that exposes an async ``walk_all()``
        returning a :class:`KeepalivedSnapshot`.
    walk_interval_s:
        Seconds between successive full MIB walks.  Default 30.
    enable_wide_tables:
        When *False* (default), :data:`WIDE_TABLES` rows are cleared
        from the snapshot before publish to cap Prometheus cardinality.
        Operator sets ``KEEPALIVED_WIDE_TABLES=yes`` (wired in Commit 4)
        to enable them.
    """

    def __init__(
        self,
        *,
        client: "KeepalivedSnmpClient",
        walk_interval_s: float = 30.0,
        enable_wide_tables: bool = False,
    ) -> None:
        self._client = client
        self._walk_interval_s = walk_interval_s
        self._enable_wide_tables = enable_wide_tables

        self._snapshot: KeepalivedSnapshot | None = None
        self._snapshot_lock = asyncio.Lock()

        # Walk counters — keys are fixed; callers read via snapshot_counters().
        self._counters: dict[str, int] = {"walk_ok": 0, "walk_error": 0}
        self._last_walk_duration_s: float | None = None

        # Per-event-type counters exposed as shorewalld_keepalived_events_total.
        # Keys are added lazily on first event of that type.  GIL-safe +=1.
        self._events_total: dict[str, int] = {}

        # Bounded ring buffer of recent events for operator introspection.
        # appendleft is O(1); maxlen enforces the cap automatically.
        self._recent_events: collections.deque[Any] = collections.deque(
            maxlen=_RECENT_EVENTS_MAX,
        )

        self._walk_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn the periodic walk task.  First walk runs immediately."""
        self._walk_task = asyncio.create_task(
            self._walk_loop(), name="keepalived-snmp-walk",
        )

    async def stop(self) -> None:
        """Cancel the walk task and wait for it to finish."""
        if self._walk_task is None:
            return
        self._walk_task.cancel()
        try:
            await self._walk_task
        except asyncio.CancelledError:
            pass
        self._walk_task = None

    # ------------------------------------------------------------------
    # Snapshot access (safe from scrape thread)
    # ------------------------------------------------------------------

    def snapshot(self) -> KeepalivedSnapshot | None:
        """Return the last-good snapshot, or *None* before the first walk.

        GIL-safe: reading a Python object reference is atomic at the
        interpreter level — no explicit lock needed for the read side.
        """
        return self._snapshot

    # ------------------------------------------------------------------
    # Stats getters (scrape-thread safe, no lock needed)
    # ------------------------------------------------------------------

    def walks_total(self) -> int:
        """Total successful walks since the dispatcher was started."""
        return self._counters["walk_ok"]

    def walk_errors_total(self) -> int:
        """Total walks that raised an exception (not partial-walk errors)."""
        return self._counters["walk_error"]

    def last_walk_duration_s(self) -> float | None:
        """Wall-clock duration of the most recent walk, or *None*."""
        return self._last_walk_duration_s

    def snapshot_counters(self) -> dict[str, int]:
        """Shallow copy of the walk counters dict — safe for the scrape thread."""
        return self._counters.copy()

    def events_total(self) -> dict[str, int]:
        """Shallow copy of the per-event-type counters.

        Keys include ``"trap_total"``, ``"trap_decode_error"``,
        ``"trap_<name>"`` for each decoded trap name, ``"dbus_total"``,
        and ``"dbus_signal_<signal>"`` for each D-Bus signal.

        Safe to call from the scrape thread (dict.copy() is a single C call
        under the GIL).
        """
        return self._events_total.copy()

    def recent_events(self) -> tuple[Any, ...]:
        """Return a snapshot of the recent-events ring as a tuple.

        Contains up to :data:`_RECENT_EVENTS_MAX` entries, most recent first.
        Each entry is a :class:`~shorewalld.keepalived.trap_listener.KeepalivedTrapEvent`
        or a :class:`~shorewalld.keepalived.dbus_client.KeepalivedDbusEvent`.

        Safe to call from the scrape thread.
        """
        return tuple(self._recent_events)

    # ------------------------------------------------------------------
    # Event ingress (sync, non-blocking, O(1))
    # ------------------------------------------------------------------

    def on_trap_event(self, event: "KeepalivedTrapEvent") -> None:
        """Ingest a decoded SNMPv2c trap from the trap listener.

        Bumps counters and appends to the recent-events ring.
        Synchronous, non-blocking, allocation-bounded — safe to call from
        the asyncio event-loop thread.
        """
        self._bump_event("trap_total")
        self._bump_event(f"trap_{event.name}")
        self._recent_events.appendleft(event)

    def on_trap_decode_error(self) -> None:
        """Record one trap decode failure (malformed datagram).

        Called by the trap listener when :meth:`_decode_trap` raises.
        Bumps ``"trap_decode_error"`` in :meth:`events_total`.
        """
        self._bump_event("trap_decode_error")

    def on_dbus_event(self, event: "KeepalivedDbusEvent") -> None:
        """Ingest a keepalived D-Bus signal from the D-Bus client.

        Bumps counters and appends to the recent-events ring.
        Synchronous, non-blocking, allocation-bounded — safe to call from
        the asyncio event-loop thread.
        """
        self._bump_event("dbus_total")
        self._bump_event(f"dbus_signal_{event.signal}")
        self._recent_events.appendleft(event)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _bump_event(self, key: str) -> None:
        """Increment a counter in _events_total, initialising to 1 if new."""
        if key in self._events_total:
            self._events_total[key] += 1
        else:
            self._events_total[key] = 1

    # ------------------------------------------------------------------
    # Internal: walk loop
    # ------------------------------------------------------------------

    async def _walk_loop(self) -> None:
        """Run a MIB walk immediately, then repeat every walk_interval_s."""
        while True:
            await self._do_walk()
            await asyncio.sleep(self._walk_interval_s)

    async def _do_walk(self) -> None:
        """Execute one full walk and publish the result."""
        t0 = time.monotonic()
        try:
            snap = await self._client.walk_all()
        except Exception:  # noqa: BLE001
            self._counters["walk_error"] += 1
            self._last_walk_duration_s = time.monotonic() - t0
            return

        self._last_walk_duration_s = time.monotonic() - t0

        if not self._enable_wide_tables:
            snap = self._filter_snapshot_by_wide_tables(snap)

        async with self._snapshot_lock:
            self._snapshot = snap

        self._counters["walk_ok"] += 1

    @staticmethod
    def _filter_snapshot_by_wide_tables(
        snap: KeepalivedSnapshot,
    ) -> KeepalivedSnapshot:
        """Return a new snapshot with :data:`WIDE_TABLES` rows emptied.

        Uses ``dataclasses.replace`` semantics via a manual rebuild
        because :class:`KeepalivedSnapshot` is frozen.
        """
        if not any(name in snap.tables for name in WIDE_TABLES):
            return snap
        filtered = dict(snap.tables)
        for name in WIDE_TABLES:
            if name in filtered:
                filtered[name] = []
        return KeepalivedSnapshot(
            scalars=snap.scalars,
            tables=filtered,
            collected_at=snap.collected_at,
            walk_errors=snap.walk_errors,
        )
