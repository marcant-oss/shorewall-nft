"""Parent-side keepalived SNMP dispatcher.

Owns a periodic MIB-walk loop (default every 30 s) and atomically
publishes the result as a :class:`KeepalivedSnapshot`.  The snapshot
is readable at any time from the scrape thread via :meth:`snapshot`.

Commit 2 ships the walk loop + wide-table cardinality guard.
Trap reception and D-Bus method wrappers arrive in Commit 3 (P4+P5).

Threading model
---------------
The walk loop runs as an asyncio :class:`asyncio.Task`.  ``snapshot``
is a plain synchronous method — the scrape thread reads the *reference*
to the last snapshot, which is an atomic Python object swap (GIL-safe).
No mutex needed for reads; the dispatcher holds an ``asyncio.Lock``
only around the swap itself to avoid partial writes from concurrent
walkers (there is only one, but the lock makes the invariant explicit).
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from shorewalld.keepalived.snmp_client import KeepalivedSnapshot

if TYPE_CHECKING:
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient

# Tables with ≥ 30 columns that default off when enable_wide_tables=False.
# vrrpInstanceTable is also large (36 cols) but is the core MVP table —
# it is always included regardless of this guard.
WIDE_TABLES: frozenset[str] = frozenset({
    "vrrpRouteTable",
    "virtualServerTable",
    "vrrpRuleTable",
})


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

        # Counters — keys are fixed; callers read via snapshot_counters().
        self._counters: dict[str, int] = {"walk_ok": 0, "walk_error": 0}
        self._last_walk_duration_s: float | None = None

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
        """Shallow copy of the counters dict — safe for the scrape thread."""
        return self._counters.copy()

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
