"""Tests for KeepalivedDispatcher.

Uses a minimal stub client that returns a configurable KeepalivedSnapshot
(or raises).  No netsnmp, no live SNMP session.

asyncio_mode is set to 'strict' globally (pyproject.toml 1af6735).
"""

from __future__ import annotations

import asyncio
import time

import pytest

from shorewalld.keepalived.snmp_client import KeepalivedSnapshot


# ---------------------------------------------------------------------------
# Helpers: stub client
# ---------------------------------------------------------------------------


def _make_snapshot(
    scalars: dict | None = None,
    tables: dict | None = None,
    walk_errors: tuple = (),
) -> KeepalivedSnapshot:
    from shorewalld.keepalived import mib
    return KeepalivedSnapshot(
        scalars=scalars or {},
        tables=tables or {name: [] for name in mib.TABLES},
        collected_at=time.time(),
        walk_errors=walk_errors,
    )


class _StubClient:
    """Minimal async walk_all() stub for dispatcher tests."""

    def __init__(self, *, result: KeepalivedSnapshot | None = None,
                 raises: Exception | None = None) -> None:
        self._result = result
        self._raises = raises
        self.call_count = 0

    async def walk_all(self) -> KeepalivedSnapshot:
        self.call_count += 1
        if self._raises is not None:
            raise self._raises
        if self._result is not None:
            return self._result
        return _make_snapshot()

    def set_result(self, snap: KeepalivedSnapshot) -> None:
        self._result = snap
        self._raises = None

    def set_raises(self, exc: Exception) -> None:
        self._raises = exc
        self._result = None


# ---------------------------------------------------------------------------
# Test 1: snapshot() is None before start
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_snapshot_is_none_before_start():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher
    dispatcher = KeepalivedDispatcher(client=_StubClient())
    assert dispatcher.snapshot() is None


# ---------------------------------------------------------------------------
# Test 2: start() triggers immediate walk; snapshot() populated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_snapshot_populated_after_first_walk():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher
    snap = _make_snapshot(scalars={"version": "2.3.1"})
    client = _StubClient(result=snap)
    dispatcher = KeepalivedDispatcher(client=client, walk_interval_s=9999.0)

    await dispatcher.start()
    # Give the event loop one iteration to let the first walk complete.
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    result = dispatcher.snapshot()
    assert result is not None
    assert result.scalars.get("version") == "2.3.1"
    assert client.call_count >= 1

    await dispatcher.stop()


# ---------------------------------------------------------------------------
# Test 3: stop() cancels the task cleanly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_stop_cancels_task_cleanly():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher
    dispatcher = KeepalivedDispatcher(
        client=_StubClient(), walk_interval_s=9999.0,
    )
    await dispatcher.start()
    await asyncio.sleep(0)
    await dispatcher.stop()
    # After stop, the task is cleaned up.
    assert dispatcher._walk_task is None


# ---------------------------------------------------------------------------
# Test 4: walk errors bump walk_error counter; success bumps walk_ok
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_walk_error_counter():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

    client = _StubClient(raises=OSError("snmpd unreachable"))
    dispatcher = KeepalivedDispatcher(client=client, walk_interval_s=9999.0)

    await dispatcher.start()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await dispatcher.stop()

    assert dispatcher.walk_errors_total() >= 1
    assert dispatcher.walks_total() == 0
    # Snapshot remains None after failed walks.
    assert dispatcher.snapshot() is None


@pytest.mark.asyncio
async def test_dispatcher_walk_ok_counter():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

    client = _StubClient(result=_make_snapshot())
    dispatcher = KeepalivedDispatcher(client=client, walk_interval_s=9999.0)

    await dispatcher.start()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await dispatcher.stop()

    assert dispatcher.walks_total() >= 1
    assert dispatcher.walk_errors_total() == 0


# ---------------------------------------------------------------------------
# Test 5: enable_wide_tables=False empties the three gated tables
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_wide_tables_filtered_when_disabled():
    from shorewalld.keepalived import mib
    from shorewalld.keepalived.dispatcher import WIDE_TABLES, KeepalivedDispatcher

    # Build a snapshot that has one row in each WIDE_TABLE.
    tables = {name: [] for name in mib.TABLES}
    for tbl_name in WIDE_TABLES:
        tables[tbl_name] = [{"__index_raw__": "1", "__index__": ("1",),
                              "someCol": "val"}]

    snap = KeepalivedSnapshot(
        scalars={}, tables=tables, collected_at=time.time(), walk_errors=(),
    )
    client = _StubClient(result=snap)
    dispatcher = KeepalivedDispatcher(
        client=client, walk_interval_s=9999.0, enable_wide_tables=False,
    )

    await dispatcher.start()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await dispatcher.stop()

    result = dispatcher.snapshot()
    assert result is not None
    for tbl_name in WIDE_TABLES:
        assert result.tables[tbl_name] == [], (
            f"expected {tbl_name} to be filtered out"
        )


@pytest.mark.asyncio
async def test_dispatcher_wide_tables_kept_when_enabled():
    from shorewalld.keepalived import mib
    from shorewalld.keepalived.dispatcher import WIDE_TABLES, KeepalivedDispatcher

    row = {"__index_raw__": "1", "__index__": ("1",), "someCol": "val"}
    tables = {name: [] for name in mib.TABLES}
    for tbl_name in WIDE_TABLES:
        tables[tbl_name] = [row]

    snap = KeepalivedSnapshot(
        scalars={}, tables=tables, collected_at=time.time(), walk_errors=(),
    )
    client = _StubClient(result=snap)
    dispatcher = KeepalivedDispatcher(
        client=client, walk_interval_s=9999.0, enable_wide_tables=True,
    )

    await dispatcher.start()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await dispatcher.stop()

    result = dispatcher.snapshot()
    assert result is not None
    for tbl_name in WIDE_TABLES:
        assert len(result.tables[tbl_name]) == 1, (
            f"expected {tbl_name} to be preserved when enable_wide_tables=True"
        )


# ---------------------------------------------------------------------------
# Test 6: snapshot_counters() returns a shallow copy (not shared state)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_snapshot_counters_isolation():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

    dispatcher = KeepalivedDispatcher(
        client=_StubClient(), walk_interval_s=9999.0,
    )
    # Read counters before any walk.
    counters = dispatcher.snapshot_counters()
    assert counters == {"walk_ok": 0, "walk_error": 0}

    # Mutating the returned dict must NOT affect the dispatcher's internal state.
    counters["walk_ok"] = 9999
    assert dispatcher.walks_total() == 0


# ---------------------------------------------------------------------------
# Test 7: last_walk_duration_s is set after a walk
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_last_walk_duration_set():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

    dispatcher = KeepalivedDispatcher(
        client=_StubClient(result=_make_snapshot()), walk_interval_s=9999.0,
    )
    assert dispatcher.last_walk_duration_s() is None

    await dispatcher.start()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await dispatcher.stop()

    dur = dispatcher.last_walk_duration_s()
    assert dur is not None
    assert isinstance(dur, float)
    assert dur >= 0.0


# ---------------------------------------------------------------------------
# Test 8: snapshot() after stop returns last-good snapshot (not None)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_snapshot_persists_after_stop():
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

    snap = _make_snapshot(scalars={"routerId": "fw-primary"})
    dispatcher = KeepalivedDispatcher(
        client=_StubClient(result=snap), walk_interval_s=9999.0,
    )

    await dispatcher.start()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await dispatcher.stop()

    result = dispatcher.snapshot()
    assert result is not None
    assert result.scalars.get("routerId") == "fw-primary"
