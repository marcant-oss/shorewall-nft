"""Tests for the four keepalived-* control-socket handlers.

These handlers are additive in this commit (Commit 3); the daemon dispatch
table wiring is Commit 4 (P8).  We call handler methods directly.

asyncio_mode = 'strict' globally (pyproject.toml).

Test cases
----------
1.  handle_keepalived_data with keepalived_dbus=None → {"error": "..."}
2.  handle_keepalived_stats with keepalived_dbus=None → {"error": "..."}
3.  handle_keepalived_reload with keepalived_dbus=None → {"error": "..."}
4.  handle_keepalived_garp with keepalived_dbus=None → {"error": "..."}
5.  handle_keepalived_data with stub client → {"data": "..."}
6.  handle_keepalived_stats with stub client → {"data": "..."}
7.  handle_keepalived_stats with clear=True → forwarded to print_stats(clear=True)
8.  handle_keepalived_reload with stub client → {"ok": True}
9.  handle_keepalived_garp missing instance → {"error": "..."}
10. handle_keepalived_garp with instance → stub.send_garp("name") called, {"ok": True}
11. handle_keepalived_data client exception → {"error": "..."}
12. handle_keepalived_garp client exception → {"error": "..."}
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_handlers(keepalived_dbus=None):
    from shorewalld.control_handlers import ControlHandlers

    return ControlHandlers(keepalived_dbus=keepalived_dbus)


def _make_stub_dbus(
    data_bytes: bytes = b"keepalived data",
    stats_bytes: bytes = b"keepalived stats",
):
    stub = MagicMock()
    stub.print_data = AsyncMock(return_value=data_bytes)
    stub.print_stats = AsyncMock(return_value=stats_bytes)
    stub.reload_config = AsyncMock(return_value=None)
    stub.send_garp = AsyncMock(return_value=None)
    return stub


# ---------------------------------------------------------------------------
# Tests 1–4: All handlers disabled (keepalived_dbus=None)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_data_disabled():
    handlers = _make_handlers(keepalived_dbus=None)
    result = await handlers.handle_keepalived_data({})
    assert "error" in result


@pytest.mark.asyncio
async def test_keepalived_stats_disabled():
    handlers = _make_handlers(keepalived_dbus=None)
    result = await handlers.handle_keepalived_stats({})
    assert "error" in result


@pytest.mark.asyncio
async def test_keepalived_reload_disabled():
    handlers = _make_handlers(keepalived_dbus=None)
    result = await handlers.handle_keepalived_reload({})
    assert "error" in result


@pytest.mark.asyncio
async def test_keepalived_garp_disabled():
    handlers = _make_handlers(keepalived_dbus=None)
    result = await handlers.handle_keepalived_garp({"instance": "VRRP_EXT"})
    assert "error" in result


# ---------------------------------------------------------------------------
# Test 5: handle_keepalived_data with stub → {"data": str}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_data_returns_decoded_content():
    stub = _make_stub_dbus(data_bytes=b"hello data content")
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_data({})
    assert result == {"data": "hello data content"}
    stub.print_data.assert_awaited_once()


# ---------------------------------------------------------------------------
# Test 6: handle_keepalived_stats with stub → {"data": str}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_stats_returns_decoded_content():
    stub = _make_stub_dbus(stats_bytes=b"stats line1\nstats line2")
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_stats({})
    assert result == {"data": "stats line1\nstats line2"}
    stub.print_stats.assert_awaited_once_with(clear=False)


# ---------------------------------------------------------------------------
# Test 7: handle_keepalived_stats with clear=True → forwarded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_stats_with_clear():
    stub = _make_stub_dbus()
    handlers = _make_handlers(keepalived_dbus=stub)

    await handlers.handle_keepalived_stats({"clear": True})
    stub.print_stats.assert_awaited_once_with(clear=True)


# ---------------------------------------------------------------------------
# Test 8: handle_keepalived_reload → {"ok": True}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_reload_ok():
    stub = _make_stub_dbus()
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_reload({})
    assert result == {"ok": True}
    stub.reload_config.assert_awaited_once()


# ---------------------------------------------------------------------------
# Test 9: handle_keepalived_garp missing instance → {"error": "..."}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_garp_missing_instance():
    stub = _make_stub_dbus()
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_garp({})
    assert "error" in result
    # send_garp should NOT have been called
    stub.send_garp.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test 10: handle_keepalived_garp with instance → send_garp called
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_garp_ok():
    stub = _make_stub_dbus()
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_garp({"instance": "VRRP_EXT"})
    assert result == {"ok": True}
    stub.send_garp.assert_awaited_once_with("VRRP_EXT")


# ---------------------------------------------------------------------------
# Test 11: handle_keepalived_data client exception → {"error": "..."}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_data_client_exception():
    stub = MagicMock()
    stub.print_data = AsyncMock(side_effect=RuntimeError("D-Bus error: something"))
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_data({})
    assert "error" in result
    assert "D-Bus error" in result["error"]


# ---------------------------------------------------------------------------
# Test 12: handle_keepalived_garp client exception → {"error": "..."}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_garp_client_exception():
    stub = MagicMock()
    stub.send_garp = AsyncMock(
        side_effect=RuntimeError("instance not found")
    )
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_garp({"instance": "MISSING"})
    assert "error" in result


# ---------------------------------------------------------------------------
# Test 13: clear=False (default) in keepalived_stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_stats_clear_default_false():
    stub = _make_stub_dbus()
    handlers = _make_handlers(keepalived_dbus=stub)

    await handlers.handle_keepalived_stats({})
    stub.print_stats.assert_awaited_once_with(clear=False)


# ---------------------------------------------------------------------------
# Test 14: handle_keepalived_reload exception → {"error": "..."}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalived_reload_exception():
    stub = MagicMock()
    stub.reload_config = AsyncMock(side_effect=PermissionError("ACL denied"))
    handlers = _make_handlers(keepalived_dbus=stub)

    result = await handlers.handle_keepalived_reload({})
    assert "error" in result
