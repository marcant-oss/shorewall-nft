"""Tests for KeepalivedDbusClient and KeepalivedDbusEvent.

No live D-Bus session needed — all bus interactions are monkeypatched.

asyncio_mode = 'strict' globally (pyproject.toml).

Test cases
----------
1.  Module-absence path: _DBUS_AVAILABLE=False → KeepalivedDbusUnavailable at construction.
2.  Invalid method_acl → ValueError at construction.
3.  ACL "none" blocks all core methods.
4.  ACL "readonly" permits print_data + print_stats; blocks reload_config + send_garp.
5.  ACL "all" permits all 5 core methods (ACL-wise; D-Bus calls mocked).
6.  create_instance blocked without enable_create_instance=True.
7.  create_instance permitted with enable_create_instance=True.
8.  _build_event for VrrpStatusChange: state int 2 → "master", instance name extracted.
9.  _build_event for VrrpStarted: instance name extracted, new_state="".
10. _build_event for VrrpReloaded: no args, instance="" new_state="".
11. _build_event for VrrpStopped: no args.
12. _on_message ignores non-SIGNAL messages.
13. _on_message ignores signals from wrong interface.
14. _on_message ignores unknown signal names.
15. _on_message dispatches VrrpStatusChange to dispatcher.on_dbus_event.
16. send_garp with no snapshot → KeepalivedDbusInstanceNotFound.
17. send_garp with snapshot missing the instance → KeepalivedDbusInstanceNotFound.
18. send_garp with snapshot containing matching row → calls _call_method with right path.
19. print_stats(clear=True) falls back to PrintStats when PrintStatsClear fails.
20. print_stats fallback is cached: subsequent call doesn't retry PrintStatsClear.
21. start() calls bus.connect() + _add_match_rule + add_message_handler.
22. stop() calls bus.disconnect().
23. _state_map coverage: all four state ints map to correct strings.
24. KeepalivedDbusEvent dataclass has correct defaults.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dispatcher_stub() -> MagicMock:
    stub = MagicMock()
    stub.on_dbus_event = MagicMock()
    stub.snapshot = MagicMock(return_value=None)
    return stub


def _make_client(
    dispatcher=None,
    method_acl="readonly",
    enable_create_instance=False,
):
    from shorewalld.keepalived.dbus_client import KeepalivedDbusClient

    if dispatcher is None:
        dispatcher = _make_dispatcher_stub()
    return KeepalivedDbusClient(
        dispatcher=dispatcher,
        method_acl=method_acl,
        enable_create_instance=enable_create_instance,
    )


# ---------------------------------------------------------------------------
# Test 1: KeepalivedDbusUnavailable when dbus-next absent
# ---------------------------------------------------------------------------


def test_unavailable_without_dbus_next(monkeypatch):
    """Construction raises KeepalivedDbusUnavailable when dbus-next is absent."""
    import shorewalld.keepalived.dbus_client as dbc_mod

    monkeypatch.setattr(dbc_mod, "_DBUS_AVAILABLE", False)

    from shorewalld.keepalived.dbus_client import (
        KeepalivedDbusClient,
        KeepalivedDbusUnavailable,
    )

    with pytest.raises(KeepalivedDbusUnavailable):
        KeepalivedDbusClient(dispatcher=_make_dispatcher_stub())


# ---------------------------------------------------------------------------
# Test 2: Invalid method_acl
# ---------------------------------------------------------------------------


def test_invalid_method_acl():
    """Unknown method_acl string raises ValueError."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusClient

    with pytest.raises(ValueError, match="method_acl"):
        KeepalivedDbusClient(
            dispatcher=_make_dispatcher_stub(),
            method_acl="superuser",
        )


# ---------------------------------------------------------------------------
# Test 3: ACL "none" blocks all methods
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acl_none_blocks_all():
    """method_acl='none' raises KeepalivedDbusAclDenied for every method."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusAclDenied

    client = _make_client(method_acl="none")

    with pytest.raises(KeepalivedDbusAclDenied):
        await client.print_data()
    with pytest.raises(KeepalivedDbusAclDenied):
        await client.print_stats()
    with pytest.raises(KeepalivedDbusAclDenied):
        await client.reload_config()
    with pytest.raises(KeepalivedDbusAclDenied):
        await client.send_garp("VRRP_EXT")


# ---------------------------------------------------------------------------
# Test 4: ACL "readonly" permits print_data/print_stats, blocks others
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acl_readonly_permits_print():
    """method_acl='readonly' permits print_data/print_stats, blocks reload/garp."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusAclDenied

    client = _make_client(method_acl="readonly")
    # These should raise RuntimeError (not connected) not KeepalivedDbusAclDenied
    with pytest.raises(RuntimeError, match="not connected"):
        await client.print_data()
    with pytest.raises(RuntimeError, match="not connected"):
        await client.print_stats()

    # These should raise AclDenied
    with pytest.raises(KeepalivedDbusAclDenied):
        await client.reload_config()
    with pytest.raises(KeepalivedDbusAclDenied):
        await client.send_garp("inst")


# ---------------------------------------------------------------------------
# Test 5: ACL "all" permits core methods (ACL check passes, bus absent → RuntimeError)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acl_all_permits_all():
    """method_acl='all' allows all core methods (no AclDenied raised)."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusInstanceNotFound

    client = _make_client(method_acl="all")
    # print_data and reload_config fail with RuntimeError (bus not connected)
    # rather than KeepalivedDbusAclDenied — that means ACL passes.
    with pytest.raises(RuntimeError, match="not connected"):
        await client.print_data()
    with pytest.raises(RuntimeError, match="not connected"):
        await client.reload_config()
    # send_garp resolves instance path first; no snapshot → InstanceNotFound
    # (not AclDenied, so ACL passes).
    with pytest.raises(KeepalivedDbusInstanceNotFound):
        await client.send_garp("x")


# ---------------------------------------------------------------------------
# Test 6: create_instance blocked without enable_create_instance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_instance_requires_opt_in():
    """create_instance raises KeepalivedDbusAclDenied without enable_create_instance."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusAclDenied

    client = _make_client(method_acl="all", enable_create_instance=False)
    with pytest.raises(KeepalivedDbusAclDenied, match="enable_create_instance"):
        await client.create_instance("inst", "config")
    with pytest.raises(KeepalivedDbusAclDenied, match="enable_create_instance"):
        await client.destroy_instance("inst")


# ---------------------------------------------------------------------------
# Test 7: create_instance permitted with enable_create_instance=True
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_instance_permitted_with_opt_in():
    """create_instance with enable_create_instance=True passes ACL (bus absent → RuntimeError)."""
    client = _make_client(method_acl="all", enable_create_instance=True)
    with pytest.raises(RuntimeError, match="not connected"):
        await client.create_instance("inst", "config")
    with pytest.raises(RuntimeError, match="not connected"):
        await client.destroy_instance("inst")


# ---------------------------------------------------------------------------
# Tests 8–11: _build_event for each signal type
# ---------------------------------------------------------------------------


def test_build_event_vrrp_status_change():
    """VrrpStatusChange with state int 2 → new_state='master'."""
    client = _make_client()
    event = client._build_event("VrrpStatusChange", ["VRRP_EXT", 2])
    assert event.signal == "VrrpStatusChange"
    assert event.instance == "VRRP_EXT"
    assert event.new_state == "master"
    assert event.source == "dbus-signal"


def test_build_event_vrrp_status_change_backup():
    """VrrpStatusChange state int 1 → 'backup'."""
    client = _make_client()
    event = client._build_event("VrrpStatusChange", ["inst", 1])
    assert event.new_state == "backup"


def test_build_event_vrrp_status_change_fault():
    """VrrpStatusChange state int 3 → 'fault'."""
    client = _make_client()
    event = client._build_event("VrrpStatusChange", ["inst", 3])
    assert event.new_state == "fault"


def test_build_event_vrrp_status_change_init():
    """VrrpStatusChange state int 0 → 'init'."""
    client = _make_client()
    event = client._build_event("VrrpStatusChange", ["inst", 0])
    assert event.new_state == "init"


def test_build_event_vrrp_started():
    """VrrpStarted carries instance name, no new_state."""
    client = _make_client()
    event = client._build_event("VrrpStarted", ["VRRP_EXT"])
    assert event.signal == "VrrpStarted"
    assert event.instance == "VRRP_EXT"
    assert event.new_state == ""


def test_build_event_vrrp_reloaded():
    """VrrpReloaded carries no args."""
    client = _make_client()
    event = client._build_event("VrrpReloaded", [])
    assert event.signal == "VrrpReloaded"
    assert event.instance == ""
    assert event.new_state == ""


def test_build_event_vrrp_stopped():
    """VrrpStopped carries no args."""
    client = _make_client()
    event = client._build_event("VrrpStopped", [])
    assert event.signal == "VrrpStopped"
    assert event.instance == ""
    assert event.new_state == ""


# ---------------------------------------------------------------------------
# Tests 12–14: _on_message filtering
# ---------------------------------------------------------------------------


def test_on_message_ignores_non_signal():
    """_on_message ignores non-SIGNAL message types."""
    from dbus_next import MessageType

    dispatcher = _make_dispatcher_stub()
    client = _make_client(dispatcher=dispatcher)

    msg = MagicMock()
    msg.message_type = MessageType.METHOD_CALL
    client._on_message(msg)
    dispatcher.on_dbus_event.assert_not_called()


def test_on_message_ignores_wrong_interface():
    """_on_message ignores signals from wrong interface."""
    from dbus_next import MessageType

    dispatcher = _make_dispatcher_stub()
    client = _make_client(dispatcher=dispatcher)

    msg = MagicMock()
    msg.message_type = MessageType.SIGNAL
    msg.interface = "org.some.other.Interface"
    msg.member = "VrrpStatusChange"
    client._on_message(msg)
    dispatcher.on_dbus_event.assert_not_called()


def test_on_message_ignores_unknown_signal():
    """_on_message ignores signal names not in _ALL_SIGNALS."""
    from dbus_next import MessageType

    dispatcher = _make_dispatcher_stub()
    client = _make_client(dispatcher=dispatcher)

    msg = MagicMock()
    msg.message_type = MessageType.SIGNAL
    msg.interface = "org.keepalived.Vrrp1.Instance"
    msg.member = "UnknownSignal"
    client._on_message(msg)
    dispatcher.on_dbus_event.assert_not_called()


# ---------------------------------------------------------------------------
# Test 15: _on_message dispatches VrrpStatusChange
# ---------------------------------------------------------------------------


def test_on_message_dispatches_vrrp_status_change():
    """_on_message with VrrpStatusChange calls dispatcher.on_dbus_event."""
    from dbus_next import MessageType

    dispatcher = _make_dispatcher_stub()
    client = _make_client(dispatcher=dispatcher)

    msg = MagicMock()
    msg.message_type = MessageType.SIGNAL
    msg.interface = "org.keepalived.Vrrp1.Instance"
    msg.member = "VrrpStatusChange"
    msg.body = ["VRRP_EXT", 2]

    client._on_message(msg)
    dispatcher.on_dbus_event.assert_called_once()
    event = dispatcher.on_dbus_event.call_args[0][0]
    assert event.signal == "VrrpStatusChange"
    assert event.instance == "VRRP_EXT"
    assert event.new_state == "master"


# ---------------------------------------------------------------------------
# Test 16: send_garp with no snapshot raises KeepalivedDbusInstanceNotFound
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_garp_no_snapshot():
    """send_garp raises KeepalivedDbusInstanceNotFound when no snapshot."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusInstanceNotFound

    dispatcher = _make_dispatcher_stub()
    dispatcher.snapshot.return_value = None
    client = _make_client(dispatcher=dispatcher, method_acl="all")

    with pytest.raises(KeepalivedDbusInstanceNotFound):
        await client.send_garp("VRRP_EXT")


# ---------------------------------------------------------------------------
# Test 17: send_garp with snapshot but missing instance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_garp_instance_not_in_snapshot():
    """send_garp raises KeepalivedDbusInstanceNotFound when instance not in table."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusInstanceNotFound

    snap = MagicMock()
    snap.tables = {
        "vrrpInstanceTable": [
            {"vrrpInstanceName": "OTHER_INST", "vrrpInstanceInterface": "eth0",
             "vrrpInstanceVirtualRouterId": "51"},
        ],
    }
    dispatcher = _make_dispatcher_stub()
    dispatcher.snapshot.return_value = snap
    client = _make_client(dispatcher=dispatcher, method_acl="all")

    with pytest.raises(KeepalivedDbusInstanceNotFound):
        await client.send_garp("VRRP_EXT")


# ---------------------------------------------------------------------------
# Test 18: send_garp with matching snapshot entry → _call_method invoked
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_garp_resolves_object_path():
    """send_garp resolves instance path and calls _call_method."""
    snap = MagicMock()
    snap.tables = {
        "vrrpInstanceTable": [
            {
                "vrrpInstanceName": "VRRP_EXT",
                "vrrpInstanceInterface": "eth0",
                "vrrpInstanceVirtualRouterId": "51",
            }
        ],
    }
    dispatcher = _make_dispatcher_stub()
    dispatcher.snapshot.return_value = snap
    client = _make_client(dispatcher=dispatcher, method_acl="all")

    expected_path = "/org/keepalived/Vrrp1/Instance/eth0/51/IPv4"

    # Patch _call_method to avoid needing a real D-Bus connection
    client._call_method = AsyncMock(return_value=[])
    # Provide a fake bus to pass _require_bus()
    client._bus = MagicMock()

    await client.send_garp("VRRP_EXT")

    client._call_method.assert_called_once()
    call_args = client._call_method.call_args
    # The path argument should contain "eth0/51/IPv4"
    path_arg = call_args[0][1]  # positional: bus, obj_path, ...
    assert "eth0" in path_arg and "51" in path_arg


# ---------------------------------------------------------------------------
# Test 19: print_stats(clear=True) falls back to PrintStats when PrintStatsClear fails
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_print_stats_clear_fallback():
    """print_stats(clear=True) falls back to PrintStats when PrintStatsClear fails."""
    client = _make_client(method_acl="readonly")
    client._bus = MagicMock()

    call_log = []

    async def mock_call_method(bus, obj_path, iface, method, sig, body):
        call_log.append(method)
        if method == "PrintStatsClear":
            raise RuntimeError("method not found")
        return []

    client._call_method = mock_call_method
    client._read_file = lambda p: b"stats content"

    result = await client.print_stats(clear=True)
    assert result == b"stats content"
    assert "PrintStatsClear" in call_log
    assert "PrintStats" in call_log


# ---------------------------------------------------------------------------
# Test 20: PrintStatsClear fallback is cached
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_print_stats_clear_fallback_cached():
    """After PrintStatsClear fails once, subsequent calls skip it."""
    client = _make_client(method_acl="readonly")
    client._bus = MagicMock()

    call_log = []

    async def mock_call_method(bus, obj_path, iface, method, sig, body):
        call_log.append(method)
        if method == "PrintStatsClear":
            raise RuntimeError("not found")
        return []

    client._call_method = mock_call_method
    client._read_file = lambda p: b""

    # First call: triggers fallback
    await client.print_stats(clear=True)
    assert client._print_stats_clear_unavailable is True

    call_log.clear()
    # Second call: should skip PrintStatsClear entirely
    await client.print_stats(clear=True)
    assert "PrintStatsClear" not in call_log
    assert "PrintStats" in call_log


# ---------------------------------------------------------------------------
# Test 21: start() calls bus.connect + _add_match_rule + add_message_handler
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_connects_and_subscribes():
    """start() connects to the bus and registers the signal match rule."""
    client = _make_client()

    mock_bus = AsyncMock()
    mock_bus._add_match_rule = AsyncMock()
    mock_bus.add_message_handler = MagicMock()
    mock_bus.disconnect = MagicMock()

    with patch(
        "shorewalld.keepalived.dbus_client.MessageBus",
        return_value=mock_bus,
    ):
        await client.start()

    mock_bus.connect.assert_awaited_once()
    mock_bus._add_match_rule.assert_awaited_once()
    mock_bus.add_message_handler.assert_called_once_with(client._on_message)


# ---------------------------------------------------------------------------
# Test 22: stop() calls bus.disconnect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_disconnects():
    """stop() calls bus.disconnect() and sets _bus to None."""
    client = _make_client()
    mock_bus = MagicMock()
    client._bus = mock_bus

    await client.stop()

    mock_bus.disconnect.assert_called_once()
    assert client._bus is None


# ---------------------------------------------------------------------------
# Test 23: State map coverage
# ---------------------------------------------------------------------------


def test_state_map_all_values():
    """All four state integers map to the correct string."""
    client = _make_client()
    for state_int, expected in [(0, "init"), (1, "backup"), (2, "master"), (3, "fault")]:
        event = client._build_event("VrrpStatusChange", ["inst", state_int])
        assert event.new_state == expected, f"state {state_int} → {event.new_state!r}"


# ---------------------------------------------------------------------------
# Test 24: KeepalivedDbusEvent defaults
# ---------------------------------------------------------------------------


def test_dbus_event_defaults():
    """KeepalivedDbusEvent has correct default source tag."""
    from shorewalld.keepalived.dbus_client import KeepalivedDbusEvent
    import time

    event = KeepalivedDbusEvent(
        signal="VrrpReloaded",
        instance="",
        new_state="",
        received_at=time.time(),
    )
    assert event.source == "dbus-signal"


# ---------------------------------------------------------------------------
# Test 25: VrrpStatusChange with empty body doesn't crash
# ---------------------------------------------------------------------------


def test_build_event_vrrp_status_change_empty_body():
    """_build_event with empty body for VrrpStatusChange doesn't crash."""
    client = _make_client()
    event = client._build_event("VrrpStatusChange", [])
    assert event.signal == "VrrpStatusChange"
    assert event.instance == ""
    assert event.new_state == ""
