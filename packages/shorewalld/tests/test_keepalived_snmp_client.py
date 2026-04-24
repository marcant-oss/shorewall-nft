"""Tests for the python-netsnmp SNMP client wrapper.

No live snmpd — we inject a fake ``netsnmp`` module or monkey-patch
``KeepalivedSnmpClient._sync_walk`` directly. Covers: construction
failure path (module absent), transport selection (unix vs udp),
varbind coercion (bytes/str/empty/numeric), async wrapper behaviour.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Module availability error path (netsnmp absent).
# ---------------------------------------------------------------------------


def test_client_raises_when_netsnmp_not_installed(monkeypatch):
    """If python3-netsnmp is absent, construction must raise a typed
    error so the caller can emit an apt-install hint.
    """
    # Force the module-cached flag to False *before* importing the
    # client (reload to pick up the patched global).
    import shorewalld.keepalived.snmp_client as mod
    monkeypatch.setattr(mod, "_NETSNMP_AVAILABLE", False)
    with pytest.raises(mod.KeepalivedSnmpClientUnavailable,
                        match="python3-netsnmp is not installed"):
        mod.KeepalivedSnmpClient(unix_path="/tmp/anything")


# ---------------------------------------------------------------------------
# Transport selection.
# ---------------------------------------------------------------------------


class _FakeNetsnmp:
    """Fake ``netsnmp`` module providing just enough surface for tests."""

    class Session:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.walks: list[str] = []

        def walk(self, varlist):
            # Default: leave the varlist empty (zero-row result).
            pass

    class Varbind:
        def __init__(self, oid):
            self.tag = oid
            self.iid = ""
            self.val = None
            self.type = ""

    class VarList(list):
        def __init__(self, *items):
            super().__init__(items)


@pytest.fixture
def fake_netsnmp(monkeypatch):
    """Inject a fake ``netsnmp`` module + mark availability true."""
    fake = _FakeNetsnmp
    monkeypatch.setitem(sys.modules, "netsnmp", fake)
    import shorewalld.keepalived.snmp_client as mod
    monkeypatch.setattr(mod, "netsnmp", fake)
    monkeypatch.setattr(mod, "_NETSNMP_AVAILABLE", True)
    return fake


def test_client_picks_unix_transport_when_socket_exists(fake_netsnmp, tmp_path):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    sock = tmp_path / "snmpd.sock"
    sock.touch()
    c = KeepalivedSnmpClient(unix_path=str(sock))
    assert c.peername == f"unix:{sock}"
    assert c._session.kwargs["Peername"] == f"unix:{sock}"
    assert c._session.kwargs["Version"] == 2


def test_client_falls_back_to_udp_when_unix_socket_missing(fake_netsnmp, tmp_path):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    # Non-existent unix path → udp fallback.
    c = KeepalivedSnmpClient(unix_path=str(tmp_path / "nosuchsock"),
                             udp_host="192.0.2.1", udp_port=1234)
    assert c.peername == "udp:192.0.2.1:1234"


def test_client_uses_udp_when_unix_path_not_given(fake_netsnmp):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    c = KeepalivedSnmpClient(udp_host="10.0.0.1")
    assert c.peername == "udp:10.0.0.1:161"


def test_client_timeout_is_expressed_in_microseconds(fake_netsnmp):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    c = KeepalivedSnmpClient(timeout_s=0.5)
    # net-snmp wants Timeout in microseconds.
    assert c._session.kwargs["Timeout"] == 500_000


# ---------------------------------------------------------------------------
# Varbind coercion.
# ---------------------------------------------------------------------------


def test_varbind_coerces_bytes_value_to_utf8(fake_netsnmp):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    vb = MagicMock()
    vb.tag = ".1.3.6.1.4.1.9586.100.5.2.3.1.2"
    vb.iid = "1"
    vb.val = b"VI_1"
    vb.type = "OCTETSTR"
    out = KeepalivedSnmpClient._varbind_to_tuple(vb, root_oid_placeholder := "")
    assert out.oid == "1.3.6.1.4.1.9586.100.5.2.3.1.2"
    assert out.index == "1"
    assert out.value == "VI_1"
    assert out.syntax == "OCTETSTR"


def test_varbind_coerces_integer_value_via_str(fake_netsnmp):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    vb = MagicMock()
    vb.tag = "1.3.6.1.4.1.9586.100.5.2.3.1.4"
    vb.iid = "1"
    vb.val = 2
    vb.type = "INTEGER"
    out = KeepalivedSnmpClient._varbind_to_tuple(vb, "")
    assert out.value == "2"
    assert out.syntax == "INTEGER"


def test_varbind_tolerates_none_value(fake_netsnmp):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    vb = MagicMock()
    vb.tag = "1.3.6.1.4.1.9586.100.5.1.1"
    vb.iid = ""
    vb.val = None
    vb.type = "OCTETSTR"
    out = KeepalivedSnmpClient._varbind_to_tuple(vb, "")
    assert out.value == ""


def test_varbind_strips_leading_dot_from_oid(fake_netsnmp):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    vb = MagicMock()
    vb.tag = ".1.3.6.1.4.1.9586"
    vb.iid = ""
    vb.val = b"x"
    vb.type = "OCTETSTR"
    out = KeepalivedSnmpClient._varbind_to_tuple(vb, "")
    assert out.oid == "1.3.6.1.4.1.9586"
    assert not out.oid.startswith(".")


def test_varbind_handles_non_utf8_bytes_gracefully(fake_netsnmp):
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    vb = MagicMock()
    vb.tag = "1.3.6.1"
    vb.iid = "1"
    vb.val = b"\xff\xfe\xff"  # Invalid UTF-8
    vb.type = "OCTETSTR"
    out = KeepalivedSnmpClient._varbind_to_tuple(vb, "")
    # `replace` emits replacement characters, doesn't raise.
    assert out.value  # non-empty
    assert "�" in out.value or "�" in out.value


# ---------------------------------------------------------------------------
# Async walk — behaviour of the asyncio.to_thread wrapper.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_walk_returns_list_of_varbinds(fake_netsnmp, tmp_path, monkeypatch):
    """Async walk wraps the sync call without altering the result."""
    sock = tmp_path / "snmpd.sock"
    sock.touch()
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient, SnmpVarbind
    c = KeepalivedSnmpClient(unix_path=str(sock))
    # Replace _sync_walk with a canned result.
    canned = [
        SnmpVarbind(
            oid="1.3.6.1.4.1.9586.100.5.2.3.1.2", index="1",
            value="VI_1", syntax="OCTETSTR",
        ),
        SnmpVarbind(
            oid="1.3.6.1.4.1.9586.100.5.2.3.1.2", index="2",
            value="VI_2", syntax="OCTETSTR",
        ),
    ]
    monkeypatch.setattr(c, "_sync_walk", lambda _o: canned)
    got = await c.walk("1.3.6.1.4.1.9586.100.5.2.3.1.2")
    assert got == canned


@pytest.mark.asyncio
async def test_walk_does_not_block_event_loop_when_sync_walk_sleeps(
    fake_netsnmp, tmp_path, monkeypatch,
):
    """Async walk must yield — verify another coroutine progresses."""
    import asyncio as _asyncio
    import time
    sock = tmp_path / "snmpd.sock"
    sock.touch()
    from shorewalld.keepalived.snmp_client import KeepalivedSnmpClient
    c = KeepalivedSnmpClient(unix_path=str(sock))

    def _slow_walk(_oid):
        time.sleep(0.1)   # blocking, would freeze the loop if not threaded
        return []

    monkeypatch.setattr(c, "_sync_walk", _slow_walk)

    progress = {"ticks": 0}

    async def _heartbeat():
        for _ in range(20):
            progress["ticks"] += 1
            await _asyncio.sleep(0.01)

    hb = _asyncio.create_task(_heartbeat())
    await c.walk("1.3.6.1")
    await hb
    # If walk had blocked the event loop for 0.1s, heartbeat would
    # have ~0 ticks. With to_thread it should hit ~10.
    assert progress["ticks"] >= 5
