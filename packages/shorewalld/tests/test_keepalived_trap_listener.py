"""Tests for KeepalivedTrapListener and the pysnmp BER decode path.

Uses in-process Unix DGRAM sockets (via tmp_path) — no live snmpd needed.

asyncio_mode = 'strict' globally (pyproject.toml).

Test cases
----------
1.  Decode happy path: synthetic vrrpInstanceStateChange trap →
    KeepalivedTrapEvent with correct name + objects.
2.  Unknown trap OID → name resolves to "unknown"; objects keyed by OID.
3.  Malformed datagram (random bytes) → _decode_trap returns None, no exception.
4.  Socket lifecycle: start() creates the socket file; stop() unlinks it.
5.  End-to-end: send a raw trap via sendto() → dispatcher counter bumped.
6.  Decode error counter: dispatcher.on_trap_decode_error() called on bad frame.
7.  Two varbinds trap (only mandatory, no payload) → objects is empty dict.
8.  Extra payload varbinds beyond the MIB's OBJECTS list → keyed by OID.
9.  sysUpTime.0 varbind skipped correctly (first varbind is sysUpTime, not OID).
10. Non-SNMPv2TrapPDU PDU type → returns None gracefully.
"""

from __future__ import annotations

import asyncio
import socket
import time
from unittest.mock import MagicMock

import pytest

# pysnmp is an optional [snmp] extra; skip this whole module when it's not
# importable. Production code soft-degrades via KeepalivedTrapListenerUnavailable;
# the tests mirror that by not running at all rather than failing.
pytest.importorskip("pysnmp", reason="pysnmp not installed (optional [snmp] extra)")


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_synthetic_trap(trap_oid_tuple: tuple, payload_varbinds: list | None = None) -> bytes:
    """Encode a SNMPv2c trap message with pysnmp and return raw bytes.

    Parameters
    ----------
    trap_oid_tuple:
        OID as a tuple of ints for snmpTrapOID.0.
    payload_varbinds:
        List of (oid_tuple, value) pairs to append after sysUpTime.0 and
        snmpTrapOID.0.  *value* may be a pysnmp type instance or a plain
        OctetString bytes.
    """
    from pyasn1.codec.ber import encoder
    from pyasn1.type import univ
    from pysnmp.proto import api

    pMod = api.v2c

    trapPDU = pMod.SNMPv2TrapPDU()
    pMod.apiTrapPDU.set_defaults(trapPDU)

    SYSUPTIME_OID = univ.ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0))
    SNMPTRAPOID_OID = univ.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0))
    TRAP_OID = univ.ObjectIdentifier(trap_oid_tuple)

    vbs = [
        (SYSUPTIME_OID, pMod.TimeTicks(12345)),
        (SNMPTRAPOID_OID, TRAP_OID),
    ]
    if payload_varbinds:
        for oid_tup, val in payload_varbinds:
            vbs.append((univ.ObjectIdentifier(oid_tup), val))

    pMod.apiTrapPDU.set_varbinds(trapPDU, vbs)

    msg = pMod.Message()
    pMod.apiMessage.set_defaults(msg)
    pMod.apiMessage.set_community(msg, "public")
    pMod.apiMessage.set_pdu(msg, trapPDU)

    return encoder.encode(msg)


def _make_dispatcher_stub() -> MagicMock:
    """Return a MagicMock that satisfies the dispatcher interface."""
    stub = MagicMock()
    stub.on_trap_event = MagicMock()
    stub.on_trap_decode_error = MagicMock()
    return stub


def _make_listener(socket_path: str, dispatcher=None):
    from shorewalld.keepalived.trap_listener import KeepalivedTrapListener

    if dispatcher is None:
        dispatcher = _make_dispatcher_stub()
    return KeepalivedTrapListener(
        socket_path=socket_path,
        dispatcher=dispatcher,
    )


# ---------------------------------------------------------------------------
# Test 1: Decode happy path — vrrpInstanceStateChange
# ---------------------------------------------------------------------------


def test_decode_vrrp_instance_state_change():
    """Synthetic vrrpInstanceStateChange trap decodes with correct name + objects."""
    from pysnmp.proto import api

    pMod = api.v2c

    # vrrpInstanceStateChange OID: 1.3.6.1.4.1.9586.100.5.2.10.0.2
    trap_oid = (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 10, 0, 2)
    # Payload: vrrpInstanceName.1 = "VRRP_EXT"
    payload = [
        (
            (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 3, 1, 2, 1),
            pMod.OctetString(b"VRRP_EXT"),
        ),
        (
            (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 3, 1, 4, 1),
            pMod.Integer(2),  # vrrpInstanceState = 2 (master)
        ),
    ]
    raw = _make_synthetic_trap(trap_oid, payload)

    listener = _make_listener("/tmp/fake_test.sock")
    event = listener._decode_trap(raw)

    assert event is not None
    assert event.name == "vrrpInstanceStateChange"
    assert event.trap_oid == "1.3.6.1.4.1.9586.100.5.2.10.0.2"
    # First payload varbind should map to vrrpInstanceName
    assert "vrrpInstanceName" in event.objects
    assert event.objects["vrrpInstanceName"] == "VRRP_EXT"
    assert event.source == "snmp-trap"
    assert isinstance(event.received_at, float)
    assert event.received_at > 0


# ---------------------------------------------------------------------------
# Test 2: Unknown trap OID → name = "unknown", objects keyed by OID string
# ---------------------------------------------------------------------------


def test_decode_unknown_trap_oid():
    """Unknown OID resolves to name='unknown', objects keyed by OID."""
    from pysnmp.proto import api

    pMod = api.v2c

    # OID not in NOTIFICATIONS
    trap_oid = (1, 3, 6, 1, 4, 1, 99999, 1, 2, 3)
    payload = [
        (
            (1, 3, 6, 1, 4, 1, 99999, 1, 2, 3, 4),
            pMod.OctetString(b"payload"),
        ),
    ]
    raw = _make_synthetic_trap(trap_oid, payload)
    listener = _make_listener("/tmp/fake_test.sock")
    event = listener._decode_trap(raw)

    assert event is not None
    assert event.name == "unknown"
    assert event.trap_oid == "1.3.6.1.4.1.99999.1.2.3"
    # With unknown OID, objects are keyed by OID string
    assert len(event.objects) == 1
    assert "1.3.6.1.4.1.99999.1.2.3.4" in event.objects


# ---------------------------------------------------------------------------
# Test 3: Malformed datagram → returns None, no exception
# ---------------------------------------------------------------------------


def test_decode_malformed_datagram():
    """Random bytes do not cause an exception; _decode_trap returns None."""
    dispatcher = _make_dispatcher_stub()
    listener = _make_listener("/tmp/fake_test.sock", dispatcher)

    result = listener._decode_trap(b"this is not snmp data at all \x00\x01\x02\xff")
    assert result is None
    # on_trap_decode_error should have been called once
    dispatcher.on_trap_decode_error.assert_called_once()
    # on_trap_event should not have been called
    dispatcher.on_trap_event.assert_not_called()


# ---------------------------------------------------------------------------
# Test 4: Socket lifecycle — start creates socket, stop unlinks it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_socket_lifecycle(tmp_path):
    """start() creates the socket file; stop() unlinks it."""
    sock_path = str(tmp_path / "snmp-trap.sock")
    listener = _make_listener(sock_path)

    import os
    assert not os.path.exists(sock_path)

    await listener.start()
    assert os.path.exists(sock_path)

    await listener.stop()
    assert not os.path.exists(sock_path)


# ---------------------------------------------------------------------------
# Test 5: End-to-end — send a raw trap → dispatcher.on_trap_event called
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_trap_received(tmp_path):
    """Sending a trap datagram results in dispatcher.on_trap_event being called."""
    from pysnmp.proto import api

    pMod = api.v2c

    sock_path = str(tmp_path / "snmp-trap-e2e.sock")
    dispatcher = _make_dispatcher_stub()
    listener = _make_listener(sock_path, dispatcher)

    await listener.start()

    # Build a synthetic trap
    trap_oid = (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 10, 0, 2)  # vrrpInstanceStateChange
    raw = _make_synthetic_trap(trap_oid)

    # Send via a client socket
    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        client_sock.sendto(raw, sock_path)
    finally:
        client_sock.close()

    # Give the event loop a few iterations to process the datagram.
    for _ in range(5):
        await asyncio.sleep(0)

    await listener.stop()

    dispatcher.on_trap_event.assert_called_once()
    event = dispatcher.on_trap_event.call_args[0][0]
    assert event.name == "vrrpInstanceStateChange"


# ---------------------------------------------------------------------------
# Test 6: Decode error counter bumped on bad frame
# ---------------------------------------------------------------------------


def test_decode_error_counter_bumped():
    """Malformed datagram calls on_trap_decode_error exactly once."""
    dispatcher = _make_dispatcher_stub()
    listener = _make_listener("/tmp/fake.sock", dispatcher)

    listener._decode_trap(b"\xff\xfe\xfd")
    dispatcher.on_trap_decode_error.assert_called_once()


# ---------------------------------------------------------------------------
# Test 7: Trap with only mandatory varbinds — objects is empty
# ---------------------------------------------------------------------------


def test_decode_minimal_trap_empty_objects():
    """A trap with only sysUpTime.0 + snmpTrapOID.0 produces empty objects."""
    trap_oid = (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 10, 0, 2)
    raw = _make_synthetic_trap(trap_oid, payload_varbinds=None)
    listener = _make_listener("/tmp/fake.sock")
    event = listener._decode_trap(raw)

    assert event is not None
    assert event.objects == {}


# ---------------------------------------------------------------------------
# Test 8: Extra payload varbinds beyond OBJECTS list → keyed by OID
# ---------------------------------------------------------------------------


def test_decode_extra_varbinds_keyed_by_oid():
    """Extra varbinds beyond the MIB OBJECTS list fall back to OID key."""
    from pysnmp.proto import api

    pMod = api.v2c

    # vrrpInstanceStateChange has 4 objects; we add a 5th
    trap_oid = (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 10, 0, 2)
    payload = [
        ((1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 3, 1, 2, 1), pMod.OctetString(b"inst1")),
        ((1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 3, 1, 4, 1), pMod.Integer(2)),
        ((1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 3, 1, 6, 1), pMod.Integer(51)),
        ((1, 3, 6, 1, 4, 1, 9586, 100, 5, 1, 1, 0), pMod.OctetString(b"fw1")),
        # 5th varbind — beyond the 4 in OBJECTS
        ((1, 3, 6, 1, 4, 1, 9586, 100, 5, 99, 0), pMod.OctetString(b"extra")),
    ]
    raw = _make_synthetic_trap(trap_oid, payload)
    listener = _make_listener("/tmp/fake.sock")
    event = listener._decode_trap(raw)

    assert event is not None
    # 5th entry should be keyed by OID
    assert "1.3.6.1.4.1.9586.100.5.99.0" in event.objects
    assert event.objects["1.3.6.1.4.1.9586.100.5.99.0"] == "extra"


# ---------------------------------------------------------------------------
# Test 9: vrrpSyncGroupStateChange decode
# ---------------------------------------------------------------------------


def test_decode_vrrp_sync_group_state_change():
    """vrrpSyncGroupStateChange OID resolves correctly."""
    from pysnmp.proto import api

    pMod = api.v2c

    # vrrpSyncGroupStateChange: 1.3.6.1.4.1.9586.100.5.2.10.0.1
    trap_oid = (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 10, 0, 1)
    payload = [
        ((1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 1, 1, 2, 1), pMod.OctetString(b"SG_MAIN")),
    ]
    raw = _make_synthetic_trap(trap_oid, payload)
    listener = _make_listener("/tmp/fake.sock")
    event = listener._decode_trap(raw)

    assert event is not None
    assert event.name == "vrrpSyncGroupStateChange"
    assert event.objects.get("vrrpSyncGroupName") == "SG_MAIN"


# ---------------------------------------------------------------------------
# Test 10: Stale socket file removed by start()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_removes_stale_socket(tmp_path):
    """start() silently removes a stale socket file before binding."""
    import os
    sock_path = str(tmp_path / "stale.sock")

    # Create a stale socket (just a file)
    with open(sock_path, "w") as f:
        f.write("stale")

    assert os.path.exists(sock_path)

    listener = _make_listener(sock_path)
    await listener.start()
    # Should have replaced the stale file with a real socket
    assert os.path.exists(sock_path)

    await listener.stop()


# ---------------------------------------------------------------------------
# Test 11: KeepalivedTrapListenerUnavailable raised without pysnmp
# ---------------------------------------------------------------------------


def test_unavailable_without_pysnmp(monkeypatch):
    """Construction raises KeepalivedTrapListenerUnavailable when pysnmp absent."""
    import shorewalld.keepalived.trap_listener as tl_mod

    monkeypatch.setattr(tl_mod, "_PYSNMP_AVAILABLE", False)

    from shorewalld.keepalived.trap_listener import (
        KeepalivedTrapListener,
        KeepalivedTrapListenerUnavailable,
    )

    dispatcher = _make_dispatcher_stub()
    with pytest.raises(KeepalivedTrapListenerUnavailable):
        KeepalivedTrapListener(socket_path="/tmp/x.sock", dispatcher=dispatcher)


# ---------------------------------------------------------------------------
# Test 12: received_at timestamp is recent
# ---------------------------------------------------------------------------


def test_received_at_is_recent():
    """Decoded trap has a recent received_at timestamp."""
    trap_oid = (1, 3, 6, 1, 4, 1, 9586, 100, 5, 2, 10, 0, 2)
    raw = _make_synthetic_trap(trap_oid)
    before = time.time()
    listener = _make_listener("/tmp/fake.sock")
    event = listener._decode_trap(raw)
    after = time.time()

    assert event is not None
    assert before <= event.received_at <= after
