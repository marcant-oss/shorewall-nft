"""Tests for the hand-rolled nfnetlink_log frame parser.

No kernel interaction: we synthesise NFULNL_MSG_PACKET frames from
canned bytes and assert :func:`shorewalld.nflog_netlink.parse_frame`
returns the expected :class:`NflogFrame` *and* that the resulting
``memoryview`` slices reference the input buffer (zero-copy contract).

The socket class itself is exercised behaviourally in the end-to-end
integration test (Commit 4) and manually on the test host (M0 gate);
its ``__init__`` opens a real ``AF_NETLINK`` fd which is covered by
import-time smoke only.
"""

from __future__ import annotations

import socket
import struct

import pytest

from shorewalld.nflog_netlink import (
    NFULA_IFINDEX_INDEV,
    NFULA_MARK,
    NFULA_PACKET_HDR,
    NFULA_PAYLOAD,
    NFULA_PREFIX,
    NFULA_TIMESTAMP,
    NFULNL_MSG_PACKET,
    NFULogSocket,
    NflogFrame,
    NflogWireError,
    parse_frame,
)


def _nla(ntype: int, payload: bytes) -> bytes:
    """Build one NLA (header + value + 4-byte alignment pad)."""
    length = 4 + len(payload)
    hdr = struct.pack("=HH", length, ntype)
    pad = b"\x00" * ((-length) & 3)
    return hdr + payload + pad


def _frame(*nlas: bytes, mtype: int = NFULNL_MSG_PACKET) -> bytes:
    """Build a complete NFULNL_MSG_PACKET netlink datagram."""
    nfgen = struct.pack("=BBH", socket.AF_INET, 0, socket.htons(0))
    body = nfgen + b"".join(nlas)
    hdr = struct.pack("=IHHII", 16 + len(body), mtype, 0, 1, 0)
    return hdr + body


# ---------------------------------------------------------------------------
# Happy path — every documented attribute decoded.
# ---------------------------------------------------------------------------


def test_parse_frame_full_attribute_set():
    pkt_hdr = struct.pack(">HBB", 0x0800, 1, 0)  # hw_proto, hook=INPUT, pad
    ts = struct.pack(">QQ", 1_700_000_000, 500_000)  # sec=1.7e9, usec=0.5ms
    payload_bytes = b"\x45\x00\x00\x28"  # truncated IPv4 header — realistic
    prefix = b"Shorewall:net-fw:DROP:\x00"
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, pkt_hdr),
        _nla(NFULA_TIMESTAMP, ts),
        _nla(NFULA_MARK, struct.pack(">I", 0xDEADBEEF)),
        _nla(NFULA_IFINDEX_INDEV, struct.pack(">I", 3)),
        _nla(NFULA_PREFIX, prefix),
        _nla(NFULA_PAYLOAD, payload_bytes),
    )
    buf = bytearray(frame_bytes)
    mv = memoryview(buf)

    frame = parse_frame(mv)

    assert isinstance(frame, NflogFrame)
    assert frame.hook == 1
    assert frame.hw_protocol == 0x0800
    assert frame.timestamp_ns == 1_700_000_000 * 1_000_000_000 + 500_000 * 1_000
    assert frame.mark == 0xDEADBEEF
    assert frame.indev == 3
    assert frame.outdev == 0  # absent → zero, not missing-key error
    assert frame.prefix_mv is not None
    assert frame.payload_mv is not None
    # NUL-terminator must be stripped so callers don't have to.
    assert bytes(frame.prefix_mv) == b"Shorewall:net-fw:DROP:"
    assert bytes(frame.payload_mv) == payload_bytes


# ---------------------------------------------------------------------------
# Zero-copy contract.
# ---------------------------------------------------------------------------


def test_parse_frame_prefix_is_zero_copy_view_of_input_buffer():
    prefix = b"Shorewall:loc-fw:ACCEPT:\x00"
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, struct.pack(">HBB", 0x86DD, 0, 0)),
        _nla(NFULA_PREFIX, prefix),
    )
    buf = bytearray(frame_bytes)
    mv = memoryview(buf)
    frame = parse_frame(mv)

    # The ``prefix_mv`` must be a slice of the caller's buffer — check by
    # mutating the buffer at the slice's offset and observing the change.
    assert frame.prefix_mv is not None
    before = bytes(frame.prefix_mv[:1])
    assert before == b"S"
    # Locate where "Shorewall:" starts in the buffer and flip a byte.
    start = frame_bytes.find(b"Shorewall:")
    assert start > 0
    buf[start] = ord(b"X")
    # Same memoryview — no copy — must reflect the mutation.
    assert bytes(frame.prefix_mv[:1]) == b"X"


def test_parse_frame_payload_is_zero_copy_view_of_input_buffer():
    payload = b"\xDE\xAD\xBE\xEF"
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, struct.pack(">HBB", 0x0800, 0, 0)),
        _nla(NFULA_PAYLOAD, payload),
    )
    buf = bytearray(frame_bytes)
    mv = memoryview(buf)
    frame = parse_frame(mv)
    assert frame.payload_mv is not None
    start = frame_bytes.find(payload)
    assert start > 0
    buf[start] = 0xFF
    assert bytes(frame.payload_mv[:1]) == b"\xff"


# ---------------------------------------------------------------------------
# Defaults when attributes are missing.
# ---------------------------------------------------------------------------


def test_parse_frame_missing_attributes_fill_zero_not_none_for_numerics():
    # Only the mandatory packet header — everything else absent.
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, struct.pack(">HBB", 0x0800, 2, 0)),
    )
    frame = parse_frame(memoryview(bytearray(frame_bytes)))

    assert frame.hook == 2
    assert frame.hw_protocol == 0x0800
    assert frame.timestamp_ns == 0
    assert frame.mark == 0
    assert frame.indev == 0
    assert frame.outdev == 0
    assert frame.uid == 0
    assert frame.gid == 0
    assert frame.prefix_mv is None
    assert frame.payload_mv is None


def test_parse_frame_unknown_attribute_silently_skipped():
    # Type 99 does not exist → must be skipped, not rejected (forward-compat).
    unknown = _nla(99, b"ignored")
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, struct.pack(">HBB", 0x0800, 0, 0)),
        unknown,
        _nla(NFULA_MARK, struct.pack(">I", 7)),
    )
    frame = parse_frame(memoryview(bytearray(frame_bytes)))
    assert frame.mark == 7


# ---------------------------------------------------------------------------
# Error paths — must raise NflogWireError, never silently pass garbage up.
# ---------------------------------------------------------------------------


def test_parse_frame_rejects_wrong_message_type():
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, struct.pack(">HBB", 0x0800, 0, 0)),
        mtype=2,  # NLMSG_ERROR
    )
    with pytest.raises(NflogWireError, match="unexpected nlmsg type"):
        parse_frame(memoryview(bytearray(frame_bytes)))


def test_parse_frame_rejects_short_buffer():
    # Only 12 bytes — shorter than nlmsg+nfgen header.
    with pytest.raises(NflogWireError, match="shorter than"):
        parse_frame(memoryview(bytearray(b"\x00" * 12)))


def test_parse_frame_rejects_nlmsg_len_exceeding_buffer():
    # Claim 100-byte message in a 40-byte buffer.
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, struct.pack(">HBB", 0x0800, 0, 0)),
    )
    buf = bytearray(frame_bytes)
    # Override nlmsg_len with a huge value.
    struct.pack_into("=I", buf, 0, 9999)
    with pytest.raises(NflogWireError, match="exceeds buffer"):
        parse_frame(memoryview(buf))


def test_parse_frame_rejects_nla_overflow():
    # Build a frame where the NLA claims to be 200 bytes long in a
    # buffer that only has ~30.
    buf = bytearray(_frame(_nla(NFULA_PACKET_HDR,
                                 struct.pack(">HBB", 0x0800, 0, 0))))
    # Append a malformed NLA (claims 200 bytes).
    bad_nla = struct.pack("=HH", 200, NFULA_MARK)
    nlmsg_len = len(buf) + len(bad_nla)
    buf.extend(bad_nla)
    struct.pack_into("=I", buf, 0, nlmsg_len)
    with pytest.raises(NflogWireError, match="overflows frame"):
        parse_frame(memoryview(buf))


def test_parse_frame_timestamp_truncated_raises():
    # NFULA_TIMESTAMP must carry 16 bytes; ship 8 and expect rejection.
    frame_bytes = _frame(
        _nla(NFULA_PACKET_HDR, struct.pack(">HBB", 0x0800, 0, 0)),
        _nla(NFULA_TIMESTAMP, b"\x00" * 8),
    )
    with pytest.raises(NflogWireError, match="NFULA_TIMESTAMP truncated"):
        parse_frame(memoryview(bytearray(frame_bytes)))


# ---------------------------------------------------------------------------
# Socket class smoke (no kernel traffic — just construct + close).
# ---------------------------------------------------------------------------


def test_nfulogsocket_construct_and_close_without_bind():
    # Opens the AF_NETLINK fd but never issues CFG_CMD_BIND → safe to run
    # anywhere, no CAP_NET_ADMIN needed, no kernel traffic.
    sock = NFULogSocket(group=0)
    try:
        assert sock.fileno() >= 0
    finally:
        sock.close()


def test_nfulogsocket_rejects_out_of_range_group():
    with pytest.raises(ValueError, match="out of range"):
        NFULogSocket(group=-1)
    with pytest.raises(ValueError, match="out of range"):
        NFULogSocket(group=0x10000)
