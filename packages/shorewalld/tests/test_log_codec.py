"""Tests for the worker↔parent NFLOG event codec."""

from __future__ import annotations

import pytest

from shorewalld.log_codec import (
    LOG_ENCODE_BUF_SIZE,
    LOG_HEADER_LEN,
    MAGIC_NFLOG,
    LogWireError,
    decode_log_event,
    encode_log_event_into,
)
from shorewalld.log_prefix import LogEvent


def _ev(**overrides) -> LogEvent:
    defaults = dict(
        chain="net-fw",
        disposition="DROP",
        rule_num=None,
        timestamp_ns=0,
        netns="",
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


def test_roundtrip_minimal():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    ev = _ev()
    mv = encode_log_event_into(buf, ev)
    got = decode_log_event(mv)
    assert got == ev


def test_roundtrip_with_rule_num():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    ev = _ev(rule_num=42, timestamp_ns=1_700_000_000_123_456_000)
    mv = encode_log_event_into(buf, ev)
    got = decode_log_event(mv)
    assert got == ev


def test_roundtrip_stamps_netns_at_decode_time():
    """The wire does not carry netns; the parent stamps it."""
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    ev_wire = _ev(netns="this-is-ignored-on-wire")
    mv = encode_log_event_into(buf, ev_wire)
    got = decode_log_event(mv, netns="fw-left")
    # Chain/disposition/rule_num/timestamp preserved; netns replaced.
    assert got.chain == ev_wire.chain
    assert got.disposition == ev_wire.disposition
    assert got.rule_num == ev_wire.rule_num
    assert got.timestamp_ns == ev_wire.timestamp_ns
    assert got.netns == "fw-left"


def test_header_length_matches_spec():
    """Regression guard: the header layout is wire-load-bearing."""
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    ev = _ev(chain="", disposition="")
    mv = encode_log_event_into(buf, ev)
    # Empty chain + disposition means the whole message IS the header.
    # Can happen if upstream parsers were lenient, so assert the size.
    assert len(mv) == LOG_HEADER_LEN


def test_magic_bytes_are_swlg_ascii():
    """MAGIC_NFLOG must decode as ASCII 'SWLG' — visible in strace."""
    assert MAGIC_NFLOG.to_bytes(4, "big") == b"SWLG"


def test_encoded_view_begins_with_magic():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    mv = encode_log_event_into(buf, _ev())
    assert bytes(mv[:4]) == b"SWLG"


def test_encode_writes_into_caller_buffer():
    """Encoder must not allocate a new buffer; view must slice *buf*."""
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    mv = encode_log_event_into(buf, _ev())
    # Flip a byte in buf at offset 4 (version), verify the view sees it.
    before = bytes(mv[4:6])
    buf[4] = (buf[4] + 1) & 0xFF
    after = bytes(mv[4:6])
    assert before != after


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_encode_rejects_overlong_chain():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    with pytest.raises(LogWireError, match="chain too long"):
        encode_log_event_into(buf, _ev(chain="x" * 256))


def test_encode_rejects_overlong_disposition():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    with pytest.raises(LogWireError, match="disposition too long"):
        encode_log_event_into(buf, _ev(disposition="y" * 256))


def test_encode_rejects_rule_num_out_of_u32_range():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    with pytest.raises(LogWireError, match="rule_num out of u32"):
        encode_log_event_into(buf, _ev(rule_num=2**33))


def test_encode_rejects_too_small_buffer():
    tiny = bytearray(LOG_HEADER_LEN + 2)
    with pytest.raises(LogWireError, match="encode buffer too small"):
        encode_log_event_into(tiny, _ev(chain="longerthanspace",
                                         disposition="AND-MORE"))


def test_decode_rejects_short_buffer():
    with pytest.raises(LogWireError, match="shorter than header"):
        decode_log_event(b"too-short")


def test_decode_rejects_wrong_magic():
    # 21 header bytes with wrong magic
    buf = bytearray(LOG_HEADER_LEN)
    buf[0:4] = b"XXXX"
    with pytest.raises(LogWireError, match="unexpected log-event magic"):
        decode_log_event(bytes(buf))


def test_decode_rejects_wrong_version():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    encode_log_event_into(buf, _ev())
    # Flip version at offset 4 (big-endian u16)
    buf[4] = 0xFF
    buf[5] = 0xFF
    with pytest.raises(LogWireError, match="unsupported log-event version"):
        decode_log_event(bytes(buf[:LOG_HEADER_LEN]))


def test_decode_rejects_truncated_body():
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    mv = encode_log_event_into(buf, _ev())
    # Lop off the last 2 bytes of the body; header claims more.
    truncated = bytes(mv)[:-2]
    with pytest.raises(LogWireError, match="truncated"):
        decode_log_event(truncated)


def test_encode_rule_num_zero_with_has_rulenum_true():
    """rule_num=0 is distinct from rule_num=None on the wire."""
    buf = bytearray(LOG_ENCODE_BUF_SIZE)
    ev = _ev(rule_num=0)
    mv = encode_log_event_into(buf, ev)
    got = decode_log_event(mv)
    assert got.rule_num == 0
