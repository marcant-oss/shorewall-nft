"""Tests for the Shorewall LOGFORMAT prefix parser."""

from __future__ import annotations

import pytest

from shorewalld.log_prefix import LogEvent, parse_log_prefix


def test_parse_default_format_two_segments():
    ev = parse_log_prefix(b"Shorewall:net-fw:DROP:")
    assert ev == LogEvent(
        chain="net-fw",
        disposition="DROP",
        rule_num=None,
        timestamp_ns=0,
        netns="",
    )


def test_parse_without_trailing_colon_still_accepted():
    # Some operators strip the trailing colon from LOGFORMAT.
    ev = parse_log_prefix(b"Shorewall:loc-fw:ACCEPT")
    assert ev is not None
    assert (ev.chain, ev.disposition) == ("loc-fw", "ACCEPT")


def test_parse_logrulenumbers_format_three_segments():
    ev = parse_log_prefix(b"Shorewall:net-fw:DROP:42:")
    assert ev is not None
    assert ev.chain == "net-fw"
    assert ev.disposition == "DROP"
    assert ev.rule_num == 42


def test_parse_logrulenumbers_without_trailing_colon():
    ev = parse_log_prefix(b"Shorewall:net-fw:DROP:42")
    assert ev is not None
    assert ev.rule_num == 42


def test_parse_propagates_timestamp_and_netns_verbatim():
    ev = parse_log_prefix(
        b"Shorewall:a:b:",
        timestamp_ns=1_700_000_001_234_567_000,
        netns="fw-left",
    )
    assert ev is not None
    assert ev.timestamp_ns == 1_700_000_001_234_567_000
    assert ev.netns == "fw-left"


def test_parse_accepts_memoryview_input():
    buf = bytearray(b"Shorewall:net-fw:REJECT:")
    ev = parse_log_prefix(memoryview(buf))
    assert ev is not None
    assert ev.disposition == "REJECT"


# ---------------------------------------------------------------------------
# Rejection cases — every malformation returns ``None``, never raises.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"a",
        b"Shorewall",              # tag only, no colon
        b"Shorewall:",             # empty body
        b"Shorewall::DROP:",       # empty chain
        b"Shorewall:net-fw::",     # empty disposition
        b"Shorewall:a:b:c:d:",     # too many segments (4+)
        b"NotShorewall:a:b:",      # wrong tag
        b"shorewall:a:b:",         # wrong case (Shorewall is case-sensitive)
        b"Shorewall:net-fw:DROP:notanumber:",   # bad rulenum
        b"\x00\x00\x00",           # garbage
    ],
)
def test_parse_rejects_malformed(raw):
    assert parse_log_prefix(raw) is None


def test_parse_rejects_none_input():
    assert parse_log_prefix(None) is None


def test_parse_rejects_non_ascii():
    # Non-ASCII chain name would poison Prom labels downstream.
    ev = parse_log_prefix("Shorewall:näet-fw:DROP:".encode("utf-8"))
    assert ev is None


def test_parse_handles_trailing_nul_gracefully():
    # NFULA_PREFIX usually strips NUL upstream, but accept both shapes.
    ev = parse_log_prefix(b"Shorewall:net-fw:DROP:\x00")
    assert ev is not None
    assert ev.disposition == "DROP"


def test_parse_overlong_segments_still_valid():
    chain = "a" * 200
    raw = f"Shorewall:{chain}:DROP:".encode("ascii")
    ev = parse_log_prefix(raw)
    assert ev is not None
    assert ev.chain == chain
