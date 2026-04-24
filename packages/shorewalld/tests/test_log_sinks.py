"""End-to-end tests for the four LogDispatcher sinks.

Each sink is exercised behaviourally using tempfiles / in-process
socket servers — no systemd-journald, no real syslog daemon. The
drop-on-full contract (user directive 2026-04-24: sinks must never
block the hot path) is covered by a dedicated test that saturates a
sink queue with a synchronous ``put_nowait`` storm.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket

import pytest

from shorewalld.log_dispatcher import (
    SINK_QUEUE_DEPTH,
    LogDispatcher,
    _format_journal_datagram,
    _format_json_line,
    _format_plain_line,
    _format_syslog_datagram,
)
from shorewalld.log_prefix import LogEvent


def _ev(**overrides) -> LogEvent:
    defaults = dict(
        chain="net-fw",
        disposition="DROP",
        rule_num=None,
        timestamp_ns=1_700_000_000_500_000_000,
        netns="fw",
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


# ---------------------------------------------------------------------------
# Pure-formatter tests (no I/O)
# ---------------------------------------------------------------------------


def test_plain_line_format_has_expected_fields():
    out = _format_plain_line(_ev()).decode("ascii")
    assert out.endswith("\n")
    assert "netns=fw" in out
    assert "chain=net-fw" in out
    assert "disposition=DROP" in out
    assert "rule=" not in out  # rule_num is None → omit
    # ISO 8601 / RFC 3339 with millis — check shape, not exact value.
    assert "T" in out
    assert "Z" in out


def test_plain_line_omits_netns_as_dash_when_empty():
    out = _format_plain_line(_ev(netns="")).decode("ascii")
    assert "netns=-" in out


def test_plain_line_includes_rule_num_when_present():
    out = _format_plain_line(_ev(rule_num=42)).decode("ascii")
    assert "rule=42" in out


def test_json_line_parses_and_contains_schema_version():
    out = _format_json_line(_ev())
    obj = json.loads(out)
    assert obj["schema_version"] == 1
    assert obj["netns"] == "fw"
    assert obj["chain"] == "net-fw"
    assert obj["disposition"] == "DROP"
    assert "rule_num" not in obj


def test_json_line_includes_rule_num_when_present():
    obj = json.loads(_format_json_line(_ev(rule_num=7)))
    assert obj["rule_num"] == 7


def test_journal_datagram_has_required_journald_keys():
    out = _format_journal_datagram(_ev()).decode("utf-8")
    assert out.startswith("MESSAGE=")
    assert "\nPRIORITY=" in out
    assert "\nSYSLOG_IDENTIFIER=shorewalld\n" in out
    assert "\nSHOREWALL_CHAIN=net-fw\n" in out
    assert "\nSHOREWALL_DISPOSITION=DROP\n" in out
    assert out.endswith("\n")


def test_journal_priority_maps_from_disposition():
    assert b"PRIORITY=4" in _format_journal_datagram(_ev(disposition="DROP"))
    assert b"PRIORITY=4" in _format_journal_datagram(_ev(disposition="REJECT"))
    assert b"PRIORITY=6" in _format_journal_datagram(_ev(disposition="ACCEPT"))
    assert b"PRIORITY=5" in _format_journal_datagram(_ev(disposition="CUSTOM"))


def test_syslog_datagram_begins_with_pri_bracket():
    out = _format_syslog_datagram(_ev(), pid=123)
    assert out.startswith(b"<")
    # PRI = (LOCAL0 << 3) | WARNING = (16 << 3) | 4 = 132
    assert out.startswith(b"<132>")
    assert b"shorewalld[123]:" in out
    assert b"netns=fw" in out
    assert b"chain=net-fw" in out
    assert b"disposition=DROP" in out


def test_syslog_priority_maps_from_disposition():
    # ACCEPT → INFO = 6 → PRI = 134
    assert _format_syslog_datagram(_ev(disposition="ACCEPT"),
                                    pid=1).startswith(b"<134>")
    # DROP → WARNING = 4 → PRI = 132
    assert _format_syslog_datagram(_ev(disposition="DROP"),
                                    pid=1).startswith(b"<132>")


# ---------------------------------------------------------------------------
# File sink end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_sink_appends_line_per_event(tmp_path):
    log_path = tmp_path / "shorewall.log"
    d = LogDispatcher(drop_file=str(log_path))
    await d.start()
    d.on_event(_ev(chain="A"), "ns1")
    d.on_event(_ev(chain="B"), "ns2")
    # Sink consumer runs on the event loop — yield until drained.
    for _ in range(20):
        await asyncio.sleep(0)
    await d.shutdown()
    content = log_path.read_text(encoding="ascii")
    lines = content.strip().split("\n")
    assert len(lines) == 2
    assert "chain=A" in lines[0]
    assert "netns=ns1" in lines[0]
    assert "chain=B" in lines[1]
    assert "netns=ns2" in lines[1]


@pytest.mark.asyncio
async def test_file_sink_start_failure_does_not_raise(tmp_path):
    # Parent dir missing → open() fails. The dispatcher must keep
    # running, log a warning, and disable the sink silently.
    bad_path = tmp_path / "no" / "such" / "dir" / "out.log"
    d = LogDispatcher(drop_file=str(bad_path))
    await d.start()   # must not raise
    d.on_event(_ev(), "ns")
    assert d.events_total == 1
    await d.shutdown()


# ---------------------------------------------------------------------------
# Unix-socket sink end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unix_socket_sink_broadcasts_json_to_client(tmp_path):
    sock_path = tmp_path / "log.sock"
    d = LogDispatcher(drop_socket_path=str(sock_path))
    await d.start()
    try:
        reader, writer = await asyncio.open_unix_connection(str(sock_path))
        try:
            # Let the server finish adding us to _clients.
            await asyncio.sleep(0.02)
            d.on_event(_ev(chain="X", disposition="DROP"), "fw")
            line = await asyncio.wait_for(reader.readline(), timeout=1.0)
            obj = json.loads(line)
            assert obj["chain"] == "X"
            assert obj["disposition"] == "DROP"
            assert obj["netns"] == "fw"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    finally:
        await d.shutdown()


@pytest.mark.asyncio
async def test_unix_socket_sink_with_no_clients_drops_silently(tmp_path):
    # No client connected = broadcast loop still consumes events but
    # writes to nobody. Must not raise. Must not leak.
    sock_path = tmp_path / "log.sock"
    d = LogDispatcher(drop_socket_path=str(sock_path))
    await d.start()
    for _ in range(5):
        d.on_event(_ev(), "ns")
    for _ in range(20):
        await asyncio.sleep(0)
    await d.shutdown()


# ---------------------------------------------------------------------------
# Datagram (syslog / journald) sink end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_syslog_sink_sends_datagrams_to_peer(tmp_path):
    # In-process DGRAM server stands in for rsyslog / syslog-ng.
    peer_path = str(tmp_path / "syslog.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(peer_path)
    srv.setblocking(False)
    try:
        d = LogDispatcher(syslog_path=peer_path)
        await d.start()
        d.on_event(_ev(disposition="DROP"), "fw")
        d.on_event(_ev(disposition="ACCEPT"), "fw")
        # Yield so the sink loop drains its queue.
        datagrams = []
        for _ in range(100):
            await asyncio.sleep(0.01)
            try:
                while True:
                    data, _ = srv.recvfrom(4096)
                    datagrams.append(data)
            except BlockingIOError:
                if len(datagrams) >= 2:
                    break
        await d.shutdown()
    finally:
        srv.close()
        try:
            os.unlink(peer_path)
        except FileNotFoundError:
            pass
    assert len(datagrams) == 2
    # Both must start with the syslog PRI bracket.
    for dg in datagrams:
        assert dg.startswith(b"<")
        assert b"shorewalld[" in dg
    # First is DROP (WARNING=4, PRI=132); second ACCEPT (INFO=6, PRI=134).
    assert datagrams[0].startswith(b"<132>")
    assert datagrams[1].startswith(b"<134>")


@pytest.mark.asyncio
async def test_syslog_sink_unavailable_peer_disables_gracefully(tmp_path):
    # Peer path exists as a dir, not a socket → connect() EINVAL.
    bad = tmp_path / "not-a-socket"
    bad.mkdir()
    d = LogDispatcher(syslog_path=str(bad))
    await d.start()  # must not raise
    d.on_event(_ev(), "ns")
    assert d.events_total == 1
    await d.shutdown()


# ---------------------------------------------------------------------------
# Backpressure — the load-bearing user directive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_event_never_blocks_when_sink_queue_is_full(tmp_path):
    """Saturate a sink's queue and assert on_event keeps running.

    Regression guard for the hot-path drop-on-full contract
    (user directive 2026-04-24). We spam far more events than the
    queue can hold, WITHOUT awaiting — the sink consumer never runs
    because we never yield. Every event after SINK_QUEUE_DEPTH must
    drop, and on_event must remain O(1) per call.
    """
    # File sink is the easiest queue target (one consumer, one queue).
    d = LogDispatcher(drop_file=str(tmp_path / "spam.log"))
    await d.start()
    # Ensure the loop has a moment to wire the sink before we spam,
    # otherwise the first event arrives before the consumer task is
    # even created — fine behaviourally but noisy.
    await asyncio.sleep(0)

    spam = SINK_QUEUE_DEPTH * 4
    for _ in range(spam):
        d.on_event(_ev(), "fw")
    # All counter bumps must have landed — counters are cheap and
    # never back-pressured.
    assert d.events_total == spam
    # Drop snapshot must show the overflow.
    dropped = d.snapshot_dropped()
    assert dropped.get("sink_file", 0) >= spam - SINK_QUEUE_DEPTH - 32
    await d.shutdown()


@pytest.mark.asyncio
async def test_counter_path_is_independent_of_sink_failures(tmp_path):
    """Counter bumps happen even when every sink is broken.

    A sink crash or misconfiguration must not disable the
    Prometheus counter — operators need to see the event rate even
    when downstream pipelines are down.
    """
    bad_dir = tmp_path / "broken"
    bad_dir.mkdir()
    d = LogDispatcher(
        drop_file=str(tmp_path / "missing" / "nope.log"),
        syslog_path=str(bad_dir),  # dir, not socket → connect fails
    )
    await d.start()
    for _ in range(10):
        d.on_event(_ev(), "ns")
    assert d.events_total == 10
    snap = d.snapshot()
    assert snap[("net-fw", "DROP", "ns")] == 10
    await d.shutdown()


# ---------------------------------------------------------------------------
# LogDispatcher glue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_can_start_and_shutdown_with_no_sinks():
    """Counter-only mode: all sinks disabled, just Prometheus."""
    d = LogDispatcher()
    await d.start()
    d.on_event(_ev(), "ns")
    assert d.events_total == 1
    assert d.snapshot_dropped() == {}
    await d.shutdown()


@pytest.mark.asyncio
async def test_on_event_restamps_netns_from_router_label():
    """Regression: if the wire carries a different netns, the
    dispatcher must prefer the router-provided label (which comes
    from ParentWorker.netns — operator-configured)."""
    d = LogDispatcher()
    await d.start()
    d.on_event(_ev(netns="wire-said-this"), "router-says-this")
    assert d.snapshot() == {
        ("net-fw", "DROP", "router-says-this"): 1,
    }
    await d.shutdown()
