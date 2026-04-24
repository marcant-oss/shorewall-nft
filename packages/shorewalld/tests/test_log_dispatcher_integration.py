"""End-to-end integration: worker-side NFLOG push → parent dispatcher.

Wires a real :class:`WorkerTransport` SEQPACKET pair between a
:class:`ParentWorker` instance and the test driver, registers the
dispatcher, sends encoded ``MAGIC_NFLOG`` datagrams from the "worker"
end, and asserts the counter + file/socket sinks received the event.

No fork, no setns, no kernel NFLOG traffic — the test drives the IPC
layer directly with synthesised ``LogEvent`` bytes, covering:

* :func:`log_codec.encode_log_event_into` → wire → ``peek_magic`` →
  ``MAGIC_NFLOG`` branch in :meth:`ParentWorker._drain_replies`
  → :meth:`LogDispatcher.on_event` → counter + sink enqueue.
* Netns-stamping from ``ParentWorker.netns`` (not the wire).
* File sink actually writes the line.
* Unix-socket sink fans out JSON to a connected client.
"""

from __future__ import annotations

import asyncio
import json

import pytest

# Resolve the collectors/exporter circular import (same pattern as
# test_vrrp_snmp.py, test_log_dispatcher_collector.py).
from shorewalld.exporter import _MetricFamily  # noqa: F401

from shorewalld.collectors.log import LogCollector
from shorewalld.log_codec import LOG_ENCODE_BUF_SIZE, encode_log_event_into
from shorewalld.log_dispatcher import LogDispatcher
from shorewalld.log_prefix import LogEvent
from shorewalld.worker_router import ParentWorker
from shorewalld.worker_transport import WorkerTransport


def _ev(**overrides) -> LogEvent:
    defaults = dict(
        chain="net-fw",
        disposition="DROP",
        rule_num=None,
        timestamp_ns=1_700_000_000_000_000_000,
        netns="irrelevant-wire-value",
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


async def _settle(loops: int = 20) -> None:
    """Yield to the event loop until pending callbacks drain."""
    for _ in range(loops):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_end_to_end_nflog_event_reaches_parent_counter():
    loop = asyncio.get_event_loop()
    dispatcher = LogDispatcher()
    await dispatcher.start()

    parent_t, worker_t = WorkerTransport.pair()
    pw = ParentWorker(
        netns="fw-left",
        tracker=None,
        loop=loop,
        log_dispatcher=dispatcher,
    )
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)

    try:
        # Craft a log-event datagram on the "worker" side and push it
        # to the parent via the SEQPACKET pair. The parent's reader
        # is hooked to _drain_replies which dispatches MAGIC_NFLOG.
        enc_buf = bytearray(LOG_ENCODE_BUF_SIZE)
        view = encode_log_event_into(
            enc_buf, _ev(chain="net-fw", disposition="DROP"))
        worker_t.send(view)
        # Parent-side callback runs in a future loop tick.
        await _settle()

        # Counter stamped with the router-side netns, not the wire's.
        snap = dispatcher.snapshot()
        assert snap == {("net-fw", "DROP", "fw-left"): 1}
        assert dispatcher.events_total == 1
    finally:
        loop.remove_reader(parent_t.fileno)
        parent_t.close()
        worker_t.close()
        await dispatcher.shutdown()


@pytest.mark.asyncio
async def test_end_to_end_populates_file_sink(tmp_path):
    loop = asyncio.get_event_loop()
    log_path = tmp_path / "shorewall.log"
    dispatcher = LogDispatcher(drop_file=str(log_path))
    await dispatcher.start()

    parent_t, worker_t = WorkerTransport.pair()
    pw = ParentWorker(
        netns="fw",
        tracker=None,
        loop=loop,
        log_dispatcher=dispatcher,
    )
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)

    try:
        enc_buf = bytearray(LOG_ENCODE_BUF_SIZE)
        for disp in ("DROP", "ACCEPT", "REJECT"):
            view = encode_log_event_into(
                enc_buf, _ev(disposition=disp))
            worker_t.send(view)
        await _settle()
    finally:
        loop.remove_reader(parent_t.fileno)
        parent_t.close()
        worker_t.close()
        await dispatcher.shutdown()

    lines = log_path.read_text(encoding="ascii").strip().split("\n")
    assert len(lines) == 3
    for line, disp in zip(lines, ("DROP", "ACCEPT", "REJECT")):
        assert f"disposition={disp}" in line
        assert "netns=fw" in line


@pytest.mark.asyncio
async def test_end_to_end_fans_out_to_socket_client(tmp_path):
    loop = asyncio.get_event_loop()
    sock_path = tmp_path / "log.sock"
    dispatcher = LogDispatcher(drop_socket_path=str(sock_path))
    await dispatcher.start()

    parent_t, worker_t = WorkerTransport.pair()
    pw = ParentWorker(
        netns="fw",
        tracker=None,
        loop=loop,
        log_dispatcher=dispatcher,
    )
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)

    try:
        reader, writer = await asyncio.open_unix_connection(str(sock_path))
        try:
            # Give the socket-sink server a tick to add us to _clients.
            await asyncio.sleep(0.02)

            enc_buf = bytearray(LOG_ENCODE_BUF_SIZE)
            view = encode_log_event_into(
                enc_buf, _ev(chain="blacklist", disposition="DROP",
                              rule_num=7))
            worker_t.send(view)
            line = await asyncio.wait_for(reader.readline(), timeout=1.0)
            obj = json.loads(line)
            assert obj["chain"] == "blacklist"
            assert obj["disposition"] == "DROP"
            assert obj["netns"] == "fw"
            assert obj["rule_num"] == 7
            assert obj["schema_version"] == 1
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
    finally:
        loop.remove_reader(parent_t.fileno)
        parent_t.close()
        worker_t.close()
        await dispatcher.shutdown()


@pytest.mark.asyncio
async def test_end_to_end_collector_surfaces_counter_and_events_total():
    loop = asyncio.get_event_loop()
    dispatcher = LogDispatcher()
    await dispatcher.start()
    collector = LogCollector(dispatcher)

    parent_t, worker_t = WorkerTransport.pair()
    pw = ParentWorker(
        netns="fw",
        tracker=None,
        loop=loop,
        log_dispatcher=dispatcher,
    )
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)

    try:
        enc_buf = bytearray(LOG_ENCODE_BUF_SIZE)
        # Five events split across two dispositions.
        for _ in range(3):
            worker_t.send(encode_log_event_into(
                enc_buf, _ev(disposition="DROP")))
        for _ in range(2):
            worker_t.send(encode_log_event_into(
                enc_buf, _ev(disposition="ACCEPT")))
        await _settle()
    finally:
        loop.remove_reader(parent_t.fileno)
        parent_t.close()
        worker_t.close()
        await dispatcher.shutdown()

    families = {f.name: f for f in collector.collect()}
    total = families["shorewall_log_total"]
    as_dict = {tuple(lbls): val for lbls, val in total.samples}
    assert as_dict == {
        ("net-fw", "DROP", "fw"): 3.0,
        ("net-fw", "ACCEPT", "fw"): 2.0,
    }
    events_total = families["shorewall_log_events_total"]
    assert events_total.samples == [([], 5.0)]


@pytest.mark.asyncio
async def test_parent_drops_nflog_silently_when_dispatcher_is_none():
    """Sanity: if the dispatcher was never attached, events just drop.

    This is the MAGIC_NFLOG branch's None-guard — protects against
    races where a worker delivers an event between the daemon starting
    and the dispatcher being attached.
    """
    loop = asyncio.get_event_loop()
    parent_t, worker_t = WorkerTransport.pair()
    pw = ParentWorker(
        netns="fw",
        tracker=None,
        loop=loop,
        log_dispatcher=None,  # <<
    )
    pw._transport = parent_t
    pw._child_pid = None
    loop.add_reader(parent_t.fileno, pw._drain_replies)

    try:
        enc_buf = bytearray(LOG_ENCODE_BUF_SIZE)
        worker_t.send(encode_log_event_into(enc_buf, _ev()))
        await _settle()
        # No crash, no ipc_errors. Just a silent drop.
        assert pw.metrics.ipc_errors_total == 0
    finally:
        loop.remove_reader(parent_t.fileno)
        parent_t.close()
        worker_t.close()


@pytest.mark.asyncio
async def test_worker_nowait_send_drops_when_parent_buffer_full():
    """Regression for backpressure contract: worker-side push uses
    send_nowait so a stuck parent drops events, not stalls the worker.

    We don't wire add_reader at all, so the parent never drains; then
    we hammer worker_t with send_nowait calls and assert some return
    False once the kernel's receive buffer fills.
    """
    parent_t, worker_t = WorkerTransport.pair()
    try:
        enc_buf = bytearray(LOG_ENCODE_BUF_SIZE)
        view = encode_log_event_into(enc_buf, _ev())
        accepted = 0
        dropped = 0
        # Loop enough times to fill any kernel receive buffer.
        # 10 000 × 30-byte datagrams = 300 KB; default SEQPACKET
        # buffer is 208 KB so we should see EAGAIN well before we
        # finish. Cap at 20 000 as a safety net.
        for _ in range(20_000):
            if worker_t.send_nowait(view):
                accepted += 1
            else:
                dropped += 1
                # As soon as we see one drop, we've proven backpressure.
                if dropped >= 1:
                    break
        assert dropped >= 1, (
            "send_nowait never returned False — kernel buffer must be "
            "larger than the test's spam count, bump the loop bound")
        assert accepted >= 1
    finally:
        parent_t.close()
        worker_t.close()
