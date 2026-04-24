"""Tests for :class:`LogDispatcher` + :class:`LogCollector`.

Full worker-IPC end-to-end integration lands in Commit 4 via
``inproc_worker_pair``; here we exercise the subsystem surface on its
own.
"""

from __future__ import annotations

import pytest

# Import shorewalld.exporter first to resolve the collectors/exporter
# circular import (same pattern as test_vrrp_snmp.py).
from shorewalld.exporter import _MetricFamily  # noqa: F401

from shorewalld.collectors.log import LogCollector
from shorewalld.log_dispatcher import LogDispatcher
from shorewalld.log_prefix import LogEvent


def _ev(chain="net-fw", disp="DROP", rule_num=None, ts=0, netns=""):
    return LogEvent(
        chain=chain, disposition=disp, rule_num=rule_num,
        timestamp_ns=ts, netns=netns,
    )


# ---------------------------------------------------------------------------
# LogDispatcher
# ---------------------------------------------------------------------------


def test_on_event_increments_labelled_counter():
    d = LogDispatcher()
    d.on_event(_ev(), "fw")
    d.on_event(_ev(), "fw")
    d.on_event(_ev(chain="loc-fw", disp="ACCEPT"), "fw")
    snap = d.snapshot()
    assert snap == {
        ("net-fw", "DROP", "fw"): 2,
        ("loc-fw", "ACCEPT", "fw"): 1,
    }


def test_on_event_uses_router_netns_not_event_netns():
    """on_event must stamp the router-provided netns, not ev.netns.

    Rationale: ParentWorker.netns is authoritative (operator-configured).
    The event's own ``netns`` field is an artefact of the wire codec
    stamping something at decode time.
    """
    d = LogDispatcher()
    d.on_event(_ev(netns="lying-netns"), "real-netns")
    snap = d.snapshot()
    assert snap == {("net-fw", "DROP", "real-netns"): 1}


def test_events_total_matches_sum_of_counter():
    d = LogDispatcher()
    for _ in range(5):
        d.on_event(_ev(), "fw-a")
    for _ in range(3):
        d.on_event(_ev(chain="loc-fw"), "fw-b")
    assert d.events_total == 8
    assert sum(d.snapshot().values()) == d.events_total


def test_snapshot_returns_a_copy_mutation_safe():
    d = LogDispatcher()
    d.on_event(_ev(), "fw")
    snap = d.snapshot()
    snap[("injected", "GARBAGE", "fw")] = 999
    # Mutating the snapshot must not leak into the dispatcher.
    assert ("injected", "GARBAGE", "fw") not in d.snapshot()


def test_dropped_snapshot_starts_empty():
    # M5 populates this; in Commit 2 it must always read empty.
    d = LogDispatcher()
    assert d.snapshot_dropped() == {}


@pytest.mark.asyncio
async def test_start_and_shutdown_are_safe_to_call():
    d = LogDispatcher()
    await d.start()
    await d.shutdown()  # also idempotent-safe
    await d.shutdown()


# ---------------------------------------------------------------------------
# LogCollector — shape, labels, values
# ---------------------------------------------------------------------------


def test_collector_emits_log_total_family_with_expected_labels():
    d = LogDispatcher()
    d.on_event(_ev(), "fw-a")
    d.on_event(_ev(disp="ACCEPT"), "fw-a")
    d.on_event(_ev(chain="loc-fw"), "fw-b")

    families = LogCollector(d).collect()
    by_name = {f.name: f for f in families}
    assert set(by_name) == {
        "shorewall_log_total",
        "shorewall_log_dropped_total",
        "shorewall_log_events_total",
    }

    total = by_name["shorewall_log_total"]
    assert total.mtype == "counter"
    assert total.labels == ["chain", "disposition", "netns"]
    as_dict = {tuple(lbls): val for lbls, val in total.samples}
    assert as_dict == {
        ("net-fw", "DROP", "fw-a"): 1.0,
        ("net-fw", "ACCEPT", "fw-a"): 1.0,
        ("loc-fw", "DROP", "fw-b"): 1.0,
    }


def test_collector_events_total_is_label_free_counter():
    d = LogDispatcher()
    for _ in range(7):
        d.on_event(_ev(), "fw")
    total = {f.name: f for f in LogCollector(d).collect()}[
        "shorewall_log_events_total"]
    assert total.mtype == "counter"
    assert total.labels == []
    assert total.samples == [([], 7.0)]


def test_collector_dropped_family_is_empty_until_m5():
    d = LogDispatcher()
    d.on_event(_ev(), "fw")
    families = {f.name: f for f in LogCollector(d).collect()}
    dropped = families["shorewall_log_dropped_total"]
    assert dropped.labels == ["reason"]
    assert dropped.samples == []


def test_collector_stable_when_no_events():
    """No events → families still emit (Prometheus can subscribe to
    a metric that is temporarily zero-sample).
    """
    d = LogDispatcher()
    families = LogCollector(d).collect()
    names = {f.name for f in families}
    assert {
        "shorewall_log_total",
        "shorewall_log_dropped_total",
        "shorewall_log_events_total",
    } <= names
    events_total = [f for f in families
                    if f.name == "shorewall_log_events_total"][0]
    assert events_total.samples == [([], 0.0)]
