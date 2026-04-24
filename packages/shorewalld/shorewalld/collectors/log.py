"""LogCollector — Prometheus surface for the NFLOG log dispatcher.

Exports two counter families from the parent-side
:class:`shorewalld.log_dispatcher.LogDispatcher`:

* ``shorewall_log_total{chain,disposition,netns}`` — one row per
  observed triple, monotonic.
* ``shorewall_log_dropped_total{reason}`` — visible backpressure (zero
  until M5 sinks land, kept in the contract from day one so operator
  dashboards don't need patching later).
* ``shorewall_log_events_total`` — grand total (label-free) so even
  operators who haven't grep'd their LOGFORMAT prefix yet can tell at
  a glance the dispatcher is ingesting.

No netns label on the collector itself (unlike most collectors here) —
the LogDispatcher is daemon-wide and events carry their netns inline.
"""

from __future__ import annotations

from shorewalld.exporter import CollectorBase, _MetricFamily
from shorewalld.log_dispatcher import LogDispatcher


class LogCollector(CollectorBase):
    """Surface the LogDispatcher counter snapshot for Prometheus scrape."""

    def __init__(self, dispatcher: LogDispatcher) -> None:
        # CollectorBase requires a netns; "" signals daemon-wide.
        super().__init__(netns="")
        self._dispatcher = dispatcher

    def collect(self) -> list[_MetricFamily]:
        total = _MetricFamily(
            "shorewall_log_total",
            "NFLOG events observed by shorewalld, by "
            "(chain, disposition, netns) — monotonic.",
            ["chain", "disposition", "netns"],
            mtype="counter",
        )
        snap = self._dispatcher.snapshot()
        for (chain, disp, netns), count in snap.items():
            total.add([chain, disp, netns], float(count))

        dropped = _MetricFamily(
            "shorewall_log_dropped_total",
            "NFLOG events dropped by the log dispatcher due to sink "
            "backpressure or queue overflow, by reason.",
            ["reason"],
            mtype="counter",
        )
        for reason, count in self._dispatcher.snapshot_dropped().items():
            dropped.add([reason], float(count))

        events_total = _MetricFamily(
            "shorewall_log_events_total",
            "NFLOG events received by the log dispatcher (label-free "
            "grand total; matches the sum over shorewall_log_total).",
            [],
            mtype="counter",
        )
        events_total.add([], float(self._dispatcher.events_total))

        return [total, dropped, events_total]
