"""Auto-registered Prometheus families for the keepalived MIB.

:class:`KeepalivedCollector` is constructed once at daemon start (Commit 4
wires it into :class:`~shorewalld.exporter.ShorewalldRegistry`).  It
pre-builds one :class:`~shorewalld.exporter._MetricFamily` per
numeric-valued scalar / table column at construction time, then populates
samples from the last-good :class:`~shorewalld.keepalived.snmp_client.KeepalivedSnapshot`
on every scrape call.

Family-building rules
---------------------
* **Scalar OIDs** — every entry in :data:`~shorewalld.keepalived.mib.SCALARS`
  becomes ``shorewalld_keepalived_<name>`` (gauge, no labels) unless its
  SYNTAX is a string type (``DisplayString``, ``InetAddress``,
  ``InetAddressType``), in which case it is skipped.
* **Table columns** — every column in :data:`~shorewalld.keepalived.mib.TABLES`
  whose ``max_access`` is not ``"not-accessible"`` and whose SYNTAX is
  numeric:

  - ``Counter32`` / ``Counter64`` → counter family named
    ``shorewalld_keepalived_<colname>_total``.
  - Everything else numeric → gauge family named
    ``shorewalld_keepalived_<colname>``.
  - String SYNTAX → skipped.

  Labels are the table's ``index`` list (index-component values from
  ``row["__index__"]``).

Coercion
--------
:func:`_coerce_numeric` converts a stringified MIB value to ``float``.
Enum syntaxes like ``INTEGER { enabled(1), disabled(2) }`` store the
integer as the string ``"1"`` or ``"2"`` — ``int()`` works directly.
Empty strings and non-coercible values return ``None``; the sample is
skipped entirely (no NaN emitted).

Meta gauges (always emitted, even with no snapshot)
----------------------------------------------------
* ``shorewalld_keepalived_walks_total`` — dispatcher walk success count.
* ``shorewalld_keepalived_walk_errors_total`` — dispatcher walk failure count.
* ``shorewalld_keepalived_last_walk_age_seconds`` — ``time.time() - snap.collected_at``
  (omitted if no snapshot yet).
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Iterable

from shorewalld.exporter import CollectorBase, _MetricFamily
from shorewalld.keepalived import mib as _mib

if TYPE_CHECKING:
    from shorewalld.keepalived.dispatcher import KeepalivedDispatcher

# SYNTAX tokens that indicate a string value — skip these for Prometheus.
_STRING_SYNTAXES = frozenset({
    "DisplayString",
    "InetAddress",
    "InetAddressType",
    "InetPortNumber",
    "InterfaceIndex",
    "InetScopeType",
    "InetAddressPrefixLength",
})

# SYNTAX prefixes indicating Counter32/Counter64.
_COUNTER_RE = re.compile(r"^Counter(32|64)")

# Syntaxes we treat as numeric gauge (everything else numeric-ish).
# We accept:  Integer32, Unsigned32, Gauge32, TruthValue, VrrpState,
#             INTEGER { ... }, Realm, RouteType, EncapType, PrefType,
#             RuleAction, and any textual convention resolving to an int.
_GAUGE_RE = re.compile(
    r"^(Integer32|Unsigned32|Gauge32|TruthValue|VrrpState|INTEGER|"
    r"Realm|RouteType|EncapType|PrefType|RuleAction)"
)


def _syntax_is_string(syntax: str) -> bool:
    """Return True if the MIB SYNTAX denotes a string type."""
    base = syntax.split()[0]
    return base in _STRING_SYNTAXES


def _syntax_is_counter(syntax: str) -> bool:
    return bool(_COUNTER_RE.match(syntax))


def _syntax_is_numeric(syntax: str) -> bool:
    """Return True for any syntax that can be cast to a float."""
    if _syntax_is_string(syntax):
        return False
    base = syntax.split()[0]
    if base in _STRING_SYNTAXES:
        return False
    # Counters are also numeric.
    if _COUNTER_RE.match(syntax):
        return True
    if _GAUGE_RE.match(syntax):
        return True
    # Textual conventions from TEXTUAL_CONVENTIONS table.
    if base in _mib.TEXTUAL_CONVENTIONS:
        tc_syntax = _mib.TEXTUAL_CONVENTIONS[base]
        return _syntax_is_numeric(tc_syntax)
    return False


def _coerce_numeric(value: str, syntax: str) -> float | None:  # noqa: ARG001
    """Convert a stringified MIB value to float, or None on failure.

    *syntax* is accepted for documentation / future expansion but
    is not currently used in the coercion — the raw string-to-int/float
    path handles all integer-valued enums because net-snmp returns their
    numeric form.
    """
    if not value:
        return None
    try:
        return float(int(value))
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return None


class KeepalivedCollector(CollectorBase):
    """Prometheus collector that reads from a :class:`KeepalivedDispatcher`.

    Constructor pre-builds one :class:`~shorewalld.exporter._MetricFamily`
    per numeric scalar/column.  Each :meth:`collect` call re-populates
    the families from the current snapshot and yields them.

    The collector is intentionally **stateless between scrapes** — it
    rebuilds sample lists from scratch on every call.  This keeps memory
    bounded and avoids stale-sample artifacts when rows disappear.
    """

    def __init__(self, dispatcher: "KeepalivedDispatcher") -> None:
        # CollectorBase expects netns; keepalived is daemon-global.
        super().__init__(netns="")
        self._dispatcher = dispatcher
        self._families = self._build_families()

    def _build_families(self) -> dict[str, _MetricFamily]:
        """Pre-build metric families from the MIB tables.

        Returns a dict ``{family_name: _MetricFamily}`` for all
        numeric scalars and table columns.  Called once at construction.
        """
        fams: dict[str, _MetricFamily] = {}

        # --- Scalars ---------------------------------------------------
        for _oid, (name, syntax, _access) in _mib.SCALARS.items():
            if _syntax_is_string(syntax):
                continue
            if not _syntax_is_numeric(syntax):
                continue
            fam_name = f"shorewalld_keepalived_{name}"
            fams[fam_name] = _MetricFamily(
                name=fam_name,
                help_text=f"keepalived MIB scalar {name} ({syntax})",
                labels=[],
                mtype="gauge",
            )

        # --- Table columns ---------------------------------------------
        for table_name, tbl in _mib.TABLES.items():
            index_labels: list[str] = list(tbl["index"])
            for _col_num, (col_name, syntax, access) in tbl["columns"].items():
                if access == "not-accessible":
                    continue
                if _syntax_is_string(syntax):
                    continue
                if not _syntax_is_numeric(syntax):
                    continue
                is_counter = _syntax_is_counter(syntax)
                if is_counter:
                    fam_name = f"shorewalld_keepalived_{col_name}_total"
                    mtype = "counter"
                else:
                    fam_name = f"shorewalld_keepalived_{col_name}"
                    mtype = "gauge"
                # Multiple tables may share a column name (unlikely in
                # keepalived MIB, but guard against name collision).
                if fam_name not in fams:
                    fams[fam_name] = _MetricFamily(
                        name=fam_name,
                        help_text=(
                            f"keepalived MIB {table_name}.{col_name} ({syntax})"
                        ),
                        labels=index_labels,
                        mtype=mtype,
                    )
                # If already registered with same type — OK, samples merge.
                # If type mismatch (shouldn't happen in this MIB) — skip.

        return fams

    def collect(self) -> Iterable[_MetricFamily]:
        """Populate and yield metric families from the current snapshot.

        Called synchronously from the scrape thread.  Rebuilds samples
        from scratch; never emits NaN.
        """
        snap = self._dispatcher.snapshot()

        # --- Meta gauges (always emitted) ------------------------------
        walks_fam = _MetricFamily(
            "shorewalld_keepalived_walks_total",
            "Total successful keepalived MIB walks.",
            labels=[],
            mtype="gauge",
        )
        walks_fam.add([], float(self._dispatcher.walks_total()))
        yield walks_fam

        errors_fam = _MetricFamily(
            "shorewalld_keepalived_walk_errors_total",
            "Total keepalived MIB walks that raised an exception.",
            labels=[],
            mtype="gauge",
        )
        errors_fam.add([], float(self._dispatcher.walk_errors_total()))
        yield errors_fam

        if snap is not None:
            age_fam = _MetricFamily(
                "shorewalld_keepalived_last_walk_age_seconds",
                "Seconds since the last keepalived MIB walk completed.",
                labels=[],
                mtype="gauge",
            )
            age_fam.add([], time.time() - snap.collected_at)
            yield age_fam

        # --- Event counters (always emitted, single family with type label) ---
        events_counters = self._dispatcher.events_total()
        if events_counters:
            events_fam = _MetricFamily(
                "shorewalld_keepalived_events_total",
                "Total keepalived events received by type "
                "(trap_total, trap_decode_error, trap_<name>, "
                "dbus_total, dbus_signal_<signal>).",
                labels=["type"],
                mtype="counter",
            )
            for event_type, count in events_counters.items():
                events_fam.add([event_type], float(count))
            yield events_fam

        if snap is None:
            return

        # Reset sample lists — rebuild from current snapshot.
        populated: dict[str, _MetricFamily] = {}
        for fam_name, fam in self._families.items():
            fresh = _MetricFamily(
                name=fam.name,
                help_text=fam.help_text,
                labels=list(fam.labels),
                mtype=fam.mtype,
            )
            populated[fam_name] = fresh

        # --- Scalar samples --------------------------------------------
        for _oid, (name, syntax, _access) in _mib.SCALARS.items():
            fam_name = f"shorewalld_keepalived_{name}"
            fam = populated.get(fam_name)
            if fam is None:
                continue
            raw = snap.scalars.get(name)
            if raw is None:
                continue
            val = _coerce_numeric(raw, syntax)
            if val is None:
                continue
            fam.add([], val)

        # --- Table column samples -------------------------------------
        for table_name, tbl in _mib.TABLES.items():
            index_labels: list[str] = list(tbl["index"])
            n_labels = len(index_labels)
            rows = snap.tables.get(table_name) or []
            for row in rows:
                # Build label values from __index__ tuple.
                index_tuple: tuple[str, ...] = row.get("__index__", ())  # type: ignore[assignment]
                if len(index_tuple) != n_labels:
                    # Index arity mismatch (InetAddress multi-dot suffix).
                    # Pad with the raw string repeated / truncated.
                    raw_idx = row.get("__index_raw__", "")
                    label_values = [raw_idx] * n_labels
                else:
                    label_values = list(index_tuple)

                for _col_num, (col_name, syntax, access) in tbl["columns"].items():
                    if access == "not-accessible":
                        continue
                    if _syntax_is_string(syntax):
                        continue
                    if not _syntax_is_numeric(syntax):
                        continue
                    is_counter = _syntax_is_counter(syntax)
                    fam_name = (
                        f"shorewalld_keepalived_{col_name}_total"
                        if is_counter
                        else f"shorewalld_keepalived_{col_name}"
                    )
                    fam = populated.get(fam_name)
                    if fam is None:
                        continue
                    raw = row.get(col_name)
                    if raw is None:
                        continue
                    val = _coerce_numeric(raw, syntax)
                    if val is None:
                        continue
                    fam.add(label_values, val)

        # Yield only families that have at least one sample.
        for fam in populated.values():
            if fam.samples:
                yield fam
