"""Tests for KeepalivedCollector and helper functions in metrics.py.

Sync collector tests only — no asyncio.  MIB is patched via monkeypatch
where needed to keep tests small; most tests use the real mib.py.
"""

from __future__ import annotations

import time

import pytest

from shorewalld.keepalived.snmp_client import KeepalivedSnapshot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_snapshot(
    scalars: dict | None = None,
    tables: dict | None = None,
    walk_errors: tuple = (),
) -> KeepalivedSnapshot:
    from shorewalld.keepalived import mib
    return KeepalivedSnapshot(
        scalars=scalars or {},
        tables=tables or {name: [] for name in mib.TABLES},
        collected_at=time.time(),
        walk_errors=walk_errors,
    )


class _StubDispatcher:
    """Minimal dispatcher stub for metrics tests."""

    def __init__(
        self,
        snap: KeepalivedSnapshot | None = None,
        walks: int = 0,
        errors: int = 0,
    ) -> None:
        self._snap = snap
        self._walks = walks
        self._errors = errors

    def snapshot(self) -> KeepalivedSnapshot | None:
        return self._snap

    def walks_total(self) -> int:
        return self._walks

    def walk_errors_total(self) -> int:
        return self._errors

    def snapshot_counters(self) -> dict[str, int]:
        return {"walk_ok": self._walks, "walk_error": self._errors}


# ---------------------------------------------------------------------------
# Test 1: _coerce_numeric
# ---------------------------------------------------------------------------


def test_coerce_numeric_empty_returns_none():
    from shorewalld.keepalived.metrics import _coerce_numeric
    assert _coerce_numeric("", "INTEGER") is None


def test_coerce_numeric_integer_string():
    from shorewalld.keepalived.metrics import _coerce_numeric
    assert _coerce_numeric("42", "Integer32") == 42.0


def test_coerce_numeric_enum_value():
    from shorewalld.keepalived.metrics import _coerce_numeric
    # INTEGER { enabled(1), disabled(2) } — net-snmp returns "1"
    assert _coerce_numeric("1", "INTEGER { enabled(1), disabled(2) }") == 1.0


def test_coerce_numeric_truthvalue():
    from shorewalld.keepalived.metrics import _coerce_numeric
    assert _coerce_numeric("1", "TruthValue") == 1.0
    assert _coerce_numeric("2", "TruthValue") == 2.0


def test_coerce_numeric_float_string():
    from shorewalld.keepalived.metrics import _coerce_numeric
    assert _coerce_numeric("3.14", "Gauge32") == pytest.approx(3.14)


def test_coerce_numeric_non_numeric_returns_none():
    from shorewalld.keepalived.metrics import _coerce_numeric
    assert _coerce_numeric("notanumber", "DisplayString") is None


# ---------------------------------------------------------------------------
# Test 2: _syntax_is_string / _syntax_is_counter / _syntax_is_numeric
# ---------------------------------------------------------------------------


def test_syntax_helpers():
    from shorewalld.keepalived.metrics import (
        _syntax_is_counter,
        _syntax_is_numeric,
        _syntax_is_string,
    )
    assert _syntax_is_string("DisplayString")
    assert _syntax_is_string("InetAddress")
    assert not _syntax_is_string("Integer32")
    assert not _syntax_is_string("TruthValue")
    assert _syntax_is_counter("Counter32 UNITS \"packets\"")
    assert _syntax_is_counter("Counter64")
    assert not _syntax_is_counter("Gauge32")
    assert _syntax_is_numeric("Gauge32")
    assert _syntax_is_numeric("Integer32")
    assert _syntax_is_numeric("TruthValue")
    assert _syntax_is_numeric("VrrpState")
    assert _syntax_is_numeric("INTEGER { enabled(1), disabled(2) }")
    assert not _syntax_is_numeric("DisplayString")
    assert not _syntax_is_numeric("InetAddress")


# ---------------------------------------------------------------------------
# Test 3: _build_families — family names and types
# ---------------------------------------------------------------------------


def test_build_families_scalar_gauge(monkeypatch):
    """Scalar 'trapEnable' → gauge family shorewalld_keepalived_trapEnable."""
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    # trapEnable has syntax "INTEGER { enabled(1), disabled(2) }" → gauge
    fam = collector._families.get("shorewalld_keepalived_trapEnable")
    assert fam is not None
    assert fam.mtype == "gauge"
    assert fam.labels == []


def test_build_families_counter_column():
    """Counter32/Counter64 columns → counter family with _total suffix."""
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    # virtualServerStatsInPkts has Counter32 syntax
    fam = collector._families.get(
        "shorewalld_keepalived_virtualServerStatsInPkts_total"
    )
    assert fam is not None
    assert fam.mtype == "counter"


def test_build_families_gauge_column():
    """Gauge32 columns → plain gauge family without _total."""
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    # virtualServerStatsConns has Gauge32 syntax
    fam = collector._families.get("shorewalld_keepalived_virtualServerStatsConns")
    assert fam is not None
    assert fam.mtype == "gauge"


def test_build_families_string_column_skipped():
    """DisplayString columns must NOT appear in the families dict."""
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    # vrrpInstanceName is DisplayString — must be skipped
    assert "shorewalld_keepalived_vrrpInstanceName" not in collector._families


def test_build_families_not_accessible_column_skipped():
    """not-accessible columns must NOT appear in the families dict."""
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    # vrrpInstanceIndex is not-accessible
    assert "shorewalld_keepalived_vrrpInstanceIndex" not in collector._families


def test_build_families_vrrpstate_is_gauge():
    """VrrpState SYNTAX → gauge."""
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    fam = collector._families.get("shorewalld_keepalived_vrrpInstanceState")
    assert fam is not None
    assert fam.mtype == "gauge"


def test_build_families_table_index_labels():
    """vrrpInstanceTable columns have label ['vrrpInstanceIndex']."""
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    # vrrpInstanceState is in vrrpInstanceTable with index ['vrrpInstanceIndex']
    fam = collector._families.get("shorewalld_keepalived_vrrpInstanceState")
    assert fam is not None
    assert fam.labels == ["vrrpInstanceIndex"]


# ---------------------------------------------------------------------------
# Test 4: collect() with no snapshot yields only meta gauges
# ---------------------------------------------------------------------------


def test_collect_no_snapshot_yields_meta_gauges():
    from shorewalld.keepalived.metrics import KeepalivedCollector

    dispatcher = _StubDispatcher(snap=None, walks=5, errors=2)
    collector = KeepalivedCollector(dispatcher)

    families = list(collector.collect())
    names = {f.name for f in families}

    assert "shorewalld_keepalived_walks_total" in names
    assert "shorewalld_keepalived_walk_errors_total" in names
    # No age gauge when no snapshot
    assert "shorewalld_keepalived_last_walk_age_seconds" not in names
    # Verify values
    walks_fam = next(f for f in families
                     if f.name == "shorewalld_keepalived_walks_total")
    assert walks_fam.samples[0][1] == 5.0
    errors_fam = next(f for f in families
                      if f.name == "shorewalld_keepalived_walk_errors_total")
    assert errors_fam.samples[0][1] == 2.0


# ---------------------------------------------------------------------------
# Test 5: collect() with snapshot populates scalar gauge
# ---------------------------------------------------------------------------


def test_collect_scalar_gauge_populated():
    from shorewalld.keepalived.metrics import KeepalivedCollector

    # trapEnable=1 (enabled) → shorewalld_keepalived_trapEnable = 1.0
    snap = _make_snapshot(scalars={"trapEnable": "1"})
    dispatcher = _StubDispatcher(snap=snap, walks=1)
    collector = KeepalivedCollector(dispatcher)

    families = {f.name: f for f in collector.collect()}
    fam = families.get("shorewalld_keepalived_trapEnable")
    assert fam is not None
    assert len(fam.samples) == 1
    assert fam.samples[0][1] == 1.0
    assert fam.samples[0][0] == []  # no labels for scalars


# ---------------------------------------------------------------------------
# Test 6: collect() with table row populates counter + labels
# ---------------------------------------------------------------------------


def test_collect_table_counter_with_labels():
    from shorewalld.keepalived.metrics import KeepalivedCollector

    row = {
        "__index_raw__": "1",
        "__index__": ("1",),
        "virtualServerStatsInPkts": "42",
        "virtualServerStatsConns": "5",
    }
    from shorewalld.keepalived import mib
    tables = {name: [] for name in mib.TABLES}
    tables["virtualServerTable"] = [row]
    snap = _make_snapshot(tables=tables)
    dispatcher = _StubDispatcher(snap=snap, walks=1)
    collector = KeepalivedCollector(dispatcher)

    families = {f.name: f for f in collector.collect()}

    # Counter32 column
    counter_fam = families.get(
        "shorewalld_keepalived_virtualServerStatsInPkts_total"
    )
    assert counter_fam is not None
    assert counter_fam.samples[0][1] == 42.0
    # Label values = ("1",) for virtualServerIndex
    assert counter_fam.samples[0][0] == ["1"]

    # Gauge32 column
    gauge_fam = families.get("shorewalld_keepalived_virtualServerStatsConns")
    assert gauge_fam is not None
    assert gauge_fam.samples[0][1] == 5.0


# ---------------------------------------------------------------------------
# Test 7: collect() skips rows with non-coercible values
# ---------------------------------------------------------------------------


def test_collect_skips_non_numeric_value():
    from shorewalld.keepalived.metrics import KeepalivedCollector

    # If value is empty string, the sample should be dropped.
    row = {
        "__index_raw__": "1",
        "__index__": ("1",),
        "vrrpInstanceState": "",  # empty → skip
    }
    from shorewalld.keepalived import mib
    tables = {name: [] for name in mib.TABLES}
    tables["vrrpInstanceTable"] = [row]
    snap = _make_snapshot(tables=tables)
    dispatcher = _StubDispatcher(snap=snap, walks=1)
    collector = KeepalivedCollector(dispatcher)

    families = {f.name: f for f in collector.collect()}
    fam = families.get("shorewalld_keepalived_vrrpInstanceState")
    # Either not present (no samples) or present with 0 samples.
    if fam is not None:
        assert fam.samples == []


# ---------------------------------------------------------------------------
# Test 8: last_walk_age_seconds is emitted when snapshot is present
# ---------------------------------------------------------------------------


def test_collect_age_gauge_emitted():
    from shorewalld.keepalived.metrics import KeepalivedCollector

    snap = _make_snapshot()
    dispatcher = _StubDispatcher(snap=snap, walks=1)
    collector = KeepalivedCollector(dispatcher)

    families = {f.name: f for f in collector.collect()}
    age_fam = families.get("shorewalld_keepalived_last_walk_age_seconds")
    assert age_fam is not None
    assert len(age_fam.samples) == 1
    age_val = age_fam.samples[0][1]
    assert isinstance(age_val, float)
    assert age_val >= 0.0
    assert age_val < 5.0  # Should be essentially instant in tests.


# ---------------------------------------------------------------------------
# Test 9: family discovery with a minimal monkeypatched MIB overlay
# ---------------------------------------------------------------------------


def test_build_families_with_minimal_mib(monkeypatch):
    """Use a tiny synthetic SCALARS/TABLES to verify family wiring."""
    import shorewalld.keepalived.mib as mib_mod
    from shorewalld.keepalived.metrics import KeepalivedCollector

    fake_scalars = {
        "9.9.9.1": ("myScalar", "Gauge32", "read-only"),
        "9.9.9.2": ("myString", "DisplayString", "read-only"),
    }
    fake_tables = {
        "myTable": {
            "oid": "9.9.9.3",
            "entry_name": "myEntry",
            "entry_oid": "9.9.9.3.1",
            "index": ["myIdx"],
            "columns": {
                1: ("myIdx", "Integer32 (1..100)", "not-accessible"),
                2: ("myCounter", "Counter32", "read-only"),
                3: ("myGauge", "Gauge32", "read-only"),
                4: ("myStr", "DisplayString", "read-only"),
            },
        },
    }
    monkeypatch.setattr(mib_mod, "SCALARS", fake_scalars)
    monkeypatch.setattr(mib_mod, "TABLES", fake_tables)

    dispatcher = _StubDispatcher()
    collector = KeepalivedCollector(dispatcher)

    assert "shorewalld_keepalived_myScalar" in collector._families
    assert collector._families["shorewalld_keepalived_myScalar"].mtype == "gauge"
    # String scalar skipped
    assert "shorewalld_keepalived_myString" not in collector._families
    # Counter column
    assert "shorewalld_keepalived_myCounter_total" in collector._families
    assert collector._families["shorewalld_keepalived_myCounter_total"].mtype == "counter"
    # Gauge column
    assert "shorewalld_keepalived_myGauge" in collector._families
    # String column skipped
    assert "shorewalld_keepalived_myStr" not in collector._families
    # not-accessible index skipped
    assert "shorewalld_keepalived_myIdx" not in collector._families
    # Labels from index
    assert collector._families["shorewalld_keepalived_myCounter_total"].labels == ["myIdx"]
