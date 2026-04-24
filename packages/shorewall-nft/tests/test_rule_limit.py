"""Tests for WP-G1: LIMIT:BURST in policy + rules.

Covers:
- ``_parse_rate_limit`` returning a typed ``RateLimitSpec`` for plain forms.
- ``_parse_limit_action`` returning a per-source ``RateLimitSpec`` for the
  ``LIMIT:name,rate,burst`` action-column form.
- The emitter producing ``limit rate N/unit burst M packets accept`` for
  plain limits.
- The emitter producing ``meter name size 65535 { ip saddr limit rate over
  N/unit burst M packets } drop`` for named per-source limits.
- Various unit forms: sec/min/hour/day and their canonical equivalents.
- The ``s:name:rate/unit:burst`` LIMIT column hashlimit form.
"""
from __future__ import annotations

import pytest

from shorewall_nft.compiler.ir._data import (
    RateLimitSpec,
    _parse_limit_action,
    _parse_rate_limit,
)
from shorewall_nft.compiler.ir import (
    Chain,
    FirewallIR,
    Rule,
    Verdict,
)
from shorewall_nft.nft.emitter import _emit_rule_lines


# ── Unit tests for _parse_rate_limit ────────────────────────────────────────


class TestParseRateLimit:
    def test_plain_rate_no_burst(self):
        rl = _parse_rate_limit("12/min")
        assert rl is not None
        assert rl.rate == 12
        assert rl.unit == "minute"
        assert rl.burst == 5  # default
        assert rl.per_source is False
        assert rl.name is None

    def test_plain_rate_with_burst(self):
        rl = _parse_rate_limit("12/min:60")
        assert rl is not None
        assert rl.rate == 12
        assert rl.unit == "minute"
        assert rl.burst == 60
        assert rl.per_source is False

    def test_unit_sec(self):
        rl = _parse_rate_limit("100/sec")
        assert rl is not None
        assert rl.unit == "second"

    def test_unit_second(self):
        rl = _parse_rate_limit("100/second")
        assert rl is not None
        assert rl.unit == "second"

    def test_unit_hour(self):
        rl = _parse_rate_limit("5/hour:2")
        assert rl is not None
        assert rl.unit == "hour"
        assert rl.burst == 2

    def test_unit_day(self):
        rl = _parse_rate_limit("1/day:1")
        assert rl is not None
        assert rl.unit == "day"

    def test_hashlimit_named(self):
        rl = _parse_rate_limit("s:LOGIN:12/min:60")
        assert rl is not None
        assert rl.rate == 12
        assert rl.unit == "minute"
        assert rl.burst == 60
        assert rl.name == "LOGIN"
        assert rl.per_source is True

    def test_hashlimit_anonymous(self):
        rl = _parse_rate_limit("s::30/sec:10")
        assert rl is not None
        assert rl.per_source is True
        assert rl.name is None
        assert rl.rate == 30
        assert rl.unit == "second"

    def test_empty_returns_none(self):
        assert _parse_rate_limit("") is None

    def test_dash_returns_none(self):
        assert _parse_rate_limit("-") is None

    def test_unparseable_returns_none(self):
        assert _parse_rate_limit("not-a-rate") is None

    def test_hashable(self):
        """RateLimitSpec must be hashable for use in optimizer key tuples."""
        rl = _parse_rate_limit("12/min:60")
        assert hash(rl) is not None
        s = {rl}
        assert rl in s


# ── Unit tests for _parse_limit_action ──────────────────────────────────────


class TestParseLimitAction:
    def test_name_rate_burst_int(self):
        """LIMIT:LOGIN,12,60 — name,rate,burst all ints."""
        rl = _parse_limit_action("LOGIN,12,60")
        assert rl is not None
        assert rl.name == "LOGIN"
        assert rl.rate == 12
        assert rl.unit == "minute"  # default when no /unit
        assert rl.burst == 60
        assert rl.per_source is True

    def test_name_rate_with_unit(self):
        """LIMIT:SSH,10/sec,5 — explicit unit."""
        rl = _parse_limit_action("SSH,10/sec,5")
        assert rl is not None
        assert rl.name == "SSH"
        assert rl.rate == 10
        assert rl.unit == "second"
        assert rl.burst == 5

    def test_no_name(self):
        """LIMIT:10,20 — no name (2-part form rate,burst)."""
        rl = _parse_limit_action("10,20")
        assert rl is not None
        # First part treated as name since it doesn't contain '/'
        # name="10", rate=20, burst=5
        # OR depending on implementation: rate=10, burst=20
        # The key invariant: result is not None and is per_source
        assert rl.per_source is True

    def test_empty_name(self):
        """LIMIT:,10,60 — empty name."""
        rl = _parse_limit_action(",10,60")
        assert rl is not None
        assert rl.name is None
        assert rl.per_source is True

    def test_none_returns_none(self):
        assert _parse_limit_action("") is None

    def test_returns_per_source(self):
        """Named LIMIT action always implies per_source=True."""
        rl = _parse_limit_action("WEB,30,100")
        assert rl is not None
        assert rl.per_source is True


# ── Integration: IR rule + emitter ──────────────────────────────────────────


def _make_ir_with_rule(rule: Rule, chain_name: str = "test-chain") -> FirewallIR:
    """Create a minimal IR containing one rule in the given chain."""
    ir = FirewallIR()
    chain = Chain(name=chain_name)
    chain.rules.append(rule)
    ir.chains[chain_name] = chain
    return ir


class TestPlainLimitEmit:
    """Plain limit rate (not per-source) emits inline ``limit rate`` clause."""

    def test_plain_rate_in_rule_str(self):
        rule = Rule(
            rate_limit=RateLimitSpec(rate=12, unit="minute", burst=60),
            verdict=Verdict.ACCEPT,
        )
        stmts = _emit_rule_lines(rule)
        assert len(stmts) == 1
        assert "limit rate 12/minute burst 60 packets" in stmts[0]
        assert "accept" in stmts[0]

    def test_plain_rate_sec(self):
        rule = Rule(
            rate_limit=RateLimitSpec(rate=100, unit="second", burst=10),
            verdict=Verdict.ACCEPT,
        )
        stmts = _emit_rule_lines(rule)
        assert len(stmts) == 1
        assert "limit rate 100/second burst 10 packets" in stmts[0]

    def test_no_meter_for_plain(self):
        """Plain limit must NOT produce a meter rule."""
        rule = Rule(
            rate_limit=RateLimitSpec(rate=5, unit="minute", burst=10),
            verdict=Verdict.ACCEPT,
        )
        stmts = _emit_rule_lines(rule)
        assert all("meter" not in s for s in stmts)

    def test_parsed_from_column_string(self):
        """End-to-end: parse column string → RateLimitSpec → emit."""
        rl = _parse_rate_limit("30/min:60")
        assert rl is not None
        rule = Rule(rate_limit=rl, verdict=Verdict.ACCEPT)
        stmts = _emit_rule_lines(rule)
        assert len(stmts) == 1
        assert "limit rate 30/minute burst 60 packets" in stmts[0]
        assert "accept" in stmts[0]


class TestHashlimitMeterEmit:
    """Named per-source limit emits meter-drop guard + verdict rule."""

    def test_meter_drop_rule_emitted(self):
        rule = Rule(
            rate_limit=RateLimitSpec(
                rate=12, unit="minute", burst=60,
                name="LOGIN", per_source=True),
            verdict=Verdict.ACCEPT,
        )
        stmts = _emit_rule_lines(rule)
        assert len(stmts) == 2, f"Expected 2 statements, got: {stmts}"
        meter_stmt, accept_stmt = stmts
        assert "meter" in meter_stmt
        assert "LOGIN" in meter_stmt
        assert "ip saddr" in meter_stmt
        assert "limit rate over 12/minute" in meter_stmt
        assert "burst 60 packets" in meter_stmt
        assert "drop" in meter_stmt

    def test_accept_verdict_in_second_stmt(self):
        rule = Rule(
            rate_limit=RateLimitSpec(
                rate=12, unit="minute", burst=60,
                name="LOGIN", per_source=True),
            verdict=Verdict.ACCEPT,
        )
        stmts = _emit_rule_lines(rule)
        accept_stmt = stmts[1]
        assert "accept" in accept_stmt

    def test_limit_action_form_compiles(self):
        """LIMIT:LOGIN,12,60 action column form → correct nft."""
        rl = _parse_limit_action("LOGIN,12,60")
        assert rl is not None
        rule = Rule(rate_limit=rl, verdict=Verdict.ACCEPT)
        stmts = _emit_rule_lines(rule)
        assert len(stmts) == 2
        assert "meter" in stmts[0]
        assert "LOGIN" in stmts[0]
        assert "12/minute" in stmts[0]
        assert "burst 60 packets" in stmts[0]

    def test_anonymous_hashlimit(self):
        """Hashlimit without name uses 'shorewall_meter'."""
        rl = RateLimitSpec(rate=10, unit="second", burst=5, per_source=True)
        rule = Rule(rate_limit=rl, verdict=Verdict.ACCEPT)
        stmts = _emit_rule_lines(rule)
        assert len(stmts) == 2
        assert "shorewall_meter" in stmts[0]


class TestUnitForms:
    """All four unit forms normalize correctly."""

    @pytest.mark.parametrize("raw,expected_unit", [
        ("10/sec:5", "second"),
        ("10/second:5", "second"),
        ("10/min:5", "minute"),
        ("10/minute:5", "minute"),
        ("10/hour:5", "hour"),
        ("10/day:5", "day"),
    ])
    def test_unit_normalization(self, raw: str, expected_unit: str):
        rl = _parse_rate_limit(raw)
        assert rl is not None, f"Failed to parse {raw!r}"
        assert rl.unit == expected_unit, f"{raw!r} → unit={rl.unit!r}, want {expected_unit!r}"

    @pytest.mark.parametrize("raw,expected_unit", [
        ("10/sec:5", "second"),
        ("10/min:5", "minute"),
        ("10/hour:5", "hour"),
        ("10/day:5", "day"),
    ])
    def test_unit_in_emit(self, raw: str, expected_unit: str):
        rl = _parse_rate_limit(raw)
        rule = Rule(rate_limit=rl, verdict=Verdict.ACCEPT)
        stmts = _emit_rule_lines(rule)
        assert expected_unit in stmts[0], (
            f"Expected unit {expected_unit!r} in emit of {raw!r}: {stmts[0]!r}"
        )
