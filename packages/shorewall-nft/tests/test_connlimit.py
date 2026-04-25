"""Tests for WP-G2: CONNLIMIT column in rules.

Covers:
- Plain ``N`` form → ``ct count over N`` in nft output.
- ``N:mask`` CIDR form → ``ip saddr and <netmask> ct count over N``.
- Well-known CIDR boundaries (/24, /16, /32, /1).
- Multiple consecutive masks for correctness.
- No match emitted when connlimit is absent or blank.
"""
from __future__ import annotations

import pytest

from shorewall_nft.compiler.ir import (
    Rule,
    Verdict,
)
from shorewall_nft.nft.emitter import _emit_rule_lines


# ── helpers ────────────────────────────────────────────────────────────────


def _rule_with_connlimit(connlimit: str) -> Rule:
    return Rule(connlimit=connlimit, verdict=Verdict.ACCEPT)


def _single_stmt(connlimit: str) -> str:
    """Return the single emitted statement for a connlimit-only rule."""
    stmts = _emit_rule_lines(_rule_with_connlimit(connlimit))
    assert len(stmts) == 1, f"Expected 1 statement, got {stmts!r}"
    return stmts[0]


# ── plain form ──────────────────────────────────────────────────────────────


class TestPlainConnlimit:
    def test_plain_10(self):
        stmt = _single_stmt("10")
        assert "ct count over 10" in stmt
        assert "ip saddr" not in stmt

    def test_plain_3(self):
        stmt = _single_stmt("3")
        assert "ct count over 3" in stmt

    def test_plain_1(self):
        stmt = _single_stmt("1")
        assert "ct count over 1" in stmt

    def test_plain_large(self):
        stmt = _single_stmt("1000")
        assert "ct count over 1000" in stmt

    def test_accept_verdict(self):
        stmt = _single_stmt("5")
        assert "accept" in stmt


# ── CIDR mask form ──────────────────────────────────────────────────────────


class TestMaskedConnlimit:
    def test_mask_24(self):
        """/24 → 255.255.255.0."""
        stmt = _single_stmt("10:24")
        assert "ip saddr and 255.255.255.0 ct count over 10" in stmt

    def test_mask_16(self):
        """/16 → 255.255.0.0."""
        stmt = _single_stmt("10:16")
        assert "ip saddr and 255.255.0.0 ct count over 10" in stmt

    def test_mask_32(self):
        """/32 → 255.255.255.255 (per-host, same as plain)."""
        stmt = _single_stmt("5:32")
        assert "ip saddr and 255.255.255.255 ct count over 5" in stmt

    def test_mask_8(self):
        """/8 → 255.0.0.0."""
        stmt = _single_stmt("20:8")
        assert "ip saddr and 255.0.0.0 ct count over 20" in stmt

    def test_mask_1(self):
        """/1 → 128.0.0.0."""
        stmt = _single_stmt("50:1")
        assert "ip saddr and 128.0.0.0 ct count over 50" in stmt

    def test_mask_count_preserved(self):
        """Mask form: the count in ct count over is correct."""
        stmt = _single_stmt("7:24")
        assert "ct count over 7" in stmt

    def test_no_meter_for_connlimit(self):
        """connlimit must never produce a meter-drop guard."""
        stmts = _emit_rule_lines(_rule_with_connlimit("10:24"))
        assert all("meter" not in s for s in stmts)

    def test_accept_verdict_masked(self):
        stmt = _single_stmt("3:24")
        assert "accept" in stmt


# ── parametric boundary checks ─────────────────────────────────────────────


@pytest.mark.parametrize("cidr,expected_mask", [
    (24, "255.255.255.0"),
    (16, "255.255.0.0"),
    (8,  "255.0.0.0"),
    (32, "255.255.255.255"),
    (30, "255.255.255.252"),
    (20, "255.255.240.0"),
])
def test_cidr_mask_values(cidr: int, expected_mask: str):
    stmt = _single_stmt(f"5:{cidr}")
    assert expected_mask in stmt, (
        f"CIDR /{cidr}: expected {expected_mask!r} in {stmt!r}"
    )


# ── no-connlimit path ───────────────────────────────────────────────────────


class TestNoConnlimit:
    def test_none_connlimit_no_ct_count(self):
        rule = Rule(verdict=Verdict.ACCEPT)
        stmts = _emit_rule_lines(rule)
        assert len(stmts) == 1
        assert "ct count" not in stmts[0]

    def test_empty_string_connlimit(self):
        """Blank connlimit must not emit ct count (treated as absent)."""
        rule = Rule(connlimit="", verdict=Verdict.ACCEPT)
        stmts = _emit_rule_lines(rule)
        assert "ct count" not in stmts[0]


# ── action-form parser + capability gate (post-libnftnl follow-up) ─────────


import shutil  # noqa: E402

from shorewall_nft.compiler.ir import build_ir  # noqa: E402
from shorewall_nft.compiler.ir.rules import _parse_connlimit_params  # noqa: E402
from shorewall_nft.config.parser import load_config  # noqa: E402
from shorewall_nft.nft.emitter import emit_nft  # noqa: E402

MINIMAL_DIR = (
    __import__("pathlib").Path(__file__).parent / "configs" / "minimal"
)


class TestParseConnlimitParams:
    def test_bare_count(self):
        assert _parse_connlimit_params("10") == "10"

    def test_count_with_mask(self):
        assert _parse_connlimit_params("50:24") == "50:24"

    def test_invalid_returns_none(self):
        assert _parse_connlimit_params("") is None
        assert _parse_connlimit_params("notanumber") is None
        assert _parse_connlimit_params("10:") is None
        assert _parse_connlimit_params("10:24:5") is None


def _config_with_rule(tmp_path, rule_line: str):
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    rules = cfg / "rules"
    rules.write_text(rules.read_text() + "\n" + rule_line + "\n")
    return cfg


class TestConnlimitActionForm:
    def test_action_emits_ct_count(self, tmp_path):
        cfg = _config_with_rule(tmp_path, "CONNLIMIT(10)\tloc\tnet\ttcp\t80")
        ir = build_ir(load_config(cfg))
        out = emit_nft(ir)
        assert "ct count over 10" in out
        caps_required = {r.capability for r in ir.required_features}
        assert "has_connlimit" in caps_required

    def test_action_with_mask_emits_saddr_match(self, tmp_path):
        cfg = _config_with_rule(tmp_path, "CONNLIMIT(50:24)\tloc\tnet\ttcp\t80")
        ir = build_ir(load_config(cfg))
        out = emit_nft(ir)
        assert "ip saddr and 255.255.255.0 ct count over 50" in out

    def test_column_form_registers_capability(self, tmp_path):
        """The classic CONNLIMIT *column* now also registers has_connlimit."""
        rule = "ACCEPT\tloc\tnet\ttcp\t80\t-\t-\t-\t-\t-\t10:24"
        cfg = _config_with_rule(tmp_path, rule)
        ir = build_ir(load_config(cfg))
        out = emit_nft(ir)
        assert "ct count over 10" in out
        caps_required = {r.capability for r in ir.required_features}
        assert "has_connlimit" in caps_required

    def test_malformed_action_does_not_register_capability(self, tmp_path):
        """``CONNLIMIT(bogus)`` falls through; capability is NOT registered."""
        cfg = _config_with_rule(
            tmp_path, "CONNLIMIT(bogus)\tloc\tnet\ttcp\t80")
        ir = build_ir(load_config(cfg))
        caps_required = {r.capability for r in ir.required_features}
        assert "has_connlimit" not in caps_required
