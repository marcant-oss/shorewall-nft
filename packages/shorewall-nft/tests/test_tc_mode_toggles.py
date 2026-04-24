"""Tests for TC mode toggle settings: TC_ENABLED, TC_EXPERT,
MARK_IN_FORWARD_CHAIN, CLEAR_TC.

Each test asserts that the correct branch fires for each combination.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft.compiler.tc import (
    TcInterface,
    TcPri,
    _clear_tc,
    _mark_in_forward,
    _tc_enabled_mode,
    _tc_expert,
    apply_tcinterfaces,
    emit_clear_tc_shell,
    emit_tcinterfaces_shell,
    emit_tcpri_nft,
)


# ── TC_ENABLED ────────────────────────────────────────────────────────────────

class TestTcEnabledMode:

    def test_default_is_internal(self):
        assert _tc_enabled_mode({}) == "Internal"

    def test_internal_explicit(self):
        assert _tc_enabled_mode({"TC_ENABLED": "Internal"}) == "Internal"

    def test_no_returns_empty_string(self):
        assert _tc_enabled_mode({"TC_ENABLED": "No"}) == ""

    def test_yes_returns_yes(self):
        assert _tc_enabled_mode({"TC_ENABLED": "Yes"}) == "Yes"

    def test_shared_returns_shared(self):
        assert _tc_enabled_mode({"TC_ENABLED": "Shared"}) == "Shared"

    def test_case_insensitive_internal(self):
        assert _tc_enabled_mode({"TC_ENABLED": "INTERNAL"}) == "Internal"

    def test_case_insensitive_no(self):
        assert _tc_enabled_mode({"TC_ENABLED": "NO"}) == ""

    def test_case_insensitive_yes(self):
        assert _tc_enabled_mode({"TC_ENABLED": "YES"}) == "Yes"

    def test_case_insensitive_shared(self):
        assert _tc_enabled_mode({"TC_ENABLED": "SHARED"}) == "Shared"


class TestTcEnabledEffectOnEmit:
    """TC_ENABLED branches control shell emit and apply."""

    _devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]

    def test_internal_emits_tbf(self):
        out = emit_tcinterfaces_shell(self._devs, {"TC_ENABLED": "Internal"})
        assert "tbf" in out

    def test_no_emits_nothing(self):
        out = emit_tcinterfaces_shell(self._devs, {"TC_ENABLED": "No"})
        assert out == ""

    def test_yes_emits_nothing(self):
        out = emit_tcinterfaces_shell(self._devs, {"TC_ENABLED": "Yes"})
        assert out == ""

    def test_shared_emits_nothing(self):
        out = emit_tcinterfaces_shell(self._devs, {"TC_ENABLED": "Shared"})
        assert out == ""

    def test_no_skips_apply(self):
        fake = MagicMock()
        fake.link_lookup.return_value = [2]
        fake.close = MagicMock()
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(self._devs, {"TC_ENABLED": "No"})
        fake.tc.assert_not_called()
        assert result.applied == 0

    def test_shared_skips_apply(self):
        fake = MagicMock()
        fake.link_lookup.return_value = [2]
        fake.close = MagicMock()
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(self._devs, {"TC_ENABLED": "Shared"})
        fake.tc.assert_not_called()

    def test_yes_skips_apply(self):
        fake = MagicMock()
        fake.link_lookup.return_value = [2]
        fake.close = MagicMock()
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(self._devs, {"TC_ENABLED": "Yes"})
        fake.tc.assert_not_called()

    def test_tcpri_nft_no_returns_empty(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        assert emit_tcpri_nft(tcpris, {"TC_ENABLED": "No"}) == ""

    def test_tcpri_nft_internal_emits_mark_rule(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {"TC_ENABLED": "Internal"})
        assert "meta mark set 1" in out

    def test_tcpri_nft_yes_emits_mark_rule(self):
        """TC_ENABLED=Yes: only mark rules, operator manages qdiscs."""
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {"TC_ENABLED": "Yes"})
        assert "meta mark set 1" in out


# ── TC_EXPERT ─────────────────────────────────────────────────────────────────

class TestTcExpert:

    def test_default_is_false(self):
        assert _tc_expert({}) is False

    def test_yes_is_true(self):
        assert _tc_expert({"TC_EXPERT": "Yes"}) is True

    def test_no_is_false(self):
        assert _tc_expert({"TC_EXPERT": "No"}) is False

    def test_case_insensitive(self):
        assert _tc_expert({"TC_EXPERT": "YES"}) is True
        assert _tc_expert({"TC_EXPERT": "yes"}) is True

    def test_numeric_1_is_true(self):
        assert _tc_expert({"TC_EXPERT": "1"}) is True


# ── MARK_IN_FORWARD_CHAIN ─────────────────────────────────────────────────────

class TestMarkInForwardChain:

    def test_default_is_false(self):
        assert _mark_in_forward({}) is False

    def test_yes_is_true(self):
        assert _mark_in_forward({"MARK_IN_FORWARD_CHAIN": "Yes"}) is True

    def test_no_is_false(self):
        assert _mark_in_forward({"MARK_IN_FORWARD_CHAIN": "No"}) is False

    def test_emit_uses_mangle_prerouting_by_default(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {})
        assert "mangle-prerouting" in out

    def test_emit_uses_forward_when_enabled(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {"MARK_IN_FORWARD_CHAIN": "Yes"})
        assert "forward" in out
        assert "mangle-prerouting" not in out


# ── CLEAR_TC ──────────────────────────────────────────────────────────────────

class TestClearTc:

    def test_default_is_false(self):
        assert _clear_tc({}) is False

    def test_yes_is_true(self):
        assert _clear_tc({"CLEAR_TC": "Yes"}) is True

    def test_no_is_false(self):
        assert _clear_tc({"CLEAR_TC": "No"}) is False

    def test_emit_no_teardown_by_default(self):
        devs = [TcInterface(interface="eth0")]
        out = emit_clear_tc_shell(devs, {})
        assert out == ""

    def test_emit_teardown_when_clear_tc_yes(self):
        devs = [TcInterface(interface="eth0")]
        out = emit_clear_tc_shell(devs, {"CLEAR_TC": "Yes"})
        assert "tc qdisc del dev eth0 root" in out
        assert "tc qdisc del dev eth0 ingress" in out

    def test_shell_emit_includes_del_when_clear_tc_yes(self):
        """emit_tcinterfaces_shell always includes the del lines (pre-clean)."""
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        out = emit_tcinterfaces_shell(devs, {"TC_ENABLED": "Internal", "CLEAR_TC": "Yes"})
        # The shell emit always pre-cleans; CLEAR_TC=Yes also appends in generate-tc.
        assert "qdisc del" in out


# ── Full matrix: all four toggles ────────────────────────────────────────────

class TestToggleMatrix:
    """Parametrized matrix over TC_ENABLED × TC_EXPERT × MARK_IN_FORWARD_CHAIN × CLEAR_TC."""

    @pytest.mark.parametrize("tc_enabled,expect_emit", [
        ("Internal", True),
        ("No", False),
        ("Yes", False),
        ("Shared", False),
    ])
    def test_tc_enabled_shell_emit(self, tc_enabled, expect_emit):
        devs = [TcInterface(interface="eth0", out_bandwidth="5mbit")]
        out = emit_tcinterfaces_shell(devs, {"TC_ENABLED": tc_enabled})
        if expect_emit:
            assert "tbf" in out
        else:
            assert out == ""

    @pytest.mark.parametrize("tc_enabled,expect_mark", [
        ("Internal", True),
        ("No", False),
        ("Yes", True),
        ("Shared", True),
    ])
    def test_tc_enabled_nft_mark_emit(self, tc_enabled, expect_mark):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {"TC_ENABLED": tc_enabled})
        if expect_mark:
            assert "meta mark set 1" in out
        else:
            assert out == ""

    @pytest.mark.parametrize("mark_in_fwd,expected_chain", [
        ("No", "mangle-prerouting"),
        ("Yes", "forward"),
    ])
    def test_mark_in_forward_chain_matrix(self, mark_in_fwd, expected_chain):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {"MARK_IN_FORWARD_CHAIN": mark_in_fwd})
        assert expected_chain in out

    @pytest.mark.parametrize("clear_tc,expect_del", [
        ("No", False),
        ("Yes", True),
    ])
    def test_clear_tc_matrix(self, clear_tc, expect_del):
        devs = [TcInterface(interface="eth0")]
        out = emit_clear_tc_shell(devs, {"CLEAR_TC": clear_tc})
        if expect_del:
            assert "qdisc del" in out
        else:
            assert out == ""
