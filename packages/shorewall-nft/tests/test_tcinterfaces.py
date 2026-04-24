"""Tests for tcinterfaces parsing, shell emit, and pyroute2 apply path.

Patching strategy: apply_tcinterfaces() imports pyroute2 lazily inside
the function body.  We patch at the pyroute2 package level so that the
``from pyroute2 import IPRoute`` statement picks up the mock.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft.compiler.tc import (
    TcInterface,
    apply_tcinterfaces,
    emit_clear_tc_shell,
    emit_tcinterfaces_shell,
    parse_tcinterfaces,
)
from shorewall_nft.config.parser import ConfigLine


# ── helpers ──────────────────────────────────────────────────────────────────

def _line(cols: list[str], lineno: int = 1) -> ConfigLine:
    return ConfigLine(columns=cols, file="tcinterfaces", lineno=lineno)


def _make_fake_ipr(*, del_raises_enoent: bool = False) -> MagicMock:
    from pyroute2.netlink.exceptions import NetlinkError

    fake = MagicMock()
    fake.link_lookup.return_value = [3]
    fake.close = MagicMock()

    if del_raises_enoent:
        _del_count = {"n": 0}

        def _tc_side(op, kind, *args, **kwargs):
            if op == "del":
                _del_count["n"] += 1
                if _del_count["n"] <= 2:
                    raise NetlinkError(2)
            return MagicMock()

        fake.tc.side_effect = _tc_side
    else:
        fake.tc.return_value = MagicMock()

    return fake


# ── parse_tcinterfaces ────────────────────────────────────────────────────────

class TestParseTcinterfaces:

    def test_external_type_maps_to_nfct_src(self):
        lines = [_line(["eth0", "external", "100mbit", "50mbit"])]
        result = parse_tcinterfaces(lines)
        assert len(result) == 1
        assert result[0].flow_type == "nfct-src"

    def test_internal_type_maps_to_dst(self):
        lines = [_line(["eth1", "internal", "-", "20mbit"])]
        result = parse_tcinterfaces(lines)
        assert len(result) == 1
        assert result[0].flow_type == "dst"

    def test_dash_type_maps_to_dash(self):
        lines = [_line(["eth2", "-", "-", "10mbit"])]
        result = parse_tcinterfaces(lines)
        assert len(result) == 1
        assert result[0].flow_type == "-"

    def test_in_bandwidth_captured(self):
        lines = [_line(["eth0", "external", "100mbit", "-"])]
        result = parse_tcinterfaces(lines)
        assert result[0].in_bandwidth == "100mbit"

    def test_in_bandwidth_dash_becomes_empty(self):
        lines = [_line(["eth0", "-", "-", "10mbit"])]
        result = parse_tcinterfaces(lines)
        assert result[0].in_bandwidth == ""

    def test_out_bandwidth_parsed(self):
        lines = [_line(["eth0", "-", "-", "50mbit"])]
        result = parse_tcinterfaces(lines)
        assert result[0].out_bandwidth == "50mbit"

    def test_out_bandwidth_burst_latency_suffix(self):
        lines = [_line(["eth0", "-", "-", "50mbit:20kb:100ms"])]
        result = parse_tcinterfaces(lines)
        dev = result[0]
        assert dev.out_bandwidth == "50mbit"
        assert dev.out_burst == "20kb"
        assert dev.out_latency == "100ms"

    def test_out_bandwidth_peak_minburst(self):
        lines = [_line(["eth0", "-", "-", "50mbit:20kb:100ms:60mbit:1540"])]
        result = parse_tcinterfaces(lines)
        dev = result[0]
        assert dev.out_peak == "60mbit"
        assert dev.out_minburst == "1540"

    def test_burst_defaults_when_omitted(self):
        lines = [_line(["eth0", "-", "-", "10mbit"])]
        result = parse_tcinterfaces(lines)
        assert result[0].out_burst == "10kb"
        assert result[0].out_latency == "200ms"

    def test_interface_dash_skipped(self):
        lines = [_line(["-", "-", "-", "10mbit"])]
        result = parse_tcinterfaces(lines)
        assert result == []

    def test_empty_lines_skipped(self):
        result = parse_tcinterfaces([])
        assert result == []

    def test_multiple_rows(self):
        lines = [
            _line(["eth0", "external", "100mbit", "50mbit"], 1),
            _line(["eth1", "internal", "-", "20mbit"], 2),
        ]
        result = parse_tcinterfaces(lines)
        assert len(result) == 2
        assert result[0].interface == "eth0"
        assert result[1].interface == "eth1"


# ── emit_tcinterfaces_shell ──────────────────────────────────────────────────

class TestEmitTcinterfacesShell:

    def test_empty_list_returns_empty(self):
        assert emit_tcinterfaces_shell([]) == ""

    def test_tc_enabled_no_returns_empty(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        assert emit_tcinterfaces_shell(devs, {"TC_ENABLED": "No"}) == ""

    def test_tc_enabled_shared_returns_empty(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        assert emit_tcinterfaces_shell(devs, {"TC_ENABLED": "Shared"}) == ""

    def test_tc_enabled_yes_returns_empty(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        assert emit_tcinterfaces_shell(devs, {"TC_ENABLED": "Yes"}) == ""

    def test_internal_mode_emits_tbf(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        out = emit_tcinterfaces_shell(devs, {"TC_ENABLED": "Internal"})
        assert "tbf" in out
        assert "eth0" in out
        assert "10mbit" in out

    def test_ingress_emitted_when_in_bandwidth_set(self):
        devs = [TcInterface(interface="eth0", in_bandwidth="100mbit")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "ingress" in out
        assert "100mbit" in out

    def test_default_mode_is_internal(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="5mbit")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "tbf" in out

    def test_prio_bands_emitted(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "prio" in out
        assert "sfq" in out

    def test_fw_filters_emitted(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "fw" in out

    def test_flow_filter_emitted_when_flow_type_set(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit", flow_type="nfct-src")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "flow hash keys nfct-src" in out

    def test_flow_filter_omitted_when_flow_type_dash(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit", flow_type="-")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "flow hash keys" not in out

    def test_up_check_included(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="5mbit")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "ip link show eth0" in out

    def test_peak_included_when_set(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit", out_peak="12mbit")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "peakrate 12mbit" in out

    def test_peak_omitted_when_empty(self):
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit", out_peak="")]
        out = emit_tcinterfaces_shell(devs, {})
        assert "peakrate" not in out


# ── emit_clear_tc_shell ──────────────────────────────────────────────────────

class TestEmitClearTcShell:

    def test_clear_tc_no_returns_empty(self):
        devs = [TcInterface(interface="eth0")]
        assert emit_clear_tc_shell(devs, {"CLEAR_TC": "No"}) == ""

    def test_clear_tc_default_returns_empty(self):
        devs = [TcInterface(interface="eth0")]
        assert emit_clear_tc_shell(devs, {}) == ""

    def test_clear_tc_yes_emits_del_commands(self):
        devs = [TcInterface(interface="eth0")]
        out = emit_clear_tc_shell(devs, {"CLEAR_TC": "Yes"})
        assert "tc qdisc del dev eth0 root" in out
        assert "tc qdisc del dev eth0 ingress" in out

    def test_clear_tc_multiple_ifaces(self):
        devs = [TcInterface(interface="eth0"), TcInterface(interface="eth1")]
        out = emit_clear_tc_shell(devs, {"CLEAR_TC": "Yes"})
        assert "eth0" in out
        assert "eth1" in out


# ── apply_tcinterfaces ───────────────────────────────────────────────────────

class TestApplyTcinterfacesCallSequence:

    def test_empty_list_no_ipr_calls(self):
        fake = _make_fake_ipr()
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces([])
        fake.tc.assert_not_called()
        assert result.applied == 0
        assert result.failed == 0

    def test_tc_enabled_no_skips_apply(self):
        fake = _make_fake_ipr()
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(devs, {"TC_ENABLED": "No"})
        fake.tc.assert_not_called()
        assert result.applied == 0

    def test_tc_enabled_shared_skips_apply(self):
        fake = _make_fake_ipr()
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(devs, {"TC_ENABLED": "Shared"})
        fake.tc.assert_not_called()

    def test_out_bandwidth_triggers_tbf_add(self):
        fake = _make_fake_ipr()
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(devs, {"TC_ENABLED": "Internal"})
        assert result.failed == 0
        assert result.applied > 0
        ops = [c[0][0] for c in fake.tc.call_args_list]
        kinds = [c[0][1] for c in fake.tc.call_args_list]
        assert "tbf" in kinds

    def test_in_bandwidth_triggers_ingress_add(self):
        fake = _make_fake_ipr()
        devs = [TcInterface(interface="eth0", in_bandwidth="100mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(devs, {})
        assert result.failed == 0
        kinds = [c[0][1] for c in fake.tc.call_args_list]
        assert "ingress" in kinds

    def test_missing_interface_records_error(self):
        fake = MagicMock()
        fake.link_lookup.return_value = []
        fake.close = MagicMock()
        devs = [TcInterface(interface="notexist", out_bandwidth="10mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(devs, {})
        assert result.failed > 0
        assert any("not found" in e for e in result.errors)

    def test_enoent_on_del_is_ignored(self):
        fake = _make_fake_ipr(del_raises_enoent=True)
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(devs, {})
        assert result.failed == 0

    def test_close_called_on_success(self):
        fake = _make_fake_ipr()
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            apply_tcinterfaces(devs, {})
        fake.close.assert_called_once()

    def test_netns_kwarg_passed_to_iproute(self):
        fake = _make_fake_ipr()
        with patch("pyroute2.IPRoute", return_value=fake) as mock_cls:
            apply_tcinterfaces([], netns="fw")
        mock_cls.assert_called_once_with(netns="fw")

    def test_pyroute2_not_installed_returns_error(self):
        import sys
        saved = {k: v for k, v in sys.modules.items() if k.startswith("pyroute2")}
        for k in list(saved):
            sys.modules.pop(k, None)
        try:
            with patch.dict("sys.modules",
                            {"pyroute2": None,
                             "pyroute2.netlink": None,
                             "pyroute2.netlink.exceptions": None}):
                result = apply_tcinterfaces([TcInterface(interface="eth0", out_bandwidth="1mbit")])
        finally:
            sys.modules.update(saved)
        assert len(result.errors) >= 1
        assert result.applied == 0

    def test_sfq_and_fw_filter_added_per_band(self):
        fake = _make_fake_ipr()
        devs = [TcInterface(interface="eth0", out_bandwidth="10mbit")]
        with patch("pyroute2.IPRoute", return_value=fake):
            result = apply_tcinterfaces(devs, {})
        assert result.failed == 0
        ops = [c[0][0] for c in fake.tc.call_args_list]
        kinds = [c[0][1] for c in fake.tc.call_args_list]
        assert "sfq" in kinds
        assert "add-filter" in ops


# ── integration (require root) ───────────────────────────────────────────────

skip_no_root = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="requires root for real-netns TC operations",
)


@skip_no_root
class TestApplyTcinterfacesRealNetns:

    def test_apply_creates_tbf_qdisc(self, tmp_path):
        import subprocess
        ns = "swnft-tci-test"
        veth = "tci-test-v0"
        try:
            subprocess.run(["ip", "netns", "add", ns], check=True)
            subprocess.run(
                ["ip", "netns", "exec", ns, "ip", "link", "add", veth, "type", "dummy"],
                check=True)
            subprocess.run(
                ["ip", "netns", "exec", ns, "ip", "link", "set", veth, "up"],
                check=True)

            devs = [TcInterface(interface=veth, out_bandwidth="10mbit")]
            result = apply_tcinterfaces(devs, {"TC_ENABLED": "Internal"}, netns=ns)
            assert result.failed == 0, result.errors
            assert result.applied > 0
        finally:
            subprocess.run(["ip", "netns", "del", ns], check=False)
