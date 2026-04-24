"""Unit tests for shorewall_nft.verify.tc_validate.

All tests are pure-logic: no network namespaces, no root, no real tc binary.
Functions that touch netns (validate_sysctl, validate_routing,
validate_nft_loaded) are covered by patching ``_ns`` and ``load_config``/
``generate_sysctl_script`` where needed.  The core TC path (validate_tc,
parse_tc_config, emit_tc_commands) is tested by constructing minimal
ShorewalConfig/ConfigLine stubs in memory.

Patch targets are in the canonical netkit location
(``shorewall_nft_netkit.validators.tc_validate``) because the implementation
moved there in Phase II.  The ``shorewall_nft.verify.tc_validate`` module is a
thin re-export shim that tests continue to import from — assertions are
unchanged.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch


from shorewall_nft.compiler.tc import (
    TcClass,
    TcConfig,
    TcDevice,
    emit_tc_commands,
    parse_tc_config,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.verify.tc_validate import (
    ValidationResult,
    validate_nft_loaded,
    validate_routing,
    validate_sysctl,
    validate_tc,
)

# Canonical patch target — implementation lives in netkit after Phase II.
_NS_PATCH = "shorewall_nft_netkit.validators.tc_validate._ns"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _make_config_line(columns: list[str]) -> ConfigLine:
    return ConfigLine(columns=columns, file="test", lineno=1)


def _make_stub_config(
    *,
    tcdevices: list[list[str]] | None = None,
    tcclasses: list[list[str]] | None = None,
    tcfilters: list[list[str]] | None = None,
):
    """Build a minimal ShorewalConfig-like object with only TC fields."""
    cfg = MagicMock()
    cfg.tcdevices = [_make_config_line(cols) for cols in (tcdevices or [])]
    cfg.tcclasses = [_make_config_line(cols) for cols in (tcclasses or [])]
    cfg.tcfilters = [_make_config_line(cols) for cols in (tcfilters or [])]
    return cfg


# ---------------------------------------------------------------------------
# ValidationResult dataclass
# ---------------------------------------------------------------------------

class TestValidationResult:
    def test_fields_accessible(self):
        r = ValidationResult(name="tc:generate", passed=True, detail="ok")
        assert r.name == "tc:generate"
        assert r.passed is True
        assert r.detail == "ok"

    def test_failed_variant(self):
        r = ValidationResult(name="sysctl:foo", passed=False, detail="mismatch")
        assert not r.passed

    def test_equality(self):
        a = ValidationResult(name="x", passed=True, detail="d")
        b = ValidationResult(name="x", passed=True, detail="d")
        assert a == b


# ---------------------------------------------------------------------------
# parse_tc_config (pure, no I/O)
# ---------------------------------------------------------------------------

class TestParseTcConfig:
    def test_empty_config_produces_empty_tc(self):
        cfg = _make_stub_config()
        tc = parse_tc_config(cfg)
        assert tc.devices == []
        assert tc.classes == []
        assert tc.filters == []

    def test_device_parsed_correctly(self):
        cfg = _make_stub_config(
            tcdevices=[["eth0", "100mbit", "10mbit"]]
        )
        tc = parse_tc_config(cfg)
        assert len(tc.devices) == 1
        dev = tc.devices[0]
        assert dev.interface == "eth0"
        assert dev.in_bandwidth == "100mbit"
        assert dev.out_bandwidth == "10mbit"

    def test_device_with_dash_bandwidth_is_empty_string(self):
        """'-' bandwidth placeholders must become empty string (no tc command emitted)."""
        cfg = _make_stub_config(
            tcdevices=[["bond1", "-", "-"]]
        )
        tc = parse_tc_config(cfg)
        dev = tc.devices[0]
        assert dev.in_bandwidth == ""
        assert dev.out_bandwidth == ""

    def test_device_short_row_skipped(self):
        """Rows with fewer than 3 columns are silently dropped."""
        cfg = _make_stub_config(
            tcdevices=[["eth0", "100mbit"]]  # only 2 cols
        )
        tc = parse_tc_config(cfg)
        assert tc.devices == []

    def test_class_parsed_correctly(self):
        cfg = _make_stub_config(
            tcclasses=[["eth0", "10", "5mbit", "10mbit", "2"]]
        )
        tc = parse_tc_config(cfg)
        assert len(tc.classes) == 1
        cls = tc.classes[0]
        assert cls.interface == "eth0"
        assert cls.mark == 10
        assert cls.rate == "5mbit"
        assert cls.ceil == "10mbit"
        assert cls.priority == 2

    def test_class_non_integer_mark_skipped(self):
        """Non-numeric mark field: the row is silently skipped."""
        cfg = _make_stub_config(
            tcclasses=[["eth0", "notanumber", "5mbit", "10mbit"]]
        )
        tc = parse_tc_config(cfg)
        assert tc.classes == []

    def test_filter_parsed_correctly(self):
        cfg = _make_stub_config(
            tcfilters=[["eth0:10", "192.168.1.0/24", "-", "tcp", "80"]]
        )
        tc = parse_tc_config(cfg)
        assert len(tc.filters) == 1
        flt = tc.filters[0]
        assert flt.tc_class == "eth0:10"
        assert flt.source == "192.168.1.0/24"
        assert flt.proto == "tcp"
        assert flt.dport == "80"

    def test_filter_minimal_one_column(self):
        """A single-column filter row is accepted (tc_class only)."""
        cfg = _make_stub_config(
            tcfilters=[["eth0:5"]]
        )
        tc = parse_tc_config(cfg)
        assert len(tc.filters) == 1
        assert tc.filters[0].tc_class == "eth0:5"
        assert tc.filters[0].source == "-"


# ---------------------------------------------------------------------------
# emit_tc_commands (pure, no I/O)
# ---------------------------------------------------------------------------

class TestEmitTcCommands:
    def test_empty_config_produces_header_only(self):
        tc = TcConfig()
        script = emit_tc_commands(tc)
        assert script.startswith("#!/bin/sh")
        assert "tc qdisc" not in script
        assert "tc class" not in script

    def test_device_with_out_bandwidth_emits_htb_commands(self):
        tc = TcConfig(devices=[TcDevice(interface="eth0", out_bandwidth="100mbit")])
        script = emit_tc_commands(tc)
        assert "tc qdisc del dev eth0 root" in script
        assert "tc qdisc add dev eth0 root handle 1: htb default 1" in script
        assert "tc class add dev eth0 parent 1: classid 1:1 htb rate 100mbit" in script

    def test_device_with_in_bandwidth_emits_ingress_commands(self):
        tc = TcConfig(devices=[TcDevice(interface="eth0", in_bandwidth="50mbit")])
        script = emit_tc_commands(tc)
        assert "tc qdisc add dev eth0 ingress" in script

    def test_device_no_bandwidth_emits_no_tc_commands(self):
        tc = TcConfig(devices=[TcDevice(interface="eth0")])
        script = emit_tc_commands(tc)
        # comment line for device exists but no actual tc commands
        assert "# Device: eth0" in script
        assert "tc qdisc add" not in script

    def test_class_uses_rate_as_ceil_when_ceil_empty(self):
        """ceil defaults to rate when not specified."""
        tc = TcConfig(classes=[TcClass(interface="eth0", mark=1, rate="5mbit")])
        script = emit_tc_commands(tc)
        assert "rate 5mbit ceil 5mbit" in script

    def test_class_explicit_ceil_used(self):
        tc = TcConfig(classes=[TcClass(interface="eth0", mark=2, rate="5mbit", ceil="20mbit")])
        script = emit_tc_commands(tc)
        assert "rate 5mbit ceil 20mbit" in script

    def test_class_mark_used_as_classid(self):
        tc = TcConfig(classes=[TcClass(interface="eth0", mark=7, rate="1mbit")])
        script = emit_tc_commands(tc)
        assert "classid 1:7" in script


# ---------------------------------------------------------------------------
# validate_tc (patches load_config + parse_tc_config internals via load_config)
# ---------------------------------------------------------------------------

class TestValidateTc:
    def test_empty_tc_config_passes(self):
        """No tcdevices → single result with passed=True and 'empty' detail."""
        stub_cfg = _make_stub_config()
        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.tc.parse_tc_config", return_value=TcConfig()):
            results = validate_tc(Path("/fake/config"))
        assert len(results) == 1
        r = results[0]
        assert r.name == "tc:generate"
        assert r.passed is True
        assert "empty" in r.detail.lower() or "No TC" in r.detail

    def test_valid_tc_config_passes(self):
        """One device + one class → script generated, passed=True."""
        stub_tc = TcConfig(
            devices=[TcDevice(interface="eth0", out_bandwidth="50mbit")],
            classes=[TcClass(interface="eth0", mark=1, rate="10mbit", ceil="50mbit")],
        )
        stub_cfg = _make_stub_config()
        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.tc.parse_tc_config", return_value=stub_tc):
            results = validate_tc(Path("/fake/config"))
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].name == "tc:generate"
        # detail should mention device/class counts
        assert "1 device" in results[0].detail or "devices" in results[0].detail

    def test_result_is_validation_result_instance(self):
        with patch("shorewall_nft.config.parser.load_config", return_value=_make_stub_config()), \
             patch("shorewall_nft.compiler.tc.parse_tc_config", return_value=TcConfig()):
            results = validate_tc(Path("/fake/config"))
        assert all(isinstance(r, ValidationResult) for r in results)


# ---------------------------------------------------------------------------
# validate_routing (patches _ns)
# ---------------------------------------------------------------------------

class TestValidateRouting:
    def test_ip_forward_enabled_passes(self):
        def _ns_stub(ns, cmd, **kw):
            if "ip_forward" in cmd:
                return _completed(0, stdout="1")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond1 bond0.20")
            if "rp_filter" in cmd:
                return _completed(0, stdout="0")
            return _completed(0, stdout="0")

        with patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_routing(None)

        named = {r.name: r for r in results}
        assert named["ip_forward"].passed is True

    def test_ip_forward_disabled_fails(self):
        def _ns_stub(ns, cmd, **kw):
            if "ip_forward" in cmd:
                return _completed(0, stdout="0")
            if "ip -o link show" in cmd:
                return _completed(0, stdout="lo bond1 bond0.20")
            return _completed(0, stdout="0")

        with patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_routing(None)

        named = {r.name: r for r in results}
        assert named["ip_forward"].passed is False

    def test_missing_interface_fails(self):
        """If bond1 is absent from 'ip link show', its check must fail."""
        def _ns_stub(ns, cmd, **kw):
            if "ip_forward" in cmd:
                return _completed(0, stdout="1")
            if "ip -o link show" in cmd:
                # bond1 deliberately absent
                return _completed(0, stdout="lo bond0.20")
            return _completed(0, stdout="0")

        with patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_routing(None)

        named = {r.name: r for r in results}
        assert named["iface:bond1"].passed is False
        assert named["iface:lo"].passed is True


# ---------------------------------------------------------------------------
# validate_sysctl (patches load_config, generate_sysctl_script, _ns)
# ---------------------------------------------------------------------------

class TestValidateSysctl:
    def test_matching_value_passes(self):
        stub_cfg = MagicMock()
        sysctl_script = "sysctl -w net.ipv4.ip_forward=1\n"

        def _ns_stub(ns, cmd, **kw):
            return _completed(0, stdout="1")

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.sysctl.generate_sysctl_script", return_value=sysctl_script), \
             patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_sysctl(Path("/fake/config"))

        assert len(results) == 1
        assert results[0].passed is True
        assert "net.ipv4.ip_forward" in results[0].name

    def test_mismatched_value_fails(self):
        stub_cfg = MagicMock()
        sysctl_script = "sysctl -w net.ipv4.ip_forward=1\n"

        def _ns_stub(ns, cmd, **kw):
            return _completed(0, stdout="0")  # actual value differs

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.sysctl.generate_sysctl_script", return_value=sysctl_script), \
             patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_sysctl(Path("/fake/config"))

        assert results[0].passed is False
        assert "expected 1" in results[0].detail

    def test_ns_error_reported_as_error(self):
        stub_cfg = MagicMock()
        sysctl_script = "sysctl -w net.ipv4.conf.all.rp_filter=0\n"

        def _ns_stub(ns, cmd, **kw):
            return _completed(1, stdout="")  # returncode != 0

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.sysctl.generate_sysctl_script", return_value=sysctl_script), \
             patch(_NS_PATCH, side_effect=_ns_stub):
            results = validate_sysctl(Path("/fake/config"))

        assert results[0].passed is False
        assert "ERROR" in results[0].detail

    def test_empty_script_produces_no_results(self):
        stub_cfg = MagicMock()

        with patch("shorewall_nft.config.parser.load_config", return_value=stub_cfg), \
             patch("shorewall_nft.compiler.sysctl.generate_sysctl_script", return_value="# comment\n"):
            results = validate_sysctl(Path("/fake/config"))

        assert results == []


# ---------------------------------------------------------------------------
# validate_nft_loaded (patches _ns)
# ---------------------------------------------------------------------------

class TestValidateNftLoaded:
    def test_no_table_fails_immediately(self):
        with patch(_NS_PATCH,
                   return_value=_completed(1, stdout="")):
            results = validate_nft_loaded()
        assert len(results) == 1
        assert results[0].name == "nft:loaded"
        assert results[0].passed is False

    def test_table_with_chains_passes(self):
        nft_output = (
            "table inet shorewall {\n"
            "  chain input { type filter hook input priority 0; policy drop;\n"
            "  }\n"
            "  chain forward { type filter hook forward priority 0; policy drop;\n"
            "  }\n"
            "  chain output { type filter hook output priority 0; policy drop;\n"
            "    ct state established,related accept\n"
            "  }\n"
            "  type nat hook prerouting priority -100;\n"
            "}\n"
        )
        with patch(_NS_PATCH,
                   return_value=_completed(0, stdout=nft_output)):
            results = validate_nft_loaded()

        named = {r.name: r for r in results}
        assert named["nft:loaded"].passed is True
        assert named["nft:chain:input"].passed is True
        assert named["nft:chain:forward"].passed is True
        assert named["nft:chain:output"].passed is True
        assert named["nft:ct_state"].passed is True

    def test_missing_forward_chain_fails(self):
        nft_output = (
            "table inet shorewall {\n"
            "  chain input { type filter hook input priority 0; }\n"
            "  chain output { type filter hook output priority 0; }\n"
            "  ct state established,related accept\n"
            "}\n"
        )
        with patch(_NS_PATCH,
                   return_value=_completed(0, stdout=nft_output)):
            results = validate_nft_loaded()

        named = {r.name: r for r in results}
        assert named["nft:chain:forward"].passed is False
