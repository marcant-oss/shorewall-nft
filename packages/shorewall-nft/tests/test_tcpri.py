"""Tests for tcpri parsing and nft meta mark set vmap emission.

Verifies that each tcpri row produces the correct mark-set rule in the
mangle-prerouting chain (or forward chain when MARK_IN_FORWARD_CHAIN=Yes).
"""

from __future__ import annotations

from shorewall_nft.compiler.tc import (
    TcPri,
    emit_tcpri_nft,
    parse_tcpri,
)
from shorewall_nft.config.parser import ConfigLine


# ── helpers ──────────────────────────────────────────────────────────────────

def _line(cols: list[str], lineno: int = 1) -> ConfigLine:
    return ConfigLine(columns=cols, file="tcpri", lineno=lineno)


# ── parse_tcpri ───────────────────────────────────────────────────────────────

class TestParseTcpri:

    def test_proto_port_row(self):
        lines = [_line(["1", "tcp", "22", "-", "-", "-"])]
        result = parse_tcpri(lines)
        assert len(result) == 1
        assert result[0].band == 1
        assert result[0].proto == "tcp"
        assert result[0].port == "22"

    def test_address_row(self):
        lines = [_line(["3", "-", "-", "192.168.1.0/24", "-", "-"])]
        result = parse_tcpri(lines)
        assert len(result) == 1
        assert result[0].band == 3
        assert result[0].address == "192.168.1.0/24"
        assert result[0].proto == "-"

    def test_interface_row(self):
        lines = [_line(["2", "-", "-", "-", "eth1", "-"])]
        result = parse_tcpri(lines)
        assert len(result) == 1
        assert result[0].interface == "eth1"

    def test_all_dash_row_skipped(self):
        lines = [_line(["1", "-", "-", "-", "-", "-"])]
        result = parse_tcpri(lines)
        assert result == []

    def test_band_out_of_range_skipped(self):
        lines = [_line(["4", "tcp", "80", "-", "-", "-"])]
        result = parse_tcpri(lines)
        assert result == []

    def test_band_zero_skipped(self):
        lines = [_line(["0", "tcp", "80", "-", "-", "-"])]
        result = parse_tcpri(lines)
        assert result == []

    def test_invalid_band_string_skipped(self):
        lines = [_line(["high", "tcp", "80", "-", "-", "-"])]
        result = parse_tcpri(lines)
        assert result == []

    def test_empty_lines_list(self):
        assert parse_tcpri([]) == []

    def test_multiple_rows(self):
        lines = [
            _line(["1", "tcp", "22", "-", "-", "-"], 1),
            _line(["3", "-", "-", "10.0.0.0/8", "-", "-"], 2),
        ]
        result = parse_tcpri(lines)
        assert len(result) == 2
        assert result[0].band == 1
        assert result[1].band == 3

    def test_band_values_1_2_3_accepted(self):
        for b in (1, 2, 3):
            lines = [_line([str(b), "tcp", "80", "-", "-", "-"])]
            result = parse_tcpri(lines)
            assert len(result) == 1
            assert result[0].band == b


# ── emit_tcpri_nft ────────────────────────────────────────────────────────────

class TestEmitTcpriNft:

    def test_empty_list_returns_empty(self):
        assert emit_tcpri_nft([]) == ""

    def test_tc_enabled_no_returns_empty(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        assert emit_tcpri_nft(tcpris, {"TC_ENABLED": "No"}) == ""

    def test_proto_port_match_emitted(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {})
        assert "meta l4proto tcp" in out
        assert "tcp dport 22" in out
        assert "meta mark set 1" in out

    def test_address_match_emitted(self):
        tcpris = [TcPri(band=3, address="192.168.1.0/24")]
        out = emit_tcpri_nft(tcpris, {})
        assert "ip saddr 192.168.1.0/24" in out
        assert "meta mark set 3" in out

    def test_interface_match_emitted(self):
        tcpris = [TcPri(band=2, interface="eth1")]
        out = emit_tcpri_nft(tcpris, {})
        assert "iifname" in out
        assert "eth1" in out
        assert "meta mark set 2" in out

    def test_proto_without_port(self):
        tcpris = [TcPri(band=2, proto="udp")]
        out = emit_tcpri_nft(tcpris, {})
        assert "meta l4proto udp" in out
        assert "dport" not in out
        assert "meta mark set 2" in out

    def test_band_3_uses_correct_mark(self):
        tcpris = [TcPri(band=3, proto="tcp", port="80")]
        out = emit_tcpri_nft(tcpris, {})
        assert "meta mark set 3" in out

    def test_default_chain_is_mangle_prerouting(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {})
        assert "mangle-prerouting" in out

    def test_mark_in_forward_chain_uses_forward(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {"MARK_IN_FORWARD_CHAIN": "Yes"})
        assert "forward" in out

    def test_mark_in_forward_chain_no_uses_prerouting(self):
        tcpris = [TcPri(band=1, proto="tcp", port="22")]
        out = emit_tcpri_nft(tcpris, {"MARK_IN_FORWARD_CHAIN": "No"})
        assert "mangle-prerouting" in out

    def test_multiple_rows_all_emitted(self):
        tcpris = [
            TcPri(band=1, proto="tcp", port="22"),
            TcPri(band=3, address="10.0.0.0/8"),
        ]
        out = emit_tcpri_nft(tcpris, {})
        assert "meta mark set 1" in out
        assert "meta mark set 3" in out
        assert "tcp dport 22" in out
        assert "ip saddr 10.0.0.0/8" in out


# ── IR integration: tcpri wired into build_ir ─────────────────────────────────

class TestTcpriIRIntegration:
    """Verify build_ir() stashes TcPri objects on ir.tcpris and injects
    the mark-set rules into the mangle-prerouting chain.

    Uses the ref-ha-minimal fixture as a base to supply a valid zones/
    interfaces/policy config.
    """

    _FIXTURE = (
        "packages/shorewall-nft/tests/fixtures/ref-ha-minimal/shorewall"
    )

    def _build(self, tcpri_rows: list[str], extra_settings: dict[str, str] | None = None):
        from pathlib import Path
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.parser import ConfigLine, load_config

        config = load_config(Path(self._FIXTURE))
        config.settings.update(extra_settings or {"TC_ENABLED": "Internal"})
        config.tcpri = []
        for i, row in enumerate(tcpri_rows, 1):
            cols = row.split()
            config.tcpri.append(ConfigLine(columns=cols, file="tcpri", lineno=i))
        return build_ir(config)

    def test_tcpri_stashed_on_ir(self):
        ir = self._build(["1 tcp 22 - - -"])
        assert len(ir.tcpris) == 1
        assert ir.tcpris[0].band == 1

    def test_tcpri_disabled_when_tc_enabled_no(self):
        ir = self._build(["1 tcp 22 - - -"], {"TC_ENABLED": "No"})
        assert ir.tcpris == []

    def test_mangle_prerouting_chain_created(self):
        ir = self._build(["1 tcp 22 - - -"])
        assert "mangle-prerouting" in ir.chains

    def test_mark_rule_added_to_mangle_chain(self):
        from shorewall_nft.compiler.verdicts import MarkVerdict
        ir = self._build(["1 tcp 22 - - -"])
        chain = ir.chains["mangle-prerouting"]
        mark_rules = [r for r in chain.rules
                      if isinstance(r.verdict_args, MarkVerdict) and r.verdict_args.value == 1]
        assert mark_rules, "expected a mark=1 rule in mangle-prerouting"
