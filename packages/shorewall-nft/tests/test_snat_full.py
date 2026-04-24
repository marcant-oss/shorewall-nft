"""WP-A1: Full snat file support tests.

One test method per snat feature. Each test verifies that the emitted
nft output contains the expected fragment.

Tests are pure-unit: they construct the IR directly (no config directory
loading required) using the helper functions in nat.py, so they run fast
and have no filesystem dependencies.
"""

from __future__ import annotations


from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Rule,
    Verdict,
)
from shorewall_nft.compiler.nat import (
    _parse_snat_action,
    process_nat,
)
from shorewall_nft.compiler.verdicts import (
    MasqueradeVerdict,
    NonatVerdict,
    SnatVerdict,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.nft.emitter import emit_nft


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ir_with_postrouting(*rules: Rule) -> FirewallIR:
    """Return a FirewallIR with a postrouting chain containing *rules*."""
    from shorewall_nft.compiler.ir import Hook
    ir = FirewallIR()
    ch = Chain(
        name="postrouting",
        chain_type=ChainType.NAT,
        hook=Hook.POSTROUTING,
        priority=100,
    )
    for r in rules:
        ch.rules.append(r)
    ir.chains["postrouting"] = ch
    return ir


def _snat_line(*cols: str) -> ConfigLine:
    """Build a minimal ConfigLine for a snat row."""
    return ConfigLine(columns=list(cols), file="test-snat", lineno=1)


def _emit(line: ConfigLine) -> str:
    """Process one snat line and emit the complete nft script."""
    ir = FirewallIR()
    process_nat(ir, masq_lines=[], dnat_rules=[], snat_lines=[line])
    return emit_nft(ir)


# ---------------------------------------------------------------------------
# _parse_snat_action unit tests
# ---------------------------------------------------------------------------

class TestParseSnatAction:
    """Unit tests for the ACTION column parser."""

    def test_snat_simple(self):
        v, log_level, log_tag = _parse_snat_action("SNAT(198.51.100.1)")
        assert isinstance(v, SnatVerdict)
        assert v.target == "198.51.100.1"
        assert v.flags == ()
        assert log_level is None

    def test_snat_port_range(self):
        v, _, _ = _parse_snat_action("SNAT(198.51.100.1:1024-65535)")
        assert isinstance(v, SnatVerdict)
        assert v.target == "198.51.100.1"
        assert v.port_range == "1024-65535"

    def test_snat_persistent_flag(self):
        v, _, _ = _parse_snat_action("SNAT(198.51.100.1:persistent)")
        assert isinstance(v, SnatVerdict)
        assert v.target == "198.51.100.1"
        assert "persistent" in v.flags

    def test_snat_random_flag(self):
        v, _, _ = _parse_snat_action("SNAT(198.51.100.1:random)")
        assert isinstance(v, SnatVerdict)
        assert "random" in v.flags

    def test_snat_fully_random_flag(self):
        v, _, _ = _parse_snat_action("SNAT(198.51.100.1:fully-random)")
        assert isinstance(v, SnatVerdict)
        assert "fully-random" in v.flags

    def test_snat_multiple_targets(self):
        v, _, _ = _parse_snat_action("SNAT(198.51.100.1,198.51.100.2)")
        assert isinstance(v, SnatVerdict)
        assert v.targets == ("198.51.100.1", "198.51.100.2")

    def test_masquerade_plain(self):
        v, _, _ = _parse_snat_action("MASQUERADE")
        assert isinstance(v, MasqueradeVerdict)
        assert v.port_range is None
        assert v.flags == ()

    def test_masquerade_port_range(self):
        v, _, _ = _parse_snat_action("MASQUERADE(1024-65535)")
        assert isinstance(v, MasqueradeVerdict)
        assert v.port_range == "1024-65535"

    def test_masquerade_random(self):
        v, _, _ = _parse_snat_action("MASQUERADE(:random)")
        assert isinstance(v, MasqueradeVerdict)
        assert "random" in v.flags

    def test_continue_returns_none(self):
        v, log_level, _ = _parse_snat_action("CONTINUE")
        assert v is None
        assert log_level is None

    def test_accept_returns_none(self):
        v, log_level, _ = _parse_snat_action("ACCEPT")
        assert v is None
        assert log_level is None

    def test_nonat_returns_none(self):
        v, log_level, _ = _parse_snat_action("NONAT")
        assert v is None
        assert log_level is None

    def test_log_prefix_snat(self):
        v, log_level, log_tag = _parse_snat_action("LOG:info:SNAT-tag:SNAT(198.51.100.1)")
        assert isinstance(v, SnatVerdict)
        assert log_level == "info"
        assert log_tag == "SNAT-tag"

    def test_log_prefix_nonat(self):
        v, log_level, log_tag = _parse_snat_action("LOG:warning:TAG:NONAT")
        assert isinstance(v, NonatVerdict)
        assert log_level == "warning"
        assert log_tag == "TAG"


# ---------------------------------------------------------------------------
# Emit tests — verify nft fragments in emitted output
# ---------------------------------------------------------------------------

class TestSnatEmit:
    """Each feature emits the expected nft fragment."""

    def _emit_line(self, *cols: str) -> str:
        return _emit(_snat_line(*cols))

    def test_basic_snat_emits_snat_to(self):
        out = self._emit_line("SNAT(198.51.100.1)", "192.0.2.0/24", "eth0")
        assert "snat to 198.51.100.1" in out

    def test_snat_oifname_match(self):
        out = self._emit_line("SNAT(198.51.100.1)", "192.0.2.0/24", "eth0")
        assert "oifname eth0" in out

    def test_snat_source_ip_match(self):
        out = self._emit_line("SNAT(198.51.100.1)", "192.0.2.0/24", "eth0")
        assert "ip saddr 192.0.2.0/24" in out

    def test_snat_port_range_emits_colon(self):
        out = self._emit_line("SNAT(198.51.100.1:1024-65535)", "192.0.2.0/24", "eth0")
        assert "snat to 198.51.100.1:1024-65535" in out

    def test_snat_persistent_flag(self):
        out = self._emit_line("SNAT(198.51.100.1:persistent)", "192.0.2.0/24", "eth0")
        assert "snat to 198.51.100.1 persistent" in out

    def test_snat_random_flag(self):
        out = self._emit_line("SNAT(198.51.100.1:random)", "192.0.2.0/24", "eth0")
        assert "snat to 198.51.100.1 random" in out

    def test_snat_fully_random_flag(self):
        out = self._emit_line("SNAT(198.51.100.1:fully-random)", "192.0.2.0/24", "eth0")
        assert "snat to 198.51.100.1 fully-random" in out

    def test_snat_multi_target_round_robin(self):
        out = self._emit_line(
            "SNAT(198.51.100.1,198.51.100.2)", "192.0.2.0/24", "eth0")
        assert "numgen inc mod 2 map" in out
        assert "198.51.100.1" in out
        assert "198.51.100.2" in out

    def test_masquerade_plain(self):
        out = self._emit_line("MASQUERADE", "192.0.2.0/24", "eth0")
        assert "masquerade" in out

    def test_masquerade_port_range(self):
        out = self._emit_line("MASQUERADE(1024-65535)", "192.0.2.0/24", "eth0")
        assert "masquerade to :1024-65535" in out

    def test_masquerade_random_flag(self):
        out = self._emit_line("MASQUERADE(:random)", "192.0.2.0/24", "eth0")
        assert "masquerade" in out
        assert "random" in out

    def test_continue_emits_no_rule(self):
        """CONTINUE lines produce no NAT rule (the chain may still be created)."""
        ir = FirewallIR()
        process_nat(ir, masq_lines=[], dnat_rules=[],
                    snat_lines=[_snat_line("CONTINUE", "192.0.2.0/24", "eth0")])
        if "postrouting" in ir.chains:
            assert len(ir.chains["postrouting"].rules) == 0

    def test_nonat_emits_no_rule(self):
        ir = FirewallIR()
        process_nat(ir, masq_lines=[], dnat_rules=[],
                    snat_lines=[_snat_line("NONAT", "192.0.2.0/24", "eth0")])
        if "postrouting" in ir.chains:
            assert len(ir.chains["postrouting"].rules) == 0

    def test_probability_column(self):
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "-", "-", "-", "-", "-", "0.5",
        )
        assert "numgen random mod 100 < 50" in out

    def test_mark_column(self):
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "-", "0x10", "-", "-", "-", "-",
        )
        assert "meta mark" in out
        assert "0x10" in out

    def test_user_column_skuid(self):
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "-", "-", "nobody", "-", "-", "-",
        )
        assert "meta skuid nobody" in out

    def test_user_column_group(self):
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "-", "-", "+nogroup", "-", "-", "-",
        )
        assert "meta skgid nogroup" in out

    def test_origdest_column(self):
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "-", "-", "-", "-", "203.0.113.1", "-",
        )
        assert "ct original ip daddr 203.0.113.1" in out

    def test_switch_column_emits_ct_mark(self):
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "-", "-", "-", "myswitch", "-", "-",
        )
        assert "ct mark" in out

    def test_log_prefix_prepends_log_rule(self):
        """LOG[:level][:tag]:ACTION prepends a log rule before the NAT rule."""
        ir = FirewallIR()
        process_nat(ir, masq_lines=[], dnat_rules=[],
                    snat_lines=[_snat_line("LOG:info:FOO:SNAT(198.51.100.1)", "192.0.2.0/24", "eth0")])
        chain = ir.chains["postrouting"]
        # Should have 2 rules: log + snat
        assert len(chain.rules) == 2
        assert chain.rules[0].verdict == Verdict.LOG
        assert isinstance(chain.rules[1].verdict_args, SnatVerdict)

    def test_ipsec_column_yes(self):
        """IPSEC=yes → ``meta secpath exists`` (any xfrm-decoded packet)."""
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "yes", "-", "-", "-", "-", "-",
        )
        assert "meta secpath exists" in out

    def test_ipsec_column_no(self):
        """IPSEC=no → ``meta secpath missing`` (packet bypassed xfrm)."""
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "-", "-", "no", "-", "-", "-", "-", "-",
        )
        assert "meta secpath missing" in out

    def test_proto_dport_columns(self):
        out = self._emit_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth0",
            "tcp", "80",
        )
        assert "meta l4proto tcp" in out

    def test_source_iface_treated_as_iifname(self):
        """Source column that looks like an interface name → iifname match."""
        out = self._emit_line("SNAT(198.51.100.1)", "eth1", "eth0")
        assert "iifname eth1" in out


# ---------------------------------------------------------------------------
# Fixture compilation test — the ref-ha-minimal fixture must compile clean
# ---------------------------------------------------------------------------

class TestRefHaMinimalSnat:
    """The updated ref-ha-minimal/snat fixture must compile without errors."""

    def test_fixture_compiles(self):
        from pathlib import Path
        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.parser import load_config

        fixture = Path(__file__).parent / "fixtures" / "ref-ha-minimal" / "shorewall"
        config = load_config(fixture)
        ir = build_ir(config)
        out = emit_nft(ir)
        # Check at least one snat rule made it through
        assert "snat to" in out or "masquerade" in out
