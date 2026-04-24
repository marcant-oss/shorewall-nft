"""WP-A2: Classic nat file (1:1 NAT) tests.

Tests for ``process_static_nat`` which processes the Shorewall ``nat`` file:

    EXTERNAL  INTERFACE[:digit]  INTERNAL  ALL  LOCAL

For each row:
- PREROUTING ``dnat to INTERNAL`` (scoped to iface if ALL != 'Yes')
- POSTROUTING ``snat to EXTERNAL`` (scoped to iface if ALL != 'Yes')
- OUTPUT ``dnat to INTERNAL`` (only if LOCAL == 'Yes')
"""

from __future__ import annotations

from pathlib import Path

from shorewall_nft.compiler.ir import (
    FirewallIR,
    build_ir,
)
from shorewall_nft.compiler.nat import process_static_nat
from shorewall_nft.compiler.verdicts import DnatVerdict, SnatVerdict
from shorewall_nft.config.parser import ConfigLine, load_config
from shorewall_nft.nft.emitter import emit_nft


def _nat_line(*cols: str) -> ConfigLine:
    return ConfigLine(columns=list(cols), file="test-nat", lineno=1)


def _process(*lines: ConfigLine) -> FirewallIR:
    ir = FirewallIR()
    process_static_nat(ir, list(lines))
    return ir


class TestStaticNatBasic:
    """Basic 1:1 NAT with interface scope (ALL=-)."""

    def setup_method(self):
        self.ir = _process(
            _nat_line("203.0.113.50", "eth0", "192.0.2.50", "-", "-")
        )

    def test_prerouting_chain_created(self):
        assert "prerouting" in self.ir.chains

    def test_postrouting_chain_created(self):
        assert "postrouting" in self.ir.chains

    def test_prerouting_dnat_rule(self):
        chain = self.ir.chains["prerouting"]
        dnat_rules = [r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict)]
        assert len(dnat_rules) == 1
        assert dnat_rules[0].verdict_args.target == "192.0.2.50"

    def test_prerouting_dnat_matches_external(self):
        chain = self.ir.chains["prerouting"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict))
        fields = [m.field for m in rule.matches]
        assert "ip daddr" in fields
        daddr = next(m.value for m in rule.matches if m.field == "ip daddr")
        assert daddr == "203.0.113.50"

    def test_prerouting_dnat_iface_scoped(self):
        """ALL=- means iifname match is present."""
        chain = self.ir.chains["prerouting"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict))
        iface_matches = [m for m in rule.matches if m.field == "iifname"]
        assert len(iface_matches) == 1
        assert iface_matches[0].value == "eth0"

    def test_postrouting_snat_rule(self):
        chain = self.ir.chains["postrouting"]
        snat_rules = [r for r in chain.rules if isinstance(r.verdict_args, SnatVerdict)]
        assert len(snat_rules) == 1
        assert snat_rules[0].verdict_args.target == "203.0.113.50"

    def test_postrouting_snat_matches_internal(self):
        chain = self.ir.chains["postrouting"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, SnatVerdict))
        saddr = next(m.value for m in rule.matches if m.field == "ip saddr")
        assert saddr == "192.0.2.50"

    def test_postrouting_snat_iface_scoped(self):
        chain = self.ir.chains["postrouting"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, SnatVerdict))
        iface_matches = [m for m in rule.matches if m.field == "oifname"]
        assert len(iface_matches) == 1
        assert iface_matches[0].value == "eth0"

    def test_no_output_dnat_rules(self):
        """LOCAL=- means no OUTPUT DNAT rules emitted."""
        if "nat-output" not in self.ir.chains:
            return  # chain not created at all is also fine
        assert len(self.ir.chains["nat-output"].rules) == 0

    def test_emitted_output_contains_dnat(self):
        out = emit_nft(self.ir)
        assert "dnat to 192.0.2.50" in out

    def test_emitted_output_contains_snat(self):
        out = emit_nft(self.ir)
        assert "snat to 203.0.113.50" in out


class TestStaticNatAllInterfaces:
    """ALL=Yes: no iface match in PREROUTING or POSTROUTING."""

    def setup_method(self):
        self.ir = _process(
            _nat_line("203.0.113.51", "eth0", "192.0.2.51", "Yes", "-")
        )

    def test_prerouting_no_iifname(self):
        chain = self.ir.chains["prerouting"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict))
        iface_matches = [m for m in rule.matches if m.field == "iifname"]
        assert len(iface_matches) == 0

    def test_postrouting_no_oifname(self):
        chain = self.ir.chains["postrouting"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, SnatVerdict))
        iface_matches = [m for m in rule.matches if m.field == "oifname"]
        assert len(iface_matches) == 0


class TestStaticNatLocal:
    """LOCAL=Yes: also emit OUTPUT DNAT."""

    def setup_method(self):
        self.ir = _process(
            _nat_line("203.0.113.52", "eth0", "192.0.2.52", "-", "Yes")
        )

    def test_output_chain_created(self):
        assert "nat-output" in self.ir.chains

    def test_output_dnat_rule(self):
        chain = self.ir.chains["nat-output"]
        dnat_rules = [r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict)]
        assert len(dnat_rules) == 1
        assert dnat_rules[0].verdict_args.target == "192.0.2.52"

    def test_output_dnat_matches_external(self):
        chain = self.ir.chains["nat-output"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict))
        daddr = next(m.value for m in rule.matches if m.field == "ip daddr")
        assert daddr == "203.0.113.52"

    def test_emitted_output_chain(self):
        out = emit_nft(self.ir)
        assert "hook output" in out
        assert "dnat to 192.0.2.52" in out


class TestStaticNatAliasDigitStripped:
    """The :digit alias suffix on INTERFACE must be silently stripped."""

    def test_alias_stripped(self):
        ir = _process(_nat_line("203.0.113.53", "eth0:0", "192.0.2.53", "-", "-"))
        # The iifname match must be "eth0", not "eth0:0"
        chain = ir.chains["prerouting"]
        rule = next(r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict))
        iface_matches = [m for m in rule.matches if m.field == "iifname"]
        assert iface_matches[0].value == "eth0"


class TestStaticNatMultipleRows:
    """Multiple nat rows all get processed."""

    def test_two_rows_two_dnat_rules(self):
        ir = _process(
            _nat_line("203.0.113.60", "eth0", "192.0.2.60", "-", "-"),
            _nat_line("203.0.113.61", "eth0", "192.0.2.61", "-", "-"),
        )
        chain = ir.chains["prerouting"]
        dnat_rules = [r for r in chain.rules if isinstance(r.verdict_args, DnatVerdict)]
        assert len(dnat_rules) == 2


class TestStaticNatFixture:
    """The ref-ha-minimal nat fixture must compile without errors."""

    def test_fixture_compiles(self):
        fixture = Path(__file__).parent / "fixtures" / "ref-ha-minimal" / "shorewall"
        config = load_config(fixture)
        ir = build_ir(config)
        out = emit_nft(ir)
        # The nat file has a 1:1 entry for 203.0.113.50 → 192.0.2.50
        assert "dnat to 192.0.2.50" in out
        assert "snat to 203.0.113.50" in out

    def test_fixture_nat_lines_parsed(self):
        fixture = Path(__file__).parent / "fixtures" / "ref-ha-minimal" / "shorewall"
        config = load_config(fixture)
        # The nat file has 3 entries
        assert len(config.nat) == 3
