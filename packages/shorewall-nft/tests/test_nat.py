import os

"""Tests for Phase 2: NAT, Conntrack, Notrack, Custom Macros."""

from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.compiler.verdicts import CtHelperVerdict, NotrackVerdict
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

NAT_DIR = Path(__file__).parent / "configs" / "nat"
_FIXTURE_DEFAULT = Path(__file__).parent / "fixtures" / "ref-ha-minimal" / "shorewall"


def _resolve_prod_dir() -> Path:
    env = os.environ.get("SHOREWALL_NFT_PROD_DIR")
    if env and Path(env).is_dir():
        return Path(env)
    if _FIXTURE_DEFAULT.is_dir():
        return _FIXTURE_DEFAULT
    pytest.skip("neither SHOREWALL_NFT_PROD_DIR nor bundled fixture available")


PROD_DIR = None  # kept for reference; tests call _resolve_prod_dir() directly


def _is_real_prod_dir() -> bool:
    """True when SHOREWALL_NFT_PROD_DIR points at a real prod config.

    Used to gate scale-assertion tests (zone/rule/chain counts) that only
    make sense against a full production config. The bundled minimal
    fixture deliberately cannot satisfy production-scale numbers.
    """
    env = os.environ.get("SHOREWALL_NFT_PROD_DIR")
    return bool(env and Path(env).is_dir())


_prod_scale_only = pytest.mark.skipif(
    not _is_real_prod_dir(),
    reason="scale assertion needs SHOREWALL_NFT_PROD_DIR with a full prod config",
)


class TestNAT:
    def setup_method(self):
        config = load_config(NAT_DIR)
        self.ir = build_ir(config)
        self.output = emit_nft(self.ir)

    def test_prerouting_chain_exists(self):
        assert "prerouting" in self.ir.chains
        chain = self.ir.chains["prerouting"]
        assert chain.hook.value == "prerouting"
        assert chain.chain_type.value == "nat"

    def test_postrouting_chain_exists(self):
        assert "postrouting" in self.ir.chains
        chain = self.ir.chains["postrouting"]
        assert chain.hook.value == "postrouting"
        assert chain.chain_type.value == "nat"

    def test_dnat_rule(self):
        from shorewall_nft.compiler.verdicts import DnatVerdict
        chain = self.ir.chains["prerouting"]
        dnat_rules = [
            r for r in chain.rules
            if isinstance(r.verdict_args, DnatVerdict)
        ]
        assert len(dnat_rules) >= 1
        # DNAT to webserver:80 on port 8080
        assert dnat_rules[0].verdict_args.target == "192.168.1.10:80"

    def test_snat_rule(self):
        from shorewall_nft.compiler.verdicts import SnatVerdict
        chain = self.ir.chains["postrouting"]
        snat_rules = [
            r for r in chain.rules
            if isinstance(r.verdict_args, SnatVerdict)
        ]
        assert len(snat_rules) >= 1
        assert "203.0.113.1" in snat_rules[0].verdict_args.target

    def test_dnat_nft_output(self):
        assert "dnat to 192.168.1.10:80" in self.output

    def test_snat_nft_output(self):
        assert "snat to 203.0.113.1" in self.output

    def test_nat_chain_hooks(self):
        assert "type nat hook prerouting priority -100;" in self.output
        assert "type nat hook postrouting priority 100;" in self.output


class TestNotrack:
    def setup_method(self):
        config = load_config(NAT_DIR)
        self.ir = build_ir(config)
        self.output = emit_nft(self.ir)

    def test_raw_chain_exists(self):
        assert "raw-prerouting" in self.ir.chains
        chain = self.ir.chains["raw-prerouting"]
        assert chain.priority == -300

    def test_notrack_rules(self):
        chain = self.ir.chains["raw-prerouting"]
        notrack_rules = [r for r in chain.rules if isinstance(r.verdict_args, NotrackVerdict)]
        assert len(notrack_rules) >= 1

    def test_notrack_nft_output(self):
        assert "notrack" in self.output

    def test_raw_output_chain(self):
        assert "raw-output" in self.ir.chains
        chain = self.ir.chains["raw-output"]
        assert len(chain.rules) >= 1


class TestConntrack:
    def setup_method(self):
        config = load_config(NAT_DIR)
        self.ir = build_ir(config)
        self.output = emit_nft(self.ir)

    def test_ct_helper_chain(self):
        assert "ct-helpers" in self.ir.chains

    def test_ftp_helper(self):
        chain = self.ir.chains["ct-helpers"]
        ftp = [r for r in chain.rules if isinstance(r.verdict_args, CtHelperVerdict) and r.verdict_args.name == "ftp"]
        assert len(ftp) == 1

    def test_ct_helper_nft_output(self):
        assert 'ct helper set "ftp"' in self.output


class TestProductionConfig:
    """Test against the real production config (or bundled fixture)."""

    def setup_method(self):
        prod_dir = _resolve_prod_dir()
        config = load_config(prod_dir)
        self.ir = build_ir(config)
        self.output = emit_nft(self.ir)

    @_prod_scale_only
    def test_zones(self):
        assert len(self.ir.zones.zones) >= 16

    @_prod_scale_only
    def test_chain_count(self):
        assert len(self.ir.chains) > 250

    @_prod_scale_only
    def test_rule_count(self):
        total = sum(len(c.rules) for c in self.ir.chains.values())
        assert total > 5000

    def test_nat_chains(self):
        assert "prerouting" in self.ir.chains
        assert "postrouting" in self.ir.chains

    def test_raw_chains(self):
        assert "raw-prerouting" in self.ir.chains
        assert "raw-output" in self.ir.chains

    def test_ct_helpers(self):
        assert "ct-helpers" in self.ir.chains
        chain = self.ir.chains["ct-helpers"]
        assert len(chain.rules) >= 4  # ftp, snmp, tftp, pptp

    @_prod_scale_only
    def test_output_line_count(self):
        lines = self.output.split("\n")
        assert len(lines) > 9000

    def test_nft_syntax_basics(self):
        assert "table inet shorewall {" in self.output
        assert "type filter hook input" in self.output
        assert "type nat hook prerouting" in self.output
        assert "snat to" in self.output
        assert "dnat to" in self.output
        assert "notrack" in self.output
