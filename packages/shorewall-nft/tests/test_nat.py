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

    def test_dnat_emits_filter_accept_companion(self):
        """Classic Shorewall splits a ``DNAT`` row into a NAT rewrite *and*
        a FILTER ACCEPT gating the post-DNAT chain by ``ct original daddr``.
        Without the companion the rewritten packet hits the zone-pair
        chain's default DROP/REJECT policy and the DNAT'd service is
        unreachable.
        """
        # The nat fixture's net2loc chain must contain an ACCEPT with both
        # the post-DNAT internal IP (192.168.1.10) and ct original daddr
        # set to the pre-DNAT public IP (203.0.113.1).
        assert (
            "ip daddr 192.168.1.10 ct original daddr 203.0.113.1 "
            "meta l4proto tcp tcp dport 80 accept"
        ) in self.output


class TestDnatFilterCompanion:
    """``extract_nat_rules`` must synthesise an ACCEPT companion for every
    DNAT row so the regular rules pipeline lands a FILTER rule next to
    the NAT rewrite.  Direct unit tests for the synthesis function so
    the column mapping (esp. ``zone:ip:rewritten_port``) is locked in.
    """

    def _synth(self, cols):
        from shorewall_nft.compiler.nat import _synthesize_dnat_filter_accept
        from shorewall_nft.config.parser import ConfigLine
        line = ConfigLine(columns=cols, file="rules", lineno=1)
        return _synthesize_dnat_filter_accept(line)

    def test_no_port_rewrite_keeps_original_dport(self):
        comp = self._synth([
            "DNAT", "net", "loc:192.168.1.10", "tcp", "80,443", "-", "203.0.113.1"
        ])
        assert comp is not None
        # ACCEPT row keeps original DPORT 80,443; DEST is zone:ip (no port)
        assert comp.columns == [
            "ACCEPT", "net", "loc:192.168.1.10", "tcp", "80,443", "-", "203.0.113.1"
        ]

    def test_port_rewrite_uses_post_dnat_port(self):
        # zone:ip:port → FILTER must match the *rewritten* port (post-NAT)
        comp = self._synth([
            "DNAT", "net", "loc:192.168.1.10:80", "tcp", "8080", "-", "203.0.113.1"
        ])
        assert comp is not None
        assert comp.columns == [
            "ACCEPT", "net", "loc:192.168.1.10", "tcp", "80", "-", "203.0.113.1"
        ]

    def test_extract_nat_rules_appends_companion_to_remaining(self):
        from shorewall_nft.compiler.nat import extract_nat_rules
        from shorewall_nft.config.parser import ConfigLine
        rules = [
            ConfigLine(
                columns=["DNAT", "net", "loc:192.168.1.10", "tcp", "80",
                         "-", "203.0.113.1"],
                file="rules", lineno=1),
            ConfigLine(
                columns=["ACCEPT", "loc", "net", "tcp", "53"],
                file="rules", lineno=2),
        ]
        nat_rules, remaining = extract_nat_rules(rules)
        assert len(nat_rules) == 1
        assert len(remaining) == 2
        assert remaining[0].columns[0] == "ACCEPT"
        assert remaining[0].columns[6] == "203.0.113.1"   # synth companion
        assert remaining[1].columns[1] == "loc"           # original ACCEPT

    def test_redirect_emits_no_companion(self):
        # REDIRECT does not need a FILTER ACCEPT companion — the redirect
        # target is the firewall itself, so the existing input-chain
        # rules govern admission.
        from shorewall_nft.compiler.nat import extract_nat_rules
        from shorewall_nft.config.parser import ConfigLine
        rules = [ConfigLine(
            columns=["REDIRECT", "loc", "3128", "tcp", "80"],
            file="rules", lineno=1)]
        nat_rules, remaining = extract_nat_rules(rules)
        assert len(nat_rules) == 1
        assert remaining == []

    def test_ipv6_bracketed_dest_no_port(self):
        # DNAT DEST uses ``[v6]`` to separate IP from optional :port.
        # The synthesised companion converts to the rules-file ``<v6>``
        # form so ``_parse_zone_spec`` lands it in the IPv6 slot.
        comp = self._synth([
            "DNAT", "net", "loc:[2001:db8::1]", "tcp", "443",
            "-", "2001:db8:cafe::5"
        ])
        assert comp is not None
        assert comp.columns == [
            "ACCEPT", "net", "loc:<2001:db8::1>", "tcp", "443",
            "-", "2001:db8:cafe::5"
        ]

    def test_ipv6_bracketed_dest_with_port_rewrite(self):
        comp = self._synth([
            "DNAT", "net", "loc:[2001:db8::1]:80", "tcp", "8080",
            "-", "2001:db8:cafe::5"
        ])
        assert comp is not None
        # FILTER must match the rewritten port (80) in the post-DNAT chain.
        assert comp.columns == [
            "ACCEPT", "net", "loc:<2001:db8::1>", "tcp", "80",
            "-", "2001:db8:cafe::5"
        ]

    def test_ipv6_bare_dest_no_port(self):
        # Bare IPv6 (no brackets) — Shorewall6 syntax permits this when
        # there's no port rewrite.  We rewrite to the ``<v6>`` form for
        # the same reason as the bracketed branch.
        comp = self._synth([
            "DNAT", "net", "loc:2001:db8::1", "tcp", "443",
            "-", "2001:db8:cafe::5"
        ])
        assert comp is not None
        assert comp.columns == [
            "ACCEPT", "net", "loc:<2001:db8::1>", "tcp", "443",
            "-", "2001:db8:cafe::5"
        ]

    def test_split_helper_table(self):
        from shorewall_nft.compiler.nat import _split_dnat_dest_for_filter
        # IPv4
        assert _split_dnat_dest_for_filter("loc:192.0.2.1") == (
            "loc:192.0.2.1", None)
        assert _split_dnat_dest_for_filter("loc:192.0.2.1:8080") == (
            "loc:192.0.2.1", "8080")
        # IPv6 bracketed → angle-bracket rewrite
        assert _split_dnat_dest_for_filter("loc:[2001:db8::1]") == (
            "loc:<2001:db8::1>", None)
        assert _split_dnat_dest_for_filter("loc:[2001:db8::1]:80") == (
            "loc:<2001:db8::1>", "80")
        # IPv6 bare → also rewritten to ``<v6>`` form
        assert _split_dnat_dest_for_filter("loc:2001:db8::1") == (
            "loc:<2001:db8::1>", None)
        # Zone-only
        assert _split_dnat_dest_for_filter("loc") == ("loc", None)


class TestRedirect:
    """REDIRECT action: rewrite destination to a local port on the firewall.

    Classic Shorewall format: ``REDIRECT SOURCE PORT PROTO [DPORT]``.  The
    DEST column is a numeric port on the firewall (the redirect target),
    not a zone:ip:port. Regression test for a bug where REDIRECT rules
    were silently processed as DNAT (empty target) and produced malformed
    nft output.
    """

    def _run(self, cols: list[str]):
        from shorewall_nft.compiler.ir import FirewallIR
        from shorewall_nft.compiler.nat import _ensure_nat_chains, _process_dnat_line
        from shorewall_nft.config.parser import ConfigLine
        from shorewall_nft.config.zones import ZoneModel

        ir = FirewallIR(zones=ZoneModel(), settings={})
        _ensure_nat_chains(ir)
        line = ConfigLine(columns=cols, file="rules", lineno=1)
        _process_dnat_line(ir, line)
        return ir

    def test_redirect_emits_typed_verdict(self):
        from shorewall_nft.compiler.verdicts import RedirectVerdict
        ir = self._run(["REDIRECT", "loc", "3128", "tcp", "80"])
        rules = ir.chains["prerouting"].rules
        assert len(rules) == 1
        assert isinstance(rules[0].verdict_args, RedirectVerdict)
        assert rules[0].verdict_args.port == 3128

    def test_redirect_preserves_proto_and_dport(self):
        ir = self._run(["REDIRECT", "loc", "3128", "tcp", "80"])
        rule = ir.chains["prerouting"].rules[0]
        match_fields = [m.field for m in rule.matches]
        assert "meta l4proto" in match_fields
        # tcp dport matches the incoming dest port (80), not the redirect target
        tcp_dport = next(m for m in rule.matches if m.field == "tcp dport")
        assert tcp_dport.value == "80"

    def test_redirect_emits_nft_redirect_statement(self):
        ir = self._run(["REDIRECT", "loc", "5353", "udp", "53"])
        out = emit_nft(ir)
        # The key bug fix: the emit must produce ``redirect to :<port>``,
        # not an empty ``dnat to`` fragment.
        assert "redirect to :5353" in out
        assert "dnat to " not in out

    def test_redirect_missing_port_raises(self):
        with pytest.raises(ValueError, match="numeric port"):
            self._run(["REDIRECT", "loc", "-", "tcp", "80"])

    def test_redirect_non_numeric_port_raises(self):
        with pytest.raises(ValueError, match="numeric port"):
            self._run(["REDIRECT", "loc", "abc", "tcp", "80"])


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
