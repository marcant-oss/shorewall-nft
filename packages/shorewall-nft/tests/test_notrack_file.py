"""Regression tests for the ``notrack`` config-file path.

Exercises ``_process_notrack`` in the IR builder.  The classic
shorewall ``notrack`` file accepts a bare host/CIDR in the destination
column (the second column), with or without a leading ``zone:`` prefix.
This file pins the IR-level result so the rule's daddr/saddr predicates
do not silently disappear when the user writes a bare-IP form.

Concrete user-visible breakage that prompted these tests: the rossini
reference ``notrack`` lines

    net   217.14.160.130   udp   53
    net   217.14.160.75    udp   -    53

emitted ``udp dport 53 notrack`` and ``udp sport 53 notrack`` with no
``ip daddr`` predicate, which notrack'd every UDP/53 flow on the wire
instead of just the four configured DNS hosts.  Surfaced as 145
spurious notrack mismatches in the simlab reference replay.
"""

from __future__ import annotations

from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import ConfigLine, load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


def _ir_with_notrack(columns_list):
    config = load_config(MINIMAL_DIR)
    config.notrack = [
        ConfigLine(columns=cols, file="notrack", lineno=i)
        for i, cols in enumerate(columns_list)
    ]
    return build_ir(config)


def _raw_prerouting_rules(ir):
    return ir.chains["raw-prerouting"].rules


def _match_fields(rule):
    return {m.field: m.value for m in rule.matches}


class TestNotrackBareIPDestination:
    """Bare-IP destinations must produce an ``ip daddr`` predicate.

    The notrack-file format is ``SOURCE DEST PROTO DPORT [SPORT]`` and
    the destination column accepts a bare address (no ``zone:`` prefix)
    — that's how the reference config ships its DNS-resolver entries.
    """

    def test_bare_ipv4_dest_keeps_daddr(self):
        ir = _ir_with_notrack([["net", "10.0.0.1", "udp", "53"]])
        rules = _raw_prerouting_rules(ir)
        assert len(rules) == 1, "expected exactly one notrack rule"
        fields = _match_fields(rules[0])
        assert fields.get("ip daddr") == "10.0.0.1", (
            f"expected ip daddr=10.0.0.1, got matches={fields!r}"
        )
        assert fields.get("meta l4proto") == "udp"
        assert fields.get("udp dport") == "53"

    def test_bare_ipv4_cidr_dest_keeps_daddr(self):
        ir = _ir_with_notrack([["net", "10.0.0.0/24", "udp", "53"]])
        fields = _match_fields(_raw_prerouting_rules(ir)[0])
        assert fields.get("ip daddr") == "10.0.0.0/24"

    def test_zone_prefixed_dest_keeps_daddr(self):
        # Sanity: the explicit zone-prefix form has always worked; this
        # test pins it so a fix for the bare-IP path doesn't regress it.
        ir = _ir_with_notrack([["net", "loc:10.0.0.1", "udp", "53"]])
        fields = _match_fields(_raw_prerouting_rules(ir)[0])
        assert fields.get("ip daddr") == "10.0.0.1"

    def test_sport_form_keeps_daddr(self):
        # Reference uses the reply-side form: ``net <dnsip> udp - 53``
        # (col-3 == "-", col-4 == "53") meaning sport 53 with a daddr
        # filter.  Same bare-IP destination, same daddr requirement.
        ir = _ir_with_notrack([["net", "10.0.0.1", "udp", "-", "53"]])
        rules = _raw_prerouting_rules(ir)
        assert len(rules) == 1
        fields = _match_fields(rules[0])
        assert fields.get("ip daddr") == "10.0.0.1"
        assert fields.get("udp sport") == "53"
        assert "udp dport" not in fields

    def test_daddr_in_emitted_nft(self):
        # End-to-end: emitted nft script must contain the daddr filter.
        # Without the IR fix, the line collapses to an unfiltered
        # ``udp dport 53 notrack`` that captures every DNS flow.
        ir = _ir_with_notrack([["net", "10.0.0.1", "udp", "53"]])
        out = emit_nft(ir)
        assert "ip daddr 10.0.0.1" in out
        assert "udp dport 53" in out
        assert "notrack" in out


class TestNotrackSourceZoneIifFilter:
    """Source zone in column 0 must produce an ``iifname`` filter.

    Classic shorewall emits a per-zone ``<zone>_ctrk`` chain in raw
    PREROUTING and gates it from the base chain via
    ``-A PREROUTING -i <iface> -j <zone>_ctrk``.  The iif filter is
    therefore implicit in the chain structure.  shorewall-nft inlines
    every NOTRACK row into a flat ``raw-prerouting`` chain, so the
    iif predicate has to land on each rule explicitly.

    Without the predicate a NOTRACK declared for the ``net`` zone
    fires for every interface — surfaced on the rossini reference as
    NOTRACK probes from the agfeo zone (bond0.70) being notrack'd
    even though only ``net_ctrk`` carries the rule in iptables-save.
    """

    def test_zone_source_emits_iifname_match(self):
        # Minimal fixture: ``net`` is a single-iface zone (eth0).
        ir = _ir_with_notrack([["net", "10.0.0.1", "udp", "53"]])
        rules = _raw_prerouting_rules(ir)
        assert len(rules) == 1
        fields = _match_fields(rules[0])
        assert fields.get("iifname") == "eth0", (
            f"expected iifname=eth0 from the ``net`` source zone, "
            f"got matches={fields!r}"
        )

    def test_iifname_in_emitted_nft(self):
        ir = _ir_with_notrack([["net", "10.0.0.1", "udp", "53"]])
        out = emit_nft(ir)
        # Scope the check to the raw-prerouting chain — "iifname eth0"
        # appears in input/forward jump dispatch lines too.
        body = out.split("chain raw-prerouting", 1)[1].split("}", 1)[0]
        assert "iifname" in body and "eth0" in body, (
            f"raw-prerouting body lacks iifname/eth0: {body!r}"
        )

    def test_no_iifname_when_source_is_dash(self):
        # Source ``-`` means "any iif" — no filter needed.  Pin the
        # behaviour so the iif fix doesn't accidentally over-filter.
        ir = _ir_with_notrack([["-", "10.0.0.1", "udp", "53"]])
        rules = _raw_prerouting_rules(ir)
        assert len(rules) == 1
        fields = _match_fields(rules[0])
        assert "iifname" not in fields, (
            f"source ``-`` must not emit an iifname filter, got {fields!r}"
        )
