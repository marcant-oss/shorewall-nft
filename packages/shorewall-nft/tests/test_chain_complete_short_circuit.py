"""Regression tests for the chain-complete short-circuit.

Mirrors classic shorewall (``Chains.pm:1832``): an unconditional
terminating verdict that lands in (or is folded into) a per-pair
chain renders every later rule in source-line order unreachable.
A wildcard ``DROP:$LOG <zone> any`` on a chain whose policy is
already drop-class is omitted as redundant — but it still closes
the chain, so subsequent ``all → <zone>`` ACCEPTs in
``?SHELL include`` files don't sneak past the user's intent.

Concrete user-visible breakage that prompted these tests:
the rossini reference rules carry, in *v4 source order*,

    rules:884   Web(ACCEPT) all      cdn:$CDN_WWW_DREAMROBOT_DE
    rules:2322  DROP:$LOG   agfeo    any
    rules:2340  ?SHELL include /etc/shorewall/rules.d/*.rules
                  ACCEPT  all:$MARCANT_PFX  siem:217.14.160.101  tcp 514,1514,1515,55000

Classic shorewall emits the line-884 ACCEPTs into ``agfeo2cdn``
(line 884 runs before line 2322 closes the chain) and *omits* the
rules.d ACCEPTs from ``agfeo2siem`` (line 2340 runs after line 2322).
Both behaviours fall out of the same chain-complete invariant.

These tests pin the after-the-catch-all branch.  The before-the-
catch-all branch is the inverse and lives in
``test_chain_complete_pre_catch_all.py``-style locations
(currently exercised end-to-end by the simlab reference replay).
"""

from __future__ import annotations

from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import ConfigLine, load_config

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


def _ir_with_rules(rules):
    """Load minimal config and replace its rules with *rules*.

    Each entry is a list of columns (``[ACTION, SOURCE, DEST, PROTO, DPORT]``).
    """
    config = load_config(MINIMAL_DIR)
    config.rules = [
        ConfigLine(columns=cols, file="rules", lineno=i + 1, section="NEW")
        for i, cols in enumerate(rules)
    ]
    return build_ir(config)


def _accept_rules(chain):
    return [r for r in chain.rules if r.verdict.name == "ACCEPT"]


def _has_daddr(rule, value):
    return any(m.field in ("ip daddr", "ip6 daddr") and m.value == value
               for m in rule.matches)


class TestCatchAllShortCircuitsLaterRules:
    """A redundant ``<zone> any`` DROP/REJECT closes the per-pair
    chain for every rule that follows it in source order.
    """

    def test_all_dest_accept_blocked_after_catch_all_reject_class(self):
        # Minimal config has policy ``net all DROP $LOG`` (drop-class)
        # — the precondition for the short-circuit to fire on a
        # catch-all DROP / REJECT from net.
        ir = _ir_with_rules([
            ["DROP:$LOG", "net", "any"],
            ["ACCEPT", "all", "loc:10.0.0.5", "tcp", "80"],
        ])
        net_loc = ir.chains["net-loc"]
        target_accepts = [r for r in _accept_rules(net_loc)
                          if _has_daddr(r, "10.0.0.5")]
        assert not target_accepts, (
            "all→loc:10.0.0.5 ACCEPT must NOT land in net-loc when a "
            "preceding DROP:$LOG net any has already closed the chain "
            "(classic shorewall semantics: chain-complete blocks later "
            "all-expansion siblings)"
        )

    def test_catch_all_reject_also_short_circuits(self):
        ir = _ir_with_rules([
            ["REJECT", "net", "any"],
            ["ACCEPT", "all", "loc:10.0.0.6", "tcp", "443"],
        ])
        net_loc = ir.chains["net-loc"]
        target = [r for r in _accept_rules(net_loc)
                  if _has_daddr(r, "10.0.0.6")]
        assert not target, (
            "REJECT-class catch-all must close the chain just like DROP "
            "(both are drop-class verdicts)"
        )

    def test_catch_all_drop_itself_is_omitted(self):
        # Counter-pin: the catch-all DROP itself is omitted from the
        # chain body (the policy tail covers it) — only the
        # chain-complete flag persists.  Without this counter-check
        # an over-eager fix could re-emit the redundant DROP.
        ir = _ir_with_rules([
            ["DROP:$LOG", "net", "any"],
        ])
        net_loc = ir.chains["net-loc"]
        unconditional_drops = [
            r for r in net_loc.rules
            if r.verdict.name in ("DROP", "REJECT") and not r.matches
        ]
        assert not unconditional_drops, (
            "redundant catch-all DROP must be omitted (policy covers it); "
            f"found {len(unconditional_drops)} unconditional drop rules"
        )

    def test_explicit_pair_rule_before_catch_all_lands(self):
        # Sanity: a rule that runs *before* the catch-all in source
        # order must still land in the chain.  This is the other half
        # of the classic-shorewall semantic — chain-complete is
        # source-order-sensitive, not blanket-blocking.
        ir = _ir_with_rules([
            ["ACCEPT", "all", "loc:10.0.0.7", "tcp", "8080"],
            ["DROP:$LOG", "net", "any"],
        ])
        net_loc = ir.chains["net-loc"]
        target = [r for r in _accept_rules(net_loc)
                  if _has_daddr(r, "10.0.0.7")]
        assert target, (
            "all→loc:10.0.0.7 ACCEPT placed *before* the catch-all "
            "must land — chain-complete only short-circuits later rules"
        )
