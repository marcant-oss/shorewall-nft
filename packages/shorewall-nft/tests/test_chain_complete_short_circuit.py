"""Regression tests for the chain-complete short-circuit (rules.py:1149).

The short-circuit closes a per-pair chain after a redundant catch-all
``<zone> any`` DROP/REJECT lands on a chain whose policy is already
drop-class.  That mirrors classic shorewall when the wildcard rule
*precedes* later includes — but it must not swallow ``all → <zone>``
expansions emitted in the same rules file.

Concrete user-visible breakage that prompted these tests: the rossini
reference rules carry

    DROP:$LOG  agfeo  any                         # rules:1042
    Web(ACCEPT) all  cdn:46.231.239.{9,10,14}     # rules:1478

with policy ``agfeo all REJECT $LOG``.  Classic shorewall emits all
13+ DreamRobot daddr ACCEPTs into ``agfeo2cdn`` in iptables-save —
the IR drops them because line 1042 marked the chain complete before
line 1478 was processed.  Surfaced as 53 fail_drops in the simlab
reference replay (every probe with src=213.149.66.254 → cdn/devop/
host/mccp/mccpx/dbm2m got REJECTed).
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


class TestCatchAllDoesNotShadowAllExpansion:
    """A redundant ``<zone> any`` DROP/REJECT must not block a later
    ``all → <zone>`` ACCEPT from landing in the same per-pair chain.

    Classic shorewall iptables-save retains both verdicts (the
    catch-all is omitted as redundant with policy, but does not close
    the chain) — anything else diverges from the point of truth.
    """

    def test_all_dest_accept_lands_after_catch_all_reject_with_reject_policy(self):
        # Minimal config has policy ``net all DROP $LOG`` and
        # ``all all REJECT $LOG`` — both drop-class.  net→loc is
        # therefore drop-class, which is the precondition for the
        # chain-complete short-circuit to fire.
        ir = _ir_with_rules([
            ["DROP:$LOG", "net", "any"],
            ["ACCEPT", "all", "loc:10.0.0.5", "tcp", "80"],
        ])
        net_loc = ir.chains["net-loc"]
        accepts = _accept_rules(net_loc)
        target_accepts = [r for r in accepts if _has_daddr(r, "10.0.0.5")]
        assert target_accepts, (
            "expected the all→loc:10.0.0.5 ACCEPT to land in net-loc "
            "even after the redundant DROP:$LOG net any catch-all; "
            f"got {len(accepts)} ACCEPT rules, none with daddr=10.0.0.5"
        )

    def test_catch_all_drop_itself_is_omitted(self):
        # Counter-pin: the catch-all DROP that *is* redundant with the
        # drop-class policy must NOT appear as a separate rule in the
        # chain — that's the half of the short-circuit that mirrors
        # classic shorewall correctly.  Only the chain-completing
        # half is wrong; this assertion guards the fix from over-
        # reaching and re-introducing the redundant DROP.
        ir = _ir_with_rules([
            ["DROP:$LOG", "net", "any"],
        ])
        net_loc = ir.chains["net-loc"]
        # No unconditional drop/reject rule in the body — the policy
        # tail handles it.
        unconditional_drops = [
            r for r in net_loc.rules
            if r.verdict.name in ("DROP", "REJECT") and not r.matches
        ]
        assert not unconditional_drops, (
            "redundant catch-all DROP must be omitted (policy covers it); "
            f"found {len(unconditional_drops)} unconditional drop rules"
        )

    def test_catch_all_reject_does_not_block_all_expansion(self):
        # Same scenario as the headline test but with REJECT instead
        # of DROP — the short-circuit treats both as drop-class and
        # the rossini reference uses REJECT in the policy column.
        ir = _ir_with_rules([
            ["REJECT", "net", "any"],
            ["ACCEPT", "all", "loc:10.0.0.6", "tcp", "443"],
        ])
        net_loc = ir.chains["net-loc"]
        target = [r for r in _accept_rules(net_loc)
                  if _has_daddr(r, "10.0.0.6")]
        assert target, (
            "all→loc:10.0.0.6 ACCEPT must land even after a catch-all "
            "REJECT for net→any (mirrors agfeo→cdn in rossini reference)"
        )
