"""Regression: mangle/forward/postrouting chains must emit ``type filter``.

The kernel rejects ``type route`` outside the ``output`` hook
(verified on Linux 6.11 / nftables 1.1.1 — the message is
``Chain of type "route" is not supported, perhaps kernel support
is missing?``). Five chain-creation sites historically used
``ChainType.ROUTE`` for prerouting, forward, and postrouting
hooks, so any config exercising mangle, providers-mark, tcpri,
mangle-forward (TCPMSS), or mangle-postrouting (ECN) was
silently un-loadable.
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    Match,
    Rule,
    Verdict,
)
from shorewall_nft.compiler.verdicts import MarkVerdict
from shorewall_nft.nft.emitter import emit_nft


def _emit_chain(name: str, hook: Hook, *, chain_type: ChainType,
                priority: int) -> str:
    ir = FirewallIR()
    ir.add_chain(Chain(name=name, chain_type=chain_type,
                       hook=hook, priority=priority))
    rule = Rule(verdict=Verdict.ACCEPT,
                verdict_args=MarkVerdict(value=0x1))
    rule.matches.append(Match(field="iifname", value="eth0"))
    ir.chains[name].rules.append(rule)
    return emit_nft(ir)


def test_mangle_prerouting_emits_type_filter():
    """tc.process_mangle / providers / tcpri all create this chain."""
    out = _emit_chain("mangle-prerouting", Hook.PREROUTING,
                      chain_type=ChainType.FILTER, priority=-150)
    assert "type filter hook prerouting priority -150" in out
    assert "type route hook prerouting" not in out


def test_mangle_forward_emits_type_filter():
    """TCPMSS rules in ``_emit_mss_rules`` land here."""
    out = _emit_chain("mangle-forward", Hook.FORWARD,
                      chain_type=ChainType.FILTER, priority=-150)
    assert "type filter hook forward priority -150" in out
    assert "type route hook forward" not in out


def test_mangle_postrouting_emits_type_filter():
    """ECN rules in ``_emit_ecn_rules`` land here."""
    out = _emit_chain("mangle-postrouting", Hook.POSTROUTING,
                      chain_type=ChainType.FILTER, priority=-150)
    assert "type filter hook postrouting priority -150" in out
    assert "type route hook postrouting" not in out
