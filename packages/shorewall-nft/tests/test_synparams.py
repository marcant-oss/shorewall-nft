"""Tests for WP-G3: synparams SYN-flood protection.

Covers:
- A ``synparams`` row ``loc 100/sec 200`` creates a ``synflood-loc`` chain
  with the expected two-rule shape:
    1. ``limit rate 100/second burst 200 packets return``
    2. ``drop``
- Every zone-pair chain whose destination is the listed zone receives a
  prepended TCP SYN jump guard: ``tcp flags syn jump synflood-loc``.
- The ``synflood-<zone>`` chain itself does NOT receive the guard (no
  recursive injection).
- Base chains and ``sw_*`` chains are skipped.
- A zone not listed in synparams is not touched.
- ``_process_synparams`` is idempotent — a second call does not duplicate chains.
"""
from __future__ import annotations


from shorewall_nft.compiler.ir._data import (
    Chain,
    FirewallIR,
    RateLimitSpec,
    Rule,
    Verdict,
    Match,
    Hook,
    ChainType,
)
from shorewall_nft.compiler.ir._build import _process_synparams
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.config.zones import ZoneModel
from shorewall_nft.nft.emitter import _emit_rule_lines


# ── helpers ─────────────────────────────────────────────────────────────────


def _cfgline(*cols: str) -> ConfigLine:
    """Create a ConfigLine from column values."""
    return ConfigLine(columns=list(cols), file="synparams", lineno=1)


def _simple_zone_model(*zone_names: str, fw: str = "fw") -> ZoneModel:
    """Build a minimal ZoneModel with named zones."""
    from shorewall_nft.config.zones import Zone
    zm = ZoneModel()
    zm.firewall_zone = fw
    for name in zone_names:
        zm.zones[name] = Zone(name=name, zone_type="ipv4", options=[])
    return zm


def _ir_with_chains(*chain_names: str) -> FirewallIR:
    """Create a FirewallIR pre-populated with named zone-pair chains."""
    ir = FirewallIR()
    for name in chain_names:
        ir.chains[name] = Chain(name=name)
    return ir


def _synparams_line(zone: str, rate: str, burst: str) -> list[ConfigLine]:
    return [_cfgline(zone, rate, burst)]


# ── synflood chain shape ─────────────────────────────────────────────────────


class TestSynfloodChainShape:
    """The synflood chain must have exactly the right two rules."""

    def test_chain_created(self):
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        assert "synflood-loc" in ir.chains

    def test_chain_has_two_rules(self):
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        sf = ir.chains["synflood-loc"]
        assert len(sf.rules) == 2, (
            f"Expected 2 rules in synflood chain, got {len(sf.rules)}"
        )

    def test_first_rule_is_rate_limited_return(self):
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        sf = ir.chains["synflood-loc"]
        r0 = sf.rules[0]
        assert r0.verdict == Verdict.RETURN
        assert isinstance(r0.rate_limit, RateLimitSpec)
        assert r0.rate_limit.rate == 100
        assert r0.rate_limit.unit == "second"
        assert r0.rate_limit.burst == 200

    def test_second_rule_is_drop(self):
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        sf = ir.chains["synflood-loc"]
        r1 = sf.rules[1]
        assert r1.verdict == Verdict.DROP

    def test_chain_emit_shape(self):
        """End-to-end: emitted nft strings for the synflood chain."""
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        sf = ir.chains["synflood-loc"]
        stmts0 = _emit_rule_lines(sf.rules[0])
        stmts1 = _emit_rule_lines(sf.rules[1])
        assert len(stmts0) == 1
        assert "limit rate 100/second burst 200 packets" in stmts0[0]
        assert "return" in stmts0[0]
        assert len(stmts1) == 1
        assert "drop" in stmts1[0]


# ── SYN jump guard injection ─────────────────────────────────────────────────


class TestSynJumpInjection:
    def test_guard_prepended_to_dst_chain(self):
        """net-loc gets the TCP SYN jump guard prepended."""
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        rules = ir.chains["net-loc"].rules
        # Find the synflood jump rule
        jump_rules = [r for r in rules if r.verdict == Verdict.JUMP
                      and r.verdict_args == "synflood-loc"]
        assert jump_rules, "No synflood jump rule found in net-loc"

    def test_guard_matches_tcp_syn(self):
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        rules = ir.chains["net-loc"].rules
        jump_rules = [r for r in rules if r.verdict == Verdict.JUMP
                      and r.verdict_args == "synflood-loc"]
        assert jump_rules
        jr = jump_rules[0]
        # Must have a tcp flags match for syn
        syn_matches = [m for m in jr.matches if m.field == "tcp flags"]
        assert syn_matches, f"Expected tcp flags match, got {jr.matches!r}"
        assert syn_matches[0].value == "syn"

    def test_guard_not_added_to_unrelated_chain(self):
        """A chain for a zone not in synparams is untouched."""
        ir = _ir_with_chains("net-loc", "loc-fw")
        zm = _simple_zone_model("net", "loc", "fw")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        # loc-fw has dest="fw" which is not in synparams → no guard
        rules = ir.chains["loc-fw"].rules
        jump_rules = [r for r in rules if r.verdict == Verdict.JUMP
                      and getattr(r, "verdict_args", "").startswith("synflood-")]
        assert not jump_rules, f"Unexpected synflood guard in loc-fw: {rules!r}"

    def test_guard_not_added_to_synflood_chain_itself(self):
        """The synflood-loc chain must not receive a recursive guard."""
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        sf = ir.chains["synflood-loc"]
        jump_rules = [r for r in sf.rules if r.verdict == Verdict.JUMP
                      and getattr(r, "verdict_args", "").startswith("synflood-")]
        assert not jump_rules, (
            f"synflood-loc should not have a recursive jump: {sf.rules!r}"
        )

    def test_guard_injected_after_ct_state_rules(self):
        """SYN guard is inserted after existing ct-state rules, not at index 0."""
        ir = _ir_with_chains()
        zm = _simple_zone_model("net", "loc")
        chain = Chain(name="net-loc")
        # Simulate a prepended ct state rule
        chain.rules.append(Rule(
            matches=[Match(field="ct state", value="established,related")],
            verdict=Verdict.ACCEPT,
        ))
        chain.rules.append(Rule(
            matches=[Match(field="ct state", value="invalid")],
            verdict=Verdict.DROP,
        ))
        ir.chains["net-loc"] = chain
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        rules = ir.chains["net-loc"].rules
        # First two rules are still ct-state rules
        assert rules[0].matches[0].field == "ct state"
        assert rules[1].matches[0].field == "ct state"
        # Third rule (index 2) is the synflood jump
        assert rules[2].verdict == Verdict.JUMP
        assert rules[2].verdict_args == "synflood-loc"

    def test_multiple_dst_chains_all_get_guard(self):
        """All chains with dest=loc get the guard (net-loc and fw-loc)."""
        ir = _ir_with_chains("net-loc", "fw-loc", "loc-net")
        zm = _simple_zone_model("net", "loc", "fw")
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        for chain_name in ("net-loc", "fw-loc"):
            rules = ir.chains[chain_name].rules
            jump_rules = [r for r in rules if r.verdict == Verdict.JUMP
                          and r.verdict_args == "synflood-loc"]
            assert jump_rules, f"Missing synflood guard in {chain_name}"
        # loc-net has dst=net, which is NOT in synparams → no guard
        rules_loc_net = ir.chains["loc-net"].rules
        assert not any(r.verdict == Verdict.JUMP for r in rules_loc_net)


# ── edge cases ───────────────────────────────────────────────────────────────


class TestSynparamsEdgeCases:
    def test_idempotent_chain_creation(self):
        """Calling _process_synparams twice does not duplicate the chain."""
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        lines = _synparams_line("loc", "100/sec", "200")
        _process_synparams(ir, lines, zm)
        _process_synparams(ir, lines, zm)
        sf = ir.chains["synflood-loc"]
        assert len(sf.rules) == 2, (
            f"Idempotency: expected 2 rules after double call, got {len(sf.rules)}"
        )

    def test_empty_lines_noop(self):
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, [], zm)
        assert "synflood-loc" not in ir.chains
        assert not ir.chains["net-loc"].rules

    def test_minute_rate(self):
        """Rate expressed in /min is normalised to /minute in the chain."""
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        _process_synparams(ir, _synparams_line("loc", "60/min", "120"), zm)
        sf = ir.chains["synflood-loc"]
        rl = sf.rules[0].rate_limit
        assert isinstance(rl, RateLimitSpec)
        assert rl.unit == "minute"
        assert rl.burst == 120

    def test_sw_chain_skipped(self):
        """sw_* chains are never modified."""
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        sw_chain = Chain(name="sw_Reject")
        ir.chains["sw_Reject"] = sw_chain
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        assert not ir.chains["sw_Reject"].rules

    def test_base_chain_skipped(self):
        """Base chains (with a hook) are never modified."""
        ir = _ir_with_chains("net-loc")
        zm = _simple_zone_model("net", "loc")
        base = Chain(name="forward", chain_type=ChainType.FILTER,
                     hook=Hook.FORWARD)
        ir.chains["forward"] = base
        _process_synparams(ir, _synparams_line("loc", "100/sec", "200"), zm)
        assert not ir.chains["forward"].rules
