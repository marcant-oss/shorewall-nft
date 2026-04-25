"""Tests for WP-E3: BLACKLIST file + DYNAMIC_BLACKLIST modes.

Covers:
- DYNAMIC_BLACKLIST=No → no dyn-blacklist chain emitted.
- =Yes / =ipset-only   → standard ipset+drop chain emitted.
- =ipset,disconnect    → standard chain + disconnect rule in forward.
- =ipset,disconnect-src → same as ipset,disconnect (src-only variant).
- BLACKLIST file with 2 rows produces matching drop rules in the
  blacklist chain.
- BLACKLIST_DISPOSITION is honoured in the blacklist file processing.
"""
from __future__ import annotations

import pytest

from shorewall_nft.compiler.actions import create_dynamic_blacklist
from shorewall_nft.compiler.ir._build import _process_blacklist
from shorewall_nft.compiler.ir._data import (
    Chain,
    FirewallIR,
    Hook,
    ChainType,
    Verdict,
)
from shorewall_nft.config.parser import ConfigLine


# ── helpers ─────────────────────────────────────────────────────────────────


def _cfgline(*cols: str) -> ConfigLine:
    return ConfigLine(columns=list(cols), file="blacklist", lineno=1)


def _ir_with_forward(**settings: str) -> FirewallIR:
    ir = FirewallIR()
    ir.settings.update(settings)
    forward = Chain(
        name="forward",
        chain_type=ChainType.FILTER,
        hook=Hook.FORWARD,
        priority=0,
        policy=Verdict.DROP,
    )
    ir.chains["forward"] = forward
    return ir


# ── DYNAMIC_BLACKLIST=No ────────────────────────────────────────────────────


class TestDynamicBlacklistNo:
    def test_no_chain_emitted(self):
        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = "No"
        create_dynamic_blacklist(ir, ir.settings)
        assert "sw_dynamic-blacklist" not in ir.chains

    def test_empty_string_is_also_disabled(self):
        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = ""
        create_dynamic_blacklist(ir, ir.settings)
        assert "sw_dynamic-blacklist" not in ir.chains

    def test_absent_key_is_disabled(self):
        ir = FirewallIR()
        create_dynamic_blacklist(ir, ir.settings)
        assert "sw_dynamic-blacklist" not in ir.chains


# ── DYNAMIC_BLACKLIST=Yes / ipset-only ──────────────────────────────────────


class TestDynamicBlacklistYes:
    @pytest.mark.parametrize("mode", ["Yes", "yes", "ipset-only", "ipset-only"])
    def test_chain_created(self, mode):
        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = mode
        create_dynamic_blacklist(ir, ir.settings)
        assert "sw_dynamic-blacklist" in ir.chains

    @pytest.mark.parametrize("mode", ["Yes", "ipset-only"])
    def test_chain_has_drop_rule(self, mode):
        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = mode
        create_dynamic_blacklist(ir, ir.settings)
        chain = ir.chains["sw_dynamic-blacklist"]
        assert any(
            r.verdict == Verdict.DROP
            and any(m.field == "ip saddr" and "@dynamic_blacklist" in m.value
                    for m in r.matches)
            for r in chain.rules
        )

    @pytest.mark.parametrize("mode", ["Yes", "ipset-only"])
    def test_no_disconnect_rule_in_forward(self, mode):
        ir = _ir_with_forward(DYNAMIC_BLACKLIST=mode)
        create_dynamic_blacklist(ir, ir.settings)
        forward_rules = ir.chains["forward"].rules
        disconnect_rules = [
            r for r in forward_rules
            if any("dynamic_blacklist" in m.value for m in r.matches)
        ]
        assert not disconnect_rules, (
            f"mode={mode!r}: no disconnect rule expected in forward"
        )

    @pytest.mark.parametrize("mode", ["Yes", "ipset-only"])
    def test_ir_dynamic_blacklist_flag_set(self, mode):
        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = mode
        create_dynamic_blacklist(ir, ir.settings)
        assert getattr(ir, "_dynamic_blacklist", False)


# ── DYNAMIC_BLACKLIST=ipset,disconnect ──────────────────────────────────────


class TestDynamicBlacklistDisconnect:
    @pytest.mark.parametrize("mode", ["ipset,disconnect", "ipset,disconnect-src"])
    def test_chain_created(self, mode):
        ir = _ir_with_forward(DYNAMIC_BLACKLIST=mode)
        create_dynamic_blacklist(ir, ir.settings)
        assert "sw_dynamic-blacklist" in ir.chains

    @pytest.mark.parametrize("mode", ["ipset,disconnect", "ipset,disconnect-src"])
    def test_disconnect_rule_in_forward_at_position_0(self, mode):
        ir = _ir_with_forward(DYNAMIC_BLACKLIST=mode)
        create_dynamic_blacklist(ir, ir.settings)
        forward_rules = ir.chains["forward"].rules
        assert forward_rules, "forward chain must have rules after disconnect inject"
        first = forward_rules[0]
        assert any("dynamic_blacklist" in m.value for m in first.matches), (
            "first forward rule must reference the dynamic_blacklist set"
        )
        established_match = any(
            m.field == "ct state" and "established" in m.value
            for m in first.matches
        )
        assert established_match

    @pytest.mark.parametrize("mode", ["ipset,disconnect", "ipset,disconnect-src"])
    def test_disconnect_rule_drops_established(self, mode):
        ir = _ir_with_forward(DYNAMIC_BLACKLIST=mode)
        create_dynamic_blacklist(ir, ir.settings)
        first = ir.chains["forward"].rules[0]
        assert first.verdict == Verdict.DROP

    def test_no_forward_chain_no_crash(self):
        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = "ipset,disconnect"
        create_dynamic_blacklist(ir, ir.settings)
        assert "sw_dynamic-blacklist" in ir.chains


# ── v6 sibling parity (audit gap closure) ────────────────────────────────────


class TestDynamicBlacklistV6Parity:
    """The dynamic-blacklist chain + disconnect rules must emit a v6 sibling.

    Surfaced by the v4-vs-v6 emit-parity audit at
    `tmp/v4-v6-parity-audit/AUDIT.md` — the chain previously held only an
    `ip saddr @dynamic_blacklist` DROP rule, so a blacklisted IPv6 source
    bypassed the entire mechanism. Closure: a parallel `ip6 saddr
    @dynamic_blacklist_v6` rule sits next to its v4 sibling, and the
    emitter declares both sets when the flag is on.
    """

    @pytest.mark.parametrize("mode", ["Yes", "ipset-only", "ipset,disconnect"])
    def test_chain_has_v6_drop_rule(self, mode):
        ir = _ir_with_forward(DYNAMIC_BLACKLIST=mode)
        create_dynamic_blacklist(ir, ir.settings)
        chain = ir.chains["sw_dynamic-blacklist"]
        assert any(
            r.verdict == Verdict.DROP
            and any(m.field == "ip6 saddr"
                    and "@dynamic_blacklist_v6" in m.value
                    for m in r.matches)
            for r in chain.rules
        ), (
            f"mode={mode!r}: sw_dynamic-blacklist chain must hold a "
            "ip6 saddr @dynamic_blacklist_v6 DROP rule"
        )

    @pytest.mark.parametrize("mode", ["Yes", "ipset-only"])
    def test_chain_has_both_v4_and_v6_drop_rules(self, mode):
        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = mode
        create_dynamic_blacklist(ir, ir.settings)
        chain = ir.chains["sw_dynamic-blacklist"]
        v4 = sum(
            1 for r in chain.rules
            if any(m.field == "ip saddr" and "@dynamic_blacklist" == m.value.split("_v6")[0].rstrip("@")
                   for m in r.matches)
        )
        v6 = sum(
            1 for r in chain.rules
            if any(m.field == "ip6 saddr" and "@dynamic_blacklist_v6" in m.value
                   for m in r.matches)
        )
        # 1 v4 + 1 v6 — exactly one DROP rule per family.
        assert v4 == 1 and v6 == 1, f"mode={mode!r}: chain rules={chain.rules!r}"

    @pytest.mark.parametrize("mode", ["ipset,disconnect", "ipset,disconnect-src"])
    def test_disconnect_inserts_both_families_in_forward(self, mode):
        ir = _ir_with_forward(DYNAMIC_BLACKLIST=mode)
        create_dynamic_blacklist(ir, ir.settings)
        forward_rules = ir.chains["forward"].rules
        # Both v4 and v6 disconnect rules must be at the top of the
        # forward chain. v4 sits at index 0 (preserves the existing
        # contract); v6 at index 1.
        assert len(forward_rules) >= 2
        v4_rule, v6_rule = forward_rules[0], forward_rules[1]
        assert any(m.field == "ip saddr" and m.value == "@dynamic_blacklist"
                   for m in v4_rule.matches)
        assert any(m.field == "ip6 saddr"
                   and m.value == "@dynamic_blacklist_v6"
                   for m in v6_rule.matches)
        # Both must drop established flows.
        for r in (v4_rule, v6_rule):
            assert r.verdict == Verdict.DROP
            assert any(m.field == "ct state" and "established" in m.value
                       for m in r.matches)


class TestDynamicBlacklistEmitDeclaresBothSets:
    """The emitter must declare BOTH dynamic_blacklist sets when the flag is on."""

    def test_emit_declares_v4_and_v6_sets(self):
        from shorewall_nft.nft.emitter import emit_nft

        ir = FirewallIR()
        ir.settings["DYNAMIC_BLACKLIST"] = "Yes"
        create_dynamic_blacklist(ir, ir.settings)
        out = emit_nft(ir)
        assert "set dynamic_blacklist {" in out
        assert "type ipv4_addr;" in out
        assert "set dynamic_blacklist_v6 {" in out
        assert "type ipv6_addr;" in out


# ── BLACKLIST file processing ────────────────────────────────────────────────


class TestBlacklistFileProcessing:
    def test_two_rows_create_two_rules(self):
        ir = FirewallIR()
        lines = [
            _cfgline("192.0.2.0/24"),
            _cfgline("198.51.100.1", "tcp", "80"),
        ]
        _process_blacklist(ir, lines)
        chain = ir.chains["blacklist"]
        assert len(chain.rules) == 2

    def test_address_only_row(self):
        ir = FirewallIR()
        _process_blacklist(ir, [_cfgline("192.0.2.1")])
        rule = ir.chains["blacklist"].rules[0]
        assert any(m.field == "ip saddr" and m.value == "192.0.2.1"
                   for m in rule.matches)
        assert not any(m.field == "meta l4proto" for m in rule.matches)

    def test_proto_port_row(self):
        ir = FirewallIR()
        _process_blacklist(ir, [_cfgline("192.0.2.2", "tcp", "443")])
        rule = ir.chains["blacklist"].rules[0]
        assert any(m.field == "meta l4proto" and m.value == "tcp"
                   for m in rule.matches)
        assert any(m.field == "tcp dport" and m.value == "443"
                   for m in rule.matches)

    def test_ipv6_address_uses_ip6_saddr(self):
        ir = FirewallIR()
        _process_blacklist(ir, [_cfgline("2001:db8::/32")])
        rule = ir.chains["blacklist"].rules[0]
        assert any(m.field == "ip6 saddr" for m in rule.matches)

    def test_default_disposition_is_drop(self):
        ir = FirewallIR()
        _process_blacklist(ir, [_cfgline("10.0.0.1")])
        assert ir.chains["blacklist"].rules[0].verdict == Verdict.DROP

    def test_blacklist_disposition_reject(self):
        ir = FirewallIR()
        ir.settings["BLACKLIST_DISPOSITION"] = "REJECT"
        _process_blacklist(ir, [_cfgline("10.0.0.1")])
        assert ir.chains["blacklist"].rules[0].verdict == Verdict.REJECT

    def test_empty_lines_skipped(self):
        ir = FirewallIR()
        empty = ConfigLine(columns=[], file="blacklist", lineno=1)
        _process_blacklist(ir, [empty])
        if "blacklist" in ir.chains:
            assert len(ir.chains["blacklist"].rules) == 0
        else:
            pass

    def test_dash_proto_treated_as_absent(self):
        ir = FirewallIR()
        _process_blacklist(ir, [_cfgline("10.0.0.2", "-", "-")])
        rule = ir.chains["blacklist"].rules[0]
        assert not any(m.field == "meta l4proto" for m in rule.matches)

    def test_chain_shared_with_blrules(self):
        from shorewall_nft.compiler.ir._build import _process_blrules
        from shorewall_nft.config.zones import ZoneModel
        ir = FirewallIR()
        zm = ZoneModel()
        _process_blacklist(ir, [_cfgline("10.0.0.1")])
        assert "blacklist" in ir.chains
        initial_len = len(ir.chains["blacklist"].rules)
        blline = ConfigLine(columns=["DROP", "net:10.0.0.0/8", "-"],
                            file="blrules", lineno=1)
        _process_blrules(ir, [blline], zm)
        assert len(ir.chains["blacklist"].rules) > initial_len
