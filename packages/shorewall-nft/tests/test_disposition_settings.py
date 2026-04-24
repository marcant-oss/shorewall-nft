"""Tests for WP-E2: disposition settings.

Covers all seven DISPOSITION settings:
  BLACKLIST_DISPOSITION, SMURF_DISPOSITION, TCP_FLAGS_DISPOSITION,
  MACLIST_DISPOSITION, RELATED_DISPOSITION, INVALID_DISPOSITION,
  UNTRACKED_DISPOSITION

For each setting, a matrix over the valid disposition values
(DROP / REJECT / A_DROP / A_REJECT / ACCEPT where allowed) asserts
that the correct verdict appears in the relevant chain or rules.
"""
from __future__ import annotations

import pytest

from shorewall_nft.compiler.actions import (
    _disposition_to_verdict,
    create_action_chains,
)
from shorewall_nft.compiler.ir._build import _prepend_ct_state_to_zone_pair_chains
from shorewall_nft.compiler.ir._data import (
    Chain,
    FirewallIR,
    Rule,
    Verdict,
)
from shorewall_nft.compiler.verdicts import AuditVerdict
from shorewall_nft.config.zones import Zone, ZoneModel


# ── helper: minimal IR with two zone-pair chains ────────────────────────────


def _ir_with_settings(**settings: str) -> FirewallIR:
    """Return a bare FirewallIR whose settings dict is pre-populated."""
    ir = FirewallIR()
    ir.settings.update(settings)
    return ir


def _ir_with_zone_pair(chain_name: str, **settings: str) -> FirewallIR:
    """IR with two zones and one pre-created zone-pair chain."""
    ir = _ir_with_settings(**settings)
    src, _, dst = chain_name.partition("-")
    zm = ZoneModel()
    zm.zones[src] = Zone(name=src, zone_type="ip", options=[])
    zm.zones[dst] = Zone(name=dst, zone_type="ip", options=[])
    ir.zones = zm
    ir.chains[chain_name] = Chain(name=chain_name)
    return ir


# ── _disposition_to_verdict helper ─────────────────────────────────────────


class TestDispositionToVerdict:
    @pytest.mark.parametrize("value,exp_verdict,exp_audit", [
        ("DROP",     Verdict.DROP,   None),
        ("REJECT",   Verdict.REJECT, None),
        ("ACCEPT",   Verdict.ACCEPT, None),
        ("A_DROP",   Verdict.DROP,   AuditVerdict("DROP")),
        ("A_REJECT", Verdict.REJECT, AuditVerdict("REJECT")),
        ("drop",     Verdict.DROP,   None),   # case-insensitive
        ("a_drop",   Verdict.DROP,   AuditVerdict("DROP")),
        ("unknown",  Verdict.DROP,   None),   # fallback
    ])
    def test_mapping(self, value, exp_verdict, exp_audit):
        v, a = _disposition_to_verdict(value)
        assert v == exp_verdict
        assert a == exp_audit


# ── BLACKLIST_DISPOSITION ───────────────────────────────────────────────────


class TestBlacklistDisposition:
    def _build(self, disp: str) -> list[Rule]:
        ir = _ir_with_settings(BLACKLIST_DISPOSITION=disp)
        create_action_chains(ir)
        chain = ir.chains["sw_BLACKLIST"]
        return chain.rules

    @pytest.mark.parametrize("disp,exp_verdict", [
        ("DROP",    Verdict.DROP),
        ("REJECT",  Verdict.REJECT),
    ])
    def test_terminal_verdict(self, disp, exp_verdict):
        rules = self._build(disp)
        assert rules[-1].verdict == exp_verdict
        assert rules[-1].verdict_args is None

    @pytest.mark.parametrize("disp,exp_audit_action", [
        ("A_DROP",   "DROP"),
        ("A_REJECT", "REJECT"),
    ])
    def test_audit_prepends_then_base_action(self, disp, exp_audit_action):
        rules = self._build(disp)
        audit_rules = [r for r in rules if isinstance(r.verdict_args, AuditVerdict)]
        assert len(audit_rules) == 1
        assert audit_rules[0].verdict_args.base_action == exp_audit_action
        terminal = rules[-1]
        expected_v = Verdict.DROP if exp_audit_action == "DROP" else Verdict.REJECT
        assert terminal.verdict == expected_v

    def test_default_is_drop(self):
        ir = FirewallIR()
        create_action_chains(ir)
        chain = ir.chains["sw_BLACKLIST"]
        assert chain.rules[-1].verdict == Verdict.DROP
        assert chain.rules[-1].verdict_args is None


# ── SMURF_DISPOSITION ───────────────────────────────────────────────────────


class TestSmurfDisposition:
    def _build(self, disp: str) -> list[Rule]:
        ir = _ir_with_settings(SMURF_DISPOSITION=disp)
        create_action_chains(ir)
        return ir.chains["sw_DropSmurfs"].rules

    def test_drop(self):
        rules = self._build("DROP")
        assert rules[-1].verdict == Verdict.DROP
        assert rules[-1].verdict_args is None

    def test_a_drop(self):
        rules = self._build("A_DROP")
        audit_rules = [r for r in rules if isinstance(r.verdict_args, AuditVerdict)]
        assert len(audit_rules) == 1
        assert audit_rules[0].verdict_args.base_action == "DROP"
        assert rules[-1].verdict == Verdict.DROP

    def test_default_is_drop(self):
        ir = FirewallIR()
        create_action_chains(ir)
        rules = ir.chains["sw_DropSmurfs"].rules
        assert rules[-1].verdict == Verdict.DROP
        assert rules[-1].verdict_args is None


# ── TCP_FLAGS_DISPOSITION ───────────────────────────────────────────────────


class TestTcpFlagsDisposition:
    def _build(self, disp: str) -> list[Rule]:
        ir = _ir_with_settings(TCP_FLAGS_DISPOSITION=disp)
        create_action_chains(ir)
        return ir.chains["sw_TCPFlags"].rules

    @pytest.mark.parametrize("disp,exp_verdict", [
        ("DROP",   Verdict.DROP),
        ("REJECT", Verdict.REJECT),
    ])
    def test_base_verdict(self, disp, exp_verdict):
        rules = self._build(disp)
        non_audit = [r for r in rules if not isinstance(r.verdict_args, AuditVerdict)]
        assert all(r.verdict == exp_verdict for r in non_audit)

    @pytest.mark.parametrize("disp,exp_audit", [
        ("A_DROP",   "DROP"),
        ("A_REJECT", "REJECT"),
    ])
    def test_audit_pairs(self, disp, exp_audit):
        rules = self._build(disp)
        audit_rules = [r for r in rules if isinstance(r.verdict_args, AuditVerdict)]
        non_audit = [r for r in rules if not isinstance(r.verdict_args, AuditVerdict)]
        assert len(audit_rules) == len(non_audit) == 4
        assert all(a.verdict_args.base_action == exp_audit for a in audit_rules)

    def test_default_is_drop(self):
        ir = FirewallIR()
        create_action_chains(ir)
        rules = ir.chains["sw_TCPFlags"].rules
        assert all(r.verdict == Verdict.DROP for r in rules)


# ── RELATED_DISPOSITION ─────────────────────────────────────────────────────


class TestRelatedDisposition:
    def _build(self, disp: str) -> list[Rule]:
        ir = _ir_with_zone_pair("loc-fw", RELATED_DISPOSITION=disp)
        _prepend_ct_state_to_zone_pair_chains(ir, include_established=True)
        return ir.chains["loc-fw"].rules

    @pytest.mark.parametrize("disp,exp_verdict", [
        ("ACCEPT", Verdict.ACCEPT),
        ("DROP",   Verdict.DROP),
    ])
    def test_related_verdict(self, disp, exp_verdict):
        rules = self._build(disp)
        related = [r for r in rules
                   if any(m.field == "ct state" and "established" in m.value
                          for m in r.matches)
                   and not isinstance(r.verdict_args, AuditVerdict)]
        assert related
        assert related[0].verdict == exp_verdict

    def test_a_drop_emits_audit(self):
        rules = self._build("A_DROP")
        audit_rules = [r for r in rules
                       if isinstance(r.verdict_args, AuditVerdict)
                       and any(m.field == "ct state" and "established" in m.value
                               for m in r.matches)]
        assert len(audit_rules) == 1

    def test_default_is_accept(self):
        ir = _ir_with_zone_pair("loc-fw")
        _prepend_ct_state_to_zone_pair_chains(ir, include_established=True)
        rules = ir.chains["loc-fw"].rules
        related = [r for r in rules
                   if any(m.field == "ct state" and "established" in m.value
                          for m in r.matches)
                   and not isinstance(r.verdict_args, AuditVerdict)]
        assert related[0].verdict == Verdict.ACCEPT


# ── INVALID_DISPOSITION ─────────────────────────────────────────────────────


class TestInvalidDisposition:
    def _build(self, disp: str) -> list[Rule]:
        ir = _ir_with_zone_pair("loc-fw", INVALID_DISPOSITION=disp)
        _prepend_ct_state_to_zone_pair_chains(ir, include_established=False)
        return ir.chains["loc-fw"].rules

    @pytest.mark.parametrize("disp,exp_verdict", [
        ("DROP",   Verdict.DROP),
        ("REJECT", Verdict.REJECT),
    ])
    def test_invalid_verdict(self, disp, exp_verdict):
        rules = self._build(disp)
        invalid = [r for r in rules
                   if any(m.field == "ct state" and m.value == "invalid"
                          for m in r.matches)
                   and not isinstance(r.verdict_args, AuditVerdict)]
        assert invalid
        assert invalid[0].verdict == exp_verdict

    def test_a_drop_emits_audit(self):
        rules = self._build("A_DROP")
        audit = [r for r in rules
                 if isinstance(r.verdict_args, AuditVerdict)
                 and any(m.field == "ct state" and m.value == "invalid"
                         for m in r.matches)]
        assert len(audit) == 1

    def test_default_is_drop(self):
        ir = _ir_with_zone_pair("loc-fw")
        _prepend_ct_state_to_zone_pair_chains(ir, include_established=False)
        rules = ir.chains["loc-fw"].rules
        invalid = [r for r in rules
                   if any(m.field == "ct state" and m.value == "invalid"
                          for m in r.matches)
                   and not isinstance(r.verdict_args, AuditVerdict)]
        assert invalid[0].verdict == Verdict.DROP


# ── UNTRACKED_DISPOSITION ───────────────────────────────────────────────────


class TestUntrackedDisposition:
    def _build(self, disp: str) -> list[Rule]:
        ir = _ir_with_zone_pair("loc-fw", UNTRACKED_DISPOSITION=disp)
        _prepend_ct_state_to_zone_pair_chains(ir, include_established=False)
        return ir.chains["loc-fw"].rules

    @pytest.mark.parametrize("disp,exp_verdict", [
        ("ACCEPT", Verdict.ACCEPT),
        ("DROP",   Verdict.DROP),
        ("REJECT", Verdict.REJECT),
    ])
    def test_untracked_verdict(self, disp, exp_verdict):
        rules = self._build(disp)
        untracked = [r for r in rules
                     if any(m.field == "ct state" and m.value == "untracked"
                            for m in r.matches)
                     and not isinstance(r.verdict_args, AuditVerdict)]
        assert untracked, f"No untracked rule emitted for UNTRACKED_DISPOSITION={disp}"
        assert untracked[0].verdict == exp_verdict

    def test_a_drop_emits_audit(self):
        rules = self._build("A_DROP")
        audit = [r for r in rules
                 if isinstance(r.verdict_args, AuditVerdict)
                 and any(m.field == "ct state" and m.value == "untracked"
                         for m in r.matches)]
        assert len(audit) == 1

    def test_absent_emits_no_untracked_rule(self):
        ir = _ir_with_zone_pair("loc-fw")
        _prepend_ct_state_to_zone_pair_chains(ir, include_established=False)
        rules = ir.chains["loc-fw"].rules
        untracked = [r for r in rules
                     if any(m.field == "ct state" and m.value == "untracked"
                            for m in r.matches)]
        assert not untracked, "No UNTRACKED_DISPOSITION set → no rule expected"


# ── MACLIST_DISPOSITION — already wired; spot-check the integration ─────────


class TestMaclistDisposition:
    def test_reject_default(self):
        from shorewall_nft.compiler.macfilter import process_maclist
        from shorewall_nft.config.parser import ConfigLine
        ir = FirewallIR()
        ir.chains["input"] = Chain(name="input")
        lines = [ConfigLine(columns=["ACCEPT", "eth0", "aa:bb:cc:dd:ee:ff"],
                            file="maclist", lineno=1)]
        process_maclist(ir, lines, disposition="REJECT")
        rules = ir.chains["input"].rules
        assert any(r.verdict == Verdict.ACCEPT for r in rules)
