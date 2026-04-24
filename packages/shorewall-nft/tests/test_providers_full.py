"""Tests for full providers.py implementation (WP-B1 / WP-B3).

Covers:
- parse_providers: column parsing, option matrix
- emit_provider_marks: mangle-prerouting nft rules (channel 1)
- emit_iproute2_setup: shell script generation (channel 2)
- WP-B3 settings: USE_DEFAULT_RT, BALANCE_PROVIDERS, RESTORE_DEFAULT_ROUTE,
  OPTIMIZE_USE_FIRST
"""

from __future__ import annotations

import pytest

from shorewall_nft.compiler.providers import (
    Provider,
    emit_iproute2_setup,
    emit_provider_marks,
    parse_providers,
)
from shorewall_nft.config.parser import ConfigLine


def _line(cols: list[str], lineno: int = 1) -> ConfigLine:
    return ConfigLine(columns=cols, file="providers", lineno=lineno)


def _providers_from_cols(rows: list[list[str]]) -> list[Provider]:
    return parse_providers([_line(cols, i + 1) for i, cols in enumerate(rows)])


# ── parse_providers ─────────────────────────────────────────────────────

class TestParseProviders:
    def test_basic_columns(self):
        # NAME NUMBER MARK DUPLICATE INTERFACE GATEWAY OPTIONS COPY
        rows = [["isp1", "1", "0x01", "-", "eth0", "203.0.113.1", "-", "-"]]
        providers = _providers_from_cols(rows)
        assert len(providers) == 1
        p = providers[0]
        assert p.name == "isp1"
        assert p.number == 1
        assert p.mark == 0x01
        assert p.interface == "eth0"
        assert p.gateway == "203.0.113.1"
        assert p.duplicate is None
        assert p.copy == []

    def test_mark_dash_means_zero(self):
        rows = [["isp1", "1", "-", "-", "eth0", "-", "-", "-"]]
        p = _providers_from_cols(rows)[0]
        assert p.mark == 0

    def test_duplicate_column(self):
        rows = [["isp2", "2", "0x02", "main", "eth1", "198.51.100.1", "-", "-"]]
        p = _providers_from_cols(rows)[0]
        assert p.duplicate == "main"

    def test_interface_with_address_stripped(self):
        rows = [["isp1", "1", "0x01", "-", "eth0:192.0.2.1", "-", "-", "-"]]
        p = _providers_from_cols(rows)[0]
        assert p.interface == "eth0"

    def test_copy_none_expands_to_interface(self):
        rows = [["isp1", "1", "0x01", "main", "eth0", "-", "-", "none"]]
        p = _providers_from_cols(rows)[0]
        assert p.copy == ["eth0"]

    def test_copy_multiple(self):
        rows = [["isp1", "1", "0x01", "main", "eth0", "-", "-", "eth1,eth2"]]
        p = _providers_from_cols(rows)[0]
        assert p.copy == ["eth1", "eth2"]

    def test_skip_dash_name(self):
        rows = [["-", "1", "0x01", "-", "eth0", "-", "-", "-"]]
        assert _providers_from_cols(rows) == []

    def test_skip_too_few_columns(self):
        providers = parse_providers([_line(["isp1", "1"])])
        assert providers == []

    def test_multiple_providers(self):
        rows = [
            ["isp1", "1", "0x01", "-", "eth0", "203.0.113.1", "-", "-"],
            ["isp2", "2", "0x02", "-", "eth1", "198.51.100.1", "-", "-"],
        ]
        providers = _providers_from_cols(rows)
        assert len(providers) == 2
        assert providers[0].name == "isp1"
        assert providers[1].name == "isp2"


class TestParseProviderOptions:
    def _parse_opts(self, opts: str) -> Provider:
        rows = [["isp1", "1", "0x01", "-", "eth0", "203.0.113.1", opts, "-"]]
        return _providers_from_cols(rows)[0]

    def test_track(self):
        assert self._parse_opts("track").track is True

    def test_notrack(self):
        p = self._parse_opts("track,notrack")
        assert p.track is False

    def test_balance(self):
        assert self._parse_opts("balance").balance == 1

    def test_primary_alias_for_balance(self):
        assert self._parse_opts("primary").balance == 1

    def test_balance_weight(self):
        assert self._parse_opts("balance=3").balance == 3

    def test_loose(self):
        assert self._parse_opts("loose").loose is True

    def test_optional(self):
        assert self._parse_opts("optional").optional is True

    def test_fallback(self):
        assert self._parse_opts("fallback").fallback == -1

    def test_fallback_weight(self):
        assert self._parse_opts("fallback=5").fallback == 5

    def test_persistent(self):
        assert self._parse_opts("persistent").persistent is True

    def test_tproxy(self):
        p = self._parse_opts("tproxy")
        assert p.tproxy is True
        assert p.track is False

    def test_local_alias_for_tproxy(self):
        p = self._parse_opts("local")
        assert p.tproxy is True

    def test_multiple_options(self):
        p = self._parse_opts("track,balance=2,optional")
        assert p.track is True
        assert p.balance == 2
        assert p.optional is True


# ── emit_provider_marks ─────────────────────────────────────────────────

class TestEmitProviderMarks:
    def _make_ir(self):
        from shorewall_nft.compiler.ir._data import FirewallIR, MarkGeometry
        ir = FirewallIR()
        ir.mark_geometry = MarkGeometry.default()
        return ir

    def test_creates_mangle_prerouting_chain(self):
        ir = self._make_ir()
        providers = [Provider(name="isp1", number=1, mark=0x01,
                               interface="eth0", table="1")]
        emit_provider_marks(ir, providers)
        assert "mangle-prerouting" in ir.chains

    def test_mark_rule_added(self):
        ir = self._make_ir()
        providers = [Provider(name="isp1", number=1, mark=0x01,
                               interface="eth0", table="1")]
        emit_provider_marks(ir, providers)
        mangle = ir.chains["mangle-prerouting"]
        assert len(mangle.rules) == 1
        rule = mangle.rules[0]
        assert rule.matches[0].field == "iifname"
        assert rule.matches[0].value == "eth0"
        assert rule.comment == "provider:isp1"

    def test_zero_mark_skipped(self):
        ir = self._make_ir()
        providers = [Provider(name="isp1", number=1, mark=0,
                               interface="eth0", table="1")]
        emit_provider_marks(ir, providers)
        if "mangle-prerouting" in ir.chains:
            assert len(ir.chains["mangle-prerouting"].rules) == 0

    def test_two_providers_two_rules(self):
        ir = self._make_ir()
        providers = [
            Provider(name="isp1", number=1, mark=0x01, interface="eth0", table="1"),
            Provider(name="isp2", number=2, mark=0x02, interface="eth1", table="2"),
        ]
        emit_provider_marks(ir, providers)
        assert len(ir.chains["mangle-prerouting"].rules) == 2

    def test_uses_provider_mask(self):
        from shorewall_nft.compiler.ir._data import FirewallIR, MarkGeometry
        ir = FirewallIR()
        # HIGH_ROUTE_MARKS → provider_mask = 0xFF00
        ir.mark_geometry = MarkGeometry.from_settings({"HIGH_ROUTE_MARKS": "Yes"})
        # Mark 0x0100 is within 0xFF00 mask
        providers = [Provider(name="isp1", number=1, mark=0x0100,
                               interface="eth0", table="1")]
        emit_provider_marks(ir, providers)
        mangle = ir.chains["mangle-prerouting"]
        from shorewall_nft.compiler.verdicts import MarkVerdict
        assert isinstance(mangle.rules[0].verdict_args, MarkVerdict)
        assert mangle.rules[0].verdict_args.value == 0x0100


# ── emit_iproute2_setup — simple single provider ───────────────────────

class TestSimpleProvider:
    def _make(self, **kwargs) -> str:
        p = Provider(name="isp1", number=1, mark=0x01,
                     interface="eth0", gateway="203.0.113.1", table="1",
                     **kwargs)
        return emit_iproute2_setup([p], [], [], {})

    def test_rt_tables_entry(self):
        script = self._make()
        assert "1 isp1" in script

    def test_fwmark_rule(self):
        script = self._make()
        assert "ip rule add fwmark 0x1/" in script
        assert "table 1" in script

    def test_default_route(self):
        script = self._make()
        assert "ip route replace default via 203.0.113.1" in script
        assert "table 1" in script

    def test_track_no_loose(self):
        script = self._make(track=True, loose=False)
        assert "ip addr show dev eth0" in script

    def test_loose_skips_source_rule(self):
        script = self._make(loose=True)
        assert "ip addr show dev eth0" not in script

    def test_no_providers_returns_comment(self):
        script = emit_iproute2_setup([], [], [], {})
        assert "No providers configured" in script


# ── emit_iproute2_setup — two providers with balance ──────────────────

class TestTwoProviderBalance:
    def test_nexthop_multipath(self):
        p1 = Provider(name="isp1", number=1, mark=0x01,
                      interface="eth0", gateway="203.0.113.1",
                      table="1", balance=2)
        p2 = Provider(name="isp2", number=2, mark=0x02,
                      interface="eth1", gateway="198.51.100.1",
                      table="2", balance=1)
        script = emit_iproute2_setup([p1, p2], [], [], {})
        assert "nexthop via 203.0.113.1" in script
        assert "nexthop via 198.51.100.1" in script
        assert "weight 2" in script
        assert "weight 1" in script

    def test_balance_target_table_main(self):
        p1 = Provider(name="isp1", number=1, mark=0x01,
                      interface="eth0", gateway="203.0.113.1",
                      table="1", balance=1)
        script = emit_iproute2_setup([p1], [], [], {})
        assert "table main" in script

    def test_balance_target_table_balance_with_use_default_rt(self):
        p1 = Provider(name="isp1", number=1, mark=0x01,
                      interface="eth0", gateway="203.0.113.1",
                      table="1", balance=1)
        script = emit_iproute2_setup([p1], [], [], {"USE_DEFAULT_RT": "Yes"})
        assert "table balance" in script


# ── WP-B3 settings ─────────────────────────────────────────────────────

class TestUseDefaultRtYes:
    def test_use_default_rt_sets_balance_table(self):
        p = Provider(name="isp1", number=1, mark=0x01,
                     interface="eth0", gateway="203.0.113.1", table="1",
                     balance=1)
        script = emit_iproute2_setup([p], [], [], {"USE_DEFAULT_RT": "Yes"})
        assert "table balance" in script

    def test_use_default_rt_with_restore_deletes_main_default(self):
        p = Provider(name="isp1", number=1, mark=0x01,
                     interface="eth0", gateway="203.0.113.1", table="1",
                     balance=1)
        script = emit_iproute2_setup(
            [p], [], [],
            {"USE_DEFAULT_RT": "Yes", "RESTORE_DEFAULT_ROUTE": "Yes"},
        )
        assert "ip route del default table main" in script

    def test_use_default_rt_restore_no_skips_del(self):
        p = Provider(name="isp1", number=1, mark=0x01,
                     interface="eth0", gateway="203.0.113.1", table="1",
                     balance=1)
        script = emit_iproute2_setup(
            [p], [], [],
            {"USE_DEFAULT_RT": "Yes", "RESTORE_DEFAULT_ROUTE": "No"},
        )
        assert "ip route del default table main" not in script


class TestBalanceProvidersYes:
    def test_global_balance_default_applied(self):
        # Providers with no explicit balance/fallback get balance=1
        p1 = Provider(name="isp1", number=1, mark=0x01,
                      interface="eth0", gateway="203.0.113.1", table="1")
        p2 = Provider(name="isp2", number=2, mark=0x02,
                      interface="eth1", gateway="198.51.100.1", table="2")
        script = emit_iproute2_setup(
            [p1, p2], [], [], {"BALANCE_PROVIDERS": "Yes"}
        )
        # Both should appear in a nexthop multipath route
        assert "nexthop via 203.0.113.1" in script
        assert "nexthop via 198.51.100.1" in script

    def test_explicit_balance_not_overridden(self):
        # Provider with explicit balance=3 keeps weight 3
        p = Provider(name="isp1", number=1, mark=0x01,
                     interface="eth0", gateway="203.0.113.1", table="1",
                     balance=3)
        script = emit_iproute2_setup([p], [], [], {"BALANCE_PROVIDERS": "Yes"})
        assert "weight 3" in script


class TestOptimizeUseFirst:
    def test_single_provider_skips_fwmark(self):
        p = Provider(name="isp1", number=1, mark=0x01,
                     interface="eth0", gateway="203.0.113.1", table="1")
        script = emit_iproute2_setup(
            [p], [], [], {"OPTIMIZE_USE_FIRST": "Yes"}
        )
        assert "ip rule add fwmark" not in script

    def test_two_providers_fwmark_not_skipped(self):
        p1 = Provider(name="isp1", number=1, mark=0x01,
                      interface="eth0", gateway="203.0.113.1", table="1")
        p2 = Provider(name="isp2", number=2, mark=0x02,
                      interface="eth1", gateway="198.51.100.1", table="2")
        script = emit_iproute2_setup(
            [p1, p2], [], [], {"OPTIMIZE_USE_FIRST": "Yes"}
        )
        assert "ip rule add fwmark" in script


# ── provider OPTIONS matrix ─────────────────────────────────────────────

@pytest.mark.parametrize("opt,field,expected", [
    ("track", "track", True),
    ("loose", "loose", True),
    ("optional", "optional", True),
    ("persistent", "persistent", True),
    ("tproxy", "tproxy", True),
    ("primary", "balance", 1),
])
def test_provider_options_matrix(opt, field, expected):
    rows = [["isp1", "1", "0x01", "-", "eth0", "203.0.113.1", opt, "-"]]
    provider = _providers_from_cols(rows)[0]
    assert getattr(provider, field) == expected
