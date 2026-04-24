"""Tests for routes and rtrules parsing and shell-script emission (WP-B2).

Each test covers one row from the routes or rtrules file format and
asserts the expected ip route / ip rule line appears in the generated
shell script.
"""

from __future__ import annotations


from shorewall_nft.compiler.providers import (
    Provider,
    Route,
    RoutingRule,
    emit_iproute2_setup,
    parse_routes,
    parse_rtrules,
)
from shorewall_nft.config.parser import ConfigLine


def _line(cols: list[str], filename: str = "routes", lineno: int = 1) -> ConfigLine:
    return ConfigLine(columns=cols, file=filename, lineno=lineno)


# ── parse_routes ────────────────────────────────────────────────────────

class TestParseRoutes:
    def test_basic_with_gateway(self):
        line = _line(["isp1", "192.0.2.0/24", "203.0.113.1", "-", "-"])
        routes = parse_routes([line])
        assert len(routes) == 1
        r = routes[0]
        assert r.provider == "isp1"
        assert r.dest == "192.0.2.0/24"
        assert r.gateway == "203.0.113.1"
        assert r.device is None

    def test_basic_with_device(self):
        line = _line(["isp2", "10.0.0.0/8", "-", "eth1", "-"])
        routes = parse_routes([line])
        r = routes[0]
        assert r.gateway is None
        assert r.device == "eth1"

    def test_with_gateway_and_device(self):
        line = _line(["isp1", "192.0.2.0/24", "203.0.113.1", "eth0", "-"])
        r = parse_routes([line])[0]
        assert r.gateway == "203.0.113.1"
        assert r.device == "eth0"

    def test_persistent_option(self):
        line = _line(["isp1", "192.0.2.0/24", "203.0.113.1", "-", "persistent"])
        r = parse_routes([line])[0]
        assert r.persistent is True

    def test_dash_gateway_is_none(self):
        line = _line(["isp1", "192.0.2.0/24", "-", "-", "-"])
        r = parse_routes([line])[0]
        assert r.gateway is None

    def test_skip_dash_provider(self):
        line = _line(["-", "192.0.2.0/24", "-", "-", "-"])
        assert parse_routes([line]) == []

    def test_skip_too_few_cols(self):
        assert parse_routes([_line(["isp1"])]) == []

    def test_multiple_routes(self):
        lines = [
            _line(["isp1", "192.0.2.0/24", "203.0.113.1", "-", "-"], lineno=1),
            _line(["isp2", "10.1.0.0/24", "198.51.100.1", "-", "-"], lineno=2),
        ]
        assert len(parse_routes(lines)) == 2


# ── parse_rtrules ───────────────────────────────────────────────────────

class TestParseRtrules:
    def test_source_only(self):
        line = _line(["192.0.2.0/24", "-", "isp1", "1000", "-"], "rtrules")
        rules = parse_rtrules([line])
        assert len(rules) == 1
        r = rules[0]
        assert r.source == "192.0.2.0/24"
        assert r.dest is None
        assert r.provider == "isp1"
        assert r.priority == 1000

    def test_dest_only(self):
        line = _line(["-", "198.51.100.0/24", "isp2", "1001", "-"], "rtrules")
        r = parse_rtrules([line])[0]
        assert r.source is None
        assert r.dest == "198.51.100.0/24"

    def test_with_mark(self):
        line = _line(["192.0.2.0/24", "-", "isp1", "500", "0x100/0xff"], "rtrules")
        r = parse_rtrules([line])[0]
        assert r.mark == "0x100/0xff"

    def test_persistent_priority_suffix(self):
        line = _line(["192.0.2.0/24", "-", "isp1", "1000!", "-"], "rtrules")
        r = parse_rtrules([line])[0]
        assert r.persistent is True
        assert r.priority == 1000

    def test_skip_dash_provider(self):
        line = _line(["192.0.2.0/24", "-", "-", "1000", "-"], "rtrules")
        assert parse_rtrules([line]) == []

    def test_skip_both_source_and_dest_dash(self):
        line = _line(["-", "-", "isp1", "1000", "-"], "rtrules")
        assert parse_rtrules([line]) == []

    def test_skip_too_few_cols(self):
        assert parse_rtrules([_line(["-", "-"], "rtrules")]) == []


# ── shell script emission for routes ───────────────────────────────────

def _make_providers() -> list[Provider]:
    return [
        Provider(name="isp1", number=1, mark=0x01, interface="eth0",
                 gateway="203.0.113.1", table="1"),
        Provider(name="isp2", number=2, mark=0x02, interface="eth1",
                 gateway="198.51.100.1", table="2"),
    ]


class TestRouteScriptEmit:
    def test_route_with_gateway(self):
        routes = [Route(provider="isp1", dest="192.0.2.0/24",
                        gateway="203.0.113.1")]
        script = emit_iproute2_setup(_make_providers(), routes, [], {})
        assert "ip route replace 192.0.2.0/24 via 203.0.113.1" in script
        assert "table 1" in script

    def test_route_with_device_only(self):
        routes = [Route(provider="isp2", dest="10.1.2.0/24", device="eth1")]
        script = emit_iproute2_setup(_make_providers(), routes, [], {})
        assert "ip route replace 10.1.2.0/24 dev eth1" in script
        assert "table 2" in script

    def test_route_with_gateway_and_device(self):
        routes = [Route(provider="isp1", dest="192.0.2.128/25",
                        gateway="203.0.113.1", device="eth0")]
        script = emit_iproute2_setup(_make_providers(), routes, [], {})
        assert "ip route replace 192.0.2.128/25 via 203.0.113.1 dev eth0" in script

    def test_route_unknown_provider_uses_name_as_table(self):
        routes = [Route(provider="custom", dest="172.16.0.0/12")]
        script = emit_iproute2_setup([], routes, [], {})
        assert "table custom" in script

    def test_two_routes_both_appear(self):
        routes = [
            Route(provider="isp1", dest="192.0.2.0/24", gateway="203.0.113.1"),
            Route(provider="isp2", dest="198.51.100.0/24"),
        ]
        script = emit_iproute2_setup(_make_providers(), routes, [], {})
        assert "192.0.2.0/24" in script
        assert "198.51.100.0/24" in script


# ── shell script emission for rtrules ──────────────────────────────────

class TestRtrulesScriptEmit:
    def test_source_rule(self):
        rules = [RoutingRule(source="192.0.2.0/24", dest=None,
                              provider="isp1", priority=1000)]
        script = emit_iproute2_setup(_make_providers(), [], rules, {})
        assert "ip rule add" in script
        assert "from 192.0.2.0/24" in script
        assert "pref 1000" in script
        assert "table 1" in script

    def test_dest_rule(self):
        rules = [RoutingRule(source=None, dest="198.51.100.0/24",
                              provider="isp2", priority=1001)]
        script = emit_iproute2_setup(_make_providers(), [], rules, {})
        assert "to 198.51.100.0/24" in script
        assert "table 2" in script

    def test_rule_with_mark(self):
        rules = [RoutingRule(source="192.0.2.0/24", provider="isp1",
                              priority=500, mark="0x100/0xff")]
        script = emit_iproute2_setup(_make_providers(), [], rules, {})
        assert "fwmark 0x100/0xff" in script

    def test_rule_iif_source(self):
        # Source that looks like an interface name (no dots or colons)
        rules = [RoutingRule(source="eth0", provider="isp1", priority=2000)]
        script = emit_iproute2_setup(_make_providers(), [], rules, {})
        assert "iif eth0" in script

    def test_two_rules_both_appear(self):
        rules = [
            RoutingRule(source="192.0.2.0/24", provider="isp1", priority=1000),
            RoutingRule(dest="198.51.100.0/24", provider="isp2", priority=1001),
        ]
        script = emit_iproute2_setup(_make_providers(), [], rules, {})
        assert "pref 1000" in script
        assert "pref 1001" in script


# ── integration: routes + rtrules together ─────────────────────────────

class TestCombinedRoutesAndRtrules:
    def test_both_sections_present(self):
        routes = [Route(provider="isp1", dest="192.0.2.0/24",
                        gateway="203.0.113.1")]
        rules = [RoutingRule(source="192.0.2.0/24", provider="isp1",
                              priority=1000)]
        script = emit_iproute2_setup(_make_providers(), routes, rules, {})
        assert "ip route replace" in script
        assert "ip rule add" in script
