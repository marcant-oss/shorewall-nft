"""Tests for apply_iproute2_rules / remove_iproute2_rules.

All tests mock pyroute2.IPRoute — no kernel or netns required.

Patching strategy: apply_iproute2_rules / remove_iproute2_rules use the
module-level IPRoute and NetlinkError imported at the top of
shorewall_nft.runtime.apply (not a lazy import).  We therefore patch at
the module level: ``patch("shorewall_nft.runtime.apply.IPRoute", …)`` and
``patch("shorewall_nft.runtime.apply.NetlinkError", …)``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from shorewall_nft.compiler.providers import Provider, Route, RoutingRule
from shorewall_nft.runtime.apply import apply_iproute2_rules, remove_iproute2_rules


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _provider(
    name: str = "isp1",
    number: int = 1,
    mark: int = 0x01,
    interface: str = "eth0",
    gateway: str | None = "203.0.113.1",
    *,
    balance: int = 0,
    fallback: int = 0,
    loose: bool = False,
    optional: bool = False,
    persistent: bool = False,
    tproxy: bool = False,
) -> Provider:
    return Provider(
        name=name,
        number=number,
        mark=mark,
        interface=interface,
        gateway=gateway,
        balance=balance,
        fallback=fallback,
        loose=loose,
        optional=optional,
        persistent=persistent,
        tproxy=tproxy,
        table=str(number),
    )


def _route(
    provider: str = "isp1",
    dest: str = "192.0.2.0/24",
    gateway: str | None = None,
    device: str | None = None,
    persistent: bool = False,
) -> Route:
    return Route(
        provider=provider,
        dest=dest,
        gateway=gateway,
        device=device,
        persistent=persistent,
    )


def _rtrule(
    source: str | None = "192.0.2.0/24",
    dest: str | None = None,
    provider: str = "isp1",
    priority: int = 1000,
    mark: str | None = None,
    persistent: bool = False,
) -> RoutingRule:
    return RoutingRule(
        source=source,
        dest=dest,
        provider=provider,
        priority=priority,
        mark=mark,
        persistent=persistent,
    )


def _make_mock_ipr(*, link_idx: int = 3) -> MagicMock:
    """Return a mock IPRoute with sensible defaults."""
    m = MagicMock()
    m.__enter__ = lambda s: s
    m.__exit__ = MagicMock(return_value=False)
    m.link_lookup.return_value = [link_idx]
    m.get_addr.return_value = []
    return m


# Convenience patch targets.
_PATCH_IPR = "shorewall_nft.runtime.apply.IPRoute"
_PATCH_NLE = "shorewall_nft.runtime.apply.NetlinkError"
_PATCH_AVAIL = "shorewall_nft.runtime.apply._PYROUTE2_AVAILABLE"
_PATCH_RT_TBL = "shorewall_nft.runtime.apply._ensure_rt_table_entry"


# ---------------------------------------------------------------------------
# Test 1: apply calls route("replace", …) for the provider default route
# ---------------------------------------------------------------------------

class TestApplyProviderRouteCallsPyroute2:
    """apply_iproute2_rules with one provider → one route("replace", …) call."""

    def test_route_replace_called(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider()

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            applied, skipped, errors = apply_iproute2_rules(
                [prov], [], [], {})

        assert errors == [], errors
        # route("replace", …) should have been called at least once.
        route_calls = [c for c in mock_ipr.route.call_args_list
                       if c.args and c.args[0] == "replace"]
        assert len(route_calls) >= 1, f"route replace not called; calls={mock_ipr.route.call_args_list}"

    def test_route_replace_kwargs_contain_table_and_dst(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=42)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [], {})

        route_calls = [c for c in mock_ipr.route.call_args_list
                       if c.args and c.args[0] == "replace"]
        # Find the provider-table route (table=42).
        prov_routes = [c for c in route_calls if c.kwargs.get("table") == 42]
        assert prov_routes, "No route replace with table=42 found"
        kwargs = prov_routes[0].kwargs
        assert kwargs.get("dst") == "0.0.0.0/0"

    def test_route_replace_includes_gateway(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider(gateway="198.51.100.1")

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [], {})

        route_calls = [c for c in mock_ipr.route.call_args_list
                       if c.args and c.args[0] == "replace"
                       and c.kwargs.get("table") == 1]
        assert route_calls, "provider route not found"
        assert route_calls[0].kwargs.get("gateway") == "198.51.100.1"


# ---------------------------------------------------------------------------
# Test 2: provider with mark → rule("add", fwmark=…, table=…)
# ---------------------------------------------------------------------------

class TestApplyProviderMarkRule:
    """Provider with mark=0x100 → rule("add", fwmark=0x100, …) called."""

    def test_rule_add_called_with_fwmark(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider(mark=0x100, number=5)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [], {})

        rule_add_calls = [c for c in mock_ipr.rule.call_args_list
                          if c.args and c.args[0] == "add"]
        assert rule_add_calls, "rule('add', …) not called"
        fwmark_calls = [c for c in rule_add_calls
                        if c.kwargs.get("fwmark") == 0x100]
        assert fwmark_calls, f"No rule add with fwmark=0x100; calls={rule_add_calls}"
        assert fwmark_calls[0].kwargs.get("table") == 5

    def test_no_mark_no_fwmark_rule(self):
        """Provider with mark=0 (no mark) → no fwmark rule emitted."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(mark=0)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [], {})

        fwmark_calls = [c for c in mock_ipr.rule.call_args_list
                        if c.kwargs.get("fwmark") is not None]
        assert fwmark_calls == []

    def test_optimize_use_first_skips_fwmark(self):
        """OPTIMIZE_USE_FIRST=Yes + single provider → fwmark rule skipped."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(mark=0x01, number=1)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [], {"OPTIMIZE_USE_FIRST": "Yes"})

        fwmark_calls = [c for c in mock_ipr.rule.call_args_list
                        if c.kwargs.get("fwmark") is not None]
        assert fwmark_calls == [], "fwmark rule should be skipped"


# ---------------------------------------------------------------------------
# Test 3: extra routes file → route("replace", …) called
# ---------------------------------------------------------------------------

class TestApplyRoutesFile:
    """Extra route entry → route("replace", …) called with correct dst/table."""

    def test_route_add_for_extra_route(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=1)
        extra = _route(provider="isp1", dest="10.0.0.0/8")

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            applied, _skipped, errors = apply_iproute2_rules(
                [prov], [extra], [], {})

        assert errors == [], errors
        # Find route replace with dst=10.0.0.0/8.
        route_calls = [c for c in mock_ipr.route.call_args_list
                       if c.args and c.args[0] == "replace"
                       and c.kwargs.get("dst") == "10.0.0.0/8"]
        assert route_calls, "route replace for extra route not found"
        assert route_calls[0].kwargs.get("table") == 1

    def test_route_uses_device_when_specified(self):
        """Route entry with explicit device → oif resolved via link_lookup."""
        mock_ipr = _make_mock_ipr(link_idx=7)
        prov = _provider(number=1)
        extra = _route(dest="10.0.0.0/8", device="eth1")

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [extra], [], {})

        # link_lookup should have been called for eth1.
        lookup_calls = [c for c in mock_ipr.link_lookup.call_args_list
                        if c.kwargs.get("ifname") == "eth1"]
        assert lookup_calls, "link_lookup for eth1 not called"

    def test_persistent_route_still_applied(self):
        """Persistent=True routes ARE applied (persistence only affects remove)."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=1)
        extra = _route(dest="172.16.0.0/12", persistent=True)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [extra], [], {})

        route_calls = [c for c in mock_ipr.route.call_args_list
                       if c.args and c.args[0] == "replace"
                       and c.kwargs.get("dst") == "172.16.0.0/12"]
        assert route_calls, "persistent route should still be applied"


# ---------------------------------------------------------------------------
# Test 4: rtrules file → rule("add", …) called
# ---------------------------------------------------------------------------

class TestApplyRtrulesFile:
    """Extra rtrule entry → rule("add", …) called with correct args."""

    def test_rule_add_for_rtrule(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=1)
        rule_entry = _rtrule(source="192.0.2.0/24", priority=1000)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            applied, _skipped, errors = apply_iproute2_rules(
                [prov], [], [rule_entry], {})

        assert errors == [], errors
        rule_add_calls = [c for c in mock_ipr.rule.call_args_list
                          if c.args and c.args[0] == "add"
                          and c.kwargs.get("priority") == 1000]
        assert rule_add_calls, "rule add with priority=1000 not found"

    def test_rtrule_with_dest(self):
        """rtrule with a dest field → dst kwarg passed to rule()."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=1)
        rule_entry = _rtrule(source=None, dest="10.20.0.0/16", priority=2000)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [rule_entry], {})

        rule_add_calls = [c for c in mock_ipr.rule.call_args_list
                          if c.args and c.args[0] == "add"
                          and c.kwargs.get("priority") == 2000]
        assert rule_add_calls
        assert rule_add_calls[0].kwargs.get("dst") == "10.20.0.0"

    def test_rtrule_with_mark(self):
        """rtrule with mark field → fwmark kwarg passed to rule()."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=1)
        rule_entry = _rtrule(source="192.0.2.1", mark="0x200/0xff", priority=3000)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [rule_entry], {})

        rule_add_calls = [c for c in mock_ipr.rule.call_args_list
                          if c.args and c.args[0] == "add"
                          and c.kwargs.get("priority") == 3000]
        assert rule_add_calls
        assert rule_add_calls[0].kwargs.get("fwmark") == 0x200
        assert rule_add_calls[0].kwargs.get("fwmask") == 0xFF


# ---------------------------------------------------------------------------
# Test 5: remove is idempotent (ENOENT swallowed, no raise)
# ---------------------------------------------------------------------------

class TestRemoveIsIdempotent:
    """Calling remove twice: second call swallows ENOENT (code=2), no raise."""

    def test_second_remove_does_not_raise(self):
        """rule("del", …) raises NetlinkError(code=2) → skipped, not error."""
        call_count = {"n": 0}

        class FakeNetlinkError(Exception):
            def __init__(self, code: int = 2):
                self.code = code

        def _rule_side(op, **kwargs):
            if op == "del":
                call_count["n"] += 1
                if call_count["n"] > 1:
                    raise FakeNetlinkError(2)

        def _route_side(op, **kwargs):
            if op == "del":
                raise FakeNetlinkError(2)

        mock_ipr = _make_mock_ipr()
        mock_ipr.rule.side_effect = _rule_side
        mock_ipr.route.side_effect = _route_side

        prov = _provider()

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, FakeNetlinkError), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            # First call: may succeed or skip.
            _r1, _s1, e1 = remove_iproute2_rules([prov], [], [], {})
            # Second call: entries already absent → must not raise.
            _r2, _s2, e2 = remove_iproute2_rules([prov], [], [], {})

        assert e2 == [], f"Second remove raised errors: {e2}"

    def test_persistent_provider_skipped_on_remove(self):
        """Provider with persistent=True is not removed."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(persistent=True)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            removed, skipped, errors = remove_iproute2_rules([prov], [], [], {})

        # route("del", …) must NOT have been called for the provider's table.
        route_del_calls = [c for c in mock_ipr.route.call_args_list
                           if c.args and c.args[0] == "del"
                           and c.kwargs.get("table") == prov.number]
        assert route_del_calls == [], "persistent provider route was deleted"

    def test_persistent_route_skipped_on_remove(self):
        """Route with persistent=True is not removed."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=1)
        extra = _route(dest="10.0.0.0/8", persistent=True)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            remove_iproute2_rules([prov], [extra], [], {})

        route_del_calls = [c for c in mock_ipr.route.call_args_list
                           if c.args and c.args[0] == "del"
                           and c.kwargs.get("dst") == "10.0.0.0/8"]
        assert route_del_calls == [], "persistent route was deleted"

    def test_restore_default_route_no_skips_del(self):
        """RESTORE_DEFAULT_ROUTE=No → balance/fallback default NOT deleted."""
        mock_ipr = _make_mock_ipr()
        prov = _provider(number=1, balance=1)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            remove_iproute2_rules(
                [prov], [], [], {"RESTORE_DEFAULT_ROUTE": "No"})

        # route("del", …) for table=0 (main) should NOT appear.
        main_del = [c for c in mock_ipr.route.call_args_list
                    if c.args and c.args[0] == "del"
                    and c.kwargs.get("table") == 0
                    and c.kwargs.get("dst") == "0.0.0.0/0"]
        assert main_del == []


# ---------------------------------------------------------------------------
# Test 6: netns → IPRoute constructed with netns=…
# ---------------------------------------------------------------------------

class TestApplyInNetns:
    """Passing netns='test-ns' → IPRoute(netns='test-ns') is called."""

    def test_iproute_constructed_with_netns(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider()

        with patch(_PATCH_IPR, return_value=mock_ipr) as ipr_cls, \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [], {}, netns="test-ns")

        ipr_cls.assert_called_once_with(netns="test-ns")

    def test_no_netns_iproute_constructed_without_arg(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider()

        with patch(_PATCH_IPR, return_value=mock_ipr) as ipr_cls, \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([prov], [], [], {}, netns=None)

        ipr_cls.assert_called_once_with()

    def test_remove_in_netns(self):
        mock_ipr = _make_mock_ipr()
        prov = _provider()

        with patch(_PATCH_IPR, return_value=mock_ipr) as ipr_cls, \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            remove_iproute2_rules([prov], [], [], {}, netns="fw-ns")

        ipr_cls.assert_called_once_with(netns="fw-ns")


# ---------------------------------------------------------------------------
# Test 7: empty inputs → fast path (no IPRoute instantiation)
# ---------------------------------------------------------------------------

class TestEmptyInputs:
    """apply/remove with no providers/routes/rtrules returns (0, 0, [])."""

    def test_apply_empty(self):
        with patch(_PATCH_AVAIL, True):
            applied, skipped, errors = apply_iproute2_rules([], [], [], {})
        assert (applied, skipped, errors) == (0, 0, [])

    def test_remove_empty(self):
        with patch(_PATCH_AVAIL, True):
            removed, skipped, errors = remove_iproute2_rules([], [], [], {})
        assert (removed, skipped, errors) == (0, 0, [])


# ---------------------------------------------------------------------------
# Test 8: pyroute2 absent → graceful (0, 0, ["pyroute2 not installed"])
# ---------------------------------------------------------------------------

class TestPyroute2Absent:
    def test_apply_no_pyroute2(self):
        with patch(_PATCH_AVAIL, False):
            result = apply_iproute2_rules([_provider()], [], [], {})
        assert result == (0, 0, ["pyroute2 not installed"])

    def test_remove_no_pyroute2(self):
        with patch(_PATCH_AVAIL, False):
            result = remove_iproute2_rules([_provider()], [], [], {})
        assert result == (0, 0, ["pyroute2 not installed"])


# ---------------------------------------------------------------------------
# Test 9: rt_tables entry written (file I/O) on apply
# ---------------------------------------------------------------------------

class TestRtTablesRegistration:
    """apply_iproute2_rules calls _ensure_rt_table_entry for each provider."""

    def test_ensure_called_per_provider(self):
        mock_ipr = _make_mock_ipr()
        provs = [_provider("isp1", 1), _provider("isp2", 2, mark=0x02, interface="eth1")]

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL) as mock_ensure:
            apply_iproute2_rules(provs, [], [], {})

        assert mock_ensure.call_count == 2
        calls = {(c.args[0], c.args[1]) for c in mock_ensure.call_args_list}
        assert (1, "isp1") in calls
        assert (2, "isp2") in calls


# ---------------------------------------------------------------------------
# Test 10: balance multipath route
# ---------------------------------------------------------------------------

class TestBalanceMultipathRoute:
    """balance=1 providers → route("replace", …, multipath=[…]) called."""

    def test_multipath_route_emitted(self):
        mock_ipr = _make_mock_ipr()
        p1 = _provider("isp1", 1, mark=0x01, gateway="203.0.113.1", balance=1)
        p2 = _provider("isp2", 2, mark=0x02, interface="eth1", gateway="203.0.113.2", balance=1)

        with patch(_PATCH_IPR, return_value=mock_ipr), \
             patch(_PATCH_NLE, Exception), \
             patch(_PATCH_AVAIL, True), \
             patch(_PATCH_RT_TBL):
            apply_iproute2_rules([p1, p2], [], [], {})

        multipath_calls = [c for c in mock_ipr.route.call_args_list
                           if c.args and c.args[0] == "replace"
                           and c.kwargs.get("multipath")]
        assert multipath_calls, "No multipath route call found"
        nexthops = multipath_calls[0].kwargs["multipath"]
        assert len(nexthops) == 2
