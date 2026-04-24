"""Unit tests for shorewall_nft.runtime.pyroute2_helpers.

Covers resolve_iface_idx (cache hits, miss returns None, miss not cached)
and settings_bool (case variants, missing key uses default, weird values
return False).

No pyroute2 or network access required — uses a minimal mock IPRoute.
"""

from __future__ import annotations

import pytest

from shorewall_nft.runtime.pyroute2_helpers import resolve_iface_idx, settings_bool


# ---------------------------------------------------------------------------
# Minimal mock IPRoute — only exposes link_lookup
# ---------------------------------------------------------------------------

class _MockIPRoute:
    """Minimal mock that records link_lookup call count per name."""

    def __init__(self, index_map: dict[str, int]) -> None:
        self._map = index_map
        self.call_counts: dict[str, int] = {}

    def link_lookup(self, *, ifname: str) -> list[int]:
        self.call_counts[ifname] = self.call_counts.get(ifname, 0) + 1
        idx = self._map.get(ifname)
        return [idx] if idx is not None else []


# ---------------------------------------------------------------------------
# resolve_iface_idx tests
# ---------------------------------------------------------------------------

class TestResolveIfaceIdx:
    def test_hit_returns_index(self) -> None:
        ipr = _MockIPRoute({"eth0": 3})
        cache: dict[str, int] = {}
        result = resolve_iface_idx(ipr, "eth0", cache)
        assert result == 3

    def test_miss_returns_none(self) -> None:
        ipr = _MockIPRoute({})
        cache: dict[str, int] = {}
        result = resolve_iface_idx(ipr, "eth99", cache)
        assert result is None

    def test_result_is_cached_after_hit(self) -> None:
        ipr = _MockIPRoute({"eth0": 5})
        cache: dict[str, int] = {}
        resolve_iface_idx(ipr, "eth0", cache)
        resolve_iface_idx(ipr, "eth0", cache)
        # link_lookup must have been called exactly once (second call uses cache)
        assert ipr.call_counts.get("eth0", 0) == 1

    def test_cache_hit_returns_correct_value(self) -> None:
        ipr = _MockIPRoute({"eth0": 7})
        cache: dict[str, int] = {}
        r1 = resolve_iface_idx(ipr, "eth0", cache)
        r2 = resolve_iface_idx(ipr, "eth0", cache)
        assert r1 == r2 == 7

    def test_miss_does_not_populate_cache(self) -> None:
        ipr = _MockIPRoute({})
        cache: dict[str, int] = {}
        resolve_iface_idx(ipr, "missing", cache)
        assert "missing" not in cache

    def test_miss_retries_next_call(self) -> None:
        """A transient miss must not poison subsequent lookups."""
        ipr = _MockIPRoute({})
        cache: dict[str, int] = {}
        resolve_iface_idx(ipr, "eth1", cache)
        resolve_iface_idx(ipr, "eth1", cache)
        # Both calls hit link_lookup because miss is never cached
        assert ipr.call_counts.get("eth1", 0) == 2

    def test_netlink_exception_returns_none(self) -> None:
        class _BrokenIPRoute:
            def link_lookup(self, *, ifname: str) -> list[int]:  # noqa: ANN001
                raise RuntimeError("netlink error")

        cache: dict[str, int] = {}
        result = resolve_iface_idx(_BrokenIPRoute(), "eth0", cache)
        assert result is None

    def test_netlink_exception_not_cached(self) -> None:
        call_count = 0

        class _BrokenIPRoute:
            def link_lookup(self, *, ifname: str) -> list[int]:  # noqa: ANN001
                nonlocal call_count
                call_count += 1
                raise RuntimeError("netlink error")

        cache: dict[str, int] = {}
        resolve_iface_idx(_BrokenIPRoute(), "eth0", cache)
        resolve_iface_idx(_BrokenIPRoute(), "eth0", cache)
        assert call_count == 2

    def test_multiple_interfaces_use_independent_cache_entries(self) -> None:
        ipr = _MockIPRoute({"eth0": 2, "eth1": 4})
        cache: dict[str, int] = {}
        assert resolve_iface_idx(ipr, "eth0", cache) == 2
        assert resolve_iface_idx(ipr, "eth1", cache) == 4
        assert len(cache) == 2


# ---------------------------------------------------------------------------
# settings_bool tests
# ---------------------------------------------------------------------------

class TestSettingsBool:
    @pytest.mark.parametrize("value", ["yes", "Yes", "YES", "yEs"])
    def test_truthy_yes(self, value: str) -> None:
        assert settings_bool({}, "K", False) is False  # baseline
        assert settings_bool({"K": value}, "K") is True

    @pytest.mark.parametrize("value", ["1"])
    def test_truthy_one(self, value: str) -> None:
        assert settings_bool({"K": value}, "K") is True

    @pytest.mark.parametrize("value", ["true", "True", "TRUE", "tRuE"])
    def test_truthy_true(self, value: str) -> None:
        assert settings_bool({"K": value}, "K") is True

    @pytest.mark.parametrize("value", ["no", "No", "NO"])
    def test_falsy_no(self, value: str) -> None:
        assert settings_bool({"K": value}, "K") is False

    @pytest.mark.parametrize("value", ["0"])
    def test_falsy_zero(self, value: str) -> None:
        assert settings_bool({"K": value}, "K") is False

    @pytest.mark.parametrize("value", ["false", "False", "FALSE"])
    def test_falsy_false(self, value: str) -> None:
        assert settings_bool({"K": value}, "K") is False

    def test_missing_key_returns_default_false(self) -> None:
        assert settings_bool({}, "MISSING") is False

    def test_missing_key_returns_default_true(self) -> None:
        assert settings_bool({}, "MISSING", default=True) is True

    def test_weird_value_returns_false(self) -> None:
        assert settings_bool({"K": "garbage"}, "K") is False

    def test_whitespace_stripped(self) -> None:
        assert settings_bool({"K": "  yes  "}, "K") is True
        assert settings_bool({"K": "  no  "}, "K") is False

    def test_empty_string_returns_false(self) -> None:
        assert settings_bool({"K": ""}, "K") is False

    def test_empty_string_with_default_true_returns_false(self) -> None:
        # Explicitly-present empty value overrides default (key IS present)
        assert settings_bool({"K": ""}, "K", default=True) is False
