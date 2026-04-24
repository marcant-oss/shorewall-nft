"""Integration tests for the keepalived daemon-wiring layer (P8).

Verifies that:

1. DaemonConfig accepts all 7 new keepalived fields with correct defaults.
2. ConfDefaults + _CONF_KEY_MAP round-trips every new KEEPALIVED_* key.
3. ControlHandlers(keepalived_dbus=None) exposes all 4 keepalived-*
   handler methods and they return {"error": ...} gracefully.
4. ControlHandlers(keepalived_dbus=<mock>) routes calls through.
5. The deprecation path in collectors/vrrp.py fires exactly once when
   both VRRP_SNMP_* and KEEPALIVED_SNMP_UNIX are set.

None of these tests start the asyncio event loop or fork a process —
they stay at the config + handler construction layer.
"""

from __future__ import annotations

import warnings
from unittest.mock import AsyncMock, MagicMock

import pytest

from shorewalld.config import ConfDefaults, _CONF_KEY_MAP, parse_conf_text
from shorewalld.control_handlers import ControlHandlers
from shorewalld.daemon_config import DaemonConfig


# ---------------------------------------------------------------------------
# DaemonConfig field coverage
# ---------------------------------------------------------------------------


class TestDaemonConfigKeepalivdFields:
    """Every new field exists, is typed, and has the expected default."""

    def _minimal_config(self, **overrides) -> DaemonConfig:
        base = dict(
            prom_host="127.0.0.1",
            prom_port=9748,
            api_socket=None,
            netns_spec=[""],
            scrape_interval=30.0,
            reprobe_interval=300.0,
        )
        base.update(overrides)
        return DaemonConfig(**base)

    def test_keepalived_snmp_unix_default_none(self):
        cfg = self._minimal_config()
        assert cfg.keepalived_snmp_unix is None

    def test_keepalived_trap_socket_default_none(self):
        cfg = self._minimal_config()
        assert cfg.keepalived_trap_socket is None

    def test_keepalived_wide_tables_default_false(self):
        cfg = self._minimal_config()
        assert cfg.keepalived_wide_tables is False

    def test_keepalived_scrape_virtual_servers_default_true(self):
        cfg = self._minimal_config()
        assert cfg.keepalived_scrape_virtual_servers is True

    def test_keepalived_dbus_methods_default_readonly(self):
        cfg = self._minimal_config()
        assert cfg.keepalived_dbus_methods == "readonly"

    def test_keepalived_dbus_create_instance_default_false(self):
        cfg = self._minimal_config()
        assert cfg.keepalived_dbus_create_instance is False

    def test_keepalived_walk_interval_s_default_30(self):
        cfg = self._minimal_config()
        assert cfg.keepalived_walk_interval_s == 30.0

    def test_keepalived_fields_round_trip(self):
        cfg = self._minimal_config(
            keepalived_snmp_unix="/run/snmpd/snmpd.sock",
            keepalived_trap_socket="/run/shorewalld/snmp-trap.sock",
            keepalived_wide_tables=True,
            keepalived_scrape_virtual_servers=False,
            keepalived_dbus_methods="all",
            keepalived_dbus_create_instance=True,
            keepalived_walk_interval_s=60.0,
        )
        assert cfg.keepalived_snmp_unix == "/run/snmpd/snmpd.sock"
        assert cfg.keepalived_trap_socket == "/run/shorewalld/snmp-trap.sock"
        assert cfg.keepalived_wide_tables is True
        assert cfg.keepalived_scrape_virtual_servers is False
        assert cfg.keepalived_dbus_methods == "all"
        assert cfg.keepalived_dbus_create_instance is True
        assert cfg.keepalived_walk_interval_s == 60.0

    def test_frozen_immutable(self):
        cfg = self._minimal_config()
        with pytest.raises((TypeError, AttributeError)):
            cfg.keepalived_snmp_unix = "/new/path"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ConfDefaults + _CONF_KEY_MAP round-trip
# ---------------------------------------------------------------------------


class TestConfKeyMap:
    """Every KEEPALIVED_* key is in the map and routes to the right attr."""

    KEEPALIVED_KEYS = {
        "KEEPALIVED_SNMP_UNIX": "keepalived_snmp_unix",
        "KEEPALIVED_TRAP_SOCKET": "keepalived_trap_socket",
        "KEEPALIVED_WIDE_TABLES": "keepalived_wide_tables",
        "KEEPALIVED_SCRAPE_VIRTUAL_SERVERS": "keepalived_scrape_virtual_servers",
        "KEEPALIVED_DBUS_METHODS": "keepalived_dbus_methods",
        "KEEPALIVED_DBUS_CREATE_INSTANCE": "keepalived_dbus_create_instance",
        "KEEPALIVED_WALK_INTERVAL": "keepalived_walk_interval_s",
    }

    def test_all_keys_in_map(self):
        for key, attr in self.KEEPALIVED_KEYS.items():
            assert key in _CONF_KEY_MAP, f"{key} missing from _CONF_KEY_MAP"
            assert _CONF_KEY_MAP[key] == attr, (
                f"{key} maps to {_CONF_KEY_MAP[key]!r}, expected {attr!r}")

    def test_conf_text_round_trip_string_fields(self):
        conf_text = "\n".join([
            "KEEPALIVED_SNMP_UNIX=/run/snmpd/snmpd.sock",
            "KEEPALIVED_TRAP_SOCKET=/run/shorewalld/snmp-trap.sock",
            "KEEPALIVED_DBUS_METHODS=all",
        ])
        raw = parse_conf_text(conf_text)
        # Feed through load_defaults via a tmp file approach is heavyweight;
        # validate the raw parse and the _CONF_KEY_MAP connection directly.
        assert raw["KEEPALIVED_SNMP_UNIX"] == "/run/snmpd/snmpd.sock"
        assert raw["KEEPALIVED_TRAP_SOCKET"] == "/run/shorewalld/snmp-trap.sock"
        assert raw["KEEPALIVED_DBUS_METHODS"] == "all"

    def test_conf_text_round_trip_bool_fields(self):
        conf_text = "\n".join([
            "KEEPALIVED_WIDE_TABLES=yes",
            "KEEPALIVED_SCRAPE_VIRTUAL_SERVERS=no",
            "KEEPALIVED_DBUS_CREATE_INSTANCE=yes",
        ])
        raw = parse_conf_text(conf_text)
        assert raw["KEEPALIVED_WIDE_TABLES"] == "yes"
        assert raw["KEEPALIVED_SCRAPE_VIRTUAL_SERVERS"] == "no"
        assert raw["KEEPALIVED_DBUS_CREATE_INSTANCE"] == "yes"

    def test_conf_text_round_trip_float_fields(self):
        conf_text = "KEEPALIVED_WALK_INTERVAL=60"
        raw = parse_conf_text(conf_text)
        assert raw["KEEPALIVED_WALK_INTERVAL"] == "60"

    def test_confdefaults_has_all_attrs(self):
        defaults = ConfDefaults()
        for attr in self.KEEPALIVED_KEYS.values():
            assert hasattr(defaults, attr), f"ConfDefaults missing attr {attr!r}"
            assert getattr(defaults, attr) is None, (
                f"ConfDefaults.{attr} should default to None, "
                f"got {getattr(defaults, attr)!r}")

    def test_legacy_vrrp_snmp_keys_still_present(self):
        """Legacy VRRP_SNMP_* keys must remain in the map for back-compat."""
        legacy_keys = {
            "VRRP_SNMP_ENABLED",
            "VRRP_SNMP_HOST",
            "VRRP_SNMP_PORT",
            "VRRP_SNMP_COMMUNITY",
            "VRRP_SNMP_TIMEOUT",
        }
        for key in legacy_keys:
            assert key in _CONF_KEY_MAP, (
                f"Legacy key {key} unexpectedly removed from _CONF_KEY_MAP")


# ---------------------------------------------------------------------------
# ControlHandlers keepalived-* handlers
# ---------------------------------------------------------------------------


class TestControlHandlersKeepalivdDisabled:
    """When keepalived_dbus=None, handlers return {"error": ...} gracefully."""

    def _handlers(self) -> ControlHandlers:
        return ControlHandlers(keepalived_dbus=None)

    @pytest.mark.asyncio
    async def test_handle_keepalived_data_returns_error(self):
        h = self._handlers()
        result = await h.handle_keepalived_data({})
        assert "error" in result
        assert "disabled" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_handle_keepalived_stats_returns_error(self):
        h = self._handlers()
        result = await h.handle_keepalived_stats({})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_handle_keepalived_reload_returns_error(self):
        h = self._handlers()
        result = await h.handle_keepalived_reload({})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_handle_keepalived_garp_missing_instance(self):
        h = self._handlers()
        result = await h.handle_keepalived_garp({})
        # Returns {"error": "keepalived-dbus disabled"} — no instance required
        assert "error" in result

    @pytest.mark.asyncio
    async def test_handle_keepalived_garp_with_instance_disabled(self):
        h = self._handlers()
        result = await h.handle_keepalived_garp({"instance": "vrrp-wan"})
        assert "error" in result

    def test_all_four_handlers_accessible(self):
        h = self._handlers()
        for name in ("handle_keepalived_data", "handle_keepalived_stats",
                     "handle_keepalived_reload", "handle_keepalived_garp"):
            assert hasattr(h, name), f"ControlHandlers missing {name}"
            assert callable(getattr(h, name))


class TestControlHandlersKeepalivdEnabled:
    """When keepalived_dbus is a mock, handlers route through it."""

    def _handlers_with_mock(self) -> tuple[ControlHandlers, MagicMock]:
        mock_dbus = MagicMock()
        mock_dbus.print_data = AsyncMock(return_value=b"data content")
        mock_dbus.print_stats = AsyncMock(return_value=b"stats content")
        mock_dbus.reload_config = AsyncMock(return_value=None)
        mock_dbus.send_garp = AsyncMock(return_value=None)
        handlers = ControlHandlers(keepalived_dbus=mock_dbus)
        return handlers, mock_dbus

    @pytest.mark.asyncio
    async def test_data_calls_print_data(self):
        h, mock = self._handlers_with_mock()
        result = await h.handle_keepalived_data({})
        assert result.get("data") == "data content"
        mock.print_data.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stats_calls_print_stats(self):
        h, mock = self._handlers_with_mock()
        result = await h.handle_keepalived_stats({})
        assert result.get("data") == "stats content"
        mock.print_stats.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stats_passes_clear_flag(self):
        h, mock = self._handlers_with_mock()
        await h.handle_keepalived_stats({"clear": True})
        mock.print_stats.assert_awaited_once_with(clear=True)

    @pytest.mark.asyncio
    async def test_reload_calls_reload_config(self):
        h, mock = self._handlers_with_mock()
        result = await h.handle_keepalived_reload({})
        assert result.get("ok") is True
        mock.reload_config.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_garp_calls_send_garp(self):
        h, mock = self._handlers_with_mock()
        result = await h.handle_keepalived_garp({"instance": "vrrp-wan"})
        assert result.get("ok") is True
        mock.send_garp.assert_awaited_once_with("vrrp-wan")

    @pytest.mark.asyncio
    async def test_garp_missing_instance_returns_error(self):
        h, mock = self._handlers_with_mock()
        result = await h.handle_keepalived_garp({})
        assert "error" in result
        mock.send_garp.assert_not_awaited()


# ---------------------------------------------------------------------------
# Legacy VrrpCollector deprecation warning
# ---------------------------------------------------------------------------


class TestVrrpCollectorLegacyOverlapWarning:
    """VrrpCollector emits a DeprecationWarning when both paths are active.

    Uses the shorewalld.exporter re-export path which is already exercised
    by test_vrrp_snmp.py and works without triggering the heavy
    collectors/__init__.py import chain.
    """

    def _import_vrrp_module(self):
        """Return the shorewalld.collectors.vrrp module object.

        The module is already loaded into sys.modules by the test runner
        (test_vrrp_snmp.py imports it via shorewalld.exporter which pulls
        the whole chain).  We access it directly to avoid a second import.
        """
        import sys
        mod = sys.modules.get("shorewalld.collectors.vrrp")
        if mod is not None:
            return mod
        # Fallback: import via exporter to trigger the chain correctly.
        import shorewalld.exporter  # noqa: F401 (side-effect: loads vrrp)
        return sys.modules["shorewalld.collectors.vrrp"]

    def test_no_warning_without_unix_path(self):
        """No warning when keepalived_snmp_unix is None (normal single-path)."""
        vrrp_mod = self._import_vrrp_module()
        vrrp_mod._LEGACY_OVERLAP_WARNED = False
        VrrpCollector = vrrp_mod.VrrpCollector
        VrrpSnmpConfig = vrrp_mod.VrrpSnmpConfig
        snmp_cfg = VrrpSnmpConfig(host="127.0.0.1", port=161)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            VrrpCollector(snmp_config=snmp_cfg, keepalived_snmp_unix=None)
        depr = [x for x in w if issubclass(x.category, DeprecationWarning)
                and "VRRP_SNMP" in str(x.message)]
        assert len(depr) == 0

    def test_no_warning_without_snmp_config(self):
        """No warning when snmp_config is None (D-Bus-only mode)."""
        vrrp_mod = self._import_vrrp_module()
        vrrp_mod._LEGACY_OVERLAP_WARNED = False
        VrrpCollector = vrrp_mod.VrrpCollector
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            VrrpCollector(
                snmp_config=None,
                keepalived_snmp_unix="/run/snmpd/snmpd.sock",
            )
        depr = [x for x in w if issubclass(x.category, DeprecationWarning)
                and "VRRP_SNMP" in str(x.message)]
        assert len(depr) == 0

    def test_warning_when_both_paths_active(self):
        """DeprecationWarning fires when VRRP_SNMP_* + KEEPALIVED_SNMP_UNIX."""
        vrrp_mod = self._import_vrrp_module()
        vrrp_mod._LEGACY_OVERLAP_WARNED = False
        VrrpCollector = vrrp_mod.VrrpCollector
        VrrpSnmpConfig = vrrp_mod.VrrpSnmpConfig
        snmp_cfg = VrrpSnmpConfig(host="127.0.0.1", port=161)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            VrrpCollector(
                snmp_config=snmp_cfg,
                keepalived_snmp_unix="/run/snmpd/snmpd.sock",
            )
        depr = [x for x in w if issubclass(x.category, DeprecationWarning)
                and "VRRP_SNMP" in str(x.message)]
        assert len(depr) == 1, f"expected 1 deprecation warning, got {depr}"

    def test_warning_fires_only_once(self):
        """Guard ensures the warning is emitted at most once per process."""
        vrrp_mod = self._import_vrrp_module()
        vrrp_mod._LEGACY_OVERLAP_WARNED = False
        VrrpCollector = vrrp_mod.VrrpCollector
        VrrpSnmpConfig = vrrp_mod.VrrpSnmpConfig
        snmp_cfg = VrrpSnmpConfig(host="127.0.0.1", port=161)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            VrrpCollector(
                snmp_config=snmp_cfg,
                keepalived_snmp_unix="/run/snmpd/snmpd.sock",
            )
            VrrpCollector(
                snmp_config=snmp_cfg,
                keepalived_snmp_unix="/run/snmpd/snmpd.sock",
            )
        depr = [x for x in w if issubclass(x.category, DeprecationWarning)
                and "VRRP_SNMP" in str(x.message)]
        assert len(depr) == 1, "expected warning to fire only once (guard flag)"
