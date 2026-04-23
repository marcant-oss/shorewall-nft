"""Tests for entry-point-based third-party plugin discovery."""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shorewall_nft.plugins.base import Plugin
from shorewall_nft.plugins.manager import (
    PluginLoadError,
    _resolve_plugin_class,
)


# ---------------------------------------------------------------------------
# Minimal fake plugin class for use in tests
# ---------------------------------------------------------------------------

class FakeExternalPlugin(Plugin):
    name = "fake-external"
    version = "0.1.0"
    priority = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ep(name: str, cls):
    """Build a mock entry-point object that mimics importlib.metadata.EntryPoint."""
    ep = MagicMock(spec=["name", "value", "load"])
    ep.name = name
    ep.value = f"fake_package.fake_module:{cls.__name__}"
    ep.load.return_value = cls
    return ep


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_builtin_still_resolves():
    """Built-in plugins resolve without any entry-point scanning."""
    cls = _resolve_plugin_class("ip-info")
    assert cls is not None
    assert cls.name == "ip-info"


def test_unknown_name_returns_none():
    """A name that is neither a built-in nor an entry-point returns None."""
    with patch(
        "shorewall_nft.plugins.manager.importlib.metadata.entry_points",
        return_value=[],
    ):
        result = _resolve_plugin_class("no-such-plugin-xyz")
    assert result is None


def test_third_party_plugin_resolves_via_entry_point():
    """A name matched by an entry-point returns the loaded class."""
    ep = _make_ep("fake-external", FakeExternalPlugin)

    with patch(
        "shorewall_nft.plugins.manager.importlib.metadata.entry_points",
        return_value=[ep],
    ):
        cls = _resolve_plugin_class("fake-external")

    assert cls is FakeExternalPlugin
    ep.load.assert_called_once()


def test_entry_point_load_failure_raises_plugin_load_error():
    """A broken entry-point raises PluginLoadError (not a bare ImportError)."""
    ep = _make_ep("broken-plugin", FakeExternalPlugin)
    ep.load.side_effect = ImportError("missing dependency 'foo'")

    with pytest.raises(PluginLoadError, match="broken-plugin"):
        with patch(
            "shorewall_nft.plugins.manager.importlib.metadata.entry_points",
            return_value=[ep],
        ):
            _resolve_plugin_class("broken-plugin")


def test_builtin_takes_precedence_over_entry_point():
    """If an entry-point shares a name with a built-in, the built-in wins."""
    # Provide an entry-point that shadows "ip-info"
    ep = _make_ep("ip-info", FakeExternalPlugin)

    with patch(
        "shorewall_nft.plugins.manager.importlib.metadata.entry_points",
        return_value=[ep],
    ):
        cls = _resolve_plugin_class("ip-info")

    # The built-in class should be returned, not FakeExternalPlugin
    assert cls is not FakeExternalPlugin
    assert cls is not None
    # entry_points() must not even have been called for this path
    ep.load.assert_not_called()
