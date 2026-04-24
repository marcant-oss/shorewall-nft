"""Tests for the BackendEmitter protocol and registry (P8 first step)."""

from __future__ import annotations

from pathlib import Path

import pytest

from shorewall_nft.compiler.backends import (
    get_backend,
    register_backend,
    select_backend,
)
from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


def test_backend_registered():
    backend = get_backend("nft")
    assert backend.name == "nft"


def _strip_timestamp(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.startswith("# Generated at:")
    )


def test_backend_emit_matches_direct():
    config = load_config(MINIMAL_DIR)
    ir = build_ir(config)
    # Timestamps differ between two independent emit_nft calls, so compare
    # the stable content only.
    assert _strip_timestamp(get_backend("nft").emit(ir)) == _strip_timestamp(
        emit_nft(ir)
    )


def test_select_backend_default():
    backend = select_backend({})
    assert backend.name == "nft"


def test_select_backend_explicit():
    backend = select_backend({"BACKEND": "nft"})
    assert backend.name == "nft"

    with pytest.raises(ValueError, match="vpp"):
        select_backend({"BACKEND": "vpp"})


def test_register_new_backend():
    from dataclasses import dataclass, field

    @dataclass
    class FakeBackend:
        name: str = field(default="fake")

        def emit(self, ir):
            return "FAKE\n"

    fake = FakeBackend()
    register_backend(fake)
    try:
        retrieved = get_backend("fake")
        assert retrieved is fake
        assert retrieved.emit(None) == "FAKE\n"
    finally:
        from shorewall_nft.compiler.backends import _BACKENDS

        _BACKENDS.pop("fake", None)
