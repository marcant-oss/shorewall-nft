"""Tests for the DUP mangle action added in Phase 5b of the
libnftnl gap-integration plan.

DUP is recognised in the ACTION column of the ``mangle`` config
file (and ``tcrules`` for back-compat). It emits an nft ``dup to
<addr> [device "<dev>"]`` statement gated by ``has_dup`` and
registers a strict-mode capability requirement.

The companion ``fwd`` (zero-copy forward) statement is netdev-
ingress only and is tracked separately — it cannot share the
mangle-prerouting hook the way DUP can.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.compiler.tc import _parse_dup_params
from shorewall_nft.compiler.verdicts import DupVerdict
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


# ── _parse_dup_params ──────────────────────────────────────────────────────

def test_dup_addr_only():
    v = _parse_dup_params("198.51.100.7")
    assert v == DupVerdict(target="198.51.100.7", device=None)


def test_dup_addr_and_device():
    v = _parse_dup_params("198.51.100.7,eth0")
    assert v == DupVerdict(target="198.51.100.7", device="eth0")


def test_dup_v6_addr():
    v = _parse_dup_params("2001:db8::1")
    assert v == DupVerdict(target="2001:db8::1", device=None)


def test_dup_addr_and_device_strips_whitespace():
    v = _parse_dup_params(" 198.51.100.7 , eth0 ")
    assert v == DupVerdict(target="198.51.100.7", device="eth0")


def test_dup_invalid_returns_none():
    assert _parse_dup_params("") is None
    assert _parse_dup_params(",eth0") is None        # missing addr
    assert _parse_dup_params("   ") is None


# ── End-to-end emit ────────────────────────────────────────────────────────

def _config_with_mangle(tmp_path: Path, mangle_line: str) -> Path:
    """Copy the minimal fixture and append a mangle file with one rule."""
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    (cfg / "mangle").write_text(
        "#ACTION              SOURCE  DEST  PROTO  DPORT\n"
        f"{mangle_line}\n"
    )
    return cfg


def test_dup_addr_only_emits_nft(tmp_path):
    cfg = _config_with_mangle(
        tmp_path, "DUP(198.51.100.7)  all  all")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "dup to 198.51.100.7" in out
    # No device clause.
    assert 'device "' not in out.split("dup to 198.51.100.7", 1)[1].split("\n", 1)[0]
    # Lives in the mangle-prerouting chain.
    assert "type filter hook prerouting priority -150" in out
    # Strict requirement registered.
    caps_required = {r.capability for r in ir.required_features}
    assert "has_dup" in caps_required


def test_dup_with_device_emits_nft(tmp_path):
    cfg = _config_with_mangle(
        tmp_path, "DUP(198.51.100.7,eth0)  all  all")
    out = emit_nft(build_ir(load_config(cfg)))
    assert 'dup to 198.51.100.7 device "eth0"' in out


def test_dup_v6_emits_nft(tmp_path):
    cfg = _config_with_mangle(
        tmp_path, "DUP(2001:db8::1)  all  all")
    out = emit_nft(build_ir(load_config(cfg)))
    assert "dup to 2001:db8::1" in out


def test_dup_malformed_skips_rule(tmp_path, caplog):
    """A malformed DUP body logs at WARNING and emits no rule."""
    import logging
    caplog.set_level(logging.WARNING, logger="shorewall_nft.compiler.tc")
    cfg = _config_with_mangle(
        tmp_path, "DUP()  all  all")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "dup to" not in out
    assert any("DUP action" in rec.getMessage()
               and "malformed" in rec.getMessage()
               for rec in caplog.records)
