"""Tests for the TPROXY mangle action added in Phase 5a of the
libnftnl gap-integration plan.

TPROXY is recognised in the ACTION column of the ``mangle`` config
file (and ``tcrules`` for back-compat). It emits an nft ``tproxy``
statement gated by ``has_tproxy_stmt`` and registers a strict-mode
capability requirement.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.compiler.tc import _parse_tproxy_params
from shorewall_nft.compiler.verdicts import TproxyVerdict
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


# ── _parse_tproxy_params ────────────────────────────────────────────────────

def test_tproxy_port_only():
    v = _parse_tproxy_params("3128")
    assert v == TproxyVerdict(port=3128, addr=None)


def test_tproxy_port_and_v4_addr():
    v = _parse_tproxy_params("3128,127.0.0.1")
    assert v == TproxyVerdict(port=3128, addr="127.0.0.1")


def test_tproxy_port_and_v6_addr():
    v = _parse_tproxy_params("3128,::1")
    assert v == TproxyVerdict(port=3128, addr="::1")


def test_tproxy_hex_port():
    """0x-prefixed integers are honoured by ``int(s, 0)``."""
    v = _parse_tproxy_params("0xc38")
    assert v is not None and v.port == 0xc38


def test_tproxy_invalid_returns_none():
    assert _parse_tproxy_params("") is None
    assert _parse_tproxy_params("notanumber") is None
    assert _parse_tproxy_params("0") is None       # port 0 out of range
    assert _parse_tproxy_params("65536") is None   # port too large


# ── End-to-end emit ────────────────────────────────────────────────────────

def _config_with_mangle(tmp_path: Path, mangle_line: str) -> Path:
    """Copy the minimal fixture and append a mangle file with one rule.

    The minimal fixture has no mangle file by default, so we add one
    with the given mangle ACTION line.
    """
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    (cfg / "mangle").write_text(
        "#ACTION              SOURCE  DEST  PROTO  DPORT\n"
        f"{mangle_line}\n"
    )
    return cfg


def test_tproxy_port_only_emits_nft(tmp_path):
    cfg = _config_with_mangle(
        tmp_path, "TPROXY(3128)  all  all  tcp  80")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    # Port-only form: no family qualifier, listener address inherited
    # from the chain family.
    assert "tproxy to :3128" in out
    # Lives in the mangle-prerouting chain (filter type, priority -150)
    assert "type filter hook prerouting priority -150" in out
    # Strict requirement registered.
    caps_required = {r.capability for r in ir.required_features}
    assert "has_tproxy_stmt" in caps_required


def test_tproxy_v4_addr_emits_ip_qualifier(tmp_path):
    cfg = _config_with_mangle(
        tmp_path, "TPROXY(3128,127.0.0.1)  all  all  tcp  80")
    out = emit_nft(build_ir(load_config(cfg)))
    assert "tproxy ip to 127.0.0.1:3128" in out


def test_tproxy_v6_addr_emits_ip6_qualifier(tmp_path):
    cfg = _config_with_mangle(
        tmp_path, "TPROXY(3128,::1)  all  all  tcp  80")
    out = emit_nft(build_ir(load_config(cfg)))
    assert "tproxy ip6 to [::1]:3128" in out


def test_tproxy_malformed_skips_rule(tmp_path, caplog):
    """A malformed TPROXY body logs at WARNING and emits no rule."""
    import logging
    caplog.set_level(logging.WARNING, logger="shorewall_nft.compiler.tc")
    cfg = _config_with_mangle(
        tmp_path, "TPROXY(notanumber)  all  all  tcp  80")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "tproxy" not in out
    assert any("TPROXY action" in rec.getMessage()
               and "malformed" in rec.getMessage()
               for rec in caplog.records)
