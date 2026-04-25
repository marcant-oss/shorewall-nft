"""Tests for the SYNPROXY and QUOTA actions added in Phase 4 of the
libnftnl gap-integration plan.

Both actions are recognised in the rules-file ACTION column and emit
nft 1.1.x statements behind capability-gated requirements (registered
on ``ir.required_features`` for ``--strict-features`` validation).
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.compiler.ir.rules import (
    _parse_quota_params,
    _parse_synproxy_params,
)
from shorewall_nft.compiler.verdicts import QuotaVerdict, SynproxyVerdict
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

from pathlib import Path

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


# ── _parse_synproxy_params ──────────────────────────────────────────────────

def test_synproxy_defaults_when_empty():
    v = _parse_synproxy_params("")
    assert v == SynproxyVerdict(mss=1460, wscale=7,
                                timestamp=True, sack_perm=True)


def test_synproxy_explicit_values():
    v = _parse_synproxy_params("mss=1380,wscale=5")
    assert v.mss == 1380
    assert v.wscale == 5
    # Defaults preserved on flags
    assert v.timestamp is True
    assert v.sack_perm is True


def test_synproxy_negative_flags():
    v = _parse_synproxy_params("no-timestamp,no-sack-perm")
    assert v.timestamp is False
    assert v.sack_perm is False


def test_synproxy_unknown_token_silently_dropped():
    """Forward-compat: unknown tokens shouldn't crash; nft -f rejects them."""
    v = _parse_synproxy_params("mss=1460,bogus")
    assert v.mss == 1460  # known token still applied


# ── _parse_quota_params ─────────────────────────────────────────────────────

def test_quota_bare_int_means_bytes():
    v = _parse_quota_params("1024")
    assert v == QuotaVerdict(bytes_count=1024, unit="bytes")


def test_quota_unit_form():
    v = _parse_quota_params("100,mbytes")
    assert v == QuotaVerdict(bytes_count=100, unit="mbytes")


def test_quota_suffix_shorthand():
    v = _parse_quota_params("500m")
    assert v == QuotaVerdict(bytes_count=500, unit="mbytes")
    v = _parse_quota_params("1g")
    assert v == QuotaVerdict(bytes_count=1, unit="gbytes")


def test_quota_invalid_returns_none():
    assert _parse_quota_params("") is None
    assert _parse_quota_params("notanumber") is None
    assert _parse_quota_params("100,mehbytes") is None  # unknown unit


# ── End-to-end emit ────────────────────────────────────────────────────────

def _config_with_action(tmp_path: Path, action: str) -> Path:
    """Copy the minimal fixture into tmp_path and append a rule with
    the given ACTION token. Returns the new config dir.
    """
    import shutil
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    (cfg / "rules").write_text(
        (cfg / "rules").read_text()
        + f"\n{action}\tloc\tnet\ttcp\t80\n"
    )
    return cfg


def test_synproxy_emits_nft_statement(tmp_path):
    cfg = _config_with_action(tmp_path, "SYNPROXY(mss=1460,wscale=7)")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "synproxy mss 1460 wscale 7 timestamp sack-perm" in out
    # Strict requirement registered.
    caps_required = {r.capability for r in ir.required_features}
    assert "has_synproxy_stmt" in caps_required


def test_synproxy_default_form(tmp_path):
    cfg = _config_with_action(tmp_path, "SYNPROXY")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "synproxy mss 1460 wscale 7 timestamp sack-perm" in out


def test_quota_emits_drop_when_over(tmp_path):
    cfg = _config_with_action(tmp_path, "QUOTA(500m)")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "quota over 500 mbytes drop" in out
    caps_required = {r.capability for r in ir.required_features}
    assert "has_quota" in caps_required


def test_quota_bytes_form(tmp_path):
    cfg = _config_with_action(tmp_path, "QUOTA(1024)")
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "quota over 1024 bytes drop" in out
