"""Tests for the IPv6 extension-header (HEADERS column) emit added in
Phase 5c of the libnftnl gap-integration plan.

The HEADERS column on a rule maps to one or more nft ``exthdr <name>
{exists,missing}`` matches. Negation in the column flips the
``exists`` vs ``missing`` keyword. Each rule that uses HEADERS
registers a ``has_exthdr`` capability requirement on the IR so
``--strict-features`` can fail compile when the kernel lacks the
match family.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


def _config_with_rule(tmp_path: Path, rule_line: str) -> Path:
    """Copy the minimal fixture and append a rules file with one rule."""
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    rules_path = cfg / "rules"
    existing = rules_path.read_text() if rules_path.exists() else ""
    rules_path.write_text(existing + rule_line + "\n")
    return cfg


def test_exthdr_single_header_emits_exists(tmp_path):
    """``frag`` in HEADERS → ``exthdr frag exists``."""
    cfg = _config_with_rule(
        tmp_path,
        "ACCEPT  loc  net  -  -  -  -  -  -  -  -  -  frag",
    )
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "exthdr frag exists" in out
    caps_required = {r.capability for r in ir.required_features}
    assert "has_exthdr" in caps_required


def test_exthdr_multiple_headers_emit_separate_matches(tmp_path):
    """``hop,dst`` produces two separate exists matches with mapped names.

    ``hop`` → ``hbh`` (nft uses hbh for hop-by-hop), ``dst`` stays
    ``dst``. Both rendered as ``exists``.
    """
    cfg = _config_with_rule(
        tmp_path,
        "ACCEPT  loc  net  -  -  -  -  -  -  -  -  -  hop,dst",
    )
    out = emit_nft(build_ir(load_config(cfg)))
    assert "exthdr hbh exists" in out
    assert "exthdr dst exists" in out


def test_exthdr_negate_emits_missing(tmp_path):
    """``!frag`` in HEADERS flips ``exists`` to ``missing``."""
    cfg = _config_with_rule(
        tmp_path,
        "ACCEPT  loc  net  -  -  -  -  -  -  -  -  -  !frag",
    )
    out = emit_nft(build_ir(load_config(cfg)))
    assert "exthdr frag missing" in out
    assert "exthdr frag exists" not in out


def test_exthdr_no_header_means_no_capability_required(tmp_path):
    """A rule without HEADERS does not register ``has_exthdr``.

    Capability registration is per-use, not blanket — a config with
    no IPv6 ext-header matches must compile cleanly on a kernel that
    lacks the feature even under ``--strict-features``.
    """
    cfg = _config_with_rule(
        tmp_path,
        "ACCEPT  loc  net  tcp  80",
    )
    ir = build_ir(load_config(cfg))
    caps_required = {r.capability for r in ir.required_features}
    assert "has_exthdr" not in caps_required
