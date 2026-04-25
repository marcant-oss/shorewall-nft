"""Tests for the secmarks file (WP-F2; SELinux MAC).

Covers the post-libnftnl follow-up that wires the previously-ignored
``secmarks`` config file into the IR + emitter:

* Parser already accepts the file (config/parser.py:89, 185) — this
  suite asserts the file now reaches the IR builder and produces
  named secmark objects + ``meta secmark set`` rules.
* Two rows sharing a SELinux label collapse to one named object so
  the kernel only allocates one secmark per context.
* Unknown CHAIN codes / SAVE/RESTORE / empty labels are skipped
  with a warning so a malformed row never crashes the compile.
* The capability ``has_secmark_obj`` is registered on
  ``ir.required_features`` so ``--strict-features`` errors out on
  a kernel that lacks the named-object form.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.compiler.ir._data import SecmarkObject
from shorewall_nft.compiler.verdicts import SecmarkVerdict
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


def _config_with_secmarks(tmp_path: Path, secmarks_body: str) -> Path:
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    (cfg / "secmarks").write_text(secmarks_body)
    return cfg


# ── IR-builder dedupe + chain wiring ───────────────────────────────────────


def test_secmarks_dedupe_unique_labels(tmp_path):
    """Two rows sharing one label produce ONE named object + 2 rules."""
    cfg = _config_with_secmarks(tmp_path, """\
#SECMARK                                    CHAIN  SOURCE  DEST  PROTO  DPORT  SPORT  STATE
"system_u:object_r:web_t:s0"                P      net     fw    tcp    80     -      -
"system_u:object_r:web_t:s0"                P      net     fw    tcp    443    -      -
"system_u:object_r:ssh_t:s0"                P      net     fw    tcp    22     -      -
""")
    ir = build_ir(load_config(cfg))
    assert ir.secmark_objects == [
        SecmarkObject(name="_sm_0", label="system_u:object_r:web_t:s0"),
        SecmarkObject(name="_sm_1", label="system_u:object_r:ssh_t:s0"),
    ]
    chain = ir.chains["mangle-prerouting"]
    secmark_rules = [r for r in chain.rules
                     if isinstance(r.verdict_args, SecmarkVerdict)]
    assert len(secmark_rules) == 3
    # The two web rules reuse _sm_0; the ssh rule uses _sm_1.
    names = [r.verdict_args.secmark_name for r in secmark_rules]
    assert names == ["_sm_0", "_sm_0", "_sm_1"]


def test_secmarks_capability_registered(tmp_path):
    cfg = _config_with_secmarks(tmp_path, """\
"system_u:object_r:web_t:s0"  P  net  fw  tcp  80  -  -
""")
    ir = build_ir(load_config(cfg))
    caps_required = {r.capability for r in ir.required_features}
    assert "has_secmark_obj" in caps_required


# ── Emitter — named-object decls + meta secmark set lines ──────────────────


def test_secmarks_emit_named_object_declaration(tmp_path):
    cfg = _config_with_secmarks(tmp_path, """\
"system_u:object_r:web_t:s0"  P  net  fw  tcp  80  -  -
""")
    out = emit_nft(build_ir(load_config(cfg)))
    assert 'secmark _sm_0 { "system_u:object_r:web_t:s0" }' in out
    # The dedicated section header must accompany the decl so reviewers
    # immediately see where the named object came from.
    assert "Named secmark objects (from secmarks file)" in out


def test_secmarks_emit_meta_secmark_set_rule(tmp_path):
    cfg = _config_with_secmarks(tmp_path, """\
"system_u:object_r:web_t:s0"  P  net  fw  tcp  80  -  -
""")
    out = emit_nft(build_ir(load_config(cfg)))
    # The mangle-prerouting chain carries the rule.
    assert 'meta secmark set "_sm_0"' in out


def test_secmarks_two_rows_share_one_object(tmp_path):
    """Two rows with same label → ONE secmark decl, TWO rules."""
    cfg = _config_with_secmarks(tmp_path, """\
"system_u:object_r:web_t:s0"  P  net  fw  tcp  80   -  -
"system_u:object_r:web_t:s0"  P  net  fw  tcp  443  -  -
""")
    out = emit_nft(build_ir(load_config(cfg)))
    assert out.count('secmark _sm_0 { "system_u:object_r:web_t:s0" }') == 1
    assert out.count('meta secmark set "_sm_0"') == 2


# ── malformed rows are skipped, not crash-on ───────────────────────────────


def test_secmarks_unknown_chain_code_skipped(tmp_path, caplog):
    """``CHAIN=Z`` is not a known code → row skipped with a warning."""
    cfg = _config_with_secmarks(tmp_path, """\
"system_u:object_r:web_t:s0"  Z  net  fw  tcp  80  -  -
""")
    import logging
    with caplog.at_level(logging.WARNING):
        ir = build_ir(load_config(cfg))
    assert ir.secmark_objects == []
    assert any("unknown CHAIN code" in rec.message for rec in caplog.records)


def test_secmarks_save_restore_deferred_skip(tmp_path, caplog):
    """SAVE / RESTORE column values are not yet supported — skip+warn."""
    cfg = _config_with_secmarks(tmp_path, """\
SAVE     P  net  fw  tcp  80  -  -
RESTORE  P  net  fw  tcp  80  -  -
""")
    import logging
    with caplog.at_level(logging.WARNING):
        ir = build_ir(load_config(cfg))
    assert ir.secmark_objects == []
    save_warnings = [r for r in caplog.records
                     if "SAVE/RESTORE" in r.message]
    assert len(save_warnings) == 2


def test_secmarks_empty_label_skipped(tmp_path, caplog):
    cfg = _config_with_secmarks(tmp_path, """\
""  P  net  fw  tcp  80  -  -
""")
    import logging
    with caplog.at_level(logging.WARNING):
        ir = build_ir(load_config(cfg))
    assert ir.secmark_objects == []
    assert any("empty SECMARK" in rec.message for rec in caplog.records)


# ── No-secmarks-file path: zero regression ─────────────────────────────────


def test_no_secmarks_file_produces_no_secmark_output(tmp_path):
    """A config without a secmarks file emits no secmark objects/rules."""
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert ir.secmark_objects == []
    assert "secmark " not in out  # zero secmark decls
    assert "meta secmark set" not in out
