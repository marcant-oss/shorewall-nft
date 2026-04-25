"""Tests for the ?DYNSET directive added in Phase 5d of the libnftnl
gap-integration plan.

``?DYNSET set=NAME [timeout=DURATION]`` is a single-shot directive
that attaches an ``add @NAME { ip saddr [timeout DURATION] }``
statement to the very next rule produced by the parser. The
attachment is gated by ``has_dynset`` so ``--strict-features`` can
fail compile when the kernel lacks the dynamic-set add statement.

The directive resets after a single rule — a second rule that follows
without a fresh ``?DYNSET`` does NOT inherit the set-membership clause.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import (
    ConfigParser,
    DynsetClause,
    load_config,
)
from shorewall_nft.nft.emitter import emit_nft

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


# ── Directive parser ───────────────────────────────────────────────────────

def test_dynset_directive_sets_pending(tmp_path):
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    rules_path = cfg / "rules"
    existing = rules_path.read_text()
    rules_path.write_text(
        existing
        + "?DYNSET set=blacklist timeout=1h\n"
        + "DROP    net   $FW   tcp   22\n"
    )
    parser = ConfigParser(cfg)
    pcfg = parser.parse()
    # The DROP line must carry the directive; previous rules must not.
    drop_lines = [c for c in pcfg.rules
                  if c.columns and c.columns[0] == "DROP"]
    assert drop_lines, "fixture should have produced a DROP rule line"
    assert drop_lines[0].dynset == DynsetClause(
        set_name="blacklist", timeout="1h")


def test_dynset_directive_is_single_shot(tmp_path):
    """Two consecutive rules with one ?DYNSET — only the first inherits."""
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    rules_path = cfg / "rules"
    existing = rules_path.read_text()
    rules_path.write_text(
        existing
        + "?DYNSET set=blacklist timeout=1h\n"
        + "DROP    net   $FW   tcp   22\n"
        + "DROP    net   $FW   tcp   23\n"
    )
    parser = ConfigParser(cfg)
    pcfg = parser.parse()
    drop_lines = [c for c in pcfg.rules
                  if c.columns and c.columns[0] == "DROP"]
    assert len(drop_lines) == 2
    assert drop_lines[0].dynset is not None
    assert drop_lines[1].dynset is None


def test_dynset_reset_clears_pending(tmp_path):
    """An explicit ``?DYNSET reset`` cancels a previous setting."""
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    rules_path = cfg / "rules"
    existing = rules_path.read_text()
    rules_path.write_text(
        existing
        + "?DYNSET set=blacklist timeout=1h\n"
        + "?DYNSET reset\n"
        + "DROP    net   $FW   tcp   22\n"
    )
    parser = ConfigParser(cfg)
    pcfg = parser.parse()
    drop_lines = [c for c in pcfg.rules
                  if c.columns and c.columns[0] == "DROP"]
    assert drop_lines[0].dynset is None


def test_dynset_no_timeout(tmp_path):
    """Directive without ``timeout=`` — clause carries None."""
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    rules_path = cfg / "rules"
    existing = rules_path.read_text()
    rules_path.write_text(
        existing
        + "?DYNSET set=blacklist\n"
        + "DROP    net   $FW   tcp   22\n"
    )
    pcfg = ConfigParser(cfg).parse()
    drop = [c for c in pcfg.rules if c.columns and c.columns[0] == "DROP"][0]
    assert drop.dynset == DynsetClause(set_name="blacklist", timeout=None)


# ── End-to-end emit ────────────────────────────────────────────────────────

def _config_with_rule(tmp_path: Path, *lines: str) -> Path:
    cfg = tmp_path / "cfg"
    shutil.copytree(MINIMAL_DIR, cfg)
    rules_path = cfg / "rules"
    existing = rules_path.read_text() if rules_path.exists() else ""
    rules_path.write_text(existing + "\n".join(lines) + "\n")
    return cfg


def test_dynset_attaches_add_set_with_timeout(tmp_path):
    cfg = _config_with_rule(
        tmp_path,
        "?DYNSET set=blacklist timeout=1h",
        "DROP    net   $FW   tcp   22",
    )
    ir = build_ir(load_config(cfg))
    out = emit_nft(ir)
    assert "add @blacklist { ip saddr timeout 1h }" in out
    caps_required = {r.capability for r in ir.required_features}
    assert "has_dynset" in caps_required


def test_dynset_attaches_add_set_no_timeout(tmp_path):
    cfg = _config_with_rule(
        tmp_path,
        "?DYNSET set=blacklist",
        "DROP    net   $FW   tcp   22",
    )
    out = emit_nft(build_ir(load_config(cfg)))
    assert "add @blacklist { ip saddr }" in out


def test_dynset_singleshot_only_first_rule(tmp_path):
    """Second rule without a fresh ?DYNSET must not inherit the clause."""
    cfg = _config_with_rule(
        tmp_path,
        "?DYNSET set=blacklist timeout=1h",
        "DROP    net   $FW   tcp   22",
        "DROP    net   $FW   tcp   23",
    )
    out = emit_nft(build_ir(load_config(cfg)))
    # The dport=22 line should carry the add@; the dport=23 line should not.
    # Find the two DROP lines in emit and verify only one has add@.
    matching = [ln for ln in out.splitlines() if "add @blacklist" in ln]
    assert len(matching) == 1
