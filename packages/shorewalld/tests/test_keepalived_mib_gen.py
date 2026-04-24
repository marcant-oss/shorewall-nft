"""Tests for ``tools/gen_keepalived_mib.py`` — the SMIv2 parser.

Uses synthetic MIB snippets so tests are hermetic (no dependency on
the pinned upstream file). One test also verifies the real output
from the committed pinned MIB hits the expected coverage targets
(22+ tables, 2+ vrrp traps, ~89 scalars) so we notice if a future
parser tweak silently drops coverage.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Import the generator module by path since it's under tools/, not a package.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_GEN_PATH = _REPO_ROOT / "tools" / "gen_keepalived_mib.py"
_spec = importlib.util.spec_from_file_location("gen_keepalived_mib", _GEN_PATH)
assert _spec is not None
gen_mod = importlib.util.module_from_spec(_spec)
sys.modules["gen_keepalived_mib"] = gen_mod
assert _spec.loader is not None
_spec.loader.exec_module(gen_mod)

parse_mib = gen_mod.parse_mib
resolve_oids = gen_mod.resolve_oids
synthesize_tables = gen_mod.synthesize_tables
extract_scalars = gen_mod.extract_scalars
build = gen_mod.build
strip_comments = gen_mod.strip_comments


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------


def test_strip_comments_removes_double_dash_to_end_of_line():
    text = """foo OBJECT IDENTIFIER ::= { bar 1 } -- trailing
-- leading comment
baz OBJECT IDENTIFIER ::= { foo 2 }  -- inline"""
    out = strip_comments(text)
    assert "-- trailing" not in out
    assert "leading comment" not in out
    assert "inline" not in out
    assert "foo OBJECT IDENTIFIER ::= { bar 1 }" in out
    assert "baz OBJECT IDENTIFIER ::= { foo 2 }" in out


# ---------------------------------------------------------------------------
# Parser — hermetic snippets
# ---------------------------------------------------------------------------


_MINIMAL_MIB = """
KEEPALIVED-MIB DEFINITIONS ::= BEGIN

IMPORTS
    enterprises FROM SNMPv2-SMI;

keepalived MODULE-IDENTITY
    LAST-UPDATED "202404240000Z"
    ::= { project 5 }

debian   OBJECT IDENTIFIER ::= { enterprises 9586 }
project  OBJECT IDENTIFIER ::= { debian 100 }
global   OBJECT IDENTIFIER ::= { keepalived 1 }
vrrp     OBJECT IDENTIFIER ::= { keepalived 2 }
vrrpTraps OBJECT IDENTIFIER ::= { vrrp 10 }

VrrpState ::= TEXTUAL-CONVENTION
    STATUS current
    DESCRIPTION "VRRP state."
    SYNTAX INTEGER { backup(1), master(2), fault(3) }

version OBJECT-TYPE
    SYNTAX DisplayString
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "keepalived version"
    ::= { global 1 }

VrrpInstanceEntry ::= SEQUENCE {
    vrrpInstanceIndex Integer32,
    vrrpInstanceName  DisplayString,
    vrrpInstanceState VrrpState
}

vrrpInstanceTable OBJECT-TYPE
    SYNTAX SEQUENCE OF VrrpInstanceEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "all VRRP instances"
    ::= { vrrp 3 }

vrrpInstanceEntry OBJECT-TYPE
    SYNTAX VrrpInstanceEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "one instance"
    INDEX { vrrpInstanceIndex }
    ::= { vrrpInstanceTable 1 }

vrrpInstanceIndex OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "row index"
    ::= { vrrpInstanceEntry 1 }

vrrpInstanceName OBJECT-TYPE
    SYNTAX DisplayString
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "name"
    ::= { vrrpInstanceEntry 2 }

vrrpInstanceState OBJECT-TYPE
    SYNTAX VrrpState
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "state"
    ::= { vrrpInstanceEntry 3 }

vrrpInstanceStateChange NOTIFICATION-TYPE
    OBJECTS {
        vrrpInstanceName,
        vrrpInstanceState
    }
    STATUS current
    DESCRIPTION "state changed"
    ::= { vrrpTraps 2 }

END
"""


def test_parser_resolves_module_root_oid():
    mib = parse_mib(_MINIMAL_MIB)
    resolve_oids(mib)
    assert mib.module_name == "keepalived"
    assert mib.module_root_oid == "1.3.6.1.4.1.9586.100.5"


def test_parser_extracts_scalar():
    mib = parse_mib(_MINIMAL_MIB)
    resolve_oids(mib)
    tables = synthesize_tables(mib)
    scalars = extract_scalars(mib, tables)
    assert "1.3.6.1.4.1.9586.100.5.1.1" in scalars
    name, syntax, access = scalars["1.3.6.1.4.1.9586.100.5.1.1"]
    assert name == "version"
    assert syntax == "DisplayString"
    assert access == "read-only"


def test_parser_synthesizes_table_with_columns():
    mib = parse_mib(_MINIMAL_MIB)
    resolve_oids(mib)
    tables = synthesize_tables(mib)
    assert "vrrpInstanceTable" in tables
    t = tables["vrrpInstanceTable"]
    assert t.oid == "1.3.6.1.4.1.9586.100.5.2.3"
    assert t.entry_name == "vrrpInstanceEntry"
    assert t.entry_oid == "1.3.6.1.4.1.9586.100.5.2.3.1"
    assert t.index_cols == ["vrrpInstanceIndex"]
    assert 2 in t.columns and 3 in t.columns
    assert t.columns[2] == ("vrrpInstanceName", "DisplayString", "read-only")
    assert t.columns[3] == ("vrrpInstanceState", "VrrpState", "read-only")


def test_parser_extracts_notification_with_objects():
    mib = parse_mib(_MINIMAL_MIB)
    resolve_oids(mib)
    assert "vrrpInstanceStateChange" in mib.notifications
    n = mib.notifications["vrrpInstanceStateChange"]
    assert n.objects == ["vrrpInstanceName", "vrrpInstanceState"]
    # vrrpTraps = { vrrp 10 } = keepalived.2.10; trap = vrrpTraps.2 = …2.10.2
    assert mib.absolute_oids["vrrpInstanceStateChange"] == \
        "1.3.6.1.4.1.9586.100.5.2.10.2"


def test_parser_captures_textual_convention_syntax():
    mib = parse_mib(_MINIMAL_MIB)
    assert "VrrpState" in mib.textual_conventions
    assert "INTEGER" in mib.textual_conventions["VrrpState"]
    assert "backup(1)" in mib.textual_conventions["VrrpState"]


def test_parser_tolerates_trailing_comments_on_oid_assignments():
    mib_text = _MINIMAL_MIB.replace(
        "global   OBJECT IDENTIFIER ::= { keepalived 1 }",
        "global   OBJECT IDENTIFIER ::= { keepalived 1 } -- the global subtree",
    )
    mib = parse_mib(mib_text)
    resolve_oids(mib)
    assert mib.absolute_oids.get("global") == "1.3.6.1.4.1.9586.100.5.1"


def test_table_columns_include_index_column():
    """Index columns (MAX-ACCESS not-accessible) stay in the column map.

    They're not separately walkable but runtime consumers need them to
    understand row encoding (e.g. how many sub-indices form the row
    suffix). The Prom metrics module filters them out by access.
    """
    mib = parse_mib(_MINIMAL_MIB)
    resolve_oids(mib)
    tables = synthesize_tables(mib)
    t = tables["vrrpInstanceTable"]
    assert sorted(t.columns) == [1, 2, 3]
    # Col 1 is the index, not-accessible.
    assert t.columns[1] == ("vrrpInstanceIndex", "Integer32", "not-accessible")


# ---------------------------------------------------------------------------
# Coverage check against the pinned upstream MIB
# ---------------------------------------------------------------------------


def test_pinned_upstream_mib_yields_expected_coverage():
    """Guardrail: real MIB produces the coverage floor we advertised.

    Not a tight spec — upstream can grow; but a drop below these
    floors means the parser silently lost something.
    """
    mib_path = _REPO_ROOT / "third_party" / "keepalived-mib" / "KEEPALIVED-MIB.txt"
    if not mib_path.exists():
        pytest.skip("pinned upstream MIB not checked into repo")
    content = build(mib_path)

    # Quick-count entries from the generated module.
    import re
    # 4-space indented OID-keyed lines = SCALARS + NOTIFICATIONS entries
    # (~32 scalars + 4 traps = ~36 at the current pin). Floor at 25 to
    # accommodate future trimming without making the test brittle.
    oid_line_count = len(re.findall(
        r"^    '1\.3\.6\.1\.4\.1\.9586\.100\.5", content, re.MULTILINE,
    ))
    assert oid_line_count >= 25, (
        f"OID entry count dropped to {oid_line_count} — parser regression?"
    )

    # Table roots — ``'name': {`` at 4-space indent inside TABLES dict.
    table_count = len(re.findall(
        r"^    '[A-Za-z]+Table': \{$", content, re.MULTILINE,
    ))
    assert table_count >= 20, f"table count dropped to {table_count}"

    # Total table columns across all tables — floor reflects the bulk
    # of actual "queryable state".
    column_count = len(re.findall(
        r"^            \d+: \('", content, re.MULTILINE,
    ))
    assert column_count >= 200, (
        f"total table-column count dropped to {column_count}"
    )

    # Notifications — both vrrp traps plus both check traps.
    assert "vrrpInstanceStateChange" in content
    assert "vrrpSyncGroupStateChange" in content
    assert "realServerStateChange" in content
    assert "virtualServerQuorumStateChange" in content
