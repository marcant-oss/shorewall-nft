#!/usr/bin/env python3
"""Build-time generator for ``shorewalld/keepalived/mib.py``.

Reads ``third_party/keepalived-mib/KEEPALIVED-MIB.txt`` (pinned to an
upstream commit — see the adjacent ``PROVENANCE.md``), parses the
relevant SMIv2 declarations, and emits a Python module with
OID ↔ name ↔ SYNTAX tables that the runtime walker uses to
auto-discover fields.

Scope — deliberately narrow so the parser stays small:

* ``<name> OBJECT IDENTIFIER ::= { <parent> <num> }``
* ``<name> MODULE-IDENTITY ... ::= { <parent> <num> }``
* ``<name> OBJECT-TYPE`` blocks (SYNTAX + MAX-ACCESS + INDEX + ::=)
* ``<name> NOTIFICATION-TYPE`` blocks (OBJECTS + ::=)
* ``<Name> ::= SEQUENCE { col TYPE, ... }`` row types
* ``<Name> ::= TEXTUAL-CONVENTION ... SYNTAX <type>`` aliases

Skipped: MODULE-COMPLIANCE, OBJECT-GROUP, NOTIFICATION-GROUP,
IMPORTS resolution. The generated ``mib.py`` carries syntax strings
verbatim; the runtime consumer interprets them (``Counter32`` →
Prometheus counter, ``Integer32`` / ``Gauge32`` → gauge, etc.).

Invocation:

    python3 tools/gen_keepalived_mib.py --emit packages/shorewalld/shorewalld/keepalived/mib.py
    python3 tools/gen_keepalived_mib.py --check packages/shorewalld/shorewalld/keepalived/mib.py

``--check`` exits 1 if the committed file differs from a freshly
generated one — wired into ``make check-keepalived-mib`` for CI drift
detection.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# SMIv2 base OIDs — not in the MIB itself, resolved out-of-band per RFC 2578.
# ---------------------------------------------------------------------------

_BASE_OIDS: dict[str, str] = {
    "iso": "1",
    "org": "1.3",
    "dod": "1.3.6",
    "internet": "1.3.6.1",
    "directory": "1.3.6.1.1",
    "mgmt": "1.3.6.1.2",
    "mib-2": "1.3.6.1.2.1",
    "experimental": "1.3.6.1.3",
    "private": "1.3.6.1.4",
    "enterprises": "1.3.6.1.4.1",
}


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass
class ObjectTypeDef:
    """One ``OBJECT-TYPE`` block."""
    name: str
    parent: str
    num: int
    syntax: str
    access: str
    index: list[str] | None = None  # non-None for table-entry nodes


@dataclass
class NotificationDef:
    """One ``NOTIFICATION-TYPE`` block."""
    name: str
    parent: str
    num: int
    objects: list[str]


@dataclass
class ParsedMib:
    module_name: str = ""
    module_root_oid: str = ""
    oid_nodes: dict[str, tuple[str, int]] = field(default_factory=dict)
    object_types: dict[str, ObjectTypeDef] = field(default_factory=dict)
    notifications: dict[str, NotificationDef] = field(default_factory=dict)
    sequence_types: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    textual_conventions: dict[str, str] = field(default_factory=dict)
    absolute_oids: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------


def strip_comments(text: str) -> str:
    """Remove SMIv2 ``-- comment`` sequences.

    SMIv2 comments start with ``--`` and end at the next ``--`` OR at
    end-of-line (ASN.1 actually says the same, but net-snmp MIBs treat
    them as end-of-line comments by convention — which is what we
    honour).
    """
    out = []
    for line in text.splitlines():
        idx = line.find("--")
        if idx >= 0:
            line = line[:idx]
        out.append(line)
    return "\n".join(out)


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# Pattern extraction
# ---------------------------------------------------------------------------

# ``<name> OBJECT IDENTIFIER ::= { <parent> <num> }``
_OID_ASSIGN_RE = re.compile(
    r"(?P<name>[A-Za-z][\w-]*)\s+"
    r"OBJECT\s+IDENTIFIER\s*::=\s*\{\s*"
    r"(?P<parent>[A-Za-z][\w-]*)\s+(?P<num>\d+)\s*\}",
    re.MULTILINE,
)

# ``<name> MODULE-IDENTITY ... ::= { <parent> <num> }``
_MODULE_IDENTITY_RE = re.compile(
    r"(?P<name>[A-Za-z][\w-]*)\s+MODULE-IDENTITY"
    r".*?::=\s*\{\s*(?P<parent>[A-Za-z][\w-]*)\s+(?P<num>\d+)\s*\}",
    re.DOTALL,
)

# ``<Name> ::= TEXTUAL-CONVENTION ... SYNTAX <type>``
_TEXTUAL_CONVENTION_RE = re.compile(
    r"(?P<name>[A-Z][\w-]*)\s*::=\s*TEXTUAL-CONVENTION"
    r".*?SYNTAX\s+(?P<syntax>[^\n]+?)(?=\n\s*(?:[A-Za-z][\w-]*\s*::=|[A-Za-z][\w-]*\s+(?:OBJECT-TYPE|NOTIFICATION-TYPE|OBJECT\s+IDENTIFIER|MODULE-IDENTITY|TEXTUAL-CONVENTION)|$))",
    re.DOTALL,
)

# ``<Name> ::= SEQUENCE { col TYPE, col TYPE, ... }``
_SEQUENCE_RE = re.compile(
    r"(?P<name>[A-Z][\w-]*)\s*::=\s*SEQUENCE\s*\{"
    r"(?P<body>[^{}]+)\}",
    re.DOTALL,
)

# ``<name> OBJECT-TYPE ... ::= { <parent> <num> }``
_OBJECT_TYPE_RE = re.compile(
    r"(?P<name>[A-Za-z][\w-]*)\s+OBJECT-TYPE"
    r"\s+SYNTAX\s+(?P<syntax>.+?)"
    r"\s+MAX-ACCESS\s+(?P<access>[\w-]+)"
    r"\s+STATUS\s+\w+"
    r".*?::=\s*\{\s*(?P<parent>[A-Za-z][\w-]*)\s+(?P<num>\d+)\s*\}",
    re.DOTALL,
)

# ``<name> NOTIFICATION-TYPE OBJECTS { ... } STATUS ... ::= { parent num }``
_NOTIFICATION_TYPE_RE = re.compile(
    r"(?P<name>[A-Za-z][\w-]*)\s+NOTIFICATION-TYPE"
    r"\s+OBJECTS\s*\{\s*(?P<objects>[^}]+)\}"
    r"\s+STATUS\s+\w+"
    r".*?::=\s*\{\s*(?P<parent>[A-Za-z][\w-]*)\s+(?P<num>\d+)\s*\}",
    re.DOTALL,
)


def _extract_index_clause(object_type_block: str) -> list[str] | None:
    """Pull the ``INDEX { c1, c2 }`` list from an OBJECT-TYPE block, if any."""
    m = re.search(
        r"INDEX\s*\{\s*(?P<cols>[^}]+)\}", object_type_block, re.DOTALL)
    if not m:
        return None
    cols = [c.strip() for c in m.group("cols").split(",")]
    return [c for c in cols if c]


def parse_mib(text: str) -> ParsedMib:
    """Run all extraction passes over the pre-stripped MIB text."""
    mib = ParsedMib()
    text = strip_comments(text)

    # Module identity → top-level OID.
    m = _MODULE_IDENTITY_RE.search(text)
    if m:
        mib.module_name = m.group("name")
        mib.oid_nodes[mib.module_name] = (m.group("parent"), int(m.group("num")))

    # OID-only assignments.
    for m in _OID_ASSIGN_RE.finditer(text):
        mib.oid_nodes[m.group("name")] = (
            m.group("parent"), int(m.group("num")))

    # TEXTUAL-CONVENTION — just remember the underlying SYNTAX so we
    # can flag a column's type as an enum if the base is INTEGER { ... }.
    for m in _TEXTUAL_CONVENTION_RE.finditer(text):
        mib.textual_conventions[m.group("name")] = \
            normalize_whitespace(m.group("syntax"))

    # SEQUENCE row types — columns for tables.
    for m in _SEQUENCE_RE.finditer(text):
        body = m.group("body")
        cols: list[tuple[str, str]] = []
        for raw_col in body.split(","):
            raw_col = normalize_whitespace(raw_col)
            if not raw_col:
                continue
            parts = raw_col.split(None, 1)
            if len(parts) == 2:
                cols.append((parts[0], parts[1]))
        if cols:
            mib.sequence_types[m.group("name")] = cols

    # OBJECT-TYPE blocks.
    for m in _OBJECT_TYPE_RE.finditer(text):
        name = m.group("name")
        syntax = normalize_whitespace(m.group("syntax"))
        access = m.group("access")
        parent = m.group("parent")
        num = int(m.group("num"))
        # Look for INDEX inside the whole matched block.
        block = m.group(0)
        index = _extract_index_clause(block)
        mib.object_types[name] = ObjectTypeDef(
            name=name, parent=parent, num=num,
            syntax=syntax, access=access, index=index,
        )
        # OBJECT-TYPE nodes are also OID nodes, needed for resolution.
        mib.oid_nodes.setdefault(name, (parent, num))

    # NOTIFICATION-TYPE blocks.
    for m in _NOTIFICATION_TYPE_RE.finditer(text):
        name = m.group("name")
        objs = [o.strip() for o in m.group("objects").split(",")]
        parent = m.group("parent")
        num = int(m.group("num"))
        mib.notifications[name] = NotificationDef(
            name=name, parent=parent, num=num,
            objects=[o for o in objs if o],
        )
        mib.oid_nodes.setdefault(name, (parent, num))

    return mib


# ---------------------------------------------------------------------------
# OID resolution
# ---------------------------------------------------------------------------


def resolve_oids(mib: ParsedMib) -> None:
    """Fill in ``mib.absolute_oids`` by walking each node's parent chain.

    Starts from the SMIv2 built-ins in :data:`_BASE_OIDS` and adds a
    node every time we can reach it from an already-resolved parent.
    """
    resolved: dict[str, str] = dict(_BASE_OIDS)
    # Iterate until fixpoint (or until we can't resolve any more).
    pending = dict(mib.oid_nodes)
    for _ in range(len(pending) + 1):
        progress = False
        for name in list(pending):
            parent, num = pending[name]
            if parent in resolved:
                resolved[name] = f"{resolved[parent]}.{num}"
                del pending[name]
                progress = True
        if not progress:
            break
    mib.absolute_oids = resolved
    if pending:
        sys.stderr.write(
            f"gen_keepalived_mib: {len(pending)} OID(s) unresolved "
            f"(unreachable from SMIv2 base): {sorted(pending)[:5]}…\n",
        )
    if mib.module_name and mib.module_name in resolved:
        mib.module_root_oid = resolved[mib.module_name]


# ---------------------------------------------------------------------------
# Table synthesis
# ---------------------------------------------------------------------------


@dataclass
class TableDef:
    name: str                    # vrrpInstanceTable
    oid: str                     # 1.3.6.1.4.1.9586.100.5.2.3
    entry_name: str              # vrrpInstanceEntry
    entry_oid: str               # 1.3.6.1.4.1.9586.100.5.2.3.1
    index_cols: list[str]        # ['vrrpInstanceIndex']
    # Column number (OID suffix after entry_oid) → (name, syntax, access)
    columns: dict[int, tuple[str, str, str]]


def synthesize_tables(mib: ParsedMib) -> dict[str, TableDef]:
    """Identify all table roots, their entry nodes, and column layouts.

    A **table** is an OBJECT-TYPE whose SYNTAX starts with
    ``SEQUENCE OF Xxx``. Its ``entry`` is the OBJECT-TYPE whose parent
    is the table, has SYNTAX ``Xxx``, and carries an INDEX clause.
    Columns come from the SEQUENCE definition of ``Xxx``.
    """
    tables: dict[str, TableDef] = {}

    # Index by parent name for fast entry lookup.
    by_parent: dict[str, list[ObjectTypeDef]] = {}
    for obj in mib.object_types.values():
        by_parent.setdefault(obj.parent, []).append(obj)

    for table_name, table_obj in mib.object_types.items():
        m = re.match(r"SEQUENCE\s+OF\s+([A-Z][\w-]*)", table_obj.syntax)
        if not m:
            continue
        entry_type = m.group(1)

        # Find the entry OBJECT-TYPE under this table.
        entries = [o for o in by_parent.get(table_name, [])
                   if normalize_whitespace(o.syntax) == entry_type]
        if not entries:
            continue
        entry_obj = entries[0]

        seq_cols = mib.sequence_types.get(entry_type)
        if not seq_cols:
            continue

        # Map each SEQUENCE column to its OBJECT-TYPE (to grab access /
        # the concrete suffix number).
        col_objs = {o.name: o for o in by_parent.get(entry_obj.name, [])}
        columns: dict[int, tuple[str, str, str]] = {}
        for col_name, col_type in seq_cols:
            obj = col_objs.get(col_name)
            if obj is None:
                continue
            columns[obj.num] = (col_name, obj.syntax, obj.access)

        table_oid = mib.absolute_oids.get(table_name, "")
        entry_oid = mib.absolute_oids.get(entry_obj.name, "")
        if not table_oid or not entry_oid:
            continue

        tables[table_name] = TableDef(
            name=table_name,
            oid=table_oid,
            entry_name=entry_obj.name,
            entry_oid=entry_oid,
            index_cols=entry_obj.index or [],
            columns=columns,
        )

    return tables


def extract_scalars(
    mib: ParsedMib, tables: dict[str, TableDef],
) -> dict[str, tuple[str, str, str]]:
    """Return scalar OBJECT-TYPE nodes — OID → (name, syntax, access).

    A **scalar** is any OBJECT-TYPE that isn't (a) a table root, (b) a
    table entry, or (c) a table column. Everything else — simple
    leaves under the module root — is a scalar.
    """
    table_names: set[str] = set(tables)
    entry_names = {t.entry_name for t in tables.values()}
    column_names: set[str] = set()
    for t in tables.values():
        for col_num, (col_name, _syntax, _access) in t.columns.items():
            column_names.add(col_name)

    scalars: dict[str, tuple[str, str, str]] = {}
    for name, obj in mib.object_types.items():
        if name in table_names or name in entry_names or name in column_names:
            continue
        oid = mib.absolute_oids.get(name)
        if oid is None:
            continue
        scalars[oid] = (name, obj.syntax, obj.access)
    return scalars


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------


_HEADER = '''"""Generated OID ↔ name ↔ SYNTAX tables for KEEPALIVED-MIB.

DO NOT EDIT BY HAND. Regenerate with::

    python3 tools/gen_keepalived_mib.py --emit \\
        packages/shorewalld/shorewalld/keepalived/mib.py

Upstream source: ``third_party/keepalived-mib/KEEPALIVED-MIB.txt``
(see ``third_party/keepalived-mib/PROVENANCE.md`` for the pinned
keepalived commit).

Consumed at runtime by ``shorewalld.keepalived.snmp_client`` (walker)
and ``shorewalld.keepalived.metrics`` (auto-registered Prometheus
families). Adding a new keepalived MIB column becomes a regen + diff
review rather than a code change in the walker.
"""

from __future__ import annotations

'''


def emit_module(
    module_name: str,
    module_root_oid: str,
    scalars: dict[str, tuple[str, str, str]],
    tables: dict[str, TableDef],
    notifications: dict[str, NotificationDef],
    absolute_oids: dict[str, str],
    textual_conventions: dict[str, str],
) -> str:
    """Render the generated mib.py content."""
    parts: list[str] = [_HEADER]

    parts.append(f"MODULE_NAME = {module_name!r}\n")
    parts.append(f"MODULE_ROOT_OID = {module_root_oid!r}\n\n")

    # Scalars: dict[oid_str, (name, syntax, access)].
    parts.append("# Scalar objects — OID → (name, syntax, max_access).\n")
    parts.append("SCALARS: dict[str, tuple[str, str, str]] = {\n")
    for oid in sorted(scalars, key=_oid_sort_key):
        name, syntax, access = scalars[oid]
        parts.append(f"    {oid!r}: ({name!r}, {syntax!r}, {access!r}),\n")
    parts.append("}\n\n")

    # Tables: dict[table_name, TableSpec].
    parts.append("# Tables — root OID → layout (entry + index + columns).\n")
    parts.append(
        "# Column entry: suffix_number → (name, syntax, max_access).\n")
    parts.append("TABLES: dict[str, dict] = {\n")
    for name in sorted(tables):
        t = tables[name]
        parts.append(f"    {name!r}: {{\n")
        parts.append(f"        'oid': {t.oid!r},\n")
        parts.append(f"        'entry_name': {t.entry_name!r},\n")
        parts.append(f"        'entry_oid': {t.entry_oid!r},\n")
        parts.append(f"        'index': {t.index_cols!r},\n")
        parts.append("        'columns': {\n")
        for col_num in sorted(t.columns):
            col_name, syntax, access = t.columns[col_num]
            parts.append(
                f"            {col_num}: ({col_name!r}, {syntax!r}, {access!r}),\n")
        parts.append("        },\n")
        parts.append("    },\n")
    parts.append("}\n\n")

    # Notifications.
    parts.append("# Traps (NOTIFICATION-TYPE) — OID → (name, [object_names]).\n")
    parts.append("NOTIFICATIONS: dict[str, tuple[str, list[str]]] = {\n")
    for name in sorted(notifications):
        n = notifications[name]
        oid = absolute_oids.get(name, "")
        parts.append(
            f"    {oid!r}: ({name!r}, {n.objects!r}),\n")
    parts.append("}\n\n")

    # Textual conventions (for enum decoding at runtime).
    parts.append("# TEXTUAL-CONVENTIONs — name → underlying SYNTAX.\n")
    parts.append("TEXTUAL_CONVENTIONS: dict[str, str] = {\n")
    for name in sorted(textual_conventions):
        parts.append(
            f"    {name!r}: {textual_conventions[name]!r},\n")
    parts.append("}\n")

    return "".join(parts)


def _oid_sort_key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.split(".") if p)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_DEFAULT_MIB_PATH = Path(__file__).resolve().parent.parent / \
    "third_party" / "keepalived-mib" / "KEEPALIVED-MIB.txt"


def build(mib_path: Path) -> str:
    text = mib_path.read_text(encoding="utf-8")
    mib = parse_mib(text)
    resolve_oids(mib)
    tables = synthesize_tables(mib)
    scalars = extract_scalars(mib, tables)
    return emit_module(
        module_name=mib.module_name,
        module_root_oid=mib.module_root_oid,
        scalars=scalars,
        tables=tables,
        notifications=mib.notifications,
        absolute_oids=mib.absolute_oids,
        textual_conventions=mib.textual_conventions,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate shorewalld/keepalived/mib.py from KEEPALIVED-MIB.txt")
    ap.add_argument(
        "--mib", type=Path, default=_DEFAULT_MIB_PATH,
        help=f"Path to the pinned MIB file (default: {_DEFAULT_MIB_PATH})")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--emit", type=Path, metavar="OUT",
        help="Write generated module to OUT.")
    group.add_argument(
        "--check", type=Path, metavar="EXISTING",
        help="Compare fresh generation against EXISTING; exit 1 on drift.")
    args = ap.parse_args(argv)

    content = build(args.mib)

    if args.emit:
        args.emit.parent.mkdir(parents=True, exist_ok=True)
        args.emit.write_text(content, encoding="utf-8")
        print(f"gen_keepalived_mib: wrote {args.emit} "
              f"({len(content.splitlines())} lines)")
        return 0

    existing = args.check.read_text(encoding="utf-8") \
        if args.check.exists() else ""
    if existing == content:
        return 0
    diff = difflib.unified_diff(
        existing.splitlines(keepends=True),
        content.splitlines(keepends=True),
        fromfile=str(args.check), tofile="<regenerated>",
        n=2,
    )
    sys.stderr.write(
        "gen_keepalived_mib: MIB drift detected — committed file is stale.\n"
        "Run: python3 tools/gen_keepalived_mib.py --emit "
        f"{args.check}\n\n",
    )
    sys.stderr.writelines(diff)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
