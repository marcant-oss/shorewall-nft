#!/usr/bin/env python3
"""Summarise a simlab full-mode report.json into a 5-line verdict table.

Usage:
    simlab-verdict-counts.py <report-dir-or-report.json> [...]

Each argument is either a path to a simlab report directory (containing
report.json) or directly to the JSON file. Output one block per report
giving the category × classification breakdown plus a list of the
mismatch desc-strings (truncated). Designed to be cheap to read in a
chat: the full log is hundreds of KB, this fits in ~30 lines.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def _resolve(arg: str) -> Path:
    p = Path(arg)
    if p.is_dir():
        p = p / "report.json"
    return p


def _summarise(path: Path) -> None:
    if not path.is_file():
        print(f"=== {path}: NOT FOUND ===")
        return
    data = json.loads(path.read_text())
    probes = data.get("probes", [])
    if not probes:
        print(f"=== {path}: 0 probes ===")
        return
    by_class = Counter(
        (p.get("category"), p.get("expected"), p.get("observed"))
        for p in probes
    )
    print(f"=== {path} — {len(probes)} probes ===")
    # Sort by category then count desc
    rows = sorted(
        by_class.items(),
        key=lambda kv: (kv[0][0] or "", -kv[1])
    )
    for (cat, exp, obs), n in rows:
        marker = ""
        if exp == "ACCEPT" and obs == "DROP":
            marker = "  <-- fail_drop"
        elif exp == "ACCEPT" and obs == "REJECT":
            marker = "  <-- expected accept, got reject"
        elif exp == "DROP" and obs == "ACCEPT":
            marker = "  <-- FAIL_ACCEPT (security regression)"
        print(f"  {cat:9} expected={exp!s:8} observed={obs!s:18} n={n}{marker}")
    # List up to 5 fail_accept desc strings if any
    fa = [
        p for p in probes
        if p.get("expected") == "DROP" and p.get("observed") == "ACCEPT"
    ]
    if fa:
        print(f"  --- fail_accept samples (n={len(fa)}) ---")
        for p in fa[:5]:
            print(f"    {p.get('desc', '')[:100]}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    for arg in sys.argv[1:]:
        _summarise(_resolve(arg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
