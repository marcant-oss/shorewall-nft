#!/usr/bin/env python3
"""simlab-report-diff — compare two simlab report.json files.

Drives the reference-replay loop's stop logic: prints (1) bucket
counts before/after, (2) probes that newly failed (regression), and
(3) probes that newly passed.  Exit 0 means *no new regressions*
(zero new failures); exit 1 means at least one probe failed in B
that didn't fail in A.  Loop scripts read this exit code.

Output is intentionally compact (≈30 lines) so it fits cleanly into
the loop's chat context.

Usage:
    simlab-report-diff.py REPORT_A.json REPORT_B.json [--max-rows N]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load(report_path: Path) -> dict:
    return json.loads(report_path.read_text())


def _is_failure(probe: dict) -> bool:
    expected = probe.get("expected")
    observed = probe.get("observed")
    if expected == "UNKNOWN":
        return False
    if not observed:
        return True
    return observed != expected


def _index(report: dict) -> dict[int, dict]:
    return {
        p["probe_id"]: p
        for p in report.get("probes", [])
        if isinstance(p.get("probe_id"), int)
    }


def _bucket_counts(report: dict) -> dict[str, int]:
    cats = report.get("categories", {})
    out: dict[str, int] = {
        k: 0 for k in (
            "pass_accept", "pass_drop",
            "fail_drop", "fail_accept", "wrong_verdict",
            "rate_limited", "errored", "dnat_mismatch",
            "variant_artifact",
        )
    }
    for stats in cats.values():
        for k in out:
            out[k] += int(stats.get(k, 0))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", type=Path, metavar="REPORT_A",
                    help="Baseline report.json (older / 'before')")
    ap.add_argument("b", type=Path, metavar="REPORT_B",
                    help="Comparison report.json (newer / 'after')")
    ap.add_argument("--max-rows", type=int, default=20,
                    help="Cap regressions / new-passes shown to N rows each")
    args = ap.parse_args(argv)

    for p in (args.a, args.b):
        if not p.is_file():
            print(f"error: {p} not found", file=sys.stderr)
            return 2

    a = _load(args.a)
    b = _load(args.b)

    a_idx = _index(a)
    b_idx = _index(b)

    # Bucket deltas
    ca = _bucket_counts(a)
    cb = _bucket_counts(b)

    print(f"A: {args.a}")
    print(f"B: {args.b}")
    print()
    print(f"{'bucket':<16} {'A':>8} {'B':>8} {'Δ':>8}")
    print("-" * 44)
    for k in ("pass_accept", "pass_drop", "fail_drop", "fail_accept",
              "wrong_verdict", "dnat_mismatch", "rate_limited",
              "variant_artifact", "errored"):
        delta = cb[k] - ca[k]
        marker = " "
        if delta > 0 and k in ("fail_drop", "fail_accept",
                               "wrong_verdict", "dnat_mismatch"):
            marker = "▲"   # regression in a failure bucket
        elif delta < 0 and k in ("fail_drop", "fail_accept",
                                 "wrong_verdict", "dnat_mismatch"):
            marker = "▼"   # improvement in a failure bucket
        print(f"{k:<16} {ca[k]:>8} {cb[k]:>8} {delta:>+8} {marker}")

    # Per-probe diff: regressions (failed in B but not A) and recoveries
    common = set(a_idx) & set(b_idx)
    regressions: list[tuple[int, dict, dict]] = []
    recoveries: list[tuple[int, dict, dict]] = []
    for pid in common:
        a_fail = _is_failure(a_idx[pid])
        b_fail = _is_failure(b_idx[pid])
        if b_fail and not a_fail:
            regressions.append((pid, a_idx[pid], b_idx[pid]))
        elif a_fail and not b_fail:
            recoveries.append((pid, a_idx[pid], b_idx[pid]))

    # Probes only in B that failed = also a regression (e.g. new probe surface)
    only_b_fail = [
        (pid, b_idx[pid])
        for pid in (set(b_idx) - set(a_idx))
        if _is_failure(b_idx[pid])
    ]

    def _row(pid: int, a_p: dict | None, b_p: dict | None) -> str:
        b_p = b_p or {}
        ai = "-" if a_p is None else f"{a_p.get('expected', '-')}/{a_p.get('observed', '-')}"
        bi = f"{b_p.get('expected', '-')}/{b_p.get('observed', '-')}"
        return (f"  {pid:>6}  A:{ai:<14} B:{bi:<14}  "
                f"{b_p.get('desc', '')[:60]}")

    print()
    if regressions or only_b_fail:
        print(f"REGRESSIONS ({len(regressions) + len(only_b_fail)} total):")
        for pid, a_p, b_p in regressions[:args.max_rows]:
            print(_row(pid, a_p, b_p))
        for pid, b_p in only_b_fail[:max(0,
                args.max_rows - len(regressions))]:
            print(_row(pid, None, b_p))
        extra = (len(regressions) + len(only_b_fail)) - args.max_rows
        if extra > 0:
            print(f"  … {extra} more regression(s) suppressed")
    else:
        print("REGRESSIONS: none")

    print()
    if recoveries:
        print(f"NEW PASSES ({len(recoveries)} total):")
        for pid, a_p, b_p in recoveries[:args.max_rows]:
            print(_row(pid, a_p, b_p))
        if len(recoveries) > args.max_rows:
            print(f"  … {len(recoveries) - args.max_rows} more "
                  "new-pass(es) suppressed")
    else:
        print("NEW PASSES: none")

    # Exit 0 = no regressions (loop may declare progress); 1 otherwise.
    return 0 if not (regressions or only_b_fail) else 1


if __name__ == "__main__":
    sys.exit(main())
