#!/usr/bin/env python3
"""simlab-rerun-failed — extract failed probe-ids from a simlab report
into a replay file consumable by ``smoketest full --replay``.

Used by the reference-replay loop: after iteration N the loop runs
this script against ``report.json`` to write ``failed-probes.json``,
then iteration N+1 invokes ``smoketest full --replay …`` so only the
previously-mismatched probes are re-executed.  Cuts a ~38k-probe run
to typically <5 % of that.

The output schema is intentionally tiny — just ``schema_version``,
``source`` (input path), ``categories_seen`` (count per bucket), and
``probe_ids`` (a sorted list of integers).  The simlab smoketest's
``--replay`` reads ``probe_ids`` and ignores the rest, so future fields
are non-breaking.

Usage:
    simlab-rerun-failed.py REPORT_JSON [--out OUT_JSON]
                           [--include-categories CAT,CAT,...]

By default, includes probes whose ``observed`` differs from
``expected`` (any of fail_drop / fail_accept / wrong_verdict /
errored / dnat_mismatch).  Pass ``--include-categories`` with a
comma-separated category-name list to narrow further.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


_DEFAULT_FAIL_BUCKETS = {
    "fail_drop", "fail_accept", "wrong_verdict", "errored", "dnat_mismatch",
}


def collect_failures(report_path: Path,
                     include_categories: set[str] | None = None
                     ) -> tuple[list[int], Counter]:
    """Return (sorted probe_ids, per-bucket counts) for failed probes."""
    blob = json.loads(report_path.read_text())
    probes = blob.get("probes")
    if probes is None:
        raise ValueError(f"{report_path}: missing 'probes' array — was the "
                         "report written with --summary-only on a run with "
                         "zero mismatches?")

    failed_ids: set[int] = set()
    seen: Counter = Counter()
    failure_buckets = {
        "fail_drop", "fail_accept", "wrong_verdict",
        "dnat_mismatch", "snat_mismatch", "errored",
    }

    for p in probes:
        category = p.get("category", "")
        bucket = p.get("bucket")
        if bucket is None:
            # Legacy report (pre-bucket field): fall back to the old
            # observed-vs-expected derivation.  This will overcount
            # wrong_verdict for probes whose oracle_definite=False but
            # the legacy schema doesn't carry that flag.
            expected = p.get("expected")
            observed = p.get("observed")
            if expected == "UNKNOWN":
                continue
            if not observed:
                bucket = "errored"
            elif observed == expected:
                continue
            elif observed == "ACCEPT" and expected in ("DROP", "REJECT"):
                bucket = "fail_accept"
            elif observed in ("DROP", "REJECT") and expected == "ACCEPT":
                bucket = "fail_drop"
            elif (observed in ("DROP", "REJECT")
                  and expected in ("DROP", "REJECT")):
                bucket = "wrong_verdict"
            else:
                bucket = "errored"

        if bucket not in failure_buckets:
            continue

        seen[bucket] += 1

        if include_categories is not None and category not in include_categories:
            continue
        pid = p.get("probe_id")
        if isinstance(pid, int):
            failed_ids.add(pid)

    return sorted(failed_ids), seen


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report_json", type=Path,
                    help="Path to simlab report.json")
    ap.add_argument("--out", type=Path, default=None,
                    help="Output path (default: <report dir>/failed-probes.json)")
    ap.add_argument("--include-categories", type=str, default=None,
                    metavar="CAT,CAT,...",
                    help="Restrict replay to probes from these probe "
                         "categories (e.g. RULE_POSITIVE,RANDOM).  "
                         "By default all categories are eligible.")
    args = ap.parse_args(argv)

    if not args.report_json.is_file():
        print(f"error: {args.report_json} not found", file=sys.stderr)
        return 2

    include_cats: set[str] | None = None
    if args.include_categories:
        include_cats = {c.strip() for c in args.include_categories.split(",")
                        if c.strip()}

    try:
        ids, seen = collect_failures(args.report_json, include_cats)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = args.out or args.report_json.parent / "failed-probes.json"
    payload = {
        "schema_version": 1,
        "source": str(args.report_json),
        "categories_seen": dict(seen),
        "probe_ids": ids,
    }
    out.write_text(json.dumps(payload, indent=2) + "\n")

    # Concise stderr summary so a CI/loop log shows the bucket counts
    # without consumers having to re-parse the file.
    print(f"wrote {out}", file=sys.stderr)
    print(f"  failed probes: {len(ids)}", file=sys.stderr)
    for bucket, count in sorted(seen.items()):
        print(f"  {bucket}: {count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
