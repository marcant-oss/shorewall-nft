#!/usr/bin/env python3
"""simlab-raw-check — diff iptables.txt's *raw block against the
shorewall-nft IR's raw-prerouting / raw-output chains.

Complementary to the simlab's dynamic NOTRACK validation
(``oracle.classify_notrack`` + ``notrack_mismatch`` bucket): static
checks catch compiler-emit gaps even on tuples that no probe ever
exercises.  Particularly load-bearing on BGP-transit configs where
the entire ``*raw`` block is NOTRACK rules to keep the conntrack
table from filling under transit load — a single dropped rule
could OOM the box in production but pass every functional probe.

Usage:
    simlab-raw-check.py --data DIR --config DIR [--family 4|6|both]

* ``--data DIR``    snapshot dir from ``simlab-collect.sh``
                    (must contain ``iptables.txt`` and, for
                    ``--family 6|both``, ``ip6tables.txt``)
* ``--config DIR``  merged shorewall-nft config dir to compile
* ``--family``      defaults to ``both``

Diff semantics:

* ``+`` rule present in the *snapshot* but missing from the
  compiled IR — likely compiler-emit gap, the bug we're hunting.
* ``-`` rule present in the *IR* but absent from the snapshot —
  shorewall-nft emitted a NOTRACK / helper rule that classic
  Shorewall doesn't.  Often safe (more aggressive notrack ≠ wrong)
  but worth a review.

Exit codes: 0 = symmetric / no diff, 1 = diffs present, 2 = setup
error (missing input).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


# ── canonical rule shape ────────────────────────────────────────────


@dataclass(frozen=True)
class CanonRule:
    """Canonical raw-table rule key.

    All fields are lowercased / stripped so that semantically
    equivalent rules from iptables.txt and the IR collapse to the
    same key.  ``target`` is one of ``notrack`` / ``helper`` /
    ``other``; only ``notrack`` rules participate in the diff today
    (helpers vary by snapshot age and are out of scope).
    """
    family: int          # 4 or 6
    chain: str           # "PREROUTING" or "OUTPUT"
    iif: str             # "" if unrestricted
    oif: str             # "" if unrestricted
    saddr: str           # "" if unrestricted; CIDR canonicalised
    daddr: str
    proto: str           # "" / "tcp" / "udp" / ...
    dport: str
    target: str          # "notrack" / "helper:<name>" / "other"


def _canon_addr(spec: str) -> str:
    """Lowercase + strip the spec; collapse host/no-prefix forms.

    Returns ``""`` for empty / wildcard.  ``!``-negation is preserved
    in the prefix so ``! -d 10.0.0.0/8`` and a plain ``-d 10.0.0.0/8``
    don't compare equal.  ``/32`` and ``/128`` host forms are stripped
    so ``10.0.0.1`` == ``10.0.0.1/32``.
    """
    s = (spec or "").strip().lower()
    if not s or s in ("0.0.0.0/0", "::/0", "any"):
        return ""
    negate = ""
    if s.startswith("!"):
        negate = "!"
        s = s[1:].lstrip()
    if s.endswith("/32"):
        s = s[:-3]
    elif s.endswith("/128"):
        s = s[:-4]
    return f"{negate}{s}"


# ── parsing iptables.txt ────────────────────────────────────────────


def parse_raw_from_dump(path: Path, family: int) -> set[CanonRule]:
    """Parse the ``*raw`` block of an iptables-save dump and return
    a set of ``CanonRule`` keys for NOTRACK rules only.
    """
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    tables = parse_iptables_save(path)
    raw = tables.get("raw")
    if raw is None:
        return set()

    out: set[CanonRule] = set()
    for chain_name in ("PREROUTING", "OUTPUT"):
        for rule in raw.rules.get(chain_name, []):
            target = (rule.target or "").upper()
            is_notrack = (
                target == "NOTRACK"
                or (target == "CT" and "--notrack" in (rule.raw or ""))
            )
            if not is_notrack:
                continue
            # iptables_parser strips the leading ``!`` from saddr /
            # daddr — but keeps the verbatim line in ``rule.raw``,
            # which is the only place the negation survives.  Detect
            # ``! -s <addr>`` / ``! -d <addr>`` against the parsed
            # value to re-attach the negation marker.
            saddr_v = rule.saddr or ""
            daddr_v = rule.daddr or ""
            rule_raw = rule.raw or ""
            if saddr_v and f"! -s {saddr_v}" in rule_raw:
                saddr_v = "!" + saddr_v
            if daddr_v and f"! -d {daddr_v}" in rule_raw:
                daddr_v = "!" + daddr_v
            out.add(CanonRule(
                family=family,
                chain=chain_name,
                iif=(rule.iif or "").strip(),
                oif=(rule.oif or "").strip(),
                saddr=_canon_addr(saddr_v),
                daddr=_canon_addr(daddr_v),
                proto=(rule.proto or "").lower(),
                dport=(rule.dport or "").strip(),
                target="notrack",
            ))
    return out


# ── parsing the IR ─────────────────────────────────────────────────


def _ir_match_value(rule, field: str) -> str:
    """Pull the first match.value where ``match.field == field``;
    apply the same canonicalisation as the iptables side."""
    for m in rule.matches:
        if m.field == field:
            value = m.value or ""
            if m.negate:
                value = f"!{value}"
            return value
    return ""


def parse_raw_from_ir(ir, family: int) -> set[CanonRule]:
    """Walk the IR's ``raw-prerouting`` + ``raw-output`` chains and
    return canonical NOTRACK rule keys.

    The compiler tags the verdict with ``NotrackVerdict()`` — that's
    how we distinguish notrack from helper assignment without
    re-parsing the emit text.

    Comma-separated address values are fanned out into individual
    keys: an IR rule ``ip daddr { A, B, C }`` (anonymous nft set)
    is functionally identical to three iptables rules ``-d A``,
    ``-d B``, ``-d C`` — the static check needs the same shape on
    both sides for set-equality to work.
    """
    from shorewall_nft.compiler.verdicts import NotrackVerdict

    def _split_cidrs(value: str) -> list[str]:
        if not value:
            return [""]
        return [tok.strip() for tok in value.split(",") if tok.strip()]

    out: set[CanonRule] = set()
    chain_map = {
        "raw-prerouting": "PREROUTING",
        "raw-output": "OUTPUT",
    }
    for ir_name, ipt_name in chain_map.items():
        chain = ir.chains.get(ir_name)
        if chain is None:
            continue
        for rule in chain.rules:
            if not isinstance(rule.verdict_args, NotrackVerdict):
                continue
            # Family disambiguation: the IR is dual-stack (inet
            # family) so each rule may carry a v4 OR v6 saddr/daddr
            # match.  Skip the rule for the wrong family.
            saddr_field = "ip saddr" if family == 4 else "ip6 saddr"
            daddr_field = "ip daddr" if family == 4 else "ip6 daddr"
            other_saddr = "ip6 saddr" if family == 4 else "ip saddr"
            other_daddr = "ip6 daddr" if family == 4 else "ip daddr"
            if any(m.field == other_saddr or m.field == other_daddr
                   for m in rule.matches):
                continue
            # Generic ``ip saddr/daddr`` (no family qualifier) —
            # appears when the row was emitted from the modern
            # ``conntrack`` file processor.  The value itself
            # carries the family marker (dotted-quad vs colon).
            saddr_raw = (_ir_match_value(rule, saddr_field)
                         or _ir_match_value(rule, "ip saddr"))
            daddr_raw = (_ir_match_value(rule, daddr_field)
                         or _ir_match_value(rule, "ip daddr"))
            for s in _split_cidrs(saddr_raw):
                for d in _split_cidrs(daddr_raw):
                    out.add(CanonRule(
                        family=family,
                        chain=ipt_name,
                        iif=_ir_match_value(rule, "iifname"),
                        oif=_ir_match_value(rule, "oifname"),
                        saddr=_canon_addr(s),
                        daddr=_canon_addr(d),
                        proto=_ir_match_value(rule, "meta l4proto").lower(),
                        dport=(_ir_match_value(rule, "tcp dport")
                               or _ir_match_value(rule, "udp dport")
                               or _ir_match_value(rule, "dccp dport")),
                        target="notrack",
                    ))
    return out


# ── driver ─────────────────────────────────────────────────────────


def _format_rule(r: CanonRule) -> str:
    parts = [f"v{r.family}", r.chain]
    if r.iif:
        parts.append(f"iif={r.iif}")
    if r.oif:
        parts.append(f"oif={r.oif}")
    if r.saddr:
        parts.append(f"saddr={r.saddr}")
    if r.daddr:
        parts.append(f"daddr={r.daddr}")
    if r.proto:
        parts.append(f"proto={r.proto}")
    if r.dport:
        parts.append(f"dport={r.dport}")
    parts.append(f"-> {r.target}")
    return "  " + " ".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, required=True,
                    help="Snapshot dir (contains iptables.txt / ip6tables.txt)")
    ap.add_argument("--config", type=Path, required=True,
                    help="Merged shorewall-nft config dir to compile")
    ap.add_argument("--family", choices=("4", "6", "both"), default="both")
    args = ap.parse_args(argv)

    if not args.data.is_dir():
        print(f"error: --data {args.data} not a directory", file=sys.stderr)
        return 2
    if not args.config.is_dir():
        print(f"error: --config {args.config} not a directory", file=sys.stderr)
        return 2

    families: list[int] = []
    if args.family in ("4", "both"):
        families.append(4)
    if args.family in ("6", "both"):
        families.append(6)

    # Load the IR once — both families share the same compile.
    from shorewall_nft.compiler.ir import build_ir
    from shorewall_nft.config.parser import load_config
    cfg = load_config(args.config)
    ir = build_ir(cfg)

    total_diffs = 0
    for fam in families:
        dump_name = "iptables.txt" if fam == 4 else "ip6tables.txt"
        dump_path = args.data / dump_name
        if not dump_path.is_file():
            print(f"v{fam}: no {dump_name} in --data — skipped",
                  file=sys.stderr)
            continue
        snap = parse_raw_from_dump(dump_path, fam)
        ir_set = parse_raw_from_ir(ir, fam)
        only_snap = snap - ir_set
        only_ir = ir_set - snap
        common = snap & ir_set

        print(f"=== v{fam} *raw NOTRACK ===")
        print(f"  snapshot rules: {len(snap)}")
        print(f"  IR rules:       {len(ir_set)}")
        print(f"  in both:        {len(common)}")
        print(f"  only snapshot:  {len(only_snap)}  "
              "(compiler-emit gap candidate)")
        print(f"  only IR:        {len(only_ir)}  "
              "(extra emit, may be safe)")
        if only_snap:
            print("--- + missing from IR ---")
            for r in sorted(only_snap, key=_format_rule):
                print(_format_rule(r))
        if only_ir:
            print("--- - extra in IR ---")
            for r in sorted(only_ir, key=_format_rule):
                print(_format_rule(r))
        total_diffs += len(only_snap) + len(only_ir)

    return 0 if total_diffs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
