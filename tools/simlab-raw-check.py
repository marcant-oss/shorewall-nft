#!/usr/bin/env python3
"""simlab-raw-check — diff iptables.txt's auxiliary tables (raw,
mangle, security) against the shorewall-nft IR's equivalent chains.

Complementary to the simlab's dynamic NOTRACK validation
(``oracle.classify_notrack`` + ``notrack_mismatch`` bucket): static
checks catch compiler-emit gaps even on tuples that no probe ever
exercises.  Particularly load-bearing on BGP-transit configs where
the entire ``*raw`` block is NOTRACK rules to keep the conntrack
table from filling under transit load — a single dropped rule
could OOM the box in production but pass every functional probe.

Tables covered:

* ``raw``       — NOTRACK + CT-helper assignments
* ``mangle``    — MARK / CONNMARK / TPROXY / DUP / MSS clamp; targets
                  shorewall-nft compiles to the ``mangle-prerouting``
                  chain (and friends).  Unknown targets are bucketed
                  as ``other:<TARGET>`` so the diff still surfaces
                  cardinality mismatches.
* ``security``  — SECMARK assignment.  shorewall-nft emits SECMARK
                  via ``meta secmark set`` into the mangle pipeline,
                  not into its own ``security`` table — the diff
                  cross-walks IR mangle chains with target=secmark
                  against the snapshot's ``*security`` block.

Usage:
    simlab-raw-check.py --data DIR --config DIR
                        [--family 4|6|both]
                        [--table raw|mangle|security|all]

* ``--data DIR``    snapshot dir from ``simlab-collect.sh``
                    (must contain ``iptables.txt`` and, for
                    ``--family 6|both``, ``ip6tables.txt``)
* ``--config DIR``  merged shorewall-nft config dir to compile
* ``--family``      defaults to ``both``
* ``--table``       defaults to ``all``

Diff semantics:

* ``+`` rule present in the *snapshot* but missing from the
  compiled IR — likely compiler-emit gap, the bug we're hunting.
* ``-`` rule present in the *IR* but absent from the snapshot —
  shorewall-nft emitted a rule that classic Shorewall doesn't.
  Often safe (more aggressive default ≠ wrong) but worth a review.

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


_re = __import__("re")
_HELPER_RE = _re.compile(r"--helper\s+(\S+)")
_MARK_RE = _re.compile(r"--set-(?:x?mark|mark)\s+(\S+)")
_CONNMARK_RE = _re.compile(r"--set-(?:x?mark|mark)\s+(\S+)")
_TPROXY_PORT_RE = _re.compile(r"--on-port\s+(\d+)")
_TPROXY_IP_RE = _re.compile(r"--on-ip\s+(\S+)")
_DUP_DST_RE = _re.compile(r"--gateway\s+(\S+)|--to-destination\s+(\S+)")
_DUP_DEV_RE = _re.compile(r"--device\s+(\S+)|--to-dev\s+(\S+)")
_SECCTX_RE = _re.compile(r"--selctx\s+(\"[^\"]+\"|\S+)")
_MSS_RE = _re.compile(r"--set-mss\s+(\d+)|--clamp-mss-to-pmtu")


def _classify_raw_target(rule) -> str | None:
    """Return canonical target string for raw-table rules we diff:
    ``"notrack"`` for NOTRACK / CT --notrack; ``"helper:<name>"`` for
    CT --helper assignments; ``None`` to skip everything else (LOG,
    TRACE, MARK in raw, etc.).
    """
    target = (rule.target or "").upper()
    raw = rule.raw or ""
    if target == "NOTRACK":
        return "notrack"
    if target == "CT":
        if "--notrack" in raw:
            return "notrack"
        m = _HELPER_RE.search(raw)
        if m:
            return f"helper:{m.group(1).lower()}"
    return None


def parse_raw_from_dump(path: Path, family: int) -> set[CanonRule]:
    """Parse the ``*raw`` block of an iptables-save dump and return
    canonical keys for both NOTRACK and CT-helper assignments.

    ``-j CT --helper ftp`` lands in classic Shorewall as a raw-table
    rule that pre-binds the ftp helper to matching new flows.
    shorewall-nft compiles the same intent into the ``ct-helpers``
    chain at priority -200; the diff catches gaps in either direction.
    """
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    tables = parse_iptables_save(path)
    raw = tables.get("raw")
    if raw is None:
        return set()

    out: set[CanonRule] = set()
    for chain_name in ("PREROUTING", "OUTPUT"):
        for rule in raw.rules.get(chain_name, []):
            target = _classify_raw_target(rule)
            if target is None:
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
                target=target,
            ))
    return out


# ── parsing *mangle / *security from the snapshot ─────────────────


def _classify_mangle_target(rule) -> str | None:
    """Canonical target string for mangle-table rules.

    Bucketed by class so a snapshot's ``-j MARK --set-xmark 0x10`` and
    the IR's ``meta mark set 0x10`` collapse to the same key.  Unknown
    targets land as ``other:<NAME>``.
    """
    target = (rule.target or "").upper()
    raw = rule.raw or ""
    if target == "MARK":
        m = _MARK_RE.search(raw)
        return f"mark:{m.group(1)}" if m else "mark"
    if target == "CONNMARK":
        m = _CONNMARK_RE.search(raw)
        return f"connmark:{m.group(1)}" if m else "connmark"
    if target == "TPROXY":
        port = _TPROXY_PORT_RE.search(raw)
        ip = _TPROXY_IP_RE.search(raw)
        bits = []
        if ip:
            bits.append(ip.group(1))
        if port:
            bits.append(port.group(1))
        return "tproxy:" + ":".join(bits) if bits else "tproxy"
    if target == "DUP":
        dst_m = _DUP_DST_RE.search(raw)
        dst = (dst_m.group(1) or dst_m.group(2)) if dst_m else ""
        dev_m = _DUP_DEV_RE.search(raw)
        dev = (dev_m.group(1) or dev_m.group(2)) if dev_m else ""
        return f"dup:{dst}{':' + dev if dev else ''}"
    if target == "TCPMSS":
        return "mss:clamp" if "--clamp-mss-to-pmtu" in raw else "mss"
    if target in ("RETURN", "ACCEPT"):
        return None  # boilerplate
    if target == "":
        return None  # bare jump-only line that classic shorewall uses for chain dispatch
    # Jumps to user-defined chains (e.g. ``-j tcpre``, ``-j tcfor``)
    # are functional anchors but their content is what matters; bucket
    # them as ``jump:<chain>`` so the diff at least counts them.
    return f"jump:{target.lower()}"


def parse_mangle_from_dump(path: Path, family: int) -> set[CanonRule]:
    """Walk every chain in the ``*mangle`` block and collect canonical
    keys for every recognised target.  All five base chains are
    covered (PREROUTING / INPUT / FORWARD / OUTPUT / POSTROUTING).
    """
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    tables = parse_iptables_save(path)
    mangle = tables.get("mangle")
    if mangle is None:
        return set()

    out: set[CanonRule] = set()
    for chain_name in ("PREROUTING", "INPUT", "FORWARD", "OUTPUT",
                       "POSTROUTING"):
        for rule in mangle.rules.get(chain_name, []):
            target = _classify_mangle_target(rule)
            if target is None:
                continue
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
                target=target,
            ))
    return out


def parse_security_from_dump(path: Path, family: int) -> set[CanonRule]:
    """Walk ``*security`` for SECMARK rules.

    Classic Shorewall emits SECMARK to the security table; shorewall-nft
    folds the same intent into mangle-prerouting via ``meta secmark
    set``.  The diff here surfaces snapshot rules; the IR side
    (``parse_security_from_ir``) returns the SecmarkVerdict rules
    from mangle so a label-by-label diff is possible across the
    table-name change.
    """
    from shorewall_nft.verify.iptables_parser import parse_iptables_save

    tables = parse_iptables_save(path)
    sec = tables.get("security")
    if sec is None:
        return set()

    out: set[CanonRule] = set()
    for chain_name in ("INPUT", "OUTPUT", "FORWARD"):
        for rule in sec.rules.get(chain_name, []):
            target = (rule.target or "").upper()
            if target != "SECMARK":
                continue
            ctx_m = _SECCTX_RE.search(rule.raw or "")
            label = ctx_m.group(1).strip('"') if ctx_m else ""
            out.add(CanonRule(
                family=family,
                chain=chain_name,
                iif=(rule.iif or "").strip(),
                oif=(rule.oif or "").strip(),
                saddr=_canon_addr(rule.saddr or ""),
                daddr=_canon_addr(rule.daddr or ""),
                proto=(rule.proto or "").lower(),
                dport=(rule.dport or "").strip(),
                target=f"secmark:{label}",
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
    """Walk the IR's raw-table-equivalent chains and return canonical
    keys for both NOTRACK rules (``raw-prerouting`` / ``raw-output``,
    priority -300, ``NotrackVerdict``) and CT-helper assignments
    (``ct-helpers``, priority -200, ``CtHelperVerdict``).

    Comma-separated address values are fanned out into individual
    keys: an IR rule ``ip daddr { A, B, C }`` (anonymous nft set)
    is functionally identical to three iptables rules ``-d A``,
    ``-d B``, ``-d C`` — the static check needs the same shape on
    both sides for set-equality to work.
    """
    from shorewall_nft.compiler.verdicts import (
        CtHelperVerdict,
        NotrackVerdict,
    )

    def _split_cidrs(value: str) -> list[str]:
        if not value:
            return [""]
        return [tok.strip() for tok in value.split(",") if tok.strip()]

    out: set[CanonRule] = set()
    chain_map = {
        "raw-prerouting": "PREROUTING",
        "raw-output": "OUTPUT",
        # ct-helpers (priority -200) attaches at PREROUTING;
        # ct-helpers-output mirrors it for the OUTPUT hook so
        # ``CT:helper:<name>:PO`` (the classic-Shorewall default
        # policy) lands a rule on both sides.
        "ct-helpers": "PREROUTING",
        "ct-helpers-output": "OUTPUT",
    }
    for ir_name, ipt_name in chain_map.items():
        chain = ir.chains.get(ir_name)
        if chain is None:
            continue
        for rule in chain.rules:
            target_label: str | None = None
            if isinstance(rule.verdict_args, NotrackVerdict):
                target_label = "notrack"
            elif isinstance(rule.verdict_args, CtHelperVerdict):
                target_label = f"helper:{rule.verdict_args.name.lower()}"
            if target_label is None:
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
                        target=target_label,
                    ))
    return out


def _ir_mangle_target(rule) -> str | None:
    """Map an IR mangle rule's verdict to a canonical target string
    matching ``_classify_mangle_target`` on the snapshot side."""
    from shorewall_nft.compiler.verdicts import (
        ConnmarkVerdict,
        DupVerdict,
        MarkVerdict,
        SecmarkVerdict,
        TproxyVerdict,
    )
    va = rule.verdict_args
    if isinstance(va, MarkVerdict):
        # MarkVerdict carries the value as ``mark`` or ``value`` depending
        # on the field naming; getattr-fallback covers both.
        v = getattr(va, "mark", None) or getattr(va, "value", "")
        return f"mark:{v}"
    if isinstance(va, ConnmarkVerdict):
        v = getattr(va, "mark", None) or getattr(va, "value", "")
        return f"connmark:{v}"
    if isinstance(va, TproxyVerdict):
        port = getattr(va, "port", "")
        ip = getattr(va, "ip", "") or ""
        return "tproxy:" + ":".join([s for s in (ip, str(port) if port else "") if s])
    if isinstance(va, DupVerdict):
        target = getattr(va, "target", "")
        device = getattr(va, "device", "") or ""
        return f"dup:{target}{':' + device if device else ''}"
    if isinstance(va, SecmarkVerdict):
        return f"secmark:{getattr(va, 'label', '') or getattr(va, 'name', '')}"
    return None


def parse_mangle_from_ir(ir, family: int) -> set[CanonRule]:
    """Walk the IR's mangle-* chains and collect canonical keys.

    shorewall-nft today centralises mangle emission in
    ``mangle-prerouting`` (priority -150).  Future compiler revisions
    that split into ``mangle-{forward,output,postrouting}`` will be
    picked up automatically by the chain-name scan.
    """
    chain_to_iptables = {
        "mangle-prerouting": "PREROUTING",
        "mangle-input": "INPUT",
        "mangle-forward": "FORWARD",
        "mangle-output": "OUTPUT",
        "mangle-postrouting": "POSTROUTING",
    }
    out: set[CanonRule] = set()
    for ir_name, ipt_name in chain_to_iptables.items():
        chain = ir.chains.get(ir_name)
        if chain is None:
            continue
        for rule in chain.rules:
            target = _ir_mangle_target(rule)
            if target is None:
                continue
            saddr_field = "ip saddr" if family == 4 else "ip6 saddr"
            daddr_field = "ip daddr" if family == 4 else "ip6 daddr"
            other_saddr = "ip6 saddr" if family == 4 else "ip saddr"
            other_daddr = "ip6 daddr" if family == 4 else "ip daddr"
            if any(m.field == other_saddr or m.field == other_daddr
                   for m in rule.matches):
                continue
            out.add(CanonRule(
                family=family,
                chain=ipt_name,
                iif=_ir_match_value(rule, "iifname"),
                oif=_ir_match_value(rule, "oifname"),
                saddr=_canon_addr(_ir_match_value(rule, saddr_field)),
                daddr=_canon_addr(_ir_match_value(rule, daddr_field)),
                proto=_ir_match_value(rule, "meta l4proto").lower(),
                dport=(_ir_match_value(rule, "tcp dport")
                       or _ir_match_value(rule, "udp dport")
                       or _ir_match_value(rule, "dccp dport")),
                target=target,
            ))
    return out


def parse_security_from_ir(ir, family: int) -> set[CanonRule]:
    """SECMARK rules in the IR live in mangle-prerouting (the
    compiler folds the security table into the mangle pipeline)."""
    out: set[CanonRule] = set()
    chain = ir.chains.get("mangle-prerouting")
    if chain is None:
        return out
    from shorewall_nft.compiler.verdicts import SecmarkVerdict
    for rule in chain.rules:
        if not isinstance(rule.verdict_args, SecmarkVerdict):
            continue
        saddr_field = "ip saddr" if family == 4 else "ip6 saddr"
        daddr_field = "ip daddr" if family == 4 else "ip6 daddr"
        label = (getattr(rule.verdict_args, "label", "")
                 or getattr(rule.verdict_args, "name", ""))
        out.add(CanonRule(
            family=family,
            chain="INPUT",   # SECMARK on inbound is the common case
            iif=_ir_match_value(rule, "iifname"),
            oif=_ir_match_value(rule, "oifname"),
            saddr=_canon_addr(_ir_match_value(rule, saddr_field)),
            daddr=_canon_addr(_ir_match_value(rule, daddr_field)),
            proto=_ir_match_value(rule, "meta l4proto").lower(),
            dport=(_ir_match_value(rule, "tcp dport")
                   or _ir_match_value(rule, "udp dport")
                   or _ir_match_value(rule, "dccp dport")),
            target=f"secmark:{label}",
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
    ap.add_argument("--table", choices=("raw", "mangle", "security", "all"),
                    default="all",
                    help="Which iptables table(s) to diff (default: all)")
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

        # Each table contributes (label, snapshot_set, ir_set).
        runs: list[tuple[str, set[CanonRule], set[CanonRule]]] = []
        if args.table in ("raw", "all"):
            runs.append(("raw NOTRACK + helpers",
                         parse_raw_from_dump(dump_path, fam),
                         parse_raw_from_ir(ir, fam)))
        if args.table in ("mangle", "all"):
            runs.append(("mangle",
                         parse_mangle_from_dump(dump_path, fam),
                         parse_mangle_from_ir(ir, fam)))
        if args.table in ("security", "all"):
            runs.append(("security (SECMARK)",
                         parse_security_from_dump(dump_path, fam),
                         parse_security_from_ir(ir, fam)))

        for label, snap, ir_set in runs:
            only_snap = snap - ir_set
            only_ir = ir_set - snap
            common = snap & ir_set
            print(f"=== v{fam} *{label} ===")
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
