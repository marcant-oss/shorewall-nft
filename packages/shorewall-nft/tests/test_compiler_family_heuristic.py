"""Tests for the rule-family heuristic in ``compiler/ir/rules.py``.

Bug history (2026-04-27): a rule whose dest spec referenced an upper-
case ``$SIP_V6``-style parameter ended up classified as IPv4 because
``_spec_family_tag`` only matched lowercase ``_v6`` and the
``is_ipv6_spec`` fall-back saw the un-expanded ``<$SIP_V6>`` token (no
``:``) → False.  Combined with the chain-complete short-circuit on a
shared zone-pair chain, that mis-classification silently dropped 24
real IPv6 rules from ``int-voice`` and surfaced as fail_drop in the
reference-replay simlab loop.

The fix has three pieces, all asserted here:

1. ``_spec_family_tag`` is case-insensitive (``$SIP_V6`` matches).
2. The fall-back ``is_ipv6_spec`` runs against a params-expanded
   spec, so ``voice:<$SIP_V6>`` resolves to its IPv6 address before
   detection.
3. After family detection, zone pairs whose ``src`` or ``dst`` zone
   is IPv4-only are skipped for IPv6 rules (and vice versa).  Without
   the gate, ``all`` expansion silently emits IPv6 rules into v4-only
   pairs that classic Shorewall never built.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config


def _write_config(root: Path, files: dict[str, str]) -> Path:
    cfg = root / "shorewall46"
    cfg.mkdir()
    for name, body in files.items():
        (cfg / name).write_text(textwrap.dedent(body).lstrip("\n"))
    return cfg


def _baseline_files(extra_rules: str = "") -> dict[str, str]:
    """Return a minimal config that exercises the family heuristic.

    Three zones — `int` (dual-stack), `voice` (dual-stack), `dmz`
    (ipv4-only) — and one upper-case IPv6 param.
    """
    return {
        "shorewall.conf": "",
        "params": "SIP_V6=2a00:f88:0:30c0::5\n",
        "zones": (
            "fw       firewall\n"
            "int      ip\n"
            "voice    ip\n"
            "dmz      ipv4\n"
        ),
        "interfaces": (
            "int      eth0\n"
            "voice    eth1\n"
            "dmz      eth2\n"
        ),
        "policy": (
            "all      all     REJECT\n"
        ),
        "rules": "?SECTION ALL\n?SECTION ESTABLISHED\n?SECTION RELATED\n?SECTION INVALID\n?SECTION UNTRACKED\n?SECTION NEW\n" + extra_rules,
    }


def test_uppercase_v6_param_classified_as_v6(tmp_path: Path) -> None:
    """A rule whose dest references ``<$SIP_V6>`` must land in the
    int-voice chain as a v6 rule (not get dropped by chain-complete
    short-circuit due to mis-classification)."""
    files = _baseline_files(
        # int → voice udp dport 30000:39999 sport 1024:65535 → ACCEPT
        "ACCEPT  int  voice:<$SIP_V6>  udp  30000:39999  1024:65535\n"
    )
    cfg = _write_config(tmp_path, files)
    ir = build_ir(load_config(cfg))

    # int-voice chain MUST contain a rule referencing the IPv6 dest.
    assert "int-voice" in ir.chains
    matched = False
    for r in ir.chains["int-voice"].rules:
        for m in getattr(r, "matches", []):
            if m.field == "ip6 daddr" and "2a00:f88:0:30c0::5" in m.value:
                matched = True
                break
    assert matched, (
        "ACCEPT rule for int → voice udp 30000-39999 was dropped — "
        "family heuristic did not classify <$SIP_V6> as IPv6"
    )


def test_v6_rule_skipped_for_ipv4_only_zone(tmp_path: Path) -> None:
    """An ``all → voice:<$SIP_V6>`` rule must NOT emit anything into
    the dmz-voice chain (dmz is ipv4-only)."""
    files = _baseline_files(
        "ACCEPT  all  voice:<$SIP_V6>  udp  30000:39999  1024:65535\n"
    )
    cfg = _write_config(tmp_path, files)
    ir = build_ir(load_config(cfg))

    # dmz-voice exists (policy fall-through), but the v6 rule must NOT
    # contribute an ip6 daddr match.  If we emitted it, the rule would
    # collide with the chain-complete logic and either no-op or — worse
    # — produce an unreachable v6 rule in a v4-only chain.
    if "dmz-voice" in ir.chains:
        for r in ir.chains["dmz-voice"].rules:
            for m in getattr(r, "matches", []):
                assert not (m.field == "ip6 daddr" and
                            "2a00:f88:0:30c0::5" in m.value), (
                    "v6 rule leaked into dmz-voice chain (dmz is ipv4-only)"
                )


def test_uppercase_v4_param_classified_as_v4(tmp_path: Path) -> None:
    """Upper-case ``$DNS_V4`` style param should be detected as v4."""
    files = _baseline_files()
    files["params"] = "DNS_V4=192.0.2.5\n"
    files["rules"] = (
        "?SECTION ALL\n?SECTION ESTABLISHED\n?SECTION RELATED\n"
        "?SECTION INVALID\n?SECTION UNTRACKED\n?SECTION NEW\n"
        "ACCEPT  int  voice:<$DNS_V4>  udp  53\n"
    )
    cfg = _write_config(tmp_path, files)
    ir = build_ir(load_config(cfg))

    # Must emit ip daddr (v4), not ip6 daddr.
    assert "int-voice" in ir.chains
    found_v4 = False
    for r in ir.chains["int-voice"].rules:
        for m in getattr(r, "matches", []):
            if m.field == "ip daddr" and "192.0.2.5" in m.value:
                found_v4 = True
            assert not (m.field == "ip6 daddr" and "192.0.2.5" in m.value), \
                "v4 address mis-classified as v6"
    assert found_v4, "v4 rule with $DNS_V4 was dropped"
