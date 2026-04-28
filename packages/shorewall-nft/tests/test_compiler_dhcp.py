"""Tests for ``_process_dhcp_interfaces`` (compiler/ir/_build.py).

Bug history (2026-04-27): the auto-DHCP-emit fanned out into every
zone-pair chain involving a dhcp-enabled zone, even when neither
endpoint carried the ``bridge`` flag.  Classic Shorewall (Misc.pm:
1136-1166) emits the DHCP rule only on ``<zone>-fw`` / ``fw-<zone>``
+ ``<zone>-<zone>`` and on the cross-zone pair ONLY when the
interface has ``bridge``.  The reference fixture replay caught the
divergence as 6 fail_accepts (DHCP UDP 67/68 between zones whose
chain in iptables.txt fell through to REJECT).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config


def _write(root: Path, files: dict[str, str]) -> Path:
    cfg = root / "shorewall"
    cfg.mkdir()
    for name, body in files.items():
        (cfg / name).write_text(textwrap.dedent(body).lstrip("\n"))
    return cfg


def _has_dhcp_rule(ir, chain_name: str) -> bool:
    """True if `chain_name` (or its merge-target) carries a DHCP allow rule.

    The optimizer can collapse identical zone-pair chains into a single
    one and replace the duplicate with a one-rule jump (`merged:
    identical to <name>`).  Follow the jump so tests don't have to
    chase the canonical chain manually.
    """
    seen = set()
    while chain_name and chain_name not in seen:
        seen.add(chain_name)
        chain = ir.chains.get(chain_name)
        if chain is None:
            return False
        for r in chain.rules:
            for m in r.matches:
                if "dport" not in m.field:
                    continue
                v = m.value.replace(" ", "").strip("{}")
                if any(p in v for p in ("67,68", "67", "68",
                                        "546,547", "546", "547")):
                    return True
        # Single-rule jump = merge stub; chase it.
        if len(chain.rules) == 1 and chain.rules[0].verdict_args:
            chain_name = chain.rules[0].verdict_args
            continue
        return False
    return False


def _baseline_files(extra_iface_opts_a: str = "dhcp",
                    extra_iface_opts_b: str = "dhcp") -> dict[str, str]:
    return {
        "shorewall.conf": "",
        "params": "",
        "zones": (
            "fw       firewall\n"
            "zoneA    ipv4\n"
            "zoneB    ipv4\n"
        ),
        "interfaces": (
            f"zoneA    eth0    -    {extra_iface_opts_a}\n"
            f"zoneB    eth1    -    {extra_iface_opts_b}\n"
        ),
        "policy": "all  all  REJECT\n",
        "rules": "?SECTION ALL\n?SECTION ESTABLISHED\n?SECTION RELATED\n"
                 "?SECTION INVALID\n?SECTION UNTRACKED\n?SECTION NEW\n",
    }


def test_dhcp_emitted_in_zone_fw_pair(tmp_path: Path) -> None:
    """``zoneA-fw`` and ``fw-zoneA`` always get DHCP-ACCEPT for
    dhcp-enabled ifaces (host as client/server)."""
    cfg = _write(tmp_path, _baseline_files())
    ir = build_ir(load_config(cfg))
    assert _has_dhcp_rule(ir, "zoneA-fw")
    assert _has_dhcp_rule(ir, "fw-zoneA")


def test_dhcp_NOT_emitted_in_cross_zone_without_bridge(tmp_path: Path) -> None:
    """Without ``bridge`` on either iface, ``zoneA-zoneB`` must NOT
    carry an auto-DHCP-ACCEPT.  This is the actual reference fixture bug —
    over-emitting here ACCEPTed UDP 67/68 between e.g. cust→tpoff
    when classic Shorewall correctly REJECTs."""
    cfg = _write(tmp_path, _baseline_files())
    ir = build_ir(load_config(cfg))
    # zoneA-zoneB chain may or may not exist (policy fall-through),
    # but if it does it must not carry the auto-DHCP rule.
    if "zoneA-zoneB" in ir.chains:
        assert not _has_dhcp_rule(ir, "zoneA-zoneB"), (
            "auto-DHCP leaked into zoneA-zoneB without bridge flag")
    if "zoneB-zoneA" in ir.chains:
        assert not _has_dhcp_rule(ir, "zoneB-zoneA"), (
            "auto-DHCP leaked into zoneB-zoneA without bridge flag")


def test_dhcp_emitted_in_cross_zone_with_bridge(tmp_path: Path) -> None:
    """When iface has ``bridge``, DHCP relay between zones IS allowed —
    chains carry the auto-DHCP-ACCEPT (matches classic shorewall's
    ``forward_option_chain`` gated on ``get_interface_option('bridge')``).
    """
    cfg = _write(tmp_path, _baseline_files(
        extra_iface_opts_a="dhcp,bridge",
        extra_iface_opts_b="dhcp,bridge"))
    ir = build_ir(load_config(cfg))
    assert _has_dhcp_rule(ir, "zoneA-zoneB")
    assert _has_dhcp_rule(ir, "zoneB-zoneA")


def test_dhcp_self_zone_emitted(tmp_path: Path) -> None:
    """``zoneA-zoneA`` (intra-zone forwarding) gets DHCP-ACCEPT for any
    dhcp-enabled iface — classic shorewall's self-chain DHCP rule."""
    cfg = _write(tmp_path, _baseline_files())
    ir = build_ir(load_config(cfg))
    assert "zoneA-zoneA" in ir.chains
    assert _has_dhcp_rule(ir, "zoneA-zoneA")
