"""Tests for the nft emit path of the proxyarp / proxyndp feature.

Covers:
  1. emit_proxyarp_nft  — IPv4 proxy ARP entries → arp filter rules
  2. emit_proxyndp_nft  — IPv6 proxy NDP entries → inet input rules
  3. HAVEROUTE=Yes      — pyroute2 route-add call is skipped (runtime path)

These are pure unit tests — they do not touch the live kernel and do
not require pyroute2 to be importable. The nft emit functions work
entirely on the in-memory IR.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from shorewall_nft.compiler.ir._data import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    Verdict,
)
from shorewall_nft.compiler.proxyarp import (
    ProxyArpEntry,
    emit_proxyarp_nft,
    emit_proxyndp_nft,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ir() -> FirewallIR:
    """Return a minimal FirewallIR with the inet filter input chain present.

    ``_create_base_chains`` normally creates this chain; we replicate the
    minimum needed here so unit tests don't need a full config parse.
    """
    ir = FirewallIR()
    # The inet filter input chain must exist before emit_proxyndp_nft runs
    # (created by _create_base_chains in the real compile path).
    ir.chains["input"] = Chain(
        name="input",
        chain_type=ChainType.FILTER,
        hook=Hook.INPUT,
        priority=0,
        policy=Verdict.DROP,
    )
    return ir


def _entry(addr: str, iface: str = "eth1", ext: str = "eth0",
           haveroute: bool = False, persistent: bool = False) -> ProxyArpEntry:
    return ProxyArpEntry(
        address=addr, iface=iface, ext_iface=ext,
        haveroute=haveroute, persistent=persistent,
    )


# ---------------------------------------------------------------------------
# 1. emit_proxyarp_nft — ARP filter rules
# ---------------------------------------------------------------------------

def test_proxyarp_emits_arp_rule():
    """A proxyarp entry must produce an arp daddr ip rule in ir.arp_chains."""
    ir = _make_ir()
    entries = [_entry("10.0.0.1")]
    emit_proxyarp_nft(ir, entries)

    assert "arp-input" in ir.arp_chains, "arp-input chain was not created"
    chain = ir.arp_chains["arp-input"]
    assert len(chain.rules) == 1
    rule = chain.rules[0]
    # Match fields: arp daddr ip + iifname
    fields = {m.field: m.value for m in rule.matches}
    assert "arp daddr ip" in fields, f"Missing 'arp daddr ip' match; got {fields}"
    assert fields["arp daddr ip"] == "10.0.0.1"
    assert fields.get("iifname") == "eth0"
    assert rule.verdict == Verdict.ACCEPT


def test_proxyarp_emits_multiple_entries():
    """Multiple IPv4 entries each get their own arp rule."""
    ir = _make_ir()
    entries = [
        _entry("10.0.0.1", ext="eth0"),
        _entry("10.0.0.2", ext="eth0"),
        _entry("192.168.1.5", ext="eth1"),
    ]
    emit_proxyarp_nft(ir, entries)

    chain = ir.arp_chains["arp-input"]
    assert len(chain.rules) == 3
    addrs = [
        next(m.value for m in r.matches if m.field == "arp daddr ip")
        for r in chain.rules
    ]
    assert "10.0.0.1" in addrs
    assert "10.0.0.2" in addrs
    assert "192.168.1.5" in addrs


def test_proxyarp_skips_ipv6_entries():
    """IPv6 entries must be silently ignored by emit_proxyarp_nft."""
    ir = _make_ir()
    entries = [_entry("2001:db8::1")]
    emit_proxyarp_nft(ir, entries)

    # No arp chain should be created at all for a pure IPv6 list
    assert "arp-input" not in ir.arp_chains


def test_proxyarp_reuses_existing_arp_chain():
    """emit_proxyarp_nft must reuse an existing arp-input chain (idempotent
    with the arprules path)."""
    ir = _make_ir()
    # Pre-create the chain as arprules would
    ir.arp_chains["arp-input"] = Chain(
        name="arp-input",
        chain_type=ChainType.FILTER,
        hook=Hook.INPUT,
        priority=0,
        policy=Verdict.ACCEPT,
    )
    entries = [_entry("10.1.1.1")]
    emit_proxyarp_nft(ir, entries)

    chain = ir.arp_chains["arp-input"]
    # The pre-existing chain must not be replaced — rule count is exactly 1
    assert len(chain.rules) == 1


def test_proxyarp_emits_nft_fragment():
    """Full compile round-trip: arp filter block appears in emitted script."""
    from shorewall_nft.nft.emitter import emit_arp_nft

    ir = _make_ir()
    entries = [_entry("192.0.2.1")]
    emit_proxyarp_nft(ir, entries)

    fragment = emit_arp_nft(ir)
    assert fragment, "emit_arp_nft returned empty for non-empty arp_chains"
    assert "table arp filter" in fragment
    assert "arp daddr ip 192.0.2.1" in fragment
    assert "iifname eth0" in fragment
    assert "accept" in fragment


# ---------------------------------------------------------------------------
# 2. emit_proxyndp_nft — NDP (ICMPv6 NS/NA) filter rules
# ---------------------------------------------------------------------------

def test_proxyndp_emits_ndp_rule():
    """A proxyndp entry must produce an NDP match rule in the input chain."""
    ir = _make_ir()
    entries = [_entry("2001:db8::1")]
    emit_proxyndp_nft(ir, entries)

    input_chain = ir.chains["input"]
    ndp_rules = [
        r for r in input_chain.rules
        if any(m.field == "icmpv6 type" for m in r.matches)
        and any(m.field == "ip6 daddr" for m in r.matches)
    ]
    assert ndp_rules, "No NDP rule found in input chain"
    rule = ndp_rules[0]
    fields = {m.field: m.value for m in rule.matches}
    assert fields["ip6 daddr"] == "2001:db8::1"
    assert fields["nexthdr"] == "icmpv6"
    assert "nd-neighbor-solicit" in fields["icmpv6 type"]
    assert "nd-neighbor-advert" in fields["icmpv6 type"]
    assert fields["iifname"] == "eth0"
    assert rule.verdict == Verdict.ACCEPT


def test_proxyndp_emits_multiple_entries():
    """Multiple IPv6 entries each get their own NDP rule."""
    ir = _make_ir()
    entries = [
        _entry("2001:db8::1", ext="eth0"),
        _entry("2001:db8::2", ext="eth1"),
    ]
    emit_proxyndp_nft(ir, entries)

    input_chain = ir.chains["input"]
    ndp_rules = [
        r for r in input_chain.rules
        if any(m.field == "ip6 daddr" for m in r.matches)
    ]
    assert len(ndp_rules) == 2
    addrs = [
        next(m.value for m in r.matches if m.field == "ip6 daddr")
        for r in ndp_rules
    ]
    assert "2001:db8::1" in addrs
    assert "2001:db8::2" in addrs


def test_proxyndp_skips_ipv4_entries():
    """IPv4 entries must be silently ignored by emit_proxyndp_nft."""
    ir = _make_ir()
    initial_rule_count = len(ir.chains["input"].rules)
    entries = [_entry("10.0.0.1")]
    emit_proxyndp_nft(ir, entries)

    # No new rules should have been added
    assert len(ir.chains["input"].rules) == initial_rule_count


def test_proxyndp_no_input_chain_is_safe():
    """emit_proxyndp_nft must not crash when the input chain is absent."""
    ir = FirewallIR()  # no chains at all
    entries = [_entry("2001:db8::1")]
    # Must not raise
    emit_proxyndp_nft(ir, entries)


def test_proxyndp_emits_nft_fragment():
    """Full compile round-trip: NDP match lines appear in emitted script."""
    from shorewall_nft.nft.emitter import emit_nft

    ir = _make_ir()
    entries = [_entry("2001:db8::1")]
    emit_proxyndp_nft(ir, entries)

    # emit_nft needs at least zones/settings to not crash
    script = emit_nft(ir)
    assert "nexthdr icmpv6" in script
    assert "nd-neighbor-solicit" in script
    assert "nd-neighbor-advert" in script
    assert "2001:db8::1" in script


# ---------------------------------------------------------------------------
# 3. HAVEROUTE=Yes — runtime path skips route-add
# ---------------------------------------------------------------------------

def test_proxyarp_haveroute_yes_skips_route():
    """apply_proxyarp must not call ipr.route() when HAVEROUTE=True.

    We mock pyroute2.IPRoute so no real kernel interaction happens, then
    assert that ``ipr.route`` is never called for the haveroute=True entry.
    IPRoute is imported lazily inside apply_proxyarp, so we patch via
    pyroute2 directly.
    """
    mock_ipr = MagicMock()
    mock_ipr.link_lookup.return_value = [2]
    mock_ipr.neigh.return_value = None
    mock_ipr.route.return_value = None
    mock_ipr.close.return_value = None

    entry_haveroute = ProxyArpEntry(
        address="10.0.0.1", iface="eth1", ext_iface="eth0",
        haveroute=True, persistent=False,
    )
    entry_no_haveroute = ProxyArpEntry(
        address="10.0.0.2", iface="eth1", ext_iface="eth0",
        haveroute=False, persistent=False,
    )

    with patch("pyroute2.IPRoute", return_value=mock_ipr):
        from shorewall_nft.compiler.proxyarp import apply_proxyarp
        applied, skipped, errors = apply_proxyarp(
            [entry_haveroute, entry_no_haveroute],
        )

    # neigh replace is called for both entries
    assert mock_ipr.neigh.call_count == 2, \
        f"Expected 2 neigh calls, got {mock_ipr.neigh.call_count}"

    # route replace must only be called for the haveroute=False entry
    route_calls = mock_ipr.route.call_args_list
    # Extract the 'dst' kwarg from each route call
    route_dsts = [str(c) for c in route_calls]
    for dst_str in route_dsts:
        assert "10.0.0.1" not in dst_str, \
            f"route() was called for haveroute=True entry 10.0.0.1: {dst_str}"
    # Exactly one route call for the no-haveroute entry
    assert mock_ipr.route.call_count == 1, \
        f"Expected 1 route call (for haveroute=False), got {mock_ipr.route.call_count}"


def test_proxyarp_haveroute_no_adds_route():
    """apply_proxyarp must call ipr.route('replace', ...) when HAVEROUTE=False.

    IPRoute is imported lazily inside apply_proxyarp, so we patch via the
    pyroute2 module itself.
    """
    mock_ipr = MagicMock()
    mock_ipr.link_lookup.return_value = [2]
    mock_ipr.neigh.return_value = None
    mock_ipr.route.return_value = None
    mock_ipr.close.return_value = None

    with patch("pyroute2.IPRoute", return_value=mock_ipr):
        from shorewall_nft.compiler.proxyarp import apply_proxyarp

        entry = ProxyArpEntry(
            address="10.0.0.3", iface="eth1", ext_iface="eth0",
            haveroute=False, persistent=False,
        )
        applied, skipped, errors = apply_proxyarp([entry])

    # route('replace', ...) must have been called at least once
    assert mock_ipr.route.called, "route() was not called for haveroute=False entry"
    call_args = mock_ipr.route.call_args_list[0]
    assert call_args[0][0] == "replace"
    # dst should contain the address
    assert "10.0.0.3" in str(call_args)
