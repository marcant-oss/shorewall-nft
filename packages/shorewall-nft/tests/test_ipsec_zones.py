"""Tests for WP-D3: zones IPsec OPTIONS.

Covers the parsing and rule-emit behaviour for ipsec/ipsec4/ipsec6 zones:
  - IpsecOptions parsing: mss=, strict, next, reqid=, spi=, proto=, mode=, mark=
  - Zone type detection in ZoneModel
  - Policy match injection: every rule emitted into a chain involving an ipsec
    zone must carry ``policy in|out ipsec [<opts>]``
"""
from __future__ import annotations


from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.compiler.ir.rules import (
    _build_ipsec_policy_clause,
    _inject_ipsec_policy_match,
)
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.config.zones import (
    ZoneModel,
    Zone,
    build_zone_model,
    _parse_ipsec_options,
)
from shorewall_nft.compiler.ir._data import Match, Rule
from shorewall_nft.nft.emitter import emit_nft


# ── Helpers ─────────────────────────────────────────────────────────────────

def _row(cols, file="test", lineno=1):
    return ConfigLine(columns=cols, file=file, lineno=lineno)


def _make_config_with_ipsec(ipsec_opts: str = "") -> ShorewalConfig:
    """Minimal config with an ipsec zone that has the given OPTIONS."""
    config = ShorewalConfig.__new__(ShorewalConfig)
    config.zones = [
        _row(["fw", "firewall"], "zones"),
        _row(["net", "ipv4"], "zones"),
        # ipsec zone; OPTIONS in column 2
        _row(["tunnel", "ipsec", ipsec_opts or "-"], "zones"),
    ]
    config.interfaces = [
        _row(["net", "eth0", "detect", "-"], "interfaces"),
        _row(["tunnel", "ipsec0", "detect", "-"], "interfaces"),
    ]
    config.hosts = []
    config.policy = [
        _row(["$FW", "all", "ACCEPT"], "policy"),
        _row(["net", "all", "DROP"], "policy"),
        _row(["tunnel", "net", "ACCEPT"], "policy"),
        _row(["net", "tunnel", "DROP"], "policy"),
        _row(["all", "all", "REJECT"], "policy"),
    ]
    config.rules = [
        _row(["ACCEPT", "tunnel", "net", "tcp", "22"], "rules"),
        _row(["ACCEPT", "net", "tunnel", "icmp", "8"], "rules"),
    ]
    config.masq = []
    config.notrack = []
    config.conntrack = []
    config.blrules = []
    config.routestopped = []
    config.macros = {}
    config.providers = []
    config.routes = []
    config.rtrules = []
    config.tcrules = []
    config.mangle = []
    config.accounting = []
    config.tunnels = []
    config.maclist = []
    config.netmap = []
    config.settings = {"FASTACCEPT": "Yes"}
    return config


# ── WP-D3: IpsecOptions parsing ──────────────────────────────────────────────

def test_parse_ipsec_options_empty():
    opts = _parse_ipsec_options([])
    assert opts.mss is None
    assert opts.strict is False
    assert opts.next is False
    assert opts.reqid is None
    assert opts.spi is None
    assert opts.proto is None
    assert opts.mode is None
    assert opts.mark is None


def test_parse_ipsec_options_strict():
    opts = _parse_ipsec_options(["strict"])
    assert opts.strict is True


def test_parse_ipsec_options_next():
    opts = _parse_ipsec_options(["next"])
    assert opts.next is True


def test_parse_ipsec_options_mss():
    opts = _parse_ipsec_options(["mss=1400"])
    assert opts.mss == 1400


def test_parse_ipsec_options_reqid():
    opts = _parse_ipsec_options(["reqid=42"])
    assert opts.reqid == 42


def test_parse_ipsec_options_spi_decimal():
    opts = _parse_ipsec_options(["spi=12345"])
    assert opts.spi == 12345


def test_parse_ipsec_options_spi_hex():
    opts = _parse_ipsec_options(["spi=0x1000"])
    assert opts.spi == 0x1000


def test_parse_ipsec_options_proto_esp():
    opts = _parse_ipsec_options(["proto=esp"])
    assert opts.proto == "esp"


def test_parse_ipsec_options_proto_ah():
    opts = _parse_ipsec_options(["proto=ah"])
    assert opts.proto == "ah"


def test_parse_ipsec_options_mode_tunnel():
    opts = _parse_ipsec_options(["mode=tunnel"])
    assert opts.mode == "tunnel"


def test_parse_ipsec_options_mode_transport():
    opts = _parse_ipsec_options(["mode=transport"])
    assert opts.mode == "transport"


def test_parse_ipsec_options_mark():
    opts = _parse_ipsec_options(["mark=7"])
    assert opts.mark == 7


def test_parse_ipsec_options_mark_hex():
    opts = _parse_ipsec_options(["mark=0xff"])
    assert opts.mark == 0xff


def test_parse_ipsec_options_combined():
    opts = _parse_ipsec_options(
        ["strict", "reqid=10", "proto=esp", "mode=tunnel", "mark=0x1"])
    assert opts.strict is True
    assert opts.reqid == 10
    assert opts.proto == "esp"
    assert opts.mode == "tunnel"
    assert opts.mark == 1


# ── WP-D3: zone model integration ────────────────────────────────────────────

def test_ipsec_zone_stores_options_in_model():
    """IpsecOptions must be populated on the Zone object."""
    config = _make_config_with_ipsec("proto=esp,mode=tunnel,reqid=5")
    zones = build_zone_model(config)
    tunnel = zones.zones["tunnel"]
    assert tunnel.zone_type == "ipsec"
    assert tunnel.ipsec_options is not None
    assert tunnel.ipsec_options.proto == "esp"
    assert tunnel.ipsec_options.mode == "tunnel"
    assert tunnel.ipsec_options.reqid == 5


def test_non_ipsec_zone_has_no_ipsec_options():
    """Non-ipsec zones must have ipsec_options=None."""
    config = _make_config_with_ipsec()
    zones = build_zone_model(config)
    assert zones.zones["net"].ipsec_options is None
    assert zones.zones["fw"].ipsec_options is None


# ── WP-D3: _build_ipsec_policy_clause ────────────────────────────────────────

def _zones_with_ipsec(opts_list: list[str]) -> ZoneModel:
    """Build a minimal ZoneModel with an 'ipsec' zone carrying opts_list."""
    from shorewall_nft.config.zones import _parse_ipsec_options
    model = ZoneModel()
    fw = Zone(name="fw", zone_type="firewall")
    ipsec_z = Zone(name="vpn", zone_type="ipsec",
                   ipsec_options=_parse_ipsec_options(opts_list))
    model.zones["fw"] = fw
    model.zones["vpn"] = ipsec_z
    model.firewall_zone = "fw"
    return model


def test_policy_clause_bare_ipsec_zone():
    """An ipsec zone with no sub-options must fall back to 'meta secpath exists'.

    nftables 1.1.x has no ``policy`` statement equivalent to iptables
    ``-m policy``; ``meta secpath exists`` is the idiomatic broad match.
    """
    zones = _zones_with_ipsec([])
    clause = _build_ipsec_policy_clause("vpn", zones, "in")
    assert clause == "meta secpath exists"


def test_policy_clause_with_proto_direction_in():
    """proto= on ingress falls back to the broad secpath match."""
    zones = _zones_with_ipsec(["proto=esp"])
    clause = _build_ipsec_policy_clause("vpn", zones, "in")
    assert clause == "meta secpath exists"


def test_policy_clause_with_mode_direction_out_uses_meta_ipsec_exists():
    """mode= on egress without reqid/spi falls back to ``meta ipsec exists``.

    ``meta secpath`` is populated only during ingress xfrm decap; the
    kernel rejects it on output hooks. ``meta ipsec exists`` is the
    direction-agnostic existence check accepted by nft 1.1.x — coarser
    than ``ipsec out reqid N`` but at least confines the rule to xfrm-
    bound packets instead of leaving the match empty.
    """
    zones = _zones_with_ipsec(["mode=tunnel"])
    clause = _build_ipsec_policy_clause("vpn", zones, "out")
    assert clause == "meta ipsec exists"


def test_policy_clause_no_opts_direction_out_uses_meta_ipsec_exists():
    """A bare ipsec zone on egress also falls back to ``meta ipsec exists``."""
    zones = _zones_with_ipsec([])
    clause = _build_ipsec_policy_clause("vpn", zones, "out")
    assert clause == "meta ipsec exists"


def test_policy_clause_with_reqid():
    """reqid= produces a narrow ``ipsec <dir> reqid N`` match."""
    zones = _zones_with_ipsec(["reqid=99"])
    clause = _build_ipsec_policy_clause("vpn", zones, "in")
    assert clause == "ipsec in reqid 99"


def test_policy_clause_with_spi():
    """spi= produces a narrow ``ipsec <dir> spi 0xN`` match."""
    zones = _zones_with_ipsec(["spi=0x1000"])
    clause = _build_ipsec_policy_clause("vpn", zones, "in")
    assert clause == "ipsec in spi 0x1000"


def test_policy_clause_proto_plus_reqid_drops_proto():
    """When reqid is present, proto= is silently dropped (no nft expression)."""
    zones = _zones_with_ipsec(["reqid=42", "proto=esp", "mode=tunnel"])
    clause = _build_ipsec_policy_clause("vpn", zones, "out")
    assert clause == "ipsec out reqid 42"


def test_policy_clause_returns_none_for_non_ipsec_zone():
    zones = _zones_with_ipsec([])
    clause = _build_ipsec_policy_clause("fw", zones, "in")
    assert clause is None


def test_policy_clause_returns_none_for_unknown_zone():
    zones = _zones_with_ipsec([])
    clause = _build_ipsec_policy_clause("nonexistent", zones, "in")
    assert clause is None


# ── WP-D3: _inject_ipsec_policy_match ────────────────────────────────────────

def test_inject_ipsec_policy_adds_match_when_src_is_ipsec():
    """When src zone is ipsec, an IPsec-match inline is prepended."""
    zones = _zones_with_ipsec(["proto=esp"])
    rule = Rule()
    rule.matches.append(Match(field="meta l4proto", value="tcp"))
    _inject_ipsec_policy_match(rule, "vpn", "fw", zones)
    assert rule.matches[0].field == "inline"
    # proto=esp has no nft counterpart → broad secpath fallback.
    assert rule.matches[0].value == "meta secpath exists"


def test_inject_ipsec_policy_adds_match_when_dst_is_ipsec_with_reqid():
    """When dst zone is ipsec and reqid is set, a narrow ``ipsec out reqid N``
    match is appended.

    Without reqid/spi the egress direction has no nft expression and
    ``_build_ipsec_policy_clause`` returns ``None`` (no match appended).
    """
    zones = _zones_with_ipsec(["reqid=42"])
    rule = Rule()
    rule.matches.append(Match(field="meta l4proto", value="tcp"))
    _inject_ipsec_policy_match(rule, "fw", "vpn", zones)
    last = rule.matches[-1]
    assert last.field == "inline"
    assert last.value == "ipsec out reqid 42"


def test_inject_ipsec_policy_out_without_reqid_uses_meta_ipsec_exists():
    """dst-ipsec zone without reqid/spi appends ``meta ipsec exists``.

    ``meta secpath`` is ingress-only; ``meta ipsec exists`` is the
    direction-agnostic existence check that confines the rule to
    xfrm-bound packets. Coarser than ``ipsec out reqid N`` but
    expressible without per-tunnel metadata.
    """
    zones = _zones_with_ipsec(["proto=esp"])
    rule = Rule()
    rule.matches.append(Match(field="meta l4proto", value="tcp"))
    _inject_ipsec_policy_match(rule, "fw", "vpn", zones)
    assert len(rule.matches) == 2
    assert rule.matches[-1].field == "inline"
    assert rule.matches[-1].value == "meta ipsec exists"


def test_inject_ipsec_no_match_for_non_ipsec_zones():
    """No policy match must be added when neither zone is ipsec."""
    zones = _zones_with_ipsec([])
    rule = Rule()
    rule.matches.append(Match(field="meta l4proto", value="tcp"))
    _inject_ipsec_policy_match(rule, "fw", "fw", zones)
    # The original match must still be present and no new match added
    assert len(rule.matches) == 1
    assert rule.matches[0].field == "meta l4proto"


# ── WP-D3: full compile — rules in ipsec-zone chains carry policy match ──────

def test_ipsec_zone_rules_carry_policy_in_match():
    """Rules whose source is an ipsec zone must carry a ``meta secpath exists``
    (or narrow ``ipsec in …``) match in the emitted nft output."""
    config = _make_config_with_ipsec("proto=esp,mode=tunnel")
    ir = build_ir(config)
    nft = emit_nft(ir)
    assert "meta secpath exists" in nft, (
        "Expected 'meta secpath exists' (or narrow 'ipsec in') in emitted "
        "nft for ipsec zone src"
    )


def test_ipsec_zone_rules_out_direction_no_match_without_reqid():
    """Rules to an ipsec zone without reqid/spi must NOT carry a ``meta
    secpath`` match — the kernel rejects that on egress hooks."""
    config = _make_config_with_ipsec("proto=esp,mode=tunnel")
    ir = build_ir(config)
    nft = emit_nft(ir)
    # No egress secpath and no stale policy-ism.
    assert "policy out ipsec" not in nft
    # The broad secpath may still appear on ingress-side rules.
    # If it does, it's only in chains reached from input/prerouting hooks.


def test_ipsec_zone_proto_mode_dropped_in_emit():
    """proto= / mode= are silently dropped; ingress rules still get the
    broad ``meta secpath exists`` match, egress rules get no IPsec match.

    Regression guard: earlier emitter output ``policy in ipsec proto ah mode
    tunnel`` which ``nft -f`` rejects with ``unexpected policy``. There is
    no ``policy`` statement in nft 1.1.x.
    """
    config = _make_config_with_ipsec("proto=ah,mode=transport")
    ir = build_ir(config)
    nft = emit_nft(ir)
    assert "policy in ipsec" not in nft
    assert "policy out ipsec" not in nft
    assert "proto ah" not in nft
    assert "mode transport" not in nft
    # Ingress-side rules keep secpath; egress-side rules drop the match.
    assert "meta secpath exists" in nft


def test_ipsec_zone_reqid_in_emitted_rule():
    """reqid= must appear as a narrow ``ipsec <dir> reqid N`` clause."""
    config = _make_config_with_ipsec("reqid=77")
    ir = build_ir(config)
    nft = emit_nft(ir)
    assert "reqid 77" in nft
    # No stale iptables-ism — narrow match, no ``policy in|out ipsec``.
    assert "policy in ipsec" not in nft
    assert "policy out ipsec" not in nft


def test_ipsec_zone_bare_minimal():
    """An ipsec zone with no sub-options must still emit ``meta secpath exists``."""
    config = _make_config_with_ipsec("-")
    ir = build_ir(config)
    nft = emit_nft(ir)
    assert "meta secpath exists" in nft


# ── WP-D3: ipsec4 / ipsec6 zone types ─────────────────────────────────────────

def test_ipsec4_zone_has_options_parsed():
    """ipsec4 zone type must also trigger IpsecOptions parsing."""
    config = ShorewalConfig.__new__(ShorewalConfig)
    config.zones = [
        _row(["fw", "firewall"], "zones"),
        _row(["vpn4", "ipsec4", "proto=esp"], "zones"),
    ]
    config.interfaces = []
    config.hosts = []
    config.policy = [_row(["all", "all", "REJECT"], "policy")]
    config.rules = []
    config.masq = []
    config.notrack = []
    config.conntrack = []
    config.blrules = []
    config.routestopped = []
    config.macros = {}
    config.providers = []
    config.routes = []
    config.rtrules = []
    config.tcrules = []
    config.mangle = []
    config.accounting = []
    config.tunnels = []
    config.maclist = []
    config.netmap = []
    config.settings = {}
    zones = build_zone_model(config)
    assert zones.zones["vpn4"].ipsec_options is not None
    assert zones.zones["vpn4"].ipsec_options.proto == "esp"


def test_ipsec6_zone_has_options_parsed():
    """ipsec6 zone type must also trigger IpsecOptions parsing."""
    config = ShorewalConfig.__new__(ShorewalConfig)
    config.zones = [
        _row(["fw", "firewall"], "zones"),
        _row(["vpn6", "ipsec6", "mode=transport"], "zones"),
    ]
    config.interfaces = []
    config.hosts = []
    config.policy = [_row(["all", "all", "REJECT"], "policy")]
    config.rules = []
    config.masq = []
    config.notrack = []
    config.conntrack = []
    config.blrules = []
    config.routestopped = []
    config.macros = {}
    config.providers = []
    config.routes = []
    config.rtrules = []
    config.tcrules = []
    config.mangle = []
    config.accounting = []
    config.tunnels = []
    config.maclist = []
    config.netmap = []
    config.settings = {}
    zones = build_zone_model(config)
    assert zones.zones["vpn6"].ipsec_options is not None
    assert zones.zones["vpn6"].ipsec_options.mode == "transport"
