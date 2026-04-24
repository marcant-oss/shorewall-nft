"""Tests for WP-D2: hosts OPTIONS.

Covers per-host options from the ``hosts`` config file:
  routeback    — annotation (zone-pair chain change)
  blacklist    — drop rule at input chain top
  tcpflags     — SYN/FIN and SYN/RST drop rules for this host
  nosmurfs     — broadcast-source drop for this host
  maclist      — annotation (MAC list enforcement, handled by macfilter)
  mss=N        — TCP MSS clamp scoped to this host
  ipsec        — match policy in/out ipsec for traffic from/to this host
  broadcast    — annotation (direction filter)
  destonly     — annotation (direction filter)
  sourceonly   — annotation (direction filter)
"""
from __future__ import annotations


from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.config.zones import build_zone_model, _parse_option_values


# ── Helpers ─────────────────────────────────────────────────────────────────

def _row(cols, file="test", lineno=1):
    return ConfigLine(columns=cols, file=file, lineno=lineno)


def _make_config(host_options: str, host_addr: str = "10.0.1.5") -> ShorewalConfig:
    """Minimal config with one hosts entry carrying *host_options*."""
    config = ShorewalConfig.__new__(ShorewalConfig)
    config.zones = [
        _row(["fw", "firewall"], "zones"),
        _row(["net", "ipv4"], "zones"),
        _row(["loc", "ipv4"], "zones"),
    ]
    config.interfaces = [
        _row(["net", "eth0", "detect", "-"], "interfaces"),
        _row(["loc", "eth1", "detect", "-"], "interfaces"),
    ]
    config.hosts = [
        _row(["loc", f"eth1:{host_addr}", host_options], "hosts"),
    ]
    config.policy = [
        _row(["$FW", "all", "ACCEPT"], "policy"),
        _row(["net", "all", "DROP"], "policy"),
        _row(["loc", "net", "ACCEPT"], "policy"),
        _row(["all", "all", "REJECT"], "policy"),
    ]
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
    config.settings = {"FASTACCEPT": "Yes"}
    return config


# ── WP-D2: zone model host parsing ──────────────────────────────────────────

def test_host_options_parsed_into_model():
    """Host OPTIONS string must populate Host.options and Host.option_values."""
    config = _make_config("routeback,mss=1400,blacklist")
    zones = build_zone_model(config)
    loc = zones.zones["loc"]
    assert loc.hosts, "Expected hosts list to be non-empty"
    h = loc.hosts[0]
    assert "routeback" in h.options
    assert "blacklist" in h.options
    assert h.option_values.get("mss") == "1400"


def test_host_mss_option_values_parsed():
    """mss=N in host OPTIONS must be accessible via option_values dict."""
    config = _make_config("mss=1280")
    zones = build_zone_model(config)
    h = zones.zones["loc"].hosts[0]
    assert h.option_values.get("mss") == "1280"


# ── WP-D2: tcpflags ──────────────────────────────────────────────────────────

def test_host_tcpflags_emits_syn_fin_rule():
    """tcpflags on a host must emit SYN|FIN drop rule in input chain."""
    config = _make_config("tcpflags")
    ir = build_ir(config)
    input_chain = ir.chains.get("input")
    assert input_chain is not None
    syn_fin_rules = [
        r for r in input_chain.rules
        if any("syn|fin" in m.value for m in r.matches)
    ]
    assert syn_fin_rules, "Expected SYN|FIN rule for host with tcpflags option"


def test_host_tcpflags_emits_syn_rst_rule():
    """tcpflags on a host must emit SYN|RST drop rule in input chain."""
    config = _make_config("tcpflags")
    ir = build_ir(config)
    input_chain = ir.chains.get("input")
    assert input_chain is not None
    syn_rst_rules = [
        r for r in input_chain.rules
        if any("syn|rst" in m.value for m in r.matches)
    ]
    assert syn_rst_rules, "Expected SYN|RST rule for host with tcpflags option"


def test_host_tcpflags_scoped_to_host_address():
    """tcpflags rules must include both iifname and saddr match for the host."""
    config = _make_config("tcpflags", host_addr="10.0.1.7")
    ir = build_ir(config)
    input_chain = ir.chains.get("input")
    assert input_chain is not None
    scoped = [
        r for r in input_chain.rules
        if (any(m.field == "ip saddr" and m.value == "10.0.1.7" for m in r.matches)
            and any("syn" in m.value for m in r.matches))
    ]
    assert scoped, "Expected tcpflags rule scoped to host address 10.0.1.7"


# ── WP-D2: nosmurfs ──────────────────────────────────────────────────────────

def test_host_nosmurfs_emits_broadcast_drop():
    """nosmurfs on a host must emit a broadcast-source drop rule in input chain."""
    config = _make_config("nosmurfs")
    ir = build_ir(config)
    input_chain = ir.chains.get("input")
    assert input_chain is not None
    smurf_rules = [
        r for r in input_chain.rules
        if any(m.field == "fib saddr type" and m.value == "broadcast"
               for m in r.matches)
    ]
    assert smurf_rules, "Expected broadcast-source drop for host with nosmurfs option"


# ── WP-D2: mss=N ─────────────────────────────────────────────────────────────

def test_host_mss_emits_clamp_rule():
    """mss=N on a host must emit a TCP MSS clamp rule."""
    config = _make_config("mss=1400")
    ir = build_ir(config)
    assert "mangle-forward" in ir.chains, (
        "Expected mangle-forward chain to be created for host mss= option"
    )
    chain = ir.chains["mangle-forward"]
    has_mss = any(
        any("tcp option maxseg size set 1400" in m.value for m in r.matches)
        for r in chain.rules
    )
    assert has_mss, "Expected MSS clamp rule for host mss=1400"


def test_host_mss_invalid_below_500_ignored():
    """mss values below 500 must be silently ignored per upstream Shorewall."""
    config = _make_config("mss=400")
    ir = build_ir(config)
    assert "mangle-forward" not in ir.chains


# ── WP-D2: blacklist ─────────────────────────────────────────────────────────

def test_host_blacklist_emits_drop_rule():
    """blacklist on a host must emit a drop rule matching that host's source."""
    config = _make_config("blacklist", host_addr="10.0.1.9")
    ir = build_ir(config)
    input_chain = ir.chains.get("input")
    assert input_chain is not None
    drop_rules = [
        r for r in input_chain.rules
        if (r.verdict.value == "drop"
            and any(m.field == "ip saddr" and m.value == "10.0.1.9"
                    for m in r.matches))
    ]
    assert drop_rules, (
        "Expected drop rule matching 10.0.1.9 for host with blacklist option"
    )


# ── WP-D2: ipsec annotation ──────────────────────────────────────────────────

def test_host_ipsec_stored_in_options():
    """'ipsec' option must appear in Host.options after parsing."""
    config = _make_config("ipsec")
    zones = build_zone_model(config)
    h = zones.zones["loc"].hosts[0]
    assert "ipsec" in h.options


# ── WP-D2: direction filter annotations ─────────────────────────────────────

def test_host_broadcast_stored_in_options():
    config = _make_config("broadcast")
    zones = build_zone_model(config)
    h = zones.zones["loc"].hosts[0]
    assert "broadcast" in h.options


def test_host_destonly_stored_in_options():
    config = _make_config("destonly")
    zones = build_zone_model(config)
    h = zones.zones["loc"].hosts[0]
    assert "destonly" in h.options


def test_host_sourceonly_stored_in_options():
    config = _make_config("sourceonly")
    zones = build_zone_model(config)
    h = zones.zones["loc"].hosts[0]
    assert "sourceonly" in h.options


# ── WP-D2: routeback annotation ──────────────────────────────────────────────

def test_host_routeback_stored_in_options():
    config = _make_config("routeback")
    zones = build_zone_model(config)
    h = zones.zones["loc"].hosts[0]
    assert "routeback" in h.options


# ── WP-D2: _parse_option_values helper ───────────────────────────────────────

def test_parse_option_values_extracts_kv():
    vals = _parse_option_values("routeback,mss=1400,nosmurfs")
    assert vals == {"mss": "1400"}


def test_parse_option_values_empty():
    assert _parse_option_values("-") == {}
    assert _parse_option_values("") == {}


def test_parse_option_values_multiple_kv():
    vals = _parse_option_values("mss=1400,arp_ignore=2,forward=0")
    assert vals["mss"] == "1400"
    assert vals["arp_ignore"] == "2"
    assert vals["forward"] == "0"
