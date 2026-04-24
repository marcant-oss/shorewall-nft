"""Tests for WP-D1: interfaces OPTIONS extras.

Covers the new interface options added in Phase 6 WP-D1:
  mss=N        — TCP MSS clamp (nft rule)
  sourceroute=  — sysctl accept_source_route
  optional      — annotation only (no nft rule, no sysctl)
  proxyarp=     — sysctl proxy_arp
  routefilter=  — sysctl rp_filter
  logmartians=  — sysctl log_martians
  arp_filter=   — sysctl arp_filter
  arp_ignore=N  — sysctl arp_ignore
  forward=      — sysctl forwarding (IPv4)
  accept_ra=    — sysctl accept_ra (IPv6)
"""
from __future__ import annotations


from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.compiler.sysctl import generate_sysctl_script
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.config.zones import build_zone_model
from shorewall_nft.nft.emitter import emit_nft


# ── Helpers ─────────────────────────────────────────────────────────────────

def _row(cols, file="zones", lineno=1):
    return ConfigLine(columns=cols, file=file, lineno=lineno)


def _zone_rows():
    return [
        _row(["fw", "firewall"], "zones"),
        _row(["net", "ipv4"], "zones"),
        _row(["loc", "ipv4"], "zones"),
    ]


def _policy_rows():
    return [
        _row(["$FW", "all", "ACCEPT"], "policy"),
        _row(["net", "all", "DROP"], "policy"),
        _row(["loc", "net", "ACCEPT"], "policy"),
        _row(["all", "all", "REJECT"], "policy"),
    ]


def _make_config(iface_options: str) -> ShorewalConfig:
    """Build a minimal ShorewalConfig with the given OPTIONS string on eth0."""
    iface_cols = ["net", "eth0", "detect", iface_options]
    iface2_cols = ["loc", "eth1", "detect", "-"]
    config = ShorewalConfig.__new__(ShorewalConfig)
    config.zones = _zone_rows()
    config.interfaces = [_row(iface_cols, "interfaces"), _row(iface2_cols, "interfaces")]
    config.hosts = []
    config.policy = _policy_rows()
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


# ── WP-D1: mss=N ────────────────────────────────────────────────────────────

def test_mss_clamp_emits_nft_rule():
    """mss=1452 on an interface must emit tcp MSS clamp rules in nft output."""
    config = _make_config("mss=1452")
    ir = build_ir(config)
    nft = emit_nft(ir)
    assert "tcp option maxseg size set 1452" in nft, (
        "Expected 'tcp option maxseg size set 1452' in emitted nft script"
    )


def test_mss_clamp_in_mangle_forward_chain():
    """mss= rule must land in the mangle-forward chain."""
    config = _make_config("mss=1452")
    ir = build_ir(config)
    assert "mangle-forward" in ir.chains, "Expected mangle-forward chain to be created"
    chain = ir.chains["mangle-forward"]
    has_mss = any(
        any(m.value == "tcp option maxseg size set 1452" for m in r.matches)
        for r in chain.rules
    )
    assert has_mss, "Expected MSS clamp rule in mangle-forward chain"


def test_mss_both_directions():
    """mss= must emit rules for both iifname and oifname."""
    config = _make_config("mss=1280")
    ir = build_ir(config)
    chain = ir.chains.get("mangle-forward")
    assert chain is not None
    iif_rules = [
        r for r in chain.rules
        if any(m.field == "iifname" and m.value == "eth0" for m in r.matches)
    ]
    oif_rules = [
        r for r in chain.rules
        if any(m.field == "oifname" and m.value == "eth0" for m in r.matches)
    ]
    assert iif_rules, "Expected iifname rule for MSS clamp"
    assert oif_rules, "Expected oifname rule for MSS clamp"


def test_mss_invalid_value_below_500_not_emitted():
    """mss values below 500 must be silently ignored per upstream."""
    config = _make_config("mss=200")
    ir = build_ir(config)
    assert "mangle-forward" not in ir.chains, (
        "mss=200 is invalid (<500) and must not create a mangle-forward chain"
    )


# ── WP-D1: sysctl options ───────────────────────────────────────────────────

def _sysctl_for(iface_options: str) -> str:
    config = _make_config(iface_options)
    return generate_sysctl_script(config)


def test_sourceroute_0_sets_accept_source_route():
    out = _sysctl_for("sourceroute=0")
    assert "net/ipv4/conf/eth0/accept_source_route" in out


def test_sourceroute_1_sets_accept_source_route():
    out = _sysctl_for("sourceroute=1")
    assert "net/ipv4/conf/eth0/accept_source_route" in out
    assert "'1'" in out


def test_proxyarp_1_sets_proxy_arp():
    out = _sysctl_for("proxyarp=1")
    assert "net/ipv4/conf/eth0/proxy_arp" in out
    assert "'1'" in out


def test_routefilter_sets_rp_filter():
    out = _sysctl_for("routefilter")
    assert "net/ipv4/conf/eth0/rp_filter" in out


def test_routefilter_value_2_sets_rp_filter_2():
    out = _sysctl_for("routefilter=2")
    assert "net/ipv4/conf/eth0/rp_filter" in out
    assert "'2'" in out


def test_routefilter_0_disables():
    out = _sysctl_for("routefilter=0")
    assert "net/ipv4/conf/eth0/rp_filter" in out
    assert "'0'" in out


def test_logmartians_sets_log_martians():
    out = _sysctl_for("logmartians")
    assert "net/ipv4/conf/eth0/log_martians" in out


def test_logmartians_0_disables():
    out = _sysctl_for("logmartians=0")
    assert "net/ipv4/conf/eth0/log_martians" in out
    assert "'0'" in out


def test_arp_filter_flag_sets_arp_filter():
    out = _sysctl_for("arp_filter")
    assert "net/ipv4/conf/eth0/arp_filter" in out
    assert "'1'" in out


def test_arp_filter_value():
    out = _sysctl_for("arp_filter=0")
    assert "net/ipv4/conf/eth0/arp_filter" in out
    assert "'0'" in out


def test_arp_ignore_sets_arp_ignore():
    out = _sysctl_for("arp_ignore=2")
    assert "net/ipv4/conf/eth0/arp_ignore" in out
    assert "'2'" in out


def test_forward_sets_ipv4_forwarding():
    out = _sysctl_for("forward=1")
    assert "net/ipv4/conf/eth0/forwarding" in out
    assert "'1'" in out


def test_accept_ra_sets_ipv6_accept_ra():
    out = _sysctl_for("accept_ra=1")
    assert "net/ipv6/conf/eth0/accept_ra" in out
    assert "'1'" in out


def test_accept_ra_value_2():
    out = _sysctl_for("accept_ra=2")
    assert "net/ipv6/conf/eth0/accept_ra" in out
    assert "'2'" in out


def test_accept_ra_disable():
    out = _sysctl_for("accept_ra=0")
    assert "net/ipv6/conf/eth0/accept_ra" in out
    assert "'0'" in out


# ── WP-D1: optional ─────────────────────────────────────────────────────────

def test_optional_does_not_crash():
    """'optional' is an annotation — it must not cause an error."""
    config = _make_config("optional")
    ir = build_ir(config)  # must not raise
    assert ir is not None


def test_optional_stored_in_interface_options():
    """'optional' must appear in Interface.options so callers can check it."""
    config = _make_config("optional")
    zones = build_zone_model(config)
    net_zone = zones.zones["net"]
    assert net_zone.interfaces, "Expected at least one interface for net zone"
    iface = net_zone.interfaces[0]
    assert "optional" in iface.options


# ── WP-D1: sysctl uses /proc/sys writes, not 'sysctl' binary ────────────────

def test_sysctl_output_uses_proc_writes():
    """pyroute2-first: sysctl script must write to /proc/sys/..., not invoke sysctl binary."""
    # The script may still contain 'sysctl' in the shebang/comments, but
    # per-interface writes must use the direct /proc path via printf.
    out = _sysctl_for("routefilter=1,logmartians,accept_ra=1")
    # Per-interface writes in the new implementation use printf > /proc/sys/...
    assert "/proc/sys/net/ipv4/conf/eth0/rp_filter" in out
    assert "/proc/sys/net/ipv6/conf/eth0/accept_ra" in out


# ── WP-D1: dot-to-slash translation for VLAN interfaces ─────────────────────

def test_dot_interface_name_translates_to_slash_in_proc_path():
    """eth0.100 must map to /proc/sys/net/ipv4/conf/eth0/100/... in sysctl output."""
    # Build config with a VLAN interface
    iface_cols = ["net", "eth0.100", "detect", "routefilter=1"]
    iface2_cols = ["loc", "eth1", "detect", "-"]
    config = ShorewalConfig.__new__(ShorewalConfig)
    config.zones = _zone_rows()
    config.interfaces = [_row(iface_cols, "interfaces"), _row(iface2_cols, "interfaces")]
    config.hosts = []
    config.policy = _policy_rows()
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
    out = generate_sysctl_script(config)
    assert "eth0/100/rp_filter" in out, (
        "Expected VLAN interface eth0.100 to translate to eth0/100 in /proc path"
    )
