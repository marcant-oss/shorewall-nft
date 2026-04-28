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


# ── physical=NAME (alias override for nft iifname/oifname) ──────────────────

def test_physical_overrides_iifname_in_protection_rules():
    """physical=eth0.100 must replace iface.name in tcpflags iifname matchers."""
    config = _make_config("tcpflags,physical=eth0.100")
    config.settings["TCP_FLAGS_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    nft = emit_nft(ir)
    # Logical name disappears from tcpflags rules; physical name takes over.
    assert 'iifname "eth0.100"' in nft, (
        "Expected tcpflags rule to use physical iface name 'eth0.100'"
    )


def test_physical_overrides_iifname_in_zone_dispatch():
    """physical=eth0.100 must replace iface.name in vmap / zone-jump dispatch."""
    config = _make_config("physical=eth0.100")
    ir = build_ir(config)
    nft = emit_nft(ir)
    # Dispatch rules use the physical name for iifname/oifname matchers.
    assert "eth0.100" in nft, (
        "Expected zone dispatch to reference physical iface name"
    )


def test_emit_name_falls_back_to_logical():
    """Without physical=, emit_name returns the logical name."""
    config = _make_config("-")
    zones = build_zone_model(config)
    iface = zones.zones["net"].interfaces[0]
    assert iface.emit_name == "eth0"


# ── unmanaged (skip iface entirely) ─────────────────────────────────────────

def test_unmanaged_iface_excluded_from_zone_model():
    """Interfaces marked 'unmanaged' must not appear in the zone model."""
    config = _make_config("unmanaged")
    zones = build_zone_model(config)
    # eth0 was unmanaged → not in net zone; eth1 was '-' → still in loc zone.
    assert zones.zones["net"].interfaces == [], (
        "Expected unmanaged eth0 to be excluded from net zone"
    )
    assert len(zones.zones["loc"].interfaces) == 1, (
        "Expected loc zone to still carry eth1"
    )


def test_unmanaged_iface_emits_no_protection_rules():
    """No tcpflags/nosmurfs/mss rules emitted for unmanaged interface."""
    config = _make_config("unmanaged,tcpflags,nosmurfs,mss=1452")
    config.settings["TCP_FLAGS_DISPOSITION"] = "DROP"
    config.settings["SMURF_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    nft = emit_nft(ir)
    # eth0 is unmanaged — none of its protection rules should appear.
    assert 'iifname "eth0"' not in nft or "tcpflags" not in nft, (
        "Expected unmanaged eth0 to skip tcpflags/nosmurfs emission"
    )
    # mangle-forward chain shouldn't be created for an unmanaged-only mss
    # config (only eth0 has mss; eth1 doesn't).
    assert "mangle-forward" not in ir.chains, (
        "mangle-forward should not be created when the only mss-bearing "
        "iface is unmanaged"
    )


# ── required (parse-only, runtime hook future) ──────────────────────────────

def test_required_does_not_crash():
    """'required' is a boolean flag — parser must accept and store it."""
    config = _make_config("required")
    zones = build_zone_model(config)
    iface = zones.zones["net"].interfaces[0]
    assert "required" in iface.options


def test_required_flag_emits_no_rules():
    """'required' has no compile-time emit — runtime fail-fast is future work."""
    config = _make_config("required")
    ir = build_ir(config)
    nft = emit_nft(ir)
    # No tcpflags/smurf/mss; just zone scaffolding. Sanity-check the
    # build doesn't crash and produces valid output.
    assert "table inet shorewall" in nft


# ── rpfilter (mangle-prerouting RPF drop) ───────────────────────────────────

def test_rpfilter_emits_mangle_prerouting_rule():
    """``rpfilter`` adds a per-iface fib-saddr drop in mangle-prerouting."""
    config = _make_config("rpfilter")
    config.settings["RPFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    assert "mangle-prerouting" in ir.chains
    chain = ir.chains["mangle-prerouting"]
    fib_rules = [
        r for r in chain.rules
        if any("fib saddr" in (m.value or "") for m in r.matches)
    ]
    assert fib_rules, "Expected fib-saddr rule for rpfilter iface"


def test_rpfilter_emits_both_families():
    """``rpfilter`` emits one rule per family (IPv4 + IPv6)."""
    config = _make_config("rpfilter")
    config.settings["RPFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    chain = ir.chains["mangle-prerouting"]
    nfprotos = {
        m.value for r in chain.rules for m in r.matches
        if m.field == "meta nfproto"
    }
    assert "ipv4" in nfprotos and "ipv6" in nfprotos


def test_rpfilter_dhcp_exception_emitted_when_combined():
    """rpfilter+dhcp on the same iface inserts a v4 DHCP-bypass RETURN."""
    config = _make_config("rpfilter,dhcp")
    config.settings["RPFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    chain = ir.chains["mangle-prerouting"]
    has_dhcp_exception = any(
        r.comment == "rpfilter:dhcp-exception"
        and any(m.value == "0.0.0.0" for m in r.matches)
        for r in chain.rules
    )
    assert has_dhcp_exception


def test_rpfilter_no_dhcp_exception_when_dhcp_absent():
    """Without dhcp on any rpfilter iface, no DHCP-bypass rule is emitted."""
    config = _make_config("rpfilter")
    config.settings["RPFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    chain = ir.chains["mangle-prerouting"]
    has_dhcp_exception = any(
        r.comment == "rpfilter:dhcp-exception" for r in chain.rules
    )
    assert not has_dhcp_exception


def test_rpfilter_skipped_when_disposition_is_continue():
    """RPFILTER_DISPOSITION=CONTINUE suppresses the emit (Perl: no chain)."""
    config = _make_config("rpfilter")
    config.settings["RPFILTER_DISPOSITION"] = "CONTINUE"
    ir = build_ir(config)
    # Either no chain or the chain has no rpfilter rules.
    chain = ir.chains.get("mangle-prerouting")
    if chain is not None:
        rpfilter_rules = [
            r for r in chain.rules
            if (r.comment or "").startswith("rpfilter")
        ]
        assert rpfilter_rules == []


def test_rpfilter_uses_emit_name_with_physical_alias():
    """rpfilter rule uses physical override when ``physical=`` is set."""
    config = _make_config("rpfilter,physical=eth0.42")
    config.settings["RPFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    chain = ir.chains["mangle-prerouting"]
    iifname_values = {
        m.value for r in chain.rules for m in r.matches
        if m.field == "iifname"
    }
    assert "eth0.42" in iifname_values
    assert "eth0" not in iifname_values


# ── sfilter=CIDR,... (anti-spoof source-CIDR drop) ──────────────────────────

def test_sfilter_emits_v4_saddr_rule():
    """sfilter=10.0.0.0/8 → mangle-prerouting drop on iif=eth0 ip saddr 10/8."""
    config = _make_config("sfilter=10.0.0.0/8")
    config.settings["SFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    assert "mangle-prerouting" in ir.chains
    chain = ir.chains["mangle-prerouting"]
    # one v4 rule, no v6 rule, no audit
    rules = [r for r in chain.rules if (r.comment or "").startswith("sfilter")]
    assert len(rules) == 1
    matches = {m.field: m.value for m in rules[0].matches}
    assert matches["iifname"] == "eth0"
    assert matches["meta nfproto"] == "ipv4"
    assert "10.0.0.0/8" in matches["ip saddr"]


def test_sfilter_splits_v4_v6_into_separate_rules():
    """Mixed CIDR list emits one rule per family.  Multi-value lists use
    Shorewall's paren-group syntax: ``sfilter=(net1,net2)``."""
    config = _make_config("sfilter=(10.0.0.0/8,fd00::/8)")
    config.settings["SFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    chain = ir.chains["mangle-prerouting"]
    nfprotos = {
        next(m.value for m in r.matches if m.field == "meta nfproto")
        for r in chain.rules if (r.comment or "").startswith("sfilter")
    }
    assert nfprotos == {"ipv4", "ipv6"}


def test_sfilter_audit_disposition_emits_companion_accept():
    """A_DROP emits both an audit-ACCEPT and the real DROP per family."""
    config = _make_config("sfilter=10.0.0.0/8")
    config.settings["SFILTER_DISPOSITION"] = "A_DROP"
    ir = build_ir(config)
    chain = ir.chains["mangle-prerouting"]
    audit_rules = [
        r for r in chain.rules if (r.comment or "").startswith("sfilter:audit:")
    ]
    drop_rules = [
        r for r in chain.rules
        if (r.comment or "").startswith("sfilter:") and "audit" not in (r.comment or "")
    ]
    assert audit_rules and drop_rules


def test_sfilter_continue_disposition_suppresses_emit():
    """SFILTER_DISPOSITION=CONTINUE → no rule emitted."""
    config = _make_config("sfilter=10.0.0.0/8")
    config.settings["SFILTER_DISPOSITION"] = "CONTINUE"
    ir = build_ir(config)
    chain = ir.chains.get("mangle-prerouting")
    if chain is not None:
        sfilter_rules = [
            r for r in chain.rules if (r.comment or "").startswith("sfilter")
        ]
        assert sfilter_rules == []


def test_sfilter_uses_emit_name_with_physical_alias():
    """sfilter rule uses physical override when ``physical=`` is set."""
    config = _make_config("sfilter=10.0.0.0/8,physical=eth0.99")
    config.settings["SFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)
    chain = ir.chains["mangle-prerouting"]
    iifname_values = {
        m.value for r in chain.rules for m in r.matches
        if m.field == "iifname"
        and any(m2.value and "ip saddr" in m2.field for m2 in r.matches)
    }
    assert "eth0.99" in iifname_values


def test_sfilter_invalid_cidr_silently_skipped():
    """Garbage tokens in the CIDR list don't crash the build."""
    config = _make_config("sfilter=not-a-cidr")
    config.settings["SFILTER_DISPOSITION"] = "DROP"
    ir = build_ir(config)  # must not raise
    chain = ir.chains.get("mangle-prerouting")
    if chain is not None:
        sfilter_rules = [
            r for r in chain.rules if (r.comment or "").startswith("sfilter")
        ]
        assert sfilter_rules == []  # no valid CIDRs → no emit


# ── nomark (mark-allocator skip) ────────────────────────────────────────────

def test_nomark_excludes_iface_from_zone_marks():
    """An iface flagged 'nomark' must not appear in the zone-mark map."""
    from shorewall_nft.nft.emitter import _compute_zone_marks
    config = _make_config("nomark")
    ir = build_ir(config)
    marks = _compute_zone_marks(ir)
    assert "eth0" not in marks
    # eth1 (loc zone, no nomark) still gets a mark
    assert "eth1" in marks


def test_nomark_does_not_break_other_ifaces():
    """nomark on one iface doesn't disturb mark allocation for siblings."""
    from shorewall_nft.nft.emitter import _compute_zone_marks
    config = _make_config("nomark")
    ir = build_ir(config)
    marks = _compute_zone_marks(ir)
    # loc.eth1 should still receive the next available mark
    assert marks.get("eth1") == 1 or marks.get("eth1") is not None


# ── upnp / upnpclient deprecation ───────────────────────────────────────────

def test_upnp_emits_deprecation_warning():
    """``upnp`` is parsed but warned-on; no rule emitted."""
    import warnings
    config = _make_config("upnp")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        zones = build_zone_model(config)
    assert any("upnp" in str(rec.message) and "deprecated" in str(rec.message)
               for rec in w)
    # iface still loaded — option is accepted (just no emit).
    assert zones.zones["net"].interfaces


def test_upnpclient_emits_deprecation_warning():
    import warnings
    config = _make_config("upnpclient")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        build_zone_model(config)
    assert any("upnpclient" in str(rec.message) and "deprecated" in str(rec.message)
               for rec in w)


# ── dbl / nodbl per-iface dynamic-blacklist gating ──────────────────────────

def test_dbl_invalid_value_warned_and_dropped():
    """``dbl=garbage`` warns and is dropped from option_values."""
    import warnings
    config = _make_config("dbl=garbage")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        zones = build_zone_model(config)
    iface = zones.zones["net"].interfaces[0]
    assert "dbl" not in iface.option_values
    assert any("dbl" in str(rec.message) and "invalid" in str(rec.message).lower()
               for rec in w)


def test_dbl_skip_src_property_honours_nodbl_and_dbl_none():
    """``Interface.dbl_skip_src`` returns True for opt-out variants."""
    from shorewall_nft.config.zones import Interface
    assert Interface(name="x", zone="z", options=["nodbl"]).dbl_skip_src
    assert Interface(name="x", zone="z",
                     option_values={"dbl": "none"}).dbl_skip_src
    assert Interface(name="x", zone="z",
                     option_values={"dbl": "dst"}).dbl_skip_src
    # Inclusion (False)
    assert not Interface(name="x", zone="z").dbl_skip_src
    assert not Interface(name="x", zone="z",
                         option_values={"dbl": "src"}).dbl_skip_src
    assert not Interface(name="x", zone="z",
                         option_values={"dbl": "src-dst"}).dbl_skip_src


def _dbl_jump_rule_for(chain, src_zone: str):
    """Return the dynamic-blacklist jump Rule object in a zone-pair chain."""
    for r in chain.rules:
        if r.verdict_args == "sw_dynamic-blacklist":
            return r
    return None


def test_dbl_nodbl_skips_blacklist_jump_when_only_iface():
    """When the sole iface in src zone has nodbl, no blacklist jump emitted."""
    config = _make_config("nodbl")
    config.settings["DYNAMIC_BLACKLIST"] = "yes"
    ir = build_ir(config)
    # net→loc chain: net's only iface (eth0) is nodbl → no blacklist jump
    chain = ir.chains.get("net-fw")
    assert chain is not None
    rule = _dbl_jump_rule_for(chain, "net")
    assert rule is None, (
        "Expected no dynamic-blacklist jump when src zone's only iface is nodbl"
    )


def test_dbl_jump_unconditional_when_no_iface_opts_out():
    """Default config: blacklist jump emitted without iifname gate."""
    config = _make_config("-")
    config.settings["DYNAMIC_BLACKLIST"] = "yes"
    ir = build_ir(config)
    chain = ir.chains.get("net-fw")
    assert chain is not None
    rule = _dbl_jump_rule_for(chain, "net")
    assert rule is not None
    iifname_match = next(
        (m for m in rule.matches if m.field == "iifname"), None,
    )
    assert iifname_match is None, (
        "Expected no iifname gate when no iface opts out"
    )


# ── dynamic_shared (zone option) ────────────────────────────────────────────

def test_dynamic_shared_zone_option_parsed():
    """``dynamic_shared`` lands in zone.in_options without parser error."""
    config = _make_config("-")
    # Inject a zone with dynamic_shared in IN_OPTIONS column.
    config.zones = [
        _row(["fw", "firewall"], "zones"),
        _row(["net", "ipv4", "-", "dynamic_shared"], "zones"),
        _row(["loc", "ipv4"], "zones"),
    ]
    zones = build_zone_model(config)
    assert "dynamic_shared" in zones.zones["net"].in_options


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
