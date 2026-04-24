"""Internal Representation (IR) for the firewall ruleset.

Transforms parsed Shorewall config into a backend-agnostic IR that
the nft emitter consumes to produce nft -f scripts.
"""

from __future__ import annotations

import logging

from shorewall_nft.compiler.ir._data import (
    _MAC_RE,
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    MarkGeometry,
    Match,
    RateLimitSpec,
    Rule,
    Verdict,
    _is_mac_addr,
    _parse_limit_action,
    _parse_rate_limit,
    is_ipv6_spec,
    split_nft_zone_pair,
)
from shorewall_nft.compiler.ir.spec_rewrite import (
    _AND_MULTISET_RE,
    _BRACKET_SET_RE,
    _has_set_token,
    _normalise_bracket_flags,
    _rewrite_bracket_spec,
    _rewrite_dns_spec,
    _rewrite_dnsr_spec,
    _rewrite_nfset_spec,
    _rewrite_spec_for_family,
    _spec_contains_bracket_ipset,
    _spec_contains_dns_token,
    _spec_contains_dnsr_token,
    _spec_contains_nfset_token,
    expand_line_for_tokens,
)
from shorewall_nft.compiler.verdicts import (
    AuditVerdict,
    CtHelperVerdict,
    EcnClearVerdict,
    MarkVerdict,
    NotrackVerdict,
    SpecialVerdict,
)
from shorewall_nft.config.parser import ConfigLine, ShorewalConfig
from shorewall_nft.config.zones import ZoneModel, build_zone_model
from shorewall_nft.nft.dns_sets import (
    DEFAULT_SET_SIZE,
    DEFAULT_TTL_CEIL,
    DEFAULT_TTL_FLOOR,
    DnsrRegistry,
    DnsSetRegistry,
    canonical_qname,
    is_valid_hostname,
    parse_dnsnames_file,
    qname_to_set_name,
)
from shorewall_nft.nft.nfsets import (
    NfSetRegistry,
    build_nfset_registry,
    nfset_to_set_name,
)

_log = logging.getLogger(__name__)

from shorewall_nft.compiler.ir._build import (
    _ROUTESTOPPED_VALID_OPTIONS,
    _apply_default_actions,
    _create_base_chains,
    _prepend_ct_state_to_zone_pair_chains,
    _process_arprules,
    _process_blacklist,
    _process_blrules,
    _process_conntrack,
    _process_dhcp_interfaces,
    _process_ecn,
    _process_host_options,
    _process_interface_options,
    _process_nfacct,
    _process_notrack,
    _process_policies,
    _process_rawnat,
    _process_routestopped,
    _process_scfilter,
    _process_stoppedrules,
    _process_synparams,
    _set_self_zone_policies,
)
from shorewall_nft.compiler.ir.rules import (
    _MACRO_RE,
    _NATIVE_HANDLED_MACROS,
    _RFC1918_RANGES,
    _SLASH_MACRO_RE,
    _add_rule,
    _expand_macro,
    _expand_zone_list,
    _load_custom_macros,
    _load_standard_macros,
    _parse_verdict,
    _parse_zone_spec,
    _process_rules,
    _sentinel_to_addr,
    _zone_pair_chain_name,
)


def _validate_log_settings(settings: dict) -> None:
    """Validate LOG_BACKEND and LOG_GROUP at build_ir() time.

    Accepted LOG_BACKEND values (case-insensitive):
      ``LOG``     — standard syslog path (nft ``log level ...``)
      ``netlink`` — nfnetlink_log (nft ``log group N``)
      ``NFLOG``   — alias for netlink (upstream Shorewall compat)
      ``ULOG``    — legacy alias for netlink (upstream Shorewall compat)

    Raises ValueError for any other value so the error surfaces at
    compile time, not at script-generation time.
    """
    raw_backend = settings.get("LOG_BACKEND", "LOG")
    if raw_backend is not None:
        normalised = raw_backend.strip().upper()
        accepted = {"LOG", "NETLINK", "NFLOG", "ULOG"}
        if normalised not in accepted:
            raise ValueError(
                f"Invalid LOG_BACKEND value {raw_backend!r}. "
                f"Accepted values: {', '.join(sorted(accepted))}"
            )

    raw_group = settings.get("LOG_GROUP")
    if raw_group is not None:
        try:
            int(raw_group)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid LOG_GROUP value {raw_group!r}: must be an integer "
                f"in the range 0–65535"
            ) from exc


def build_ir(config: ShorewalConfig) -> FirewallIR:
    """Build the complete IR from a parsed config."""
    zones = build_zone_model(config)
    ir = FirewallIR(zones=zones, settings=config.settings)
    ir.mark_geometry = MarkGeometry.from_settings(config.settings)
    ir._fastaccept = config.settings.get("FASTACCEPT", "Yes").lower() in ("yes", "1")

    # Validate log-infrastructure settings early so errors surface at
    # compile time rather than at nft script-generation time.
    _validate_log_settings(config.settings)

    # Seed DNS set registry with global defaults from shorewall.conf;
    # per-name overrides from the ``dnsnames`` config file win over
    # these defaults, and rule-discovered hostnames fall back to them.
    try:
        ir.dns_registry.default_ttl_floor = int(
            config.settings.get("DNS_SET_TTL_FLOOR", DEFAULT_TTL_FLOOR))
    except (TypeError, ValueError):
        ir.dns_registry.default_ttl_floor = DEFAULT_TTL_FLOOR
    try:
        ir.dns_registry.default_ttl_ceil = int(
            config.settings.get("DNS_SET_TTL_CEIL", DEFAULT_TTL_CEIL))
    except (TypeError, ValueError):
        ir.dns_registry.default_ttl_ceil = DEFAULT_TTL_CEIL
    try:
        ir.dns_registry.default_size = int(
            config.settings.get("DNS_SET_SIZE", DEFAULT_SET_SIZE))
    except (TypeError, ValueError):
        ir.dns_registry.default_size = DEFAULT_SET_SIZE

    # Per-name overrides from the ``dnsnames`` config file, if present.
    if getattr(config, "dnsnames", None):
        for spec in parse_dnsnames_file(
            config.dnsnames,
            default_ttl_floor=ir.dns_registry.default_ttl_floor,
            default_ttl_ceil=ir.dns_registry.default_ttl_ceil,
            default_size=ir.dns_registry.default_size,
        ):
            ir.dns_registry.add_spec(spec)

    # Named dynamic nft sets from the ``nfsets`` config file, if present.
    if getattr(config, "nfsets", None):
        ir.nfset_registry = build_nfset_registry(config.nfsets)

    # Load custom macros (user-defined take precedence)
    _load_custom_macros(ir, config.macros)

    # Load standard Shorewall macros (from Shorewall/Macros/)
    _load_standard_macros(ir)

    # Create base chains
    _create_base_chains(ir)

    # Process policies (default actions per zone-pair)
    _process_policies(ir, config.policy, zones)

    # Process NAT (DNAT from rules, SNAT from masq, netmap, static 1:1 nat)
    from shorewall_nft.compiler.nat import (
        extract_nat_rules,
        process_nat,
        process_netmap,
        process_static_nat,
    )
    dnat_rules, filter_rules = extract_nat_rules(config.rules)
    process_nat(ir, config.masq, dnat_rules,
                snat_lines=getattr(config, "snat", None))
    if config.netmap:
        process_netmap(ir, config.netmap)
    if getattr(config, "nat", None):
        process_static_nat(ir, config.nat)

    # Process filter rules (excluding DNAT)
    _process_rules(ir, filter_rules, zones)

    # Process synparams (SYN-flood protection per zone).
    # Must run AFTER _process_rules so zone-pair chains already exist
    # for the TCP SYN guard injection.
    if getattr(config, "synparams", None):
        _process_synparams(ir, config.synparams, zones)

    # Process notrack rules
    if config.notrack:
        _process_notrack(ir, config.notrack, zones)

    # Process rawnat rules (raw-table actions, runs pre-conntrack)
    if getattr(config, "rawnat", None):
        _process_rawnat(ir, config.rawnat, zones)

    # Process arprules (arp family — separate table)
    if getattr(config, "arprules", None):
        _process_arprules(ir, config.arprules)

    # Process proxyarp / proxyndp — emit nft filter rules that make
    # the kernel's proxy_arp / proxy_ndp mechanism visible in the
    # compiled ruleset.  The sysctl + neigh-table apply path runs at
    # start time (in apply_cmds.py); these rules are the compile-time
    # counterpart.
    from shorewall_nft.compiler.proxyarp import (
        emit_proxyarp_nft,
        emit_proxyndp_nft,
        parse_proxyarp,
    )
    _proxy_entries = (
        parse_proxyarp(getattr(config, "proxyarp", None) or []) +
        parse_proxyarp(getattr(config, "proxyndp", None) or [])
    )
    if _proxy_entries:
        emit_proxyarp_nft(ir, _proxy_entries)
        emit_proxyndp_nft(ir, _proxy_entries)

    # Process nfacct (named counter objects in the inet table)
    if getattr(config, "nfacct", None):
        _process_nfacct(ir, config.nfacct)

    # Process scfilter (source CIDR sanity filter)
    if getattr(config, "scfilter", None):
        _process_scfilter(ir, config.scfilter)

    # Process ecn (clear ECN bits per iface/host)
    if getattr(config, "ecn", None):
        _process_ecn(ir, config.ecn)

    # Process conntrack helpers
    if config.conntrack:
        _process_conntrack(ir, config.conntrack)

    # Process mangle/tcrules
    if config.tcrules or config.mangle:
        from shorewall_nft.compiler.tc import process_mangle
        process_mangle(ir, config.tcrules, config.mangle, zones)

    # Process tcinterfaces (simple-device TC shaping) and tcpri (DSCP→priority).
    from shorewall_nft.compiler.tc import (
        _tc_enabled_mode,
        emit_tcpri_nft,
        parse_tcinterfaces,
        parse_tcpri,
    )
    tc_mode = _tc_enabled_mode(config.settings)
    if tc_mode and getattr(config, "tcinterfaces", None):
        ir.tcinterfaces = parse_tcinterfaces(config.tcinterfaces)
    if tc_mode and getattr(config, "tcpri", None):
        ir.tcpris = parse_tcpri(config.tcpri)
        # Emit nft meta mark set rules for each tcpri entry into the
        # mangle-prerouting chain (or forward chain when
        # MARK_IN_FORWARD_CHAIN=Yes).
        from shorewall_nft.compiler.ir._data import ChainType, Hook
        from shorewall_nft.compiler.tc import _mark_in_forward
        if _mark_in_forward(config.settings):
            chain_name = "forward"
        else:
            chain_name = "mangle-prerouting"
        if chain_name not in ir.chains:
            ir.add_chain(Chain(
                name=chain_name,
                chain_type=ChainType.ROUTE,
                hook=Hook.PREROUTING,
                priority=-150,
            ))
        _chain = ir.chains[chain_name]
        from shorewall_nft.compiler.ir._data import Match, Rule, Verdict
        from shorewall_nft.compiler.verdicts import MarkVerdict
        for entry in ir.tcpris:
            rule = Rule()
            if entry.interface != "-":
                rule.matches.append(Match(field="iifname", value=entry.interface))
            if entry.address != "-":
                rule.matches.append(Match(field="ip saddr", value=entry.address))
            if entry.proto != "-":
                rule.matches.append(Match(field="meta l4proto", value=entry.proto))
                if entry.port != "-":
                    rule.matches.append(Match(field=f"{entry.proto} dport", value=entry.port))
            rule.verdict = Verdict.ACCEPT
            rule.verdict_args = MarkVerdict(value=entry.band)
            _chain.rules.append(rule)

    # Add interface-level protections (tcpflags, nosmurfs, mss=) and DHCP
    _process_interface_options(ir, zones)

    # Per-host option rules (tcpflags, nosmurfs, mss=, blacklist)
    _process_host_options(ir, zones)

    # DHCP: interfaces with 'dhcp' option get automatic UDP 67,68 ACCEPT
    _process_dhcp_interfaces(ir, zones)

    # Process legacy blacklist file (simple address/proto/port drop list)
    if getattr(config, "blacklist", None):
        _process_blacklist(ir, config.blacklist)

    # Process blrules (blacklist rules)
    if config.blrules:
        _process_blrules(ir, config.blrules, zones)

    # Process routestopped (legacy)
    if config.routestopped:
        _process_routestopped(ir, config.routestopped, config.settings)

    # Process stoppedrules (modern routestopped successor)
    if getattr(config, "stoppedrules", None):
        _process_stoppedrules(ir, config.stoppedrules, zones)

    # Set self-zone ACCEPT for multi-interface zones and routeback zones
    _set_self_zone_policies(ir, zones)

    # Apply default actions (DROP_DEFAULT, REJECT_DEFAULT)
    _apply_default_actions(ir, config.settings)

    # Process accounting rules
    if config.accounting:
        from shorewall_nft.compiler.accounting import process_accounting
        process_accounting(ir, config.accounting)

    # Process providers (multi-ISP routing)
    from shorewall_nft.compiler.providers import (
        emit_provider_marks,
        parse_providers,
        parse_routes,
        parse_rtrules,
    )
    if config.providers:
        providers = parse_providers(config.providers)
        ir.providers = providers
        # Channel 1: nft mangle-prerouting mark rules
        if providers:
            emit_provider_marks(ir, providers)

    if config.routes:
        ir.routes = parse_routes(config.routes)

    if config.rtrules:
        ir.rtrules = parse_rtrules(config.rtrules)

    # Process tunnels
    if config.tunnels:
        from shorewall_nft.compiler.tunnels import process_tunnels
        process_tunnels(ir, config.tunnels, zones)

    # Process MAC filtering
    if config.maclist:
        from shorewall_nft.compiler.macfilter import process_maclist
        process_maclist(ir, config.maclist,
                        config.settings.get("MACLIST_DISPOSITION", "REJECT"))

    # Docker integration
    from shorewall_nft.compiler.docker import setup_docker
    setup_docker(ir, config.settings)

    # Create action chains (Drop, Reject, Broadcast, etc.)
    from shorewall_nft.compiler.actions import create_action_chains, create_dynamic_blacklist
    create_action_chains(ir)
    create_dynamic_blacklist(ir, config.settings)

    # FASTACCEPT=No: classic shorewall puts `ctstate RELATED,ESTABLISHED
    # -j ACCEPT` + `ctstate INVALID -j DROP` inside every zone-pair chain
    # instead of at the top of the FORWARD base chain. shorewall-nft's
    # base-chain pass already handles the FASTACCEPT=Yes case; mirror
    # the classic behaviour here for FASTACCEPT=No so return traffic
    # through zone-pair chains still gets accepted.
    fastaccept = getattr(ir, "_fastaccept", True)
    _prepend_ct_state_to_zone_pair_chains(
        ir, include_established=not fastaccept)

    # Optimize: run all applicable optimizations
    optimize_level = int(config.settings.get("OPTIMIZE", "8"))
    if optimize_level >= 1:
        from shorewall_nft.compiler.optimize import run_optimizations
        run_optimizations(ir, optimize_level)

    return ir

