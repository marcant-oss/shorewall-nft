"""build_ir() stage functions: per-table compilation passes.

Each ``_process_*`` here implements one pass of the build pipeline,
typically corresponding to one Shorewall config file
(notrack, conntrack, blrules, ecn, ...).  The orchestrator
``build_ir()`` in ``ir/__init__.py`` calls them in order.

Also includes the base-chain creation (``_create_base_chains``) and
zone-policy stages (``_set_self_zone_policies``,
``_apply_default_actions``) used by ``build_ir()``.
"""

from __future__ import annotations

import logging

from shorewall_nft.compiler.ir._data import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    Match,
    RateLimitSpec,
    Rule,
    Verdict,
    _parse_rate_limit,
    is_ipv6_spec,
)
from shorewall_nft.compiler.ir.rules import (
    _parse_verdict,
    _parse_zone_spec,
    _sentinel_to_addr,
    _zone_pair_chain_name,
)
from shorewall_nft.compiler.ir.spec_rewrite import (
    _has_set_token,
    expand_line_for_tokens,
)
from shorewall_nft.compiler.verdicts import (
    CtHelperVerdict,
    EcnClearVerdict,
    NotrackVerdict,
    SpecialVerdict,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.config.zones import ZoneModel

_log = logging.getLogger("shorewall_nft.compiler.ir._build")


def _create_base_chains(ir: FirewallIR) -> None:
    """Create the base filter chains with hooks.

    Each base chain gets ct state established,related accept as first rule
    (standard Shorewall FASTACCEPT semantik).
    """
    for hook, name in [
        (Hook.INPUT, "input"),
        (Hook.FORWARD, "forward"),
        (Hook.OUTPUT, "output"),
    ]:
        chain = Chain(
            name=name,
            chain_type=ChainType.FILTER,
            hook=hook,
            priority=0,
            policy=Verdict.DROP,
        )
        # Base chains mirror Shorewall's iptables architecture:
        # policy DROP, no ct state rules, only dispatch jumps (emitted
        # later by the emitter).  ct state established/related accept
        # and invalid drop live in the zone-pair chains (prepended by
        # _prepend_ct_state_to_zone_pair_chains).
        #
        # FASTACCEPT: if Yes (default), established/related accept is
        # added here so it fires before dispatch — a fast path that
        # skips the per-chain walk for return traffic.
        fastaccept = getattr(ir, '_fastaccept', True)
        if fastaccept:
            chain.rules.append(Rule(
                matches=[Match(field="ct state", value="established,related")],
                verdict=Verdict.ACCEPT,
            ))
        # Loopback always passes — classic Shorewall emits an implicit
        # `-i lo -j ACCEPT` / `-o lo -j ACCEPT` so local services (e.g.
        # pdns-recursor bound to 127.0.0.1 or an Anycast IP on lo, the
        # firewall's own loopback-originated mgmt traffic) work without
        # an explicit `$FW $FW ACCEPT` policy entry.  Forward chain is
        # excluded — you don't forward on lo.
        if hook in (Hook.INPUT, Hook.OUTPUT):
            field = "iifname" if hook == Hook.INPUT else "oifname"
            chain.rules.append(Rule(
                matches=[Match(field=field, value="lo")],
                verdict=Verdict.ACCEPT,
                comment="loopback",
            ))
        # ICMPv6 NDP essentials — MUST be accepted in input/output
        # base chains before dispatch so the kernel can resolve
        # neighbors and receive router advertisements.
        if hook in (Hook.INPUT, Hook.OUTPUT):
            for icmpv6_type in [
                "nd-neighbor-solicit",
                "nd-neighbor-advert",
                "nd-router-solicit",
                "nd-router-advert",
            ]:
                chain.rules.append(Rule(
                    matches=[
                        Match(field="meta l4proto", value="icmpv6"),
                        Match(field="icmpv6 type", value=icmpv6_type),
                    ],
                    verdict=Verdict.ACCEPT,
                    comment="NDP essential",
                ))
        ir.add_chain(chain)


def _prepend_ct_state_to_zone_pair_chains(ir: FirewallIR,
                                          include_established: bool = True,
                                          ) -> None:
    """Prepend ct state rules to every zone-pair chain.

    The verdict for invalid packets is controlled by ``INVALID_DISPOSITION``
    (default: DROP).  When *include_established* is True (FASTACCEPT=No),
    also prepends a ``ct state established,related`` rule whose verdict is
    controlled by ``RELATED_DISPOSITION`` (default: ACCEPT).  A disposition
    of ``CONTINUE`` (upstream Perl semantics: empty string) suppresses the
    rule entirely.

    Zone-pair chains are identified as non-base chains whose names
    contain a dash matching a known zone pair (emitter convention:
    "<src>-<dst>"). Chains starting with "sw_" are action chains —
    skipped.
    """
    from shorewall_nft.compiler.actions import _disposition_to_verdict

    related_disp = ir.settings.get("RELATED_DISPOSITION", "ACCEPT")
    invalid_disp = ir.settings.get("INVALID_DISPOSITION", "DROP")
    # UNTRACKED_DISPOSITION: only emit a rule when explicitly configured
    # AND the disposition resolves to an actual verdict. CONTINUE / NONE /
    # missing → no rule (upstream Shorewall behaviour; emitting a synthetic
    # ``ct state untracked drop`` used to blackhole probes whose packets
    # hadn't yet been pushed through conntrack).
    untracked_disp = ir.settings.get("UNTRACKED_DISPOSITION")

    related_resolved = _disposition_to_verdict(related_disp)
    invalid_resolved = _disposition_to_verdict(invalid_disp)
    untracked_resolved = _disposition_to_verdict(untracked_disp)

    all_zones = set(ir.zones.all_zone_names())
    for name, chain in ir.chains.items():
        if chain.is_base_chain:
            continue
        if name.startswith("sw_"):
            continue
        if "-" not in name:
            continue
        src, _, dst = name.partition("-")
        if src not in all_zones or dst not in all_zones:
            continue
        ct_rules: list[Rule] = []
        if include_established and related_resolved is not None:
            related_verdict, related_audit = related_resolved
            if related_audit is not None:
                ct_rules.append(Rule(
                    matches=[Match(field="ct state",
                                   value="established,related")],
                    verdict=Verdict.ACCEPT,
                    verdict_args=related_audit,
                ))
            ct_rules.append(Rule(
                matches=[Match(field="ct state", value="established,related")],
                verdict=related_verdict,
            ))
        if invalid_resolved is not None:
            invalid_verdict, invalid_audit = invalid_resolved
            if invalid_audit is not None:
                ct_rules.append(Rule(
                    matches=[Match(field="ct state", value="invalid")],
                    verdict=Verdict.ACCEPT,
                    verdict_args=invalid_audit,
                ))
            ct_rules.append(Rule(
                matches=[Match(field="ct state", value="invalid")],
                verdict=invalid_verdict,
            ))
        if untracked_resolved is not None:
            untracked_verdict, untracked_audit = untracked_resolved
            if untracked_audit is not None:
                ct_rules.append(Rule(
                    matches=[Match(field="ct state", value="untracked")],
                    verdict=Verdict.ACCEPT,
                    verdict_args=untracked_audit,
                ))
            ct_rules.append(Rule(
                matches=[Match(field="ct state", value="untracked")],
                verdict=untracked_verdict,
            ))
        # TCP-flags jump — every iptables zone-pair chain emits
        # ``-A <chain> -p tcp -j tcpflags`` right after the ct-prefix
        # block. Without it, TCP packets carrying the SYN+FIN /
        # SYN+RST / FIN+URG+PSH / all-zero flag combinations bypass
        # the ``sw_TCPFlags`` chain and reach the dport-specific
        # accept rules. Surfaced by simlab probe-classes G + H — 305
        # fail_accept on a single fixture before this fix.
        #
        # Only emit when ``sw_TCPFlags`` actually exists in the IR
        # (TCP_FLAGS_DISPOSITION may be CONTINUE/NONE which keeps the
        # chain empty; in that case there is nothing to drop on, and
        # an unconditional jump would be dead code).
        if "sw_TCPFlags" in ir.chains and ir.chains["sw_TCPFlags"].rules:
            ct_rules.append(Rule(
                matches=[Match(field="meta l4proto", value="tcp")],
                verdict=Verdict.JUMP,
                verdict_args="sw_TCPFlags",
            ))
        # Smurfs jump — upstream emits ``ct state invalid,new,untracked
        # counter jump smurfs`` on every zone-pair chain. The
        # ``sw_DropSmurfs`` chain handles broadcast / multicast saddr
        # filtering; without the per-pair jump it only fires on input,
        # leaving forwarded smurf-source traffic untouched.
        if "sw_DropSmurfs" in ir.chains and ir.chains["sw_DropSmurfs"].rules:
            ct_rules.append(Rule(
                matches=[Match(field="ct state",
                               value="invalid,new,untracked")],
                verdict=Verdict.JUMP,
                verdict_args="sw_DropSmurfs",
            ))
        chain.rules = ct_rules + list(chain.rules)


def _process_policies(ir: FirewallIR, policy_lines: list[ConfigLine],
                      zones: ZoneModel) -> None:
    """Process policy definitions into default chain rules."""
    for line in policy_lines:
        cols = line.columns
        if len(cols) < 3:
            continue

        source = cols[0]
        dest = cols[1]
        policy_str = cols[2].upper()
        log_level = cols[3] if len(cols) > 3 else None

        verdict = _parse_verdict(policy_str)
        if verdict is None:
            continue

        # Resolve $FW
        if source == "$FW":
            source = zones.firewall_zone
        if dest == "$FW":
            dest = zones.firewall_zone

        # "all" means all zones
        sources = zones.all_zone_names() if source in ("all", "any") else [source]
        dests = zones.all_zone_names() if dest in ("all", "any") else [dest]

        for src in sources:
            for dst in dests:
                # Skip self-zone pairs unless explicitly configured
                # (e.g. "loc loc ACCEPT" is explicit)
                if src == dst:
                    if source in ("all", "any") or dest in ("all", "any"):
                        continue  # Don't create self-zone from "all" expansion
                    # Explicit self-zone policy (e.g. "loc loc ACCEPT")
                chain_name = _zone_pair_chain_name(src, dst, zones)
                chain = ir.get_or_create_chain(chain_name)
                if chain.policy is None:
                    chain.policy = verdict


def _process_notrack(ir: FirewallIR, notrack_lines: list[ConfigLine],
                     zones: ZoneModel) -> None:
    """Process notrack rules into raw-priority chains.

    Format: SOURCE DESTINATION PROTO DEST_PORT SOURCE_PORT
    """
    # Create raw chain if needed
    if "raw-prerouting" not in ir.chains:
        ir.add_chain(Chain(
            name="raw-prerouting",
            chain_type=ChainType.FILTER,
            hook=Hook.PREROUTING,
            priority=-300,
        ))
    if "raw-output" not in ir.chains:
        ir.add_chain(Chain(
            name="raw-output",
            chain_type=ChainType.FILTER,
            hook=Hook.OUTPUT,
            priority=-300,
        ))

    for line in notrack_lines:
        cols = line.columns
        if len(cols) < 3:
            continue

        # nfset/dns/dnsr token pre-pass: clone for v4+v6 when tokens present.
        found, expanded = expand_line_for_tokens(line, 0, 1, ir)
        if found:
            _process_notrack(ir, expanded, zones)
            continue

        source_spec = cols[0]
        dest_spec = cols[1]
        proto = cols[2] if len(cols) > 2 else None
        dport = cols[3] if len(cols) > 3 else None
        sport = cols[4] if len(cols) > 4 else None

        if proto == "-":
            proto = None
        if dport == "-":
            dport = None
        if sport == "-":
            sport = None

        src_zone, src_addr = _parse_zone_spec(source_spec, zones)
        src_addr = _sentinel_to_addr(src_zone, src_addr)

        # Determine chain: $FW source -> output, else -> prerouting
        fw = zones.firewall_zone
        if src_zone == fw:
            chain = ir.chains["raw-output"]
        else:
            chain = ir.chains["raw-prerouting"]

        rule = Rule(
            verdict=Verdict.ACCEPT,
            verdict_args=NotrackVerdict(),
            source_file=line.file,
            source_line=line.lineno,
        source_raw=line.raw,
        )

        if src_addr:
            rule.matches.append(Match(field="ip saddr", value=src_addr))

        _dst_zone, dst_addr = _parse_zone_spec(dest_spec, zones)
        dst_addr = _sentinel_to_addr(_dst_zone, dst_addr)
        if dst_addr and dst_addr != "0.0.0.0/0":
            rule.matches.append(Match(field="ip daddr", value=dst_addr))

        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))
            if sport:
                rule.matches.append(Match(field=f"{proto} sport", value=sport))

        chain.rules.append(rule)


def _process_conntrack(ir: FirewallIR, conntrack_lines: list[ConfigLine]) -> None:
    """Process conntrack helper rules.

    Format: CT:helper:NAME:POLICY SOURCE DESTINATION PROTO DEST_PORT
    """
    # Create ct helper chain if needed
    if "ct-helpers" not in ir.chains:
        ir.add_chain(Chain(
            name="ct-helpers",
            chain_type=ChainType.FILTER,
            hook=Hook.PREROUTING,
            priority=-200,  # Between raw and conntrack
        ))

    for line in conntrack_lines:
        cols = line.columns
        if not cols:
            continue

        action = cols[0]
        if not action.startswith("CT:helper:"):
            continue

        # nfset/dns/dnsr token pre-pass on SOURCE(col 1) + DEST(col 2).
        found, expanded = expand_line_for_tokens(line, 1, 2, ir)
        if found:
            _process_conntrack(ir, expanded)
            continue

        # Parse CT:helper:NAME:POLICY
        parts = action.split(":")
        helper_name = parts[2] if len(parts) > 2 else ""
        # policy = parts[3] if len(parts) > 3 else ""

        proto = cols[3] if len(cols) > 3 else None
        dport = cols[4] if len(cols) > 4 else None

        if proto == "-":
            proto = None
        if dport == "-":
            dport = None

        chain = ir.chains["ct-helpers"]
        rule = Rule(
            verdict=Verdict.ACCEPT,
            verdict_args=CtHelperVerdict(name=helper_name),
            source_file=line.file,
            source_line=line.lineno,
        source_raw=line.raw,
        )

        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))

        chain.rules.append(rule)  # conntrack helper


def _process_interface_options(ir: FirewallIR, zones: ZoneModel) -> None:
    """Generate nft rules for interface-level protections.

    Handles tcpflags, nosmurfs, and mss= interface options.
    tcpflags/nosmurfs rules are inserted into the input chain.
    mss= rules are inserted into the forward chain (mangle-postrouting).
    """
    input_chain = ir.chains.get("input")
    if not input_chain:
        return

    from shorewall_nft.compiler.actions import _disposition_to_verdict
    tcpflags_resolved = _disposition_to_verdict(
        ir.settings.get("TCP_FLAGS_DISPOSITION", "DROP"))
    smurf_resolved = _disposition_to_verdict(
        ir.settings.get("SMURF_DISPOSITION", "DROP"))
    # CONTINUE / NONE / missing → skip the per-iface protection emit.
    tcpflags_verdict, tcpflags_audit = (
        tcpflags_resolved if tcpflags_resolved is not None else (None, None)
    )
    smurf_verdict, smurf_audit = (
        smurf_resolved if smurf_resolved is not None else (None, None)
    )

    protection_rules: list[Rule] = []

    for zone in zones.zones.values():
        for iface in zone.interfaces:
            opts = set(iface.options)
            oval = iface.option_values

            if "tcpflags" in opts and tcpflags_verdict is not None:
                # SYN+FIN
                if tcpflags_audit is not None:
                    protection_rules.append(Rule(
                        matches=[
                            Match(field="iifname", value=iface.name),
                            Match(field="tcp flags & (syn|fin)",
                                  value="syn|fin"),
                        ],
                        verdict=Verdict.ACCEPT,
                        verdict_args=tcpflags_audit,
                        comment=f"tcpflags:audit:{iface.name}",
                    ))
                protection_rules.append(Rule(
                    matches=[
                        Match(field="iifname", value=iface.name),
                        Match(field="tcp flags & (syn|fin)", value="syn|fin"),
                    ],
                    verdict=tcpflags_verdict,
                    comment=f"tcpflags:{iface.name}",
                ))
                # SYN+RST
                if tcpflags_audit is not None:
                    protection_rules.append(Rule(
                        matches=[
                            Match(field="iifname", value=iface.name),
                            Match(field="tcp flags & (syn|rst)",
                                  value="syn|rst"),
                        ],
                        verdict=Verdict.ACCEPT,
                        verdict_args=tcpflags_audit,
                        comment=f"tcpflags:audit:{iface.name}",
                    ))
                protection_rules.append(Rule(
                    matches=[
                        Match(field="iifname", value=iface.name),
                        Match(field="tcp flags & (syn|rst)", value="syn|rst"),
                    ],
                    verdict=tcpflags_verdict,
                    comment=f"tcpflags:{iface.name}",
                ))

            if "nosmurfs" in opts and smurf_verdict is not None:
                if smurf_audit is not None:
                    protection_rules.append(Rule(
                        matches=[
                            Match(field="iifname", value=iface.name),
                            Match(field="fib saddr type", value="broadcast"),
                        ],
                        verdict=Verdict.ACCEPT,
                        verdict_args=smurf_audit,
                        comment=f"nosmurfs:audit:{iface.name}",
                    ))
                protection_rules.append(Rule(
                    matches=[
                        Match(field="iifname", value=iface.name),
                        Match(field="fib saddr type", value="broadcast"),
                    ],
                    verdict=smurf_verdict,
                    comment=f"nosmurfs:{iface.name}",
                ))

            # mss=N — emit a TCP MSS clamp rule in the mangle-forward chain.
            # Upstream Shorewall: `tcp option maxseg size set <N>` on SYN
            # packets entering/leaving this interface.
            mss_str = oval.get("mss")
            if mss_str is not None:
                try:
                    mss_val = int(mss_str)
                except ValueError:
                    mss_val = None
                if mss_val is not None and mss_val >= 500:
                    _emit_mss_clamp_rule(ir, iface.name, mss_val)

    # Insert after ct state rules (positions 0-1) but before dispatch
    insert_pos = 2
    for rule in protection_rules:
        input_chain.rules.insert(insert_pos, rule)
        insert_pos += 1


def _emit_mss_clamp_rule(ir: FirewallIR, iface_name: str, mss: int) -> None:
    """Emit a TCP MSS clamp rule for *iface_name* into the mangle-forward chain.

    Uses nft's ``tcp option maxseg size set <N>`` statement on TCP SYN
    packets transiting through the given interface.  The rule is placed in
    ``mangle-forward`` (priority -150) — the same priority that Shorewall
    uses for its TCPMSS target rules in iptables ``mangle FORWARD``.
    """
    from shorewall_nft.compiler.ir._data import Chain, ChainType, Hook

    chain_name = "mangle-forward"
    if chain_name not in ir.chains:
        ir.add_chain(Chain(
            name=chain_name,
            chain_type=ChainType.ROUTE,
            hook=Hook.FORWARD,
            priority=-150,
        ))
    chain = ir.chains[chain_name]

    # ingress direction (iifname)
    r_in = Rule(
        verdict=Verdict.ACCEPT,
        comment=f"mss:{iface_name}",
    )
    r_in.matches.append(Match(field="iifname", value=iface_name))
    r_in.matches.append(Match(field="meta l4proto", value="tcp"))
    r_in.matches.append(Match(field="tcp flags & syn", value="syn"))
    r_in.matches.append(Match(
        field="inline",
        value=f"tcp option maxseg size set {mss}",
    ))
    chain.rules.append(r_in)

    # egress direction (oifname)
    r_out = Rule(
        verdict=Verdict.ACCEPT,
        comment=f"mss:{iface_name}",
    )
    r_out.matches.append(Match(field="oifname", value=iface_name))
    r_out.matches.append(Match(field="meta l4proto", value="tcp"))
    r_out.matches.append(Match(field="tcp flags & syn", value="syn"))
    r_out.matches.append(Match(
        field="inline",
        value=f"tcp option maxseg size set {mss}",
    ))
    chain.rules.append(r_out)


def _process_host_options(ir: FirewallIR, zones: ZoneModel) -> None:
    """Generate nft rules for per-host OPTIONS (from the hosts file).

    Upstream reference: ``Zones.pm::process_host`` — valid per-host options
    are: ``routeback``, ``blacklist``, ``tcpflags``, ``nosmurfs``,
    ``maclist``, ``mss=N``, ``ipsec``, ``broadcast``, ``destonly``,
    ``sourceonly``.

    Implementation approach:

    * ``tcpflags``  / ``nosmurfs`` — emit the same protection rules as the
      interface-level variants, but scoped to the host addresses.
    * ``mss=N``     — emit a TCP MSS clamp rule scoped to the host.
    * ``blacklist`` — add the host addresses to the dynamic-blacklist nft
      set match (emit a ``ip saddr @blacklist drop`` rule before the zone
      dispatch).
    * ``ipsec``     — mark the zone as IPSEC type and emit an
      ``meta secpath exists`` / narrow ``ipsec <dir> reqid N`` match on
      all rules entering/leaving chains that involve this host (handled
      at rule-emit time by tagging the zone; see
      ``_build_ipsec_policy_clause``).
    * ``routeback``,``broadcast``,``destonly``,``sourceonly`` — annotate
      only (affect chain dispatch ordering, not individual rules).
    * ``maclist``   — MAC-list enforcement (stub; full maclist emit is
      handled by the macfilter module when it exists).
    """
    input_chain = ir.chains.get("input")
    if not input_chain:
        return

    for zone in zones.zones.values():
        for host in zone.hosts:
            opts = set(host.options)
            oval = host.option_values

            for addr in host.addresses:
                if not addr or addr == "-":
                    continue

                # Determine address family field
                from shorewall_nft.compiler.ir._data import is_ipv6_spec
                is_v6 = is_ipv6_spec(addr)
                saddr_field = "ip6 saddr" if is_v6 else "ip saddr"

                # tcpflags — SYN/FIN and SYN/RST checks for this host
                if "tcpflags" in opts:
                    for flags in ("syn|fin", "syn|rst"):
                        r = Rule(
                            matches=[
                                Match(field="iifname", value=host.interface),
                                Match(field=saddr_field, value=addr),
                                Match(field=f"tcp flags & ({flags})", value=flags),
                            ],
                            verdict=Verdict.DROP,
                            comment=f"tcpflags:host:{addr}",
                        )
                        input_chain.rules.append(r)

                # nosmurfs — drop broadcast sources from this host
                if "nosmurfs" in opts and not is_v6:
                    r = Rule(
                        matches=[
                            Match(field="iifname", value=host.interface),
                            Match(field=saddr_field, value=addr),
                            Match(field="fib saddr type", value="broadcast"),
                        ],
                        verdict=Verdict.DROP,
                        comment=f"nosmurfs:host:{addr}",
                    )
                    input_chain.rules.append(r)

                # mss=N — TCP MSS clamp scoped to this host source address
                mss_str = oval.get("mss")
                if mss_str is not None:
                    try:
                        mss_val = int(mss_str)
                    except ValueError:
                        mss_val = None
                    if mss_val is not None and mss_val >= 500:
                        _emit_mss_clamp_rule(ir, host.interface, mss_val)

                # blacklist — drop packets whose source is in the blacklist set
                if "blacklist" in opts:
                    r = Rule(
                        matches=[
                            Match(field="iifname", value=host.interface),
                            Match(field=saddr_field, value=addr),
                        ],
                        verdict=Verdict.DROP,
                        comment=f"blacklist:host:{addr}",
                    )
                    input_chain.rules.append(r)


def _process_dhcp_interfaces(ir: FirewallIR, zones: ZoneModel) -> None:
    """Generate DHCP allow rules for interfaces with 'dhcp' option.

    Shorewall automatically allows UDP 67,68 (DHCP) on interfaces
    configured with the dhcp option. This creates rules in both
    the input chain (for DHCP to the firewall) and in all zone-pair
    chains involving this zone (for DHCP forwarding).
    """
    for zone in zones.zones.values():
        for iface in zone.interfaces:
            if "dhcp" not in iface.options:
                continue

            fw = zones.firewall_zone

            def _add_dhcp_to_chain(chain_name: str) -> None:
                chain = ir.get_or_create_chain(chain_name)
                has_dhcp = any(
                    any(m.value in ("67,68", "67", "68") for m in r.matches if "dport" in m.field)
                    for r in chain.rules
                )
                if not has_dhcp:
                    chain.rules.append(Rule(
                        matches=[
                            Match(field="meta l4proto", value="udp"),
                            Match(field="udp dport", value="67,68"),
                        ],
                        verdict=Verdict.ACCEPT,
                        comment=f"dhcp:{iface.name}",
                    ))
                    chain.rules.append(Rule(
                        matches=[
                            Match(field="meta l4proto", value="udp"),
                            Match(field="udp dport", value="546,547"),
                        ],
                        verdict=Verdict.ACCEPT,
                        comment=f"dhcpv6:{iface.name}",
                    ))

            # DHCP to/from firewall (INPUT/OUTPUT chains)
            _add_dhcp_to_chain(f"{zone.name}-{fw}")
            _add_dhcp_to_chain(f"{fw}-{zone.name}")

            # Self-zone DHCP (bridge interfaces)
            _add_dhcp_to_chain(f"{zone.name}-{zone.name}")

            # DHCP forwarding from this zone to ALL other zones
            # (Shorewall generates DHCP allow in all zone-pair chains
            # where the dhcp-enabled zone is the source)
            for other_zone in zones.zones.values():
                if other_zone.name == zone.name or other_zone.is_firewall:
                    continue
                _add_dhcp_to_chain(f"{zone.name}-{other_zone.name}")
                _add_dhcp_to_chain(f"{other_zone.name}-{zone.name}")


def _process_blacklist(ir: FirewallIR,
                       blacklist_lines: list[ConfigLine]) -> None:
    """Process the legacy ``blacklist`` file into drop rules.

    Legacy format (pre-4.4.25): each line is one of::

        ADDRESS
        ADDRESS  PROTO  PORT

    All entries are "src" (source-match) drops.  Upstream Perl
    ``convert_blacklist`` translates these to ``blrules`` entries;
    we emit direct drop rules instead, respecting
    ``BLACKLIST_DISPOSITION``.

    The blacklist chain created here is named ``blacklist`` (same as
    the one used by ``_process_blrules`` so both sources share it).
    """
    if not blacklist_lines:
        return

    from shorewall_nft.compiler.actions import _disposition_to_verdict
    disp = ir.settings.get("BLACKLIST_DISPOSITION", "DROP")
    resolved = _disposition_to_verdict(disp)
    # CONTINUE / NONE on the blacklist file makes no sense (every entry
    # would fall through); fall back to DROP.
    verdict, _audit = resolved if resolved is not None else (Verdict.DROP, None)

    if "blacklist" not in ir.chains:
        ir.add_chain(Chain(name="blacklist"))
    chain = ir.chains["blacklist"]

    for line in blacklist_lines:
        cols = line.columns
        if not cols:
            continue
        addr = cols[0]
        proto = cols[1] if len(cols) > 1 and cols[1] != "-" else None
        port = cols[2] if len(cols) > 2 and cols[2] != "-" else None

        from shorewall_nft.compiler.ir._data import is_ipv6_spec
        saddr_field = "ip6 saddr" if is_ipv6_spec(addr) else "ip saddr"
        rule = Rule(
            verdict=verdict,
            source_file=line.file,
            source_line=line.lineno,
            source_raw=line.raw,
        )
        rule.matches.append(Match(field=saddr_field, value=addr))
        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if port:
                rule.matches.append(Match(field=f"{proto} dport", value=port))
        chain.rules.append(rule)


def _process_blrules(ir: FirewallIR, blrules: list[ConfigLine],
                     zones: ZoneModel) -> None:
    """Process blacklist rules into a blacklist chain.

    blrules format: ACTION SOURCE DEST PROTO DPORT SPORT ORIGDEST ...
    """
    if not blrules:
        return

    # Create blacklist chain, called from input/forward before zone dispatch
    if "blacklist" not in ir.chains:
        ir.add_chain(Chain(name="blacklist"))

    chain = ir.chains["blacklist"]

    for line in blrules:
        cols = line.columns
        if not cols:
            continue

        # nfset/dns/dnsr token pre-pass on SOURCE(col 1) + DEST(col 2).
        found, expanded = expand_line_for_tokens(line, 1, 2, ir)
        if found:
            _process_blrules(ir, expanded, zones)
            continue

        action_str = cols[0]
        source_spec = cols[1] if len(cols) > 1 else "-"
        dest_spec = cols[2] if len(cols) > 2 else "-"
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None

        # Map blacklist actions
        if action_str.lower() in ("blacklog", "blacklist"):
            verdict = Verdict.DROP
        elif action_str.upper() == "DROP":
            verdict = Verdict.DROP
        elif action_str.upper() == "REJECT":
            verdict = Verdict.REJECT
        else:
            verdict = Verdict.DROP

        rule = Rule(
            verdict=verdict,
            source_file=line.file,
            source_line=line.lineno,
        source_raw=line.raw,
        )

        if source_spec and source_spec != "-":
            zone, addr = _parse_zone_spec(source_spec, zones)
            addr = _sentinel_to_addr(zone, addr)
            if addr:
                rule.matches.append(Match(field="ip saddr", value=addr))

        if dest_spec and dest_spec != "-":
            zone, addr = _parse_zone_spec(dest_spec, zones)
            addr = _sentinel_to_addr(zone, addr)
            if addr:
                rule.matches.append(Match(field="ip daddr", value=addr))

        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))

        chain.rules.append(rule)


_ROUTESTOPPED_VALID_OPTIONS = {
    "routeback", "source", "dest", "critical", "notrack",
}


def _process_routestopped(ir: FirewallIR, routestopped: list[ConfigLine],
                          settings: dict[str, str] | None = None) -> None:
    """Process routestopped rules.

    Renders Shorewall's full ``routestopped`` semantics into the
    standalone ``inet shorewall_stopped`` table (built by
    :func:`shorewall_nft.nft.emitter.emit_stopped_nft`). Loaded by
    ``shorewall-nft stop`` after deleting the running ruleset.

    Format::

        INTERFACE  HOST(S)  OPTIONS  PROTO  DPORT  SPORT

    Supported OPTIONS (comma-separated):
      * ``routeback`` — also forward between hosts on the same iface
      * ``source``    — only ingress (no matching output rule)
      * ``dest``      — only egress  (no matching input rule)
      * ``critical``  — recorded but currently a no-op (we don't ship
        a ``clear`` command yet)
      * ``notrack``   — disables conntrack for this iface/host via a
        ``stopped-raw-prerouting`` chain at priority raw

    Global setting ``ROUTESTOPPED_OPEN=Yes`` opens every interface
    listed in routestopped wide (no host/proto filtering) — matching
    Shorewall's "panic but keep the network up" mode.

    Base chain layout:
      * stopped-input    — policy DROP, ACCEPT for matching traffic
      * stopped-output   — policy DROP, ACCEPT for matching traffic
      * stopped-forward  — policy DROP, ACCEPT for routeback pairs
      * stopped-raw-prerouting — only present if any rule sets notrack

    Loopback ACCEPT and ``ct state established,related`` are added
    unconditionally so local services and active mgmt sessions
    survive a stop window.
    """
    settings = settings or {}
    open_mode = settings.get("ROUTESTOPPED_OPEN", "No").lower() in (
        "yes", "1", "true")

    stopped_input = Chain(
        name="stopped-input",
        chain_type=ChainType.FILTER,
        hook=Hook.INPUT,
        priority=0,
        policy=Verdict.DROP,
    )
    stopped_output = Chain(
        name="stopped-output",
        chain_type=ChainType.FILTER,
        hook=Hook.OUTPUT,
        priority=0,
        policy=Verdict.DROP,
    )
    stopped_forward = Chain(
        name="stopped-forward",
        chain_type=ChainType.FILTER,
        hook=Hook.FORWARD,
        priority=0,
        policy=Verdict.DROP,
    )

    # Loopback always passes — otherwise local services break.
    lo_in = Rule(verdict=Verdict.ACCEPT)
    lo_in.matches.append(Match(field="iifname", value="lo"))
    stopped_input.rules.append(lo_in)
    lo_out = Rule(verdict=Verdict.ACCEPT)
    lo_out.matches.append(Match(field="oifname", value="lo"))
    stopped_output.rules.append(lo_out)

    # Established/related survive — otherwise short-lived stop windows
    # would tear down every active mgmt session.
    est_in = Rule(verdict=Verdict.ACCEPT)
    est_in.matches.append(Match(field="ct state", value="established,related"))
    stopped_input.rules.append(est_in)
    est_out = Rule(verdict=Verdict.ACCEPT)
    est_out.matches.append(Match(field="ct state", value="established,related"))
    stopped_output.rules.append(est_out)

    ir.stopped_chains[stopped_input.name] = stopped_input
    ir.stopped_chains[stopped_output.name] = stopped_output
    ir.stopped_chains[stopped_forward.name] = stopped_forward

    # notrack chain is added lazily — only if any rule needs it.
    stopped_raw: Chain | None = None

    def _saddr_field(host: str) -> str:
        return "ip6 saddr" if is_ipv6_spec(host) else "ip saddr"

    def _daddr_field(host: str) -> str:
        return "ip6 daddr" if is_ipv6_spec(host) else "ip daddr"

    def _add_proto(rule: Rule, proto: str | None,
                   dport: str | None, sport: str | None) -> None:
        if not proto:
            return
        rule.matches.append(Match(field="meta l4proto", value=proto))
        if dport:
            rule.matches.append(Match(field=f"{proto} dport", value=dport))
        if sport:
            rule.matches.append(Match(field=f"{proto} sport", value=sport))

    for line in routestopped:
        cols = line.columns
        if not cols:
            continue

        iface = cols[0]
        hosts = cols[1] if len(cols) > 1 and cols[1] != "-" else None
        options_raw = cols[2] if len(cols) > 2 and cols[2] != "-" else ""
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        opts = {o.strip() for o in options_raw.split(",") if o.strip()}
        unknown = opts - _ROUTESTOPPED_VALID_OPTIONS
        if unknown:
            # Best effort: keep going, but warn — matches Shorewall's
            # behaviour of accepting and ignoring unknown options.
            import warnings
            warnings.warn(
                f"routestopped {line.file}:{line.lineno}: unknown "
                f"option(s) {sorted(unknown)} — ignored",
                stacklevel=2)

        emit_in = "dest" not in opts
        emit_out = "source" not in opts
        do_routeback = "routeback" in opts
        do_notrack = "notrack" in opts

        # ROUTESTOPPED_OPEN: collapse to wildcard accept on this
        # interface, ignoring host/proto filtering. The single rule
        # per direction supersedes everything else for this iface.
        if open_mode:
            if emit_in:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                stopped_input.rules.append(r)
            if emit_out:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="oifname", value=iface))
                stopped_output.rules.append(r)
            if do_routeback:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                r.matches.append(Match(field="oifname", value=iface))
                stopped_forward.rules.append(r)
            if do_notrack:
                if stopped_raw is None:
                    stopped_raw = Chain(
                        name="stopped-raw-prerouting",
                        chain_type=ChainType.FILTER,
                        hook=Hook.PREROUTING,
                        priority=-300,  # raw
                        policy=None,
                    )
                    ir.stopped_chains[stopped_raw.name] = stopped_raw
                r = Rule(verdict=Verdict.ACCEPT, verdict_args=NotrackVerdict())
                r.matches.append(Match(field="iifname", value=iface))
                stopped_raw.rules.append(r)
            continue

        host_list: list[str | None]
        if hosts:
            host_list = [h.strip() for h in hosts.split(",") if h.strip()]
        else:
            host_list = [None]  # iface-wide

        for h in host_list:
            if emit_in:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                if h:
                    r.matches.append(Match(field=_saddr_field(h), value=h))
                _add_proto(r, proto, dport, sport)
                stopped_input.rules.append(r)

            if emit_out:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="oifname", value=iface))
                if h:
                    r.matches.append(Match(field=_daddr_field(h), value=h))
                # Output direction swaps src/dst port semantics —
                # keep dport on dport (it's the listening port on
                # the host we're talking to) and sport on sport.
                _add_proto(r, proto, dport, sport)
                stopped_output.rules.append(r)

            if do_routeback:
                r = Rule(verdict=Verdict.ACCEPT)
                r.matches.append(Match(field="iifname", value=iface))
                r.matches.append(Match(field="oifname", value=iface))
                if h:
                    # transit between two hosts on the same iface —
                    # the listed host can be either side, so we emit
                    # one rule per side instead of constraining both.
                    r.matches.append(Match(field=_daddr_field(h), value=h))
                _add_proto(r, proto, dport, sport)
                stopped_forward.rules.append(r)

            if do_notrack:
                if stopped_raw is None:
                    stopped_raw = Chain(
                        name="stopped-raw-prerouting",
                        chain_type=ChainType.FILTER,
                        hook=Hook.PREROUTING,
                        priority=-300,  # raw
                        policy=None,
                    )
                    ir.stopped_chains[stopped_raw.name] = stopped_raw
                r = Rule(verdict=Verdict.ACCEPT, verdict_args=NotrackVerdict())
                r.matches.append(Match(field="iifname", value=iface))
                if h:
                    r.matches.append(Match(field=_saddr_field(h), value=h))
                _add_proto(r, proto, dport, sport)
                stopped_raw.rules.append(r)


def _process_scfilter(ir: FirewallIR, scfilter_lines: list[ConfigLine]) -> None:
    """Process the ``scfilter`` config file (source CIDR sanity filter).

    scfilter declares per-interface allow-lists for source IPs:
    any packet whose source address does NOT fall in the listed
    CIDRs gets dropped at ingress. Useful as an anti-spoof gate
    on uplinks where you know the legitimate source ranges.

    We emit drop rules at the top of the forward + input base
    chains (so they fire before any zone dispatch). The simpler
    form is one rule per (iface, !cidr-list) tuple:

        iifname X ip saddr != { allowed cidrs } drop

    Format::

        INTERFACE  HOST(S)  OPTIONS
    """
    if not scfilter_lines:
        return

    # Insert at the top of the forward + input chains. Both base
    # chains exist by now (created in _create_base_chains).
    forward = ir.chains.get("forward")
    inp = ir.chains.get("input")

    inserts: list[Rule] = []
    for line in scfilter_lines:
        cols = line.columns
        if not cols:
            continue
        iface = cols[0]
        hosts_raw = cols[1] if len(cols) > 1 and cols[1] != "-" else ""
        if not hosts_raw:
            continue
        hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]
        v4 = [h for h in hosts if not is_ipv6_spec(h)]
        v6 = [h for h in hosts if is_ipv6_spec(h)]

        if v4:
            r = Rule(verdict=Verdict.DROP)
            r.matches.append(Match(field="iifname", value=iface))
            r.matches.append(Match(
                field="ip saddr",
                value="{ " + ", ".join(v4) + " }",
                negate=True))
            inserts.append(r)
        if v6:
            r = Rule(verdict=Verdict.DROP)
            r.matches.append(Match(field="iifname", value=iface))
            r.matches.append(Match(
                field="ip6 saddr",
                value="{ " + ", ".join(v6) + " }",
                negate=True))
            inserts.append(r)

    # Prepend so the sanity drop fires before zone dispatch.
    if forward:
        forward.rules = inserts + list(forward.rules)
    if inp:
        inp.rules = inserts + list(inp.rules)


def _process_ecn(ir: FirewallIR, ecn_lines: list[ConfigLine]) -> None:
    """Process the ``ecn`` config file (clear ECN bits per iface/host).

    Shorewall's ``ecn`` file lists (interface, host) tuples whose
    TCP traffic should have ECN bits cleared — historically used
    when a buggy peer rejects ECN-marked packets. The original
    implementation used iptables' ``-j ECN --ecn-tcp-remove``
    target. nftables expresses the same with::

        ip dscp set ip dscp and 0xfc

    on the matching tcp flow (DSCP field is 6 bits, ECN is the
    low 2 bits — masking with 0xfc clears them). The rule lands
    in the mangle-postrouting chain so the change applies just
    before the packet leaves the box.

    Format::

        INTERFACE  HOST(S)
    """
    if not ecn_lines:
        return

    # Lazily create the mangle-postrouting chain.
    chain_name = "mangle-postrouting"
    if chain_name not in ir.chains:
        ir.add_chain(Chain(
            name=chain_name,
            chain_type=ChainType.ROUTE,
            hook=Hook.POSTROUTING,
            priority=-150,  # mangle
        ))
    chain = ir.chains[chain_name]

    for line in ecn_lines:
        cols = line.columns
        if not cols:
            continue
        iface = cols[0]
        hosts_raw = cols[1] if len(cols) > 1 and cols[1] != "-" else None

        # nfset/dns/dnsr token pre-pass: the HOST column may carry a set
        # token instead of a literal CIDR list.  Clone for v4+v6 and recurse.
        if hosts_raw and _has_set_token(hosts_raw):
            found, expanded = expand_line_for_tokens(line, 1, None, ir)
            if found:
                _process_ecn(ir, expanded)
                continue

        hosts: list[str | None]
        if hosts_raw:
            hosts = [h.strip() for h in hosts_raw.split(",") if h.strip()]
        else:
            hosts = [None]

        for h in hosts:
            r = Rule(
                verdict=Verdict.ACCEPT,
                verdict_args=EcnClearVerdict(),
            )
            r.matches.append(Match(field="oifname", value=iface))
            r.matches.append(Match(field="meta l4proto", value="tcp"))
            if h:
                field = "ip6 daddr" if is_ipv6_spec(h) else "ip daddr"
                r.matches.append(Match(field=field, value=h))
            chain.rules.append(r)


def _process_nfacct(ir: FirewallIR, nfacct_lines: list[ConfigLine]) -> None:
    """Process the ``nfacct`` config file into named counter objects.

    Shorewall's ``nfacct`` file declares named accounting objects
    that the kernel maintains via the ``nfnetlink_acct`` module.
    The closest nft equivalent is a named counter object —
    ``counter <name> { packets N bytes M }`` — which can be
    referenced from rules with ``counter name "<name>"``.

    We map nfacct rows onto nft named counters and store them in
    ``ir.nfacct_counters`` for the emitter to declare at the top
    of the inet shorewall table. Initial values from the file
    survive the table flush so reload-and-keep-counts is at
    least theoretically possible (in practice nft resets named
    counters on table flush; the field is here to capture intent
    if/when we wire a counter snapshot/restore path through
    libnftables).

    Format::

        NAME  [PACKETS  [BYTES]]
    """
    for line in nfacct_lines:
        cols = line.columns
        if not cols:
            continue
        name = cols[0]
        try:
            packets = int(cols[1]) if len(cols) > 1 and cols[1] != "-" else 0
        except ValueError:
            packets = 0
        try:
            byte_count = int(cols[2]) if len(cols) > 2 and cols[2] != "-" else 0
        except ValueError:
            byte_count = 0
        ir.nfacct_counters[name] = (packets, byte_count)


def _process_arprules(ir: FirewallIR, arprules: list[ConfigLine]) -> None:
    """Process the ``arprules`` config file into the arp filter table.

    arprules sit at OSI layer 2.5 — they match on ARP packets, not
    IP traffic. nftables exposes them via a separate table family
    (``table arp filter``) with its own input/output base chains
    that hook the kernel's ARP path.

    Format::

        ACTION  SOURCE  DEST  INTERFACE  MAC

    where SOURCE is the ARP sender IP, DEST is the ARP target IP,
    INTERFACE is the iface, and MAC is the sender Ethernet
    address (optional). The chains live in ``ir.arp_chains`` and
    are emitted as a standalone ``table arp filter`` block by
    :func:`shorewall_nft.nft.emitter.emit_arp_nft`, included by
    the main script when present.

    Supported actions: ACCEPT, DROP, REJECT (mapped onto an arp
    drop with ICMP-host-unreachable analogue is not possible —
    REJECT in the arp family just becomes a drop).
    """
    arp_input = Chain(
        name="arp-input",
        chain_type=ChainType.FILTER,
        hook=Hook.INPUT,
        priority=0,
        policy=Verdict.ACCEPT,
    )
    arp_output = Chain(
        name="arp-output",
        chain_type=ChainType.FILTER,
        hook=Hook.OUTPUT,
        priority=0,
        policy=Verdict.ACCEPT,
    )
    ir.arp_chains[arp_input.name] = arp_input
    ir.arp_chains[arp_output.name] = arp_output

    for line in arprules:
        cols = line.columns
        if not cols:
            continue

        # nfset/dns/dnsr token pre-pass on SOURCE(col 1) + DEST(col 2).
        found, expanded = expand_line_for_tokens(line, 1, 2, ir)
        if found:
            _process_arprules(ir, expanded)
            continue

        action_raw = cols[0]
        source = cols[1] if len(cols) > 1 and cols[1] != "-" else None
        dest = cols[2] if len(cols) > 2 and cols[2] != "-" else None
        iface = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        mac = cols[4] if len(cols) > 4 and cols[4] != "-" else None

        action = action_raw.upper().split("(")[0].rstrip("+")
        if action in ("ACCEPT", "ACCEPT_LOG"):
            verdict = Verdict.ACCEPT
        elif action in ("DROP", "DROP_LOG", "REJECT", "DROP_DEFAULT"):
            verdict = Verdict.DROP
        else:
            import warnings
            warnings.warn(
                f"arprules {line.file}:{line.lineno}: unsupported "
                f"action {action_raw!r} — skipped", stacklevel=2)
            continue

        # Direction inference: a rule whose only constraint is the
        # ARP sender IP defaults to input (we received an ARP from
        # someone). A rule with a target IP (dest) and no other
        # qualifier is also input — the kernel saw a who-has for
        # that IP. Output rules are rare and we treat any rule
        # with explicit `out:` prefix in the action as output.
        # Most arprules deployments only need input, so default
        # there.
        chain = arp_input

        rule = Rule(verdict=verdict)
        if iface:
            rule.matches.append(Match(field="meta iifname", value=iface))
        if source:
            # ARP sender IP
            rule.matches.append(Match(field="arp saddr ip", value=source))
        if dest:
            # ARP target IP
            rule.matches.append(Match(field="arp daddr ip", value=dest))
        if mac:
            mac_norm = mac.lstrip("~").replace("-", ":").lower()
            rule.matches.append(
                Match(field="arp saddr ether", value=mac_norm))
        chain.rules.append(rule)


def _process_rawnat(ir: FirewallIR, rawnat_lines: list[ConfigLine],
                    zones: ZoneModel) -> None:
    """Process the ``rawnat`` config file.

    Shorewall's ``rawnat`` lets you put rules in the iptables raw
    PREROUTING chain — i.e. they fire **before** conntrack and any
    DNAT/SNAT in the regular nat table. The supported actions are
    things like ``NOTRACK`` and ``ACCEPT`` plus the rare early-DNAT
    ``DNAT`` form (only useful with conntrack zones / notrack
    follow-up rules).

    For us this slots cleanly onto the existing
    ``raw-prerouting`` / ``raw-output`` chains created by the
    ``notrack`` processor — we re-create them lazily here so a
    config that uses ONLY ``rawnat`` (no notrack file) still gets
    the chains.

    Format::

        ACTION  SOURCE  DEST  PROTO  DPORT  SPORT  USER

    SOURCE / DEST are zone:host specs. ``$FW`` source routes the
    rule into ``raw-output``; everything else into
    ``raw-prerouting``.
    """
    if "raw-prerouting" not in ir.chains:
        ir.add_chain(Chain(
            name="raw-prerouting",
            chain_type=ChainType.FILTER,
            hook=Hook.PREROUTING,
            priority=-300,
        ))
    if "raw-output" not in ir.chains:
        ir.add_chain(Chain(
            name="raw-output",
            chain_type=ChainType.FILTER,
            hook=Hook.OUTPUT,
            priority=-300,
        ))

    fw = zones.firewall_zone

    for line in rawnat_lines:
        cols = line.columns
        if not cols:
            continue

        # nfset/dns/dnsr token pre-pass on SOURCE(col 1) + DEST(col 2).
        found, expanded = expand_line_for_tokens(line, 1, 2, ir)
        if found:
            _process_rawnat(ir, expanded, zones)
            continue

        action_raw = cols[0]
        source_spec = cols[1] if len(cols) > 1 and cols[1] != "-" else "all"
        dest_spec = cols[2] if len(cols) > 2 and cols[2] != "-" else "all"
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        action = action_raw.upper().split("(")[0].rstrip("+")

        # Map the action onto a (verdict, verdict_args) pair. We
        # support NOTRACK, ACCEPT, DROP — the only ones that make
        # any sense in the raw table. Everything else gets a
        # warning and is skipped.
        if action == "NOTRACK":
            verdict = Verdict.ACCEPT
            verdict_args: SpecialVerdict | str | None = NotrackVerdict()
        elif action == "ACCEPT":
            verdict = Verdict.ACCEPT
            verdict_args = None
        elif action == "DROP":
            verdict = Verdict.DROP
            verdict_args = None
        else:
            import warnings
            warnings.warn(
                f"rawnat {line.file}:{line.lineno}: unsupported "
                f"action {action_raw!r} — skipped", stacklevel=2)
            continue

        src_zone, src_addr = _parse_zone_spec(source_spec, zones)
        src_addr = _sentinel_to_addr(src_zone, src_addr)
        dst_zone, dst_addr = _parse_zone_spec(dest_spec, zones)
        dst_addr = _sentinel_to_addr(dst_zone, dst_addr)

        chain = (ir.chains["raw-output"] if src_zone == fw
                 else ir.chains["raw-prerouting"])

        rule = Rule(
            verdict=verdict,
            verdict_args=verdict_args,
            source_file=line.file,
            source_line=line.lineno,
            source_raw=line.raw,
        )

        # iif/oif from zone interfaces (skip $FW + the all/any
        # catchalls — those leave the chain unrestricted).
        def _zone_iface_match(zone_name: str | None, field: str) -> None:
            if not zone_name or zone_name == fw:
                return
            if zone_name in ("all", "any"):
                return
            z = zones.zones.get(zone_name)
            if not z:
                return
            iface_names = [i.name for i in z.interfaces]
            if not iface_names:
                return
            if len(iface_names) == 1:
                rule.matches.append(Match(
                    field=field, value=iface_names[0]))
            else:
                rule.matches.append(Match(
                    field=field,
                    value="{ " + ", ".join(
                        f'"{i}"' for i in sorted(iface_names)) + " }"))

        _zone_iface_match(src_zone, "iifname")
        _zone_iface_match(dst_zone, "oifname")

        if src_addr:
            field = "ip6 saddr" if is_ipv6_spec(src_addr) else "ip saddr"
            rule.matches.append(Match(field=field, value=src_addr))
        if dst_addr:
            field = "ip6 daddr" if is_ipv6_spec(dst_addr) else "ip daddr"
            rule.matches.append(Match(field=field, value=dst_addr))
        if proto:
            rule.matches.append(Match(field="meta l4proto", value=proto))
            if dport:
                rule.matches.append(Match(field=f"{proto} dport", value=dport))
            if sport:
                rule.matches.append(Match(field=f"{proto} sport", value=sport))

        chain.rules.append(rule)


def _process_stoppedrules(ir: FirewallIR, stoppedrules: list[ConfigLine],
                          zones: ZoneModel) -> None:
    """Process the modern ``stoppedrules`` file (Shorewall >= 5.x).

    The legacy ``routestopped`` file (handled by
    :func:`_process_routestopped`) only knew interface + host
    tuples. ``stoppedrules`` is a full rule format::

        ACTION  SOURCE  DEST  PROTO  DPORT  SPORT  ORIGDEST

    where ACTION is one of ``ACCEPT``, ``DROP``, ``NOTRACK``,
    ``ACCEPT+`` (an alias). SOURCE / DEST are zone:host specs
    just like the regular ``rules`` file. The rules are emitted
    into the same standalone ``inet shorewall_stopped`` table that
    routestopped uses, so a config can mix both files.

    Routing rules into base chains:

    * SOURCE = ``$FW`` -> output (the firewall sending traffic)
    * DEST   = ``$FW`` -> input (traffic destined for the firewall)
    * neither $FW       -> forward (transit traffic)

    NOTRACK lands in ``stopped-raw-prerouting`` regardless of the
    src/dst direction (it's a raw-table affair).

    The base chains are created lazily — if neither routestopped
    nor stoppedrules is configured, no stopped table is emitted.
    """
    # Make sure the standard input/output/forward base chains
    # exist (routestopped may not have run).
    def _ensure(name: str, hook: Hook) -> Chain:
        ch = ir.stopped_chains.get(name)
        if ch is None:
            ch = Chain(
                name=name,
                chain_type=ChainType.FILTER,
                hook=hook,
                priority=0,
                policy=Verdict.DROP,
            )
            ir.stopped_chains[name] = ch
            # Loopback + ct established/related survive — same
            # baseline as routestopped.
            if name == "stopped-input":
                lo = Rule(verdict=Verdict.ACCEPT)
                lo.matches.append(Match(field="iifname", value="lo"))
                ch.rules.append(lo)
                est = Rule(verdict=Verdict.ACCEPT)
                est.matches.append(
                    Match(field="ct state", value="established,related"))
                ch.rules.append(est)
            elif name == "stopped-output":
                lo = Rule(verdict=Verdict.ACCEPT)
                lo.matches.append(Match(field="oifname", value="lo"))
                ch.rules.append(lo)
                est = Rule(verdict=Verdict.ACCEPT)
                est.matches.append(
                    Match(field="ct state", value="established,related"))
                ch.rules.append(est)
        return ch

    stopped_raw: Chain | None = ir.stopped_chains.get("stopped-raw-prerouting")

    fw = zones.firewall_zone

    for line in stoppedrules:
        cols = line.columns
        if not cols:
            continue

        # nfset/dns/dnsr token pre-pass on SOURCE(col 1) + DEST(col 2).
        found, expanded = expand_line_for_tokens(line, 1, 2, ir)
        if found:
            _process_stoppedrules(ir, expanded, zones)
            continue

        target_raw = cols[0]
        source_spec = cols[1] if len(cols) > 1 and cols[1] != "-" else "all"
        dest_spec = cols[2] if len(cols) > 2 and cols[2] != "-" else "all"
        proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
        dport = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        sport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        target = target_raw.upper().split("(")[0].rstrip("+")
        if target == "ACCEPT":
            verdict = Verdict.ACCEPT
            verdict_args: SpecialVerdict | str | None = None
        elif target == "DROP":
            verdict = Verdict.DROP
            verdict_args = None
        elif target == "REJECT":
            verdict = Verdict.REJECT
            verdict_args = None
        elif target == "NOTRACK":
            verdict = Verdict.ACCEPT
            verdict_args = NotrackVerdict()
        else:
            import warnings
            warnings.warn(
                f"stoppedrules {line.file}:{line.lineno}: unsupported "
                f"target {target_raw!r} — skipped", stacklevel=2)
            continue

        src_zone, src_addr = _parse_zone_spec(source_spec, zones)
        src_addr = _sentinel_to_addr(src_zone, src_addr)
        dst_zone, dst_addr = _parse_zone_spec(dest_spec, zones)
        dst_addr = _sentinel_to_addr(dst_zone, dst_addr)

        is_v6_src = src_addr is not None and is_ipv6_spec(src_addr)
        is_v6_dst = dst_addr is not None and is_ipv6_spec(dst_addr)

        def _make_match(field: str, val: str) -> Match:
            return Match(field=field, value=val)

        def _add_proto_to(rule: Rule) -> None:
            if proto:
                rule.matches.append(Match(field="meta l4proto", value=proto))
                if dport:
                    rule.matches.append(
                        Match(field=f"{proto} dport", value=dport))
                if sport:
                    rule.matches.append(
                        Match(field=f"{proto} sport", value=sport))

        # NOTRACK always lands in the raw-prerouting chain
        if isinstance(verdict_args, NotrackVerdict):
            if stopped_raw is None:
                stopped_raw = Chain(
                    name="stopped-raw-prerouting",
                    chain_type=ChainType.FILTER,
                    hook=Hook.PREROUTING,
                    priority=-300,
                    policy=None,
                )
                ir.stopped_chains[stopped_raw.name] = stopped_raw
            r = Rule(verdict=Verdict.ACCEPT, verdict_args=NotrackVerdict())
            if src_addr:
                r.matches.append(_make_match(
                    "ip6 saddr" if is_v6_src else "ip saddr", src_addr))
            if dst_addr:
                r.matches.append(_make_match(
                    "ip6 daddr" if is_v6_dst else "ip daddr", dst_addr))
            _add_proto_to(r)
            stopped_raw.rules.append(r)
            continue

        # Pick base chain by direction
        if src_zone == fw and dst_zone == fw:
            chains = [_ensure("stopped-output", Hook.OUTPUT)]
        elif src_zone == fw:
            chains = [_ensure("stopped-output", Hook.OUTPUT)]
        elif dst_zone == fw:
            chains = [_ensure("stopped-input", Hook.INPUT)]
        else:
            chains = [_ensure("stopped-forward", Hook.FORWARD)]

        for ch in chains:
            r = Rule(verdict=verdict, verdict_args=verdict_args)
            # Translate zone -> iifname/oifname when the zone has
            # interfaces. Skip the firewall zone (no iface match).
            if src_zone and src_zone != fw and src_zone in zones.zones:
                z = zones.zones[src_zone]
                iface_names = [i.name for i in z.interfaces]
                if iface_names:
                    if len(iface_names) == 1:
                        r.matches.append(Match(
                            field="iifname", value=iface_names[0]))
                    else:
                        r.matches.append(Match(
                            field="iifname",
                            value="{ " + ", ".join(
                                f'"{i}"' for i in sorted(iface_names))
                            + " }"))
            if dst_zone and dst_zone != fw and dst_zone in zones.zones:
                z = zones.zones[dst_zone]
                iface_names = [i.name for i in z.interfaces]
                if iface_names:
                    if len(iface_names) == 1:
                        r.matches.append(Match(
                            field="oifname", value=iface_names[0]))
                    else:
                        r.matches.append(Match(
                            field="oifname",
                            value="{ " + ", ".join(
                                f'"{i}"' for i in sorted(iface_names))
                            + " }"))
            if src_addr:
                r.matches.append(_make_match(
                    "ip6 saddr" if is_v6_src else "ip saddr", src_addr))
            if dst_addr:
                r.matches.append(_make_match(
                    "ip6 daddr" if is_v6_dst else "ip daddr", dst_addr))
            _add_proto_to(r)
            ch.rules.append(r)


def _set_self_zone_policies(ir: FirewallIR, zones: ZoneModel) -> None:
    """Set ACCEPT policy for self-zone chains.

    Shorewall behavior: traffic within the same zone (between multiple
    interfaces) is ACCEPT by default. This applies to:
    - Zones with multiple interfaces (inter-interface routing)
    - Zones with routeback option on any interface
    """
    for zone_name, zone in zones.zones.items():
        if zone.is_firewall:
            continue

        # Check if zone has routeback or multiple interfaces
        has_routeback = any(
            "routeback" in opt or opt.startswith("routeback=")
            for iface in zone.interfaces
            for opt in iface.options
        )
        has_multi_iface = len(zone.interfaces) > 1

        if has_routeback or has_multi_iface:
            chain_name = f"{zone_name}-{zone_name}"
            chain = ir.get_or_create_chain(chain_name)
            if chain.policy is None:
                chain.policy = Verdict.ACCEPT


def _apply_default_actions(ir: FirewallIR, settings: dict[str, str]) -> None:
    """Apply DROP_DEFAULT and REJECT_DEFAULT action chains.

    In Shorewall, these prepend Broadcast/Multicast filtering before
    the actual DROP/REJECT policy in zone-pair chains.

    DROP_DEFAULT=Drop means: before dropping, silently discard broadcasts.
    REJECT_DEFAULT=Reject means: before rejecting, silently discard broadcasts.
    """
    drop_default = settings.get("DROP_DEFAULT", "Drop")
    reject_default = settings.get("REJECT_DEFAULT", "Reject")

    from shorewall_nft.compiler.actions import ACTION_CHAIN_MAP

    for chain in ir.chains.values():
        if chain.is_base_chain or chain.name.startswith("sw_"):
            continue

        if chain.policy == Verdict.DROP and drop_default in ACTION_CHAIN_MAP:
            # Replace simple drop policy with jump to action chain
            chain.policy = Verdict.JUMP
            chain.rules.append(Rule(
                verdict=Verdict.JUMP,
                verdict_args=ACTION_CHAIN_MAP[drop_default],
            ))
        elif chain.policy == Verdict.REJECT and reject_default in ACTION_CHAIN_MAP:
            chain.policy = Verdict.JUMP
            chain.rules.append(Rule(
                verdict=Verdict.JUMP,
                verdict_args=ACTION_CHAIN_MAP[reject_default],
            ))


def _process_synparams(ir: FirewallIR, lines: list[ConfigLine],
                       zones: ZoneModel) -> None:
    """Process the ``synparams`` config file — SYN-flood protection per zone.

    Upstream analogue: ``process_a_policy1`` inline block in Rules.pm:787.
    For each row in ``synparams`` (ZONE RATE BURST [SUPPRESS]), this function:

    1. Creates a ``synflood-<zone>`` chain containing:
       - ``limit rate <rate>/<unit> burst <burst> packets return``
       - ``drop``
       (Packets within the rate limit return; excess is dropped.)

    2. Prepends a TCP SYN guard jump into every zone-pair chain whose
       destination zone matches the listed zone.  The guard rule is:
       ``tcp flags syn jump synflood-<zone>``

    The ``SUPPRESS`` column (optional) is parsed but not currently acted
    on — it controls whether the synflood chain suppresses logging, which
    is a future WP-E enhancement.

    nft emit for a row ``loc 100/sec 200``:

    .. code-block:: nft

        chain synflood-loc {
            limit rate 100/second burst 200 packets return
            drop
        }

    And in every ``*-loc`` zone-pair chain, prepend:

    .. code-block:: nft

        tcp flags & (fin|syn|rst|ack) == syn jump synflood-loc
    """
    if not lines:
        return

    # Parse each row: ZONE RATE BURST [SUPPRESS]
    synflood_zones: list[tuple[str, RateLimitSpec]] = []

    for line in lines:
        cols = line.columns
        if not cols:
            continue
        zone_name = cols[0].strip()
        if not zone_name or zone_name == "-":
            continue
        # Resolve $FW alias
        if zone_name == "$FW":
            zone_name = zones.firewall_zone

        rate_str = cols[1].strip() if len(cols) > 1 else "100/sec"
        burst_str = cols[2].strip() if len(cols) > 2 else "200"

        # Parse rate: may be "100/sec", "10/min" etc.
        rl = _parse_rate_limit(rate_str)
        if rl is None:
            # Try appending ":burst" and re-parsing
            rl = _parse_rate_limit(f"{rate_str}:{burst_str}" if burst_str else rate_str)
        if rl is None:
            _log.warning("synparams: unparseable rate %r for zone %r — skipped",
                         rate_str, zone_name)
            continue
        # Override burst from the dedicated column
        try:
            rl_burst = int(burst_str)
        except (ValueError, TypeError):
            rl_burst = rl.burst
        # RateLimitSpec is slots=True, create a new one with the burst override
        rl = RateLimitSpec(
            rate=rl.rate, unit=rl.unit, burst=rl_burst,
            name=None, per_source=False,
        )
        synflood_zones.append((zone_name, rl))

    if not synflood_zones:
        return

    # Step 1: Build the ``synflood-<zone>`` chains.
    for zone_name, rl in synflood_zones:
        chain_name = f"synflood-{zone_name}"
        if chain_name in ir.chains:
            continue  # idempotent — don't overwrite if already built

        sf_chain = Chain(name=chain_name)
        # Rule 1: pass traffic within the rate limit
        sf_chain.rules.append(Rule(
            matches=[],
            verdict=Verdict.RETURN,
            rate_limit=rl,
        ))
        # Rule 2: drop the rest
        sf_chain.rules.append(Rule(
            matches=[],
            verdict=Verdict.DROP,
        ))
        ir.add_chain(sf_chain)

    # Step 2: Inject TCP SYN jumps at the front of every *-<zone> chain.
    # We must collect target chains first, then prepend, to avoid
    # modifying the dict while iterating.
    synflood_zone_set = {z for z, _ in synflood_zones}
    for chain_name, chain in list(ir.chains.items()):
        if chain.is_base_chain or chain_name.startswith("sw_"):
            continue
        # Skip the synflood chains themselves — they must not receive the guard.
        if chain_name.startswith("synflood-"):
            continue
        # Zone-pair chain names: "<src>-<dst>"
        parts = chain_name.split("-", 1)
        if len(parts) != 2:
            continue
        _src, _dst = parts
        if _dst not in synflood_zone_set:
            continue
        # Prepend the syn-jump guard AFTER any ct state rules at the top.
        # We find the first non-ct-state rule position.
        insert_pos = 0
        for i, r in enumerate(chain.rules):
            is_ct_state = any(m.field == "ct state" for m in r.matches)
            if is_ct_state:
                insert_pos = i + 1
            else:
                break
        jump_rule = Rule(
            matches=[
                Match(field="tcp flags", value="syn"),
            ],
            verdict=Verdict.JUMP,
            verdict_args=f"synflood-{_dst}",
            comment="synflood guard",
        )
        chain.rules.insert(insert_pos, jump_rule)
