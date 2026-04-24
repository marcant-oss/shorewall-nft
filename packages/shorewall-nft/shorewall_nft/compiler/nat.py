"""NAT rule processing: SNAT (masq), DNAT, Masquerade, static 1:1 NAT.

Translates Shorewall masq/snat/nat config and DNAT rules into
nft nat chain rules.

Inputs: ``ConfigLine`` lists from the ``masq``, ``snat``, ``nat``,
``rules`` (DNAT/REDIRECT rows), and ``netmap`` config files, plus a
``FirewallIR`` that may already contain ``prerouting``/``postrouting`` chains.

Outputs: ``Rule`` entries appended to the ``prerouting`` chain
(``verdict_args=DnatVerdict(…)``) and the ``postrouting`` chain
(``verdict_args=SnatVerdict(…)`` or ``MasqueradeVerdict()``).  Both chains are
created with ``ChainType.NAT`` and the appropriate hook/priority if they do
not already exist.

Entry points: ``process_nat(ir, masq_lines, dnat_rules)``,
``process_static_nat(ir, nat_lines)``,
``process_netmap(ir, netmap_lines)``, ``extract_nat_rules(rules)``.
"""

from __future__ import annotations

import re

from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    Match,
    Rule,
    Verdict,
    _has_set_token,
    expand_line_for_tokens,
)
from shorewall_nft.compiler.verdicts import (
    DnatVerdict,
    MasqueradeVerdict,
    NonatVerdict,
    RedirectVerdict,
    SnatVerdict,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.runtime.pyroute2_helpers import settings_bool

# ACTION column patterns
_SNAT_ADDR_RE = re.compile(r'^SNAT\+?\((.+)\)$', re.IGNORECASE)
_MASQ_RE = re.compile(r'^MASQUERADE\+?(?:\(([^)]*)\))?$', re.IGNORECASE)
_LOG_RE = re.compile(r'^LOG(?::([^:]+))?(?::([^:]+))?:(.+)$', re.IGNORECASE)

# Flag tokens recognised in SNAT address parameter after stripping
_SNAT_FLAGS = ("persistent", "random", "fully-random")

# Shorewall SWITCH column: runtime toggle via ct mark bit 0x40000000.
# Shorewall uses the second-highest bit of a 32-bit ct mark as the
# per-rule on/off switch. Packets with that bit set in ct mark are
# treated as "switch enabled". We test with `ct mark & 0x40000000 != 0`.
_SWITCH_MARK = 0x40000000


def process_nat(ir: FirewallIR, masq_lines: list[ConfigLine],
                dnat_rules: list[ConfigLine],
                snat_lines: list[ConfigLine] | None = None) -> None:
    """Process NAT rules into the IR.

    *snat_lines* is the modern Shorewall ``snat`` file, with the
    action moved to col 0 (see ``_process_snat_line``). Optional
    keyword to keep the call signature backward-compatible.
    """
    snat_lines = snat_lines or []

    # Create nat base chains if we have any NAT rules
    if masq_lines or dnat_rules or snat_lines:
        _ensure_nat_chains(ir)

    # Process masq (SNAT) rules — legacy column layout
    for line in masq_lines:
        _process_masq_line(ir, line)

    # Process snat rules — modern column layout
    for line in snat_lines:
        _process_snat_line(ir, line)

    # Process DNAT rules (extracted from rules file)
    for line in dnat_rules:
        _process_dnat_line(ir, line)


def _parse_snat_action(action_raw: str) -> tuple[SnatVerdict | MasqueradeVerdict | NonatVerdict | None, str | None, str | None]:
    """Parse the ACTION column of a ``snat`` line.

    Returns ``(verdict_args, log_level, log_tag)`` where ``log_level`` /
    ``log_tag`` are set when the action is prefixed with ``LOG[:level][:tag]:``.
    Returns ``(None, None, None)`` when the line should be skipped (CONTINUE /
    ACCEPT / NONAT without NAT target — all are "skip NAT" semantics).
    """
    action_upper = action_raw.upper()

    # Handle LOG prefix: LOG[:level][:tag]:ACTION
    log_level: str | None = None
    log_tag: str | None = None
    inner = action_raw
    m = _LOG_RE.match(action_raw)
    if m:
        log_level = m.group(1) or "info"
        log_tag = m.group(2)
        inner = m.group(3)
        action_upper = inner.upper()

    # CONTINUE / ACCEPT / NONAT → skip NAT (return from NAT table)
    if action_upper.startswith(("CONTINUE", "ACCEPT", "NONAT")):
        if log_level is not None:
            return NonatVerdict(), log_level, log_tag
        return None, None, None

    # MASQUERADE[(port-range[:random])]
    mm = _MASQ_RE.match(inner)
    if mm:
        param = mm.group(1) or ""
        port_range: str | None = None
        flags: list[str] = []
        if param:
            # Strip :random flag
            if param.endswith(":random"):
                flags.append("random")
                param = param[:-len(":random")]
            elif param == "random":
                flags.append("random")
                param = ""
            if param:
                port_range = param
        return MasqueradeVerdict(port_range=port_range, flags=tuple(flags)), log_level, log_tag

    # SNAT[(addr[,addr...][:port-range][:flags])]
    sm = _SNAT_ADDR_RE.match(inner)
    if sm:
        addr_part = sm.group(1)
        return _parse_snat_addr(addr_part), log_level, log_tag

    return None, None, None


def _parse_snat_addr(addr_part: str) -> SnatVerdict:
    """Parse the address parameter of ``SNAT(…)``.

    Handles:
    - Single address: ``198.51.100.1``
    - Address with port range: ``198.51.100.1:1024-65535``
    - Multiple addresses (round-robin): ``198.51.100.1,198.51.100.2``
    - Flags: ``:persistent``, ``:random``, ``:fully-random`` (suffix)
    """
    flags: list[str] = []
    # Strip recognised flags from the end (may appear multiple times)
    changed = True
    while changed:
        changed = False
        for flag in _SNAT_FLAGS:
            if addr_part.endswith(f":{flag}"):
                flags.insert(0, flag)
                addr_part = addr_part[:-len(flag) - 1]
                changed = True

    # Multiple addresses → round-robin
    addrs = [a.strip() for a in addr_part.split(",") if a.strip()]
    if len(addrs) > 1:
        return SnatVerdict(target=addrs[0], targets=tuple(addrs), flags=tuple(flags))

    # Single address — may carry port range after last colon
    single = addrs[0] if addrs else addr_part
    port_range: str | None = None
    # Detect port range: addr:p1-p2 or addr:port
    # IPv4: split on last colon only if the suffix looks like a port/range
    # (not part of an IPv6 address and not empty)
    if ":" in single:
        # Only interpret a trailing :port or :p1-p2 as a port range if
        # the last segment contains only digits and an optional '-'.
        last_colon = single.rfind(":")
        suffix = single[last_colon + 1:]
        if re.match(r'^\d+(?:-\d+)?$', suffix):
            port_range = suffix
            single = single[:last_colon]

    return SnatVerdict(target=single, port_range=port_range, flags=tuple(flags))


def _add_snat_matches(rule: Rule, cols: list[str]) -> None:
    """Append match conditions for columns 5–10 of a ``snat`` line.

    Column indices (0-based):
      5  IPSEC
      6  MARK
      7  USER
      8  SWITCH
      9  ORIGDEST
      10 PROBABILITY
    """
    ipsec     = cols[5] if len(cols) > 5 and cols[5] != "-" else None
    mark      = cols[6] if len(cols) > 6 and cols[6] != "-" else None
    user      = cols[7] if len(cols) > 7 and cols[7] != "-" else None
    switch    = cols[8] if len(cols) > 8 and cols[8] != "-" else None
    orig_dest = cols[9] if len(cols) > 9 and cols[9] != "-" else None
    prob      = cols[10] if len(cols) > 10 and cols[10] != "-" else None

    if ipsec:
        rule.matches.extend(_build_ipsec_matches(ipsec, direction="out"))

    if mark:
        rule.matches.append(_build_mark_match(mark))

    if user:
        rule.matches.extend(_build_user_matches(user))

    if switch:
        # SWITCH column: the value names a shorewall "switch". We model this
        # as a ct mark bit test using Shorewall's convention: bit 0x40000000
        # is set when the named switch is "on". This lets operators toggle
        # rules at runtime without reloading the firewall.
        val = switch.strip()
        negate = val.startswith("!")
        if negate:
            val = val[1:].strip()
        rule.matches.append(Match(
            field="ct mark",
            value=f"& {_SWITCH_MARK:#010x} != 0" if not negate else f"& {_SWITCH_MARK:#010x} == 0",
        ))

    if orig_dest:
        negate = orig_dest.startswith("!")
        addr = orig_dest.lstrip("!")
        rule.matches.append(Match(field="ct original ip daddr", value=addr, negate=negate))

    if prob:
        rule.matches.append(_build_probability_match(prob))


def _build_ipsec_matches(ipsec: str, direction: str) -> list[Match]:
    """Build the nft IPsec match for the IPSEC column of snat/masq rules.

    nftables 1.1.x does not expose ``proto=`` / ``mode=`` on its ``ipsec``
    match; the two workable forms are ``meta secpath exists`` (any
    xfrm-decoded packet) and ``ipsec <dir> reqid N`` / ``spi 0xN``.
    Since the IPSEC column usually just carries ``yes`` / ``no`` / extras,
    map to those two forms: ``yes``/``ipsec`` → ``meta secpath exists``,
    ``no``/``none`` → ``meta secpath missing``. Extras (``proto=…`` etc.)
    are dropped with the broad match preserved.
    """
    val = ipsec.strip().lower()
    if val in ("no", "none"):
        return [Match(field="inline", value="meta secpath missing")]
    # "yes", "ipsec", or any extras → broad "came through IPsec" check.
    # direction is not meaningful for secpath (kernel marks both ingress
    # decode and egress encrypt), so we keep the argument for signature
    # compatibility but don't use it.
    _ = direction
    return [Match(field="inline", value="meta secpath exists")]


def _build_mark_match(mark: str) -> Match:
    """Build a ``meta mark`` match for the MARK column.

    Syntax: ``[!]value[/mask]`` or ``[!]value&mask``
    """
    negate = mark.startswith("!")
    m = mark.lstrip("!")
    # Convert & to / for the emitter's `meta mark and mask == val` path.
    if "&" in m:
        val, mask = m.split("&", 1)
        return Match(field="meta mark", value=f"{val.strip()}/{mask.strip()}", negate=negate)
    return Match(field="meta mark", value=m.strip(), negate=negate)


def _build_user_matches(user: str) -> list[Match]:
    """Build ``meta skuid`` / ``meta skgid`` matches for the USER column.

    Shorewall USER syntax: ``[!]user`` or ``[!]+group`` or ``[!]user:group``
    """
    matches: list[Match] = []
    negate = user.startswith("!")
    u = user.lstrip("!")
    if ":" in u:
        uname, gname = u.split(":", 1)
        if uname:
            matches.append(Match(field="meta skuid", value=uname, negate=negate))
        if gname:
            matches.append(Match(field="meta skgid", value=gname, negate=negate))
    elif u.startswith("+"):
        matches.append(Match(field="meta skgid", value=u[1:], negate=negate))
    else:
        matches.append(Match(field="meta skuid", value=u, negate=negate))
    return matches


def _build_probability_match(prob: str) -> Match:
    """Build a probability match for the PROBABILITY column.

    Shorewall stores probabilities as fractions (``0.25``).  nft expresses
    random matching as ``meta random < N`` where N is scaled to 2^32.
    We use the ``probability`` inline-match field which the emitter maps
    to ``numgen random mod 100 < percent``.
    """
    try:
        frac = float(prob)
    except ValueError:
        frac = 0.5
    percent = int(frac * 100)
    return Match(field="probability", value=str(percent))


def _process_snat_line(ir: FirewallIR, line: ConfigLine) -> None:
    """Process one ``snat`` config line.

    Modern Shorewall column layout::

        ACTION  SOURCE  DEST  PROTO  PORT  IPSEC  MARK  USER  SWITCH  ORIGDEST  PROBABILITY

    ACTION carries:
      * ``SNAT(addr[,addr...])``        — explicit SNAT target(s)
      * ``SNAT(addr:port-range)``       — SNAT with port range
      * ``SNAT(addr:random)``           — SNAT with random flag
      * ``SNAT(addr:persistent)``       — SNAT with persistent flag
      * ``SNAT(addr:fully-random)``     — SNAT with fully-random flag
      * ``MASQUERADE``                  — dynamic masquerade
      * ``MASQUERADE(port-range)``      — masquerade with port range
      * ``MASQUERADE(port-range:random)``
      * ``CONTINUE`` / ``ACCEPT`` / ``NONAT`` — skip NAT (return)
      * ``LOG[:level][:tag]:ACTION``    — log before the action

    SOURCE is an IP / zone / interface; DEST is the outbound
    interface. PROTO/PORT/etc. mirror the masq layout.
    """
    cols = line.columns
    if len(cols) < 3:
        return

    action_raw = cols[0]
    source = cols[1]
    dest_iface = cols[2]
    proto = cols[3] if len(cols) > 3 and cols[3] != "-" else None
    ports = cols[4] if len(cols) > 4 and cols[4] != "-" else None

    # Reject set tokens in the SOURCE column.
    if _has_set_token(source):
        raise ValueError(
            f"snat {line.file}:{line.lineno}: SOURCE column does not accept "
            f"nfset:/dns:/dnsr: tokens — got {source!r}"
        )
    found, expanded = expand_line_for_tokens(line, 1, None, ir)
    if found:
        for exp_line in expanded:
            _process_snat_line(ir, exp_line)
        return

    verdict_args, log_level, log_tag = _parse_snat_action(action_raw)

    # CONTINUE/ACCEPT/NONAT (without LOG prefix) → skip this line entirely.
    if verdict_args is None and log_level is None:
        return

    chain = ir.chains["postrouting"]

    def _make_base_rule() -> Rule:
        r = Rule(
            verdict=Verdict.ACCEPT,
            source_file=line.file,
            source_line=line.lineno,
            comment=line.comment_tag,
        )
        # Outbound interface match (DEST column).
        if dest_iface and dest_iface != "-":
            r.matches.append(Match(field="oifname", value=dest_iface))
        # Source — interface name OR ip/cidr. Heuristic: if it looks like
        # an iface name (no dot, no colon, no slash) treat as iifname,
        # otherwise as a saddr match.
        if source and source != "-":
            if _looks_like_iface(source):
                r.matches.append(Match(field="iifname", value=source))
            else:
                r.matches.append(Match(field="ip saddr", value=source))
        # Protocol and port (cols 3, 4)
        if proto:
            r.matches.append(Match(field="meta l4proto", value=proto))
            if ports:
                r.matches.append(Match(field=f"{proto} dport", value=ports))
        # Optional extra columns (IPSEC, MARK, USER, SWITCH, ORIGDEST, PROBABILITY)
        _add_snat_matches(r, cols)
        return r

    # If there is a LOG prefix, prepend a log rule with the same matches.
    if log_level is not None:
        log_rule = _make_base_rule()
        log_rule.verdict = Verdict.LOG
        log_rule.log_level = log_level
        log_rule.log_prefix = log_tag or "SNAT"
        chain.rules.append(log_rule)

    # NONAT/CONTINUE/ACCEPT with a LOG prefix → return after logging.
    if verdict_args is None:
        return

    rule = _make_base_rule()
    rule.verdict_args = verdict_args
    chain.rules.append(rule)

    # ADD_SNAT_ALIASES: record SNAT target address for runtime alias apply.
    # Mirrors Nat.pm::process_one_masq1: ``if ($add_snat_aliases) { … }``.
    # Conditions for recording:
    #   1. ADD_SNAT_ALIASES=Yes in settings.
    #   2. Verdict is an explicit SNAT to a concrete IP (not MASQUERADE /
    #      NONAT / detect).  MASQUERADE uses the interface's current address
    #      dynamically — no static alias needed.
    #   3. A DEST interface is specified (needed to know *which* iface to
    #      alias on).
    #   4. The SNAT target is a plain IP (not a range start/end nor a
    #      port-only specification).
    if isinstance(verdict_args, SnatVerdict) and dest_iface and dest_iface != "-":
        add_snat_aliases = settings_bool(ir.settings, "ADD_SNAT_ALIASES", False)
        if add_snat_aliases:
            snat_target = verdict_args.target
            # Skip if target looks like an iface-variable reference (&/%)
            # or an address-range (contains '-') or is empty.
            if (
                snat_target
                and not snat_target.startswith(("&", "%"))
                and "-" not in snat_target
                and not any(a == snat_target for a, _ in ir.ip_aliases)
            ):
                ir.ip_aliases.append((snat_target, dest_iface))


def _looks_like_iface(s: str) -> bool:
    """True if *s* looks like an interface name (no dot/colon/slash)."""
    return not any(c in s for c in ".:/")


def _ensure_nat_chains(ir: FirewallIR) -> None:
    """Create nat base chains if they don't exist."""
    if "prerouting" not in ir.chains:
        ir.add_chain(Chain(
            name="prerouting",
            chain_type=ChainType.NAT,
            hook=Hook.PREROUTING,
            priority=-100,
        ))
    if "postrouting" not in ir.chains:
        ir.add_chain(Chain(
            name="postrouting",
            chain_type=ChainType.NAT,
            hook=Hook.POSTROUTING,
            priority=100,
        ))


def _process_masq_line(ir: FirewallIR, line: ConfigLine) -> None:
    """Process a masq (SNAT/Masquerade) line.

    Format: INTERFACE[:dest_addr] SOURCE ADDRESS [PROTO] [PORT(S)]
    Examples:
        bond1            192.0.2.35  198.51.100.34
        bond1::198.51.100.21,198.51.100.193  192.0.2.35  198.51.100.34
        bond1::198.51.100.107  192.0.2.200  203.0.113.100  tcp  443

    SOURCE (col 1) accepts nfset:/dns:/dnsr: tokens.
    ADDRESS (col 2) is a single SNAT target IP/range and MUST NOT carry
    set tokens — raise ValueError if one is found.
    """
    cols = line.columns
    if len(cols) < 3:
        return

    # Reject set tokens in the ADDRESS column (SNAT target).
    snat_addr_raw = cols[2]
    if _has_set_token(snat_addr_raw):
        raise ValueError(
            f"masq {line.file}:{line.lineno}: ADDRESS column (SNAT target) "
            f"does not accept nfset:/dns:/dnsr: tokens — got {snat_addr_raw!r}. "
            f"Use a literal IP address or CIDR instead."
        )

    # nfset/dns/dnsr token pre-pass on SOURCE (col 1) only.
    found, expanded = expand_line_for_tokens(line, 1, None, ir)
    if found:
        for exp_line in expanded:
            _process_masq_line(ir, exp_line)
        return

    iface_spec = cols[0]
    source = cols[1]
    snat_addr = cols[2]
    proto = cols[3] if len(cols) > 3 else None
    ports = cols[4] if len(cols) > 4 else None

    if proto == "-":
        proto = None
    if ports == "-":
        ports = None

    # Parse interface spec: IFACE or IFACE::DEST_ADDRS
    iface = iface_spec
    orig_dest = None
    if "::" in iface_spec:
        iface, orig_dest = iface_spec.split("::", 1)
    elif ":" in iface_spec:
        parts = iface_spec.split(":", 1)
        iface = parts[0]
        if parts[1]:
            orig_dest = parts[1]

    chain = ir.chains["postrouting"]
    rule = Rule(
        verdict=Verdict.ACCEPT,  # placeholder, emitter handles snat specially
        verdict_args=SnatVerdict(target=snat_addr),
        source_file=line.file,
        source_line=line.lineno,
        comment=line.comment_tag,
    )

    # Output interface match
    if iface and iface != "-":
        rule.matches.append(Match(field="oifname", value=iface))

    # Source address match
    if source and source != "-":
        rule.matches.append(Match(field="ip saddr", value=source))

    # Original destination (for selective SNAT)
    if orig_dest and orig_dest != "-":
        rule.matches.append(Match(field="ip daddr", value=orig_dest))

    # Protocol and port
    if proto:
        rule.matches.append(Match(field="meta l4proto", value=proto))
        if ports:
            rule.matches.append(Match(field=f"{proto} dport", value=ports))

    chain.rules.append(rule)


def _process_dnat_line(ir: FirewallIR, line: ConfigLine) -> None:
    """Process a DNAT or REDIRECT rule from the rules file.

    DNAT format: ``DNAT SOURCE DEST:IP[:PORT] PROTO DPORT [SPORT] [ORIG_DEST]``
      DNAT  net  host:203.0.113.38:3389  tcp  13389  -  203.0.113.38
      DNAT  all  loc:192.0.2.201         tcp  80,443 -  203.0.113.100

    REDIRECT format: ``REDIRECT SOURCE REDIRECT_PORT PROTO [DPORT]``
      REDIRECT  loc  3128  tcp  80      (transparent HTTP → local squid)
      REDIRECT  net  5353  udp  53      (intercept DNS to local resolver)

    REDIRECT differs from DNAT: the DEST column is a plain numeric port
    on the firewall itself, not a ``zone:ip[:port]`` target. Emits
    ``RedirectVerdict(port=...)`` instead of ``DnatVerdict(target=...)``.

    SOURCE (col 1) accepts nfset:/dns:/dnsr: tokens for both actions.
    DEST (col 2) must not carry set tokens — for DNAT it is a literal
    zone:ip[:port] target, for REDIRECT a bare port number.
    """
    cols = line.columns
    if len(cols) < 4:
        return

    action = cols[0].upper().split(":")[0]
    is_redirect = (action == "REDIRECT")

    # Reject set tokens in the DEST column.
    dest_spec_raw = cols[2] if len(cols) > 2 else "-"
    if _has_set_token(dest_spec_raw):
        action_label = "redirect" if is_redirect else "dnat"
        target_desc = (
            "redirect target port" if is_redirect
            else "DNAT target"
        )
        raise ValueError(
            f"{action_label} {line.file}:{line.lineno}: DEST column "
            f"({target_desc}) does not accept nfset:/dns:/dnsr: tokens "
            f"— got {dest_spec_raw!r}."
        )

    # nfset/dns/dnsr token pre-pass on SOURCE (col 1) only.
    found, expanded = expand_line_for_tokens(line, 1, None, ir)
    if found:
        for exp_line in expanded:
            _process_dnat_line(ir, exp_line)
        return

    source_spec = cols[1] if len(cols) > 1 else "all"
    dest_spec = cols[2] if len(cols) > 2 else "-"
    proto = cols[3] if len(cols) > 3 else None
    dport = cols[4] if len(cols) > 4 else None
    sport = cols[5] if len(cols) > 5 else None
    orig_dest = cols[6] if len(cols) > 6 else None

    if proto == "-":
        proto = None
    if dport == "-":
        dport = None
    if sport == "-":
        sport = None
    if orig_dest == "-":
        orig_dest = None

    # Build the verdict — REDIRECT and DNAT differ here.
    if is_redirect:
        # DEST column is a numeric port on the firewall.
        if not dest_spec or dest_spec == "-":
            raise ValueError(
                f"redirect {line.file}:{line.lineno}: DEST column must be "
                f"a numeric port (the local port to redirect to)"
            )
        try:
            redirect_port = int(dest_spec)
        except ValueError:
            raise ValueError(
                f"redirect {line.file}:{line.lineno}: DEST must be a "
                f"numeric port, got {dest_spec!r}"
            )
        verdict_args = RedirectVerdict(port=redirect_port)
    else:
        # DNAT: DEST is zone:ip[:port].
        dest_ip = None
        dest_port = None
        if dest_spec and dest_spec != "-":
            parts = dest_spec.split(":")
            # parts[0] is the destination zone — not used in the emit
            # (kept only to document the grammar); matching is on the
            # SOURCE iifname + ORIG_DEST in col 6.
            if len(parts) > 1:
                dest_ip = parts[1]
            if len(parts) > 2:
                dest_port = parts[2]
        dnat_target = dest_ip or ""
        if dest_port:
            dnat_target += f":{dest_port}"
        verdict_args = DnatVerdict(target=dnat_target)

    # Parse source zone.  A rewritten set-reference sentinel starts with
    # '+' (e.g. ``+nfset_allowed_v4``) and contains no zone prefix — use
    # it directly as the saddr match value.
    src_zone = None
    src_addr = None
    if source_spec and source_spec != "-":
        if source_spec.startswith("+") or source_spec.startswith("!+"):
            # Pre-rewritten set sentinel — use as address directly.
            src_addr = source_spec
        elif ":" in source_spec:
            src_zone, src_addr = source_spec.split(":", 1)
        else:
            src_zone = source_spec

    chain = ir.chains["prerouting"]
    rule = Rule(
        verdict=Verdict.ACCEPT,  # placeholder
        verdict_args=verdict_args,
        source_file=line.file,
        source_line=line.lineno,
        comment=line.comment_tag,
    )

    # Source address
    if src_addr:
        rule.matches.append(Match(field="ip saddr", value=src_addr))

    # Original destination (the external IP being accessed)
    if orig_dest:
        rule.matches.append(Match(field="ip daddr", value=orig_dest))

    # Protocol and port
    if proto:
        rule.matches.append(Match(field="meta l4proto", value=proto))
        if dport:
            rule.matches.append(Match(field=f"{proto} dport", value=dport))

    chain.rules.append(rule)


def process_static_nat(ir: FirewallIR, nat_lines: list[ConfigLine]) -> None:
    """Process classic 1:1 NAT rules from the ``nat`` config file.

    Shorewall ``nat`` file column layout::

        EXTERNAL  INTERFACE[:digit]  INTERNAL  ALL  LOCAL

    For each row we emit two rules:

    1. PREROUTING ``dnat to INTERNAL`` matching ``ip daddr EXTERNAL``
       (scoped to *iface* if ``ALL != 'Yes'``).
    2. POSTROUTING ``snat to EXTERNAL`` matching ``ip saddr INTERNAL``
       (scoped to *iface* if ``ALL != 'Yes'``).

    If ``LOCAL == 'Yes'``, also emit an OUTPUT-chain DNAT rule so that
    traffic originating on the firewall itself can reach ``INTERNAL``
    via the external alias ``EXTERNAL``.

    The ``:digit`` alias suffix on ``INTERFACE`` is stripped — alias
    creation is runtime work (WP-F3) and not emitted here.
    """
    if not nat_lines:
        return

    _ensure_nat_chains(ir)

    # ADD_IP_ALIASES: auto-add /32 aliases for 1:1 NAT external IPs.
    # Default upstream value is Yes.
    add_ip_aliases = settings_bool(ir.settings, "ADD_IP_ALIASES", True)

    for line in nat_lines:
        cols = line.columns
        if len(cols) < 3:
            continue

        external = cols[0]
        iface_spec = cols[1]
        internal = cols[2]
        all_ints = (cols[3].lower() in ("yes", "1") if len(cols) > 3 and cols[3] not in ("-", "") else False)
        local_nat = (cols[4].lower() in ("yes", "1") if len(cols) > 4 and cols[4] not in ("-", "") else False)

        # Strip :digit alias suffix from interface name.
        # The full iface_spec (including :digit) is preserved for the
        # alias lookup so that callers providing eth0:0 get the correct
        # base interface name in the alias tuple.
        iface = iface_spec.split(":")[0]

        # 1. PREROUTING — dnat to INTERNAL when destination is EXTERNAL
        pre_rule = Rule(
            verdict=Verdict.ACCEPT,
            verdict_args=DnatVerdict(target=internal),
            source_file=line.file,
            source_line=line.lineno,
            comment=line.comment_tag,
        )
        pre_rule.matches.append(Match(field="ip daddr", value=external))
        if not all_ints and iface and iface != "-":
            pre_rule.matches.append(Match(field="iifname", value=iface))
        ir.chains["prerouting"].rules.append(pre_rule)

        # 2. POSTROUTING — snat to EXTERNAL when source is INTERNAL
        post_rule = Rule(
            verdict=Verdict.ACCEPT,
            verdict_args=SnatVerdict(target=external),
            source_file=line.file,
            source_line=line.lineno,
            comment=line.comment_tag,
        )
        post_rule.matches.append(Match(field="ip saddr", value=internal))
        if not all_ints and iface and iface != "-":
            post_rule.matches.append(Match(field="oifname", value=iface))
        ir.chains["postrouting"].rules.append(post_rule)

        # 3. OUTPUT — dnat to INTERNAL so locally-originated traffic works
        if local_nat:
            _ensure_output_chain(ir)
            out_rule = Rule(
                verdict=Verdict.ACCEPT,
                verdict_args=DnatVerdict(target=internal),
                source_file=line.file,
                source_line=line.lineno,
                comment=line.comment_tag,
            )
            out_rule.matches.append(Match(field="ip daddr", value=external))
            ir.chains["nat-output"].rules.append(out_rule)

        # 4. IP alias — record (external, iface) for runtime apply.
        # Mirrors Nat.pm::do_one_nat: ``$addresses_to_add{$external} = 1;
        # push @addresses_to_add, ($external, $fullinterface);``
        # The alias is skipped when ADD_IP_ALIASES is No, or when the
        # iface_spec carries an explicit empty alias (``eth0:``).
        if add_ip_aliases and external and iface:
            # Upstream: if alias digit is explicitly empty (``eth0:``)
            # skip the alias — ``$add_ip_aliases = ''`` branch in Nat.pm.
            alias_part = iface_spec[len(iface):]
            if alias_part not in (":", ""):
                # Has a non-empty alias suffix — still add on base iface.
                pass
            # Only skip if explicitly ``iface:`` (empty alias).
            if alias_part == ":":
                pass  # skip per upstream semantics
            else:
                # De-duplicate: same external IP already queued.
                if not any(a == external for a, _ in ir.ip_aliases):
                    ir.ip_aliases.append((external, iface))


def _ensure_output_chain(ir: FirewallIR) -> None:
    """Create the nat OUTPUT chain if it does not already exist."""
    if "nat-output" not in ir.chains:
        ir.add_chain(Chain(
            name="nat-output",
            chain_type=ChainType.NAT,
            hook=Hook.OUTPUT,
            priority=-100,
        ))


def process_netmap(ir: FirewallIR, netmap_lines: list[ConfigLine]) -> None:
    """Process netmap (bidirectional NAT) rules.

    Format: TYPE NET1 INTERFACE NET2 [PROTO] [DEST PORT]
    """
    if not netmap_lines:
        return

    _ensure_nat_chains(ir)

    for line in netmap_lines:
        cols = line.columns
        if len(cols) < 4:
            continue

        map_type = cols[0].upper()  # DNAT, SNAT, or MAP
        net1 = cols[1]
        iface = cols[2]
        net2 = cols[3]
        proto = cols[4] if len(cols) > 4 and cols[4] != "-" else None
        dport = cols[5] if len(cols) > 5 and cols[5] != "-" else None

        if map_type in ("DNAT", "MAP"):
            chain = ir.chains["prerouting"]
            rule = Rule(
                verdict=Verdict.ACCEPT,
                verdict_args=DnatVerdict(target=net2),
                source_file=line.file,
                source_line=line.lineno,
            )
            rule.matches.append(Match(field="ip daddr", value=net1))
            if iface != "-":
                rule.matches.append(Match(field="iifname", value=iface))
            if proto:
                rule.matches.append(Match(field="meta l4proto", value=proto))
                if dport:
                    rule.matches.append(Match(field=f"{proto} dport", value=dport))
            chain.rules.append(rule)

        if map_type in ("SNAT", "MAP"):
            chain = ir.chains["postrouting"]
            rule = Rule(
                verdict=Verdict.ACCEPT,
                verdict_args=SnatVerdict(target=net1),
                source_file=line.file,
                source_line=line.lineno,
            )
            rule.matches.append(Match(field="ip saddr", value=net2))
            if iface != "-":
                rule.matches.append(Match(field="oifname", value=iface))
            if proto:
                rule.matches.append(Match(field="meta l4proto", value=proto))
            chain.rules.append(rule)


def extract_nat_rules(rules: list[ConfigLine]) -> tuple[list[ConfigLine], list[ConfigLine]]:
    """Separate DNAT/REDIRECT rules from regular rules.

    Returns (nat_rules, remaining_rules).
    """
    nat_rules = []
    remaining = []

    for line in rules:
        if not line.columns:
            remaining.append(line)
            continue

        action = line.columns[0].upper()
        # Strip log level: DNAT:info -> DNAT
        base_action = action.split(":")[0]

        if base_action in ("DNAT", "REDIRECT"):
            nat_rules.append(line)
        else:
            remaining.append(line)

    return nat_rules, remaining
