"""Rule processing: macro expansion, zone-pair construction, _add_rule.

Contains the core rule-translation logic. ``_process_rules`` is the
orchestrator called by ``build_ir()``; it routes each config line
through macro expansion (``_expand_macro``), spec rewriting (imported
from spec_rewrite), and finally ``_add_rule`` which produces the
Rule+Match+Verdict triple and attaches it to the appropriate zone-pair
chain.

Also hosts the macro registry _CUSTOM_MACROS — primary registry,
populated by _load_standard_macros (from the bundled Shorewall
macro files) and _load_custom_macros (from the user's config dir).
User macros take precedence during load.
"""

from __future__ import annotations

import re
from pathlib import Path

from shorewall_nft.compiler.ir._data import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    Match,
    Rule,
    Verdict,
    _MAC_RE,
    _is_mac_addr,
    _parse_rate_limit,
    is_ipv6_spec,
    split_nft_zone_pair,
)
from shorewall_nft.compiler.ir.spec_rewrite import (
    _AND_MULTISET_RE,
    _BRACKET_SET_RE,
    _DNS_DEPRECATION_WARNED,
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
    SpecialVerdict,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.config.zones import ZoneModel


# Macro pattern: NAME(VERDICT) e.g. SSH(ACCEPT), DNS(DROP):$LOG
# Name can contain hyphens (e.g. OrgAdmin(ACCEPT))
_MACRO_RE = re.compile(r'^([\w-]+)\((\w+)\)(?::(.+))?$')

# Slash macro pattern: NAME/VERDICT e.g. Ping/ACCEPT, Rfc1918/DROP:$LOG
# Name can contain hyphens (e.g. OrgAdmin/ACCEPT)
_SLASH_MACRO_RE = re.compile(r'^([\w-]+)/(\w+)(?::(.+))?$')

# RFC1918 private address ranges
_RFC1918_RANGES = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

# Custom macros loaded from macros/ directory
# Each entry is a list of (action, source, dest, proto, dport, sport) tuples
# where "PARAM" means "use the calling action", "SOURCE"/"DEST" mean "use caller's"
_CUSTOM_MACROS: dict[str, list[tuple[str, ...]]] = {}


def _load_standard_macros(shorewall_dir: Path | None = None) -> None:
    """Load standard Shorewall macros.

    Loads from the bundled macros directory (shipped inside the package)
    by default, with fallbacks to system-installed Shorewall locations
    if the bundled copy is missing. Entries are merged into _CUSTOM_MACROS
    so user macros can override them.
    """
    if shorewall_dir is None:
        # Try bundled macros first (shipped with the package), then
        # fall back to a system Shorewall installation if present.
        import shorewall_nft as _pkg
        _pkg_root = Path(_pkg.__file__).parent
        candidates = [
            _pkg_root / "data" / "macros",
            Path("/usr/share/shorewall/Macros"),
            Path("/usr/share/shorewall/macro"),
        ]
        for c in candidates:
            if c.is_dir():
                shorewall_dir = c
                break

    if shorewall_dir is None or not shorewall_dir.is_dir():
        return

    from shorewall_nft.config.parser import ConfigParser
    parser = ConfigParser(shorewall_dir)

    for macro_file in sorted(shorewall_dir.iterdir()):
        if not macro_file.is_file() or not macro_file.name.startswith("macro."):
            continue
        macro_name = macro_file.name[6:]
        if macro_name in _CUSTOM_MACROS:
            continue  # User macros take precedence
        if macro_name in _NATIVE_HANDLED_MACROS:
            continue  # Handled natively by the compiler

        try:
            lines = parser._parse_columnar(macro_file)
        except Exception:
            continue

        entries = []
        for line in lines:
            cols = line.columns
            if not cols:
                continue
            while len(cols) < 6:
                cols.append("-")
            entries.append(tuple(cols[:6]))

        if entries:
            _CUSTOM_MACROS[macro_name] = entries


# Macros that we handle natively (better than the standard macro files)
_NATIVE_HANDLED_MACROS = {"Rfc1918"}


def _load_custom_macros(macros: dict[str, list]) -> None:
    """Load custom macros from parsed macro files into _CUSTOM_MACROS."""
    _CUSTOM_MACROS.clear()
    for name, lines in macros.items():
        entries = []
        for line in lines:
            cols = line.columns
            if not cols:
                continue
            # Pad to 6 columns
            while len(cols) < 6:
                cols.append("-")
            entries.append(tuple(cols[:6]))
        if entries:
            _CUSTOM_MACROS[name] = entries


def _parse_zone_spec(spec: str, zones: ZoneModel) -> tuple[str, str | None]:
    """Parse a zone:address or zone:<address> specification.

    Shorewall uses zone:addr for IPv4, zone:<addr> for IPv6
    (angle brackets avoid ambiguity with IPv6 colons).

    Returns (zone_name, address_or_None).
    Examples:
        "net"                    -> ("net", None)
        "net:10.0.0.1"           -> ("net", "10.0.0.1")
        "net:<2001:db8::1>"      -> ("net", "2001:db8::1")
        "net:<$ORG_PFX>"     -> ("net", "$ORG_PFX")
        "$FW"                    -> ("fw", None)
        "all"                    -> ("all", None)
        "all:<2001:db8::/32>"    -> ("all", "2001:db8::/32")
    """
    if spec == "$FW":
        return zones.firewall_zone, None

    # Handle negation prefix: !zone or !zone:addr
    if spec.startswith("!"):
        zone, addr = _parse_zone_spec(spec[1:], zones)
        # Negation is handled at the rule level, not zone level
        # Return the zone with a negation marker in the address
        if addr:
            return zone, f"!{addr}"
        return zone, None

    # IPv6 angle-bracket syntax: zone:<addr> or zone:<addr,addr>
    if ":<" in spec:
        zone, rest = spec.split(":<", 1)
        # Strip trailing > and any nested <> from addresses
        addr = rest.rstrip(">").replace("<", "").replace(">", "")
        if zone == "$FW":
            zone = zones.firewall_zone
        return zone, addr

    # Standard colon syntax (IPv4 or zone without address)
    if ":" in spec:
        # Check if it looks like zone:addr or just an IPv6 address
        parts = spec.split(":", 1)
        # If the first part is a known zone or special name, split there
        if parts[0] in zones.zones or parts[0] in ("$FW", "all", "any"):
            zone = parts[0]
            addr = parts[1]
            if zone == "$FW":
                zone = zones.firewall_zone
            return zone, addr
        # Bare IPv6 address (from macro expansion) — treat as address
        # without zone. The _add_rule caller will get zone "all" which
        # expands to all zones. For proper zone context, the calling
        # macro should prepend the zone.
        if "::" in spec or spec.count(":") >= 3:
            # Strip angle brackets if present
            clean = spec.replace("<", "").replace(">", "")
            return "all", clean

    return spec, None


def _sentinel_to_addr(zone: str, addr: str | None) -> str | None:
    """If *zone* is a set-reference sentinel (starts with '+'), return it as the
    address value.  Otherwise return *addr* unchanged.

    After ``_expand_line_for_tokens`` runs a bare ``nfset:X`` spec through
    ``_rewrite_spec_for_family``, it becomes ``+nfset_X_vN`` — no zone
    prefix, no colon.  ``_parse_zone_spec`` then returns
    ``("+nfset_X_vN", None)``.  This helper promotes the sentinel from the
    zone slot into the addr slot so callers can use it in a set-match.
    """
    if addr is None and zone.startswith("+"):
        return zone
    return addr


def _zone_pair_chain_name(src: str, dst: str, zones: ZoneModel) -> str:
    """Generate chain name for a zone pair.

    Traffic direction determines which base chain dispatches:
    - src=fw -> output chain
    - dst=fw -> input chain
    - else   -> forward chain
    """
    fw = zones.firewall_zone
    if src == fw and dst == fw:
        return "output"  # fw->fw goes through output
    if src == fw:
        return f"{src}-{dst}"
    if dst == fw:
        return f"{src}-{dst}"
    return f"{src}-{dst}"


def _parse_verdict(action: str) -> Verdict | None:
    """Parse an action string into a Verdict."""
    mapping = {
        "ACCEPT": Verdict.ACCEPT,
        "DROP": Verdict.DROP,
        "REJECT": Verdict.REJECT,
        "LOG": Verdict.LOG,
        "RETURN": Verdict.RETURN,
    }
    return mapping.get(action.upper())


def _expand_zone_list(spec: str, zones: ZoneModel) -> list[str]:
    """Expand a comma-separated zone list in a source/dest spec.

    Shorewall rules allow comma-separated zone names in the SOURCE and
    DEST columns: `linux,vpn  voice` means "from either linux OR vpn
    to voice". We expand this into N individual specs so each gets its
    own chain name (otherwise we'd emit `linux,vpn-voice` which is an
    invalid nft chain identifier).

    Handles:
        'linux,vpn'         → ['linux', 'vpn']
        'linux,vpn:1.2.3.4' → ['linux:1.2.3.4', 'vpn:1.2.3.4']
        'net'               → ['net']
        'all'               → ['all']             (not a zone list)
        '$FW'               → ['$FW']             (firewall variable)
        'net:<2a00::1>'     → ['net:<2a00::1>']   (angle-bracket v6 not split)
    """
    # Don't split inside angle brackets (IPv6 literals in shorewall6 syntax)
    if "<" in spec or ">" in spec:
        return [spec]

    # Split zone part (before first colon) from address part
    if ":" in spec:
        zone_part, addr_part = spec.split(":", 1)
    else:
        zone_part, addr_part = spec, None

    if "," not in zone_part:
        return [spec]

    # Only split if every comma-separated piece is a known zone name.
    # This avoids accidentally splitting things like port lists.
    pieces = [z.strip() for z in zone_part.split(",")]
    valid_names = set(zones.zones.keys()) | {"all", "any", "$FW"}
    if not all(p in valid_names for p in pieces):
        return [spec]

    if addr_part is not None:
        return [f"{p}:{addr_part}" for p in pieces]
    return pieces


def _process_rules(ir: FirewallIR, rule_lines: list[ConfigLine],
                   zones: ZoneModel) -> None:
    """Process firewall rules into chain rules."""
    for line in rule_lines:
        cols = line.columns
        if not cols:
            continue

        action_str = cols[0]
        source_spec_raw = cols[1] if len(cols) > 1 else "all"
        dest_spec_raw = cols[2] if len(cols) > 2 else "all"

        # nfset-token pre-pass: must run BEFORE the dns: pre-pass so that
        # ``+nfset_*`` sentinels are already in place when the dns: rewriter
        # runs (the dns: rewriter must not accidentally touch them).
        #
        # Two-phase expansion:
        # 1. Multi-name ``nfset:a,b,c`` → one clone per name (same pattern as
        #    zone-list expansion).  Each clone carries a single ``nfset:X``.
        # 2. Single-name ``nfset:X`` → two family clones (v4, v6), rewritten
        #    to ``+nfset_X_v4`` / ``+nfset_X_v6`` sentinels.  The recursive
        #    call to _process_rules then sees no nfset token and falls through
        #    to the dns: pre-pass unaffected.
        _src_has_nfset = _spec_contains_nfset_token(source_spec_raw)
        _dst_has_nfset = _spec_contains_nfset_token(dest_spec_raw)

        if _src_has_nfset or _dst_has_nfset:
            # Phase 1: extract comma-separated name list from each spec.
            def _nfset_name_list(spec: str) -> list[str]:
                """Return comma-separated names inside the nfset:... token."""
                body = spec
                for pfx in ("nfset:", "!nfset:"):
                    if body.startswith(pfx):
                        raw = body[len(pfx):]
                        return [n.strip() for n in raw.split(",") if n.strip()]
                colon = body.find(":")
                if colon >= 0:
                    rest = body[colon + 1:]
                    for pfx in ("nfset:", "!nfset:"):
                        if rest.startswith(pfx):
                            raw = rest[len(pfx):]
                            return [n.strip() for n in raw.split(",") if n.strip()]
                return []

            def _nfset_replace_names(spec: str, single_name: str) -> str:
                """Replace the (possibly multi-name) nfset token with one name."""
                return re.sub(
                    r"((?:!?)nfset:)[^\s>:]+",
                    lambda m: m.group(1) + single_name,
                    spec,
                )

            src_names = _nfset_name_list(source_spec_raw) if _src_has_nfset else [None]
            dst_names = _nfset_name_list(dest_spec_raw) if _dst_has_nfset else [None]

            # Only expand if multi-name (>1 in either list) — single-name
            # falls through to Phase 2 below (same iteration, one clone).
            _needs_clone = len(src_names) > 1 or len(dst_names) > 1
            if _needs_clone:
                for sn in src_names:
                    for dn in dst_names:
                        new_cols = list(cols)
                        if sn is not None:
                            new_cols[1] = _nfset_replace_names(source_spec_raw, sn)
                        if dn is not None:
                            if len(new_cols) > 2:
                                new_cols[2] = _nfset_replace_names(dest_spec_raw, dn)
                            else:
                                new_cols.append(_nfset_replace_names(dest_spec_raw, dn))
                        expanded_line = ConfigLine(
                            columns=new_cols,
                            file=line.file,
                            lineno=line.lineno,
                            comment_tag=line.comment_tag,
                            section=line.section,
                            raw=line.raw,
                            format_version=line.format_version,
                        )
                        _process_rules(ir, [expanded_line], zones)
                continue

            # Phase 2: single-name nfset token → family clone + rewrite.
            _line_ctx = f"{line.file}:{line.lineno}" if line.file else ""
            for family in ("v4", "v6"):
                new_cols = list(cols)
                new_cols[1] = _rewrite_nfset_spec(
                    source_spec_raw, ir.nfset_registry, family, _line_ctx)
                if len(new_cols) > 2:
                    new_cols[2] = _rewrite_nfset_spec(
                        dest_spec_raw, ir.nfset_registry, family, _line_ctx)
                expanded_line = ConfigLine(
                    columns=new_cols,
                    file=line.file,
                    lineno=line.lineno,
                    comment_tag=line.comment_tag,
                    section=line.section,
                    raw=line.raw,
                    format_version=line.format_version,
                )
                _process_rules(ir, [expanded_line], zones)
            continue

        # DNS-token pre-pass: if SOURCE or DEST carries a ``dns:HOST`` or
        # ``dnsr:HOST[,HOST…]`` token, clone the rule into two
        # family-specific variants.  Each clone gets rewritten sentinels
        # (``+dns_*_v4`` / ``+dns_*_v6``) so the downstream pipeline never
        # sees raw hostnames.  Both rewriters are applied sequentially; each
        # is a no-op when its token type is absent.
        _src_has_dns = _spec_contains_dns_token(source_spec_raw)
        _dst_has_dns = _spec_contains_dns_token(dest_spec_raw)
        _src_has_dnsr = _spec_contains_dnsr_token(source_spec_raw)
        _dst_has_dnsr = _spec_contains_dnsr_token(dest_spec_raw)
        if _src_has_dns or _dst_has_dns or _src_has_dnsr or _dst_has_dnsr:
            _cfg_path = line.file or ""
            for family in ("v4", "v6"):
                new_cols = list(cols)
                src = _rewrite_dns_spec(
                    source_spec_raw, ir.dns_registry, family,
                    ir.dnsr_registry, _cfg_path)
                src = _rewrite_dnsr_spec(
                    src, ir.dns_registry, ir.dnsr_registry, family)
                new_cols[1] = src
                if len(new_cols) > 2:
                    dst = _rewrite_dns_spec(
                        dest_spec_raw, ir.dns_registry, family,
                        ir.dnsr_registry, _cfg_path)
                    dst = _rewrite_dnsr_spec(
                        dst, ir.dns_registry, ir.dnsr_registry, family)
                    new_cols[2] = dst
                elif _dst_has_dns or _dst_has_dnsr:
                    dst = _rewrite_dns_spec(
                        dest_spec_raw, ir.dns_registry, family,
                        ir.dnsr_registry, _cfg_path)
                    dst = _rewrite_dnsr_spec(
                        dst, ir.dns_registry, ir.dnsr_registry, family)
                    new_cols.append(dst)
                expanded_line = ConfigLine(
                    columns=new_cols,
                    file=line.file,
                    lineno=line.lineno,
                    comment_tag=line.comment_tag,
                    section=line.section,
                    raw=line.raw,
                    format_version=line.format_version,
                )
                _process_rules(ir, [expanded_line], zones)
            continue

        # Bracket-flag / AND-multi-set pre-pass (W16).
        # Runs AFTER nfset + dns pre-passes (those produce +sentinel specs
        # that start with '+' and never carry bracket flags, so
        # _spec_contains_bracket_ipset and _rewrite_bracket_spec leave them
        # untouched — they have no [...] suffix).
        #
        # We detect, validate and strip the bracket flags here, then forward
        # the bracket metadata directly to _add_rule (via the
        # ``bracket_src_infos`` / ``bracket_dst_infos`` kwargs added in W16)
        # so the correct Match field is emitted for each set name.
        _src_has_bracket = _spec_contains_bracket_ipset(source_spec_raw)
        _dst_has_bracket = _spec_contains_bracket_ipset(dest_spec_raw)
        if _src_has_bracket or _dst_has_bracket:
            src_bracket_infos: list[tuple[str, str, bool]] = []
            dst_bracket_infos: list[tuple[str, str, bool]] = []
            _bracket_source = source_spec_raw
            _bracket_dest = dest_spec_raw
            _bracket_ctx = f"{line.file}:{line.lineno}" if line.file else ""
            if _src_has_bracket:
                _bracket_source, src_bracket_infos = _rewrite_bracket_spec(
                    source_spec_raw, "src", _bracket_ctx)
            if _dst_has_bracket:
                _bracket_dest, dst_bracket_infos = _rewrite_bracket_spec(
                    dest_spec_raw, "dst", _bracket_ctx)
            # Build a synthetic line with stripped specs and recurse once so
            # zone-list expansion and the remaining logic apply normally.
            new_cols = list(cols)
            new_cols[1] = _bracket_source
            if len(new_cols) > 2:
                new_cols[2] = _bracket_dest
            else:
                new_cols.append(_bracket_dest)
            expanded_line = ConfigLine(
                columns=new_cols,
                file=line.file,
                lineno=line.lineno,
                comment_tag=line.comment_tag,
                section=line.section,
                raw=line.raw,
                format_version=line.format_version,
            )
            # Attach bracket infos as transient attributes so that the
            # final _add_rule call (at the bottom of the recursive iteration)
            # can pick them up.  The attribute names are private to this
            # module; they are never serialised or persisted.
            expanded_line._bracket_src = src_bracket_infos  # type: ignore[attr-defined]
            expanded_line._bracket_dst = dst_bracket_infos  # type: ignore[attr-defined]
            _process_rules(ir, [expanded_line], zones)
            continue

        # Expand comma-separated zone lists in SOURCE and DEST.
        # One rule line may become N×M processed rules.
        src_specs = _expand_zone_list(source_spec_raw, zones)
        dst_specs = _expand_zone_list(dest_spec_raw, zones)

        # Recursively process each expanded combination by rewriting the
        # ConfigLine's columns for a single-zone rule. This keeps the
        # existing rule processing logic unchanged.
        if len(src_specs) > 1 or len(dst_specs) > 1:
            for src in src_specs:
                for dst in dst_specs:
                    new_cols = list(cols)
                    new_cols[1] = src
                    if len(new_cols) > 2:
                        new_cols[2] = dst
                    else:
                        new_cols.append(dst)
                    expanded_line = ConfigLine(
                        columns=new_cols,
                        file=line.file,
                        lineno=line.lineno,
                        comment_tag=line.comment_tag,
                        section=line.section,
                        raw=line.raw,
                        format_version=line.format_version,
                    )
                    _process_rules(ir, [expanded_line], zones)
            continue

        source_spec = source_spec_raw
        dest_spec = dest_spec_raw
        proto = cols[3] if len(cols) > 3 else None
        dport = cols[4] if len(cols) > 4 else None
        sport = cols[5] if len(cols) > 5 else None
        origdest = cols[6] if len(cols) > 6 else None
        rate = cols[7] if len(cols) > 7 else None
        user = cols[8] if len(cols) > 8 else None
        mark = cols[9] if len(cols) > 9 else None
        connlimit = cols[10] if len(cols) > 10 else None
        time_col = cols[11] if len(cols) > 11 else None
        headers = cols[12] if len(cols) > 12 else None
        switch = cols[13] if len(cols) > 13 else None
        helper = cols[14] if len(cols) > 14 else None

        # Handle defaults
        for v in (proto, dport, sport, origdest, rate, user, mark,
                  connlimit, time_col, headers, switch, helper):
            pass  # Can't use locals() trick, handle individually
        if proto == "-": proto = None
        if dport == "-": dport = None
        if sport == "-": sport = None
        if origdest == "-": origdest = None
        if rate == "-": rate = None
        if user == "-": user = None
        if mark == "-": mark = None
        if connlimit == "-": connlimit = None
        if time_col == "-": time_col = None
        if headers == "-": headers = None
        if switch == "-": switch = None
        if helper == "-": helper = None

        # Normalize protocol name to lowercase so that `TCP`/`tcp`/`Tcp`
        # all produce the same nft field name (e.g. `tcp dport 80`).
        # nft rejects uppercase protocol identifiers.
        if proto:
            proto = proto.lower()

        # Parse action — may be macro like SSH(ACCEPT), Ping/ACCEPT, or plain ACCEPT
        macro_match = _MACRO_RE.match(action_str) or _SLASH_MACRO_RE.match(action_str)
        if macro_match:
            macro_name = macro_match.group(1)
            verdict_str = macro_match.group(2)
            log_tag = macro_match.group(3)
            _expand_macro(ir, zones, macro_name, verdict_str, log_tag,
                          source_spec, dest_spec, proto, dport, sport, line)
        else:
            # Check for action:loglevel pattern
            log_prefix = None
            if ":" in action_str:
                action_str, log_tag = action_str.split(":", 1)
                log_prefix = log_tag if log_tag and log_tag != "-" else None

            # Rfc1918: drop RFC1918 source addresses — one rule per range
            if action_str == "Rfc1918":
                verdict = _parse_verdict("DROP")
                src_zone = source_spec.split(":")[0]
                for rfc_range in _RFC1918_RANGES.split(","):
                    _add_rule(ir, zones, verdict, log_prefix,
                              f"{src_zone}:{rfc_range}",
                              dest_spec, proto, dport, sport, line)
                continue

            # Limit:TAG — rate-limited action
            if action_str.startswith("Limit"):
                _add_rule(ir, zones, Verdict.ACCEPT, log_prefix,
                          source_spec, dest_spec, proto, dport, sport, line)
                continue

            # AUDIT actions: A_ACCEPT, A_DROP, A_REJECT
            # These log to the kernel audit subsystem then apply the verdict
            if action_str.startswith("A_"):
                base_action = action_str[2:]  # Strip A_ prefix
                verdict = _parse_verdict(base_action)
                if verdict:
                    _add_rule(ir, zones, verdict, log_prefix,
                              source_spec, dest_spec, proto, dport, sport, line,
                              verdict_args=AuditVerdict(base_action=base_action))
                    continue

            # Check if it's a known action → jump to action chain
            from shorewall_nft.compiler.actions import ACTION_CHAIN_MAP
            if action_str in ACTION_CHAIN_MAP:
                chain_name = ACTION_CHAIN_MAP[action_str]
                _add_rule(ir, zones, Verdict.JUMP, log_prefix,
                          source_spec, dest_spec, proto, dport, sport, line,
                          verdict_args=chain_name, origdest=origdest,
                          rate=rate, user=user, mark=mark,
                          connlimit=connlimit, time_match=time_col,
                          headers=headers, switch=switch, helper=helper)
                continue

            verdict = _parse_verdict(action_str)
            if verdict is None:
                continue

            _add_rule(ir, zones, verdict, log_prefix,
                      source_spec, dest_spec, proto, dport, sport, line,
                      origdest=origdest, rate=rate, user=user, mark=mark,
                      connlimit=connlimit, time_match=time_col,
                      headers=headers, switch=switch, helper=helper)


def _expand_macro(ir: FirewallIR, zones: ZoneModel,
                  macro_name: str, verdict_str: str, log_tag: str | None,
                  source_spec: str, dest_spec: str,
                  proto: str | None, dport: str | None, sport: str | None,
                  line: ConfigLine) -> None:
    """Expand a macro into individual rules."""
    verdict = _parse_verdict(verdict_str)
    if verdict is None:
        return

    log_prefix = None
    if log_tag and log_tag != "-":
        log_prefix = log_tag

    # Native-handled macros
    if macro_name == "Rfc1918":
        src_zone = source_spec.split(":")[0]
        for rfc_range in _RFC1918_RANGES.split(","):
            _add_rule(ir, zones, verdict, log_prefix,
                      f"{src_zone}:{rfc_range}",
                      dest_spec, proto, dport, sport, line)
        return

    # Check custom macros (populated from both bundled Shorewall macro
    # files and user-supplied macros; user overrides take precedence).
    custom = _CUSTOM_MACROS.get(macro_name)
    if custom:
        # Detect if calling context is IPv6:
        # - Source/dest has IPv6 addresses
        # - Source/dest zones are ipv6 type
        # - The rule comes from a shorewall6 config
        ctx_is_v6 = (is_ipv6_spec(source_spec) or is_ipv6_spec(dest_spec))
        if not ctx_is_v6:
            # Check zone types
            src_z = source_spec.split(":<")[0].split(":")[0]
            dst_z = dest_spec.split(":<")[0].split(":")[0]
            if src_z == "$FW":
                src_z = zones.firewall_zone
            if dst_z == "$FW":
                dst_z = zones.firewall_zone
            for z in (src_z, dst_z):
                if z in zones.zones and zones.zones[z].zone_type == "ipv6":
                    ctx_is_v6 = True
                    break
        # Also check if the config line comes from a shorewall6 directory
        if not ctx_is_v6 and line.file and "shorewall6" in line.file:
            ctx_is_v6 = True
        ctx_is_v4 = not ctx_is_v6

        for entry in custom:
            m_action, m_source, m_dest, m_proto, m_dport, m_sport = entry

            # Filter entries by address family — skip v4 entries in v6
            # context and vice versa
            entry_has_v6 = any(is_ipv6_spec(str(f)) for f in (m_source, m_dest)
                               if f not in ("SOURCE", "DEST", "-", "PARAM"))
            entry_has_v4 = any(
                f not in ("SOURCE", "DEST", "-", "PARAM") and f[0:1].isdigit()
                for f in (m_source, m_dest)
            )
            if entry_has_v6 and ctx_is_v4:
                continue  # Skip IPv6 entry in IPv4 context
            if entry_has_v4 and ctx_is_v6:
                continue  # Skip IPv4 entry in IPv6 context

            # Resolve PARAM -> calling verdict
            if m_action == "PARAM":
                m_verdict = verdict
            else:
                m_verdict = _parse_verdict(m_action)
                if m_verdict is None:
                    # m_action might be a sub-macro (e.g. Web → HTTP, HTTPS)
                    # Recursively expand it
                    sub_source = source_spec if m_source in ("SOURCE", "-") else m_source
                    sub_dest = dest_spec if m_dest in ("DEST", "-") else m_dest
                    sub_proto = m_proto if m_proto != "-" else proto
                    sub_dport = m_dport if m_dport != "-" else dport
                    sub_sport = m_sport if m_sport != "-" else sport
                    _expand_macro(ir, zones, m_action, verdict_str, log_tag,
                                  sub_source, sub_dest,
                                  sub_proto, sub_dport, sub_sport, line)
                    continue

            # Resolve SOURCE/DEST placeholders
            # SOURCE → calling rule's source, DEST → calling rule's dest
            # Reverse rules use DEST as source and SOURCE as dest
            if m_source == "SOURCE":
                actual_source = source_spec
            elif m_source == "DEST":
                actual_source = dest_spec
            elif m_source == "-":
                actual_source = source_spec
            else:
                actual_source = m_source

            if m_dest == "DEST":
                actual_dest = dest_spec
            elif m_dest == "SOURCE":
                actual_dest = source_spec
            elif m_dest == "-":
                actual_dest = dest_spec
            else:
                actual_dest = m_dest

            # If macro provides raw IP addresses (not SOURCE/DEST/zone),
            # combine them with the calling rule's zone context.
            # Only for values that are NOT already zone-prefixed.
            # IPv4 raw: starts with digit, no colon
            if actual_source and actual_source[0].isdigit() and ":" not in actual_source:
                src_zone_ctx = source_spec.split(":")[0] if ":" in source_spec else source_spec
                if src_zone_ctx not in ("all", "any"):
                    actual_source = f"{src_zone_ctx}:{actual_source}"
            if actual_dest and actual_dest[0].isdigit() and ":" not in actual_dest:
                dst_zone_ctx = dest_spec.split(":")[0] if ":" in dest_spec else dest_spec
                if dst_zone_ctx not in ("all", "any"):
                    actual_dest = f"{dst_zone_ctx}:{actual_dest}"

            # IPv6 raw: starts with < (angle-bracket from shorewall6 macro)
            # These ONLY come from merged v6 macros with literal addresses
            if actual_source and actual_source.startswith("<"):
                src_zone_ctx = source_spec.split(":<")[0].split(":")[0]
                if src_zone_ctx == "$FW":
                    src_zone_ctx = zones.firewall_zone
                if src_zone_ctx in zones.zones and src_zone_ctx not in ("all", "any"):
                    actual_source = f"{src_zone_ctx}:<{actual_source.strip('<>')}>"
            if actual_dest and actual_dest.startswith("<"):
                dst_zone_ctx = dest_spec.split(":<")[0].split(":")[0]
                if dst_zone_ctx == "$FW":
                    dst_zone_ctx = zones.firewall_zone
                if dst_zone_ctx in zones.zones and dst_zone_ctx not in ("all", "any"):
                    actual_dest = f"{dst_zone_ctx}:<{actual_dest.strip('<>')}>"

            # Resolve proto/port: calling rule overrides macro defaults
            actual_proto = proto if proto else (m_proto if m_proto != "-" else None)
            actual_dport = dport if dport else (m_dport if m_dport != "-" else None)
            actual_sport = sport if sport else (m_sport if m_sport != "-" else None)

            _add_rule(ir, zones, m_verdict, log_prefix,
                      actual_source, actual_dest, actual_proto, actual_dport,
                      actual_sport, line)
        return

    # Unknown macro — treat as simple action with given proto/port
    _add_rule(ir, zones, verdict, log_prefix,
              source_spec, dest_spec, proto, dport, sport, line)


def _add_rule(ir: FirewallIR, zones: ZoneModel,
              verdict: Verdict, log_prefix: str | None,
              source_spec: str, dest_spec: str,
              proto: str | None, dport: str | None, sport: str | None,
              line: ConfigLine, verdict_args: SpecialVerdict | str | None = None,
              origdest: str | None = None,
              rate: str | None = None,
              user: str | None = None,
              mark: str | None = None,
              connlimit: str | None = None,
              time_match: str | None = None,
              headers: str | None = None,
              switch: str | None = None,
              helper: str | None = None) -> None:
    """Add a rule to the appropriate chain(s)."""
    src_zone, src_addrs = _parse_zone_spec(source_spec, zones)
    dst_zone, dst_addrs = _parse_zone_spec(dest_spec, zones)

    # Determine source/dest zones ("any" is a Shorewall synonym for "all")
    src_zones = zones.all_zone_names() if src_zone in ("all", "any") else [src_zone]
    dst_zones = zones.all_zone_names() if dst_zone in ("all", "any") else [dst_zone]

    is_all_expansion = src_zone in ("all", "any") or dst_zone in ("all", "any")

    for sz in src_zones:
        for dz in dst_zones:
            # Skip self-zone pairs from "all" expansion
            if sz == dz and is_all_expansion:
                continue

            chain_name = _zone_pair_chain_name(sz, dz, zones)
            chain = ir.get_or_create_chain(chain_name)

            # Shorewall optimization: don't add ACCEPT rules to chains
            # that already have ACCEPT policy (redundant).
            # Only applies to "all" expansion — explicit rules always go in.
            # Exception: FASTACCEPT=No means established traffic goes through
            # all chains, so ACCEPT rules ARE needed for accounting.
            fastaccept = getattr(ir, '_fastaccept', True)
            if (is_all_expansion and verdict == Verdict.ACCEPT
                    and chain.policy == Verdict.ACCEPT
                    and not verdict_args
                    and fastaccept):
                continue

            # Symmetric optimisation for DROP/REJECT: a rule like
            # `DROP:$LOG customer-a any` expands into every customer-a→X chain.
            # If the chain's policy is *also* drop-class, the inline
            # rule is redundant — and worse, when it lands mid-chain
            # (because file order has it BEFORE later `all → adm:host`
            # accept rules) it shadows everything that follows. The
            # iptables backend simply omits these rules; we mirror
            # that behaviour. Only triggers for catch-all expansions
            # without any host/proto/port narrowing — explicit
            # `customer-a→adm DROP` stays in the chain.
            drop_like = (Verdict.DROP, Verdict.REJECT)
            chain_drops = chain.policy in drop_like
            rule_is_drop_like = verdict in drop_like
            if (is_all_expansion and rule_is_drop_like and chain_drops
                    and not verdict_args
                    and not src_addrs and not dst_addrs
                    and not proto and not dport and not sport
                    and not origdest and not headers
                    and not mark and not connlimit and not user
                    and not time_match and not switch and not helper):
                continue

            rule = Rule(
                verdict=verdict,
                verdict_args=verdict_args,
                comment=line.comment_tag,
                source_file=line.file,
                source_line=line.lineno,
            source_raw=line.raw,
            )

            # Add matches — detect IPv4 vs IPv6 addresses
            has_v4_addr = False
            has_v6_addr = False

            # W16: bracket-flag metadata from the pre-pass (if any).
            # These are lists of (side, set_name, negate) produced by
            # _rewrite_bracket_spec and stored as transient attributes on
            # the ConfigLine by the bracket pre-pass in _process_rules.
            _bsrc: list[tuple[str, str, bool]] = getattr(line, "_bracket_src", [])
            _bdst: list[tuple[str, str, bool]] = getattr(line, "_bracket_dst", [])

            # Map side ("src"/"dst") → (ipv4-field, ipv6-field)
            _SIDE_FIELD: dict[str, tuple[str, str]] = {
                "src": ("ip saddr", "ip6 saddr"),
                "dst": ("ip daddr", "ip6 daddr"),
            }

            if src_addrs:
                negate = src_addrs.startswith("!")
                clean_addr = src_addrs.lstrip("!")
                # Shorewall MAC syntax: ~XX-XX-XX-XX-XX-XX (dash-separated).
                # Convert to nft ether-addr match with colon separators.
                if clean_addr.startswith("~") and _is_mac_addr(clean_addr[1:]):
                    mac = clean_addr[1:].replace("-", ":").lower()
                    rule.matches.append(
                        Match(field="ether saddr", value=mac, negate=negate))
                elif _bsrc:
                    # Bracket-flag metadata present: emit one Match per
                    # (side, set_name) entry produced by the pre-pass.
                    for _side, _sname, _neg in _bsrc:
                        _f4, _f6 = _SIDE_FIELD[_side]
                        _set_val = f"+{_sname}"
                        if _set_val.endswith("_v6"):
                            rule.matches.append(
                                Match(field=_f6, value=_set_val, negate=_neg,
                                      force_side=_side))
                            has_v6_addr = True
                        else:
                            rule.matches.append(
                                Match(field=_f4, value=_set_val, negate=_neg,
                                      force_side=_side))
                            has_v4_addr = True
                elif clean_addr.startswith("+dns_") and clean_addr.endswith("_v6"):
                    # DNS-backed set sentinel produced by the pre-pass
                    # in _process_rules. Force ip6 family; bare name
                    # has no colons, so is_ipv6_spec would misclassify.
                    rule.matches.append(Match(
                        field="ip6 saddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                elif clean_addr.startswith("+dns_") and clean_addr.endswith("_v4"):
                    rule.matches.append(Match(
                        field="ip saddr", value=clean_addr, negate=negate))
                    has_v4_addr = True
                elif is_ipv6_spec(clean_addr):
                    rule.matches.append(Match(field="ip6 saddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                else:
                    rule.matches.append(Match(field="ip saddr", value=clean_addr, negate=negate))
                    has_v4_addr = True

            if dst_addrs:
                negate = dst_addrs.startswith("!")
                clean_addr = dst_addrs.lstrip("!")
                if _bdst:
                    # Bracket-flag metadata for DEST column.
                    for _side, _sname, _neg in _bdst:
                        _f4, _f6 = _SIDE_FIELD[_side]
                        _set_val = f"+{_sname}"
                        if _set_val.endswith("_v6"):
                            rule.matches.append(
                                Match(field=_f6, value=_set_val, negate=_neg,
                                      force_side=_side))
                            has_v6_addr = True
                        else:
                            rule.matches.append(
                                Match(field=_f4, value=_set_val, negate=_neg,
                                      force_side=_side))
                            has_v4_addr = True
                elif clean_addr.startswith("+dns_") and clean_addr.endswith("_v6"):
                    rule.matches.append(Match(
                        field="ip6 daddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                elif clean_addr.startswith("+dns_") and clean_addr.endswith("_v4"):
                    rule.matches.append(Match(
                        field="ip daddr", value=clean_addr, negate=negate))
                    has_v4_addr = True
                elif is_ipv6_spec(clean_addr):
                    rule.matches.append(Match(field="ip6 daddr", value=clean_addr, negate=negate))
                    has_v6_addr = True
                else:
                    rule.matches.append(Match(field="ip daddr", value=clean_addr, negate=negate))
                    has_v4_addr = True

            # ORIGDEST: match on original destination (before DNAT)
            if origdest:
                rule.matches.append(Match(field="ct original daddr", value=origdest))

            # Family restriction for dual-stack:
            # In a merged inet table, rules without address matches
            # apply to BOTH families. We must restrict them to the
            # correct family to avoid cross-family leaks.
            if not has_v4_addr and not has_v6_addr:
                is_from_v6 = line.file and "shorewall6" in line.file
                is_from_v4 = line.file and "shorewall6" not in line.file
                if is_from_v6:
                    rule.matches.insert(0, Match(
                        field="meta nfproto", value="ipv6"))
                elif is_from_v4:
                    rule.matches.insert(0, Match(
                        field="meta nfproto", value="ipv4"))

            # No interface matches here — dispatch in base chains handles that

            # Detect if this rule is in IPv6 context
            is_v6 = any(m.field.startswith("ip6 ") or
                        (m.field == "meta nfproto" and m.value == "ipv6")
                        for m in rule.matches)

            # ICMP type code mapping: IPv4 ↔ IPv6
            _ICMP4_TO_6: dict[str, str] = {
                "8": "128", "echo-request": "echo-request",
                "0": "129", "echo-reply": "echo-reply",
                "3": "1",   # destination-unreachable
                "11": "3",  # time-exceeded
                "12": "4",  # parameter-problem
            }
            _ICMP6_TO_4: dict[str, str] = {v: k for k, v in _ICMP4_TO_6.items()}

            if proto:
                # Auto-translate icmp ↔ icmpv6 based on address family
                actual_proto = proto
                actual_dport_icmp = dport
                if proto == "icmp" and is_v6:
                    actual_proto = "icmpv6"
                    if dport and dport in _ICMP4_TO_6:
                        actual_dport_icmp = _ICMP4_TO_6[dport]
                elif proto == "icmpv6" and not is_v6 and not any(
                    m.field.startswith("ip6 ") for m in rule.matches):
                    actual_proto = "icmp"
                    if dport and dport in _ICMP6_TO_4:
                        actual_dport_icmp = _ICMP6_TO_4[dport]

                if actual_proto in ("icmp", "icmpv6"):
                    rule.matches.append(Match(field="meta l4proto", value=actual_proto))
                    if actual_dport_icmp:
                        rule.matches.append(Match(field=f"{actual_proto} type", value=actual_dport_icmp))
                elif proto == "icmpv6":
                    rule.matches.append(Match(field="meta l4proto", value="icmpv6"))
                    if dport:
                        rule.matches.append(Match(field="icmpv6 type", value=dport))
                else:
                    rule.matches.append(Match(field="meta l4proto", value=proto))
                    if dport:
                        rule.matches.append(Match(field=f"{proto} dport", value=dport))
                    if sport:
                        rule.matches.append(Match(field=f"{proto} sport", value=sport))

            if log_prefix:
                # Generate Shorewall-style log prefix: "Shorewall:chain:action:"
                nft_log_prefix = f"Shorewall:{chain_name}:{verdict.value.upper()}:"
                log_level = log_prefix  # The original value is the syslog level
                log_rule = Rule(
                    matches=list(rule.matches),
                    verdict=Verdict.LOG,
                    log_prefix=nft_log_prefix,
                    log_level=log_level,
                    source_file=line.file,
                    source_line=line.lineno,
                source_raw=line.raw,
                )
                chain.rules.append(log_rule)

            # HEADERS (col 13): IPv6 extension header matching
            if headers:
                _HEADER_MAP = {
                    "hop": "hbh", "dst": "dst", "route": "rt",
                    "frag": "frag", "auth": "ah", "esp": "esp",
                    "none": "none", "protocol": "proto",
                }
                for hdr in headers.replace("any:", "").replace("exactly:", "").split(","):
                    hdr = hdr.strip().lstrip("!")
                    nft_hdr = _HEADER_MAP.get(hdr, hdr)
                    rule.matches.append(Match(
                        field="exthdr", value=nft_hdr,
                        negate=headers.startswith("!")))

            # SWITCH (col 14): conditional rule via conntrack mark
            if switch:
                rule.matches.append(Match(field="ct mark", value=switch))

            # HELPER (col 15): match by ct helper
            if helper:
                rule.matches.append(Match(field="ct helper", value=f'"{helper}"'))

            # Inline matches (;; passthrough from config columns)
            for col in line.columns:
                if col.startswith(";;"):
                    inline_text = col[2:].strip()
                    if inline_text:
                        # Convert iptables inline to nft equivalent where possible
                        # Common patterns: -m set --match-set, -m recent, etc.
                        rule.matches.append(Match(field="inline", value=inline_text))

            # Rate limit: s:name:rate/unit:burst → nft limit
            if rate:
                rule.rate_limit = _parse_rate_limit(rate)
            if user:
                rule.user_match = user
            if mark:
                rule.mark_match = mark
            if connlimit:
                rule.connlimit = connlimit
            if time_match:
                rule.time_match = time_match

            chain.rules.append(rule)
