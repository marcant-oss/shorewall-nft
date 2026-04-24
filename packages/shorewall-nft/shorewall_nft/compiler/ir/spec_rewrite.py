"""Token/spec rewriters for DNS, DNSR, nfset, and bracket-ipset syntax.

Each ``_spec_contains_*`` predicate detects a specific token form in a
spec string (e.g. ``nfset:foo``, ``dns:example.com``, ``+setname[src]``).
Each ``_rewrite_*_spec`` helper converts the detected form into its
family-specific nft sentinel (e.g. ``+nfset_foo_v4``).
``expand_line_for_tokens`` is the orchestrator that clones a
``ConfigLine`` into v4/v6 variants when any such token is present.

Consumers: ir/__init__.py (re-exports everything), compiler/nat.py and
compiler/tc.py import ``expand_line_for_tokens`` directly.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.nft.dns_sets import (
    DnsrRegistry,
    DnsSetRegistry,
    canonical_qname,
    is_valid_hostname,
    qname_to_set_name,
)
from shorewall_nft.nft.nfsets import (
    NfSetRegistry,
    nfset_to_set_name,
)

if TYPE_CHECKING:
    from shorewall_nft.compiler.ir._data import FirewallIR

_log = logging.getLogger(__name__)


def _spec_contains_dns_token(spec: str) -> bool:
    """Cheap test for ``dns:HOSTNAME`` or ``dnst:HOSTNAME`` in a raw spec column.

    Covers every shape the compiler's rule parser accepts for a
    DNS-managed address: bare ``dns:host`` / ``dnst:host``,
    zone-prefixed ``net:dns:host`` / ``net:dnst:host``, leading negation
    ``!dns:host`` / ``!dnst:host``, and zone-prefixed inner negation
    ``net:!dns:host`` / ``net:!dnst:host``.

    ``dnst:`` is an alias for ``dns:`` (W13).  The rewriter handles both
    tokens identically; ``dns:`` additionally emits a deprecation warning.
    """
    return (
        spec.startswith("dns:")
        or spec.startswith("!dns:")
        or ":dns:" in spec
        or ":!dns:" in spec
        or spec.startswith("dnst:")
        or spec.startswith("!dnst:")
        or ":dnst:" in spec
        or ":!dnst:" in spec
    )


def _rewrite_dns_spec(
    spec: str,
    registry: DnsSetRegistry,
    family: str,
    dnsr_registry: DnsrRegistry | None = None,
    config_path: str = "",
    dns_warned: set[str] | None = None,
) -> str:
    """Replace any ``dns:hostname[,hostname…]`` or ``dnst:hostname[,hostname…]``
    token in ``spec`` with the compiled set-reference sentinel
    ``+dns_<sanitised>_<family>``.

    ``dnst:`` is an alias for ``dns:`` (W13).  Both tokens produce identical
    IR output.  A one-per-config-path deprecation warning is emitted whenever
    the older ``dns:`` form is encountered; use ``dnst:`` in new configs.

    Supports every negation shape Shorewall accepts:

    * ``dns:host`` / ``dnst:host``        — bare
    * ``!dns:host`` / ``!dnst:host``      — whole-spec negation
    * ``net:dns:host`` / ``net:dnst:host`` — zone-prefixed
    * ``net:!dns:host`` / ``net:!dnst:host`` — zone-prefixed inner negation
    * ``<dns:host>`` / ``net:<dns:host>`` — ipv6 angle brackets (rare
      but grammatically valid)

    Multi-host ``dns:host1,host2,…`` is supported: the first hostname
    is the primary (its set is what the rule references); the rest
    are registered as tap-alias secondaries so shorewalld's tap
    pipeline routes their DNS answers into the primary's set.  This
    mirrors ``dnsr:`` multi-host semantics but without active pull
    resolution — ``dnsr_registry`` records the group with
    ``pull_enabled=False``.

    The zone prefix (if any) and negation marker (wherever it sat)
    are preserved verbatim on the rewritten sentinel so
    ``_parse_zone_spec`` and ``_add_rule`` downstream handle it
    with their existing codepaths.

    Side-effect: registers the canonicalised hostname(s) with
    ``registry`` so the emitter later produces matching set
    declarations.  Invalid hostnames are left untouched — the
    caller's existing parser will reject them with a syntactic
    error further down the line.
    """
    prefix = ""
    body = spec
    sentinel_negate = ""
    used_legacy_dns = False  # set True when the matched token is dns:, not dnst:

    if body.startswith("dns:"):
        host_str = body[4:]
        used_legacy_dns = True
    elif body.startswith("dnst:"):
        host_str = body[5:]
    elif body.startswith("!dns:"):
        sentinel_negate = "!"
        host_str = body[5:]
        used_legacy_dns = True
    elif body.startswith("!dnst:"):
        sentinel_negate = "!"
        host_str = body[6:]
    else:
        # ``zone:[!]dns:hostname`` or ``zone:[!]dnst:hostname`` —
        # split off the zone prefix at the first colon.
        colon = body.find(":")
        if colon < 0:
            return spec
        prefix = body[: colon + 1]
        rest = body[colon + 1:]
        if rest.startswith("dns:"):
            host_str = rest[4:]
            used_legacy_dns = True
        elif rest.startswith("dnst:"):
            host_str = rest[5:]
        elif rest.startswith("!dns:"):
            sentinel_negate = "!"
            host_str = rest[5:]
            used_legacy_dns = True
        elif rest.startswith("!dnst:"):
            sentinel_negate = "!"
            host_str = rest[6:]
        else:
            return spec

    # Emit one deprecation warning per config path when dns: is used.
    if used_legacy_dns:
        key = config_path or "<unknown>"
        _warned = dns_warned if dns_warned is not None else set()
        if key not in _warned:
            _warned.add(key)
            _log.warning(
                "'dns:' prefix is deprecated; use 'dnst:' instead (config: %s)",
                key,
            )

    # Strip any ipv6 angle brackets — grammatically legal for DNS
    # tokens even though they're nonsensical.
    host_str = host_str.rstrip(">").lstrip("<")
    raw_hosts = [h.strip() for h in host_str.split(",") if h.strip()]
    if not raw_hosts:
        return spec
    for h in raw_hosts:
        if not is_valid_hostname(h):
            return spec

    qnames = [canonical_qname(h) for h in raw_hosts]
    primary = qnames[0]

    # Primary always materialises the nft set; secondaries only enter
    # the allowlist so the tap filter forwards them through a tracker
    # alias into the primary's set.
    registry.add_from_rule(primary, declare_set=True)
    for qn in qnames[1:]:
        registry.add_from_rule(qn, declare_set=False)

    # Multi-host dns: needs the same tap-alias plumbing as dnsr: so
    # the daemon installs add_qname_alias for the secondaries. Record
    # the group in dnsr_registry with pull_enabled=False — same data
    # shape, no active resolution. Single-host dns: is a pure set
    # reference and doesn't need an alias entry.
    if len(qnames) > 1 and dnsr_registry is not None:
        dnsr_registry.add_from_rule(primary, qnames, pull_enabled=False)

    set_name = qname_to_set_name(primary, family)
    return f"{prefix}{sentinel_negate}+{set_name}"


def _spec_contains_dnsr_token(spec: str) -> bool:
    """Cheap test for ``dnsr:HOSTNAME[,HOSTNAME…]`` embedded in a spec column.

    Mirrors :func:`_spec_contains_dns_token` but for the pull-resolver
    variant.  Covers bare, negated, zone-prefixed, and zone+negation forms.
    """
    return (
        spec.startswith("dnsr:")
        or spec.startswith("!dnsr:")
        or ":dnsr:" in spec
        or ":!dnsr:" in spec
    )


def _rewrite_dnsr_spec(
    spec: str,
    dns_registry: DnsSetRegistry,
    dnsr_registry: DnsrRegistry,
    family: str,
) -> str:
    """Replace a ``dnsr:host[,host…]`` token with the same sentinel as ``dns:``.

    The primary hostname (first in the comma list) is registered in
    ``dns_registry`` so the emitter declares the ``dns_<primary>_v4/v6``
    sets.  The full hostname list is recorded in ``dnsr_registry`` so the
    daemon's PullResolver knows which hostnames to actively resolve into
    that set.

    Secondary hostnames are also registered individually in ``dns_registry``
    so the tap pipeline's qname-filter accepts their DNS answers and
    routes them to the same set via tracker aliases.

    The returned sentinel is identical to a ``dns:primary`` rewrite
    (``+dns_<primary>_<family>``), so the downstream IR and emitter need
    no changes.
    """
    prefix = ""
    body = spec
    sentinel_negate = ""

    if body.startswith("dnsr:"):
        host_str = body[5:]
    elif body.startswith("!dnsr:"):
        sentinel_negate = "!"
        host_str = body[6:]
    else:
        colon = body.find(":")
        if colon < 0:
            return spec
        prefix = body[: colon + 1]
        rest = body[colon + 1:]
        if rest.startswith("dnsr:"):
            host_str = rest[5:]
        elif rest.startswith("!dnsr:"):
            sentinel_negate = "!"
            host_str = rest[6:]
        else:
            return spec

    host_str = host_str.rstrip(">").lstrip("<")
    raw_hosts = [h.strip() for h in host_str.split(",") if h.strip()]
    if not raw_hosts:
        return spec
    for h in raw_hosts:
        if not is_valid_hostname(h):
            return spec

    qnames = [canonical_qname(h) for h in raw_hosts]
    primary = qnames[0]

    # Primary materialises the nft set; secondaries only enter the
    # allowlist so the tap filter passes their answers through the
    # tracker alias into the primary's set.
    dns_registry.add_from_rule(primary, declare_set=True)
    for qn in qnames[1:]:
        dns_registry.add_from_rule(qn, declare_set=False)

    # Record the full pull-resolver group (primary + secondaries).
    dnsr_registry.add_from_rule(primary, qnames)

    set_name = qname_to_set_name(primary, family)
    return f"{prefix}{sentinel_negate}+{set_name}"


def _spec_contains_nfset_token(spec: str) -> bool:
    """True if *spec* contains an ``nfset:name`` token in any position.

    Covers every shape the rule parser accepts:

    * ``nfset:name``          — bare
    * ``!nfset:name``         — whole-spec negation
    * ``zone:nfset:name``     — zone-prefixed
    * ``zone:!nfset:name``    — zone-prefixed with inner negation

    Used as a cheap pre-filter so the rewriter below only runs when
    actually needed.
    """
    return (
        spec.startswith("nfset:")
        or spec.startswith("!nfset:")
        or ":nfset:" in spec
        or ":!nfset:" in spec
    )


def _rewrite_nfset_spec(
    spec: str,
    registry: NfSetRegistry,
    family: str,
    line_ctx: str = "",
) -> str:
    """Rewrite an ``nfset:name`` token in *spec* to the nft set sentinel.

    Converts ``net:nfset:myname`` → ``net:+nfset_myname_v4`` (or ``_v6``
    depending on *family*).  Preserves the zone prefix and any negation
    marker in the same position they occupied in the original spec.

    Multi-value ``nfset:a,b`` is **not** handled here — multi-set
    expansion is done by the caller before invoking this function (one
    clone per set name, each with a single name).

    *line_ctx* — optional ``"file:lineno"`` prefix added to the error
    message when *name* is not registered.

    Raises :exc:`ValueError` if the logical name is not registered in
    *registry*.
    """
    prefix = ""
    body = spec
    sentinel_negate = ""

    if body.startswith("nfset:"):
        name = body[6:]
    elif body.startswith("!nfset:"):
        sentinel_negate = "!"
        name = body[7:]
    else:
        colon = body.find(":")
        if colon < 0:
            return spec
        prefix = body[: colon + 1]
        rest = body[colon + 1:]
        if rest.startswith("nfset:"):
            name = rest[6:]
        elif rest.startswith("!nfset:"):
            sentinel_negate = "!"
            name = rest[7:]
        else:
            return spec

    # Strip angle brackets (IPv6 shorewall6 syntax, rare but valid).
    name = name.rstrip(">").lstrip("<")
    if not name:
        return spec

    if name not in registry.set_names:
        where = f"{line_ctx}: " if line_ctx else ""
        raise ValueError(
            f"{where}nfset:{name!r} is not declared in the nfsets config "
            f"file (known sets: {sorted(registry.set_names)})"
        )

    set_name = nfset_to_set_name(name, family)
    return f"{prefix}{sentinel_negate}+{set_name}"


# ---------------------------------------------------------------------------
# W16 — Classic ipsets bracket-flag syntax + AND-multi-set
# ---------------------------------------------------------------------------

# Matches:  +setname[flags]  OR  +setname  (bare, no brackets)
# Also handles zone-prefixed and negated forms after the zone/negate prefix
# has been stripped by the caller.  Only the inner +name[flags] is matched
# here; the outer zone/negate wrapper is preserved by _rewrite_bracket_spec.
#
# Group 1: setname (alphanumeric, hyphens, underscores)
# Group 2: flags string inside [...] (optional)
_BRACKET_SET_RE = re.compile(
    r'^\+([A-Za-z0-9_-]+)(?:\[([A-Za-z,]*)\])?$'
)

# Matches the AND-multi-set form: +[name1,!name2,…]
# Per-member negation (``!name``) is allowed — shorewall syntax for
# "packet must NOT be in this set".  No other punctuation is permitted
# inside the list.  Group 1 is the raw comma-separated body; per-member
# ``!`` prefixes are parsed downstream.
_AND_MULTISET_RE = re.compile(
    r'^\+\[([A-Za-z0-9_,\-! ]+)\]$'
)

_VALID_BRACKET_FLAGS: frozenset[str] = frozenset({"src", "dst", "src,dst", "dst,src"})


def _normalise_bracket_flags(
    flags_raw: str,
    column_side: str,
    line_ctx: str = "",
) -> list[str]:
    """Return list of match sides from bracket flags string.

    ``flags_raw`` is the content inside ``[...]``, e.g. ``"src"`` or
    ``"src,dst"``.  An empty string means "use the column default".

    Returns a list of canonical sides: ``["src"]``, ``["dst"]``, or
    ``["src", "dst"]`` (for the two-side form).

    Raises :exc:`ValueError` for unrecognised flags.
    """
    if not flags_raw:
        return [column_side]

    normed = flags_raw.lower().strip()
    if normed not in _VALID_BRACKET_FLAGS:
        where = f"{line_ctx}: " if line_ctx else ""
        raise ValueError(
            f"{where}invalid bracket flag {flags_raw!r}; "
            f"allowed: src, dst, src,dst (got {flags_raw!r})"
        )
    # Normalise both orderings of the two-side form
    if "," in normed:
        return ["src", "dst"]
    return [normed]


def _spec_contains_bracket_ipset(spec: str) -> bool:
    """True if *spec* requires the bracket pre-pass.

    Returns True only for specs that carry explicit bracket flags or that
    are AND-multi-set lists.  Bare ``+setname`` without brackets does NOT
    trigger this — it is already handled naturally by ``_add_rule`` via the
    existing ipset-reference path (column position determines the field).

    Covered forms:
    * ``+setname[src]`` / ``+setname[dst]`` / ``+setname[src,dst]``
    * ``!+setname[dst]``               — negated bracket
    * ``zone:+setname[src]``           — zone-prefixed bracket
    * ``zone:!+setname[src]``          — zone-prefixed negated bracket
    * ``+[a,b,c]``                     — AND-multi-set
    * ``!+[a,b]``                      — negated AND-multi-set

    NOT covered (falls through to the normal ipset path):
    * ``+setname``                     — bare, no bracket — no pre-pass needed
    """
    # Strip zone prefix (up to and including first colon, not inside <...>)
    body = spec
    if ":" in body and "<" not in body:
        _, _, rest = body.partition(":")
        body = rest
    body = body.lstrip("!")
    if not body.startswith("+"):
        return False
    rest = body[1:]
    # AND-multi-set: +[...]
    if rest.startswith("["):
        return True
    # Bracket flags: +name[...]
    return "[" in rest


def _rewrite_bracket_spec(
    spec: str,
    column_side: str,
    line_ctx: str = "",
) -> tuple[str, list[tuple[str, str, bool]]]:
    """Parse a classic ``+setname[flags]`` / ``+[a,b,c]`` spec.

    Returns a 2-tuple:
    * ``stripped_spec`` — the spec with bracket flags removed (the set
      sentinel still carries the ``+`` prefix so downstream code that
      detects ``+name`` sentinels continues to work).  Zone prefix and
      negation are preserved verbatim.
    * ``match_infos`` — list of ``(side, set_name, negate)`` tuples
      describing the Match objects that should be emitted for this spec.
      ``side`` ∈ ``{"src", "dst"}``; ``set_name`` is bare (no leading
      ``+``); ``negate`` is True when the spec carried a ``!`` prefix.

    The list has:
    * One entry for ``+setname`` / ``+setname[src]`` / ``+setname[dst]``
    * Two entries for ``+setname[src,dst]``
    * N entries for ``+[a,b,c]`` (one per set name, all same side)

    Raises :exc:`ValueError` for invalid bracket content.
    """
    body = spec
    negate = False
    zone_prefix = ""

    # Strip zone prefix
    if ":" in body and "<" not in body:
        colon = body.index(":")
        zone_prefix = body[: colon + 1]
        body = body[colon + 1:]

    # Strip negation
    if body.startswith("!"):
        negate = True
        body = body[1:]

    # AND-multi-set: +[a,!b,c]
    # Per-member negation via leading ``!`` is supported — maps to a
    # negated Match object for that specific member.  The outer
    # whole-spec ``!`` (parsed above as ``negate``) XORs with each
    # per-member bang.
    m_and = _AND_MULTISET_RE.match(body)
    if m_and:
        raw_names = [n.strip() for n in m_and.group(1).split(",") if n.strip()]
        if not raw_names:
            where = f"{line_ctx}: " if line_ctx else ""
            raise ValueError(
                f"{where}empty AND-multi-set list in {spec!r}")
        match_infos = []
        for raw in raw_names:
            mem_negate = raw.startswith("!")
            name = raw[1:] if mem_negate else raw
            if not name:
                where = f"{line_ctx}: " if line_ctx else ""
                raise ValueError(
                    f"{where}empty member name in AND-multi-set {spec!r}")
            # XOR: outer ``!`` flips per-member negation.
            effective_negate = negate ^ mem_negate
            match_infos.append((column_side, name, effective_negate))
        # Return a sentinel spec using the first set name (no brackets).
        # This ensures the recursive _process_rules call does NOT re-fire
        # the bracket pre-pass (no [...] present), while still providing a
        # non-empty address part so _add_rule enters the src_addrs / dst_addrs
        # branch where it reads _bsrc / _bdst for the actual Match objects.
        first_raw = raw_names[0]
        first = first_raw[1:] if first_raw.startswith("!") else first_raw
        sentinel_body = f"+{first}"
        if negate:
            sentinel_body = f"!{sentinel_body}"
        stripped_spec = f"{zone_prefix}{sentinel_body}"
        return stripped_spec, match_infos

    # Single set with optional bracket flags: +setname[flags]
    m_bracket = _BRACKET_SET_RE.match(body)
    if not m_bracket:
        # ``body`` is the spec after stripping zone prefix + whole-spec
        # negation.  If it starts with ``+`` we're in ipset territory
        # (``_spec_contains_bracket_ipset`` already returned True at the
        # caller) but neither regex matched — that is an unparseable
        # bracket form.  Returning ``spec`` unchanged here would let the
        # caller at rules.py:479 recurse forever on the same input, so
        # raise with a clear context.  Non-``+`` specs (plain addresses,
        # zone refs, DNS tokens, …) pass through unchanged — some call
        # paths feed them in and expect a no-op.
        if body.startswith("+"):
            where = f"{line_ctx}: " if line_ctx else ""
            raise ValueError(
                f"{where}unparseable bracket-ipset spec {spec!r}; "
                f"expected +setname[flags] or +[name1,!name2,...]"
            )
        return spec, []

    set_name = m_bracket.group(1)
    # group(2) is None when no brackets present, "" when empty brackets [] used.
    # Empty brackets are invalid — require at least src or dst.
    bracket_content = m_bracket.group(2)
    if bracket_content is not None and bracket_content == "":
        where = f"{line_ctx}: " if line_ctx else ""
        raise ValueError(
            f"{where}empty bracket flags in {spec!r}; "
            f"use [src], [dst], or [src,dst]"
        )
    flags_raw = bracket_content if bracket_content is not None else ""

    sides = _normalise_bracket_flags(flags_raw, column_side, line_ctx)
    match_infos = [(side, set_name, negate) for side in sides]

    # Build the stripped spec (remove bracket portion)
    stripped_body = f"+{set_name}"
    if negate:
        stripped_body = f"!{stripped_body}"
    stripped_spec = f"{zone_prefix}{stripped_body}"

    return stripped_spec, match_infos


# ---------------------------------------------------------------------------
# Per-table token-expansion helpers (used by the functions below)
# ---------------------------------------------------------------------------

def _has_set_token(spec: str) -> bool:
    """True if *spec* contains any nfset:/dns:/dnsr: token."""
    return (
        _spec_contains_nfset_token(spec)
        or _spec_contains_dns_token(spec)
        or _spec_contains_dnsr_token(spec)
    )


def _rewrite_spec_for_family(
    spec: str, ir: "FirewallIR", family: str, line_ctx: str = "",
) -> str:
    """Apply nfset/dns/dnsr rewrites for a single family (v4 or v6).

    Runs nfset → dns → dnsr in order; each rewriter is a no-op when its
    token type is absent.

    *line_ctx* — optional ``"file:lineno"`` prefix forwarded to the nfset
    rewriter so its error messages pinpoint the offending config line.
    """
    if _spec_contains_nfset_token(spec):
        spec = _rewrite_nfset_spec(spec, ir.nfset_registry, family, line_ctx)
    if _spec_contains_dns_token(spec):
        spec = _rewrite_dns_spec(
            spec, ir.dns_registry, family, ir.dnsr_registry,
            dns_warned=ir._dns_deprecation_warned,
        )
    if _spec_contains_dnsr_token(spec):
        spec = _rewrite_dnsr_spec(spec, ir.dns_registry, ir.dnsr_registry, family)
    return spec


def expand_line_for_tokens(
    line: ConfigLine,
    src_col: int,
    dst_col: int | None,
    ir: "FirewallIR",
) -> tuple[bool, list[ConfigLine]]:
    """If *line* carries set/dns tokens, return family-cloned ConfigLines.

    Returns ``(found_tokens, expanded_lines)``.  When *found_tokens* is
    False the caller should process the original line as normal.  When
    True the caller should process each expanded line instead and skip
    the original.

    *src_col* / *dst_col* are the 0-based column indices for SOURCE and
    DEST.  Pass *dst_col=None* when there is no DEST column.
    """
    cols = line.columns
    src_raw = cols[src_col] if src_col < len(cols) else "-"
    dst_raw = cols[dst_col] if dst_col is not None and dst_col < len(cols) else "-"

    if not (_has_set_token(src_raw) or _has_set_token(dst_raw)):
        return False, []

    expanded: list[ConfigLine] = []
    _line_ctx = f"{line.file}:{line.lineno}" if line.file else ""
    for family in ("v4", "v6"):
        new_cols = list(cols)
        new_cols[src_col] = _rewrite_spec_for_family(
            src_raw, ir, family, _line_ctx)
        if dst_col is not None and dst_col < len(cols):
            new_cols[dst_col] = _rewrite_spec_for_family(
                dst_raw, ir, family, _line_ctx)
        expanded.append(ConfigLine(
            columns=new_cols,
            file=line.file,
            lineno=line.lineno,
            comment_tag=line.comment_tag,
            section=line.section,
            raw=line.raw,
            format_version=line.format_version,
        ))
    return True, expanded
