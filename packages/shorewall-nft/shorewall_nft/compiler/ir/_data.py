"""IR data model: enums, dataclasses, and pure helpers.

Contains the backend-agnostic representation (Rule, Chain, FirewallIR,
Match, Verdict, etc.) plus small pure utilities (is_ipv6_spec,
split_nft_zone_pair, _parse_rate_limit, _is_mac_addr).

Consumed by ir/spec_rewrite.py, ir/rules.py, ir/_build.py, and re-
exported from ir/__init__.py so ``from shorewall_nft.compiler.ir
import Rule`` continues to work.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

# Typed verdict union — Rule.verdict_args annotation
from shorewall_nft.compiler.verdicts import SpecialVerdict
from shorewall_nft.config.zones import ZoneModel
from shorewall_nft.nft.dns_sets import DnsrRegistry, DnsSetRegistry
from shorewall_nft.nft.nfsets import NfSetRegistry
from shorewall_nft.runtime.pyroute2_helpers import settings_bool

if TYPE_CHECKING:
    pass

# Unit normalization map shared by _parse_rate_limit and tests.
_UNIT_MAP: dict[str, str] = {
    "sec": "second", "second": "second",
    "min": "minute", "minute": "minute",
    "hour": "hour",
    "day": "day",
}

# Log-level tokens the Shorewall ACTION column may carry as a
# ``:level[:tag]`` suffix on ``Limit:...``. Accepted forms mirror
# syslog priorities plus the numeric 0-7 aliases upstream permits.
_SHOREWALL_LOG_LEVELS: frozenset[str] = frozenset({
    "emerg", "alert", "crit", "err", "error", "warn", "warning",
    "notice", "info", "debug",
    "0", "1", "2", "3", "4", "5", "6", "7",
})


class Verdict(Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"
    JUMP = "jump"
    GOTO = "goto"
    RETURN = "return"


class ChainType(Enum):
    FILTER = "filter"
    NAT = "nat"
    ROUTE = "route"


class Hook(Enum):
    INPUT = "input"
    FORWARD = "forward"
    OUTPUT = "output"
    PREROUTING = "prerouting"
    POSTROUTING = "postrouting"


@dataclass(slots=True, frozen=True)
class RateLimitSpec:
    """Parsed Shorewall rate-limit / hashlimit specification.

    Plain form (LIMIT column: ``12/min:60`` or action ``12/min``)::

        RateLimitSpec(rate=12, unit="minute", burst=60, name=None,
                      per_source=False)

    Named hashlimit form (action column: ``LIMIT:LOGIN,12,60``)::

        RateLimitSpec(rate=12, unit="minute", burst=60, name="LOGIN",
                      per_source=True)

    Named srcip form (LIMIT column: ``s:LOGIN:12/min:60``)::

        RateLimitSpec(rate=12, unit="minute", burst=60, name="LOGIN",
                      per_source=True)
    """
    rate: int
    unit: str       # "second" | "minute" | "hour" | "day"
    burst: int = 5  # default upstream burst
    name: str | None = None
    per_source: bool = False


@dataclass(slots=True)
class Match:
    """A single match condition in a rule."""
    field: str      # e.g. "iifname", "ip saddr", "tcp dport", "ct state"
    value: str      # e.g. "eth0", "10.0.0.0/8", "80", "established"
    negate: bool = False
    # Bracket-flag override (W16): when a classic ipset spec carries an
    # explicit ``[src]`` / ``[dst]`` flag, the effective match field is
    # stored here instead of being derived from the column position.
    # ``None`` means "use the column-position default" (existing behaviour).
    force_side: str | None = None


@dataclass(slots=True)
class Rule:
    """A single firewall rule."""
    matches: list[Match] = field(default_factory=list)
    verdict: Verdict = Verdict.ACCEPT
    verdict_args: SpecialVerdict | str | None = None  # typed verdict, chain name for JUMP/GOTO, or log prefix for LOG
    comment: str | None = None
    counter: bool = False
    log_prefix: str | None = None
    log_level: str | None = None  # e.g. "info", "debug" — typed override for log_level: prefix
    rate_limit: RateLimitSpec | None = None  # parsed rate-limit spec
    connlimit: str | None = None   # e.g. "10" or "10:24" (count[:mask])
    time_match: str | None = None  # e.g. "utc&timestart=8:00&timestop=17:00"
    user_match: str | None = None  # e.g. "nobody"
    mark_match: str | None = None  # e.g. "0x1/0xff"
    source_file: str = ""
    source_line: int = 0
    source_raw: str = ""  # Trimmed raw source line for debug comments


@dataclass(slots=True)
class Chain:
    """A chain containing rules."""
    name: str
    chain_type: ChainType | None = None  # None for non-base chains
    hook: Hook | None = None             # None for non-base chains
    priority: int = 0
    policy: Verdict | None = None
    rules: list[Rule] = field(default_factory=list)
    # Optional log level from the policy file's LOG column. When set
    # and the chain has a DROP/REJECT policy, the chain-tail emit pass
    # inserts a rate-limited ``meter <name> { ip daddr limit rate
    # 5/second burst 10 packets } log level <lvl> prefix "<chain>:..."``
    # rule before the terminal jump.
    policy_log_level: str | None = None
    # Per-family policy slots. When the merged shorewall + shorewall6
    # configs disagree on a zone-pair's policy (e.g. ``dmz net ACCEPT``
    # in v4 + ``dmz all REJECT`` in v6 falling back via the all-
    # expansion), the chain-tail emit pass inserts a family-tagged
    # guard rule for the "minority" family before the terminal jump.
    # When v4 == v6 these are equal and the chain emits a single
    # family-agnostic terminal — current behaviour preserved.
    policy_v4: Verdict | None = None
    policy_v6: Verdict | None = None
    # Mirrors classic shorewall's ``$chainref->{complete}`` flag
    # (``Chains.pm:1832``).  Once a terminating, fully unconditional
    # rule is added (``DROP``/``REJECT``/``-g`` with no host/proto/
    # port narrowing), classic stops appending further rules — line
    # 8400 of ``expand_rule1`` short-circuits with
    # ``return if $chainref->{complete};``.  Real configs lean on
    # this idiom: a wildcard ``DROP:$LOG <zone> any`` blocks the
    # rules-file-tail rules (``?SHELL`` includes, etc.) from ever
    # reaching that ``<zone>2X`` chain.  ``_add_rule`` mirrors the
    # behaviour by checking these flags before appending and
    # setting them when emitting an unconditional terminating
    # verdict.
    #
    # Separate v4 / v6 slots: classic shorewall keeps independent
    # iptables and ip6tables chains, so its single ``complete`` flag
    # is implicitly per-family.  shorewall-nft compiles into a single
    # merged ``inet`` chain, so we track the two slots explicitly to
    # avoid a v4-side close inadvertently swallowing a v6-side rule
    # (or vice versa).
    complete_v4: bool = False
    complete_v6: bool = False

    @property
    def is_base_chain(self) -> bool:
        """Return True if this chain is attached to a netfilter hook.

        Base chains have a non-None ``hook`` (input/forward/output/prerouting/
        postrouting) and carry a ``policy`` verdict.  The emitter uses this to
        decide whether to emit ``type … hook … priority …; policy …;`` header
        lines, and the optimizer skips deduplication passes on base chains.
        Non-base (regular) chains have ``hook=None``.
        """
        return self.hook is not None


def _make_mask(bits: int) -> int:
    """Return a bitmask with the low *bits* bits set (equivalent to Perl make_mask)."""
    if bits <= 0:
        return 0
    return (1 << bits) - 1


@dataclass(frozen=True)
class MarkGeometry:
    """Packet-mark field layout derived from shorewall.conf geometry settings.

    Mirrors the Perl Config.pm mark-geometry block so that all mask
    constants in the emitter are derived from a single, consistent source
    rather than scattered literals.

    Use ``MarkGeometry.from_settings(config.settings)`` to build from a
    parsed shorewall.conf, or ``MarkGeometry.default()`` for the upstream
    defaults when no config is available.
    """
    tc_bits: int
    mask_bits: int
    provider_bits: int
    provider_offset: int
    zone_bits: int
    zone_offset: int

    @property
    def tc_max(self) -> int:
        return _make_mask(self.tc_bits)

    @property
    def tc_mask(self) -> int:
        return _make_mask(self.mask_bits)

    @property
    def provider_mask(self) -> int:
        return _make_mask(self.provider_bits) << self.provider_offset

    @property
    def zone_mask(self) -> int:
        if self.zone_bits:
            return _make_mask(self.zone_bits) << self.zone_offset
        return 0

    @property
    def exclusion_mask(self) -> int:
        return 1 << (self.zone_offset + self.zone_bits)

    @property
    def tproxy_mark(self) -> int:
        return self.exclusion_mask << 1

    @property
    def event_mark(self) -> int:
        return self.tproxy_mark << 1

    @property
    def user_mask(self) -> int:
        userbits = self.provider_offset - self.tc_bits
        if userbits > 0:
            return _make_mask(userbits) << self.tc_bits
        return 0

    @classmethod
    def from_settings(cls, settings: dict[str, str]) -> MarkGeometry:
        """Build from a shorewall.conf settings dict.

        Replicates the Perl Config.pm mark-geometry initialization block
        faithfully, including the default-computation order and the
        PROVIDER_OFFSET clamping rule.
        """
        wide = settings_bool(settings, "WIDE_TC_MARKS", False)
        high = settings_bool(settings, "HIGH_ROUTE_MARKS", False)

        def _int_setting(key: str, default: int) -> int:
            raw = settings.get(key)
            if raw is None:
                return default
            try:
                return int(raw.strip(), 0)
            except (ValueError, AttributeError):
                return default

        tc_bits = _int_setting("TC_BITS", 14 if wide else 8)
        mask_bits = _int_setting("MASK_BITS", 16 if wide else 8)

        provider_offset_default = (16 if wide else 8) if high else 0
        provider_offset = _int_setting("PROVIDER_OFFSET", provider_offset_default)
        provider_bits = _int_setting("PROVIDER_BITS", 8)
        zone_bits = _int_setting("ZONE_BITS", 0)

        if provider_offset:
            if provider_offset < mask_bits:
                provider_offset = mask_bits
            zone_offset = provider_offset + provider_bits
        elif mask_bits >= provider_bits:
            zone_offset = mask_bits
        else:
            zone_offset = provider_bits

        return cls(
            tc_bits=tc_bits,
            mask_bits=mask_bits,
            provider_bits=provider_bits,
            provider_offset=provider_offset,
            zone_bits=zone_bits,
            zone_offset=zone_offset,
        )

    @classmethod
    def default(cls) -> MarkGeometry:
        return cls.from_settings({})


@dataclass
class Provider:
    """A routing provider (ISP).

    Moved here from compiler/providers.py so FirewallIR can carry a
    properly-typed ``list[Provider]`` field without a circular import.
    """
    name: str
    number: int
    mark: int           # raw numeric mark value (0 = no mark)
    interface: str
    duplicate: str | None = None   # routing table to copy
    gateway: str | None = None
    copy: list[str] = field(default_factory=list)
    # Parsed OPTIONS
    track: bool = False
    balance: int = 0       # 0 = not balanced; >0 = weight
    fallback: int = 0      # 0 = not fallback; -1 = bare fallback; >0 = weighted fallback
    loose: bool = False
    optional: bool = False
    persistent: bool = False
    tproxy: bool = False
    # Derived / assigned
    table: str = ""         # routing table id (number or name)


@dataclass
class Route:
    """A static route for a provider.

    Moved here from compiler/providers.py so FirewallIR can carry a
    properly-typed ``list[Route]`` field without a circular import.
    """
    provider: str
    dest: str
    gateway: str | None = None
    device: str | None = None
    persistent: bool = False


@dataclass
class RoutingRule:
    """An ip rule for policy routing.

    Moved here from compiler/providers.py so FirewallIR can carry a
    properly-typed ``list[RoutingRule]`` field without a circular import.
    """
    source: str | None = None
    dest: str | None = None
    provider: str = ""
    priority: int = 0
    mark: str | None = None    # fwmark value, e.g. "0x100/0xff"
    persistent: bool = False


@dataclass
class TcInterface:
    """A simple-device TC entry from the tcinterfaces file.

    Moved here from compiler/tc.py so FirewallIR can carry a
    properly-typed ``list[TcInterface]`` field without a circular import.

    Maps to ``process_simple_device`` in upstream Tc.pm.
    Upstream format: INTERFACE TYPE IN_BANDWIDTH OUT_BANDWIDTH
    where TYPE is 'external' (→ nfct-src) | 'internal' (→ dst) | '-'.
    OUT_BANDWIDTH accepts burst:latency:peak:minburst suffixes (colon-separated).
    """
    interface: str
    flow_type: str = "-"          # '-' | 'nfct-src' | 'dst'
    in_bandwidth: str = ""
    out_bandwidth: str = ""
    out_burst: str = "10kb"       # default upstream burst
    out_latency: str = "200ms"    # default upstream latency
    out_peak: str = ""
    out_minburst: str = ""
    qdisc: str = "htb"            # 'htb' | 'hfsc' | 'cake'
    overhead: str = ""
    mtu: str = ""
    mpu: str = ""


@dataclass
class TcPri:
    """A single tcpri DSCP-to-priority mapping row.

    Moved here from compiler/tc.py so FirewallIR can carry a
    properly-typed ``list[TcPri]`` field without a circular import.

    Maps to ``process_tc_priority`` in upstream Tc.pm.
    Upstream format: BAND PROTO PORT ADDRESS INTERFACE HELPER
    BAND is 1-3 (Linux prio band).
    """
    band: int                    # 1–3
    proto: str = "-"
    port: str = "-"
    address: str = "-"
    interface: str = "-"
    helper: str = "-"


@dataclass(frozen=True)
class SecmarkObject:
    """Table-level ``secmark <name> { "<label>" }`` declaration.

    Populated from the ``secmarks`` config file by
    ``_process_secmarks()``. Rules carrying a ``SecmarkVerdict``
    reference the ``name`` field; the ``label`` field holds the
    SELinux security context string that the kernel uses at
    secmark-resolution time.
    """
    name: str
    label: str


@dataclass
class FirewallIR:
    """Complete intermediate representation of the firewall."""
    zones: ZoneModel = field(default_factory=ZoneModel)
    chains: dict[str, Chain] = field(default_factory=dict)
    settings: dict[str, str] = field(default_factory=dict)
    # Shell-style variable definitions from the ``params`` config file
    # (``KEY=VALUE``).  Stored on the IR so late stages — notably the
    # rule-family heuristic in ``compiler/ir/rules.py`` — can pre-expand
    # ``$VAR`` / ``<$VAR>`` references that appear in a rule's source
    # / destination spec.  Without that expansion the heuristic mis-
    # classifies rules whose addresses live behind a variable name
    # (e.g. ``voice:<$SIP_V6>,<$SIP_HA>``) — see issue tracked in
    # ``docs/testing/reference-known-issues.md``.
    params: dict[str, str] = field(default_factory=dict)
    # Chains for the separate `inet shorewall_stopped` table — populated
    # from routestopped. Kept apart from `chains` so the main emitter
    # never mixes them into the running ruleset.
    stopped_chains: dict[str, Chain] = field(default_factory=dict)
    # Chains for the separate `arp filter` table — populated from
    # arprules. The arp family is its own table type so we keep it
    # apart from the inet chains, which only see L3 IPv4/IPv6 traffic.
    arp_chains: dict[str, Chain] = field(default_factory=dict)
    # Named counter objects from the nfacct file. Each entry maps a
    # name to its (packets, bytes) initial values. Emitted as
    # `counter <name> { packets N bytes M }` declarations at the
    # top of the inet shorewall table.
    nfacct_counters: dict[str, tuple[int, int]] = field(default_factory=dict)
    # Named secmark objects from the secmarks file. Each entry is a
    # ``SecmarkObject(name, label)`` declared at the top of the inet
    # shorewall table as ``secmark <name> { "<label>" }``. Rules
    # generated from the same secmarks rows reference the name via
    # ``meta secmark set "<name>"``. Populated by
    # ``_process_secmarks()`` in ``compiler/ir/_build.py``.
    secmark_objects: list["SecmarkObject"] = field(default_factory=list)
    # DNS-backed nft set registry — populated from rules that use
    # ``dns:hostname`` tokens and from the optional ``dnsnames`` file.
    # The emitter reads this to declare one ``dns_<name>_v4`` /
    # ``dns_<name>_v6`` pair per hostname, and the start command writes
    # a compiled allowlist for shorewalld to consume at runtime.
    dns_registry: DnsSetRegistry = field(default_factory=DnsSetRegistry)
    # Pull-resolver groups — populated from ``dnsr:hostname[,hostname…]``
    # tokens. Uses the same dns_* nft sets as the tap pipeline; the
    # registry carries the extra metadata (secondary qnames) needed by
    # shorewalld's PullResolver to actively maintain those sets.
    dnsr_registry: DnsrRegistry = field(default_factory=DnsrRegistry)
    # Named dynamic nft sets from the ``nfsets`` config file.  Each entry
    # declares a backend (dnstap, resolver, ip-list, ip-list-plain) and a
    # list of hosts/providers.  The emitter declares the nft sets; shorewalld
    # populates them at runtime via ``NfSetsManager``.
    nfset_registry: NfSetRegistry = field(default_factory=NfSetRegistry)

    # Mark field layout derived from WIDE_TC_MARKS / HIGH_ROUTE_MARKS /
    # TC_BITS / MASK_BITS / PROVIDER_BITS / PROVIDER_OFFSET / ZONE_BITS.
    # Populated by build_ir() immediately after the IR is constructed.
    # Default is the upstream defaults (8-bit TC, 8-bit total, low routes).
    mark_geometry: MarkGeometry = field(default_factory=MarkGeometry.default)

    # IP alias lifecycle — populated by process_static_nat() and
    # _process_snat_line() when ADD_IP_ALIASES / ADD_SNAT_ALIASES are
    # enabled in shorewall.conf.  Each tuple is ``(address, iface_name)``.
    # ``runtime/apply.py::apply_ip_aliases`` consumes this list at start;
    # ``remove_ip_aliases`` consumes it at stop (gated on RETAIN_ALIASES).
    ip_aliases: list[tuple[str, str]] = field(default_factory=list)

    # Multi-ISP provider state — populated by build_ir() from the
    # providers / routes / rtrules config files.  Channel-2 consumers
    # (generate-iproute2-rules CLI command) read these after build_ir().
    providers: list[Provider] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    rtrules: list[RoutingRule] = field(default_factory=list)

    # TC simple-device shaping — populated by build_ir() from tcinterfaces
    # and tcpri config files.  Channel-2 consumers (generate-tc, apply_tcinterfaces)
    # read these after build_ir().
    tcinterfaces: list[TcInterface] = field(default_factory=list)
    tcpris: list[TcPri] = field(default_factory=list)

    # Macro registry: populated by _load_standard_macros (bundled Shorewall
    # macros) and _load_custom_macros (user macros override).  Per-compile
    # state — moved here from module-level _CUSTOM_MACROS so repeated
    # build_ir() calls in the same process (parallel tests, daemon usage)
    # are properly isolated.
    macros: dict[str, list[tuple[str, ...]]] = field(default_factory=dict)

    # Per-compile dedup set for the dns: deprecation warnings, so the same
    # hostname only warns once per build_ir() call.  Moved here from
    # module-level _DNS_DEPRECATION_WARNED for the same isolation reason.
    _dns_deprecation_warned: set[str] = field(default_factory=set)

    # Strict-features capability requirements collected by emit paths.
    # ``require_capability`` appends one entry per call site; the
    # ``check_strict_features`` post-pass (in ``shorewall_nft.nft.strict``)
    # validates them against probed capabilities and errors out on misses
    # when ``--strict-features`` is set. Always-empty for configs that
    # don't touch capability-gated features.
    required_features: list = field(default_factory=list)

    def add_chain(self, chain: Chain) -> None:
        """Register ``chain`` in this IR under ``chain.name``.

        Overwrites any existing chain with the same name.  Callers that need
        the lookup-or-insert pattern should use ``get_or_create_chain`` instead.
        """
        self.chains[chain.name] = chain

    def get_or_create_chain(self, name: str) -> Chain:
        """Return the chain named ``name``, creating a plain chain if absent.

        If no chain with ``name`` exists in ``self.chains``, a new ``Chain``
        with only ``name`` set (no hook, no policy, empty rules) is inserted
        and returned.  Subsequent calls with the same name return the same
        object, so callers can accumulate rules across multiple call sites.
        """
        if name not in self.chains:
            self.chains[name] = Chain(name=name)
        return self.chains[name]

    def require_capability(self, capability: str, description: str,
                           source: str | None = None) -> None:
        """Register a kernel-capability requirement for ``--strict-features``.

        Emit paths that depend on a probed capability (e.g.
        ``has_synproxy_stmt``, ``has_tproxy_stmt``) call this with the
        capability attribute name, a human-readable description, and
        optionally a ``file:line`` source hint. The
        :func:`shorewall_nft.nft.strict.check_strict_features` post-pass
        walks the collected list and raises
        :class:`~shorewall_nft.nft.strict.UnsupportedFeatureError` for
        any miss against the probed
        :class:`~shorewall_nft.nft.capabilities.NftCapabilities`.

        No-op outside strict mode (the list is collected anyway, but
        nothing reads it). Cheap — bounded by the number of capability-
        gated emit sites times rules that hit them.
        """
        from shorewall_nft.nft.strict import FeatureRequirement
        self.required_features.append(
            FeatureRequirement(
                capability=capability,
                description=description,
                source=source,
            )
        )


def _parse_rate_limit(rate_str: str) -> RateLimitSpec | None:
    """Parse a Shorewall rate-limit token into a typed ``RateLimitSpec``.

    Accepted forms (mirrors upstream ``do_ratelimit`` in Chains.pm):

    Plain limit column forms:
        ``12/min``          → plain limit, no burst (default 5)
        ``12/min:60``       → plain limit, burst 60
        ``12/second:5``     → plain limit, burst 5

    Named per-source (hashlimit) forms:
        ``s:LOGIN:12/min``         → per-source, name "LOGIN", no burst
        ``s:LOGIN:12/min:60``      → per-source, name "LOGIN", burst 60
        ``s::12/min:60``           → per-source, auto-name, burst 60

    Action-column named form (``LIMIT:name,rate,burst``):
        Callers split the ``LIMIT:`` prefix and pass ``"name,rate,burst"``
        to the helper below — see ``_parse_limit_action()``.

    Returns ``None`` when the token is empty, ``"-"``, or unparseable.
    """
    if not rate_str or rate_str == "-":
        return None

    # Named per-source form: s[/mask]:name:rate/unit[:burst]
    # Also handles anonymous per-source: s::rate/unit[:burst]
    m = re.match(
        r'^s(?:/\d+)?:(\w*):(\d+)/(sec|min|hour|day|second|minute)(?::(\d+))?$',
        rate_str)
    if m:
        name = m.group(1) or None
        rate = int(m.group(2))
        unit = _UNIT_MAP.get(m.group(3), m.group(3))
        burst = int(m.group(4)) if m.group(4) else 5
        return RateLimitSpec(rate=rate, unit=unit, burst=burst,
                             name=name, per_source=True)

    # Plain form: rate/unit[:burst]
    m = re.match(r'^(\d+)/(sec|min|hour|day|second|minute)(?::(\d+))?$', rate_str)
    if m:
        rate = int(m.group(1))
        unit = _UNIT_MAP.get(m.group(2), m.group(2))
        burst = int(m.group(3)) if m.group(3) else 5
        return RateLimitSpec(rate=rate, unit=unit, burst=burst)

    return None


def _strip_limit_log_prefix(name_field: str) -> str | None:
    """Strip an optional ``<level>[:<tag>]:`` prefix from a LIMIT name.

    Shorewall ACTION columns accept the standard ``:level[:tag]`` suffix
    on any action. In ``Limit:info:LOGIN,4,60`` the fragment ``info:LOGIN``
    arrives here as a single comma-segmented token — the ``:`` must be
    peeled off because nft meter identifiers reject ``:``.

    Examples::

        "info:LOGIN"        → "LOGIN"
        "debug:mailclnt"    → "mailclnt"
        "info:SSH:LOGIN"    → "LOGIN"   (level + tag + name)
        "LOGIN"             → "LOGIN"   (unchanged, no colon)
        ""                  → None

    Returns ``None`` when nothing meter-nameable remains (e.g. the input
    was empty or contained only log-level tokens).
    """
    if ":" not in name_field:
        return name_field or None
    tokens = name_field.split(":")
    while tokens and tokens[0].lower() in _SHOREWALL_LOG_LEVELS:
        tokens.pop(0)
    if not tokens:
        return None
    # Remaining head ``tag:name`` keeps only the trailing ``name`` —
    # the tag belongs on the logging side, not on the nft meter.
    return tokens[-1] or None


def _parse_limit_action(param: str) -> RateLimitSpec | None:
    """Parse the ``LIMIT:name,rate,burst`` action-column form.

    The ACTION column may carry ``LIMIT:name,rate,burst`` (Shorewall
    hashlimit shorthand).  The caller strips the ``LIMIT:`` prefix and
    passes the remainder here.

    Examples::

        "LOGIN,12,60"         → RateLimitSpec(rate=12, unit="minute",
                                              burst=60, name="LOGIN",
                                              per_source=True)
        "12,60"               → RateLimitSpec(rate=12, unit="minute",
                                              burst=60, name=None,
                                              per_source=True)
        "info:LOGIN,4,60"     → RateLimitSpec(rate=4,  unit="minute",
                                              burst=60, name="LOGIN",
                                              per_source=True)

    The upstream Shorewall ``LIMIT:`` action always implies per-source
    (srcip hashlimit) and uses ``/minute`` as the default unit — see
    ``process_rule`` in Rules.pm and the ``LIMIT:BURST`` policy column.
    If a ``rate/unit`` token is embedded the unit is honoured; otherwise
    ``/minute`` is assumed.

    Returns ``None`` on parse failure.
    """
    if not param:
        return None
    parts = [p.strip() for p in param.split(",")]
    if len(parts) == 3:
        name_or_rate, rate_or_unit, burst_str = parts
        # name,rate/unit,burst  OR  name,rate,burst (rate implied /minute)
        if "/" in rate_or_unit:
            # name,rate/unit,burst
            name = _strip_limit_log_prefix(name_or_rate) if name_or_rate else None
            m = re.match(r'^(\d+)/(sec|min|hour|day|second|minute)$', rate_or_unit)
            if not m:
                return None
            rate = int(m.group(1))
            unit = _UNIT_MAP.get(m.group(2), m.group(2))
        else:
            # name,rate,burst — rate in /minute
            name = _strip_limit_log_prefix(name_or_rate) if name_or_rate else None
            try:
                rate = int(rate_or_unit)
            except ValueError:
                return None
            unit = "minute"
        try:
            burst = int(burst_str)
        except ValueError:
            return None
        return RateLimitSpec(rate=rate, unit=unit, burst=burst,
                             name=name, per_source=True)
    if len(parts) == 2:
        # Either: rate,burst  or  name,rate (no burst)
        a, b = parts
        if "/" in a:
            m = re.match(r'^(\d+)/(sec|min|hour|day|second|minute)$', a)
            if m:
                rate = int(m.group(1))
                unit = _UNIT_MAP.get(m.group(2), m.group(2))
                burst = int(b) if b.isdigit() else 5
                return RateLimitSpec(rate=rate, unit=unit, burst=burst,
                                     per_source=True)
        # name,rate  (no burst, /minute implied)
        try:
            rate = int(b)
        except ValueError:
            return None
        return RateLimitSpec(rate=rate, unit="minute", burst=5,
                             name=(_strip_limit_log_prefix(a) if a else None),
                             per_source=True)
    if len(parts) == 1:
        # bare rate/unit
        return _parse_rate_limit(parts[0])
    return None


def is_ipv6_spec(addr: str) -> bool:
    """Heuristic: does *addr* describe an IPv6 host/CIDR/set?

    Accepts any of the forms that appear in Shorewall config columns:

    * bare host — ``"192.0.2.1"`` / ``"2001:db8::1"``
    * CIDR — ``"192.0.2.0/24"`` / ``"2001:db8::/32"``
    * negated — ``"!2001:db8::1"``
    * ipset reference — ``"+setname"`` (always False; family is
      encoded in the set sentinel, not the spec)
    * brace-wrapped set — ``"{ 2001:db8::1, 2001:db8::2 }"``
    * comma-separated list — True if *any* member is IPv6

    Returns True if the spec contains at least one IPv6 address.
    False for pure IPv4, empty, and bare ipset references.
    """
    # Strip set braces and check individual addresses
    clean = addr.strip("{ }")
    for part in clean.split(","):
        part = part.strip().lstrip("!")
        if part.startswith("+"):
            continue  # ipset reference
        if ":" in part and not part.startswith("/"):
            return True
    return False


def split_nft_zone_pair(chain_name: str) -> tuple[str, str] | None:
    """Split an nft zone-pair chain name into ``(src_zone, dst_zone)``.

    nft zone-pair chains are emitted as ``"src-dst"`` by the compiler.
    Returns ``None`` for any chain name that doesn't have exactly one
    hyphen-delimited pair (base chains, helper chains, malformed
    names) — callers should skip those.

    Note: zone names themselves may not contain hyphens in this
    project's naming convention, so a simple ``split("-", 1)`` is
    sufficient. The iptables-compatible splitter (separator ``"2"``)
    lives in ``verify/`` where disambiguation against known zones is
    needed.
    """
    parts = chain_name.split("-", 1)
    if len(parts) != 2:
        return None
    return parts[0], parts[1]


_MAC_RE = re.compile(r'^[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1'
                     r'[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}\1[0-9A-Fa-f]{2}$')


def _is_mac_addr(s: str) -> bool:
    """Check if a string is an Ethernet MAC address.

    Accepts both colon-separated (00:22:61:be:37:7a) and Shorewall's
    dash-separated (00-22-61-BE-37-7A) forms.
    """
    return bool(_MAC_RE.match(s))
