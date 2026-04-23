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

if TYPE_CHECKING:
    pass


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
    rate_limit: str | None = None  # e.g. "30/minute burst 100"
    connlimit: str | None = None   # e.g. "s:1:2"
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


@dataclass
class FirewallIR:
    """Complete intermediate representation of the firewall."""
    zones: ZoneModel = field(default_factory=ZoneModel)
    chains: dict[str, Chain] = field(default_factory=dict)
    settings: dict[str, str] = field(default_factory=dict)
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


def _parse_rate_limit(rate_str: str) -> str:
    """Parse Shorewall rate limit format to nft format.

    Shorewall: s:name:rate/unit:burst  or  rate/unit:burst
    nft:       limit rate N/unit burst M
    """
    # s:name:30/min:100 → limit rate 30/minute burst 100
    m = re.match(r'^(?:s:\w+:)?(\d+)/(\w+)(?::(\d+))?$', rate_str)
    if m:
        count = m.group(1)
        unit = m.group(2)
        burst = m.group(3)
        # Normalize unit names
        unit_map = {"sec": "second", "min": "minute", "hour": "hour", "day": "day",
                    "second": "second", "minute": "minute"}
        nft_unit = unit_map.get(unit, unit)
        result = f"{count}/{nft_unit}"
        if burst:
            result += f" burst {burst} packets"
        return result
    return rate_str


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
