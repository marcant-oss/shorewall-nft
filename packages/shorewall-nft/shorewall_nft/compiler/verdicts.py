"""Typed discriminated union for Rule.verdict_args special verdicts.

Each dataclass represents a distinct Shorewall action that emits a
non-standard nft statement. Chain-name strings for Verdict.JUMP /
Verdict.GOTO stay as plain ``str`` on ``Rule.verdict_args`` — they
are not "special" verdicts and are not represented here.

The full ``verdict_args`` type is therefore ``SpecialVerdict | str | None``
where ``str`` covers the JUMP/GOTO chain-name case.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Union

# ── NAT family ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SnatVerdict:
    """SNAT to a specific address (or address range).

    ``targets``: list of addresses for round-robin SNAT (multi-target).
    ``port_range``: ``"p1-p2"`` or ``"p"`` appended after ``addr:`` in emit.
    ``flags``: subset of ``{"random", "persistent", "fully-random"}`` —
        space-joined and appended after the address in the nft statement.
    """
    target: str
    targets: tuple[str, ...] = ()   # non-empty → round-robin map
    port_range: str | None = None
    flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class DnatVerdict:
    """DNAT to a specific address (and optional port)."""
    target: str


@dataclass(frozen=True)
class MasqueradeVerdict:
    """Dynamic masquerade (no fixed target).

    ``port_range``: optional port range ``"p1-p2"`` emitted as
        ``masquerade to :p1-p2``.
    ``flags``: subset of ``{"random", "persistent", "fully-random"}``.
    """
    port_range: str | None = None
    flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class NonatVerdict:
    """Skip NAT for this match (NONAT / ACCEPT / CONTINUE).

    Emitted as ``return`` so the packet continues through the NAT table
    without being translated.
    """


@dataclass(frozen=True)
class RedirectVerdict:
    """Redirect inbound traffic to a local port on the firewall.

    Shorewall ``REDIRECT`` action. Emitted as ``redirect to :<port>`` —
    distinct from ``DnatVerdict`` which targets a remote address.
    """
    port: int


# ── Conntrack family ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class NotrackVerdict:
    """Bypass connection tracking (nft: notrack)."""


@dataclass(frozen=True)
class CtHelperVerdict:
    """Assign a conntrack helper object by name."""
    name: str


# ── Mark / TC family ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class MarkVerdict:
    """Set the packet mark (meta mark set).

    If ``mask`` is set, emits ``mark and ~mask | value`` semantics.
    """
    value: int
    mask: int | None = None


@dataclass(frozen=True)
class ConnmarkVerdict:
    """Set the conntrack mark (ct mark set)."""
    value: int


@dataclass(frozen=True)
class RestoreMarkVerdict:
    """Copy ct mark to meta mark."""


@dataclass(frozen=True)
class SaveMarkVerdict:
    """Copy meta mark to ct mark."""


@dataclass(frozen=True)
class DscpVerdict:
    """Set the DSCP field. Value is an nft token (keyword or hex)."""
    value: str


@dataclass(frozen=True)
class ClassifyVerdict:
    """Set tc priority (meta priority set). Value is a tc handle like '1:10'."""
    value: str


@dataclass(frozen=True)
class EcnClearVerdict:
    """Clear the ECN bits (ip ecn set not-ect)."""


# ── Accounting / logging family ───────────────────────────────────────────

@dataclass(frozen=True)
class CounterVerdict:
    """Anonymous counter + accept.

    Covers both the ``COUNT`` action (``params=None``) and the
    ``ACCOUNT(params)`` action. ACCOUNT's ``params`` string is
    retained here for future use but is ignored at emit time —
    current behaviour maps both to the same ``counter accept``.
    """
    params: str | None = None


@dataclass(frozen=True)
class NamedCounterVerdict:
    """Named nfnetlink counter object, then accept."""
    name: str


@dataclass(frozen=True)
class NflogVerdict:
    """Log via nfnetlink log (nft ``log group N``).

    ``group`` is the nfnetlink_log group number (0–65535).  The default
    of 0 matches the previous hard-coded behaviour; the emitter will
    override it with the ``LOG_GROUP`` setting when LOG_BACKEND is
    netlink/NFLOG/ULOG.
    """
    group: int = 0


@dataclass(frozen=True)
class AuditVerdict:
    """Kernel audit log, then apply the base action."""
    base_action: Literal["ACCEPT", "DROP", "REJECT"]


# ── nft-native protection / accounting ─────────────────────────────────────

@dataclass(frozen=True)
class SynproxyVerdict:
    """Inline SYNPROXY — TCP SYN-cookie engine in the kernel.

    Surfaces ``SYNPROXY(mss=N,wscale=N,timestamp,sack-perm)`` in the
    ACTION column of rules. Emitted as
    ``synproxy mss N wscale N [timestamp] [sack-perm]`` (nft 1.1.x
    statement form).

    Fields are kept as bare types instead of an option dict so the
    dispatch table can render the statement deterministically. The
    nft kernel rejects the statement outside ``input`` / ``forward``
    hooks; the emitter honours that by only attaching the verdict to
    those chains.

    ``has_synproxy_stmt`` is the gating capability; the named-object
    form (``has_synproxy_obj``) is a separate concern not yet exposed
    via the action surface.
    """
    mss: int = 1460
    wscale: int = 7
    timestamp: bool = True
    sack_perm: bool = True


@dataclass(frozen=True)
class QuotaVerdict:
    """Bandwidth-quota cap on a flow.

    Surfaces ``QUOTA(BYTES[,UNIT])`` in the ACTION column. ``unit`` is
    one of nft's accepted quota units (``bytes``, ``kbytes``,
    ``mbytes``, ``gbytes``); default ``bytes``. Emitted as
    ``quota over <bytes> <unit> drop`` (nft 1.1.x).

    Gated by ``has_quota``. Named quota objects (``has_quota_obj``)
    are tracked as a separate follow-up — they need a config-file
    surface for declaration.
    """
    bytes_count: int
    unit: Literal["bytes", "kbytes", "mbytes", "gbytes"] = "bytes"


@dataclass(frozen=True)
class TproxyVerdict:
    """Transparent-proxy divert (mangle file only).

    Surfaces ``TPROXY(PORT[,ADDR])`` in the ACTION column of the
    mangle file. Emitted as one of:

    * ``tproxy to :PORT``                 — port only (inherits chain family)
    * ``tproxy ip to ADDR:PORT``          — IPv4 address present
    * ``tproxy ip6 to [ADDR]:PORT``       — IPv6 address present

    Gated by ``has_tproxy_stmt``. The companion ``socket transparent``
    pre-filter match is tracked separately and not exposed via this
    verdict.

    The kernel routes the diverted packet to a local listener; the
    caller is responsible for the routing-table glue
    (``ip rule add fwmark … lookup …``) — composing TPROXY with a
    MARK rule on the same flow is the typical pattern.
    """
    port: int
    addr: str | None = None


@dataclass(frozen=True)
class DupVerdict:
    """Tap-copy a packet to another destination (mangle file).

    Surfaces ``DUP(ADDR)`` and ``DUP(ADDR,DEV)`` in the ACTION column
    of the mangle file. Emitted as one of:

    * ``dup to ADDR``                     — copy out via routing
    * ``dup to ADDR device "DEV"``        — copy out via DEV

    Gated by ``has_dup``. The kernel duplicates the packet without
    consuming a verdict — the original packet continues through the
    chain after the dup statement, so this is not a terminal action.

    Useful for tap / sniffer pipelines and for redirecting a copy to
    a remote analyser without disturbing the production flow. The
    ``fwd`` (zero-copy forward) counterpart is netdev-ingress only
    and is tracked separately.
    """
    target: str
    device: str | None = None


# ── Union alias ───────────────────────────────────────────────────────────

SpecialVerdict = Union[
    SnatVerdict, DnatVerdict, MasqueradeVerdict, NonatVerdict, RedirectVerdict,
    NotrackVerdict, CtHelperVerdict,
    MarkVerdict, ConnmarkVerdict, RestoreMarkVerdict, SaveMarkVerdict,
    DscpVerdict, ClassifyVerdict, EcnClearVerdict,
    CounterVerdict, NamedCounterVerdict, NflogVerdict,
    AuditVerdict,
    SynproxyVerdict, QuotaVerdict, TproxyVerdict, DupVerdict,
]
