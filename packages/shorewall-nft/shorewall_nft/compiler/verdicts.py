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
    """SNAT to a specific address (or address range)."""
    target: str


@dataclass(frozen=True)
class DnatVerdict:
    """DNAT to a specific address (and optional port)."""
    target: str


@dataclass(frozen=True)
class MasqueradeVerdict:
    """Dynamic masquerade (no fixed target)."""


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
    """Log via nfnetlink log (currently hardcoded to group 0).

    TODO: make the group configurable once the shorewall-nft config
    surface exposes nflog_group.
    """


@dataclass(frozen=True)
class AuditVerdict:
    """Kernel audit log, then apply the base action."""
    base_action: Literal["ACCEPT", "DROP", "REJECT"]


# ── Union alias ───────────────────────────────────────────────────────────

SpecialVerdict = Union[
    SnatVerdict, DnatVerdict, MasqueradeVerdict, RedirectVerdict,
    NotrackVerdict, CtHelperVerdict,
    MarkVerdict, ConnmarkVerdict, RestoreMarkVerdict, SaveMarkVerdict,
    DscpVerdict, ClassifyVerdict, EcnClearVerdict,
    CounterVerdict, NamedCounterVerdict, NflogVerdict,
    AuditVerdict,
]
