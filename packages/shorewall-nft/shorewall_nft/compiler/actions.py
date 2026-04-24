"""Shorewall action processing.

Actions are reusable rule chains that implement complex behaviors like
Broadcast filtering, TCP flag checking, smurf detection, etc.

Shorewall action files support embedded Perl and iptables passthrough
syntax (;;). Since we're a clean nft reimplementation, we translate
the well-known actions to their nft equivalents directly.
"""

from __future__ import annotations

from shorewall_nft.compiler.ir import (
    FirewallIR,
    Match,
    RateLimitSpec,
    Rule,
    Verdict,
)
from shorewall_nft.compiler.verdicts import AuditVerdict, SpecialVerdict


def _disposition_to_verdict(
    value: str | None,
) -> tuple[Verdict, SpecialVerdict | None] | None:
    """Map a Shorewall disposition string to (Verdict, optional AuditVerdict).

    Accepted values (case-insensitive): DROP, REJECT, ACCEPT,
    A_DROP, A_REJECT.  The A_* variants prepend an AuditVerdict so
    the emitter logs via the kernel audit subsystem before applying
    the base action.

    Upstream Shorewall also accepts CONTINUE (no action; fall through
    to the next rule) and NONE (skip emit entirely). Both are modelled
    here by returning ``None`` — callers MUST check for that sentinel
    and skip emitting a rule. Silently defaulting these to DROP (the
    pre-2026-04 behaviour) caused ``UNTRACKED_DISPOSITION=CONTINUE``
    to emit an unintended ``ct state untracked drop`` that blackholed
    probes with no conntrack state.

    Returns ``None`` for CONTINUE / NONE / empty / unrecognised input.
    """
    if value is None:
        return None
    canon = value.upper().strip()
    if canon in ("", "CONTINUE", "NONE"):
        return None
    if canon == "DROP":
        return Verdict.DROP, None
    if canon == "REJECT":
        return Verdict.REJECT, None
    if canon == "ACCEPT":
        return Verdict.ACCEPT, None
    if canon == "A_DROP":
        return Verdict.DROP, AuditVerdict(base_action="DROP")
    if canon == "A_REJECT":
        return Verdict.REJECT, AuditVerdict(base_action="REJECT")
    return None


def create_action_chains(ir: FirewallIR) -> None:
    """Create nft chains for standard Shorewall actions."""
    _create_drop_chain(ir)
    _create_reject_chain(ir)
    _create_broadcast_chain(ir)
    _create_multicast_chain(ir)
    _create_drop_smurfs_chain(ir)
    _create_drop_not_syn_chain(ir)
    _create_drop_invalid_chain(ir)
    _create_allow_icmps_chain(ir)
    _create_drop_dnsrep_chain(ir)
    _create_established_chain(ir)
    _create_invalid_chain(ir)
    _create_blacklist_chain(ir)
    _create_tcp_flags_chain(ir)
    _create_fin_chain(ir)
    _create_rst_chain(ir)
    _create_rej_not_syn_chain(ir)
    _create_allow_upnp_chain(ir)
    _create_dns_amp_chain(ir)


def _create_drop_chain(ir: FirewallIR) -> None:
    """action.Drop: Drop with broadcast/multicast pre-filter.

    Broadcasts and multicasts are silently dropped before the
    actual drop+log to avoid log noise.
    """
    chain = ir.get_or_create_chain("sw_Drop")
    # Silently drop broadcasts
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    # Silently drop multicasts
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))
    # Drop non-SYN TCP to avoid RST floods
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
        comment="dropNotSyn",
    ))
    # Drop invalid
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
        comment="dropInvalid",
    ))
    # Final drop
    chain.rules.append(Rule(verdict=Verdict.DROP))


def _create_reject_chain(ir: FirewallIR) -> None:
    """action.Reject: Reject with broadcast/multicast pre-filter."""
    chain = ir.get_or_create_chain("sw_Reject")
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
        comment="dropNotSyn",
    ))
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
        comment="dropInvalid",
    ))
    chain.rules.append(Rule(verdict=Verdict.REJECT))


def _create_broadcast_chain(ir: FirewallIR) -> None:
    """action.Broadcast: Handle broadcast/anycast packets."""
    chain = ir.get_or_create_chain("sw_Broadcast")
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="anycast")],
        verdict=Verdict.DROP,
    ))


def _create_multicast_chain(ir: FirewallIR) -> None:
    """action.Multicast: Handle multicast packets."""
    chain = ir.get_or_create_chain("sw_Multicast")
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))


def _create_drop_smurfs_chain(ir: FirewallIR) -> None:
    """action.DropSmurfs: Drop smurf attacks (broadcast source).

    The verdict is controlled by ``SMURF_DISPOSITION`` (DROP or A_DROP).
    """
    disp = ir.settings.get("SMURF_DISPOSITION", "DROP")
    resolved = _disposition_to_verdict(disp)
    chain = ir.get_or_create_chain("sw_DropSmurfs")
    if resolved is None:
        # CONTINUE / NONE — create the chain but emit no rule.
        return
    verdict, audit = resolved
    if audit is not None:
        chain.rules.append(Rule(
            matches=[Match(field="fib saddr type", value="broadcast")],
            verdict=Verdict.ACCEPT,
            verdict_args=audit,
            comment="smurf:audit",
        ))
    chain.rules.append(Rule(
        matches=[Match(field="fib saddr type", value="broadcast")],
        verdict=verdict,
        comment="smurf",
    ))


def _create_drop_not_syn_chain(ir: FirewallIR) -> None:
    """action.dropNotSyn: Drop new TCP without SYN."""
    chain = ir.get_or_create_chain("sw_dropNotSyn")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
    ))


def _create_drop_invalid_chain(ir: FirewallIR) -> None:
    """action.dropInvalid: Drop invalid state packets."""
    chain = ir.get_or_create_chain("sw_dropInvalid")
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
    ))


def _create_allow_icmps_chain(ir: FirewallIR) -> None:
    """action.AllowICMPs: Allow required ICMP types per RFC."""
    chain = ir.get_or_create_chain("sw_AllowICMPs")
    # Essential ICMP types
    for icmp_type in ["destination-unreachable", "time-exceeded",
                      "parameter-problem", "echo-request", "echo-reply"]:
        chain.rules.append(Rule(
            matches=[
                Match(field="meta l4proto", value="icmp"),
                Match(field="icmp type", value=icmp_type),
            ],
            verdict=Verdict.ACCEPT,
        ))


def _create_drop_dnsrep_chain(ir: FirewallIR) -> None:
    """action.DropDNSrep: Drop unsolicited DNS replies (amplification)."""
    chain = ir.get_or_create_chain("sw_DropDNSrep")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp sport", value="53"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
        comment="DNS amplification",
    ))


def _create_established_chain(ir: FirewallIR) -> None:
    """action.Established: Accept established connections."""
    chain = ir.get_or_create_chain("sw_Established")
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="established")],
        verdict=Verdict.ACCEPT,
    ))


def _create_invalid_chain(ir: FirewallIR) -> None:
    """action.Invalid: Handle invalid packets."""
    chain = ir.get_or_create_chain("sw_Invalid")
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
    ))


def _create_blacklist_chain(ir: FirewallIR) -> None:
    """action.BLACKLIST: Default blacklist action chain.

    The terminal verdict is controlled by ``BLACKLIST_DISPOSITION``
    (DROP / REJECT / A_DROP / A_REJECT).
    """
    disp = ir.settings.get("BLACKLIST_DISPOSITION", "DROP")
    resolved = _disposition_to_verdict(disp)
    chain = ir.get_or_create_chain("sw_BLACKLIST")
    # BLACKLIST_DISPOSITION=CONTINUE / NONE would leave no terminal
    # verdict; treat as explicit DROP (the chain is named BLACKLIST —
    # falling through would defeat its purpose).
    verdict, audit = resolved if resolved is not None else (Verdict.DROP, None)
    # Broadcast/multicast silent drop
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="broadcast")],
        verdict=Verdict.DROP,
    ))
    chain.rules.append(Rule(
        matches=[Match(field="fib daddr type", value="multicast")],
        verdict=Verdict.DROP,
    ))
    # dropNotSyn
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0", negate=False),
        ],
        verdict=Verdict.DROP,
    ))
    # dropInvalid
    chain.rules.append(Rule(
        matches=[Match(field="ct state", value="invalid")],
        verdict=Verdict.DROP,
    ))
    # DropDNSrep
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp sport", value="53"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
    ))
    if audit is not None:
        chain.rules.append(Rule(
            verdict=Verdict.ACCEPT,
            verdict_args=audit,
            comment="blacklist:audit",
        ))
    chain.rules.append(Rule(verdict=verdict))


def _create_tcp_flags_chain(ir: FirewallIR) -> None:
    """action.TCPFlags: Drop bad TCP flag combinations.

    The verdict is controlled by ``TCP_FLAGS_DISPOSITION``
    (DROP / REJECT / A_DROP / A_REJECT / ACCEPT).
    """
    disp = ir.settings.get("TCP_FLAGS_DISPOSITION", "DROP")
    resolved = _disposition_to_verdict(disp)
    chain = ir.get_or_create_chain("sw_TCPFlags")
    if resolved is None:
        return
    verdict, audit = resolved
    for flags in [
        ("fin | syn", "fin | syn"),
        ("syn | rst", "syn | rst"),
        ("fin | rst", "fin | rst"),
        ("fin | urg | psh", "fin | urg | psh"),
    ]:
        if audit is not None:
            chain.rules.append(Rule(
                matches=[
                    Match(field="meta l4proto", value="tcp"),
                    Match(field=f"tcp flags & ({flags[0]})", value=flags[1]),
                ],
                verdict=Verdict.ACCEPT,
                verdict_args=audit,
                comment="tcpflags:audit",
            ))
        chain.rules.append(Rule(
            matches=[
                Match(field="meta l4proto", value="tcp"),
                Match(field=f"tcp flags & ({flags[0]})", value=flags[1]),
            ],
            verdict=verdict,
        ))


def _create_fin_chain(ir: FirewallIR) -> None:
    """action.FIN: Handle TCP FIN packets."""
    chain = ir.get_or_create_chain("sw_FIN")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp flags & fin", value="fin"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
    ))


def _create_rst_chain(ir: FirewallIR) -> None:
    """action.RST: Rate-limit TCP RST packets."""
    chain = ir.get_or_create_chain("sw_RST")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp flags & rst", value="rst"),
        ],
        verdict=Verdict.ACCEPT,
        rate_limit=RateLimitSpec(rate=2, unit="second", burst=5),
    ))
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp flags & rst", value="rst"),
        ],
        verdict=Verdict.DROP,
    ))


def _create_rej_not_syn_chain(ir: FirewallIR) -> None:
    """action.rejNotSyn: Reject new TCP without SYN."""
    chain = ir.get_or_create_chain("sw_rejNotSyn")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="ct state", value="new"),
            Match(field="tcp flags & syn", value="0"),
        ],
        verdict=Verdict.REJECT,
    ))


def _create_allow_upnp_chain(ir: FirewallIR) -> None:
    """action.allowinUPnP: Allow UPnP/SSDP discovery."""
    chain = ir.get_or_create_chain("sw_allowinUPnP")
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp dport", value="1900"),
        ],
        verdict=Verdict.ACCEPT,
        comment="SSDP",
    ))
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="tcp"),
            Match(field="tcp dport", value="5000"),
        ],
        verdict=Verdict.ACCEPT,
        comment="UPnP",
    ))


def _create_dns_amp_chain(ir: FirewallIR) -> None:
    """action.DNSAmp: Drop DNS amplification attempts."""
    chain = ir.get_or_create_chain("sw_DNSAmp")
    # Drop large DNS responses from unknown sources
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp sport", value="53"),
            Match(field="ct state", value="new"),
        ],
        verdict=Verdict.DROP,
        comment="DNS amplification",
    ))
    # Drop ANY queries (common in amplification)
    chain.rules.append(Rule(
        matches=[
            Match(field="meta l4proto", value="udp"),
            Match(field="udp dport", value="53"),
        ],
        verdict=Verdict.DROP,
        comment="DNS amplification",
    ))


# Map action names to their chain names
ACTION_CHAIN_MAP: dict[str, str] = {
    "Drop": "sw_Drop",
    "Reject": "sw_Reject",
    "Broadcast": "sw_Broadcast",
    "Multicast": "sw_Multicast",
    "DropSmurfs": "sw_DropSmurfs",
    "dropNotSyn": "sw_dropNotSyn",
    "dropInvalid": "sw_dropInvalid",
    "AllowICMPs": "sw_AllowICMPs",
    "DropDNSrep": "sw_DropDNSrep",
    "Established": "sw_Established",
    "Invalid": "sw_Invalid",
    "BLACKLIST": "sw_BLACKLIST",
    "A_DROP": "sw_Drop",
    "A_REJECT": "sw_Reject",
    "dropBcast": "sw_Broadcast",
    "dropBcasts": "sw_Broadcast",
    "dropMcast": "sw_Multicast",
    "allowBcast": "sw_Broadcast",  # same chain, but called with ACCEPT
    "allowMcast": "sw_Multicast",
    "allowInvalid": "sw_dropInvalid",
    "allowinUPnP": "sw_AllowICMPs",  # approximation
    "New": "sw_Established",  # no-op, new is default
    "Related": "sw_Established",
    "NotSyn": "sw_dropNotSyn",
    "TCPFlags": "sw_TCPFlags",
    "FIN": "sw_FIN",
    "RST": "sw_RST",
    "rejNotSyn": "sw_rejNotSyn",
    "DNSAmp": "sw_DNSAmp",
    "allowinUPnP": "sw_allowinUPnP",
    "A_ACCEPT": "sw_Established",  # audit accept
}


def create_dynamic_blacklist(ir: FirewallIR, settings: dict[str, str]) -> None:
    """Create dynamic blacklist set and chain.

    ``DYNAMIC_BLACKLIST`` values (Shorewall 5.2.6.1 semantics):

    * ``No``                 — no dynamic blacklist emitted at all.
    * ``Yes`` / ``ipset-only`` — ipset-based drop chain (standard).
    * ``ipset,disconnect``   — standard chain + a ``ct state established
                               ct mark != @dynamic_blacklist disconnect``
                               rule at the top of the forward chain so that
                               newly-blacklisted sources have existing flows
                               torn down immediately.
    * ``ipset,disconnect-src`` — same as ``ipset,disconnect`` (src-only
                               semantics; the nft disconnect statement
                               matches established in both directions
                               so the behaviour is equivalent).

    The dynamic set itself (``@dynamic_blacklist``) is declared in the
    emitter via the sets mechanism.  Rules add elements at runtime:
      nft add element inet shorewall dynamic_blacklist { 1.2.3.4 timeout 1h }
    """
    dbl = settings.get("DYNAMIC_BLACKLIST", "")
    if not dbl or dbl.strip().lower() in ("no", "0", ""):
        return

    mode = dbl.strip().lower()

    chain = ir.get_or_create_chain("sw_dynamic-blacklist")
    chain.rules.append(Rule(
        matches=[Match(field="ip saddr", value="@dynamic_blacklist")],
        verdict=Verdict.DROP,
        comment="dynamic blacklist",
    ))

    if not hasattr(ir, "_dynamic_blacklist"):
        ir._dynamic_blacklist = True  # type: ignore[attr-defined]

    if mode in ("ipset,disconnect", "ipset,disconnect-src"):
        forward = ir.chains.get("forward")
        if forward is not None:
            disconnect_rule = Rule(
                matches=[
                    Match(field="ip saddr", value="@dynamic_blacklist"),
                    Match(field="ct state", value="established"),
                ],
                verdict=Verdict.DROP,
                comment="dynamic blacklist:disconnect",
            )
            forward.rules.insert(0, disconnect_rule)
