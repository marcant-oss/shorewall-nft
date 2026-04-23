"""Capability checking — validates that the compiled ruleset
can actually run on the target kernel.

Scans the IR for features that require specific nft capabilities
and reports errors with context (which rule, which config file,
which feature is missing).
"""

from __future__ import annotations

from dataclasses import dataclass

from shorewall_nft.compiler.ir import FirewallIR, Rule
from shorewall_nft.compiler.verdicts import (
    CtHelperVerdict,
    DnatVerdict,
    MasqueradeVerdict,
    NotrackVerdict,
    SnatVerdict,
)
from shorewall_nft.nft.capabilities import NftCapabilities


@dataclass
class CapabilityError:
    """A missing capability for a specific rule."""
    feature: str
    description: str
    rule_file: str
    rule_line: int
    rule_context: str
    suggestion: str


def check_capabilities(ir: FirewallIR, caps: NftCapabilities) -> list[CapabilityError]:
    """Check all rules against detected capabilities.

    Returns list of errors — empty means all features available.
    """
    errors: list[CapabilityError] = []

    for chain_name, chain in ir.chains.items():
        for rule in chain.rules:
            errors.extend(_check_rule(rule, caps, chain_name))

    # Check set features
    if not caps.has_interval_sets:
        # Any set with interval flag will fail
        errors.append(CapabilityError(
            feature="interval_sets",
            description="Kernel does not support interval sets (flags interval)",
            rule_file="",
            rule_line=0,
            rule_context="Set declarations with 'flags interval'",
            suggestion="Update kernel to >= 4.6 or load nft_set_rbtree module",
        ))

    if not caps.has_timeout_sets:
        # Dynamic blacklist needs timeout sets
        if hasattr(ir, '_dynamic_blacklist') and ir._dynamic_blacklist:
            errors.append(CapabilityError(
                feature="timeout_sets",
                description="DYNAMIC_BLACKLIST=Yes requires timeout sets",
                rule_file="shorewall.conf",
                rule_line=0,
                rule_context="DYNAMIC_BLACKLIST=Yes",
                suggestion="Set DYNAMIC_BLACKLIST=No or update kernel to >= 4.6",
            ))

    # Check ct helper objects
    if not caps.has_ct_helper_obj:
        for chain_name, chain in ir.chains.items():
            for rule in chain.rules:
                if isinstance(rule.verdict_args, CtHelperVerdict):
                    errors.append(CapabilityError(
                        feature="ct_helper_obj",
                        description="CT helper objects not supported",
                        rule_file=rule.source_file,
                        rule_line=rule.source_line,
                        rule_context=f"ct helper set in chain {chain_name}",
                        suggestion="Load nft_ct module: modprobe nft_ct",
                    ))
                    break
            else:
                continue
            break

    return errors


def _check_rule(rule: Rule, caps: NftCapabilities, chain_name: str) -> list[CapabilityError]:
    """Check a single rule for unsupported features."""
    errors: list[CapabilityError] = []
    ctx = f"chain {chain_name}, {rule.source_file}:{rule.source_line}"

    for match in rule.matches:
        # ct state
        if match.field == "ct state" and not caps.has_ct_state:
            errors.append(CapabilityError(
                feature="ct_state",
                description="Connection tracking state matching not available",
                rule_file=rule.source_file,
                rule_line=rule.source_line,
                rule_context=f"ct state {match.value} in {ctx}",
                suggestion="Load nft_ct module: modprobe nft_ct",
            ))

        # ct count (connlimit)
        if match.field == "ct count" and not caps.has_ct_count:
            errors.append(CapabilityError(
                feature="ct_count",
                description="Connection count limiting not available",
                rule_file=rule.source_file,
                rule_line=rule.source_line,
                rule_context=f"ct count in {ctx}",
                suggestion="Load nft_connlimit module: modprobe nft_connlimit",
            ))

        # fib (routing lookups)
        if match.field.startswith("fib ") and not caps.has_fib:
            errors.append(CapabilityError(
                feature="fib",
                description="FIB (routing table) lookups not available",
                rule_file=rule.source_file,
                rule_line=rule.source_line,
                rule_context=f"{match.field} {match.value} in {ctx}",
                suggestion="Load nft_fib and nft_fib_inet modules",
            ))

        # socket (tproxy)
        if match.field == "socket transparent" and not caps.has_socket:
            errors.append(CapabilityError(
                feature="socket",
                description="Socket expression not available (needed for tproxy)",
                rule_file=rule.source_file,
                rule_line=rule.source_line,
                rule_context=f"socket transparent in {ctx}",
                suggestion="Kernel >= 4.18 required for socket expression",
            ))

        # osf (OS fingerprinting)
        if match.field == "osf" and not caps.has_osf:
            errors.append(CapabilityError(
                feature="osf",
                description="OS fingerprinting not available",
                rule_file=rule.source_file,
                rule_line=rule.source_line,
                rule_context=f"osf in {ctx}",
                suggestion="Load nft_osf module: modprobe nft_osf",
            ))

        # meta nfproto
        if match.field == "meta nfproto" and not caps.has_meta_nfproto:
            errors.append(CapabilityError(
                feature="meta_nfproto",
                description="meta nfproto not available (needed for dual-stack)",
                rule_file=rule.source_file,
                rule_line=rule.source_line,
                rule_context=f"meta nfproto {match.value} in {ctx}",
                suggestion="Kernel >= 3.14 required",
            ))

        # exthdr (IPv6 extension headers)
        if match.field == "exthdr":
            # No specific cap check — always available in inet family
            pass

    # Rate limit
    if rule.rate_limit and not caps.has_limit:
        errors.append(CapabilityError(
            feature="limit",
            description="Rate limiting not available",
            rule_file=rule.source_file,
            rule_line=rule.source_line,
            rule_context=f"limit rate {rule.rate_limit} in {ctx}",
            suggestion="Load nft_limit module: modprobe nft_limit",
        ))

    # Log — check the typed log_level field.
    if rule.log_level is not None and not caps.has_log:
        errors.append(CapabilityError(
            feature="log",
            description="Logging not available",
            rule_file=rule.source_file,
            rule_line=rule.source_line,
            rule_context=f"log in {ctx}",
            suggestion="Load nft_log module: modprobe nft_log",
        ))

    # NAT — check typed NAT verdict variants.
    _nat_verdict_type: str | None = None
    if isinstance(rule.verdict_args, SnatVerdict):
        _nat_verdict_type = "snat"
    elif isinstance(rule.verdict_args, DnatVerdict):
        _nat_verdict_type = "dnat"
    elif isinstance(rule.verdict_args, MasqueradeVerdict):
        _nat_verdict_type = "masquerade"
    if _nat_verdict_type is not None and not caps.has_nat:
        errors.append(CapabilityError(
            feature="nat",
            description="NAT not available",
            rule_file=rule.source_file,
            rule_line=rule.source_line,
            rule_context=f"{_nat_verdict_type} in {ctx}",
            suggestion="Load nft_nat and nft_masq modules",
        ))

    # Notrack — typed NotrackVerdict.
    if isinstance(rule.verdict_args, NotrackVerdict) and not caps.has_notrack:
        errors.append(CapabilityError(
            feature="notrack",
            description="Notrack (raw table) not available",
            rule_file=rule.source_file,
            rule_line=rule.source_line,
            rule_context=f"notrack in {ctx}",
            suggestion="Load nft_ct module: modprobe nft_ct",
        ))

    return errors


def format_errors(errors: list[CapabilityError]) -> str:
    """Format capability errors for display."""
    if not errors:
        return "All required capabilities available."

    # Deduplicate by feature
    seen: set[str] = set()
    unique: list[CapabilityError] = []
    for e in errors:
        if e.feature not in seen:
            seen.add(e.feature)
            unique.append(e)

    lines = [f"ERROR: {len(unique)} missing nft capabilities:\n"]
    for e in unique:
        lines.append(f"  [{e.feature}] {e.description}")
        if e.rule_file:
            lines.append(f"    Source: {e.rule_file}:{e.rule_line}")
        lines.append(f"    Context: {e.rule_context}")
        lines.append(f"    Fix: {e.suggestion}")
        lines.append("")

    return "\n".join(lines)
