"""Strict-features mode — fail compile when the kernel can't express
a feature the IR demands.

Without strict mode (the default), the compiler emits whatever it
chooses and lets ``nft -f`` reject syntax the kernel doesn't
understand. Diagnostics from ``nft -f`` are line-level and rarely
mention the originating Shorewall rule. Strict mode reverses this:
each emit path declares the capability it depends on via
``ir.require_capability(...)``; before the script is rendered, the
strict-features check walks the requirements and errors out for any
that aren't satisfied by the running kernel's probed capabilities.

Public API:

* :class:`FeatureRequirement` — one row in the requirements list.
* :class:`UnsupportedFeatureError` — raised when strict mode finds
  any unmet requirement; ``.requirements`` lists every miss in one
  shot so the user fixes them all at once instead of compile-edit-
  compile.
* :func:`check_strict_features` — call after ``build_ir()`` and
  before ``emit_nft()`` (or the strict mode flag flips it on).

The mechanism is opt-in (``shorewall-nft compile --strict-features``)
to preserve back-compat. CI / packaging scripts that want fail-fast
flip the flag explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shorewall_nft.compiler.ir import FirewallIR
    from shorewall_nft.nft.capabilities import NftCapabilities


@dataclass(slots=True, frozen=True)
class FeatureRequirement:
    """Single capability requirement registered by an emit path.

    ``capability`` is an attribute name on
    :class:`~shorewall_nft.nft.capabilities.NftCapabilities`
    (e.g. ``"has_synproxy_stmt"``); ``description`` is a short
    human-readable phrase (``"SYNPROXY action"``); ``source`` —
    optional ``file:line`` pointer to the rule that triggered the
    requirement, propagated from ``Rule.source_file`` /
    ``source_line`` where available.
    """
    capability: str
    description: str
    source: str | None = None


class UnsupportedFeatureError(Exception):
    """Raised in strict mode when the IR demands capabilities the
    probed kernel doesn't have.

    All unmet requirements are collected into ``.requirements`` so a
    single compile run reports every gap, not just the first.
    """

    def __init__(self, requirements: list[FeatureRequirement]) -> None:
        self.requirements = requirements
        lines = ["The compiled ruleset requires nft features the running "
                 "kernel / libnftnl doesn't expose:"]
        for r in requirements:
            loc = f" (from {r.source})" if r.source else ""
            lines.append(f"  * {r.description} — needs {r.capability}{loc}")
        lines.append(
            "Run ``shorewall-nft capabilities`` to see what the kernel "
            "supports, or drop --strict-features to compile anyway "
            "(nft -f will reject the unsupported syntax at load time).")
        super().__init__("\n".join(lines))


def check_strict_features(ir: "FirewallIR",
                          caps: "NftCapabilities") -> None:
    """Validate every IR feature requirement against probed caps.

    Raises :class:`UnsupportedFeatureError` listing every miss when at
    least one requirement isn't satisfied. Returns silently when all
    pass (or when the IR has no requirements registered — the typical
    case for configs that only use widely-supported features).
    """
    missing: list[FeatureRequirement] = []
    for req in getattr(ir, "required_features", ()) or ():
        if not getattr(caps, req.capability, False):
            missing.append(req)
    if missing:
        raise UnsupportedFeatureError(missing)
