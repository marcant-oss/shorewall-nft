"""Static coverage tests for ``NftCapabilities``.

These tests do NOT exercise the live probe — they parse the source of
``probe()`` and assert that every ``has_*`` field declared on the
dataclass is actually probed somewhere in the function body. This
catches the failure mode that motivated this file: declaring a
capability flag (``has_dup``, ``has_synproxy_obj``, etc.) and forgetting
to probe it, leaving the emitter to gate dormant code on a flag that
is always ``False``.

Run with: ``pytest packages/shorewall-nft/tests/test_capabilities.py``
"""

from __future__ import annotations

import inspect
import re

import pytest

from shorewall_nft.nft.capabilities import NftCapabilities


def _has_fields() -> list[str]:
    """Public ``has_*`` fields declared on the dataclass."""
    return [
        f.name for f in NftCapabilities.__dataclass_fields__.values()
        if f.name.startswith("has_")
    ]


def _probe_source() -> str:
    """The full source of :py:meth:`NftCapabilities.probe`."""
    return inspect.getsource(NftCapabilities.probe)


@pytest.mark.parametrize("field_name", _has_fields())
def test_has_field_is_probed(field_name: str) -> None:
    """Every ``has_*`` field must be assigned somewhere in ``probe()``.

    The probe routine is the single source of truth for capability
    detection. A field declared on the dataclass but never assigned
    in ``probe()`` is a silent bug — the field stays at its default
    ``False``, the emitter sees a permanently-disabled capability,
    and any feature gated on it is dead code from the user's
    perspective.

    Detection: source-level regex ``\\bcaps\\.<field>\\s*=``. Cheap
    and exact — matches the assignment, not just any mention.
    """
    src = _probe_source()
    pattern = rf"\bcaps\.{re.escape(field_name)}\s*="
    assert re.search(pattern, src), (
        f"NftCapabilities.{field_name} declared on the dataclass but "
        f"never assigned inside probe(). Either add a probe or remove "
        f"the field. Search pattern: {pattern!r}"
    )


def test_no_orphan_caps_assignment() -> None:
    """Reverse direction: every ``caps.has_*`` assignment in probe()
    must reference a field that exists on the dataclass. Catches typos
    that would silently create a dynamic attribute on the dataclass
    instance.
    """
    src = _probe_source()
    fields = set(_has_fields())
    assigned = set(re.findall(r"\bcaps\.(has_[a-z_]+)\s*=", src))
    orphans = assigned - fields
    assert not orphans, (
        f"probe() assigns to undeclared caps fields: {sorted(orphans)}. "
        f"Add them to the NftCapabilities dataclass."
    )
