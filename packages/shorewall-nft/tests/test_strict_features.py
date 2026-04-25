"""Tests for the ``--strict-features`` strict-mode capability check.

The mechanism is opt-in (off by default) so existing configs keep
compiling. When enabled, every emit path that depends on a probed
nft capability registers its requirement on the IR; the strict-
features post-pass then validates the requirements against the
probed
:class:`~shorewall_nft.nft.capabilities.NftCapabilities` and raises
:class:`~shorewall_nft.nft.strict.UnsupportedFeatureError` listing
every miss in one report.

These tests use synthesised IR + caps objects — no live netns probe
involved, so they run in any CI environment.
"""

from __future__ import annotations

import pytest

from shorewall_nft.compiler.ir import FirewallIR
from shorewall_nft.nft.capabilities import NftCapabilities
from shorewall_nft.nft.strict import (
    FeatureRequirement,
    UnsupportedFeatureError,
    check_strict_features,
)


def test_no_requirements_passes() -> None:
    """An IR with no registered requirements is always valid."""
    ir = FirewallIR()
    caps = NftCapabilities()  # all has_* fields default to False
    check_strict_features(ir, caps)  # no exception


def test_satisfied_requirement_passes() -> None:
    """A registered requirement whose capability is True passes."""
    ir = FirewallIR()
    ir.require_capability(
        "has_synproxy_stmt", "SYNPROXY action",
        source="rules:42")
    caps = NftCapabilities()
    caps.has_synproxy_stmt = True
    check_strict_features(ir, caps)


def test_unsatisfied_requirement_raises() -> None:
    ir = FirewallIR()
    ir.require_capability(
        "has_synproxy_stmt", "SYNPROXY action",
        source="rules:42")
    caps = NftCapabilities()  # has_synproxy_stmt defaults False
    with pytest.raises(UnsupportedFeatureError) as exc_info:
        check_strict_features(ir, caps)
    err = exc_info.value
    assert len(err.requirements) == 1
    assert err.requirements[0].capability == "has_synproxy_stmt"
    msg = str(err)
    assert "SYNPROXY action" in msg
    assert "has_synproxy_stmt" in msg
    assert "rules:42" in msg


def test_multiple_misses_collected_in_one_report() -> None:
    """All unmet requirements report in a single error, not first-fail."""
    ir = FirewallIR()
    ir.require_capability("has_tproxy_stmt", "TPROXY action")
    ir.require_capability("has_synproxy_stmt", "SYNPROXY action",
                          source="rules:7")
    ir.require_capability("has_dup", "DUP action")
    caps = NftCapabilities()
    with pytest.raises(UnsupportedFeatureError) as exc_info:
        check_strict_features(ir, caps)
    captured = {r.capability for r in exc_info.value.requirements}
    assert captured == {"has_tproxy_stmt", "has_synproxy_stmt", "has_dup"}


def test_partial_satisfaction_only_misses_in_report() -> None:
    """Capabilities that ARE satisfied don't appear in the error report."""
    ir = FirewallIR()
    ir.require_capability("has_synproxy_stmt", "SYNPROXY action")
    ir.require_capability("has_tproxy_stmt", "TPROXY action")
    caps = NftCapabilities()
    caps.has_synproxy_stmt = True
    # has_tproxy_stmt stays False
    with pytest.raises(UnsupportedFeatureError) as exc_info:
        check_strict_features(ir, caps)
    captured = [r.capability for r in exc_info.value.requirements]
    assert captured == ["has_tproxy_stmt"]


def test_unknown_capability_treated_as_missing() -> None:
    """A typoed capability name (not on NftCapabilities) errors as missing.

    Defensive: rather than crash with AttributeError, the strict-
    features check uses ``getattr(caps, name, False)`` so unknown
    names default to ``False`` and surface in the report. The user
    sees a clear "has_typo not supported" entry and can grep the
    codebase for the typo.
    """
    ir = FirewallIR()
    ir.require_capability("has_definitely_not_a_real_cap", "imaginary feature")
    caps = NftCapabilities()
    with pytest.raises(UnsupportedFeatureError) as exc_info:
        check_strict_features(ir, caps)
    assert exc_info.value.requirements[0].capability == \
        "has_definitely_not_a_real_cap"


def test_requirement_dataclass_is_frozen() -> None:
    """``FeatureRequirement`` is frozen — once registered, can't be mutated."""
    req = FeatureRequirement(capability="has_x", description="X")
    with pytest.raises((AttributeError, Exception)):
        req.capability = "has_y"  # type: ignore[misc]
