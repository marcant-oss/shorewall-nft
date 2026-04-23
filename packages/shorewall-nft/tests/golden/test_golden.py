"""Parametrized runner for golden-snapshot cases.

See ``conftest.py`` for how the framework works, how to add a case, and
how to regenerate goldens after intentional emitter changes.
"""

from __future__ import annotations

import pytest

from .conftest import assert_golden, discover_cases

_CASES = discover_cases()


@pytest.mark.parametrize("case_name", _CASES, ids=_CASES)
def test_golden(case_name: str) -> None:
    assert_golden(case_name)


def test_at_least_one_case_registered() -> None:
    """Safety net: if the discovery glob silently returns empty, fail loudly."""
    assert _CASES, (
        "no golden cases discovered under tests/golden/cases/ — "
        "either the framework broke or no fixture directories exist."
    )
