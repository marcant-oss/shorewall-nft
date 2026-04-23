"""Golden-snapshot test harness for the nft emitter.

Replaces dozens of fragile ``"some literal" in emit_output`` assertions
with whole-output diff tests. Each case lives at::

    tests/golden/cases/<case_name>/
        config/            # a valid shorewall-nft config directory
        expected.nft       # the emitter output that `config/` must produce

Running pytest discovers every directory under ``cases/`` that contains
both a ``config/`` subdirectory and an ``expected.nft`` file, and checks
that the emit is byte-identical.

Regenerating goldens
--------------------
After intentional emitter changes, regenerate every case in one go::

    UPDATE_GOLDEN=1 .venv/bin/pytest tests/golden/ -q

The test function becomes a no-op verdict-wise; it just rewrites the
``expected.nft`` files. Review the resulting diff with ``git diff`` before
committing.

Adding a new case
-----------------
1. Create ``tests/golden/cases/<new_name>/config/`` with at least
   ``zones``, ``interfaces``, ``policy`` files (``rules`` optional).
2. Run ``UPDATE_GOLDEN=1 pytest tests/golden/ -q -k <new_name>`` to
   generate ``expected.nft``.
3. Eyeball the generated file. If it matches your expectation, commit.
4. Future runs without ``UPDATE_GOLDEN`` will fail loudly on any drift.

Timestamp stability
-------------------
``emit_nft()`` embeds the current UTC datetime into the header comment.
That string is stripped before comparison so goldens stay stable across
runs.
"""

from __future__ import annotations

import difflib
import os
import re
from pathlib import Path

import pytest

from shorewall_nft.compiler.ir import build_ir
from shorewall_nft.config.parser import load_config
from shorewall_nft.nft.emitter import emit_nft

GOLDEN_ROOT = Path(__file__).parent / "cases"

_TIMESTAMP_RE = re.compile(
    r"^# Generated at: .*$",
    re.MULTILINE,
)


def _strip_volatile(output: str) -> str:
    """Remove non-deterministic fields (timestamp, config hash) so goldens are stable."""
    output = _TIMESTAMP_RE.sub("# Generated at: <TIMESTAMP>", output)
    return output


def compile_case(case_dir: Path) -> str:
    """Run ``config/ → IR → emit`` for a golden case directory.

    Supports dual-stack configs: if ``<case>/config46/`` exists it is
    passed as the second (ipv6) config dir. Otherwise the single
    ``<case>/config/`` is used for both families via the normal
    ``load_config`` auto-detection.
    """
    config_dir = case_dir / "config"
    config6_dir = case_dir / "config46"
    cfg = load_config(
        config_dir,
        config6_dir if config6_dir.is_dir() else None,
    )
    ir = build_ir(cfg)
    return _strip_volatile(emit_nft(ir))


def assert_golden(case_name: str) -> None:
    """Compile ``cases/<case_name>`` and compare against its ``expected.nft``.

    Honours the ``UPDATE_GOLDEN=1`` env var: when set, regenerates the
    golden instead of asserting.
    """
    case_dir = GOLDEN_ROOT / case_name
    if not (case_dir / "config").is_dir():
        pytest.fail(
            f"golden case {case_name!r}: missing {case_dir / 'config'!s}"
        )

    output = compile_case(case_dir)
    expected_path = case_dir / "expected.nft"

    if os.environ.get("UPDATE_GOLDEN") == "1":
        expected_path.write_text(output)
        return

    if not expected_path.exists():
        pytest.fail(
            f"golden case {case_name!r}: expected.nft missing. "
            f"Run `UPDATE_GOLDEN=1 pytest tests/golden/ -k {case_name}` "
            f"to generate it."
        )

    expected = expected_path.read_text()
    if expected == output:
        return

    diff = "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            output.splitlines(keepends=True),
            fromfile=f"cases/{case_name}/expected.nft",
            tofile=f"<current emit of cases/{case_name}/config/>",
            n=3,
        )
    )
    pytest.fail(
        f"golden mismatch for {case_name!r}:\n{diff}\n"
        f"If the emitter change is intentional, regenerate with "
        f"`UPDATE_GOLDEN=1 pytest tests/golden/ -k {case_name}`."
    )


def discover_cases() -> list[str]:
    """Return sorted list of case names: every dir in cases/ with a config/ child."""
    if not GOLDEN_ROOT.is_dir():
        return []
    return sorted(
        p.name for p in GOLDEN_ROOT.iterdir()
        if p.is_dir() and (p / "config").is_dir()
    )
