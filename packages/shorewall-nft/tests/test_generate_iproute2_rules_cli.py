"""CLI test for generate-iproute2-rules command (WP-B1/B2/B3).

Uses click.testing.CliRunner to invoke the command without a subprocess
or network namespace — no root required.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from shorewall_nft.runtime.cli import cli

# Fixture with providers / routes / rtrules files
_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "ref-ha-minimal" / "shorewall"


@pytest.fixture
def runner():
    return CliRunner()


class TestGenerateIproute2RulesCli:
    def test_exit_code_zero(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", str(_FIXTURE_DIR)])
        assert result.exit_code == 0, f"CLI failed:\n{result.output}"

    def test_output_is_shell_script(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", str(_FIXTURE_DIR)])
        assert "#!/bin/sh" in result.output

    def test_output_contains_ip_rule(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", str(_FIXTURE_DIR)])
        assert "ip rule add fwmark" in result.output

    def test_output_contains_ip_route(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", str(_FIXTURE_DIR)])
        assert "ip route replace default" in result.output

    def test_rt_tables_registration(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", str(_FIXTURE_DIR)])
        # Fixture defines providers isp1 (number=1) and isp2 (number=2)
        assert "1 isp1" in result.output
        assert "2 isp2" in result.output

    def test_extra_routes_from_routes_file(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", str(_FIXTURE_DIR)])
        # Fixture routes file has 192.0.2.0/24 → isp1
        assert "192.0.2.0/24" in result.output

    def test_extra_rtrules_from_rtrules_file(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", str(_FIXTURE_DIR)])
        # Fixture rtrules file has source 192.0.2.0/24 → isp1, pref 1000
        assert "pref 1000" in result.output

    def test_help_option(self, runner):
        result = runner.invoke(cli, ["generate-iproute2-rules", "--help"])
        assert result.exit_code == 0
        assert "iproute2" in result.output.lower() or "routing" in result.output.lower()


class TestGenerateIproute2RulesNoProviders:
    """Verify graceful handling of a config with no providers file."""

    def test_no_providers_no_crash(self, runner):
        # Use the minimal config dir that has no providers file
        minimal = Path(__file__).parent / "configs" / "minimal"
        if not minimal.is_dir():
            pytest.skip("minimal config fixture not found")
        result = runner.invoke(cli, ["generate-iproute2-rules", str(minimal)])
        assert result.exit_code == 0
        assert "No providers configured" in result.output
