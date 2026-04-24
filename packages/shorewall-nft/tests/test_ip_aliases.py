"""WP-F3: IP alias setup options tests.

Covers:
  ADD_IP_ALIASES  — auto-add /32 aliases for 1:1 NAT external IPs.
  ADD_SNAT_ALIASES — auto-add /32 aliases for explicit SNAT targets.
  apply_ip_aliases / remove_ip_aliases — pyroute2 runtime apply paths.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from shorewall_nft.compiler.ir import FirewallIR
from shorewall_nft.compiler.nat import _process_snat_line, process_static_nat
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.runtime.apply import apply_ip_aliases, remove_ip_aliases


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nat_line(*cols: str) -> ConfigLine:
    return ConfigLine(columns=list(cols), file="test-nat", lineno=1)


def _snat_line(*cols: str) -> ConfigLine:
    return ConfigLine(columns=list(cols), file="test-snat", lineno=1)


def _make_ir(**settings: str) -> FirewallIR:
    ir = FirewallIR()
    ir.settings.update(settings)
    return ir


# ---------------------------------------------------------------------------
# Compiler tests — ip_aliases population
# ---------------------------------------------------------------------------

class TestDnatAddIpAliasesYes:
    """ADD_IP_ALIASES=Yes: 1:1 NAT external IP added to ir.ip_aliases."""

    def setup_method(self):
        self.ir = _make_ir(ADD_IP_ALIASES="Yes")
        process_static_nat(self.ir, [
            _nat_line("203.0.113.50", "eth0", "192.0.2.50", "-", "-"),
        ])

    def test_ip_aliases_populated(self):
        assert len(self.ir.ip_aliases) == 1

    def test_ip_aliases_address(self):
        addr, _iface = self.ir.ip_aliases[0]
        assert addr == "203.0.113.50"

    def test_ip_aliases_iface(self):
        _addr, iface = self.ir.ip_aliases[0]
        assert iface == "eth0"

    def test_default_is_yes(self):
        """ADD_IP_ALIASES defaults to Yes when the key is absent."""
        ir = FirewallIR()  # no settings at all
        process_static_nat(ir, [
            _nat_line("203.0.113.51", "eth0", "192.0.2.51", "-", "-"),
        ])
        assert len(ir.ip_aliases) == 1
        assert ir.ip_aliases[0][0] == "203.0.113.51"


class TestDnatAddIpAliasesNo:
    """ADD_IP_ALIASES=No: ir.ip_aliases stays empty."""

    def setup_method(self):
        self.ir = _make_ir(ADD_IP_ALIASES="No")
        process_static_nat(self.ir, [
            _nat_line("203.0.113.50", "eth0", "192.0.2.50", "-", "-"),
        ])

    def test_ip_aliases_empty(self):
        assert self.ir.ip_aliases == []


class TestDnatAliasDeduplication:
    """Same external IP across two NAT rows should only appear once."""

    def test_dedup(self):
        ir = _make_ir(ADD_IP_ALIASES="Yes")
        process_static_nat(ir, [
            _nat_line("203.0.113.50", "eth0", "192.0.2.50", "-", "-"),
            _nat_line("203.0.113.50", "eth0", "192.0.2.51", "-", "-"),
        ])
        assert len(ir.ip_aliases) == 1


class TestDnatEmptyAliasSuffix:
    """INTERFACE with explicit empty alias (eth0:) suppresses alias."""

    def test_empty_alias_suffix_no_record(self):
        ir = _make_ir(ADD_IP_ALIASES="Yes")
        process_static_nat(ir, [
            _nat_line("203.0.113.50", "eth0:", "192.0.2.50", "-", "-"),
        ])
        # Upstream: $add_ip_aliases = '' when alias part is explicitly empty.
        assert ir.ip_aliases == []


class TestSnatAddSnatAliasesYes:
    """ADD_SNAT_ALIASES=Yes: explicit SNAT target added to ir.ip_aliases."""

    def setup_method(self):
        self.ir = _make_ir(ADD_SNAT_ALIASES="Yes")
        # Ensure NAT chains exist for _process_snat_line.
        from shorewall_nft.compiler.nat import _ensure_nat_chains
        _ensure_nat_chains(self.ir)
        _process_snat_line(self.ir, _snat_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth1",
        ))

    def test_ip_aliases_populated(self):
        assert len(self.ir.ip_aliases) == 1

    def test_snat_alias_address(self):
        addr, _iface = self.ir.ip_aliases[0]
        assert addr == "198.51.100.1"

    def test_snat_alias_iface(self):
        _addr, iface = self.ir.ip_aliases[0]
        assert iface == "eth1"


class TestSnatAddSnatAliasesNo:
    """ADD_SNAT_ALIASES=No (default): ir.ip_aliases stays empty."""

    def setup_method(self):
        self.ir = _make_ir(ADD_SNAT_ALIASES="No")
        from shorewall_nft.compiler.nat import _ensure_nat_chains
        _ensure_nat_chains(self.ir)
        _process_snat_line(self.ir, _snat_line(
            "SNAT(198.51.100.1)", "192.0.2.0/24", "eth1",
        ))

    def test_ip_aliases_empty(self):
        assert self.ir.ip_aliases == []

    def test_default_is_no(self):
        """ADD_SNAT_ALIASES defaults to No when absent."""
        ir = FirewallIR()  # no settings
        from shorewall_nft.compiler.nat import _ensure_nat_chains
        _ensure_nat_chains(ir)
        _process_snat_line(ir, _snat_line(
            "SNAT(198.51.100.2)", "192.0.2.0/24", "eth1",
        ))
        assert ir.ip_aliases == []


class TestSnatMasqueradeNoAlias:
    """MASQUERADE targets do not produce aliases (dynamic IP — no alias needed)."""

    def test_masquerade_no_alias(self):
        ir = _make_ir(ADD_SNAT_ALIASES="Yes")
        from shorewall_nft.compiler.nat import _ensure_nat_chains
        _ensure_nat_chains(ir)
        _process_snat_line(ir, _snat_line("MASQUERADE", "192.0.2.0/24", "eth1"))
        assert ir.ip_aliases == []


class TestSnatNoDest:
    """If there is no DEST interface column, no alias is recorded."""

    def test_no_dest_no_alias(self):
        ir = _make_ir(ADD_SNAT_ALIASES="Yes")
        from shorewall_nft.compiler.nat import _ensure_nat_chains
        _ensure_nat_chains(ir)
        _process_snat_line(ir, _snat_line("SNAT(198.51.100.1)", "192.0.2.0/24", "-"))
        assert ir.ip_aliases == []


# ---------------------------------------------------------------------------
# Runtime tests — apply_ip_aliases / remove_ip_aliases with pyroute2 mocked
# ---------------------------------------------------------------------------

class TestApplyIpAliasesCallsPyroute2:
    """apply_ip_aliases calls IPRoute.addr("add", …) with the right args."""

    def test_add_called(self):
        mock_ipr = MagicMock()
        # No existing addr — get_addr returns empty list.
        mock_ipr.get_addr.return_value = []
        mock_ipr.link_lookup.return_value = [5]

        with patch("shorewall_nft.runtime.apply.IPRoute", return_value=mock_ipr), \
             patch("shorewall_nft.runtime.apply.NetlinkError", Exception), \
             patch("shorewall_nft.runtime.apply._PYROUTE2_AVAILABLE", True):
            applied, skipped, errors = apply_ip_aliases(
                [("192.0.2.1", "eth0")])

        assert applied == 1
        assert skipped == 0
        assert errors == []

        # addr("add", …) must have been called with address= and index=.
        call_args = mock_ipr.addr.call_args
        assert call_args is not None
        args, kwargs = call_args
        assert args[0] == "add"
        assert kwargs.get("address") == "192.0.2.1"
        assert kwargs.get("index") == 5
        assert kwargs.get("prefixlen") == 32

    def test_link_lookup_called_with_iface(self):
        mock_ipr = MagicMock()
        mock_ipr.get_addr.return_value = []
        mock_ipr.link_lookup.return_value = [7]

        with patch("shorewall_nft.runtime.apply.IPRoute", return_value=mock_ipr), \
             patch("shorewall_nft.runtime.apply.NetlinkError", Exception), \
             patch("shorewall_nft.runtime.apply._PYROUTE2_AVAILABLE", True):
            apply_ip_aliases([("192.0.2.1", "eth1")])

        mock_ipr.link_lookup.assert_called_with(ifname="eth1")


class TestRemoveIpAliasesCallsPyroute2:
    """remove_ip_aliases calls IPRoute.addr("del", …) with the right args."""

    def test_del_called(self):
        mock_ipr = MagicMock()
        mock_ipr.link_lookup.return_value = [5]

        with patch("shorewall_nft.runtime.apply.IPRoute", return_value=mock_ipr), \
             patch("shorewall_nft.runtime.apply.NetlinkError", Exception), \
             patch("shorewall_nft.runtime.apply._PYROUTE2_AVAILABLE", True):
            removed, skipped, errors = remove_ip_aliases(
                [("192.0.2.1", "eth0")])

        assert removed == 1
        assert skipped == 0
        assert errors == []

        call_args = mock_ipr.addr.call_args
        assert call_args is not None
        args, kwargs = call_args
        assert args[0] == "del"
        assert kwargs.get("address") == "192.0.2.1"
        assert kwargs.get("index") == 5
        assert kwargs.get("prefixlen") == 32


class TestApplyIpAliasesIdempotent:
    """Calling apply_ip_aliases twice: second call skips already-present addr."""

    def test_second_call_skips(self):
        mock_ipr = MagicMock()
        mock_ipr.link_lookup.return_value = [5]

        call_count = [0]

        def _addr_side_effect(op, **kwargs):
            call_count[0] += 1

        mock_ipr.addr.side_effect = _addr_side_effect

        # First call: addr not present yet.
        mock_ipr.get_addr.return_value = []

        with patch("shorewall_nft.runtime.apply.IPRoute", return_value=mock_ipr), \
             patch("shorewall_nft.runtime.apply.NetlinkError", Exception), \
             patch("shorewall_nft.runtime.apply._PYROUTE2_AVAILABLE", True):
            a1, s1, e1 = apply_ip_aliases([("192.0.2.1", "eth0")])
            assert a1 == 1
            assert s1 == 0

            # Second call: addr now "present" (get_addr returns a match).
            mock_ipr.get_addr.return_value = [{"IFA_ADDRESS": "192.0.2.1"}]
            a2, s2, e2 = apply_ip_aliases([("192.0.2.1", "eth0")])
            assert a2 == 0
            assert s2 == 1  # skipped because already present

        # addr("add", …) must have been called exactly once.
        assert call_count[0] == 1


class TestApplyIpAliasesEmptyList:
    """Empty address list returns (0, 0, []) immediately."""

    def test_empty_list(self):
        applied, skipped, errors = apply_ip_aliases([])
        assert (applied, skipped, errors) == (0, 0, [])


class TestRemoveIpAliasesEmptyList:
    """Empty address list returns (0, 0, []) immediately."""

    def test_empty_list(self):
        removed, skipped, errors = remove_ip_aliases([])
        assert (removed, skipped, errors) == (0, 0, [])


class TestApplyIpAliasesMissingIface:
    """If the interface is not present, the entry is counted as skipped."""

    def test_missing_iface_skipped(self):
        mock_ipr = MagicMock()
        mock_ipr.link_lookup.return_value = []  # iface not found

        with patch("shorewall_nft.runtime.apply.IPRoute", return_value=mock_ipr), \
             patch("shorewall_nft.runtime.apply.NetlinkError", Exception), \
             patch("shorewall_nft.runtime.apply._PYROUTE2_AVAILABLE", True):
            applied, skipped, errors = apply_ip_aliases(
                [("192.0.2.1", "nonexistent0")])

        assert applied == 0
        assert skipped == 1
        assert any("nonexistent0" in e for e in errors)
        mock_ipr.addr.assert_not_called()
