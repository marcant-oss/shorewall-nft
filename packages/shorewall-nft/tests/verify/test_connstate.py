"""Unit tests for shorewall_nft.verify.connstate.

All tests are pure-logic: no network namespaces, no root, no scapy.
``ns`` (the subprocess side-effect) is patched to a stub that returns a
configurable subprocess.CompletedProcess.  ``NFCTSocket`` (used only by
``run_small_conntrack_probe``) is patched to an in-memory fake that never
opens a real netlink socket.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

import shorewall_nft.verify.connstate as connstate
from shorewall_nft.verify.connstate import ConnStateResult

# Pull the netns-calling functions through module references so pytest does
# not collect them as test items (pytest harvests bare ``test_*`` names
# injected into the module namespace by a star/named import).
_test_established_tcp = connstate.test_established_tcp
_test_drop_not_syn = connstate.test_drop_not_syn
_test_invalid_flags = connstate.test_invalid_flags
_test_syn_to_allowed = connstate.test_syn_to_allowed
_test_syn_to_blocked = connstate.test_syn_to_blocked
_test_udp_conntrack = connstate.test_udp_conntrack
_test_rfc1918_blocked = connstate.test_rfc1918_blocked
_run_connstate_tests = connstate.run_connstate_tests
_run_small_conntrack_probe = connstate.run_small_conntrack_probe


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    """Build a fake CompletedProcess."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


# ---------------------------------------------------------------------------
# ConnStateResult dataclass
# ---------------------------------------------------------------------------

class TestConnStateResult:
    def test_fields_accessible(self):
        r = ConnStateResult(name="foo", passed=True, detail="ok", ms=42)
        assert r.name == "foo"
        assert r.passed is True
        assert r.detail == "ok"
        assert r.ms == 42

    def test_default_ms_is_zero(self):
        r = ConnStateResult(name="bar", passed=False, detail="fail")
        assert r.ms == 0

    def test_equality(self):
        a = ConnStateResult(name="x", passed=True, detail="d", ms=1)
        b = ConnStateResult(name="x", passed=True, detail="d", ms=1)
        assert a == b

    def test_passed_false_variant(self):
        r = ConnStateResult(name="ct_state_established", passed=False, detail="blocked")
        assert not r.passed


# ---------------------------------------------------------------------------
# test_established_tcp
# ---------------------------------------------------------------------------

class TestEstablishedTcp:
    def test_happy_path_returncode_zero(self):
        """returncode=0 → passed=True."""
        with patch("shorewall_nft.verify.connstate.ns", return_value=_completed(0)):
            r = _test_established_tcp("10.0.0.1", port=80)
        assert r.passed is True
        assert r.name == "ct_state_established"

    def test_nonzero_returncode_is_failure(self):
        """returncode != 0 → passed=False."""
        with patch("shorewall_nft.verify.connstate.ns", return_value=_completed(1)):
            r = _test_established_tcp("10.0.0.1", port=443)
        assert r.passed is False

    def test_default_port_is_80(self):
        """Without explicit port the call should use port 80 in the detail."""
        with patch("shorewall_nft.verify.connstate.ns", return_value=_completed(0)) as mock_ns:
            r = _test_established_tcp("10.0.0.1")
        assert "80" in r.detail
        assert mock_ns.called

    def test_ms_field_is_non_negative(self):
        with patch("shorewall_nft.verify.connstate.ns", return_value=_completed(0)):
            r = _test_established_tcp("10.0.0.1")
        assert r.ms >= 0


# ---------------------------------------------------------------------------
# test_drop_not_syn
# ---------------------------------------------------------------------------

class TestDropNotSyn:
    def test_dropped_output_passes(self):
        """scapy stdout='DROPPED' → passed=True."""
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            r = _test_drop_not_syn("10.0.0.1")
        assert r.passed is True
        assert r.name == "dropNotSyn"

    def test_rst_response_fails(self):
        """scapy stdout='RST' → passed=False (packet reached host)."""
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="RST")):
            r = _test_drop_not_syn("10.0.0.1")
        assert r.passed is False

    def test_response_string_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="RESPONSE")):
            r = _test_drop_not_syn("10.0.0.1")
        assert r.passed is False

    def test_exception_in_ns_is_caught(self):
        """If ns raises, result is passed=False with detail describing the error."""
        with patch("shorewall_nft.verify.connstate.ns",
                   side_effect=RuntimeError("netns gone")):
            r = _test_drop_not_syn("10.0.0.1")
        assert r.passed is False
        assert "netns gone" in r.detail


# ---------------------------------------------------------------------------
# test_invalid_flags
# ---------------------------------------------------------------------------

class TestInvalidFlags:
    def test_dropped_passes(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            r = _test_invalid_flags("10.0.0.1")
        assert r.passed is True
        assert r.name == "invalid_flags_synfin"

    def test_response_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="RESPONSE")):
            r = _test_invalid_flags("10.0.0.1")
        assert r.passed is False

    def test_exception_caught(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   side_effect=OSError("test")):
            r = _test_invalid_flags("10.0.0.1")
        assert r.passed is False


# ---------------------------------------------------------------------------
# test_syn_to_allowed
# ---------------------------------------------------------------------------

class TestSynToAllowed:
    def test_syn_ack_passes(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="SYN-ACK")):
            r = _test_syn_to_allowed("10.0.0.1", port=80)
        assert r.passed is True
        assert r.name == "syn_allowed"

    def test_dropped_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            r = _test_syn_to_allowed("10.0.0.1", port=80)
        assert r.passed is False

    def test_rst_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="RST")):
            r = _test_syn_to_allowed("10.0.0.1")
        assert r.passed is False


# ---------------------------------------------------------------------------
# test_syn_to_blocked
# ---------------------------------------------------------------------------

class TestSynToBlocked:
    @pytest.mark.parametrize("outcome", ["DROPPED", "RST", "ICMP_REJECT"])
    def test_blocked_outcomes_pass(self, outcome):
        """DROPPED, RST, and ICMP_REJECT are all valid 'blocked' results."""
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout=outcome)):
            r = _test_syn_to_blocked("10.0.0.1", port=12345)
        assert r.passed is True, f"Expected pass for outcome={outcome!r}"

    def test_other_outcome_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="OTHER")):
            r = _test_syn_to_blocked("10.0.0.1")
        assert r.passed is False

    def test_default_port_in_detail(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            r = _test_syn_to_blocked("10.0.0.1")
        assert "12345" in r.detail


# ---------------------------------------------------------------------------
# test_udp_conntrack
# ---------------------------------------------------------------------------

class TestUdpConntrack:
    def test_udp_response_passes(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="UDP_RESPONSE")):
            r = _test_udp_conntrack("10.0.0.1", port=53)
        assert r.passed is True
        assert r.name == "udp_conntrack"

    def test_no_response_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="NO_RESPONSE")):
            r = _test_udp_conntrack("10.0.0.1")
        assert r.passed is False

    def test_icmp_unreachable_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="ICMP_3")):
            r = _test_udp_conntrack("10.0.0.1")
        assert r.passed is False


# ---------------------------------------------------------------------------
# test_rfc1918_blocked
# ---------------------------------------------------------------------------

class TestRfc1918Blocked:
    def test_dropped_passes(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            r = _test_rfc1918_blocked("10.0.0.1")
        assert r.passed is True
        assert r.name == "rfc1918_blocked"

    def test_response_fails(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="RESPONSE")):
            r = _test_rfc1918_blocked("10.0.0.1")
        assert r.passed is False

    def test_exception_caught(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   side_effect=Exception("boom")):
            r = _test_rfc1918_blocked("10.0.0.1")
        assert r.passed is False
        assert "boom" in r.detail


# ---------------------------------------------------------------------------
# run_connstate_tests (orchestrator)
# ---------------------------------------------------------------------------

class TestRunConnstateTests:
    def test_returns_seven_results(self):
        """Orchestrator must produce exactly 7 ConnStateResult objects."""
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            results = _run_connstate_tests("10.0.0.1", allowed_port=80)
        assert len(results) == 7

    def test_all_items_are_conn_state_result(self):
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            results = _run_connstate_tests("10.0.0.1")
        assert all(isinstance(r, ConnStateResult) for r in results)

    def test_result_names_are_unique(self):
        """Each test case must have a distinct name."""
        with patch("shorewall_nft.verify.connstate.ns",
                   return_value=_completed(0, stdout="DROPPED")):
            results = _run_connstate_tests("10.0.0.1")
        names = [r.name for r in results]
        assert len(names) == len(set(names)), f"Duplicate names: {names}"


# ---------------------------------------------------------------------------
# run_small_conntrack_probe
# ---------------------------------------------------------------------------

def _make_nfct_mock(entries_per_dump: int = 1) -> MagicMock:
    """Return a mock for ``NFCTSocket`` that behaves as a context manager.

    ``ct.dump(...)`` returns a fresh list of ``entries_per_dump`` sentinel
    objects on every call (so repeated calls within one probe run are all
    independent).  ``ct.flush()`` is a no-op.
    """
    ct_instance = MagicMock()
    ct_instance.dump.side_effect = lambda *_a, **_kw: iter([object()] * entries_per_dump)
    ct_instance.flush.return_value = None
    # Support ``with NFCTSocket(...) as ct:`` — __enter__ returns the mock itself.
    ct_instance.__enter__ = MagicMock(return_value=ct_instance)
    ct_instance.__exit__ = MagicMock(return_value=False)

    nfct_cls = MagicMock(return_value=ct_instance)
    return nfct_cls


class TestRunSmallConntrackProbe:
    # ``ns`` is still called for the NS_SRC traffic-generation probes (nc/ping).
    # Those calls don't affect the count logic, so a plain no-op stub is fine.
    _ns_stub = staticmethod(lambda *_a, **_kw: _completed(0, stdout=""))

    def test_returns_four_results(self):
        """Probe must produce exactly 4 ConnStateResult objects."""
        with patch("shorewall_nft.verify.connstate.ns", side_effect=self._ns_stub), \
             patch("shorewall_nft.verify.connstate.NFCTSocket", _make_nfct_mock(1)):
            results = _run_small_conntrack_probe("10.0.0.1", port=80)
        assert len(results) == 4

    def test_all_pass_when_counts_positive(self):
        """When conntrack count >= 1 all results should pass."""
        with patch("shorewall_nft.verify.connstate.ns", side_effect=self._ns_stub), \
             patch("shorewall_nft.verify.connstate.NFCTSocket", _make_nfct_mock(1)):
            results = _run_small_conntrack_probe()
        assert all(r.passed for r in results)

    def test_fails_when_zero_entries(self):
        """When conntrack count = 0 the tracked-flow checks should fail."""
        with patch("shorewall_nft.verify.connstate.ns", side_effect=self._ns_stub), \
             patch("shorewall_nft.verify.connstate.NFCTSocket", _make_nfct_mock(0)):
            results = _run_small_conntrack_probe()
        # The 4th result (ct:table_nonempty) and the per-proto checks all fail
        named = {r.name: r for r in results}
        assert not named["ct:tcp_flow_tracked"].passed
        assert not named["ct:udp_flow_tracked"].passed
        assert not named["ct:icmp_flow_tracked"].passed
        assert not named["ct:table_nonempty"].passed

    def test_result_names(self):
        """The four canonical probe names must be present."""
        expected = {
            "ct:tcp_flow_tracked",
            "ct:udp_flow_tracked",
            "ct:icmp_flow_tracked",
            "ct:table_nonempty",
        }
        with patch("shorewall_nft.verify.connstate.ns", side_effect=self._ns_stub), \
             patch("shorewall_nft.verify.connstate.NFCTSocket", _make_nfct_mock(1)):
            results = _run_small_conntrack_probe()
        assert {r.name for r in results} == expected

    def test_exception_in_count_treated_as_zero(self):
        """If NFCTSocket raises, _ct_count falls back to 0 → all checks fail."""
        ct_instance = MagicMock()
        ct_instance.dump.side_effect = OSError("netns gone")
        ct_instance.flush.return_value = None
        ct_instance.__enter__ = MagicMock(return_value=ct_instance)
        ct_instance.__exit__ = MagicMock(return_value=False)
        nfct_cls = MagicMock(return_value=ct_instance)

        with patch("shorewall_nft.verify.connstate.ns", side_effect=self._ns_stub), \
             patch("shorewall_nft.verify.connstate.NFCTSocket", nfct_cls):
            results = _run_small_conntrack_probe()
        named = {r.name: r for r in results}
        assert not named["ct:tcp_flow_tracked"].passed
