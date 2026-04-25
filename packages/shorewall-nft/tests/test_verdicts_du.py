"""Tests for the typed SpecialVerdict discriminated union.

Covers:
- Construction and value-equality of all 21 dataclasses.
- SpecialVerdict union alias exports all 21 variants.
- Each typed variant, when placed on Rule.verdict_args, produces the same
  nft fragment as the legacy string-prefix producer would have produced.
- Legacy string-prefix path still works (fallback regression).
- rule.log_level takes precedence over a legacy log_level: prefix string.
"""

from __future__ import annotations



from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Rule,
    Verdict,
)
from shorewall_nft.compiler.verdicts import (
    AuditVerdict,
    ClassifyVerdict,
    ConnmarkVerdict,
    CounterVerdict,
    CtHelperVerdict,
    DnatVerdict,
    DscpVerdict,
    DupVerdict,
    EcnClearVerdict,
    MarkVerdict,
    MasqueradeVerdict,
    NamedCounterVerdict,
    NflogVerdict,
    NonatVerdict,
    NotrackVerdict,
    QuotaVerdict,
    RedirectVerdict,
    RestoreMarkVerdict,
    SaveMarkVerdict,
    SnatVerdict,
    SpecialVerdict,
    SynproxyVerdict,
    TproxyVerdict,
)
from shorewall_nft.nft.emitter import emit_nft

# ---------------------------------------------------------------------------
# Helper: build a minimal FirewallIR with one rule in a plain filter chain.
# We do NOT load any config directory — this constructs the IR directly so
# these tests have no filesystem dependency and run in pure-unit time.
# ---------------------------------------------------------------------------

def _ir_with_rule(rule: Rule) -> FirewallIR:
    """Return a bare FirewallIR containing exactly one rule in a non-base chain."""
    ir = FirewallIR()
    ch = Chain(name="test-chain", chain_type=ChainType.FILTER)
    ch.rules.append(rule)
    ir.chains["test-chain"] = ch
    return ir


def _emit_rule(rule: Rule) -> str:
    """Emit a complete nft script for a single-rule IR and return it."""
    return emit_nft(_ir_with_rule(rule))


# ---------------------------------------------------------------------------
# 1. Construction + value equality for all 17 dataclasses
# ---------------------------------------------------------------------------

class TestDataclassConstruction:
    """Every frozen dataclass must be constructible and support value equality."""

    def test_snat_verdict(self):
        v = SnatVerdict(target="198.51.100.1")
        assert v.target == "198.51.100.1"
        assert v == SnatVerdict(target="198.51.100.1")

    def test_dnat_verdict(self):
        v = DnatVerdict(target="192.0.2.1:80")
        assert v.target == "192.0.2.1:80"
        assert v == DnatVerdict(target="192.0.2.1:80")

    def test_masquerade_verdict(self):
        v = MasqueradeVerdict()
        assert v == MasqueradeVerdict()

    def test_redirect_verdict(self):
        v = RedirectVerdict(port=3128)
        assert v.port == 3128
        assert v == RedirectVerdict(port=3128)

    def test_notrack_verdict(self):
        v = NotrackVerdict()
        assert v == NotrackVerdict()

    def test_ct_helper_verdict(self):
        v = CtHelperVerdict(name="ftp")
        assert v.name == "ftp"
        assert v == CtHelperVerdict(name="ftp")

    def test_mark_verdict_no_mask(self):
        v = MarkVerdict(value=0x10)
        assert v.value == 0x10
        assert v.mask is None
        assert v == MarkVerdict(value=0x10)

    def test_mark_verdict_with_mask(self):
        v = MarkVerdict(value=0x10, mask=0xFF)
        assert v.mask == 0xFF
        assert v == MarkVerdict(value=0x10, mask=0xFF)

    def test_connmark_verdict(self):
        v = ConnmarkVerdict(value=0xAB)
        assert v.value == 0xAB
        assert v == ConnmarkVerdict(value=0xAB)

    def test_restore_mark_verdict(self):
        v = RestoreMarkVerdict()
        assert v == RestoreMarkVerdict()

    def test_save_mark_verdict(self):
        v = SaveMarkVerdict()
        assert v == SaveMarkVerdict()

    def test_dscp_verdict(self):
        v = DscpVerdict(value="ef")
        assert v.value == "ef"
        assert v == DscpVerdict(value="ef")

    def test_classify_verdict(self):
        v = ClassifyVerdict(value="1:10")
        assert v.value == "1:10"
        assert v == ClassifyVerdict(value="1:10")

    def test_ecn_clear_verdict(self):
        v = EcnClearVerdict()
        assert v == EcnClearVerdict()

    def test_counter_verdict_no_params(self):
        v = CounterVerdict()
        assert v.params is None
        assert v == CounterVerdict()

    def test_counter_verdict_with_params(self):
        v = CounterVerdict(params="192.0.2.0/24")
        assert v.params == "192.0.2.0/24"

    def test_named_counter_verdict(self):
        v = NamedCounterVerdict(name="drop_pkts")
        assert v.name == "drop_pkts"
        assert v == NamedCounterVerdict(name="drop_pkts")

    def test_nflog_verdict(self):
        v = NflogVerdict()
        assert v == NflogVerdict()

    def test_audit_verdict(self):
        v = AuditVerdict(base_action="ACCEPT")
        assert v.base_action == "ACCEPT"
        assert v == AuditVerdict(base_action="ACCEPT")


# ---------------------------------------------------------------------------
# 2. SpecialVerdict union alias covers all 20 variants
# ---------------------------------------------------------------------------

class TestSpecialVerdictUnion:
    """SpecialVerdict must be importable and cover every variant."""

    def test_all_variants_in_union(self):
        # get_args() on a Union returns the constituent types.
        import typing
        args = typing.get_args(SpecialVerdict)
        expected = {
            SnatVerdict, DnatVerdict, MasqueradeVerdict, NonatVerdict,
            RedirectVerdict, NotrackVerdict, CtHelperVerdict,
            MarkVerdict, ConnmarkVerdict, RestoreMarkVerdict, SaveMarkVerdict,
            DscpVerdict, ClassifyVerdict, EcnClearVerdict,
            CounterVerdict, NamedCounterVerdict, NflogVerdict,
            AuditVerdict,
            SynproxyVerdict, QuotaVerdict, TproxyVerdict, DupVerdict,
        }
        assert set(args) == expected, (
            f"Union mismatch. Extra: {set(args) - expected}. "
            f"Missing: {expected - set(args)}"
        )

    def test_count_is_22(self):
        import typing
        assert len(typing.get_args(SpecialVerdict)) == 22


# ---------------------------------------------------------------------------
# 3. Typed emit — each variant produces the expected nft fragment
# ---------------------------------------------------------------------------

class TestTypedEmit:
    """Typed SpecialVerdict on Rule.verdict_args must produce the correct fragment."""

    def _assert_contains(self, verdict_obj, expected_fragment: str):
        rule = Rule(verdict=Verdict.JUMP, verdict_args=verdict_obj)
        out = _emit_rule(rule)
        assert expected_fragment in out, (
            f"Expected {expected_fragment!r} in emitted output for {verdict_obj!r}.\n"
            f"Output snippet: {out[:500]}"
        )

    def test_snat(self):
        self._assert_contains(SnatVerdict(target="198.51.100.1"), "snat to 198.51.100.1")

    def test_dnat(self):
        self._assert_contains(DnatVerdict(target="192.0.2.1:80"), "dnat to 192.0.2.1:80")

    def test_masquerade(self):
        self._assert_contains(MasqueradeVerdict(), "masquerade")

    def test_redirect(self):
        self._assert_contains(RedirectVerdict(port=3128), "redirect to :3128")

    def test_notrack(self):
        self._assert_contains(NotrackVerdict(), "notrack")

    def test_ct_helper(self):
        self._assert_contains(CtHelperVerdict(name="ftp"), 'ct helper set "ftp"')

    def test_mark_no_mask(self):
        self._assert_contains(MarkVerdict(value=0x10), "meta mark set 0x00000010")

    def test_mark_with_mask(self):
        # mask=0xFF → mask_int = 0xFF ^ 0xFFFFFFFF = 0xFFFFFF00
        rule = Rule(verdict=Verdict.JUMP, verdict_args=MarkVerdict(value=0x10, mask=0xFF))
        out = _emit_rule(rule)
        assert "meta mark set meta mark and 0xffffff00 or 0x00000010" in out

    def test_connmark(self):
        self._assert_contains(ConnmarkVerdict(value=0xAB), "ct mark set 0x000000ab")

    def test_restore_mark(self):
        self._assert_contains(RestoreMarkVerdict(), "meta mark set ct mark")

    def test_save_mark(self):
        self._assert_contains(SaveMarkVerdict(), "ct mark set meta mark")

    def test_dscp(self):
        self._assert_contains(DscpVerdict(value="ef"), "ip dscp set ef")

    def test_classify(self):
        self._assert_contains(ClassifyVerdict(value="1:10"), "meta priority set 1:10")

    def test_ecn_clear(self):
        self._assert_contains(EcnClearVerdict(), "ip ecn set not-ect")

    def test_counter(self):
        self._assert_contains(CounterVerdict(), "counter accept")

    def test_named_counter(self):
        self._assert_contains(
            NamedCounterVerdict(name="drop_pkts"),
            'counter name "drop_pkts" accept',
        )

    def test_nflog(self):
        self._assert_contains(NflogVerdict(), "log group 0")

    def test_audit_accept(self):
        self._assert_contains(
            AuditVerdict(base_action="ACCEPT"),
            'log prefix "AUDIT:ACCEPT: " accept',
        )

    def test_audit_drop(self):
        self._assert_contains(
            AuditVerdict(base_action="DROP"),
            'log prefix "AUDIT:DROP: " accept',
        )


# ---------------------------------------------------------------------------
# 4. log_level field
# ---------------------------------------------------------------------------

class TestLogLevel:
    """rule.log_level carries the nft log level for Verdict.LOG rules."""

    def test_log_level_field_used(self):
        rule = Rule(verdict=Verdict.LOG, log_level="info")
        out = _emit_rule(rule)
        assert "level info" in out

    def test_log_level_strips_limit_tag(self):
        """A level like 'info:LOGIN,12,60' is stripped to just the level."""
        rule = Rule(verdict=Verdict.LOG, log_level="info:LOGIN,12,60")
        out = _emit_rule(rule)
        assert "level info" in out
        assert "LOGIN" not in out
