"""Tests for the IR compiler."""

import textwrap
from pathlib import Path

from shorewall_nft.compiler.ir import Verdict, build_ir
from shorewall_nft.config.parser import load_config

MINIMAL_DIR = Path(__file__).parent / "configs" / "minimal"


class TestBuildIR:
    def setup_method(self):
        config = load_config(MINIMAL_DIR)
        self.ir = build_ir(config)

    def test_firewall_zone(self):
        assert self.ir.zones.firewall_zone == "fw"

    def test_zones(self):
        names = self.ir.zones.all_zone_names()
        assert "fw" in names
        assert "net" in names
        assert "loc" in names

    def test_base_chains(self):
        assert "input" in self.ir.chains
        assert "forward" in self.ir.chains
        assert "output" in self.ir.chains
        assert self.ir.chains["input"].is_base_chain
        assert self.ir.chains["forward"].is_base_chain
        assert self.ir.chains["output"].is_base_chain

    def test_zone_pair_chains(self):
        # From policy: loc->net ACCEPT, net->all DROP
        assert "loc-net" in self.ir.chains
        assert "net-fw" in self.ir.chains
        assert "net-loc" in self.ir.chains

    def test_policy_defaults(self):
        assert self.ir.chains["fw-net"].policy == Verdict.ACCEPT
        assert self.ir.chains["fw-loc"].policy == Verdict.ACCEPT
        assert self.ir.chains["loc-net"].policy == Verdict.ACCEPT
        # DROP/REJECT policies become JUMP to action chains (Drop/Reject)
        # when DROP_DEFAULT/REJECT_DEFAULT are set
        assert self.ir.chains["net-fw"].policy in (Verdict.DROP, Verdict.JUMP)
        assert self.ir.chains["net-loc"].policy in (Verdict.DROP, Verdict.JUMP)

    def test_ssh_rule_in_loc_fw(self):
        chain = self.ir.chains["loc-fw"]
        # SSH(ACCEPT) should expand to tcp dport 22
        ssh_rules = [r for r in chain.rules if
                     any(m.field == "tcp dport" and m.value == "22"
                         for m in r.matches)]
        assert len(ssh_rules) >= 1
        assert ssh_rules[0].verdict == Verdict.ACCEPT

    def test_dns_rule_in_loc_net(self):
        chain = self.ir.chains["loc-net"]
        # DNS(ACCEPT) should expand to tcp+udp dport 53
        dns_rules = [r for r in chain.rules if
                     any(m.value == "53" for m in r.matches)]
        assert len(dns_rules) == 2  # tcp and udp

    def test_ping_rule(self):
        chain = self.ir.chains["net-fw"]
        ping_rules = [r for r in chain.rules if
                      any("icmp" in m.field and "type" in m.field for m in r.matches)]
        assert len(ping_rules) >= 1

    def test_admin_ssh_comment(self):
        chain = self.ir.chains["net-fw"]
        commented = [r for r in chain.rules if r.comment == "Admin SSH"]
        assert len(commented) >= 1

    def test_http_anonymous_set(self):
        chain = self.ir.chains["net-loc"]
        http_rules = [r for r in chain.rules if
                      any("80" in m.value for m in r.matches)]
        assert len(http_rules) >= 1


class TestPerFamilyPolicySplit:
    """Per-family policy disagreement → family-tagged guard rule.

    Surfaces when shorewall (v4) and shorewall6 (v6) disagree on a
    zone-pair's terminal action — e.g. v4 says ``zoneA zoneB ACCEPT``
    but v6 only has ``zoneA all REJECT`` which expands to (zoneA,
    zoneB) at REJECT. The compiler must emit a ``meta nfproto ipv6
    jump sw_Reject`` guard before the ``accept`` terminal so v6
    packets actually take the v6-policy verdict.
    """

    def _make_config(self, tmp_path: Path) -> Path:
        """Build a minimal config that exercises the per-family split.

        Mirrors the ``merge-config`` output layout: v4 policy block,
        then ``# IPv6-only policies`` + ``?FAMILY ipv6`` block + ``?FAMILY any``.
        """
        cfg = tmp_path / "cfg"
        cfg.mkdir()
        (cfg / "shorewall.conf").write_text(
            "STARTUP_ENABLED=Yes\nDROP_DEFAULT=Drop\nREJECT_DEFAULT=Reject\n"
        )
        (cfg / "zones").write_text(textwrap.dedent("""\
            fw  firewall
            net ip
            loc ip
            voi ip
        """))
        (cfg / "interfaces").write_text(textwrap.dedent("""\
            net eth0 -
            loc eth1 -
            voi eth2 -
        """))
        (cfg / "policy").write_text(textwrap.dedent("""\
            loc voi ACCEPT
            loc all REJECT
            ?FAMILY ipv6
            loc voi REJECT
            loc all REJECT
            ?FAMILY any
        """))
        (cfg / "rules").write_text("")
        return cfg

    def test_v6_minority_emits_family_guard_before_accept(self, tmp_path):
        cfg = self._make_config(tmp_path)
        ir = build_ir(load_config(cfg))
        chain = ir.chains["loc-voi"]
        # The chain.policy_v4 + policy_v6 disagree → one family-guard
        # rule was prepended before the terminal jump/accept.
        assert chain.policy_v4 == Verdict.ACCEPT
        assert chain.policy_v6 == Verdict.REJECT

        guards = [r for r in chain.rules
                  if any(m.field == "meta nfproto" and m.value == "ipv6"
                         and m.negate is False
                         for m in r.matches)
                  and r.verdict == Verdict.JUMP
                  and r.verdict_args is not None
                  and "Reject" in str(r.verdict_args)]
        assert len(guards) == 1, (
            f"expected exactly one ipv6 reject guard, got "
            f"{[(r.verdict, r.verdict_args, r.matches) for r in chain.rules[-3:]]}"
        )
        # And the family-agnostic terminal is still ACCEPT (v4 path).
        assert chain.policy == Verdict.ACCEPT


class TestMacroFamilyTagging:
    """Macros sourced from a v6 file (or wrapped with ``?FAMILY ipv6``)
    must NOT have their entries expanded into v4 zone-pair chains.

    Concrete bug surfaced on the reference live-dump: a custom
    ``macros/macro.Trcrt`` shipped with shorewall6 only had the v6
    PARAM line ``ipv6-icmp 128``. ``merge-config`` copied the file
    untagged → the compiler treated those entries as family-agnostic
    and emitted dead ``meta nfproto ipv4 meta l4proto ipv6-icmp ...``
    rules into every v4 zone-pair chain. The fix tags v6 macro entries
    with ``family="ipv6"`` so ``_expand_macro`` skips them in v4
    context.
    """

    def _build_macro_fixture(self, tmp_path):
        cfg = tmp_path / "cfg"
        cfg.mkdir()
        (cfg / "shorewall.conf").write_text(
            "STARTUP_ENABLED=Yes\nDROP_DEFAULT=Drop\nREJECT_DEFAULT=Reject\n"
        )
        (cfg / "zones").write_text(textwrap.dedent("""\
            fw  firewall
            net ip
            loc ip
        """))
        (cfg / "interfaces").write_text(textwrap.dedent("""\
            net eth0 -
            loc eth1 -
        """))
        (cfg / "policy").write_text("loc net ACCEPT\nnet all DROP\n")
        # Custom macro tagged ipv6 — emulates merge-config's wrap.
        macros = cfg / "macros"
        macros.mkdir()
        (macros / "macro.MyV6Trcrt").write_text(textwrap.dedent("""\
            ?FAMILY ipv6
            PARAM	-	-	udp	33434:33524
            PARAM	-	-	ipv6-icmp	128
            ?FAMILY any
        """))
        (cfg / "rules").write_text(
            "MyV6Trcrt(ACCEPT)	loc	net\n"
        )
        return cfg

    def test_v6_macro_does_not_emit_in_v4_context(self, tmp_path):
        cfg = self._build_macro_fixture(tmp_path)
        ir = build_ir(load_config(cfg))
        chain = ir.chains.get("loc-net")
        assert chain is not None
        bogus = [
            r for r in chain.rules
            if any(m.field == "meta nfproto" and m.value == "ipv4"
                   for m in r.matches)
            and any(m.field == "meta l4proto"
                    and m.value in ("ipv6-icmp", "icmpv6")
                    for m in r.matches)
        ]
        assert bogus == [], (
            "v6 macro entries leaked into v4 zone-pair chain: "
            f"{[(r.matches, r.verdict) for r in bogus]}"
        )
