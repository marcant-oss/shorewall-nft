"""Regression test for merge-config rules-file order preservation.

Pins the invariant that ``_merge_rules`` keeps v4 untagged segments
and ``?COMMENT``-tagged blocks interleaved in their original
source-line order.  Classic shorewall's chain-complete short-circuit
(``Chains.pm:1832``) closes a per-pair chain when a terminating
catch-all rule lands in it; every later rule in source order is
then unreachable.

An earlier ``_merge_rules`` implementation parsed the file into
``(header, blocks)`` and emitted ``header`` followed by all blocks,
which inverted the order classic shorewall saw in the v4 source.
On the rossini reference this surfaced as 53 fail_drops where

    rules:884   Web(ACCEPT) all  cdn:$CDN_WWW_DREAMROBOT_DE
    rules:2322  DROP:$LOG   agfeo  any

ended up reordered in the merged output (DROP first, Web ACCEPT
later) — closing every ``agfeo→X`` chain before the line-884
ACCEPTs could land.

This test feeds a minimal v4 rules file that mixes untagged regions
with ``?COMMENT TAG`` blocks and asserts the merged output keeps
the segments in the same relative order.
"""

from __future__ import annotations

from pathlib import Path

from shorewall_nft.tools.merge_config import _merge_rules, _parse_rules_segments


def _write(path: Path, body: str) -> None:
    path.write_text(body)


def test_segment_parser_preserves_order(tmp_path):
    src = tmp_path / "rules"
    _write(src, """\
# untagged-A
ACCEPT  net  loc:10.0.0.1  tcp 22

?COMMENT block1
ACCEPT  all  loc:10.0.0.2  tcp 80
?COMMENT

# untagged-B
DROP:$LOG  net  any

?COMMENT block2
ACCEPT  all  loc:10.0.0.3  tcp 443
?COMMENT
""")

    segs = _parse_rules_segments(src)
    kinds = [(s[0] if s[0] == "untagged" else f"tagged:{s[1]}") for s in segs]
    assert kinds == [
        "untagged",
        "tagged:block1",
        "untagged",
        "tagged:block2",
    ], f"unexpected segment order: {kinds}"


def test_merge_rules_keeps_untagged_before_later_tagged_block(tmp_path):
    """Reproduces the rossini shape: an untagged DROP at the *end*
    of v4 must remain after the earlier tagged Web(ACCEPT) block in
    the merged output.
    """
    v4 = tmp_path / "v4-rules"
    v6 = tmp_path / "v6-rules"
    _write(v4, """\
# v4 head
?SECTION NEW

?COMMENT cdn-block
Web(ACCEPT)  all  cdn:46.231.239.9
?COMMENT

DROP:$LOG  agfeo  any
""")
    _write(v6, "?SECTION NEW\n")

    out = tmp_path / "merged-rules"
    _merge_rules(v4, v6, out)

    text = out.read_text()
    cdn_idx = text.index("Web(ACCEPT)")
    drop_idx = text.index("DROP:$LOG")
    assert cdn_idx < drop_idx, (
        "Web(ACCEPT) all cdn:host (tagged) must appear before "
        "DROP:$LOG agfeo any (untagged tail) in the merged output — "
        "classic shorewall's chain-complete short-circuit depends on "
        "this source-line order"
    )


def test_merge_rules_keeps_untagged_before_first_tagged_block(tmp_path):
    """An untagged region *before* a tagged block must come first
    in the merged output.  Sanity counter-pin to make sure the fix
    didn't only handle the tail-end case.
    """
    v4 = tmp_path / "v4-rules"
    v6 = tmp_path / "v6-rules"
    _write(v4, """\
?SECTION NEW
ACCEPT  net  loc:10.0.0.99  tcp 22

?COMMENT cdn-block
Web(ACCEPT)  all  cdn:46.231.239.10
?COMMENT
""")
    _write(v6, "?SECTION NEW\n")

    out = tmp_path / "merged-rules"
    _merge_rules(v4, v6, out)

    text = out.read_text()
    early = text.index("10.0.0.99")
    later = text.index("46.231.239.10")
    assert early < later, "untagged head rule must precede the tagged block"


def test_merge_rules_inlines_v6_into_matching_v4_block(tmp_path):
    """v6 ?COMMENT block with a tag matching a v4 block is folded
    inside the v4 block (wrapped in ``?FAMILY ipv6``).  Pin this so
    a later tweak to the segment merger doesn't drop v6 content.
    """
    v4 = tmp_path / "v4-rules"
    v6 = tmp_path / "v6-rules"
    _write(v4, """\
?SECTION NEW

?COMMENT shared
ACCEPT  net  loc:1.2.3.4  tcp 80
?COMMENT
""")
    _write(v6, """\
?SECTION NEW

?COMMENT shared
ACCEPT  net  loc:<2001:db8::1>  tcp 80
?COMMENT
""")

    out = tmp_path / "merged-rules"
    _merge_rules(v4, v6, out)

    text = out.read_text()
    assert "?COMMENT shared" in text
    assert "?FAMILY ipv6" in text
    assert "2001:db8::1" in text
    # v6 content is INSIDE the shared block (between opening and
    # closing ?COMMENT), not appended elsewhere.
    open_idx = text.find("?COMMENT shared")
    close_idx = text.rfind("?COMMENT", 0, text.find("?FAMILY ipv6") + 1)
    v6_idx = text.index("2001:db8::1")
    assert open_idx < v6_idx, "v6 content must be after ?COMMENT shared opener"
