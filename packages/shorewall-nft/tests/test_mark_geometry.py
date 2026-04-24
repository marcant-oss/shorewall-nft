"""Unit tests for MarkGeometry — upstream Config.pm mark-geometry parity.

Tests replicate the exact arithmetic from Config.pm::initialize() at
Shorewall 5.2.6.1, exercising defaults, WIDE_TC_MARKS, HIGH_ROUTE_MARKS,
explicit TC_BITS override, and the build_ir() integration path.
"""

from __future__ import annotations

import pytest

from shorewall_nft.compiler.ir._data import MarkGeometry


def _geom(**settings: str) -> MarkGeometry:
    return MarkGeometry.from_settings(settings)


class TestDefaultGeometry:
    """No settings → upstream defaults (8-bit TC, 8-bit total mask)."""

    def test_tc_bits(self):
        assert _geom().tc_bits == 8

    def test_mask_bits(self):
        assert _geom().mask_bits == 8

    def test_provider_bits(self):
        assert _geom().provider_bits == 8

    def test_provider_offset(self):
        assert _geom().provider_offset == 0

    def test_zone_bits(self):
        assert _geom().zone_bits == 0

    def test_zone_offset(self):
        # PROVIDER_OFFSET=0, MASK_BITS(8) >= PROVIDER_BITS(8) → zone_offset = 8
        assert _geom().zone_offset == 8

    def test_tc_max(self):
        # make_mask(8) = 0xff
        assert _geom().tc_max == 0xFF

    def test_tc_mask(self):
        # make_mask(MASK_BITS=8) = 0xff
        assert _geom().tc_mask == 0xFF

    def test_provider_mask(self):
        # make_mask(8) << 0 = 0xff
        assert _geom().provider_mask == 0xFF

    def test_zone_mask(self):
        # ZONE_BITS=0 → 0
        assert _geom().zone_mask == 0x00

    def test_exclusion_mask(self):
        # 1 << (zone_offset=8 + zone_bits=0) = 0x100
        assert _geom().exclusion_mask == 0x100

    def test_tproxy_mark(self):
        # exclusion_mask << 1 = 0x200
        assert _geom().tproxy_mark == 0x200

    def test_event_mark(self):
        # tproxy_mark << 1 = 0x400
        assert _geom().event_mark == 0x400

    def test_user_mask(self):
        # provider_offset(0) - tc_bits(8) = -8 ≤ 0 → user_mask = 0
        assert _geom().user_mask == 0


class TestWideTcMarks:
    """WIDE_TC_MARKS=Yes → 14-bit TC field, 16-bit total mask."""

    def test_tc_bits(self):
        assert _geom(WIDE_TC_MARKS="Yes").tc_bits == 14

    def test_mask_bits(self):
        assert _geom(WIDE_TC_MARKS="Yes").mask_bits == 16

    def test_tc_mask_is_16bit(self):
        # make_mask(MASK_BITS=16) = 0xffff
        assert _geom(WIDE_TC_MARKS="Yes").tc_mask == 0xFFFF

    def test_tc_max(self):
        # make_mask(TC_BITS=14) = 0x3fff
        assert _geom(WIDE_TC_MARKS="Yes").tc_max == 0x3FFF

    def test_provider_offset_low(self):
        # No HIGH_ROUTE_MARKS → still 0
        assert _geom(WIDE_TC_MARKS="Yes").provider_offset == 0

    def test_provider_mask(self):
        # make_mask(8) << 0 = 0xff
        assert _geom(WIDE_TC_MARKS="Yes").provider_mask == 0xFF


class TestHighRouteMarks:
    """HIGH_ROUTE_MARKS=Yes → provider marks shift to upper bits."""

    def test_provider_offset_no_wide(self):
        # HIGH + no WIDE → provider_offset default = 8; mask_bits=8;
        # clamping: 8 < 8 is False → stays 8
        assert _geom(HIGH_ROUTE_MARKS="Yes").provider_offset == 8

    def test_provider_mask_upper_byte(self):
        # make_mask(8) << 8 = 0xff00
        assert _geom(HIGH_ROUTE_MARKS="Yes").provider_mask == 0xFF00

    def test_zone_offset(self):
        # provider_offset=8 (non-zero branch) → zone_offset = 8 + 8 = 16
        assert _geom(HIGH_ROUTE_MARKS="Yes").zone_offset == 16

    def test_provider_offset_wide_and_high(self):
        # HIGH + WIDE → provider_offset default = 16
        m = _geom(HIGH_ROUTE_MARKS="Yes", WIDE_TC_MARKS="Yes")
        assert m.provider_offset == 16

    def test_provider_mask_wide_high(self):
        # make_mask(8) << 16 = 0xff0000
        m = _geom(HIGH_ROUTE_MARKS="Yes", WIDE_TC_MARKS="Yes")
        assert m.provider_mask == 0xFF0000

    def test_user_mask_wide_high(self):
        # provider_offset(16) - tc_bits(14) = 2 → user_mask = make_mask(2) << 14 = 0xc000
        m = _geom(HIGH_ROUTE_MARKS="Yes", WIDE_TC_MARKS="Yes")
        assert m.user_mask == 0xC000


class TestExplicitTcBitsOverrides:
    """Explicit TC_BITS setting overrides the WIDE_TC_MARKS-computed default."""

    def test_tc_bits_explicit_wins(self):
        # TC_BITS=12 wins even when WIDE_TC_MARKS=Yes (which would give 14)
        m = _geom(TC_BITS="12", WIDE_TC_MARKS="Yes")
        assert m.tc_bits == 12

    def test_mask_bits_still_from_wide(self):
        # MASK_BITS not set → WIDE_TC_MARKS=Yes gives 16
        m = _geom(TC_BITS="12", WIDE_TC_MARKS="Yes")
        assert m.mask_bits == 16

    def test_tc_bits_8_without_wide(self):
        m = _geom(TC_BITS="8")
        assert m.tc_bits == 8

    def test_tc_bits_4(self):
        m = _geom(TC_BITS="4")
        assert m.tc_bits == 4
        assert m.tc_max == 0x0F


class TestProviderOffsetClamping:
    """PROVIDER_OFFSET < MASK_BITS → clamped to MASK_BITS."""

    def test_clamping_applied(self):
        # PROVIDER_OFFSET=4 < MASK_BITS=8 → clamped to 8
        m = _geom(PROVIDER_OFFSET="4", MASK_BITS="8")
        assert m.provider_offset == 8

    def test_no_clamping_when_equal(self):
        m = _geom(PROVIDER_OFFSET="8", MASK_BITS="8")
        assert m.provider_offset == 8

    def test_no_clamping_when_greater(self):
        m = _geom(PROVIDER_OFFSET="16", MASK_BITS="8")
        assert m.provider_offset == 16


class TestZoneBits:
    """Non-zero ZONE_BITS fills the zone_mask field."""

    def test_zone_mask_with_bits(self):
        # ZONE_BITS=4, default zone_offset=8 → zone_mask = 0xf << 8 = 0xf00
        m = _geom(ZONE_BITS="4")
        assert m.zone_mask == 0xF00

    def test_exclusion_mask_with_zone_bits(self):
        # zone_offset=8, zone_bits=4 → exclusion_mask = 1 << 12 = 0x1000
        m = _geom(ZONE_BITS="4")
        assert m.exclusion_mask == 0x1000


class TestDefaultClassmethod:
    """MarkGeometry.default() returns upstream defaults."""

    def test_default_equals_empty_settings(self):
        assert MarkGeometry.default() == MarkGeometry.from_settings({})

    def test_frozen(self):
        m = MarkGeometry.default()
        with pytest.raises((AttributeError, TypeError)):
            m.tc_bits = 99  # type: ignore[misc]


class TestBuildIrIntegration:
    """build_ir() populates ir.mark_geometry from config.settings."""

    def test_mark_geometry_populated(self):
        from pathlib import Path

        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.parser import load_config

        minimal = Path(__file__).parent / "configs" / "minimal"
        config = load_config(minimal)
        ir = build_ir(config)

        assert hasattr(ir, "mark_geometry")
        assert isinstance(ir.mark_geometry, MarkGeometry)

    def test_mark_geometry_reflects_wide_tc(self):
        from pathlib import Path

        from shorewall_nft.compiler.ir import build_ir
        from shorewall_nft.config.parser import load_config

        minimal = Path(__file__).parent / "configs" / "minimal"
        config = load_config(minimal)
        config.settings["WIDE_TC_MARKS"] = "Yes"
        ir = build_ir(config)

        assert ir.mark_geometry.tc_bits == 14
        assert ir.mark_geometry.tc_mask == 0xFFFF


class TestEmitterRespectsGeometry:
    """Verify emitter output reflects mark geometry — or skip with explanation."""

    def test_emitter_respects_geometry(self):
        pytest.skip(
            "No emitter literal replacement was made: all mark-layout literals "
            "found in the codebase are either TC kernel handle constants "
            "(0xffff0000 in tc.py), IP-layer constants (slave_worker.py), or "
            "bitmask complement operations (0xffffffff in emitter.py). "
            "CT_ZONE_TAG_MASK at emitter.py:195 is a per-deployment ct-mark "
            "partition setting, distinct from the mark-geometry ZONE_MASK. "
            "The mark_geometry fields are populated and available on ir for "
            "future WP-B1/WP-C1 provider/TC emit work."
        )
