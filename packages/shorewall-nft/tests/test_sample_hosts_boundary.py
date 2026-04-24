"""Boundary-host inclusion in ``_sample_hosts`` (probe-class C).

Asserts that the first slots of the sampled list always carry the
four "interesting" boundary addresses for any CIDR — first host, last
host, network, broadcast — so probe-class C exercises CIDR-boundary
behaviour deterministically. Catches off-by-one regressions in the
compiler's address-set membership.
"""
from __future__ import annotations

import ipaddress
import random

from shorewall_nft.verify.simulate import _sample_hosts


def _addrs_in(samples, *expected):
    s = set(samples)
    return all(addr in s for addr in expected)


def test_v4_28_full_enumeration_first_and_last_host():
    """Full-enumeration path (n_hosts ≤ cap) returns hosts only via
    ``net.hosts()`` — first and last host present, network/broadcast
    are NOT (RFC behaviour for ``hosts()``)."""
    net = ipaddress.ip_network("217.14.160.32/28", strict=False)
    rng = random.Random(0)
    samples = _sample_hosts(net, 16, rng)
    assert "217.14.160.33" in samples   # first host
    assert "217.14.160.46" in samples   # last host
    # Boundary addresses are deliberately excluded by net.hosts().
    assert "217.14.160.32" not in samples
    assert "217.14.160.47" not in samples


def test_v4_24_first_slots_are_boundaries():
    net = ipaddress.ip_network("10.42.0.0/24", strict=False)
    rng = random.Random(0xDEADBEEF)
    samples = _sample_hosts(net, 16, rng)
    # /24 has 256 total > 16 sample cap → boundary path. First four
    # slots must be the boundaries in fixed order.
    assert samples[0] == "10.42.0.1"
    assert samples[1] == "10.42.0.254"
    assert samples[2] == "10.42.0.0"
    assert samples[3] == "10.42.0.255"
    # Remaining slots are random in (1, 254) and must not collide.
    for s in samples[4:]:
        ip = ipaddress.IPv4Address(s)
        assert int(ip) not in {0, 1, 254, 255}


def test_v6_64_first_slots_are_boundaries():
    net = ipaddress.ip_network("2a00:f88:0:5020::/64", strict=False)
    rng = random.Random(7)
    samples = _sample_hosts(net, 8, rng)
    # /64 has 2^64 total → boundary path. First four are boundaries.
    assert samples[0] == "2a00:f88:0:5020::1"
    assert samples[1] == "2a00:f88:0:5020:ffff:ffff:ffff:fffe"
    assert samples[2] == "2a00:f88:0:5020::"
    assert samples[3] == "2a00:f88:0:5020:ffff:ffff:ffff:ffff"


def test_boundary_addresses_unique_in_output():
    """Even when the random fill picks an offset already used by a
    boundary, the sampler must not return duplicates."""
    net = ipaddress.ip_network("192.0.2.0/30", strict=False)  # 4 addresses
    rng = random.Random(0)
    samples = _sample_hosts(net, 4, rng)
    assert len(samples) == len(set(samples))


def test_small_subnet_full_enumeration():
    """Fewer hosts than the cap → full enumeration path bypasses the
    boundary code; everything just gets returned."""
    net = ipaddress.ip_network("198.51.100.0/30", strict=False)
    rng = random.Random(0)
    samples = _sample_hosts(net, 64, rng)
    # /30 has hosts .1 and .2 only.
    assert "198.51.100.1" in samples
    assert "198.51.100.2" in samples
