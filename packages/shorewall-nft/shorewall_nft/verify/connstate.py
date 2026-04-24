"""Backward-compatibility shim for connstate.

The implementation has moved to
``shorewall_nft_netkit.validators.connstate``.  This module re-exports all
public symbols so that existing callers remain unaffected.

Patch targets
-------------
The functions now live in ``shorewall_nft_netkit.validators.connstate``.
Tests that previously patched ``shorewall_nft.verify.connstate.ns`` or
``shorewall_nft.verify.connstate.NFCTSocket`` should update their patch
targets to:

- ``shorewall_nft_netkit.validators.connstate._ns_shell``
- ``shorewall_nft_netkit.validators.connstate.NFCTSocket``

Deprecated:
    Direct imports from ``shorewall_nft.verify.connstate`` work unchanged
    but callers are encouraged to migrate to
    ``shorewall_nft_netkit.validators`` for new code.
"""

from __future__ import annotations

from pyroute2 import NFCTSocket  # noqa: F401

# ---------------------------------------------------------------------------
# Back-compat aliases for patching support
#
# The original module exposed ``ns`` (from simulate.py) and ``NFCTSocket``
# (from pyroute2) as module-level names that tests patched.  Those patches
# now need to target the canonical location in netkit.  We keep these
# aliases here as documentation breadcrumbs — patching *this* module's
# ``ns`` / ``NFCTSocket`` will NOT affect the actual function calls
# (functions are bound to netkit's namespace).  Update patch targets to:
#   shorewall_nft_netkit.validators.connstate._ns_shell
#   shorewall_nft_netkit.validators.connstate.NFCTSocket
# ---------------------------------------------------------------------------
from shorewall_nft_netkit.netns_shell import run_shell_in_netns as ns  # noqa: F401

# Alias kept for any callers that imported DEFAULT_SRC from this module.
from shorewall_nft_netkit.validators.connstate import (  # noqa: F401
    _DEFAULT_SRC as DEFAULT_SRC,
)

# Re-export the full public surface from netkit.
from shorewall_nft_netkit.validators.connstate import (  # noqa: F401
    ConnStateResult,
    run_connstate_tests,
    run_small_conntrack_probe,
    test_drop_not_syn,
    test_established_tcp,
    test_invalid_flags,
    test_rfc1918_blocked,
    test_syn_to_allowed,
    test_syn_to_blocked,
    test_udp_conntrack,
)
