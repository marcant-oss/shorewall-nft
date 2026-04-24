"""Backward-compatibility shim for tc_validate.

The implementation has moved to
``shorewall_nft_netkit.validators.tc_validate``.  This module re-exports all
public symbols so that existing callers remain unaffected.

Deprecated:
    Direct imports from ``shorewall_nft.verify.tc_validate`` work unchanged
    but callers are encouraged to migrate to
    ``shorewall_nft_netkit.validators`` for new code.
"""

from __future__ import annotations

# Re-export the full public surface from netkit.
# The __all__ list is intentionally omitted so that ``from … import *``
# continues to work for legacy callers, and so that the module appears
# transparent in ``help()``.
from shorewall_nft_netkit.validators.tc_validate import (  # noqa: F401
    ValidationResult,
    run_all_validations,
    validate_nft_loaded,
    validate_routing,
    validate_sysctl,
    validate_tc,
)
