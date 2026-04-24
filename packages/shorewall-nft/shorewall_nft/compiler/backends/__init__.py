"""Backend-pluggable emitter protocol (P8 first step).

This module defines the ``BackendEmitter`` protocol and a lightweight
registry so that the compiler can target multiple kernel backends without
touching the IR or the config layer.

Current status (2026-04-24):
    Only the ``nft`` backend is implemented.  ``select_backend`` is NOT
    wired into ``apply_cmds.py`` yet — that is the next P8 work-package.
    The intended wiring point is ``runtime/cli/apply_cmds.py``:
    ``_compile_pipeline()`` should call ``select_backend(settings)`` and
    pass the result to whatever replaces the direct ``emit_nft()`` call.

Future backends (VPP, eBPF/XDP) register themselves via
``register_backend()`` — either from their own package's ``__init__`` or
via an importlib.metadata entry-point under the group
``shorewall_nft.backends`` (not yet implemented).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from shorewall_nft.compiler.ir import FirewallIR


@runtime_checkable
class BackendEmitter(Protocol):
    """Pluggable ruleset emitter for a specific kernel backend.

    Implementations take a backend-agnostic FirewallIR and return
    the backend's native configuration text (nft -f script, VPP
    config, eBPF map bytecode, etc.).
    """

    name: str  # short backend identifier: "nft", "vpp", "bpf"

    def emit(self, ir: "FirewallIR") -> str: ...


_BACKENDS: dict[str, BackendEmitter] = {}


def register_backend(backend: BackendEmitter) -> None:
    """Add *backend* to the registry, keyed by ``backend.name``."""
    _BACKENDS[backend.name] = backend


def get_backend(name: str) -> BackendEmitter:
    """Return the registered backend for *name*.

    Raises ``KeyError`` if no backend with that name has been registered.
    """
    return _BACKENDS[name]


def select_backend(settings: dict[str, str]) -> BackendEmitter:
    """Read the ``BACKEND`` setting (default ``"nft"``) and return the
    registered emitter.

    Raises ``ValueError`` on an unknown backend, listing the accepted
    values.
    """
    name = settings.get("BACKEND", "nft")
    if name not in _BACKENDS:
        accepted = ", ".join(sorted(_BACKENDS))
        raise ValueError(
            f"Unknown backend {name!r}. Accepted values: {accepted}"
        )
    return _BACKENDS[name]


# Register the built-in nft backend on first import.
# The import is deferred inside nft_backend.py (via a lazy emit_nft import)
# to avoid a circular-import cycle between this module and nft/emitter.py.
from shorewall_nft.compiler.backends import nft_backend as _nft_backend  # noqa: E402, F401
