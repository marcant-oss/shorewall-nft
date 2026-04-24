"""Shared pyroute2 / settings helpers used across runtime and compiler modules.

Two thin utilities extracted from the duplicated patterns in
``runtime/apply.py``, ``compiler/tc.py``, and ``compiler/proxyarp.py``:

* :func:`resolve_iface_idx` — interface-name → kernel-index lookup with a
  per-call cache so the same ``link_lookup`` netlink roundtrip is never
  repeated twice for the same name within one operation.

* :func:`settings_bool` — parse a yes/no/1/0/true/false shorewall.conf
  setting; case-insensitive with a caller-supplied default for missing keys.
"""

from __future__ import annotations

try:
    from pyroute2 import IPRoute as _IPRoute  # noqa: F401 — type reference only
except ImportError:
    _IPRoute = None  # type: ignore[assignment,misc]


def resolve_iface_idx(
    ipr: object,
    name: str,
    cache: dict[str, int],
) -> int | None:
    """Look up an interface's kernel index, with per-call cache.

    *ipr* must expose a ``link_lookup(ifname=name)`` method (i.e. a
    ``pyroute2.IPRoute`` instance or equivalent mock).  *cache* is a
    ``dict[str, int]`` that the caller owns and passes on every invocation
    for the duration of a single operation (e.g. one ``apply_ip_aliases``
    call).

    Returns the integer kernel interface index, or ``None`` if the
    interface is absent or the lookup raises a netlink error.  A failed
    lookup is **not** cached — a transient error won't poison subsequent
    calls for the same name.
    """
    if name in cache:
        return cache[name]
    try:
        matches = ipr.link_lookup(ifname=name)  # type: ignore[union-attr]
    except Exception:
        return None
    if not matches:
        return None
    idx = matches[0]
    cache[name] = idx
    return idx


def settings_bool(
    settings: dict[str, str],
    key: str,
    default: bool = False,
) -> bool:
    """Read a yes/no/1/0/true/false setting; case-insensitive.

    Returns *default* when *key* is absent from *settings*.
    Returns ``False`` for any unrecognised value (e.g. garbage input).
    """
    raw = settings.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in ("yes", "1", "true")
