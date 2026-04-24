"""Runtime apply helpers for IP alias lifecycle.

Adds and removes IP address aliases on network interfaces for DNAT
and SNAT targets, honouring ``ADD_IP_ALIASES``, ``ADD_SNAT_ALIASES``,
and ``RETAIN_ALIASES`` from ``shorewall.conf``.

Upstream reference (Perl): ``Nat.pm::add_addresses()`` and
``Misc.pm::compile_stop_firewall()``.  The Perl module emits shell
commands (``add_ip_aliases`` / ``del_ip_addr``); this module replaces
that shell-script path with a pyroute2 runtime-apply path so no
``ip`` binary is required.

Each tuple in the address list is ``(address, iface_name)`` where
``address`` is the bare IPv4 address (no prefix-length) and
``iface_name`` is the interface on which the alias should appear.

Both functions are idempotent:

* ``apply_ip_aliases`` skips any address already assigned to the
  interface (checking via ``IPRoute.get_addr``).
* ``remove_ip_aliases`` skips any address not currently assigned
  (swallows the ``ENOENT`` NetlinkError from the kernel).

Pattern follows ``compiler/proxyarp.py::apply_proxyarp`` for
consistent pyroute2 usage across the codebase.
"""

from __future__ import annotations

try:
    from pyroute2 import IPRoute
    from pyroute2.netlink.exceptions import NetlinkError
    _PYROUTE2_AVAILABLE = True
except ImportError:  # pyroute2 may be absent in minimal installs
    _PYROUTE2_AVAILABLE = False
    IPRoute = None  # type: ignore[assignment,misc]
    NetlinkError = None  # type: ignore[assignment,misc]


def apply_ip_aliases(
    addresses_to_add: list[tuple[str, str]],
    netns: str | None = None,
) -> tuple[int, int, list[str]]:
    """Add IP address aliases via pyroute2.

    For each ``(address, iface_name)`` in *addresses_to_add* the helper:

    1. Resolves the interface index via ``IPRoute.link_lookup``.
    2. Checks whether the address is already present with
       ``IPRoute.get_addr``.  If already present the entry is skipped
       (idempotent).
    3. Adds the address as ``/32`` on the interface via
       ``IPRoute.addr("add", …)``.

    Returns ``(applied, skipped, errors)``:

    * ``applied`` — number of aliases actually added.
    * ``skipped`` — number of aliases already present (idempotent skip).
    * ``errors`` — human-readable failure descriptions for entries that
      could not be added (e.g. interface missing).
    """
    if not _PYROUTE2_AVAILABLE:
        return 0, 0, ["pyroute2 not installed"]

    if not addresses_to_add:
        return 0, 0, []

    applied = 0
    skipped = 0
    errors: list[str] = []

    try:
        ipr = IPRoute(netns=netns) if netns else IPRoute()
    except Exception as ex:
        return 0, len(addresses_to_add), [f"IPRoute init failed: {ex}"]

    try:
        iface_idx: dict[str, int] = {}

        def _idx(name: str) -> int | None:
            if name in iface_idx:
                return iface_idx[name]
            try:
                links = ipr.link_lookup(ifname=name)
            except NetlinkError:
                return None
            if not links:
                return None
            iface_idx[name] = links[0]
            return links[0]

        for addr, iface in addresses_to_add:
            idx = _idx(iface)
            if idx is None:
                errors.append(
                    f"{addr}: interface {iface!r} not found, skipped")
                skipped += 1
                continue

            # Check whether the address is already assigned.
            try:
                existing = ipr.get_addr(index=idx, address=addr)
            except NetlinkError:
                existing = []

            if existing:
                skipped += 1
                continue

            # Add the alias as /32.
            try:
                ipr.addr("add", index=idx, address=addr, prefixlen=32)
                applied += 1
            except NetlinkError as ex:
                # EEXIST (17) means already present — treat as skipped.
                if getattr(ex, "code", None) == 17:
                    skipped += 1
                else:
                    errors.append(
                        f"{addr} on {iface}: addr add failed: {ex}")
    finally:
        try:
            ipr.close()
        except Exception:
            pass

    return applied, skipped, errors


def remove_ip_aliases(
    addresses_to_remove: list[tuple[str, str]],
    netns: str | None = None,
) -> tuple[int, int, list[str]]:
    """Remove IP address aliases via pyroute2.

    For each ``(address, iface_name)`` in *addresses_to_remove* the
    helper:

    1. Resolves the interface index via ``IPRoute.link_lookup``.
    2. Removes the address via ``IPRoute.addr("del", …)``.  If the
       address is not present (``ENOENT`` / ``EADDRNOTAVAIL``) the
       kernel returns an error that is swallowed — the operation is
       idempotent.

    Returns ``(removed, skipped, errors)`` following the same
    convention as ``apply_ip_aliases``.
    """
    if not _PYROUTE2_AVAILABLE:
        return 0, 0, ["pyroute2 not installed"]

    if not addresses_to_remove:
        return 0, 0, []

    removed = 0
    skipped = 0
    errors: list[str] = []

    try:
        ipr = IPRoute(netns=netns) if netns else IPRoute()
    except Exception as ex:
        return 0, len(addresses_to_remove), [f"IPRoute init failed: {ex}"]

    try:
        iface_idx: dict[str, int] = {}

        def _idx(name: str) -> int | None:
            if name in iface_idx:
                return iface_idx[name]
            try:
                links = ipr.link_lookup(ifname=name)
            except NetlinkError:
                return None
            if not links:
                return None
            iface_idx[name] = links[0]
            return links[0]

        for addr, iface in addresses_to_remove:
            idx = _idx(iface)
            if idx is None:
                # Interface gone — address definitely absent.
                skipped += 1
                continue

            try:
                ipr.addr("del", index=idx, address=addr, prefixlen=32)
                removed += 1
            except NetlinkError as ex:
                # ENOENT (2) / EADDRNOTAVAIL (99) — already absent.
                if getattr(ex, "code", None) in (2, 99):
                    skipped += 1
                else:
                    errors.append(
                        f"{addr} on {iface}: addr del failed: {ex}")
    finally:
        try:
            ipr.close()
        except Exception:
            pass

    return removed, skipped, errors
