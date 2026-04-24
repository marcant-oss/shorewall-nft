"""Runtime apply helpers: IP alias lifecycle + iproute2 policy routing.

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

``apply_iproute2_rules`` / ``remove_iproute2_rules`` replace the
shell-script path emitted by
``compiler/providers.py::emit_iproute2_setup`` with direct pyroute2
netlink calls.  This allows ``start``/``restart`` to configure policy
routing without forking any subprocess.  The generator
(``emit_iproute2_setup`` / ``generate-iproute2-rules``) is kept for
operators who prefer a portable shell artefact.

Upstream reference (Perl): ``Providers.pm`` — per-provider fwmark
rules, routing-table setup, balance/fallback multipath routes.
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

from shorewall_nft.runtime.pyroute2_helpers import resolve_iface_idx, settings_bool


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

        for addr, iface in addresses_to_add:
            idx = resolve_iface_idx(ipr, iface, iface_idx)
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

        for addr, iface in addresses_to_remove:
            idx = resolve_iface_idx(ipr, iface, iface_idx)
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


# ---------------------------------------------------------------------------
# Policy-routing apply/remove via pyroute2 (migration #3 from WP-B1)
# ---------------------------------------------------------------------------

_RT_TABLES_PATH = "/etc/iproute2/rt_tables"

# Default PROVIDER_MASK used by shorewall for fwmark → table rules.
# Eight low bits; matches emit_iproute2_setup's mask_hex = hex(0xFF).
_PROVIDER_FWMARK_MASK = 0xFF

# Priority base for per-provider fwmark rules: 10000 + (number - 1).
_FWMARK_PREF_BASE = 10000

# Priority for per-address source routing rules (same as upstream).
_SRC_PREF = 20000


def _ensure_rt_table_entry(number: int, name: str) -> None:
    """Write ``<number> <name>`` to /etc/iproute2/rt_tables if absent.

    Idempotent — re-running is safe.  The write is a direct file I/O
    operation (no subprocess).  Silently skips if the file is not
    writable (e.g. read-only rootfs) so non-root unit tests stay clean.
    """
    try:
        with open(_RT_TABLES_PATH) as f:
            content = f.read()
    except OSError:
        content = ""

    line = f"{number} {name}\n"
    # Check for an exact line match (same format as the shell generator).
    if f"{number} {name}" in content.splitlines():
        return  # already present

    try:
        with open(_RT_TABLES_PATH, "a") as f:
            f.write(line)
    except OSError:
        pass  # non-fatal: kernel already knows the table number


def apply_iproute2_rules(
    providers: list,
    routes: list,
    rtrules: list,
    settings: dict,
    netns: str | None = None,
) -> tuple[int, int, list[str]]:
    """Apply provider policy routing setup via pyroute2.

    Performs the same kernel-state changes as the shell script emitted by
    ``compiler/providers.py::emit_iproute2_setup``, but using
    ``pyroute2.IPRoute`` directly — no subprocess is forked.

    Steps performed (mirroring the generator's sections):

    1. Register routing table names in /etc/iproute2/rt_tables (file I/O).
    2. Install per-provider ``fwmark → table`` ip rules.
    3. Install per-provider default routes in the provider routing table
       (gateway-based or dev-only).  ``DUPLICATE`` tables are *not*
       reproduced via netlink here because iterating an arbitrary routing
       table with ``route("dump", …)`` then re-inserting rows into a
       different table is complex, fragile, and carries risk of
       duplication across reloads.  Sites that rely on ``DUPLICATE``
       should pipe the generated shell script instead.
    4. Add balance/fallback multipath default routes in main (or the
       ``balance`` table when ``USE_DEFAULT_RT=Yes``).
    5. Add extra static routes from the routes file.
    6. Add extra ip rules from the rtrules file.
    7. If ``loose=False``, install per-address source routing rules for
       each address currently assigned to the provider interface.

    ``persistent`` provider/route/rule entries are applied on every call
    (persistence affects the *remove* path, not apply).

    Returns ``(applied, skipped, errors)`` following the same convention
    as ``apply_ip_aliases``.
    """
    if not _PYROUTE2_AVAILABLE:
        return 0, 0, ["pyroute2 not installed"]

    if not providers and not routes and not rtrules:
        return 0, 0, []

    use_default_rt = settings_bool(settings, "USE_DEFAULT_RT", False)
    balance_providers = settings_bool(settings, "BALANCE_PROVIDERS", False)
    optimize_use_first = settings_bool(settings, "OPTIMIZE_USE_FIRST", False)

    # Apply BALANCE_PROVIDERS: providers with no explicit balance/fallback
    # get balance=1.
    from shorewall_nft.compiler.providers import _build_provider_index
    if balance_providers:
        for p in providers:
            if not p.balance and not p.fallback:
                p.balance = 1

    active = [p for p in providers if p.mark]
    skip_fwmark = optimize_use_first and len(active) <= 1

    applied = 0
    skipped = 0
    errors: list[str] = []

    # Step 1: register table names (file I/O, no netlink).
    for prov in providers:
        _ensure_rt_table_entry(prov.number, prov.name)

    # Open a single IPRoute socket for all netlink calls.
    try:
        ipr = IPRoute(netns=netns) if netns else IPRoute()
    except Exception as ex:
        return 0, len(providers) + len(routes) + len(rtrules), [
            f"IPRoute init failed: {ex}"]

    try:
        # Cache interface name → index.
        iface_idx: dict[str, int] = {}

        # Step 2: per-provider fwmark → table ip rules.
        if not skip_fwmark:
            for prov in providers:
                if not prov.mark:
                    continue
                pref = _FWMARK_PREF_BASE + prov.number - 1
                try:
                    ipr.rule(
                        "add",
                        fwmark=prov.mark,
                        fwmask=_PROVIDER_FWMARK_MASK,
                        table=prov.number,
                        priority=pref,
                    )
                    applied += 1
                except NetlinkError as ex:
                    # EEXIST (17) — already installed; treat as skipped.
                    if getattr(ex, "code", None) == 17:
                        skipped += 1
                    else:
                        errors.append(
                            f"provider {prov.name}: fwmark rule failed: {ex}")

        # Step 3: per-provider routing table setup (default route + source rules).
        for prov in providers:
            iface_id = resolve_iface_idx(ipr, prov.interface, iface_idx) if prov.interface else None
            if iface_id is None and prov.interface:
                errors.append(
                    f"provider {prov.name}: interface {prov.interface!r} "
                    f"not found, skipping route setup")
                skipped += 1
                continue

            # Default route in the provider table.
            route_kwargs: dict = {
                "table": prov.number,
                "dst": "0.0.0.0/0",
            }
            if prov.gateway:
                route_kwargs["gateway"] = prov.gateway
            if iface_id is not None:
                route_kwargs["oif"] = iface_id

            try:
                ipr.route("replace", **route_kwargs)
                applied += 1
            except NetlinkError as ex:
                errors.append(
                    f"provider {prov.name}: default route failed: {ex}")

            # Step 3b: source routing rules (loose=False).
            if not prov.loose and iface_id is not None:
                try:
                    addrs = ipr.get_addr(index=iface_id, family=2)  # AF_INET
                except NetlinkError:
                    addrs = []
                for addr_msg in addrs:
                    try:
                        # get_addr returns NLMsg objects; .get() extracts attrs.
                        addr_val = addr_msg.get_attr("IFA_ADDRESS")
                        if not addr_val:
                            continue
                        ipr.rule(
                            "add",
                            src=addr_val,
                            src_len=32,
                            table=prov.number,
                            priority=_SRC_PREF,
                        )
                        applied += 1
                    except NetlinkError as ex:
                        if getattr(ex, "code", None) == 17:
                            skipped += 1
                        else:
                            errors.append(
                                f"provider {prov.name}: src rule for "
                                f"{addr_val!r}: {ex}")

        # Step 4: balance / fallback multipath default route.
        balance_list = [p for p in providers if p.balance]
        fallback_list = [p for p in providers if p.fallback]
        target_table = 0 if not use_default_rt else 210  # 210 = conventional balance table

        if balance_list:
            # Build multipath nexthops list.
            nexthops = []
            for p in balance_list:
                nh: dict = {"hops": p.balance - 1}  # hops = weight-1 in iproute2
                if p.gateway:
                    nh["gateway"] = p.gateway
                p_idx = resolve_iface_idx(ipr, p.interface, iface_idx) if p.interface else None
                if p_idx is not None:
                    nh["oif"] = p_idx
                nexthops.append(nh)
            try:
                ipr.route(
                    "replace",
                    dst="0.0.0.0/0",
                    table=target_table,
                    multipath=nexthops,
                )
                applied += 1
            except NetlinkError as ex:
                errors.append(f"balance multipath route failed: {ex}")

        elif fallback_list:
            for p in fallback_list:
                fb_kwargs: dict = {
                    "dst": "0.0.0.0/0",
                    "table": target_table,
                    "priority": p.number,
                }
                if p.gateway:
                    fb_kwargs["gateway"] = p.gateway
                p_idx = resolve_iface_idx(ipr, p.interface, iface_idx) if p.interface else None
                if p_idx is not None:
                    fb_kwargs["oif"] = p_idx
                try:
                    ipr.route("replace", **fb_kwargs)
                    applied += 1
                except NetlinkError as ex:
                    errors.append(
                        f"provider {p.name}: fallback route failed: {ex}")

        # Step 5: extra static routes from the routes file.
        provider_idx = _build_provider_index(providers)
        for route in routes:
            prov = provider_idx.get(route.provider)
            table_id = prov.number if prov else 0
            route_kwargs = {"dst": route.dest, "table": table_id}
            if route.gateway:
                route_kwargs["gateway"] = route.gateway
            dev_name = route.device or (prov.interface if prov else None)
            if dev_name:
                dev_id = resolve_iface_idx(ipr, dev_name, iface_idx)
                if dev_id is not None:
                    route_kwargs["oif"] = dev_id
            try:
                ipr.route("replace", **route_kwargs)
                applied += 1
            except NetlinkError as ex:
                errors.append(
                    f"route {route.dest} via {route.provider}: {ex}")

        # Step 6: extra ip rules from the rtrules file.
        for rule in rtrules:
            prov = provider_idx.get(rule.provider)
            table_id = prov.number if prov else 0
            rule_kwargs: dict = {"table": table_id}

            if rule.source:
                if ":" in rule.source:
                    # iface:addr format
                    iface_part, addr_part = rule.source.split(":", 1)
                    rule_kwargs["iifname"] = iface_part
                    rule_kwargs["src"] = addr_part
                    rule_kwargs["src_len"] = 32
                elif "." in rule.source or "/" in rule.source:
                    rule_kwargs["src"] = rule.source.split("/")[0]
                    bits = int(rule.source.split("/")[1]) if "/" in rule.source else 32
                    rule_kwargs["src_len"] = bits
                else:
                    rule_kwargs["iifname"] = rule.source
            else:
                pass  # "from all" — no src kwarg needed

            if rule.dest:
                dest_addr = rule.dest.split("/")[0]
                dest_bits = int(rule.dest.split("/")[1]) if "/" in rule.dest else 32
                rule_kwargs["dst"] = dest_addr
                rule_kwargs["dst_len"] = dest_bits

            if rule.mark:
                mark_val, _, mask_val = rule.mark.partition("/")
                rule_kwargs["fwmark"] = int(mark_val, 0)
                if mask_val:
                    rule_kwargs["fwmask"] = int(mask_val, 0)

            if rule.priority:
                rule_kwargs["priority"] = rule.priority

            try:
                ipr.rule("add", **rule_kwargs)
                applied += 1
            except NetlinkError as ex:
                if getattr(ex, "code", None) == 17:
                    skipped += 1
                else:
                    errors.append(
                        f"rtrule provider={rule.provider}: {ex}")

    finally:
        try:
            ipr.close()
        except Exception:
            pass

    return applied, skipped, errors


def remove_iproute2_rules(
    providers: list,
    routes: list,
    rtrules: list,
    settings: dict,
    netns: str | None = None,
) -> tuple[int, int, list[str]]:
    """Remove provider policy routing state installed by apply_iproute2_rules.

    Called by the ``stop``/``clear`` runtime path.

    Entries with ``persistent=True`` (Provider, Route, or RoutingRule) are
    skipped — they survive a shorewall stop, matching upstream Shorewall
    semantics.

    ``RESTORE_DEFAULT_ROUTE=No`` (default Yes) suppresses the removal of
    the balance/fallback default route from main/balance table.

    All netlink deletions are idempotent: ``ENOENT`` / ``EEXIST``-like
    errors (2, 17, 101) are swallowed and counted as skipped.

    Returns ``(removed, skipped, errors)``.
    """
    if not _PYROUTE2_AVAILABLE:
        return 0, 0, ["pyroute2 not installed"]

    if not providers and not routes and not rtrules:
        return 0, 0, []

    restore_default_route = settings_bool(settings, "RESTORE_DEFAULT_ROUTE", True)
    use_default_rt = settings_bool(settings, "USE_DEFAULT_RT", False)
    optimize_use_first = settings_bool(settings, "OPTIMIZE_USE_FIRST", False)

    from shorewall_nft.compiler.providers import _build_provider_index
    active = [p for p in providers if p.mark]
    skip_fwmark = optimize_use_first and len(active) <= 1

    removed = 0
    skipped = 0
    errors: list[str] = []

    # ENOENT-class codes: treat these as "already absent" on del.
    _ABSENT_CODES = frozenset({2, 6, 101})  # ENOENT, ENXIO, ENOBUFS(ENONET)

    try:
        ipr = IPRoute(netns=netns) if netns else IPRoute()
    except Exception as ex:
        return 0, len(providers) + len(routes) + len(rtrules), [
            f"IPRoute init failed: {ex}"]

    try:
        iface_idx: dict[str, int] = {}

        def _del_rule(**kwargs: object) -> None:
            nonlocal removed, skipped
            try:
                ipr.rule("del", **kwargs)
                removed += 1
            except NetlinkError as ex:
                if getattr(ex, "code", None) in _ABSENT_CODES:
                    skipped += 1
                else:
                    errors.append(f"rule del {kwargs}: {ex}")

        def _del_route(**kwargs: object) -> None:
            nonlocal removed, skipped
            try:
                ipr.route("del", **kwargs)
                removed += 1
            except NetlinkError as ex:
                if getattr(ex, "code", None) in _ABSENT_CODES:
                    skipped += 1
                else:
                    errors.append(f"route del {kwargs}: {ex}")

        # Remove per-provider fwmark rules.
        if not skip_fwmark:
            for prov in providers:
                if not prov.mark:
                    continue
                pref = _FWMARK_PREF_BASE + prov.number - 1
                _del_rule(
                    fwmark=prov.mark,
                    fwmask=_PROVIDER_FWMARK_MASK,
                    table=prov.number,
                    priority=pref,
                )

        # Remove per-provider default routes and source-routing rules.
        for prov in providers:
            if prov.persistent:
                skipped += 1
                continue

            # Default route in the provider table.
            _del_route(dst="0.0.0.0/0", table=prov.number)

            # Source routing rules for this provider's interface addresses.
            if not prov.loose:
                iface_id = resolve_iface_idx(ipr, prov.interface, iface_idx) if prov.interface else None
                if iface_id is not None:
                    try:
                        addrs = ipr.get_addr(index=iface_id, family=2)
                    except NetlinkError:
                        addrs = []
                    for addr_msg in addrs:
                        try:
                            addr_val = addr_msg.get_attr("IFA_ADDRESS")
                            if not addr_val:
                                continue
                            _del_rule(
                                src=addr_val,
                                src_len=32,
                                table=prov.number,
                                priority=_SRC_PREF,
                            )
                        except Exception:  # noqa: BLE001 — per-address best-effort
                            pass

        # Remove balance / fallback default route (gated on RESTORE_DEFAULT_ROUTE).
        if restore_default_route:
            target_table = 0 if not use_default_rt else 210
            balance_list = [p for p in providers if p.balance]
            fallback_list = [p for p in providers if p.fallback]
            if balance_list or fallback_list:
                _del_route(dst="0.0.0.0/0", table=target_table)

        # Remove extra static routes.
        provider_idx = _build_provider_index(providers)
        for route in routes:
            if route.persistent:
                skipped += 1
                continue
            prov = provider_idx.get(route.provider)
            table_id = prov.number if prov else 0
            _del_route(dst=route.dest, table=table_id)

        # Remove extra ip rules.
        for rule in rtrules:
            if rule.persistent:
                skipped += 1
                continue
            prov = provider_idx.get(rule.provider)
            table_id = prov.number if prov else 0
            rule_kwargs: dict = {"table": table_id}
            if rule.source and "." in rule.source:
                rule_kwargs["src"] = rule.source.split("/")[0]
            if rule.dest:
                rule_kwargs["dst"] = rule.dest.split("/")[0]
            if rule.priority:
                rule_kwargs["priority"] = rule.priority
            _del_rule(**rule_kwargs)

    finally:
        try:
            ipr.close()
        except Exception:
            pass

    return removed, skipped, errors
