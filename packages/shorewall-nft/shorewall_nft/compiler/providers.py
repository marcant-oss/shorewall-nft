"""Provider / Multi-ISP policy routing support.

Handles providers, routes, and rtrules config files.
Generates nft mark rules for policy routing and ip rule / ip route
shell commands for the iproute2 routing setup.

Two output channels (as documented in WP-B1):
  Channel 1 — nft mangle-prerouting mark rules → emit_provider_marks()
  Channel 2 — ip rule / ip route shell script  → emit_iproute2_setup()
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shorewall_nft.config.parser import ConfigLine

# ── Provider OPTIONS recognised by shorewall-nft ──────────────────────

_VALID_OPTIONS: frozenset[str] = frozenset({
    "track", "notrack",
    "balance", "primary",
    "loose",
    "optional",
    "fallback",
    "persistent",
    "tproxy",
    "local",
})


@dataclass
class Provider:
    """A routing provider (ISP)."""
    name: str
    number: int
    mark: int           # raw numeric mark value (0 = no mark)
    interface: str
    duplicate: str | None = None   # routing table to copy
    gateway: str | None = None
    copy: list[str] = field(default_factory=list)
    # Parsed OPTIONS
    track: bool = False
    balance: int = 0       # 0 = not balanced; >0 = weight
    fallback: int = 0      # 0 = not fallback; -1 = bare fallback; >0 = weighted fallback
    loose: bool = False
    optional: bool = False
    persistent: bool = False
    tproxy: bool = False
    # Derived / assigned
    table: str = ""         # routing table id (number or name)


@dataclass
class Route:
    """A static route for a provider."""
    provider: str
    dest: str
    gateway: str | None = None
    device: str | None = None
    persistent: bool = False


@dataclass
class RoutingRule:
    """An ip rule for policy routing."""
    source: str | None = None
    dest: str | None = None
    provider: str = ""
    priority: int = 0
    mark: str | None = None    # fwmark value, e.g. "0x100/0xff"
    persistent: bool = False


# ── Parsers ────────────────────────────────────────────────────────────


def parse_providers(lines: list[ConfigLine]) -> list[Provider]:
    """Parse providers config file.

    Format: NAME NUMBER MARK DUPLICATE INTERFACE GATEWAY OPTIONS COPY

    Upstream column indices (Providers.pm process_a_provider):
      0=table(name)  1=number  2=mark  3=duplicate  4=interface
      5=gateway  6=options  7=copy
    """
    providers: list[Provider] = []
    for line in lines:
        cols = line.columns
        if len(cols) < 5:
            continue
        name = cols[0]
        if name == "-":
            continue

        try:
            number = int(cols[1])
        except ValueError:
            continue

        raw_mark = cols[2] if len(cols) > 2 else "-"
        try:
            mark = int(raw_mark, 0) if raw_mark != "-" else 0
        except ValueError:
            mark = 0

        duplicate_col = cols[3] if len(cols) > 3 else "-"
        duplicate = duplicate_col if duplicate_col != "-" else None

        interface = cols[4] if len(cols) > 4 else ""
        if ":" in interface:
            interface = interface.split(":", 1)[0]

        gateway_col = cols[5] if len(cols) > 5 else "-"
        gateway = gateway_col if gateway_col not in ("-", "") else None

        options_col = cols[6] if len(cols) > 6 else "-"
        copy_col = cols[7] if len(cols) > 7 else "-"

        # Parse OPTIONS
        track = False
        balance = 0
        fallback = 0
        loose = False
        optional = False
        persistent = False
        tproxy = False

        if options_col != "-":
            for opt in options_col.split(","):
                opt = opt.strip()
                if opt == "track":
                    track = True
                elif opt == "notrack":
                    track = False
                elif opt in ("balance", "primary"):
                    balance = 1
                elif opt.startswith("balance="):
                    try:
                        balance = int(opt.split("=", 1)[1])
                    except ValueError:
                        balance = 1
                elif opt == "loose":
                    loose = True
                elif opt == "optional":
                    optional = True
                elif opt == "fallback":
                    fallback = -1
                elif opt.startswith("fallback="):
                    try:
                        fallback = int(opt.split("=", 1)[1])
                    except ValueError:
                        fallback = -1
                elif opt == "persistent":
                    persistent = True
                elif opt in ("tproxy", "local"):
                    tproxy = True
                    track = False
                # src=, mtu=, load=, autosrc, noautosrc, hostroute, nohostroute
                # are recognised upstream but produce only runtime-script output;
                # we parse and silently ignore the ones not yet emitted.

        # Parse COPY column
        copy: list[str] = []
        if copy_col not in ("-", ""):
            if copy_col == "none":
                copy = [interface]
            else:
                copy = [c.strip() for c in copy_col.split(",") if c.strip()]

        providers.append(Provider(
            name=name,
            number=number,
            mark=mark,
            interface=interface,
            duplicate=duplicate,
            gateway=gateway,
            copy=copy,
            track=track,
            balance=balance,
            fallback=fallback,
            loose=loose,
            optional=optional,
            persistent=persistent,
            tproxy=tproxy,
            table=str(number),
        ))
    return providers


def parse_routes(lines: list[ConfigLine]) -> list[Route]:
    """Parse routes config file.

    Format: PROVIDER DEST GATEWAY DEVICE OPTIONS

    Upstream column indices (Providers.pm add_a_route):
      0=provider  1=dest  2=gateway  3=device  4=options
    """
    routes: list[Route] = []
    for line in lines:
        cols = line.columns
        if len(cols) < 2:
            continue
        provider = cols[0]
        if provider == "-":
            continue
        dest = cols[1]
        if dest == "-":
            continue

        gateway_col = cols[2] if len(cols) > 2 else "-"
        gateway = gateway_col if gateway_col not in ("-", "") else None

        device_col = cols[3] if len(cols) > 3 else "-"
        device = device_col if device_col not in ("-", "") else None

        options_col = cols[4] if len(cols) > 4 else "-"
        persistent = False
        if options_col != "-":
            for opt in options_col.split(","):
                if opt.strip() == "persistent":
                    persistent = True

        routes.append(Route(
            provider=provider,
            dest=dest,
            gateway=gateway,
            device=device,
            persistent=persistent,
        ))
    return routes


def parse_rtrules(lines: list[ConfigLine]) -> list[RoutingRule]:
    """Parse rtrules config file.

    Format: SOURCE DEST PROVIDER PRIORITY MARK

    Upstream column indices (Providers.pm add_an_rtrule):
      0=source  1=dest  2=provider  3=priority  4=mark
    """
    rules: list[RoutingRule] = []
    for line in lines:
        cols = line.columns
        if len(cols) < 3:
            continue
        source_col = cols[0]
        dest_col = cols[1]
        provider = cols[2]
        if provider == "-":
            continue

        source = source_col if source_col != "-" else None
        dest = dest_col if dest_col != "-" else None

        # At least one of source/dest must be specified
        if source is None and dest is None:
            continue

        priority_col = cols[3] if len(cols) > 3 else "-"
        persistent = False
        if priority_col.endswith("!"):
            persistent = True
            priority_col = priority_col[:-1]
        try:
            priority = int(priority_col) if priority_col != "-" else 0
        except ValueError:
            priority = 0

        mark_col = cols[4] if len(cols) > 4 else "-"
        mark = mark_col if mark_col != "-" else None

        rules.append(RoutingRule(
            source=source,
            dest=dest,
            provider=provider,
            priority=priority,
            mark=mark,
            persistent=persistent,
        ))
    return rules


# ── Channel 1: nft mangle-prerouting mark rules ────────────────────────


def emit_provider_marks(ir: object, providers: list[Provider]) -> None:
    """Emit mangle-prerouting mark rules for providers that carry a mark.

    Uses ir.mark_geometry.provider_mask for the mask so the mark write
    is constrained to the configured provider field.

    This populates ir.chains["mangle-prerouting"] — creates the chain
    if it doesn't already exist.
    """
    from shorewall_nft.compiler.ir._data import Chain, ChainType, Hook, Match, Rule, Verdict
    from shorewall_nft.compiler.verdicts import MarkVerdict

    if "mangle-prerouting" not in ir.chains:
        ir.add_chain(Chain(
            name="mangle-prerouting",
            chain_type=ChainType.ROUTE,
            hook=Hook.PREROUTING,
            priority=-150,
        ))

    provider_mask = ir.mark_geometry.provider_mask

    for prov in providers:
        if not prov.mark:
            continue
        mangle = ir.chains["mangle-prerouting"]
        # Mask the mark write to the provider field only
        mark_value = prov.mark & provider_mask
        if not mark_value:
            continue
        mangle.rules.append(Rule(
            matches=[Match(field="iifname", value=prov.interface)],
            verdict=Verdict.ACCEPT,
            verdict_args=MarkVerdict(value=mark_value),
            comment=f"provider:{prov.name}",
        ))


# ── Channel 2: shell script (iproute2 setup) ──────────────────────────


def _build_provider_index(providers: list[Provider]) -> dict[str, Provider]:
    """Build name→Provider and number→Provider lookups."""
    idx: dict[str, Provider] = {}
    for p in providers:
        idx[p.name] = p
        idx[str(p.number)] = p
    return idx


def emit_iproute2_setup(
    providers: list[Provider],
    routes: list[Route],
    rtrules: list[RoutingRule],
    settings: dict[str, str],
) -> str:
    """Emit a shell script that configures iproute2 routing for multi-ISP.

    The generated script:
    1. Adds provider routing-table names to /etc/iproute2/rt_tables.
    2. Sets up per-provider fwmark → table routing rules.
    3. Copies/builds per-provider routing tables (if DUPLICATE specified).
    4. Adds per-provider default routes (gateway-based or dev-only).
    5. Emits balance/fallback nexthop multipath routes (USE_DEFAULT_RT or main).
    6. Appends extra static routes from the routes file.
    7. Appends extra ip-rule entries from the rtrules file.

    WP-B3 settings honoured:
    - USE_DEFAULT_RT (default No): if Yes, emit default routes into a
      dedicated 'balance' table instead of 'main'.
    - BALANCE_PROVIDERS (default No): if Yes, all providers default to
      balance=1 unless they explicitly set it.
    - RESTORE_DEFAULT_ROUTE (default Yes): controls whether the undo
      script restores the kernel default route on provider stop.
    - OPTIMIZE_USE_FIRST (default No): if Yes and only one provider,
      skip fwmark routing rules entirely.
    """

    def _bool_setting(key: str, default: bool) -> bool:
        val = settings.get(key, "Yes" if default else "No").strip().lower()
        return val in ("yes", "1", "true")

    use_default_rt = _bool_setting("USE_DEFAULT_RT", False)
    balance_providers = _bool_setting("BALANCE_PROVIDERS", False)
    restore_default_route = _bool_setting("RESTORE_DEFAULT_ROUTE", True)
    optimize_use_first = _bool_setting("OPTIMIZE_USE_FIRST", False)

    if not providers and not routes and not rtrules:
        return "# No providers configured\n"

    # Apply BALANCE_PROVIDERS global default: any provider without an
    # explicit balance or fallback setting gets balance=1.
    if balance_providers:
        for p in providers:
            if not p.balance and not p.fallback:
                p.balance = 1

    # OPTIMIZE_USE_FIRST: skip fwmark rules when only one active provider.
    active = [p for p in providers if p.mark]
    skip_fwmark = optimize_use_first and len(active) <= 1

    lines: list[str] = ["#!/bin/sh", "# iproute2 routing setup — generated by shorewall-nft", ""]

    # 1. Routing table name entries
    lines.append("# Register routing table names")
    for prov in providers:
        lines.append(
            f"grep -qx '{prov.number} {prov.name}' /etc/iproute2/rt_tables "
            f"|| echo '{prov.number} {prov.name}' >> /etc/iproute2/rt_tables"
        )
    lines.append("")

    # 2. Per-provider fwmark → table rules
    if not skip_fwmark:
        lines.append("# fwmark routing rules")
        for prov in providers:
            if not prov.mark:
                continue
            pref = 10000 + prov.number - 1
            mask_hex = hex(0xFF)   # default PROVIDER_MASK (8 bits at offset 0)
            mark_hex = hex(prov.mark)
            lines.append(
                f"ip rule add fwmark {mark_hex}/{mask_hex} "
                f"pref {pref} table {prov.table}"
            )
        lines.append("")

    # 3. Per-provider routing table setup
    lines.append("# Routing table setup")
    provider_idx = _build_provider_index(providers)

    for prov in providers:
        # Duplicate an existing table
        if prov.duplicate:
            if prov.copy:
                ifaces = ",".join(prov.copy)
                lines.append(
                    f"# Copy table {prov.duplicate} into table {prov.table}, "
                    f"excluding routes via {ifaces}"
                )
                lines.append(
                    f"ip route show table {prov.duplicate} | "
                    f"grep -v ' dev \\({' '.join(prov.copy)}\\) ' | "
                    f"while read r; do ip route add table {prov.table} $r; done"
                )
            else:
                lines.append(
                    f"ip route show table {prov.duplicate} | "
                    f"while read r; do ip route add table {prov.table} $r; done"
                )

        # Default route in provider table
        if prov.gateway:
            lines.append(
                f"ip route replace default via {prov.gateway} "
                f"dev {prov.interface} table {prov.table}"
            )
        elif prov.interface:
            lines.append(
                f"ip route replace default dev {prov.interface} table {prov.table}"
            )

        # Source-address routing rule (per-iface address → table)
        if not prov.loose:
            lines.append(
                f"# Source routing rule for {prov.name}: "
                f"add per-address rules pointing to table {prov.table}"
            )
            lines.append(
                f"ip addr show dev {prov.interface} | "
                f"awk '/inet / {{print $2}}' | cut -d/ -f1 | "
                f"while read addr; do ip rule add from $addr pref 20000 table {prov.table}; done"
            )

    lines.append("")

    # 4. Balance / fallback multipath default route
    balance_providers_list = [p for p in providers if p.balance]
    fallback_providers_list = [p for p in providers if p.fallback]

    if balance_providers_list:
        target_table = "balance" if use_default_rt else "main"
        nexthops: list[str] = []
        for p in balance_providers_list:
            weight = p.balance
            if p.gateway:
                nexthops.append(f"nexthop via {p.gateway} dev {p.interface} weight {weight}")
            else:
                nexthops.append(f"nexthop dev {p.interface} weight {weight}")
        nh_str = " ".join(nexthops)
        lines.append(f"# Multipath default route (table={target_table})")
        lines.append(f"ip route replace default table {target_table} {nh_str}")
        lines.append("")

    elif fallback_providers_list:
        # Fallback: add default routes with different metrics
        target_table = "balance" if use_default_rt else "main"
        lines.append(f"# Fallback default routes (table={target_table})")
        for p in fallback_providers_list:
            if p.gateway:
                lines.append(
                    f"ip route replace default via {p.gateway} "
                    f"dev {p.interface} table {target_table} metric {p.number}"
                )
            else:
                lines.append(
                    f"ip route replace default dev {p.interface} "
                    f"table {target_table} metric {p.number}"
                )
        lines.append("")

    # 5. USE_DEFAULT_RT: also restore / set the main table default
    if use_default_rt and restore_default_route:
        lines.append("# RESTORE_DEFAULT_ROUTE: delete any conflicting main-table default")
        lines.append("while ip route del default table main 2>/dev/null; do true; done")
        lines.append("")

    # 6. Extra static routes from routes file
    if routes:
        lines.append("# Extra static routes")
        for route in routes:
            prov = provider_idx.get(route.provider)
            table_id = prov.table if prov else route.provider
            parts = ["ip route replace", route.dest]
            if route.gateway:
                parts.append(f"via {route.gateway}")
            if route.device:
                parts.append(f"dev {route.device}")
            elif prov and prov.interface:
                parts.append(f"dev {prov.interface}")
            parts.append(f"table {table_id}")
            lines.append(" ".join(parts))
        lines.append("")

    # 7. Extra ip-rule entries from rtrules file
    if rtrules:
        lines.append("# Extra routing rules")
        for rule in rtrules:
            prov = provider_idx.get(rule.provider)
            table_id = prov.table if prov else rule.provider

            parts = ["ip rule add"]
            if rule.source:
                # Could be iface:addr or plain addr or iface
                if ":" in rule.source:
                    iface, addr = rule.source.split(":", 1)
                    parts.append(f"iif {iface} from {addr}")
                elif "." in rule.source or ":" in rule.source:
                    parts.append(f"from {rule.source}")
                else:
                    parts.append(f"iif {rule.source}")
            else:
                parts.append("from all")

            if rule.dest:
                parts.append(f"to {rule.dest}")
            else:
                parts.append("to all")

            if rule.mark:
                mark_val, _, mask_val = rule.mark.partition("/")
                if mask_val:
                    parts.append(f"fwmark {mark_val}/{mask_val}")
                else:
                    parts.append(f"fwmark {mark_val}")

            if rule.priority:
                parts.append(f"pref {rule.priority}")
            parts.append(f"table {table_id}")
            lines.append(" ".join(parts))
        lines.append("")

    return "\n".join(lines) + "\n"
