"""Debugging, verification, and blacklist commands.

Covers: verify, trace, debug, counters, migrate, simulate,
capabilities, explain-nft-features, drop, allow, reject, blacklist.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from shorewall_nft.runtime.cli._common import (
    _check_loaded_hash,
    _compile,
    _compile_from_cli,
    _extract_table,
    _resolve_config_paths,
    config_options,
)


# ──────────────────────────────────────────────────────────────────────
# Dynamic blacklist commands (Shorewall-compatible + extensions)
# ──────────────────────────────────────────────────────────────────────

@click.command()
@click.argument("addresses", nargs=-1, required=True)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def drop(addresses: tuple[str], netns: str | None):
    """Dynamically drop traffic from addresses (like shorewall drop)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    for addr in addresses:
        try:
            nft.add_set_element("dynamic_blacklist", addr, timeout="0s", netns=netns)
            click.echo(f"Dropping {addr}")
        except NftError as e:
            click.echo(f"Error: {e}", err=True)


@click.command()
@click.argument("addresses", nargs=-1, required=True)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def allow(addresses: tuple[str], netns: str | None):
    """Remove addresses from the blacklist (like shorewall allow)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    for addr in addresses:
        try:
            nft.delete_set_element("dynamic_blacklist", addr, netns=netns)
            click.echo(f"Allowed {addr}")
        except NftError as e:
            click.echo(f"Error: {e}", err=True)


@click.command()
@click.argument("addresses", nargs=-1, required=True)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def reject(addresses: tuple[str], netns: str | None):
    """Dynamically reject traffic from addresses (like shorewall reject)."""
    # In nft, we use the same blacklist set — reject vs drop distinction
    # would require a separate set. For now, treat same as drop.
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    for addr in addresses:
        try:
            nft.add_set_element("dynamic_blacklist", addr, timeout="0s", netns=netns)
            click.echo(f"Rejecting {addr}")
        except NftError as e:
            click.echo(f"Error: {e}", err=True)


@click.command()
@click.argument("address")
@click.option("-t", "--timeout", default="1h", help="Timeout (e.g. 1h, 30m, 1d).")
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def blacklist(address: str, timeout: str, netns: str | None):
    """Add address to dynamic blacklist with timeout (like shorewall blacklist)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    try:
        nft.add_set_element("dynamic_blacklist", address, timeout=timeout, netns=netns)
        click.echo(f"Blacklisted {address} (timeout: {timeout})")
    except NftError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────
# nft-native extensions: verification and debugging
# ──────────────────────────────────────────────────────────────────────

@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--iptables", type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to iptables-save dump (ground truth).")
@config_options
def verify(directory, iptables, config_dir, config_dir_v4, config_dir_v6,
           no_auto_v4, no_auto_v6):
    """Verify compiled output against iptables baseline."""
    primary, secondary, _ = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config_dir = primary
    from shorewall_nft.verify.triangle import run_triangle

    if secondary is not None:
        config6_dir = secondary
    else:
        config6 = config_dir.parent / (config_dir.name + "6")
        config6_dir = config6 if config6.is_dir() else None

    # IPv4 verification
    report = run_triangle(
        shorewall_config_dir=config_dir,
        iptables_dump=iptables,
        config6_dir=config6_dir,
        family=4,
    )
    click.echo(f"IPv4: {report.summarize()}")

    # IPv6 verification (auto-detect ip6tables dump). For a merged
    # shorewall46 config, there is no separate config6_dir — the v6
    # rules live in the same directory and are tagged via ?FAMILY.
    ip6_dump = iptables.parent / iptables.name.replace("iptables", "ip6tables")
    if ip6_dump.exists():
        report6 = run_triangle(
            shorewall_config_dir=config_dir,
            iptables_dump=iptables,
            ip6tables_dump=ip6_dump,
            config6_dir=config6_dir,
            family=6,
        )
        click.echo(f"IPv6: {report6.summarize()}")
    if not report.passed:
        failing = [pr for pr in report.pair_reports if not pr.passed]
        for pr in failing[:20]:
            click.echo(f"  {pr.zone_pair}: ok={pr.ok} missing={len(pr.missing)} extra={len(pr.extra)} order={len(pr.order_conflicts)}")
        if report.order_conflicts > 0:
            click.echo(f"\nWARNING: {report.order_conflicts} rule ordering conflicts!")

    sys.exit(0 if report.passed else 1)


@click.command()
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def trace(netns: str | None):
    """Start live packet tracing (nft monitor trace)."""
    from shorewall_nft.runtime.monitor import trace_start
    trace_start(netns=netns)


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False,
                                             path_type=Path), required=False)
@click.option("--netns", type=str, default=None,
              help="Network namespace name.")
@click.option("--no-restore", is_flag=True,
              help="Do not restore the original ruleset on exit.")
@click.option("--trace", "trace_filter", type=str, default=None,
              metavar="NFT_MATCH",
              help="Auto-install a `meta nftrace set 1` rule in the input "
                   "chain for the given nft match (e.g. 'ip saddr 1.2.3.4' "
                   "or 'meta l4proto icmp'). Removed on exit.")
@config_options
def debug(directory, netns, no_restore, trace_filter,
          config_dir, config_dir_v4, config_dir_v6,
          no_auto_v4, no_auto_v6):
    """Temporarily load a debug-annotated ruleset.

    Compiles the given config (or the default config dir) with debug mode
    enabled. Every rule gets a named counter and a source-location comment.
    The current ruleset is saved, the debug ruleset is loaded, and a short
    help is printed. Press Ctrl+C to restore the original ruleset.

    Use `nft list counters table inet shorewall` to see per-rule hits, or
    `nft monitor trace` (after inserting a `meta nftrace set 1` rule, or
    automatically via `--trace MATCH`) to see the source reference in the
    trace output as a rule comment.
    """
    import signal
    import sys
    import tempfile

    from shorewall_nft.netns.apply import apply_nft
    from shorewall_nft.nft.netlink import NftInterface

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config_dir = primary

    # Step 0: Hash drift check. If a production ruleset is loaded AND
    # its hash doesn't match the on-disk config, this debug session would
    # replace a DIFFERENT ruleset than what the user expects. Require
    # explicit confirmation.
    source_hash, loaded_hash = _check_loaded_hash(config_dir, netns)
    if loaded_hash is not None and loaded_hash != source_hash:
        click.secho("\n── WARNING: Config drift detected ──",
                    fg="yellow", bold=True)
        click.echo(f"  Loaded ruleset hash:  {loaded_hash}")
        click.echo(f"  On-disk config hash:  {source_hash}")
        click.echo("")
        click.echo(
            "The currently loaded ruleset was compiled from a DIFFERENT")
        click.echo(
            "config than the one on disk. Entering debug mode will")
        click.echo(
            "RELOAD the firewall with the current on-disk config, which")
        click.echo(
            "may change production behavior until you exit debug mode.")
        click.echo("")
        if not click.confirm(
                "Do you want to proceed and reload with debug annotations?",
                default=False):
            click.echo("Aborted.")
            sys.exit(1)

    # Step 1: save the current ruleset
    nft = NftInterface()
    result = nft.run_in_netns(
        [nft._nft_bin, "list", "ruleset"],
        netns=netns, capture_output=True, text=True)
    saved_path: Path | None = None
    if result.returncode == 0 and result.stdout.strip():
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".nft", delete=False,
            prefix="shorewall-next-sim-debug-saved-")
        tmp.write(result.stdout)
        tmp.close()
        saved_path = Path(tmp.name)
        click.echo(f"Saved current ruleset to {saved_path}")
    else:
        click.echo("(no existing ruleset to save)")

    # Step 2: compile with debug=True (uses _compile helper which adds
    # the config hash automatically)
    _, script, _ = _compile(config_dir, config6_dir=secondary,
                            skip_sibling_merge=skip, debug=True)

    debug_path = Path(tempfile.mkstemp(
        suffix=".nft", prefix="shorewall-next-sim-debug-")[1])
    debug_path.write_text(script)

    # Step 3: load the debug ruleset
    click.echo(f"Loading debug ruleset from {debug_path}")
    try:
        apply_nft(script, netns=netns)
    except Exception as e:
        click.echo(f"ERROR loading debug ruleset: {e}", err=True)
        if saved_path:
            click.echo(f"Saved original is at {saved_path}")
        sys.exit(1)

    # Step 3b: optional auto-install trace filter
    if trace_filter:
        # Inserts `<FILTER> meta nftrace set 1` as the first rule in the
        # input chain. The rule is removed on exit (see _restore_and_exit).
        try:
            nft.cmd(
                f"insert rule inet shorewall input "
                f"{trace_filter} meta nftrace set 1",
                netns=netns)
            click.echo(f"Trace filter active: {trace_filter}")
        except Exception as exc:  # noqa: BLE001 — trace-filter is optional; debug session continues without it
            click.echo(f"WARNING: --trace filter install failed: {exc}",
                       err=True)
            trace_filter = None  # don't try to remove later

    # Step 4: print instructions
    ns_prefix = (f"ip netns exec {netns} " if netns else "")
    click.secho("\n── Debug mode active ──", fg="cyan", bold=True)
    click.echo("Every rule has a named counter and source-location comment.")
    click.echo("")
    click.echo("Useful commands:")
    click.echo(f"  {ns_prefix}nft list counters table inet shorewall")
    click.echo(f"  {ns_prefix}nft list counter inet shorewall r_<chain>_<idx>")
    click.echo(f"  {ns_prefix}nft monitor trace")
    if not trace_filter:
        click.echo("  # To enable trace for specific traffic:")
        click.echo(f"  {ns_prefix}nft insert rule inet shorewall input "
                   f"ip saddr <IP> meta nftrace set 1")
        click.echo("  # ... or use --trace 'ip saddr 1.2.3.4' on debug.")
    click.echo("")
    if no_restore:
        click.echo("--no-restore: Ctrl+C will NOT restore the ruleset.")
    else:
        click.echo("Press Ctrl+C to restore the original ruleset.")

    # Step 5: wait for Ctrl+C
    def _restore_and_exit(*_):
        click.echo("\n── Restoring original ruleset ──")
        if no_restore:
            click.echo(f"(skipped — ruleset kept at {debug_path})")
            sys.exit(0)
        try:
            # Drop ONLY the debug `inet shorewall` table. Do NOT flush
            # the entire ruleset — that would also remove unrelated
            # tables (docker, fail2ban, libvirt, ...) that we never
            # touched and have no business restoring.
            #
            # The saved file contains `table inet shorewall { ... }`
            # blocks that will be re-added by apply_nft. If the saved
            # ruleset had additional tables, they weren't changed by
            # debug mode, so they're already correct and don't need
            # re-loading.
            try:
                nft.cmd("delete table inet shorewall", netns=netns)
            except Exception:  # noqa: BLE001 — TEARDOWN: table may already be absent; suppress to proceed with restore
                pass

            if saved_path and saved_path.exists():
                saved_text = saved_path.read_text()
                # Only reapply the shorewall table section of the save
                # to avoid accidentally overwriting live state in other
                # tables that may have changed during the debug session
                # (e.g. docker adding new chains).
                shorewall_only = _extract_table(
                    saved_text, "inet", "shorewall")
                if shorewall_only:
                    apply_nft(shorewall_only, netns=netns)
                    click.echo("Restored.")
                else:
                    click.echo("(saved ruleset had no shorewall table; "
                               "left state untouched)")
            else:
                click.echo("(no saved ruleset — shorewall table removed)")
        except Exception as e:
            click.echo(f"ERROR restoring: {e}", err=True)
            if saved_path:
                click.echo(f"Saved ruleset is at {saved_path}")
            sys.exit(1)
        sys.exit(0)

    signal.signal(signal.SIGINT, _restore_and_exit)
    signal.signal(signal.SIGTERM, _restore_and_exit)

    # Idle loop
    try:
        signal.pause()
    except KeyboardInterrupt:
        _restore_and_exit()


@click.command()
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def counters(netns: str | None):
    """List all counter values (packets/bytes)."""
    from shorewall_nft.nft.netlink import NftError, NftInterface
    nft = NftInterface()
    try:
        ctrs = nft.list_counters(netns=netns)
        if ctrs:
            for name, vals in sorted(ctrs.items()):
                click.echo(f"{name}: packets={vals['packets']} bytes={vals['bytes']}")
        else:
            click.echo("No counters found.")
    except NftError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--iptables", type=click.Path(exists=True, path_type=Path), default=None,
              help="iptables-save dump for verification.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None)
@click.option("--dry-run", is_flag=True, help="Validate with nft -c.")
@config_options
def migrate(directory, iptables, output, dry_run,
            config_dir, config_dir_v4, config_dir_v6, no_auto_v4, no_auto_v6):
    """Verify migration from Shorewall to shorewall-nft."""
    from shorewall_nft.tools.migrate import migrate as run_migrate
    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    ctx = click.Context(run_migrate)
    ctx.invoke(run_migrate, config_dir=primary,
               iptables=iptables, output=output, dry_run=dry_run)


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--iptables", type=click.Path(exists=True, path_type=Path), required=True,
              help="iptables-save dump (ground truth).")
@click.option("--target", default="203.0.113.5", help="Target IP for tests.")
@click.option("--targets", default=None,
              help="Comma-separated list of target IPs, or @FILE with one IP "
                   "per line. Bypasses --target; all targets share a single "
                   "netns topology so the nft ruleset is loaded once.")
@click.option("--ip6tables", "ip6tables_dump",
              type=click.Path(exists=True, path_type=Path), default=None,
              help="ip6tables-save dump for IPv6 tests (optional).")
@click.option("--targets-v6", "targets_v6", default=None,
              help="Comma-separated list or @FILE of IPv6 target addresses. "
                   "Requires --ip6tables.")
@click.option("--src-iface", default=None,
              help="Override the src-zone interface name in the FW netns "
                   f"(default: {'bond1'}). Use to exercise a different "
                   "source zone than net.")
@click.option("--dst-iface", default=None,
              help="Override the dst-zone interface name in the FW netns "
                   f"(default: {'bond0.20'}). Use to exercise a different "
                   "destination zone than host.")
@click.option("--all-zones", is_flag=True,
              help="Multi-zone topology: create one veth pair per zone "
                   "from the shorewall config and derive test cases across "
                   "every <src>2<dst> chain in the iptables dump. Runs as "
                   "a single simulate pass against one loaded ruleset.")
@click.option("--max-tests", "-n", default=60,
              help="Max test cases per target.")
@click.option("--seed", default=42, help="Random seed for sampling.")
@click.option("-v", "--verbose", is_flag=True, help="Show all test results.")
@click.option("--parallel", "-j", default=4, help="Parallel test threads.")
@click.option("--no-trace", is_flag=True, help="Disable nft trace logging.")
@config_options
def simulate(directory, iptables, target, targets, ip6tables_dump, targets_v6,
             src_iface, dst_iface, all_zones, max_tests, seed, verbose,
             parallel, no_trace,
             config_dir, config_dir_v4, config_dir_v6, no_auto_v4, no_auto_v6):
    """Run packet-level simulation in 3 network namespaces."""
    from shorewall_nft.verify.simulate import (
        DST_IFACE_DEFAULT,
        SRC_IFACE_DEFAULT,
        run_simulation,
    )

    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config_dir = primary

    def _parse_list(val: str | None) -> list[str] | None:
        if not val:
            return None
        if val.startswith("@"):
            return [
                line.strip()
                for line in Path(val[1:]).read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        return [t.strip() for t in val.split(",") if t.strip()]

    target_list = _parse_list(targets)
    target_list6 = _parse_list(targets_v6)
    sif = src_iface or SRC_IFACE_DEFAULT
    dif = dst_iface or DST_IFACE_DEFAULT

    click.echo(f"Simulating {config_dir} against {iptables}")
    click.echo(f"Topology: src-iface={sif}, dst-iface={dif}")
    if target_list or target_list6:
        n4 = len(target_list) if target_list else 0
        n6 = len(target_list6) if target_list6 else 0
        click.echo(f"Targets: {n4} v4 + {n6} v6 (single topology), "
                   f"max per target: {max_tests}, seed: {seed}, "
                   f"parallel: {parallel}, trace: {not no_trace}")
    else:
        click.echo(f"Target: {target}, max tests: {max_tests}, seed: {seed}, "
                   f"parallel: {parallel}, trace: {not no_trace}")
    click.echo()

    if all_zones:
        click.echo("All-zones mode: one topology, derive tests across every "
                   "known <src>2<dst> chain in the dump.")

    results = run_simulation(
        config_dir=config_dir,
        iptables_dump=iptables,
        target_ip=target,
        targets=target_list,
        ip6tables_dump=ip6tables_dump,
        targets6=target_list6,
        max_tests=max_tests,
        seed=seed,
        verbose=verbose,
        parallel=parallel,
        trace=not no_trace,
        all_zones_from_config=all_zones,
        src_iface=sif,
        dst_iface=dif,
    )

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    total = len(results)

    click.echo()
    click.echo(f"Results: {passed} passed, {failed} failed ({total} total)")

    if failed > 0:
        click.echo("\nFailed tests:")
        for r in results:
            if not r.passed:
                tc = r.test
                port_str = f":{tc.port}" if tc.port else ""
                click.echo(f"  {tc.src_ip} → {tc.dst_ip} {tc.proto}{port_str} "
                          f"expect={tc.expected} got={r.got}")
        sys.exit(1)


@click.command("capabilities")
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def capabilities(netns: str | None, as_json: bool):
    """Detect nftables capabilities of the running kernel."""
    import json as json_mod

    from shorewall_nft.nft.capabilities import NftCapabilities

    click.echo("Probing nft capabilities...")
    caps = NftCapabilities.probe(netns=netns)

    if as_json:
        d = {k: v for k, v in caps.__dict__.items() if not k.startswith("_")}
        click.echo(json_mod.dumps(d, indent=2))
    else:
        click.echo(caps.summary())


@click.command("explain-nft-features")
@click.option("--probe", is_flag=True, help="Probe kernel for feature availability.")
@click.option("--category", type=str, default=None,
              help="Filter by category (e.g. 'Sets', 'NAT', 'IPv6').")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def explain_nft_features(probe: bool, category: str | None, as_json: bool):
    """Show nft features with syntax examples and availability."""
    from shorewall_nft.nft.explain import (
        format_features,
        get_features_with_availability,
    )

    caps = None
    if probe:
        click.echo("Probing kernel capabilities...")
        from shorewall_nft.nft.capabilities import NftCapabilities
        caps = NftCapabilities.probe()

    features = get_features_with_availability(caps)

    if as_json:
        import json as json_mod
        data = [
            {
                "name": f.name,
                "category": f.category,
                "description": f.description,
                "nft_syntax": f.nft_syntax,
                "shorewall_equivalent": f.shorewall_equivalent,
                "available": f.available,
            }
            for f in features
            if not category or f.category.lower() == category.lower()
        ]
        click.echo(json_mod.dumps(data, indent=2))
    else:
        click.echo(format_features(features, category=category))
