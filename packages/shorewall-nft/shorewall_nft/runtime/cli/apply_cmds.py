"""Lifecycle / apply commands.

Covers: start, stop, restart, reload, clear, status, check, compile,
save, restore, show (+ aliases list/ls/dump), reset, load-sets,
apply-tc, and the shared _apply_and_register helper used by
restart and reload.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from shorewall_nft.runtime.cli._common import (
    DEFAULT_SHOREWALLD_SOCKET,
    _check_loaded_hash,
    _compile_from_cli,
    _detect_current_netns,
    _extract_seed_qnames,
    _get_config_dir,
    _Progress,
    _resolve_config_paths,
    _resolve_instance_name,
    _resolve_seed_config,
    _try_notify_shorewalld,
    config_options,
)
from shorewall_nft.runtime.pyroute2_helpers import settings_bool


def _apply_and_register(
    verb: str,
    directory, netns, shorewalld_socket, instance_name,
    config_dir, config_dir_v4, config_dir_v6,
    no_auto_v4, no_auto_v6,
    *,
    do_seed: bool = False,
    seed_timeout: str | None = None,
    seed_wait_passive: bool | None = None,
) -> None:
    """Shared body for ``restart`` / ``reload``: compile, apply, update
    the DNS allowlist, and re-register the instance with shorewalld."""
    (ir, script, _), (cfg_primary, _, _) = _compile_from_cli(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)

    _dns_reg = getattr(ir, "dns_registry", None)
    _dnsr_reg = getattr(ir, "dnsr_registry", None)
    _nfset_reg = getattr(ir, "nfset_registry", None)
    _has_dns = bool(
        (_dns_reg and _dns_reg.specs) or (_dnsr_reg and _dnsr_reg.groups)
    )

    # Seed injection: only for restart (table is recreated), not reload.
    if do_seed:
        _seed_enabled, _seed_timeout_ms, _seed_wait_passive = _resolve_seed_config(
            None, seed_timeout, seed_wait_passive,
            getattr(ir, "settings", None),
        )
        if _seed_enabled:
            _seed_qnames = _extract_seed_qnames(_dns_reg, _dnsr_reg)
            if _seed_qnames:
                try:
                    from shorewall_nft.nft.dns_sets import inject_seed_elements
                    from shorewall_nft.runtime.seed import request_seeds_from_shorewalld
                    _reg_netns_seed = netns or _detect_current_netns()
                    _inst_seed = _resolve_instance_name(
                        instance_name, getattr(ir, "settings", None),
                        _reg_netns_seed, cfg_primary)
                    _seed_res = request_seeds_from_shorewalld(
                        socket_path=shorewalld_socket,
                        netns=_reg_netns_seed or "",
                        name=_inst_seed,
                        qnames=_seed_qnames,
                        iplist_sets=[],
                        timeout_ms=_seed_timeout_ms,
                        wait_for_passive=_seed_wait_passive,
                    )
                    if _seed_res is not None and _seed_res.dns:
                        script, _n_inj = inject_seed_elements(script, _seed_res.dns)
                        _srcs = ",".join(_seed_res.sources_contributed) or "-"
                        click.echo(
                            f"Seed: {_n_inj} element(s) from [{_srcs}] "
                            f"in {_seed_res.elapsed_ms}ms"
                            + (" (timeout)" if _seed_res.timeout_hit else "")
                        )
                    elif _seed_res is None:
                        click.echo(
                            "warn: seed request failed — sets start empty",
                            err=True)
                except Exception as _seed_exc:  # noqa: BLE001 — seed best-effort; firewall must still load
                    click.echo(f"warn: seed skipped ({_seed_exc})", err=True)

    from shorewall_nft.netns.apply import apply_nft
    apply_nft(script, netns=netns)

    click.echo(f"Shorewall-nft {verb} ({len(ir.chains)} chains).")
    _reg_netns = netns or _detect_current_netns()
    _instance = _resolve_instance_name(
        instance_name, getattr(ir, "settings", None), _reg_netns, cfg_primary)
    _try_notify_shorewalld(
        None, "register", _instance, cfg_primary, _reg_netns,
        shorewalld_socket, _has_dns,
        dns_reg=_dns_reg, dnsr_reg=_dnsr_reg, nfset_reg=_nfset_reg)


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.option(
    "--shorewalld-socket",
    default=DEFAULT_SHOREWALLD_SOCKET,
    envvar="SHOREWALLD_SOCKET",
    show_default=True,
    metavar="PATH",
    help="Path to the shorewalld control socket.",
)
@click.option(
    "--instance-name",
    default=None,
    envvar="SHOREWALLD_INSTANCE_NAME",
    metavar="NAME",
    help="Override the shorewalld instance name "
         "(default: INSTANCE_NAME from shorewall.conf, then netns, "
         "then config_dir basename).",
)
@click.option(
    "--seed/--no-seed",
    "seed",
    default=None,
    envvar="SHOREWALLD_SEED_ENABLED",
    help="Request a seed from shorewalld to pre-populate DNS sets "
         "(default: Yes if shorewall.conf SHOREWALLD_SEED_ENABLED not set).",
)
@click.option(
    "--seed-timeout",
    default=None,
    envvar="SHOREWALLD_SEED_TIMEOUT",
    metavar="DURATION",
    help="Seed request timeout, e.g. '10s' or '10000' (ms). Default: 10s.",
)
@click.option(
    "--seed-wait-passive/--no-seed-wait-passive",
    "seed_wait_passive",
    default=None,
    help="Wait the full timeout for passive sources (dnstap/pbdns) to warm up "
         "(default: Yes).",
)
@config_options
def start(directory, netns, shorewalld_socket, instance_name,
          seed, seed_timeout, seed_wait_passive,
          config_dir, config_dir_v4, config_dir_v6,
          no_auto_v4, no_auto_v6):
    """Compile and apply firewall rules (like shorewall start)."""
    prog = _Progress()
    prog.header("Starting shorewall-nft…")

    # ── Step 1: parse + compile ───────────────────────────────────────
    with prog.step("Parsing and compiling config") as s:
        (ir, script, _), (cfg_primary, _, _) = _compile_from_cli(
            directory, config_dir, config_dir_v4, config_dir_v6,
            no_auto_v4, no_auto_v6)
        n_rules = sum(len(c.rules) for c in ir.chains.values())
        s.info(f"{len(ir.chains)} chains, {n_rules} rules")

    # ── Step 2: capability probe — non-fatal ─────────────────────────
    # Probing failures or missing capabilities produce warnings, not
    # hard errors.  The actual kernel verdict comes in step 3 when the
    # ruleset is loaded: if nft rejects it, *that* is the hard failure.
    nft_iface = None
    with prog.step("Probing kernel capabilities") as s:
        try:
            from shorewall_nft.nft.capabilities import NftCapabilities
            from shorewall_nft.nft.capability_check import check_capabilities, format_errors
            from shorewall_nft.nft.netlink import NftInterface
            nft_iface = NftInterface()
            caps = NftCapabilities.probe(netns=netns, nft=nft_iface)
            n_ok = sum(1 for a in dir(caps)
                       if a.startswith("has_") and getattr(caps, a))
            cap_errors = check_capabilities(ir, caps)
            if cap_errors:
                s.info(f"{n_ok} ok, {len(cap_errors)} warning(s)")
                for line in format_errors(cap_errors).splitlines():
                    if line.strip():
                        s.warn(line)
            else:
                s.info(f"{n_ok} available")
        except Exception as exc:
            s.warn(f"probe failed ({exc}) — attempting load anyway")

    # ── Step 2b: request seed from shorewalld ────────────────────────
    _seed_enabled_raw, _seed_timeout_ms, _seed_wait_passive_raw = _resolve_seed_config(
        seed, seed_timeout, seed_wait_passive,
        getattr(ir, "settings", None),
    )
    if _seed_enabled_raw:
        _seed_qnames = _extract_seed_qnames(
            getattr(ir, "dns_registry", None),
            getattr(ir, "dnsr_registry", None),
        )
        if _seed_qnames:
            with prog.step(
                f"Requesting seed ({len(_seed_qnames)} qname(s))"
            ) as s:
                try:
                    from shorewall_nft.nft.dns_sets import inject_seed_elements
                    from shorewall_nft.runtime.seed import request_seeds_from_shorewalld
                    _reg_netns_seed = netns or _detect_current_netns()
                    _inst_seed = _resolve_instance_name(
                        instance_name, getattr(ir, "settings", None),
                        _reg_netns_seed, cfg_primary)
                    _seed_res = request_seeds_from_shorewalld(
                        socket_path=shorewalld_socket,
                        netns=_reg_netns_seed or "",
                        name=_inst_seed,
                        qnames=_seed_qnames,
                        iplist_sets=[],
                        timeout_ms=_seed_timeout_ms,
                        wait_for_passive=_seed_wait_passive_raw,
                    )
                    if _seed_res is not None and _seed_res.dns:
                        script, _n_inj = inject_seed_elements(script, _seed_res.dns)
                        _srcs = ",".join(_seed_res.sources_contributed) or "-"
                        s.info(f"{_n_inj} elements from [{_srcs}] "
                               f"in {_seed_res.elapsed_ms}ms")
                        if _seed_res.timeout_hit:
                            s.warn("timeout hit — partial seed data")
                        for _qn, _fams in sorted(_seed_res.dns.items()):
                            _n4 = len(_fams.get("v4") or [])
                            _n6 = len(_fams.get("v6") or [])
                            _ttls = [e["ttl"] for f in _fams.values()
                                     for e in f if e.get("ttl")]
                            _ttl_info = (f"  ttl {min(_ttls)}–{max(_ttls)}s"
                                         if _ttls else "")
                            s.note(f"{_qn}: {_n4}×v4  {_n6}×v6{_ttl_info}")
                    elif _seed_res is None:
                        s.warn("seed request failed, sets start empty")
                    else:
                        s.info("no seed data available")
                except Exception as _seed_exc:  # noqa: BLE001 — seed best-effort; firewall must still load
                    s.warn(f"seed skipped ({_seed_exc})")

    # ── Step 3: apply ruleset — this is the real gate ─────────────────
    with prog.step("Applying ruleset") as s:
        from shorewall_nft.netns.apply import apply_nft
        apply_nft(script, netns=netns)
        s.info(f"{len(ir.chains)} chains")

    # ── Step 3b: register instance with shorewalld ───────────────────
    _dns_reg = getattr(ir, "dns_registry", None)
    _dnsr_reg = getattr(ir, "dnsr_registry", None)
    _nfset_reg = getattr(ir, "nfset_registry", None)
    _has_dns = bool(
        (_dns_reg and _dns_reg.specs) or (_dnsr_reg and _dnsr_reg.groups)
    )
    # When running inside a named netns via JoinsNamespaceOf (no --netns
    # flag), detect the current netns so shorewalld receives the correct
    # netns name in the registration payload and so it is used as the
    # default instance name.
    _reg_netns = netns or _detect_current_netns()
    _instance = _resolve_instance_name(
        instance_name, getattr(ir, "settings", None), _reg_netns, cfg_primary)
    with prog.step(
        f"Registering instance {_instance!r} with shorewalld"
    ) as s:
        _try_notify_shorewalld(
            s, "register", _instance, cfg_primary, _reg_netns,
            shorewalld_socket, _has_dns,
            dns_reg=_dns_reg, dnsr_reg=_dnsr_reg, nfset_reg=_nfset_reg)

    # ── Step 4: proxy-ARP / NDP ───────────────────────────────────────
    with prog.step("Proxy-ARP / NDP") as s:
        try:
            from shorewall_nft.compiler.proxyarp import apply_proxyarp, parse_proxyarp
            from shorewall_nft.config.parser import load_config
            primary, secondary, skip = _resolve_config_paths(
                directory, config_dir, config_dir_v4, config_dir_v6,
                no_auto_v4, no_auto_v6)
            cfg = load_config(primary, config6_dir=secondary,
                              skip_sibling_merge=skip)
            proxy_entries = (
                parse_proxyarp(getattr(cfg, "proxyarp", []) or []) +
                parse_proxyarp(getattr(cfg, "proxyndp", []) or []))
            if proxy_entries:
                applied, skipped, errs = apply_proxyarp(
                    proxy_entries, netns=netns)
                s.info(f"{applied} applied"
                       + (f", {skipped} skipped" if skipped else ""))
                for e in errs:
                    s.warn(e)
            else:
                s.info("none configured")
        except Exception as exc:  # noqa: BLE001 — proxy-ARP apply is best-effort; don't block start
            s.warn(f"skipped ({exc})")

    # ── Step 4b: IP aliases (ADD_IP_ALIASES / ADD_SNAT_ALIASES) ──────
    with prog.step("IP aliases") as s:
        try:
            from shorewall_nft.runtime.apply import apply_ip_aliases
            aliases = getattr(ir, "ip_aliases", [])
            if aliases:
                applied, skipped, errs = apply_ip_aliases(aliases, netns=netns)
                s.info(
                    f"{applied} added"
                    + (f", {skipped} already present" if skipped else ""))
                for e in errs:
                    s.warn(e)
            else:
                s.info("none configured")
        except Exception as exc:  # noqa: BLE001 — alias apply is best-effort; don't block start
            s.warn(f"skipped ({exc})")

    # ── Step 4c: provider policy routing (iproute2 rules/routes) ─────
    with prog.step("Provider policy routing") as s:
        try:
            from shorewall_nft.runtime.apply import apply_iproute2_rules
            _providers = getattr(ir, "providers", [])
            _routes = getattr(ir, "routes", [])
            _rtrules = getattr(ir, "rtrules", [])
            if _providers or _routes or _rtrules:
                _settings = getattr(ir, "settings", {}) or {}
                applied, _skipped, errs = apply_iproute2_rules(
                    _providers, _routes, _rtrules, _settings, netns=netns)
                s.info(
                    f"{applied} applied"
                    + (f", {_skipped} skipped" if _skipped else ""))
                for e in errs:
                    s.warn(e)
            else:
                s.info("none configured")
        except Exception as exc:  # noqa: BLE001 — policy-routing apply is best-effort; don't block start
            s.warn(f"skipped ({exc})")

    # ── Step 5: tear down leftover shorewall_stopped table ────────────
    with prog.step("Cleanup") as s:
        try:
            from shorewall_nft.nft.netlink import NftError, NftInterface
            if nft_iface is None:
                nft_iface = NftInterface()
            try:
                nft_iface.cmd(
                    "delete table inet shorewall_stopped", netns=netns)
                s.info("stopped table removed")
            except NftError:
                s.info("nothing to clean")
        except (ImportError, OSError):
            # nft binary or netlink unavailable — cleanup is non-critical.
            s.info("nothing to clean")

    prog.done("Shorewall-nft started.")


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.option(
    "--shorewalld-socket",
    default=DEFAULT_SHOREWALLD_SOCKET,
    envvar="SHOREWALLD_SOCKET",
    show_default=True,
    metavar="PATH",
    help="Path to the shorewalld control socket.",
)
@click.option(
    "--instance-name",
    default=None,
    envvar="SHOREWALLD_INSTANCE_NAME",
    metavar="NAME",
    help="Override the shorewalld instance name "
         "(default: INSTANCE_NAME from shorewall.conf, then netns, "
         "then config_dir basename).",
)
@config_options
def stop(directory, netns, shorewalld_socket, instance_name,
         config_dir, config_dir_v4, config_dir_v6,
         no_auto_v4, no_auto_v6):
    """Stop the firewall.

    Removes the running ``inet shorewall`` table. If the configuration
    contains a ``routestopped`` file, the compiled
    ``inet shorewall_stopped`` table is loaded so the listed
    (interface, host) pairs remain reachable while the firewall is down.
    Without ``routestopped`` the kernel falls back to its default
    (typically wide-open) policy — same behaviour as before.
    """
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    # Resolve the primary config path up front — needed for the
    # shorewalld deregister even if the compile below fails.
    primary_cfg_dir, _secondary, _skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)

    # Try to compile so we can load shorewall_stopped if defined.
    # Compile failures must not block the stop — fall through to the
    # plain `delete table inet shorewall` path.
    stopped_script: str | None = None
    ir = None
    try:
        (ir, _script, _sets), _paths = _compile_from_cli(
            directory, config_dir, config_dir_v4, config_dir_v6,
            no_auto_v4, no_auto_v6)
        from shorewall_nft.nft.emitter import emit_stopped_nft
        s = emit_stopped_nft(ir)
        if s.strip():
            stopped_script = s
    except Exception as e:  # noqa: BLE001 — compile failure must not block stop; fall through
        click.echo(f"Note: stopped-table compile failed ({e}); "
                   "falling back to plain delete.", err=True)

    def _run(cmd_str: str) -> None:
        nft.cmd(cmd_str, netns=netns)

    # Best-effort delete of the running table.
    try:
        _run("delete table inet shorewall")
    except Exception as e:  # noqa: BLE001 — table may already be absent; non-fatal
        click.echo(f"Note: {e}", err=True)

    if stopped_script is not None:
        from shorewall_nft.netns.apply import apply_nft
        try:
            apply_nft(stopped_script, netns=netns)
            click.echo("Shorewall-nft stopped (routestopped table loaded).")
        except Exception as e:  # noqa: BLE001 — stopped-table load is best-effort; firewall is already down
            click.echo(f"Note: failed to load shorewall_stopped: {e}",
                       err=True)

    # Remove non-persistent proxy ARP/NDP entries via pyroute2.
    try:
        from shorewall_nft.compiler.proxyarp import (
            parse_proxyarp,
            remove_proxyarp,
        )
        from shorewall_nft.config.parser import load_config
        cfg = load_config(primary_cfg_dir, config6_dir=_secondary,
                          skip_sibling_merge=_skip)
        proxy_entries = (
            parse_proxyarp(getattr(cfg, "proxyarp", []) or []) +
            parse_proxyarp(getattr(cfg, "proxyndp", []) or []))
        if proxy_entries:
            n = remove_proxyarp(proxy_entries, netns=netns)
            if n:
                click.echo(f"proxy-arp/ndp: {n} entries removed")
    except Exception as e:  # noqa: BLE001 — proxy-ARP removal is best-effort on stop
        click.echo(f"proxy-arp/ndp removal: skipped ({e})", err=True)

    # Remove IP aliases (DNAT/SNAT) — gated on RETAIN_ALIASES=No (default).
    try:
        from shorewall_nft.runtime.apply import remove_ip_aliases
        _settings_stop = getattr(ir, "settings", {}) or {}
        retain = settings_bool(_settings_stop, "RETAIN_ALIASES", False)
        if not retain:
            aliases = getattr(ir, "ip_aliases", []) if ir is not None else []
            if aliases:
                n_removed, _skipped, _errs = remove_ip_aliases(aliases, netns=netns)
                if n_removed:
                    click.echo(f"ip-aliases: {n_removed} removed")
    except Exception as e:  # noqa: BLE001 — alias removal is best-effort on stop
        click.echo(f"ip-aliases removal: skipped ({e})", err=True)

    # Remove provider policy routing (ip rules / ip routes).
    try:
        from shorewall_nft.runtime.apply import remove_iproute2_rules
        _settings_stop2 = getattr(ir, "settings", {}) or {} if ir is not None else {}
        _providers_stop = getattr(ir, "providers", []) if ir is not None else []
        _routes_stop = getattr(ir, "routes", []) if ir is not None else []
        _rtrules_stop = getattr(ir, "rtrules", []) if ir is not None else []
        if _providers_stop or _routes_stop or _rtrules_stop:
            n_removed, _skipped, _errs = remove_iproute2_rules(
                _providers_stop, _routes_stop, _rtrules_stop,
                _settings_stop2, netns=netns)
            if n_removed:
                click.echo(f"provider routing: {n_removed} entries removed")
            for _e in _errs:
                click.echo(f"provider routing removal: {_e}", err=True)
    except Exception as e:  # noqa: BLE001 — policy-routing removal is best-effort on stop
        click.echo(f"provider routing removal: skipped ({e})", err=True)

    # Deregister from shorewalld. Determine whether DNS/DNSR sets are
    # present from the compile result if available, else from the
    # on-disk allowlist file.
    _has_dns = False
    if ir is not None:
        _dns_reg = getattr(ir, "dns_registry", None)
        _dnsr_reg = getattr(ir, "dnsr_registry", None)
        _has_dns = bool(
            (_dns_reg and _dns_reg.specs) or (_dnsr_reg and _dnsr_reg.groups)
        )
    else:
        _allowlist = primary_cfg_dir / "dnsnames.compiled"
        try:
            _has_dns = _allowlist.is_file() and _allowlist.stat().st_size > 0
        except OSError:
            pass
    _settings = getattr(ir, "settings", None) if ir is not None else None
    _reg_netns = netns or _detect_current_netns()
    _instance = _resolve_instance_name(
        instance_name, _settings, _reg_netns, primary_cfg_dir)
    _try_notify_shorewalld(
        None, "deregister", _instance, primary_cfg_dir, _reg_netns,
        shorewalld_socket, _has_dns)

    if stopped_script is None:
        click.echo("Shorewall-nft stopped.")


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.option(
    "--shorewalld-socket",
    default=DEFAULT_SHOREWALLD_SOCKET,
    envvar="SHOREWALLD_SOCKET",
    show_default=True,
    metavar="PATH",
    help="Path to the shorewalld control socket.",
)
@click.option(
    "--instance-name",
    default=None,
    envvar="SHOREWALLD_INSTANCE_NAME",
    metavar="NAME",
    help="Override the shorewalld instance name "
         "(default: INSTANCE_NAME from shorewall.conf, then netns, "
         "then config_dir basename).",
)
@click.option(
    "--seed/--no-seed",
    "seed",
    default=None,
    envvar="SHOREWALLD_SEED_ENABLED",
    help="Request a seed from shorewalld to pre-populate DNS sets.",
)
@click.option(
    "--seed-timeout",
    default=None,
    envvar="SHOREWALLD_SEED_TIMEOUT",
    metavar="DURATION",
    help="Seed request timeout, e.g. '10s' or '10000' (ms). Default: 10s.",
)
@click.option(
    "--seed-wait-passive/--no-seed-wait-passive",
    "seed_wait_passive",
    default=None,
    help="Wait the full timeout for passive sources (dnstap/pbdns) to warm up.",
)
@config_options
def restart(directory, netns, shorewalld_socket, instance_name,
            seed, seed_timeout, seed_wait_passive,
            config_dir, config_dir_v4, config_dir_v6,
            no_auto_v4, no_auto_v6):
    """Recompile and atomically replace the ruleset."""
    _apply_and_register(
        "restarted",
        directory, netns, shorewalld_socket, instance_name,
        config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6,
        do_seed=True,
        seed_timeout=seed_timeout,
        seed_wait_passive=seed_wait_passive,
    )


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.option(
    "--shorewalld-socket",
    default=DEFAULT_SHOREWALLD_SOCKET,
    envvar="SHOREWALLD_SOCKET",
    show_default=True,
    metavar="PATH",
    help="Path to the shorewalld control socket.",
)
@click.option(
    "--instance-name",
    default=None,
    envvar="SHOREWALLD_INSTANCE_NAME",
    metavar="NAME",
    help="Override the shorewalld instance name "
         "(default: INSTANCE_NAME from shorewall.conf, then netns, "
         "then config_dir basename).",
)
@config_options
def reload(directory, netns, shorewalld_socket, instance_name,
           config_dir, config_dir_v4, config_dir_v6,
           no_auto_v4, no_auto_v6):
    """Reload rules (same as restart for nft — atomic replace)."""
    _apply_and_register(
        "reloaded",
        directory, netns, shorewalld_socket, instance_name,
        config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6,
    )


@click.command()
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def clear(netns: str | None):
    """Clear all firewall rules (accept all traffic)."""
    # In nft: delete table then create empty with accept policies
    clear_script = """
table inet shorewall
delete table inet shorewall
table inet shorewall {
    chain input { type filter hook input priority 0; policy accept; }
    chain forward { type filter hook forward priority 0; policy accept; }
    chain output { type filter hook output priority 0; policy accept; }
}
"""
    from shorewall_nft.netns.apply import apply_nft
    apply_nft(clear_script.strip(), netns=netns)
    click.echo("Shorewall-nft cleared (all traffic accepted).")


@click.command()
@click.option("--netns", type=str, default=None, help="Network namespace name.")
def status(netns: str | None):
    """Show firewall status."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    result = nft.run_in_netns(
        [nft._nft_bin, "list", "table", "inet", "shorewall"],
        netns=netns, capture_output=True, text=True)
    if result.returncode == 0:
        click.echo("Shorewall-nft is running.")
        # Count chains and rules
        lines = result.stdout.splitlines()
        chains = sum(1 for l in lines if l.strip().startswith("chain "))
        rules = sum(1 for l in lines if l.strip() and not l.strip().startswith(("chain ", "table ", "type ", "}", "{", "#", "set ", "flags ", "elements ", "priority")))
        click.echo(f"  Chains: {chains}")
        click.echo(f"  Rules: ~{rules}")

        # Hash drift detection
        from shorewall_nft.config.hash import extract_hash_from_ruleset
        loaded_hash = extract_hash_from_ruleset(result.stdout)
        if loaded_hash:
            try:
                source_hash, _ = _check_loaded_hash(
                    _get_config_dir(None), netns)
                if loaded_hash == source_hash:
                    click.echo(f"  Config hash: {loaded_hash} (matches source)")
                else:
                    click.secho(
                        f"  Config hash: {loaded_hash} (loaded)",
                        fg="yellow")
                    click.secho(
                        f"               {source_hash} (on-disk) — DRIFT!",
                        fg="yellow", bold=True)
                    click.secho(
                        "  WARNING: loaded ruleset differs from on-disk "
                        "config. Run `shorewall-nft reload` to sync.",
                        fg="yellow")
            except (OSError, ValueError):
                # config_dir not found or hash unreadable — drift display is non-critical
                pass
        # Debug marker
        if "debug" in result.stdout[:500]:
            import re as _re
            if _re.search(r'config-hash:\S+\s+debug', result.stdout):
                click.secho(
                    "  DEBUG MODE ACTIVE — this is not a production ruleset.",
                    fg="magenta", bold=True)
    else:
        click.echo("Shorewall-nft is stopped.", err=True)
        sys.exit(1)


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--skip-caps", is_flag=True, help="Skip capability check.")
@config_options
def check(directory, skip_caps, config_dir, config_dir_v4, config_dir_v6,
          no_auto_v4, no_auto_v6):
    """Validate config without applying (like shorewall check)."""
    try:
        (ir, script, _), _ = _compile_from_cli(
            directory, config_dir, config_dir_v4, config_dir_v6,
            no_auto_v4, no_auto_v6)
        click.echo(f"Configuration compiled ({len(ir.chains)} chains).")

        if not skip_caps:
            from shorewall_nft.nft.capabilities import NftCapabilities
            from shorewall_nft.nft.capability_check import check_capabilities, format_errors

            click.echo("Checking kernel capabilities...")
            caps = NftCapabilities.probe()
            errors = check_capabilities(ir, caps)
            if errors:
                click.echo(format_errors(errors), err=True)
                sys.exit(1)
            else:
                click.echo(f"All {len([a for a in dir(caps) if a.startswith('has_') and getattr(caps, a)])} required capabilities available.")
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


@click.command("compile")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file.")
@config_options
def compile_cmd(directory, output, config_dir, config_dir_v4, config_dir_v6,
                no_auto_v4, no_auto_v6):
    """Compile config to nft script (like shorewall compile)."""
    (_, script, _), _ = _compile_from_cli(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    if output:
        output.write_text(script)
        click.echo(f"Compiled to {output}")
    else:
        click.echo(script)


@click.command()
@click.option("--counters", is_flag=True, help="Include counters in the saved ruleset.")
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.argument("filename", required=False)
def save(counters, netns: str | None, filename: str | None):
    """Save current ruleset (like shorewall save)."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    result = nft.run_in_netns(
        [nft._nft_bin, "list", "ruleset"],
        netns=netns, capture_output=True, text=True)
    if result.returncode != 0:
        click.echo("ERROR: No ruleset to save.", err=True)
        sys.exit(1)

    if filename:
        Path(filename).write_text(result.stdout)
        click.echo(f"Ruleset saved to {filename}")
    else:
        click.echo(result.stdout)


@click.command()
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.argument("filename", type=click.Path(exists=True, path_type=Path))
def restore(netns: str | None, filename: Path):
    """Restore a saved ruleset (like shorewall restore)."""
    from shorewall_nft.netns.apply import apply_nft
    script = filename.read_text()
    apply_nft(script, netns=netns)
    click.echo(f"Ruleset restored from {filename}")


@click.command()
@click.option("-x", is_flag=True, help="Show exact counters.")
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.argument("what", required=False)
def show(x, netns: str | None, what: str | None):
    """Show firewall info (like shorewall show). Subcommands: zones, policies, config, connections."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    if what in ("zones", "connections"):
        args = [nft._nft_bin, "list", "table", "inet", "shorewall"]
    elif what == "counters":
        args = [nft._nft_bin, "list", "counters", "table", "inet", "shorewall"]
    elif what == "sets":
        args = [nft._nft_bin, "list", "sets", "table", "inet", "shorewall"]
    else:
        args = [nft._nft_bin, "list", "ruleset"]

    result = nft.run_in_netns(args, netns=netns, capture_output=True, text=True)
    click.echo(result.stdout if result.returncode == 0 else "No rules loaded.")


@click.command()
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.argument("chains", nargs=-1)
def reset(netns: str | None, chains: tuple[str]):
    """Reset counters (like shorewall reset)."""
    from shorewall_nft.nft.netlink import NftInterface
    nft = NftInterface()

    result = nft.run_in_netns(
        [nft._nft_bin, "reset", "counters", "table", "inet", "shorewall"],
        netns=netns, capture_output=True, text=True)
    click.echo("Counters reset." if result.returncode == 0 else f"Error: {result.stderr}")


@click.command("load-sets")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--netns", type=str, default=None, help="Network namespace name.")
@click.option("--geoip-dir", type=click.Path(exists=True, path_type=Path), default=None,
              help="GeoIP prefix directory.")
@config_options
def load_sets(directory, netns, geoip_dir,
              config_dir, config_dir_v4, config_dir_v6, no_auto_v4, no_auto_v6):
    """Load external sets (ipsets, GeoIP) into nft after apply."""
    from shorewall_nft.nft.set_loader import SetLoader

    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config_dir = primary
    loader = SetLoader(netns=netns)

    # Load sets from init script
    init_path = config_dir / "init"
    if init_path.exists():
        results = loader.load_from_init(init_path, config_dir)
        for name, count in results.items():
            click.echo(f"  Loaded {name}: {count} elements")

    # Load GeoIP sets
    if geoip_dir:
        results = loader.load_geoip_dir(geoip_dir)
        for name, count in results.items():
            click.echo(f"  Loaded {name}: {count} elements")

    if not init_path.exists() and not geoip_dir:
        click.echo("No sets to load.")


@click.command("apply-tc")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
@click.option("--netns", default=None, metavar="NAME",
              help="Apply inside this named network namespace (pyroute2 "
                   "IPRoute(netns=NAME) — no ip-netns-exec fork).")
@click.option("--dry-run", "dry_run", is_flag=True, default=False,
              help="Parse and validate the TC config then print the planned "
                   "operations as a bulleted list.  Nothing is applied to "
                   "the kernel.")
def apply_tc(directory, config_dir, config_dir_v4, config_dir_v6,
             no_auto_v4, no_auto_v6, netns, dry_run):
    """Apply TC (traffic control) config via pyroute2.

    Reads tcdevices / tcclasses / tcfilters from the config directory
    and configures kernel qdiscs, classes, and fwmark filters directly
    via netlink.  No tc(8) binary is required.

    \b
    Idempotence: existing qdiscs are deleted then re-added before each
    apply so that re-running the command after a config change is safe.

    \b
    Netns: --netns binds each netlink socket directly to the target
    namespace via pyroute2's IPRoute(netns=) constructor.  No
    ip-netns-exec fork is used.
    """
    from shorewall_nft.compiler.tc import apply_tc as _apply_tc_impl
    from shorewall_nft.compiler.tc import parse_tc_config
    from shorewall_nft.config.parser import load_config

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    tc = parse_tc_config(config)

    if not tc.devices and not tc.classes and not tc.filters:
        click.echo("No TC configuration found.")
        return

    if dry_run:
        click.echo("TC apply plan (dry-run — nothing applied):")
        ns_label = f" [netns={netns}]" if netns else ""
        for dev in tc.devices:
            if dev.out_bandwidth:
                click.echo(
                    f"  * {dev.interface}{ns_label}: del + add root HTB qdisc"
                    f" (rate {dev.out_bandwidth}), add root class 1:1")
            if dev.in_bandwidth:
                click.echo(
                    f"  * {dev.interface}{ns_label}: del + add ingress qdisc"
                    f" (in_bandwidth {dev.in_bandwidth})")
        for cls in tc.classes:
            ceil = cls.ceil or cls.rate
            click.echo(
                f"  * {cls.interface}{ns_label}: add HTB class 1:{cls.mark}"
                f" rate={cls.rate} ceil={ceil} prio={cls.priority}")
        for flt in tc.filters:
            click.echo(
                f"  * filter class={flt.tc_class}{ns_label}:"
                f" add fw filter handle=<mark> -> classid")
        return

    result = _apply_tc_impl(tc, netns=netns)

    ns_label = f" (netns={netns})" if netns else ""
    if result.failed == 0:
        click.echo(
            f"TC apply{ns_label}: {result.applied} operation(s) applied, "
            f"0 failed.")
    else:
        click.echo(
            f"TC apply{ns_label}: {result.applied} applied, "
            f"{result.failed} failed.",
            err=True)
        for msg in result.errors:
            click.echo(f"  ERROR: {msg}", err=True)
        raise SystemExit(1)
