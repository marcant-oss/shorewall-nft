"""CLI interface for shorewall-nft.

Provides Shorewall-compatible commands plus nft-native extensions.

Shorewall-compatible: start, stop, restart, reload, clear, status, check,
    compile, save, restore, show/list, dump, version, logwatch, reset,
    allow, drop, reject, logdrop, logreject, blacklist

nft-native extensions: verify, trace, counters, generate-sysctl,
    generate-systemd, generate-tc, blacklist-add, blacklist-del,
    blacklist-list
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from shorewall_nft import __version__
from shorewall_nft.runtime.cli._common import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_SHOREWALLD_SOCKET,
    MERGED_CONFIG_DIR,
    _check_loaded_hash,
    _compile_from_cli,
    _derive_v4_sibling,
    _detect_current_netns,
    _do_seed_request,
    _extract_seed_qnames,
    _get_config_dir,
    _load_override_arg,
    _load_sets,
    _load_static_nft,
    _notify_shorewalld,
    _parse_seed_duration_ms,
    _Progress,
    _report_shorewalld_result,
    _resolve_config_paths,
    _resolve_instance_name,
    _resolve_seed_config,
    _Step,
    _try_notify_shorewalld,
    config_options,
)

# Tests and external callers import several helpers from this module
# directly (e.g. ``from shorewall_nft.runtime.cli import _get_config_dir``).
# Keep them exported here even though they live in ``_common.py`` now.
__all__ = [
    "cli",
    "DEFAULT_CONFIG_DIR",
    "DEFAULT_SHOREWALLD_SOCKET",
    "MERGED_CONFIG_DIR",
    "_derive_v4_sibling",
    "_get_config_dir",
    "_resolve_config_paths",
    "_resolve_seed_config",
    "config_options",
]


@click.group()
@click.version_option(version=__version__)
@click.option("-q", is_flag=True, help="Quiet mode.")
@click.option("-v", "verbose", count=True, help="Verbose mode (-v, -vv).")
@click.option(
    "--override-json", "override_json", default=None,
    metavar="JSON_OR_@FILE",
    help="Structured JSON merged over every parsed config file at "
         "runtime. Accepts a literal JSON string, ``@path`` (reads a "
         "JSON/YAML file; YAML auto-detected by .yaml/.yml extension), "
         "or ``-`` (reads from stdin). See docs/cli/override-json.md.")
@click.option(
    "--override", "override_per_file", multiple=True,
    metavar="FILE=JSON_OR_@FILE",
    help="Per-file overlay entry, repeatable. "
         "``--override rules=@extra.json`` merges the JSON in "
         "extra.json under the ``rules`` top-level key. Mergeable "
         "with --override-json (later wins on collision).")
@click.pass_context
def cli(ctx, q, verbose, override_json, override_per_file):
    """shorewall-nft: nftables-native firewall compiler."""
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = q
    ctx.obj["verbose"] = verbose

    # Assemble the effective overlay: --override-json first, then
    # each --override FILE=JSON layered on top in argv order.
    overlay: dict = {}
    if override_json:
        try:
            overlay.update(_load_override_arg(override_json))
        except Exception as e:
            raise click.ClickException(
                f"failed to parse --override-json: {e}")
    for entry in override_per_file:
        if "=" not in entry:
            raise click.ClickException(
                f"--override must be of the form FILE=JSON: {entry!r}")
        file, _, value = entry.partition("=")
        try:
            overlay[file] = _load_override_arg(value)
        except Exception as e:
            raise click.ClickException(
                f"failed to parse --override {file}=...: {e}")
    ctx.obj["override_json"] = overlay or None


# ──────────────────────────────────────────────────────────────────────
# Register lifecycle / apply commands (extracted to apply_cmds.py)
# ──────────────────────────────────────────────────────────────────────

from shorewall_nft.runtime.cli.apply_cmds import (  # noqa: E402
    apply_tc as _apply_tc_cmd,
    check as _check_cmd,
    clear as _clear_cmd,
    compile_cmd as _compile_cmd,
    load_sets as _load_sets_cmd,
    reload as _reload_cmd,
    reset as _reset_cmd,
    restart as _restart_cmd,
    restore as _restore_cmd,
    save as _save_cmd,
    show as _show_cmd,
    start as _start_cmd,
    status as _status_cmd,
    stop as _stop_cmd,
)

cli.add_command(_start_cmd)
cli.add_command(_stop_cmd)
cli.add_command(_restart_cmd)
cli.add_command(_reload_cmd)
cli.add_command(_clear_cmd)
cli.add_command(_status_cmd)
cli.add_command(_check_cmd)
cli.add_command(_compile_cmd)
cli.add_command(_save_cmd)
cli.add_command(_restore_cmd)
cli.add_command(_show_cmd)
cli.add_command(_show_cmd, "list")
cli.add_command(_show_cmd, "ls")
cli.add_command(_show_cmd, "dump")
cli.add_command(_reset_cmd)
cli.add_command(_load_sets_cmd)
cli.add_command(_apply_tc_cmd)

# ──────────────────────────────────────────────────────────────────────
# Register commands extracted to subgroup files
# ──────────────────────────────────────────────────────────────────────
from shorewall_nft.runtime.cli.generate_cmds import (  # noqa: E402
    generate_conntrackd,
    generate_set_loader,
    generate_sysctl,
    generate_systemd,
    generate_tc,
)

cli.add_command(generate_sysctl)
cli.add_command(generate_systemd)
cli.add_command(generate_conntrackd)
cli.add_command(generate_tc)
cli.add_command(generate_set_loader)

from shorewall_nft.runtime.cli.config_cmds import (  # noqa: E402
    config_group as _config_group,
    merge_config as _merge_config_cmd,
)

cli.add_command(_config_group)
cli.add_command(_merge_config_cmd)

from shorewall_nft.runtime.cli.plugin_cmds import (  # noqa: E402
    plugins_cmd as _plugins_cmd,
    lookup_cmd as _lookup_cmd,
    enrich_cmd as _enrich_cmd,
    _register_plugin_commands,
)

cli.add_command(_plugins_cmd)
cli.add_command(_lookup_cmd)
cli.add_command(_enrich_cmd)
_register_plugin_commands(cli)

from shorewall_nft.runtime.cli.debug_cmds import (  # noqa: E402
    allow as _allow_cmd,
    blacklist as _blacklist_cmd,
    capabilities as _capabilities_cmd,
    counters as _counters_cmd,
    debug as _debug_cmd,
    drop as _drop_cmd,
    explain_nft_features as _explain_nft_features_cmd,
    migrate as _migrate_cmd,
    reject as _reject_cmd,
    simulate as _simulate_cmd,
    trace as _trace_cmd,
    verify as _verify_cmd,
)

cli.add_command(_verify_cmd)
cli.add_command(_trace_cmd)
cli.add_command(_debug_cmd)
cli.add_command(_counters_cmd)
cli.add_command(_migrate_cmd)
cli.add_command(_simulate_cmd)
cli.add_command(_capabilities_cmd)
cli.add_command(_explain_nft_features_cmd)
cli.add_command(_drop_cmd)
cli.add_command(_allow_cmd)
cli.add_command(_reject_cmd)
cli.add_command(_blacklist_cmd)
