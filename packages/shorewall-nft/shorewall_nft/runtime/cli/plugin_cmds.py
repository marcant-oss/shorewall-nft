"""Plugin-related CLI commands.

Covers: plugins, lookup, enrich, and _register_plugin_commands which
dynamically registers plugin-exposed subcommands onto the root cli group.
"""

from __future__ import annotations

from pathlib import Path

import click

from shorewall_nft.runtime.cli._common import _get_config_dir


@click.command("plugins")
@click.argument("subcommand", type=click.Choice(["list"]), default="list",
                required=False)
@click.option("--config-dir", "-c", type=click.Path(exists=True, path_type=Path),
              default=None)
def plugins_cmd(subcommand: str, config_dir: Path | None):
    """Manage shorewall-nft plugins."""
    from shorewall_nft.plugins.manager import PluginManager

    cdir = config_dir or _get_config_dir(None)
    pm = PluginManager(cdir)
    if subcommand == "list":
        if not pm.plugins:
            click.echo(f"No plugins loaded (plugins.conf in {cdir})")
            return
        click.echo(f"Loaded plugins (from {cdir}/plugins.conf):")
        for p in pm.plugins:
            click.echo(f"  {p.name:15s} v{p.version}  priority={p.priority}")


@click.command("lookup")
@click.argument("ip")
@click.option("--config-dir", "-c", type=click.Path(exists=True, path_type=Path),
              default=None, help="Config dir with plugins.conf")
@click.option("--json", "as_json", is_flag=True, default=False,
              help="Output raw JSON (machine-readable).")
def lookup_cmd(ip: str, config_dir: Path | None, as_json: bool):
    """Lookup an IP address across all configured plugins."""
    import json as json_mod

    from shorewall_nft.plugins.manager import PluginManager

    cdir = config_dir or _get_config_dir(None)
    pm = PluginManager(cdir)
    if not pm.plugins:
        if as_json:
            click.echo(json_mod.dumps({"error": "no plugins loaded",
                                       "config_dir": str(cdir)}))
        else:
            click.echo("No plugins loaded. Configure plugins.conf in "
                       f"{cdir}", err=True)
        raise SystemExit(1)
    info = pm.lookup_ip(ip)
    if not info:
        if as_json:
            click.echo(json_mod.dumps({"ip": ip, "found": False}))
        else:
            click.echo(f"No info for {ip}", err=True)
        raise SystemExit(1)
    # Both modes emit JSON, but the default-mode version is indented
    # for human reading. --json just guarantees a pure JSON stream on
    # stdout even on errors.
    click.echo(json_mod.dumps(
        info, indent=None if as_json else 2))


@click.command("enrich")
@click.argument("directory", type=click.Path(exists=True, file_okay=False,
                                             path_type=Path), required=False)
@click.option("--no-backup", is_flag=True, default=False,
              help="Skip .bak file creation (dangerous)")
@click.option("--dry-run", is_flag=True, default=False,
              help="Preview changes without touching disk (shows a unified diff).")
def enrich_cmd(directory: Path | None, no_backup: bool, dry_run: bool):
    """Run plugin enrichment in-place on a config directory.

    Rewrites rules and params with plugin annotations.
    Creates .bak backups unless --no-backup is passed.

    With --dry-run, no files are modified — instead a unified diff of
    the would-be changes is printed. Useful for reviewing plugin output
    before committing to the rewrite.
    """
    import difflib
    import shutil

    from shorewall_nft.plugins.manager import PluginManager
    from shorewall_nft.tools.merge_config import (
        _apply_enrich_to_block,
        _parse_comment_blocks,
        _parse_params,
    )

    cdir = _get_config_dir(directory)
    pm = PluginManager(cdir)
    if not pm.plugins:
        click.echo(f"No plugins configured in {cdir}/plugins.conf",
                   err=True)
        raise SystemExit(1)

    mode = "Dry-run" if dry_run else "Enriching"
    click.echo(f"{mode} {cdir} with plugins: "
               f"{', '.join(p.name for p in pm.plugins)}")

    # Enrich rules file
    rules_path = cdir / "rules"
    if rules_path.exists():
        original_text = rules_path.read_text(errors="replace")

        header, blocks = _parse_comment_blocks(rules_path)
        lines = list(header)
        enriched_count = 0
        for tag, block_lines in blocks.items():
            import re as re_mod
            content = [l for l in block_lines
                       if not re_mod.match(r'^\?COMMENT', l.strip(),
                                           re_mod.IGNORECASE)]
            enrich = pm.enrich_comment_block(tag, content, [])
            new_block = _apply_enrich_to_block(block_lines, tag, enrich)
            if not enrich.is_empty():
                enriched_count += 1
            lines.append("")
            lines.extend(new_block)
        new_text = "\n".join(lines) + "\n"

        if dry_run:
            # Show unified diff
            diff = list(difflib.unified_diff(
                original_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"{rules_path.name}",
                tofile=f"{rules_path.name} (enriched)",
                n=3,
            ))
            if diff:
                click.echo(f"\n--- rules diff ({enriched_count}/"
                           f"{len(blocks)} blocks changed) ---")
                click.echo("".join(diff))
            else:
                click.echo("  rules: no changes")
        else:
            if not no_backup:
                shutil.copy2(rules_path, rules_path.with_suffix(".bak"))
            rules_path.write_text(new_text)
            click.echo(f"  rules: {enriched_count}/{len(blocks)} "
                       f"blocks enriched")

    # Enrich params file (report pairs, don't rewrite)
    params_path = cdir / "params"
    if params_path.exists():
        v4p = _parse_params(params_path)
        pe = pm.enrich_params(v4p, {})
        if pe.pairs:
            click.echo(f"  params: {len(pe.pairs)} pairs detected "
                       f"(rewrite only during merge-config)")

    click.echo("Dry-run complete." if dry_run else "Done.")


def _register_plugin_commands(cli_group: click.Group) -> None:
    """Register plugin-provided subcommands onto *cli_group*.

    Called from runtime.cli.__init__ after the root group is built
    and the static commands are registered. Wrapped in a broad
    try/except because a broken plugin must not prevent the CLI
    from starting.
    """
    try:
        from shorewall_nft.plugins.manager import PluginManager
        cdir = _get_config_dir(None)
        if not (cdir / "plugins.conf").exists():
            return
        pm = PluginManager(cdir)
        pm.register_cli_commands(cli_group)
    except Exception:
        pass  # Never block CLI startup on plugin errors
