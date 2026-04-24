"""config subgroup commands + merge-config.

shorewall-nft config {export, import, template, merge} — structured
config I/O, plus the legacy flat merge-config command that delegates
to the tools module.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

# ──────────────────────────────────────────────────────────────────────
# Flat command: merge-config
# ──────────────────────────────────────────────────────────────────────

@click.command("merge-config")
@click.argument("shorewall_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("shorewall6_dir", type=click.Path(exists=True, path_type=Path),
                required=False)
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output directory (default: <parent>/shorewall46)")
@click.option("--guided", is_flag=True, default=False,
              help="Interactive mode: ask on each collision")
@click.option("--no-plugins", is_flag=True, default=False,
              help="Disable plugin enrichment even if plugins.conf exists")
def merge_config(shorewall_dir: Path, shorewall6_dir: Path | None,
                 output: Path | None, guided: bool, no_plugins: bool):
    """Merge Shorewall + Shorewall6 configs into unified directory.

    If only the v4 dir is given, the v6 sibling is auto-detected by
    appending '6' to the v4 dir name (e.g. /etc/shorewall → /etc/shorewall6).
    """
    if shorewall6_dir is None:
        candidate = shorewall_dir.parent / (shorewall_dir.name + "6")
        if not candidate.is_dir():
            raise click.UsageError(
                f"No v6 config given and {candidate} not found. "
                f"Specify both directories or create the sibling.")
        shorewall6_dir = candidate
        click.echo(f"Auto-detected v6 sibling: {shorewall6_dir}")

    from shorewall_nft.tools.merge_config import merge_config as do_merge
    ctx = click.Context(do_merge)
    ctx.invoke(do_merge, shorewall_dir=shorewall_dir,
               shorewall6_dir=shorewall6_dir, output=output,
               guided=guided, no_plugins=no_plugins)


# ──────────────────────────────────────────────────────────────────────
# Group: config
# ──────────────────────────────────────────────────────────────────────

@click.group(name="config")
def config_group() -> None:
    """Structured config I/O (export / import / edit — planned)."""


@config_group.command("export")
@click.argument("directory", type=click.Path(exists=True, file_okay=False,
                                             path_type=Path),
                required=False)
@click.option("--format", "fmt",
              type=click.Choice(["json", "yaml"]), default="json",
              show_default=True,
              help="Output format. YAML needs PyYAML available.")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Write to FILE instead of stdout. Extension auto-"
                   "selects the format if --format is not given.")
@click.option("--include-trace", is_flag=True,
              help="Keep _file / _lineno / _comment diagnostics in the "
                   "output (off by default for stable diffs).")
@click.option("--indent", type=int, default=2, show_default=True,
              help="JSON indent (ignored for YAML).")
def config_export(directory: Path | None, fmt: str, output: Path | None,
                  include_trace: bool, indent: int) -> None:
    """Dump a Shorewall config directory as a structured JSON/YAML blob.

    Columnar files emit one object per row with column names as keys;
    ``rules`` / ``blrules`` / ``policy`` are nested under their
    ``?SECTION`` labels.
    """
    from shorewall_nft.config.exporter import export_config
    from shorewall_nft.config.parser import load_config

    cfg_dir = directory or Path("/etc/shorewall46")
    cfg = load_config(cfg_dir)
    blob = export_config(cfg, include_trace=include_trace)

    # Auto-format from extension when -o is given and --format wasn't.
    if output is not None and output.suffix in (".yaml", ".yml"):
        fmt = "yaml"

    if fmt == "yaml":
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            click.echo(
                "YAML output requested but PyYAML is not installed. "
                "Install python3-yaml or pass --format=json.", err=True)
            sys.exit(2)
        text = yaml.safe_dump(blob, sort_keys=False, default_flow_style=False,
                              allow_unicode=True)
    else:
        import json as _json
        text = _json.dumps(blob, indent=indent, ensure_ascii=False,
                           sort_keys=False) + "\n"

    if output is not None:
        output.write_text(text)
        click.echo(f"wrote {output} ({len(text)} bytes)")
    else:
        click.echo(text, nl=False)


@config_group.command("import")
@click.argument("source", type=click.Path(path_type=Path),
                required=True)
@click.option("--format", "fmt",
              type=click.Choice(["json", "yaml", "auto"]), default="auto",
              show_default=True,
              help="Input format. 'auto' selects by file extension.")
@click.option("--to", "target", type=click.Path(path_type=Path), default=None,
              help="Target directory. When given, the parsed blob is "
                   "written back as on-disk Shorewall files. Otherwise "
                   "the command only validates the blob.")
@click.option("--force", is_flag=True,
              help="Overwrite --to target even if it is not empty.")
@click.option("--dry-run", is_flag=True,
              help="Parse + validate only, print a summary. Implied "
                   "when --to is absent.")
def config_import(source: Path, fmt: str, target: Path | None,
                  force: bool, dry_run: bool) -> None:
    """Import a structured JSON/YAML config blob into a ShorewalConfig.

    Currently the CLI validates the blob and prints a summary
    (zones / interfaces / rules / etc counts). Writing back to a
    target directory is a follow-up — the in-memory path is already
    enough for the ``--override-json`` wiring and for round-trip
    testing.
    """
    from shorewall_nft.config.importer import (
        ImportError as CfgImportError,
    )
    from shorewall_nft.config.importer import (
        blob_to_config,
        write_config_dir,
    )

    if source.name == "-":
        text = sys.stdin.read()
        suffix = ""
    else:
        if not source.exists():
            click.echo(f"input not found: {source}", err=True)
            sys.exit(2)
        text = source.read_text()
        suffix = source.suffix

    if fmt == "auto":
        fmt = "yaml" if suffix in (".yaml", ".yml") else "json"
    if fmt == "yaml":
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            click.echo("YAML input requested but PyYAML not installed.",
                       err=True)
            sys.exit(2)
        blob = yaml.safe_load(text)
    else:
        import json as _json
        blob = _json.loads(text)

    try:
        config = blob_to_config(blob)
    except CfgImportError as e:
        click.echo(f"import failed: {e}", err=True)
        sys.exit(2)

    click.echo(f"imported schema_version={blob.get('schema_version')}")
    click.echo(f"  shorewall.conf: {len(config.settings)} keys")
    click.echo(f"  params:         {len(config.params)} keys")
    click.echo(f"  zones:          {len(config.zones)} rows")
    click.echo(f"  interfaces:     {len(config.interfaces)} rows")
    click.echo(f"  hosts:          {len(config.hosts)} rows")
    click.echo(f"  policy:         {len(config.policy)} rows")
    click.echo(f"  rules:          {len(config.rules)} rows")
    click.echo(f"  blrules:        {len(config.blrules)} rows")
    click.echo(f"  masq:           {len(config.masq)} rows")
    click.echo(f"  conntrack:      {len(config.conntrack)} rows")
    click.echo(f"  macros:         {len(config.macros)} defined")
    click.echo(f"  scripts:        {len(config.scripts)} files")

    if target is not None and not dry_run:
        try:
            written = write_config_dir(config, target, force=force)
        except CfgImportError as e:
            click.echo(f"write failed: {e}", err=True)
            sys.exit(2)
        click.echo(f"wrote {len(written)} files to {target}")


@config_group.command("template")
@click.argument("source", type=click.Path(exists=True, dir_okay=False,
                                          path_type=Path),
                required=True)
@click.option("--host", "host_name", required=True,
              help="Target host name. Lines prefixed with `@<other>` "
                   "are dropped, lines prefixed with `@<host>` keep "
                   "the rest of the line, unprefixed lines pass "
                   "through unchanged.")
@click.option("-o", "--output", type=click.Path(path_type=Path),
              default=None,
              help="Write to FILE. Defaults to stdout.")
def config_template(source: Path, host_name: str,
                    output: Path | None) -> None:
    """Expand a multi-host text template against a target host name.

    Implements the prefix-templating convention used by the legacy
    keepalived / conntrackd snapshots: every line that's specific
    to a single host is tagged with ``@<hostname>`` at column 1
    (followed by a tab or space), and lines without a tag are
    shared. This subcommand walks one input file, drops every
    line tagged for a host other than ``--host``, strips the tag
    from lines that match, and emits the result.

    Shorewall config files don't use this convention — only
    keepalived/conntrackd do — so the helper lives here as a
    generic file-level utility rather than a parser feature.

    Example::

        shorewall-nft config template ../legacy/keepalived.conf \\
            --host fw-primary -o /etc/keepalived/keepalived.conf
    """
    import re
    text = source.read_text()
    out_lines: list[str] = []
    # Match lines that begin with `@<word>` followed by ONE
    # whitespace separator. Capturing only one whitespace char
    # (not the whole run) preserves the writer's intended
    # indentation: a row written as `@fw-primary\t\trouter_id fw-primary-legacy`
    # round-trips to `\trouter_id fw-primary-legacy` after the tag + first
    # tab are stripped, keeping the body aligned with the
    # surrounding shared lines.
    tag_re = re.compile(r"^@(\S+)[ \t](.*)$")
    kept = 0
    dropped = 0
    untagged = 0
    for raw in text.splitlines():
        m = tag_re.match(raw)
        if m is None:
            out_lines.append(raw)
            untagged += 1
            continue
        tag = m.group(1)
        rest = m.group(2)
        if tag == host_name:
            out_lines.append(rest)
            kept += 1
        else:
            dropped += 1
            continue

    body = "\n".join(out_lines)
    if not body.endswith("\n"):
        body += "\n"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(body)
        click.echo(
            f"wrote {output} — {kept} kept, {dropped} dropped, "
            f"{untagged} untagged for host {host_name}",
            err=True)
    else:
        click.echo(body, nl=False)


@config_group.command("merge")
@click.argument("sources", nargs=-1, required=True,
                type=click.Path(exists=True, file_okay=False,
                                path_type=Path))
@click.option("--to", "target", required=True,
              type=click.Path(path_type=Path),
              help="Target directory for the merged output. "
                   "Pretty-printed (aligned columns + zone-pair "
                   "grouping + tail-sorted catch-all DROPs).")
@click.option("--force", is_flag=True,
              help="Overwrite --to even if it exists and is "
                   "non-empty.")
@click.option("--provenance", is_flag=True,
              help="Interleave `# from <file>:<lineno>` shell "
                   "comments before each rule so a future bisect "
                   "can blame the origin file/line.")
@click.option("--config-dir-v6", "config_dir_v6",
              type=click.Path(exists=True, file_okay=False,
                              path_type=Path),
              default=None,
              help="Optional v6 sibling for the FIRST source dir. "
                   "When given, the parser merges shorewall + "
                   "shorewall6 into a unified inet config.")
def config_merge(sources: tuple[Path, ...], target: Path, force: bool,
                 provenance: bool, config_dir_v6: Path | None) -> None:
    """Merge one or more Shorewall config directories into a pretty
    unified output (TODO #13: 3-firewall config-merge replay).

    Reads each SOURCE directory in turn, parses it through the
    standard ``load_config`` (with ``shorewall6`` sibling
    auto-detection), and unions the resulting in-memory configs
    into a single ``ShorewalConfig``. The merged result is
    written via ``write_config_dir`` with ``pretty=True``, so
    the on-disk output gets:

      * column alignment per block
      * zone-pair grouping (all ``foo→bar`` rules adjacent)
      * catch-all ``DROP`` / ``REJECT`` rules tail-sorted within
        each zone-pair group
      * optional provenance markers when ``--provenance`` is set

    Multi-source merge semantics: later sources extend earlier
    ones — duplicate rules are appended verbatim (the
    ``_reorder_rules_block`` pass de-dups by sort key only when
    the columns are byte-equal). Settings (``shorewall.conf`` /
    ``params``) follow last-wins on key collisions.

    Use this when re-doing the unified ``/etc/shorewall46``
    layout from a hand-pruned host snapshot — the output is the
    canonical form going forward.
    """
    from shorewall_nft.config.importer import (
        ImportError as CfgImportError,
    )
    from shorewall_nft.config.importer import (
        write_config_dir,
    )
    from shorewall_nft.config.parser import load_config

    if not sources:
        raise click.UsageError("at least one SOURCE directory required")

    merged = None
    total_rules = 0
    for i, src in enumerate(sources):
        c6 = config_dir_v6 if i == 0 else None
        cfg = load_config(src, config6_dir=c6)
        n = len(cfg.rules)
        click.echo(f"loaded {src} → {n} rules, "
                   f"{len(cfg.policy)} policies, "
                   f"{len(cfg.zones)} zones")
        total_rules += n
        if merged is None:
            merged = cfg
            continue
        # Concatenate the columnar lists. Dedup happens after
        # all sources are loaded so the order across sources is
        # preserved (first occurrence wins, later duplicates
        # drop).
        for attr in ("zones", "interfaces", "hosts", "policy",
                     "rules", "blrules", "masq", "conntrack",
                     "notrack", "rawnat", "stoppedrules",
                     "routestopped", "providers", "tunnels",
                     "maclist", "accounting", "tcrules", "mangle",
                     "netmap", "blacklist", "arprules", "proxyarp",
                     "proxyndp", "ecn", "nfacct", "scfilter"):
            existing = getattr(merged, attr, None)
            new = getattr(cfg, attr, None)
            if existing is None:
                setattr(merged, attr, new)
            elif new:
                existing.extend(new)
        # last-wins for KEY=VALUE settings
        for k, v in cfg.settings.items():
            merged.settings[k] = v
        for k, v in cfg.params.items():
            if not k.startswith("__"):
                merged.params[k] = v
        # last-wins for plugin files (plugins.conf + plugins/*.toml +
        # plugins/*.token) and macro definitions. The exporter
        # writes whatever ends up in these dicts byte-for-byte.
        for k, v in (getattr(cfg, "plugin_files", None) or {}).items():
            merged.plugin_files[k] = v
        for k, v in (getattr(cfg, "macros", None) or {}).items():
            merged.macros[k] = v
        for k, v in (getattr(cfg, "scripts", None) or {}).items():
            merged.scripts[k] = v

    assert merged is not None

    # Dedup pass: drop later occurrences of byte-equal rows in
    # the columnar lists. The merge of multiple host snapshots
    # often produces overlapping rules — dedup is the difference
    # between a tidy unified config and a config that lists every
    # rule twice. The match key is ``(section, columns)`` so
    # rules in different ``?SECTION`` blocks (NEW vs ESTABLISHED
    # in the legacy v4 dump) stay separate.
    deduped_total = 0
    for attr in ("zones", "interfaces", "hosts", "policy",
                 "rules", "blrules", "masq", "conntrack",
                 "notrack", "rawnat", "stoppedrules",
                 "routestopped", "providers", "tunnels",
                 "maclist", "accounting", "tcrules", "mangle",
                 "netmap", "blacklist", "arprules", "proxyarp",
                 "proxyndp", "ecn", "nfacct", "scfilter"):
        rows = getattr(merged, attr, None) or []
        if len(rows) < 2:
            continue
        seen: set[tuple] = set()
        out_list = []
        dropped = 0
        for ln in rows:
            key = (ln.section or "", tuple(ln.columns))
            if key in seen:
                dropped += 1
                continue
            seen.add(key)
            out_list.append(ln)
        if dropped:
            setattr(merged, attr, out_list)
            deduped_total += dropped
    if deduped_total:
        click.echo(f"dedup: dropped {deduped_total} byte-equal "
                   f"duplicate rows across all columnar files")
    try:
        written = write_config_dir(
            merged, target, force=force, pretty=True,
            provenance=provenance,
        )
    except CfgImportError as e:
        click.echo(f"merge write failed: {e}", err=True)
        sys.exit(2)
    click.echo(
        f"merged {len(sources)} sources → {target} "
        f"({len(written)} files, {total_rules} rules total"
        + (", with provenance" if provenance else "") + ")")
