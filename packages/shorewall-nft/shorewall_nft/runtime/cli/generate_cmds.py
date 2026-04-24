"""generate-* commands: emit static artefacts (no kernel apply).

Covers: generate-sysctl, generate-systemd, generate-conntrackd,
generate-tc, generate-set-loader.
"""

from __future__ import annotations

from pathlib import Path

import click

from shorewall_nft.runtime.cli._common import (
    _resolve_config_paths,
    config_options,
)


@click.command("generate-set-loader")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
def generate_set_loader(directory, config_dir, config_dir_v4, config_dir_v6,
                        no_auto_v4, no_auto_v6):
    """Generate a shell script that loads external sets."""
    from shorewall_nft.nft.set_loader import generate_set_loader_script

    primary, _, _ = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    click.echo(generate_set_loader_script(primary))


@click.command("generate-sysctl")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
def generate_sysctl(directory, config_dir, config_dir_v4, config_dir_v6,
                    no_auto_v4, no_auto_v6):
    """Generate sysctl configuration script."""
    from shorewall_nft.compiler.sysctl import generate_sysctl_script
    from shorewall_nft.config.parser import load_config

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    click.echo(generate_sysctl_script(config))


@click.command("generate-systemd")
@click.option("--with-netns", is_flag=True, help="Generate template for network namespace deployments.")
@click.option("-o", "--output-dir", type=click.Path(path_type=Path), default=None)
def generate_systemd(with_netns: bool, output_dir: Path | None):
    """Generate systemd service files."""
    from shorewall_nft.netns.systemd import generate_netns_service, generate_service

    if with_netns:
        content = generate_netns_service()
        filename = "shorewall-nft@.service"
    else:
        content = generate_service()
        filename = "shorewall-nft.service"

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / filename).write_text(content)
        click.echo(f"Written to {output_dir / filename}")
    else:
        click.echo(content)


@click.command("generate-conntrackd")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--sync-iface", default=None,
              help="Interface used for the conntrackd sync link. "
                   "Defaults to the CONNTRACKD_IFACE setting.")
@click.option("--peer-ip", default=None,
              help="IPv4 of the other HA node on the sync link.")
@click.option("--local-ip", default=None,
              help="IPv4 of this node on the sync link.")
@click.option("--cluster-ip", default=None,
              help="Shared VIP that HA failover moves.")
@config_options
def generate_conntrackd(directory, sync_iface, peer_ip, local_ip, cluster_ip,
                        config_dir, config_dir_v4, config_dir_v6,
                        no_auto_v4, no_auto_v6):
    """Generate a conntrackd.conf fragment for an HA firewall pair.

    Honours CT_ZONE_TAG_MASK to build a Mark filter that replicates
    only zone bits across the sync link, keeping routing / policy
    marks local to each node.
    """
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.runtime.conntrackd import generate_conntrackd_fragment

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    click.echo(generate_conntrackd_fragment(
        config,
        sync_iface=sync_iface,
        peer_ip=peer_ip,
        local_ip=local_ip,
        cluster_ip=cluster_ip,
    ))


@click.command("generate-tc")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
def generate_tc(directory, config_dir, config_dir_v4, config_dir_v6,
                no_auto_v4, no_auto_v6):
    """Generate tc (traffic control) commands."""
    from shorewall_nft.compiler.tc import emit_tc_commands, parse_tc_config
    from shorewall_nft.config.parser import load_config

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    tc = parse_tc_config(config)
    if tc.devices or tc.classes:
        click.echo(emit_tc_commands(tc))
    else:
        click.echo("No TC configuration found.")
