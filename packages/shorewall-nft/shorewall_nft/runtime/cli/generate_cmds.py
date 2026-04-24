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
    """Generate tc (traffic control) commands.

    Covers both the advanced tcdevices/tcclasses model and the simple
    tcinterfaces (TBF+prio+SFQ) model.  When CLEAR_TC=Yes a teardown
    section is appended.
    """
    from shorewall_nft.compiler.tc import (
        emit_clear_tc_shell,
        emit_tc_commands,
        emit_tcinterfaces_shell,
        parse_tc_config,
        parse_tcinterfaces,
    )
    from shorewall_nft.config.parser import load_config

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    settings = config.settings
    tc = parse_tc_config(config)
    tcinterfaces = parse_tcinterfaces(getattr(config, "tcinterfaces", []))

    output_parts: list[str] = []

    # Advanced tcdevices/tcclasses section.
    if tc.devices or tc.classes:
        output_parts.append(emit_tc_commands(tc))

    # Simple tcinterfaces section.
    if tcinterfaces:
        fragment = emit_tcinterfaces_shell(tcinterfaces, settings)
        if fragment:
            output_parts.append(fragment)

    # Clear-TC teardown section (all managed interfaces).
    all_ifaces = [d.interface for d in tc.devices] + [t.interface for t in tcinterfaces]
    if all_ifaces:
        from shorewall_nft.compiler.tc import TcInterface
        synthetic = [TcInterface(interface=i) for i in all_ifaces]
        clear_section = emit_clear_tc_shell(synthetic, settings)
        if clear_section:
            output_parts.append("# CLEAR_TC teardown")
            output_parts.append(clear_section)

    if output_parts:
        click.echo("\n".join(output_parts))
    else:
        click.echo("No TC configuration found.")


@click.command("generate-iproute2-rules")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@config_options
def generate_iproute2_rules(directory, config_dir, config_dir_v4, config_dir_v6,
                             no_auto_v4, no_auto_v6):
    """Generate iproute2 routing setup script for multi-ISP providers.

    Reads the providers, routes, and rtrules config files and emits a
    shell script that configures ip rule / ip route for policy routing.
    The script is written to stdout; redirect to a file or pipe into sh.
    """
    from shorewall_nft.compiler.ir import build_ir
    from shorewall_nft.compiler.providers import emit_iproute2_setup
    from shorewall_nft.config.parser import load_config

    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    config = load_config(primary, config6_dir=secondary,
                         skip_sibling_merge=skip)
    ir = build_ir(config)
    script = emit_iproute2_setup(
        ir.providers,
        ir.routes,
        ir.rtrules,
        config.settings,
    )
    click.echo(script, nl=False)
