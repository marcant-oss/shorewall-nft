"""Traffic Control / Mangle rule processing.

Handles:
- MARK, CONNMARK actions and tcrules/mangle files
- tcdevices, tcinterfaces, tcclasses, tcfilters, tcpri configs
- Translates to nft meta mark set / ct mark set statements

Note: nftables does not do tc/qdisc directly. TC shaping is handled
by setting marks in nft which are then used by tc qdiscs configured
separately. The tcdevices/tcclasses/tcfilters configs generate the
corresponding `tc` commands, not nft rules.

Native kernel apply path: ``apply_tc`` and ``apply_tcinterfaces`` use
pyroute2 to configure qdiscs/classes/filters directly via netlink —
no tc(8) binary needed.  The ``emit_tc_commands`` / ``generate-tc``
bash-script path is kept as a portable fallback.

TC mode toggles (WP-C4):
- TC_ENABLED=Internal (default): full qdisc/class setup emitted.
- TC_ENABLED=No: all TC emission skipped.
- TC_ENABLED=Yes or Shared: only mark rules are emitted; qdisc/class
  setup is the operator's responsibility (external TC).
- TC_EXPERT=Yes: skip the mark-mask collision guard.
- MARK_IN_FORWARD_CHAIN=Yes: emit packet-mark rules in FORWARD instead
  of PREROUTING.
- CLEAR_TC=Yes: emit ``tc qdisc del dev <iface> root`` per managed
  interface during clear/stop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from shorewall_nft.compiler.ir import (
    Chain,
    ChainType,
    FirewallIR,
    Hook,
    Match,
    Rule,
    Verdict,
    expand_line_for_tokens,
)
from shorewall_nft.compiler.ir._data import TcInterface, TcPri
from shorewall_nft.compiler.verdicts import (
    ClassifyVerdict,
    ConnmarkVerdict,
    DscpVerdict,
    MarkVerdict,
    RestoreMarkVerdict,
    SaveMarkVerdict,
)
from shorewall_nft.config.parser import ConfigLine
from shorewall_nft.config.zones import ZoneModel
from shorewall_nft.runtime.pyroute2_helpers import resolve_iface_idx, settings_bool

logger = logging.getLogger("shorewall_nft.compiler.tc")

# Re-export so existing ``from shorewall_nft.compiler.tc import TcInterface, TcPri``
# imports continue to work unchanged.
__all__ = ["TcInterface", "TcPri"]


@dataclass
class TcDevice:
    """A traffic-controlled device."""
    interface: str
    in_bandwidth: str = ""
    out_bandwidth: str = ""
    options: list[str] = field(default_factory=list)
    redirect: str = ""


@dataclass
class TcClass:
    """A traffic class with rate/ceiling."""
    interface: str
    mark: int
    rate: str
    ceil: str = ""
    priority: int = 1
    options: list[str] = field(default_factory=list)


@dataclass
class TcFilter:
    """A filter to classify traffic into a TC class."""
    tc_class: str  # CLASS reference
    source: str = "-"
    dest: str = "-"
    proto: str = "-"
    dport: str = "-"
    sport: str = "-"
    tos: str = "-"
    length: str = "-"


@dataclass
class TcConfig:
    """Complete TC configuration."""
    devices: list[TcDevice] = field(default_factory=list)
    classes: list[TcClass] = field(default_factory=list)
    filters: list[TcFilter] = field(default_factory=list)


# ── TC mode helpers ──────────────────────────────────────────────────────────

def _tc_enabled_mode(settings: dict[str, str]) -> str:
    """Return normalised TC_ENABLED value: 'Internal', 'Yes', 'Shared', or ''.

    '' means TC_ENABLED=No (disabled).
    """
    raw = settings.get("TC_ENABLED", "Internal").strip().lower()
    _MAP = {
        "internal": "Internal",
        "yes": "Yes",
        "shared": "Shared",
        "simple": "Simple",
        "no": "",
        "": "",
    }
    return _MAP.get(raw, "Internal")


def _tc_expert(settings: dict[str, str]) -> bool:
    return settings_bool(settings, "TC_EXPERT", False)


def _mark_in_forward(settings: dict[str, str]) -> bool:
    return settings_bool(settings, "MARK_IN_FORWARD_CHAIN", False)


def _clear_tc(settings: dict[str, str]) -> bool:
    return settings_bool(settings, "CLEAR_TC", False)


# ── Parse helpers ────────────────────────────────────────────────────────────

def _parse_out_bandwidth_field(raw: str) -> tuple[str, str, str, str, str]:
    """Split OUT_BANDWIDTH into (bw, burst, latency, peak, minburst).

    Upstream format: bw[:burst[:latency[:peak[:minburst]]]]
    """
    if not raw or raw == "-":
        return ("", "10kb", "200ms", "", "")
    parts = raw.split(":")
    bw = parts[0] if parts else ""
    burst = parts[1] if len(parts) > 1 and parts[1] else "10kb"
    latency = parts[2] if len(parts) > 2 and parts[2] else "200ms"
    peak = parts[3] if len(parts) > 3 else ""
    minburst = parts[4] if len(parts) > 4 else ""
    return (bw, burst, latency, peak, minburst)


def parse_tcinterfaces(lines: list) -> "list[TcInterface]":
    """Parse tcinterfaces config lines into TcInterface objects.

    Upstream columns: INTERFACE TYPE IN_BANDWIDTH OUT_BANDWIDTH
    TYPE values: 'external' → 'nfct-src', 'internal' → 'dst', '-' → '-'
    OUT_BANDWIDTH may carry :burst:latency:peak:minburst suffixes.
    """
    result: list[TcInterface] = []
    for line in lines:
        cols = line.columns
        if len(cols) < 1:
            continue
        iface = cols[0]
        if iface == "-":
            continue

        raw_type = cols[1] if len(cols) > 1 else "-"
        raw_type_lc = raw_type.lower()
        if raw_type_lc == "external":
            flow_type = "nfct-src"
        elif raw_type_lc == "internal":
            flow_type = "dst"
        else:
            flow_type = "-"

        raw_in = cols[2] if len(cols) > 2 else "-"
        in_bw = raw_in if raw_in and raw_in != "-" else ""

        raw_out = cols[3] if len(cols) > 3 else "-"
        out_bw, out_burst, out_latency, out_peak, out_minburst = _parse_out_bandwidth_field(raw_out)

        result.append(TcInterface(
            interface=iface,
            flow_type=flow_type,
            in_bandwidth=in_bw,
            out_bandwidth=out_bw,
            out_burst=out_burst,
            out_latency=out_latency,
            out_peak=out_peak,
            out_minburst=out_minburst,
        ))
    return result


def parse_tcpri(lines: list) -> "list[TcPri]":
    """Parse tcpri config lines into TcPri objects.

    Upstream columns: BAND PROTO PORT ADDRESS INTERFACE HELPER
    BAND must be 1–3.  At least one of PROTO/PORT/ADDRESS/INTERFACE/HELPER
    must be set (not '-').
    """
    result: list[TcPri] = []
    for line in lines:
        cols = line.columns
        if len(cols) < 1:
            continue
        try:
            band = int(cols[0])
        except (ValueError, IndexError):
            continue
        if band < 1 or band > 3:
            continue

        proto = cols[1] if len(cols) > 1 and cols[1] != "-" else "-"
        port = cols[2] if len(cols) > 2 and cols[2] != "-" else "-"
        address = cols[3] if len(cols) > 3 and cols[3] != "-" else "-"
        interface = cols[4] if len(cols) > 4 and cols[4] != "-" else "-"
        helper = cols[5] if len(cols) > 5 and cols[5] != "-" else "-"

        if proto == "-" and port == "-" and address == "-" and interface == "-" and helper == "-":
            continue

        result.append(TcPri(
            band=band, proto=proto, port=port,
            address=address, interface=interface, helper=helper,
        ))
    return result


# ── Shell-script generators ──────────────────────────────────────────────────

def emit_tcinterfaces_shell(tcinterfaces: "list[TcInterface]",
                             settings: "dict[str, str] | None" = None) -> str:
    """Generate shell tc commands for simple-device shaping (tcinterfaces file).

    Mirrors the Perl ``process_simple_device`` / ``setup_${dev}_tc``
    function output.  Returns a shell fragment suitable for inclusion in
    the ``generate-tc`` script.

    TC_ENABLED=No: returns empty string.
    TC_ENABLED=Yes or Shared: returns empty string (operator manages qdiscs).
    TC_ENABLED=Internal (default): returns full qdisc setup.
    CLEAR_TC=Yes: includes ``tc qdisc del`` teardown lines.
    """
    if settings is None:
        settings = {}
    mode = _tc_enabled_mode(settings)
    if not mode or mode in ("Yes", "Shared"):
        return ""

    clear = _clear_tc(settings)
    lines: list[str] = []

    for dev in tcinterfaces:
        iface = dev.interface
        lines.append(f"# Simple TC device: {iface}")
        lines.append(f"if ip link show {iface} > /dev/null 2>&1; then")

        if clear:
            lines.append(f"  tc qdisc del dev {iface} root 2>/dev/null || true")
            lines.append(f"  tc qdisc del dev {iface} ingress 2>/dev/null || true")
        else:
            lines.append(f"  tc qdisc del dev {iface} root 2>/dev/null || true")
            lines.append(f"  tc qdisc del dev {iface} ingress 2>/dev/null || true")

        if dev.in_bandwidth:
            lines.append(f"  tc qdisc add dev {iface} ingress handle ffff:")
            lines.append(
                f"  tc filter add dev {iface} parent ffff: protocol all"
                f" u32 match u32 0 0 police rate {dev.in_bandwidth} burst 10k drop"
            )

        if dev.out_bandwidth:
            tbf_cmd = (
                f"  tc qdisc add dev {iface} root handle 1: tbf"
                f" rate {dev.out_bandwidth}"
                f" burst {dev.out_burst}"
                f" latency {dev.out_latency}"
                f" mpu 64"
            )
            if dev.out_peak:
                tbf_cmd += f" peakrate {dev.out_peak}"
            if dev.out_minburst:
                tbf_cmd += f" minburst {dev.out_minburst}"
            lines.append(tbf_cmd)
            lines.append(f"  tc qdisc add dev {iface} parent 1:1 handle 100: prio bands 3")

            for band in (1, 2, 3):
                lines.append(f"  tc qdisc add dev {iface} parent 100:{band} sfq quantum 1875 limit 127 perturb 10")
                lines.append(f"  tc filter add dev {iface} protocol all prio {16 + band} parent 100: handle {band} fw classid 100:{band}")
                if dev.flow_type != "-":
                    lines.append(
                        f"  tc filter add dev {iface} protocol all prio 1"
                        f" parent 100{band}: handle {band + 3}"
                        f" flow hash keys {dev.flow_type} divisor 1024"
                    )
                lines.append("")

        lines.append("else")
        lines.append(f"  echo 'WARNING: Device {iface} is not UP — TC skipped' >&2")
        lines.append("fi")
        lines.append("")

    return "\n".join(lines)


def emit_tcpri_nft(tcpris: "list[TcPri]", settings: "dict[str, str] | None" = None) -> str:
    """Emit nft mangle rules that set meta priority (tc handle) from tcpri rows.

    Upstream: ``process_tc_priority1`` marks packets in the mangle table
    using ``MARK --set-mark <band>``.  In nft the equivalent is
    ``meta mark set <band>`` in the mangle-prerouting chain (or forward
    chain when MARK_IN_FORWARD_CHAIN=Yes).

    Returns a raw nft rule fragment string.  The caller (build_ir) is
    responsible for inserting these rules into the correct chain.
    Returns empty string when TC_ENABLED=No or no tcpris.
    """
    if settings is None:
        settings = {}
    mode = _tc_enabled_mode(settings)
    if not mode:
        return ""
    if not tcpris:
        return ""

    forward_chain = _mark_in_forward(settings)
    chain_name = "forward" if forward_chain else "mangle-prerouting"
    lines: list[str] = []
    lines.append(f"# tcpri DSCP/proto → priority mark rules (chain: {chain_name})")

    for entry in tcpris:
        mark = entry.band
        parts: list[str] = []

        if entry.interface != "-":
            parts.append(f"iifname {entry.interface!r}")

        if entry.address != "-":
            parts.append(f"ip saddr {entry.address}")

        if entry.proto != "-":
            parts.append(f"meta l4proto {entry.proto}")
            if entry.port != "-":
                parts.append(f"{entry.proto} dport {entry.port}")

        match_str = " ".join(parts)
        lines.append(f"  {match_str} meta mark set {mark}")

    return "\n".join(lines)


# ── pyroute2 apply path for tcinterfaces ────────────────────────────────────

@dataclass
class TcInterfaceApplyResult:
    """Summary of a tcinterfaces native apply via pyroute2."""
    applied: int
    failed: int
    errors: list[str]


def apply_tcinterfaces(
    tcinterfaces: "list[TcInterface]",
    settings: "dict[str, str] | None" = None,
    *,
    netns: str | None = None,
) -> TcInterfaceApplyResult:
    """Apply simple-device TC setup via pyroute2.

    Configures TBF root qdisc + prio qdisc + SFQ leaf qdiscs and fw
    filters for each interface in *tcinterfaces* directly via netlink —
    no tc(8) binary required.  Opens ``IPRoute(netns=netns)`` when
    *netns* is set; otherwise uses the default (caller's) network
    namespace.

    TC_ENABLED=No: returns immediately with applied=0, failed=0.
    TC_ENABLED=Yes or Shared: skips qdisc setup (operator manages TC),
    returns applied=0, failed=0.

    Idempotence: root and ingress qdiscs are deleted then re-added.
    NetlinkError(errno=ENOENT) during the delete step is silently
    ignored.
    """
    if settings is None:
        settings = {}

    mode = _tc_enabled_mode(settings)
    if not mode or mode in ("Yes", "Shared"):
        return TcInterfaceApplyResult(applied=0, failed=0, errors=[])

    try:
        from pyroute2 import IPRoute
    except ImportError:
        return TcInterfaceApplyResult(
            applied=0, failed=0,
            errors=["pyroute2 not installed — cannot apply tcinterfaces natively"],
        )

    applied = 0
    failed = 0
    errors: list[str] = []

    def _record_error(msg: str) -> None:
        nonlocal failed
        failed += 1
        errors.append(msg)
        logger.warning("apply_tcinterfaces: %s", msg)

    try:
        ipr: IPRoute = IPRoute(netns=netns) if netns else IPRoute()
    except Exception as ex:
        return TcInterfaceApplyResult(
            applied=0, failed=0,
            errors=[f"IPRoute init failed: {ex}"],
        )

    iface_idx: dict[str, int] = {}

    try:
        for dev in tcinterfaces:
            idx = resolve_iface_idx(ipr, dev.interface, iface_idx)
            if idx is None:
                _record_error(f"tcinterface {dev.interface!r}: not found, skipped")
                continue

            # Teardown existing qdiscs (idempotent).
            for qdisc_handle, qdisc_kind in ((0x10000, "tbf"), (0xffff0000, "ingress")):
                try:
                    ipr.tc("del", qdisc_kind, idx, qdisc_handle)
                except Exception as ex:
                    code = getattr(ex, "code", None)
                    if code != 2:  # not ENOENT
                        logger.debug("apply_tcinterfaces: del %s on %s: %s",
                                     qdisc_kind, dev.interface, ex)

            # Ingress qdisc for in_bandwidth policing.
            if dev.in_bandwidth:
                try:
                    ipr.tc("add", "ingress", idx, 0xffff0000)
                    applied += 1
                except Exception as ex:
                    _record_error(f"tcinterface {dev.interface!r}: add ingress qdisc: {ex}")

            # Root TBF qdisc + prio + SFQ leaves for out_bandwidth.
            if dev.out_bandwidth:
                try:
                    ipr.tc(
                        "add", "tbf", idx, 0x10000,
                        rate=dev.out_bandwidth,
                        burst=dev.out_burst or "10kb",
                        latency=dev.out_latency or "200ms",
                    )
                    applied += 1
                except Exception as ex:
                    _record_error(
                        f"tcinterface {dev.interface!r}: add tbf root qdisc: {ex}")
                    continue

                # Parent 1: — add prio qdisc (handle 0x01000000 = 100:)
                prio_handle = 0x01000000
                try:
                    ipr.tc("add", "prio", idx, prio_handle,
                           parent=0x10000, bands=3)
                    applied += 1
                except Exception as ex:
                    _record_error(
                        f"tcinterface {dev.interface!r}: add prio qdisc: {ex}")
                    continue

                # SFQ leaf qdiscs and fw filters for bands 1–3.
                for band in (1, 2, 3):
                    sfq_handle = (prio_handle | band) << 4
                    parent = prio_handle | band
                    try:
                        ipr.tc("add", "sfq", idx, sfq_handle,
                               parent=parent, quantum=1875, limit=127, perturb=10)
                        applied += 1
                    except Exception as ex:
                        _record_error(
                            f"tcinterface {dev.interface!r} band {band}: add sfq: {ex}")
                        continue

                    classid = prio_handle | band
                    try:
                        ipr.tc(
                            "add-filter", "fw", idx,
                            parent=prio_handle,
                            prio=16 + band,
                            handle=band,
                            classid=classid,
                        )
                        applied += 1
                    except Exception as ex:
                        _record_error(
                            f"tcinterface {dev.interface!r} band {band}: add fw filter: {ex}")

    finally:
        try:
            ipr.close()
        except Exception:
            pass

    return TcInterfaceApplyResult(applied=applied, failed=failed, errors=errors)


def emit_clear_tc_shell(tcinterfaces: "list[TcInterface]",
                         settings: "dict[str, str] | None" = None) -> str:
    """Generate ``tc qdisc del`` teardown lines for use in stop/clear.

    Only emits when CLEAR_TC=Yes in *settings*.  Returns empty string
    otherwise.
    """
    if settings is None:
        settings = {}
    if not _clear_tc(settings):
        return ""

    lines: list[str] = []
    for dev in tcinterfaces:
        iface = dev.interface
        lines.append(f"tc qdisc del dev {iface} root 2>/dev/null || true")
        lines.append(f"tc qdisc del dev {iface} ingress 2>/dev/null || true")
    return "\n".join(lines)


def parse_tc_config(config) -> TcConfig:
    """Parse TC config files into a TcConfig."""
    tc = TcConfig()

    for line in config.tcdevices:
        cols = line.columns
        if len(cols) < 3:
            continue
        tc.devices.append(TcDevice(
            interface=cols[0],
            in_bandwidth=cols[1] if cols[1] != "-" else "",
            out_bandwidth=cols[2] if cols[2] != "-" else "",
            options=cols[3].split(",") if len(cols) > 3 and cols[3] != "-" else [],
            redirect=cols[4] if len(cols) > 4 and cols[4] != "-" else "",
        ))

    for line in config.tcclasses:
        cols = line.columns
        if len(cols) < 4:
            continue
        try:
            mark = int(cols[1])
        except ValueError:
            continue
        tc.classes.append(TcClass(
            interface=cols[0],
            mark=mark,
            rate=cols[2],
            ceil=cols[3] if len(cols) > 3 and cols[3] != "-" else "",
            priority=int(cols[4]) if len(cols) > 4 and cols[4] != "-" else 1,
            options=cols[5].split(",") if len(cols) > 5 and cols[5] != "-" else [],
        ))

    for line in config.tcfilters:
        cols = line.columns
        if len(cols) < 1:
            continue
        tc.filters.append(TcFilter(
            tc_class=cols[0],
            source=cols[1] if len(cols) > 1 else "-",
            dest=cols[2] if len(cols) > 2 else "-",
            proto=cols[3] if len(cols) > 3 else "-",
            dport=cols[4] if len(cols) > 4 else "-",
            sport=cols[5] if len(cols) > 5 else "-",
            tos=cols[6] if len(cols) > 6 else "-",
            length=cols[7] if len(cols) > 7 else "-",
        ))

    return tc


def emit_tc_commands(tc: TcConfig) -> str:
    """Generate tc (traffic control) shell commands for QoS setup.

    These commands configure Linux kernel qdiscs and classes.
    They are NOT nft rules but complementary tc setup.
    """
    lines: list[str] = []
    lines.append("#!/bin/sh")
    lines.append("# Generated by shorewall-nft — tc/qdisc setup")
    lines.append("# Run this separately to configure traffic shaping")
    lines.append("")

    for dev in tc.devices:
        lines.append(f"# Device: {dev.interface}")
        if dev.out_bandwidth:
            lines.append(f"tc qdisc del dev {dev.interface} root 2>/dev/null")
            lines.append(f"tc qdisc add dev {dev.interface} root handle 1: htb default 1")
            lines.append(f"tc class add dev {dev.interface} parent 1: classid 1:1 htb rate {dev.out_bandwidth}")
        if dev.in_bandwidth:
            lines.append(f"tc qdisc del dev {dev.interface} ingress 2>/dev/null")
            lines.append(f"tc qdisc add dev {dev.interface} ingress")
        lines.append("")

    for cls in tc.classes:
        ceil = cls.ceil or cls.rate
        lines.append(f"tc class add dev {cls.interface} parent 1:1 classid 1:{cls.mark} htb rate {cls.rate} ceil {ceil} prio {cls.priority}")

    return "\n".join(lines)


@dataclass
class TcApplyResult:
    """Summary of a native TC apply operation via pyroute2."""
    applied: int
    failed: int
    errors: list[str]


def apply_tc(tc: TcConfig, *, netns: str | None = None) -> TcApplyResult:
    """Apply TC config via pyroute2.

    Configures kernel qdiscs, classes, and fwmark filters directly
    via netlink — no tc(8) binary required.  Opens
    ``IPRoute(netns=netns)`` when *netns* is set, otherwise uses the
    default (caller's) network namespace.

    Idempotence: qdiscs are deleted then re-added (same semantics as
    the bash script ``emit_tc_commands`` generates).  A
    ``NetlinkError`` with ``errno=ENOENT`` (2) during the delete step
    is silently ignored — the qdisc was simply not present yet.

    Returns a :class:`TcApplyResult` with counts of successfully
    applied and failed operations.  Failed operations are logged at
    WARNING level; no exception is raised.
    """
    try:
        from pyroute2 import IPRoute
        from pyroute2.netlink.exceptions import NetlinkError
    except ImportError:
        return TcApplyResult(
            applied=0, failed=0,
            errors=["pyroute2 not installed — cannot apply TC config natively"],
        )

    applied = 0
    failed = 0
    errors: list[str] = []

    def _record_error(msg: str) -> None:
        nonlocal failed
        failed += 1
        errors.append(msg)
        logger.warning("apply_tc: %s", msg)

    try:
        ipr: IPRoute = IPRoute(netns=netns) if netns else IPRoute()
    except Exception as ex:
        return TcApplyResult(
            applied=0, failed=0,
            errors=[f"IPRoute init failed: {ex}"],
        )

    # Cache interface name → index.
    iface_idx: dict[str, int] = {}

    try:
        # ── Devices: root HTB qdisc (egress) and ingress qdisc ──────────
        for dev in tc.devices:
            idx = resolve_iface_idx(ipr, dev.interface, iface_idx)
            if idx is None:
                _record_error(
                    f"device {dev.interface!r}: interface not found, skipped")
                continue

            if dev.out_bandwidth:
                # Teardown existing root qdisc (idempotent).
                try:
                    ipr.tc("del", "htb", idx, 0x10000)
                except NetlinkError as ex:
                    if ex.code != 2:  # ENOENT → already absent
                        _record_error(
                            f"device {dev.interface!r}: "
                            f"del root qdisc failed: {ex}")
                        continue

                # Add HTB root qdisc: handle 1: default class 1.
                try:
                    ipr.tc("add", "htb", idx, 0x10000, default=1)
                except NetlinkError as ex:
                    _record_error(
                        f"device {dev.interface!r}: "
                        f"add root htb qdisc failed: {ex}")
                    continue

                # Add root class 1:1 with out_bandwidth as rate and ceil.
                try:
                    ipr.tc(
                        "add", "htb", idx,
                        handle=0x00010001,   # classid 1:1
                        parent=0x10000,      # parent 1:
                        rate=dev.out_bandwidth,
                        ceil=dev.out_bandwidth,
                        prio=0,
                    )
                    applied += 1
                except NetlinkError as ex:
                    _record_error(
                        f"device {dev.interface!r}: "
                        f"add root class 1:1 failed: {ex}")
                    continue

            if dev.in_bandwidth:
                # Teardown existing ingress qdisc (idempotent).
                try:
                    ipr.tc("del", "ingress", idx, 0xffff0000)
                except NetlinkError as ex:
                    if ex.code != 2:  # ENOENT → already absent
                        _record_error(
                            f"device {dev.interface!r}: "
                            f"del ingress qdisc failed: {ex}")
                        # Non-fatal; attempt add anyway.

                try:
                    ipr.tc("add", "ingress", idx, 0xffff0000)
                    applied += 1
                except NetlinkError as ex:
                    _record_error(
                        f"device {dev.interface!r}: "
                        f"add ingress qdisc failed: {ex}")

        # ── Classes: HTB leaf classes under root class 1:1 ──────────────
        for cls in tc.classes:
            idx = resolve_iface_idx(ipr, cls.interface, iface_idx)
            if idx is None:
                _record_error(
                    f"class {cls.interface!r}/{cls.mark}: "
                    f"interface not found, skipped")
                continue

            ceil = cls.ceil or cls.rate
            # classid 1:<mark>  parent 1:1
            classid = (1 << 16) | (cls.mark & 0xFFFF)
            parent = 0x00010001  # 1:1
            try:
                ipr.tc(
                    "add", "htb", idx,
                    handle=classid,
                    parent=parent,
                    rate=cls.rate,
                    ceil=ceil,
                    prio=cls.priority,
                )
                applied += 1
            except NetlinkError as ex:
                _record_error(
                    f"class {cls.interface!r}/{cls.mark}: "
                    f"add htb class failed: {ex}")

        # ── Filters: fwmark → classid mapping ───────────────────────────
        # Each TcFilter references a CLASS string like "eth0:1".
        # We add a fw (fwmark) filter: protocol ip parent 1:0 prio 1
        # handle <mark> fw classid 1:<mark>
        for flt in tc.filters:
            # Parse "INTERFACE:MARK" from tc_class field.
            if ":" not in flt.tc_class:
                _record_error(
                    f"filter class {flt.tc_class!r}: "
                    f"expected INTERFACE:MARK, skipped")
                continue
            iface_part, mark_part = flt.tc_class.rsplit(":", 1)
            try:
                mark_int = int(mark_part)
            except ValueError:
                _record_error(
                    f"filter class {flt.tc_class!r}: "
                    f"mark {mark_part!r} not an integer, skipped")
                continue

            idx = resolve_iface_idx(ipr, iface_part, iface_idx)
            if idx is None:
                _record_error(
                    f"filter {flt.tc_class!r}: "
                    f"interface {iface_part!r} not found, skipped")
                continue

            classid = (1 << 16) | (mark_int & 0xFFFF)
            # parent 1:0  (root qdisc handle, minor=0)
            parent = 0x10000
            try:
                ipr.tc(
                    "add-filter", "fw", idx,
                    parent=parent,
                    prio=1,
                    handle=mark_int,
                    classid=classid,
                )
                applied += 1
            except NetlinkError as ex:
                _record_error(
                    f"filter {flt.tc_class!r}: "
                    f"add fw filter failed: {ex}")

    finally:
        try:
            ipr.close()
        except Exception:
            pass

    return TcApplyResult(applied=applied, failed=failed, errors=errors)


def _parse_mark_verdict(raw: str) -> MarkVerdict:
    """Parse a MARK action value like ``"0x10"`` or ``"0x10/0xff"``."""
    if "/" in raw:
        val, mask = raw.split("/", 1)
        return MarkVerdict(value=int(val, 0), mask=int(mask, 0))
    return MarkVerdict(value=int(raw, 0))


def process_mangle(ir: FirewallIR, tcrules: list[ConfigLine],
                   mangle: list[ConfigLine], zones: ZoneModel) -> None:
    """Process mangle/tcrules into nft mark rules."""
    if not tcrules and not mangle:
        return

    if "mangle-prerouting" not in ir.chains:
        ir.add_chain(Chain(
            name="mangle-prerouting",
            chain_type=ChainType.ROUTE,
            hook=Hook.PREROUTING,
            priority=-150,
        ))

    for line in tcrules + mangle:
        _process_mark_rule(ir, line, zones)


def _process_mark_rule(ir: FirewallIR, line: ConfigLine,
                       zones: ZoneModel) -> None:
    """Process a single MARK/CONNMARK rule.

    tcrules format: MARK_VALUE SOURCE DEST PROTO PORT(S) ...
    mangle format:  ACTION SOURCE DEST PROTO PORT(S) ...

    SOURCE (col 1) and DEST (col 2) accept nfset:/dns:/dnsr: tokens.
    When tokens are present the rule is cloned for v4 and v6 families.
    """
    cols = line.columns
    if len(cols) < 2:
        return

    # nfset/dns/dnsr token pre-pass on SOURCE(col 1) + DEST(col 2).
    found, expanded = expand_line_for_tokens(line, 1, 2, ir)
    if found:
        for exp_line in expanded:
            _process_mark_rule(ir, exp_line, zones)
        return

    action = cols[0]
    source_spec = cols[1] if len(cols) > 1 else "-"
    dest_spec = cols[2] if len(cols) > 2 else "-"
    proto = cols[3] if len(cols) > 3 else None
    dport = cols[4] if len(cols) > 4 else None

    if proto == "-":
        proto = None
    if dport == "-":
        dport = None

    chain = ir.chains["mangle-prerouting"]
    rule = Rule(
        source_file=line.file,
        source_line=line.lineno,
    )

    if action.startswith("MARK("):
        mark_val = action[5:].rstrip(")")
        rule.verdict = Verdict.ACCEPT
        rule.verdict_args = _parse_mark_verdict(mark_val)
    elif action.startswith("CONNMARK("):
        mark_val = action[9:].rstrip(")")
        rule.verdict = Verdict.ACCEPT
        rule.verdict_args = ConnmarkVerdict(value=int(mark_val, 0))
    elif action.startswith("RESTORE"):
        rule.verdict = Verdict.ACCEPT
        rule.verdict_args = RestoreMarkVerdict()
    elif action.startswith("SAVE"):
        rule.verdict = Verdict.ACCEPT
        rule.verdict_args = SaveMarkVerdict()
    elif action.startswith("DSCP("):
        dscp_val = action[5:].rstrip(")")
        rule.verdict = Verdict.ACCEPT
        rule.verdict_args = DscpVerdict(value=dscp_val)
    elif action.startswith("CLASSIFY("):
        classify_val = action[9:].rstrip(")")
        rule.verdict = Verdict.ACCEPT
        rule.verdict_args = ClassifyVerdict(value=classify_val)
    else:
        try:
            int(action, 0)
        except ValueError:
            logger.warning(
                "%s:%d: tc/mangle action %r is not MARK/CONNMARK/RESTORE/"
                "SAVE/DSCP/CLASSIFY and not a bare mark integer — rule "
                "skipped (no nft emit). Fix the action token or remove "
                "the line.",
                line.file, line.lineno, action,
            )
            return
        rule.verdict = Verdict.ACCEPT
        rule.verdict_args = _parse_mark_verdict(action)

    if source_spec and source_spec != "-":
        # A rewritten set sentinel starts with '+'; use directly as addr.
        if source_spec.startswith("+") or source_spec.startswith("!+"):
            rule.matches.append(Match(field="ip saddr", value=source_spec))
        elif ":" in source_spec:
            _, addr = source_spec.split(":", 1)
            if addr:
                rule.matches.append(Match(field="ip saddr", value=addr))

    if dest_spec and dest_spec != "-":
        # A rewritten set sentinel starts with '+'; use directly as addr.
        if dest_spec.startswith("+") or dest_spec.startswith("!+"):
            rule.matches.append(Match(field="ip daddr", value=dest_spec))
        elif ":" in dest_spec:
            _, addr = dest_spec.split(":", 1)
            if addr:
                rule.matches.append(Match(field="ip daddr", value=addr))

    if proto:
        rule.matches.append(Match(field="meta l4proto", value=proto))
        if dport:
            rule.matches.append(Match(field=f"{proto} dport", value=dport))

    chain.rules.append(rule)
