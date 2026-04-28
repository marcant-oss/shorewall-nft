"""Zone and interface model for Shorewall configuration.

Parses zones, interfaces, and hosts config files into a structured model.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from shorewall_nft.config.parser import ShorewalConfig


@dataclass
class Interface:
    """A network interface assigned to a zone."""
    name: str
    zone: str
    broadcast: str | None = None
    options: list[str] = field(default_factory=list)
    # Parsed option values for options that take a value (e.g. mss=1452).
    # Keys match the option name without the "=" suffix.
    option_values: dict[str, str] = field(default_factory=dict)

    @property
    def emit_name(self) -> str:
        """Kernel-visible name for nft ``iifname``/``oifname`` matchers.

        When the interface declares ``physical=NAME`` (Shorewall alias
        used for VLAN trunks, dummy interfaces, or any case where the
        logical zone-config name differs from the kernel name) the
        physical override wins. Otherwise the logical name is used.
        """
        return self.option_values.get("physical") or self.name

    @property
    def dbl_skip_src(self) -> bool:
        """Whether to skip this iface from dynamic-blacklist src-matching.

        Honours Perl ``dbl`` / ``nodbl`` semantics:
          * ``nodbl``         → skip (Perl: ``dbl=0:0``)
          * ``dbl=none``      → skip
          * ``dbl=dst``       → skip src-match (dst-only spec — the
                                companion dst-emit lives in
                                ``_process_dbl_dst_interfaces``)
          * ``dbl=src``       → include (Perl default behaviour)
          * ``dbl=src-dst``   → include (src part)
          * unspecified       → include (matches existing emit)
        """
        if "nodbl" in self.options:
            return True
        return self.option_values.get("dbl") in ("none", "dst")

    @property
    def dbl_dst_active(self) -> bool:
        """Whether this iface needs dst-side dynamic-blacklist matching.

        True for ``dbl=dst`` (out=2 only in Perl ``2:0``) and
        ``dbl=src-dst`` (Perl ``1:2``).  The accompanying emit lives in
        ``_process_dbl_dst_interfaces`` (``compiler/ir/_build.py``).
        """
        if "nodbl" in self.options:
            return False
        return self.option_values.get("dbl") in ("dst", "src-dst")

    def _nets_split(self) -> tuple[list[str], list[str]]:
        """Parse ``nets=`` into IPv4 and IPv6 CIDR lists.

        Returns ``(v4_cidrs, v6_cidrs)``.  Empty lists when ``nets=`` is
        unset or the value contains only invalid tokens.  Garbage tokens
        are silently dropped (matches the parser's tolerance for sfilter).
        """
        raw = self.option_values.get("nets")
        if not raw:
            return [], []
        import ipaddress as _ip
        v4: list[str] = []
        v6: list[str] = []
        for tok in raw.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                net = _ip.ip_network(tok, strict=False)
            except ValueError:
                continue
            (v4 if isinstance(net, _ip.IPv4Network) else v6).append(str(net))
        return v4, v6

    @property
    def has_nets(self) -> bool:
        """Whether this iface declares any ``nets=`` scoping."""
        v4, v6 = self._nets_split()
        return bool(v4 or v6)


@dataclass
class Host:
    """A host group within a zone."""
    zone: str
    interface: str
    addresses: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    # Parsed option values for options that take a value (e.g. mss=1452).
    option_values: dict[str, str] = field(default_factory=dict)


@dataclass
class IpsecOptions:
    """Parsed IPsec zone OPTIONS (zones file, ipsec/ipsec4/ipsec6 zones).

    Upstream reference: Zones.pm ``parse_zone_option_list`` / ``process_zone``.
    Each field corresponds to a known ipsec option token.
    """
    mss: int | None = None
    strict: bool = False
    next: bool = False            # ``next`` keyword: use next SA
    # ``reqid=N`` accepts a single value or a comma-list (``reqid=1,2,3``)
    # so a tunnel that spans multiple SAs is expressible as
    # ``ipsec <dir> reqid { N1, N2, ... }``. Single values stay
    # one-element lists; emit collapses to ``reqid N`` in that case.
    reqid: list[int] = field(default_factory=list)
    # ``reqid=any`` (or just ``reqid`` with no value) is the
    # "match-any-reqid" form, emitted as ``ipsec <dir> reqid != 0``.
    # Narrower than ``meta ipsec exists`` (excludes reqid=0 special-
    # case SAs) but doesn't pin a specific tunnel.
    reqid_any: bool = False
    spi: int | None = None
    proto: str | None = None      # ``esp`` | ``ah`` | ``comp``
    mode: str | None = None       # ``tunnel`` | ``transport``
    mark: int | None = None


# Valid Shorewall zone types
ZONE_TYPES = {"firewall", "ipv4", "ipv6", "ipsec", "ipsec4", "ipsec6",
              "bport", "bport4", "bport6", "vserver", "loopback", "local"}


@dataclass
class Zone:
    """A firewall zone."""
    name: str
    zone_type: str  # firewall, ipv4, ipv6, bport4, bport6, ipsec, ...
    parent: str | None = None  # Parent zone for nested zones (bport)
    interfaces: list[Interface] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    in_options: list[str] = field(default_factory=list)
    out_options: list[str] = field(default_factory=list)
    # Parsed IPsec options for ipsec/ipsec4/ipsec6 zones.
    ipsec_options: IpsecOptions | None = None

    @property
    def is_firewall(self) -> bool:
        return self.zone_type == "firewall"

    @property
    def is_ipv4(self) -> bool:
        return self.zone_type in ("ipv4", "bport4", "ipsec4")

    @property
    def is_ipv6(self) -> bool:
        return self.zone_type in ("ipv6", "bport6", "ipsec6")

    @property
    def is_bport(self) -> bool:
        return self.zone_type in ("bport", "bport4", "bport6")


@dataclass
class ZoneModel:
    """Complete zone/interface model."""
    zones: dict[str, Zone] = field(default_factory=dict)
    firewall_zone: str = ""

    def get_zone(self, name: str) -> Zone:
        """Get a zone by name. Raises KeyError if not found."""
        if name == "$FW" or name == "fw":
            name = self.firewall_zone
        return self.zones[name]

    def zone_names(self) -> list[str]:
        """Return all zone names excluding the firewall zone."""
        return [z for z in self.zones if z != self.firewall_zone]

    def all_zone_names(self) -> list[str]:
        """Return all zone names including the firewall zone."""
        return list(self.zones.keys())


def build_zone_model(config: ShorewalConfig) -> ZoneModel:
    """Build the zone model from parsed config."""
    model = ZoneModel()

    # Parse zones
    for line in config.zones:
        cols = line.columns
        name = cols[0]
        zone_type = cols[1] if len(cols) > 1 else "ipv4"
        options = _parse_options(cols[2]) if len(cols) > 2 else []
        in_options = _parse_options(cols[3]) if len(cols) > 3 else []
        out_options = _parse_options(cols[4]) if len(cols) > 4 else []

        # Handle parent zone syntax: ZONE:PARENT or type:parent
        parent = None
        if ":" in name:
            name, parent = name.split(":", 1)
        if ":" in zone_type:
            zone_type, parent = zone_type.split(":", 1)

        # Parse IPsec OPTIONS for ipsec zones
        ipsec_opts: IpsecOptions | None = None
        if zone_type in ("ipsec", "ipsec4", "ipsec6"):
            ipsec_opts = _parse_ipsec_options(options, zone_name=name)

        zone = Zone(
            name=name,
            zone_type=zone_type,
            parent=parent,
            options=options,
            in_options=in_options,
            out_options=out_options,
            ipsec_options=ipsec_opts,
        )
        model.zones[name] = zone

        if zone_type == "firewall":
            model.firewall_zone = name

    # Parse interfaces
    for line in config.interfaces:
        cols = line.columns
        zone_name = cols[0]
        iface_name = cols[1]
        broadcast = cols[2] if len(cols) > 2 else None
        raw_options_str = cols[3] if len(cols) > 3 else ""
        options = _parse_options(raw_options_str)
        option_values = _parse_option_values(raw_options_str)

        # Shorewall bridge-port syntax: "bridge:port" means the interface
        # is a port on a bridge. Linux kernel interface names cannot
        # contain colons, so the actual interface for nft matching is
        # just the port side. The bridge name is informational only.
        if ":" in iface_name:
            bridge, port = iface_name.split(":", 1)
            iface_name = port

        if broadcast == "-" or broadcast == "detect":
            broadcast = None

        # ``unmanaged`` excludes the iface from rule generation entirely
        # (mirrors Perl ``find_interfaces_by_option`` skip).  Typical
        # use: bond slaves where the bond itself is the managed iface.
        if "unmanaged" in options:
            continue

        # ``upnp`` / ``upnpclient`` are deprecated in shorewall-nft —
        # the runtime side (miniupnpd integration, gateway-IP shell-var
        # resolution) has no equivalent in this compiler.  Accept at
        # parse time so existing configs still load, but warn so the
        # operator knows the rules won't fire.
        if "upnp" in options:
            warnings.warn(
                f"shorewall-nft: interface {iface_name!r}: ``upnp`` is "
                f"deprecated and emits no NAT rules — miniupnpd "
                f"integration is not supported.",
                UserWarning, stacklevel=2,
            )
        if "upnpclient" in options:
            warnings.warn(
                f"shorewall-nft: interface {iface_name!r}: ``upnpclient`` "
                f"is deprecated and emits no input-accept rule — "
                f"runtime gateway-IP resolution is not supported.",
                UserWarning, stacklevel=2,
            )

        # Validate ``dbl=VAL`` if present.  Perl Zones.pm:1383-1390
        # accepts none / src / dst / src-dst.  Anything else is fatal
        # in Perl — we warn + drop the value here (parser tolerance).
        dbl_val = option_values.get("dbl")
        if dbl_val is not None and dbl_val not in ("none", "src", "dst", "src-dst"):
            warnings.warn(
                f"shorewall-nft: interface {iface_name!r}: invalid "
                f"dbl={dbl_val!r} (expected none|src|dst|src-dst) — "
                f"option dropped.",
                UserWarning, stacklevel=2,
            )
            option_values.pop("dbl", None)

        # ``wait=N`` is parsed but the runtime side is not implemented.
        # Perl uses this in init scripts to retry iface-presence checks
        # at start time; shorewall-nft has no equivalent init phase
        # today.  Accept + warn so existing configs load.
        wait_val = option_values.get("wait")
        if wait_val is not None:
            try:
                int(wait_val)
            except ValueError:
                warnings.warn(
                    f"shorewall-nft: interface {iface_name!r}: "
                    f"wait={wait_val!r} must be numeric — option dropped.",
                    UserWarning, stacklevel=2,
                )
                option_values.pop("wait", None)
            else:
                warnings.warn(
                    f"shorewall-nft: interface {iface_name!r}: "
                    f"wait={wait_val} is parser-only — no runtime "
                    f"iface-presence retry is performed at start.",
                    UserWarning, stacklevel=2,
                )

        iface = Interface(
            name=iface_name,
            zone=zone_name,
            broadcast=broadcast,
            options=options,
            option_values=option_values,
        )

        if zone_name in model.zones:
            model.zones[zone_name].interfaces.append(iface)

    # Parse hosts
    for line in config.hosts:
        cols = line.columns
        zone_name = cols[0]
        # Format: ZONE HOST(S) [OPTIONS]
        # HOST(S) is interface:address[,address...]
        host_spec = cols[1] if len(cols) > 1 else ""
        raw_options_str = cols[2] if len(cols) > 2 else ""
        options = _parse_options(raw_options_str)
        option_values = _parse_option_values(raw_options_str)

        if ":" in host_spec:
            iface, addr_str = host_spec.split(":", 1)
            addresses = [a.strip() for a in addr_str.split(",")]
        else:
            iface = host_spec
            addresses = []

        host = Host(
            zone=zone_name,
            interface=iface,
            addresses=addresses,
            options=options,
            option_values=option_values,
        )

        if zone_name in model.zones:
            model.zones[zone_name].hosts.append(host)

    if not model.firewall_zone:
        raise ValueError("No firewall zone defined in zones config")

    return model


def _split_options_respecting_parens(text: str) -> list[str]:
    """Split a comma-separated options string, respecting paren grouping.

    Shorewall list-valued options use ``key=(v1,v2,...)`` syntax (see
    ``shorewall-interfaces(5)`` ``sfilter=(net[,...])``).  Naive
    ``str.split(",")`` would break the inner list — this helper splits
    only on commas at depth 0.
    """
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    for c in text:
        if c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            depth = max(0, depth - 1)
            cur.append(c)
        elif c == "," and depth == 0:
            tok = "".join(cur).strip()
            if tok:
                out.append(tok)
            cur = []
        else:
            cur.append(c)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _parse_options(text: str) -> list[str]:
    """Parse a comma-separated options string."""
    if not text or text == "-":
        return []
    return _split_options_respecting_parens(text)


def _parse_option_values(text: str) -> dict[str, str]:
    """Parse key=value pairs from a comma-separated options string.

    Returns a dict of ``{key: value}`` for options that use ``key=value``
    syntax (e.g. ``mss=1452``, ``sourceroute=0``). Simple flag options
    without ``=`` are not included.

    List-valued options written as ``key=(v1,v2)`` have the surrounding
    parens stripped — the dict value is the inner ``v1,v2`` string.
    """
    if not text or text == "-":
        return {}
    result: dict[str, str] = {}
    for tok in _split_options_respecting_parens(text):
        if "=" in tok:
            key, _, val = tok.partition("=")
            val = val.strip()
            if val.startswith("(") and val.endswith(")"):
                val = val[1:-1].strip()
            result[key.strip()] = val
    return result


def _parse_ipsec_options(options: list[str],
                         zone_name: str = "<unknown>") -> IpsecOptions:
    """Parse IPsec zone OPTIONS tokens into an :class:`IpsecOptions` struct.

    Upstream reference: ``Zones.pm::parse_zone_option_list`` — all tokens
    listed below are recognised in the Perl 5.2.6.1 source.

    Token grammar:
      ``strict``           — enforce strict policy matching
      ``next``             — advance to next SA
      ``mss=N``            — TCP MSS clamp value (N >= 500)
      ``reqid=N``          — IPsec SA request-id
      ``reqid=N1,N2,...``  — multi-SA tunnel: emits ``ipsec <dir>
                              reqid { N1, N2, ... }`` (nft set match)
      ``spi=N``            — Security Parameter Index
      ``proto=esp|ah|comp``— IPsec protocol (no nft expression — dropped
                              from emit; ``UserWarning`` raised so the
                              user knows the filter won't survive compile)
      ``mode=tunnel|transport`` — IPsec encapsulation mode (no nft
                              expression — dropped + warned, same as proto)
      ``mark=N``           — packet mark (hex or decimal); the nft
                              ``ipsec`` keyword has no mark sub-field, so
                              this is also dropped + warned.

    ``zone_name`` is included in the warning text so users can locate
    the offending zone when one config file declares many.
    """
    opts = IpsecOptions()
    for tok in options:
        if tok == "strict":
            opts.strict = True
        elif tok == "next":
            opts.next = True
        elif tok.startswith("mss="):
            try:
                opts.mss = int(tok.split("=", 1)[1])
            except ValueError:
                pass
        elif tok == "reqid" or tok.startswith("reqid="):
            raw = tok.split("=", 1)[1] if "=" in tok else ""
            # ``reqid=any`` and bare ``reqid`` map to the "any-reqid"
            # match form (``ipsec <dir> reqid != 0``).  Numeric lists
            # stay the explicit-reqid path.
            if raw.lower() in ("", "any"):
                opts.reqid_any = True
            else:
                for part in raw.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    try:
                        opts.reqid.append(int(part))
                    except ValueError:
                        pass
        elif tok.startswith("spi="):
            try:
                raw = tok.split("=", 1)[1]
                opts.spi = int(raw, 0)
            except ValueError:
                pass
        elif tok.startswith("proto="):
            value = tok.split("=", 1)[1].lower()
            opts.proto = value
            warnings.warn(
                f"shorewall-nft: ipsec zone {zone_name!r}: "
                f"proto={value!r} has no nft expression — dropped. "
                f"nft 1.1.x ``ipsec <dir>`` only matches reqid/spi/saddr/daddr.",
                UserWarning, stacklevel=2,
            )
        elif tok.startswith("mode="):
            # ``mode=tunnel|transport`` has no direct nft match expression,
            # but the kernel's nft_xfrm hook resolves the SA from the
            # packet's secpath and the SA itself encodes mode — so a
            # ``ipsec <dir> reqid N`` match implicitly disambiguates by
            # mode through the reqid→SA binding.  Mode is recorded for
            # documentation but no rule emit is needed; the warning
            # previously raised here was outdated and is dropped.
            value = tok.split("=", 1)[1].lower()
            opts.mode = value
        elif tok.startswith("mark="):
            try:
                raw = tok.split("=", 1)[1]
                opts.mark = int(raw, 0)
                warnings.warn(
                    f"shorewall-nft: ipsec zone {zone_name!r}: "
                    f"mark={raw!r} has no nft expression — dropped. "
                    f"nft has no IPsec-SA mark sub-field; use ``meta mark`` "
                    f"in rules instead if a packet-mark match is needed.",
                    UserWarning, stacklevel=2,
                )
            except ValueError:
                pass
    return opts
