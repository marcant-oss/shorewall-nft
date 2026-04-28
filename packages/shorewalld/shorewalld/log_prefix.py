"""LOGFORMAT prefix parser for shorewalld's log dispatcher.

Given the ``NFULA_PREFIX`` slice from an :class:`~shorewalld.nflog_netlink.NflogFrame`,
extract ``chain`` / ``disposition`` / optional rule number out of a
Shorewall-style ``LOGFORMAT`` tag. The format is configurable in
``shorewall.conf`` (``LOGFORMAT=`` / ``LOGRULENUMBERS=``); we parse the
upstream-Shorewall default (``"Shorewall:%s:%s:"``) plus the
``LOGRULENUMBERS=Yes`` variant (``"Shorewall:%s:%s:%d:"``).

Only frames whose prefix peeks as Shorewall-shaped are returned; bogus
prefixes (user rules logging something else into the same NFLOG group,
truncated bytes, non-ASCII junk) return ``None`` and the caller should
count them under a decode-error metric rather than panicking.

Zero-copy contract
------------------
The incoming ``memoryview`` slices the nflog recv buffer. We must
produce ``str`` fields (Prometheus labels aren't byte-typed) which
requires a decode — that costs one copy per string, unavoidable. The
parser pays that cost **only** after the prefix has been confirmed
Shorewall-shaped, so malformed / unrelated logs cost a single
``bytes(mv[:sep]).startswith`` check and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass

SHOREWALL_TAG = b"Shorewall:"
SHOREWALL_TAG_LEN = len(SHOREWALL_TAG)


@dataclass(frozen=True, slots=True)
class LogEvent:
    """One decoded NFLOG log-entry.

    Fields are plain Python types (str / int) — this crosses the worker
    ↔ parent IPC boundary and feeds a Prometheus label set, so opaque
    memoryviews would be the wrong shape here. The zero-copy budget is
    spent upstream (nfnetlink_log parse); the one decode of the prefix
    bytes happens here, exactly once per surviving event.

    The ``packet_*`` and ``indev``/``outdev`` fields are populated when
    the worker calls :func:`shorewalld.nflog_netlink.parse_packet_5tuple`
    on the NFULA_PAYLOAD slice and forwards the resolved ifindex names
    over the wire. ``packet_family == 0`` means "no L3 parse" — sinks
    should fall back to the chain/disp-only line. Defaults keep the
    older test fixtures (which build LogEvent directly without packet
    info) working.
    """
    chain: str
    disposition: str
    rule_num: int | None
    timestamp_ns: int
    netns: str
    # Packet metadata (NFULA_PAYLOAD parse) — 0/"" when absent.
    packet_family: int = 0   # 4, 6, or 0
    packet_proto: int = 0    # IANA proto number, 0 if unknown
    packet_saddr: str = ""
    packet_daddr: str = ""
    packet_sport: int = 0    # ICMP type when proto in (1, 58)
    packet_dport: int = 0    # ICMP code when proto in (1, 58)
    packet_len: int = 0
    packet_ttl: int = 0      # IPv4 TTL / IPv6 Hop Limit, 0 if absent
    packet_tcp_flags: int = 0  # raw TCP flags byte (FIN/SYN/RST/PSH/ACK/URG/ECE/CWR)
    indev: str = ""          # interface name (resolved from ifindex)
    outdev: str = ""
    # NFLOG metadata fields — netfilter context, not packet content.
    nf_hook: int = 0         # 0=PREROUTING 1=INPUT 2=FORWARD 3=OUTPUT 4=POSTROUTING
    nf_mark: int = 0         # ct/fwmark on the packet (32-bit)
    nf_uid: int = 0xFFFFFFFF  # only set on output hook for locally-generated traffic; sentinel = unset
    nf_gid: int = 0xFFFFFFFF


def parse_log_prefix(
    prefix_mv: memoryview | bytes | None,
    *,
    timestamp_ns: int = 0,
    netns: str = "",
) -> LogEvent | None:
    """Parse a Shorewall LOGFORMAT prefix into a :class:`LogEvent`.

    Returns ``None`` on any malformation: empty prefix, non-Shorewall
    tag, missing separators, non-ASCII junk, empty chain/disposition.
    Callers should count ``None`` returns on a decode-error metric.

    Accepted formats (Shorewall defaults)::

        Shorewall:<chain>:<disposition>:
        Shorewall:<chain>:<disposition>:<rulenum>:

    The trailing colon is what Shorewall's LOGFORMAT emits (``"%s:%s:"``
    expands to ``chain:disposition:``); some operators strip it. We
    accept both.
    """
    if prefix_mv is None:
        return None
    # Accept memoryview, bytes, bytearray — unify via bytes() once we
    # know the shape is plausible.
    n = len(prefix_mv)
    if n < SHOREWALL_TAG_LEN + 3:  # "Shorewall:" + "a:b"
        return None
    # Peek the tag without copying the whole view.
    if bytes(prefix_mv[:SHOREWALL_TAG_LEN]) != SHOREWALL_TAG:
        return None

    # Strip optional trailing NUL (parse_frame already strips it, but
    # bytes-form callers might forget).
    if prefix_mv[n - 1] == 0:
        n -= 1
    # Strip optional trailing colon so the segment count is deterministic.
    if n > 0 and prefix_mv[n - 1] == 0x3A:  # ":"
        n -= 1

    body = bytes(prefix_mv[SHOREWALL_TAG_LEN:n])
    if not body:
        return None
    parts = body.split(b":")
    # Expect 2 (chain, disp) or 3 (chain, disp, rulenum) segments.
    if len(parts) == 2:
        chain_b, disp_b = parts
        rule_num: int | None = None
    elif len(parts) == 3:
        chain_b, disp_b, rnum_b = parts
        try:
            rule_num = int(rnum_b.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            return None
    else:
        return None

    if not chain_b or not disp_b:
        return None

    try:
        chain = chain_b.decode("ascii")
        disposition = disp_b.decode("ascii")
    except UnicodeDecodeError:
        # Shorewall chains / dispositions are ASCII by construction.
        # If we see non-ASCII, something injected a rogue LOG rule —
        # drop it rather than letting it pollute Prom labels.
        return None

    return LogEvent(
        chain=chain,
        disposition=disposition,
        rule_num=rule_num,
        timestamp_ns=timestamp_ns,
        netns=netns,
    )
