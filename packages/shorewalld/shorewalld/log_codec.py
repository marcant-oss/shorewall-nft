"""Wire codec for worker → parent NFLOG events (``MAGIC_NFLOG``).

The third message kind sharing the per-netns SEQPACKET pair (alongside
:mod:`batch_codec` set mutations and :mod:`read_codec` file/CT reads).

Unlike the other two, this one is **push-only**: the worker decodes an
nfnetlink_log frame inside its own netns (see
:mod:`shorewalld.nflog_netlink`), runs the prefix parser
(:func:`shorewalld.log_prefix.parse_log_prefix`), and hands the resulting
:class:`~shorewalld.log_prefix.LogEvent` to the parent via one datagram
per event. No ack. The parent dispatches on the ``MAGIC_NFLOG`` header
in ``ParentWorker._drain_replies`` and forwards to the
:class:`~shorewalld.log_dispatcher.LogDispatcher`.

Wire format (LOG_WIRE_VERSION = 2)
----------------------------------

Header (35 bytes, big-endian)::

    offset  size  field           notes
    0       4     magic           0x53574C47 ('SWLG')
    4       2     log_wire_ver    LOG_WIRE_VERSION = 2
    6       1     flags           bit 0 = has_rulenum, bit 1 = has_packet
    7       1     chain_len       0..255
    8       1     disp_len        0..255
    9       8     timestamp_ns    be64 nanoseconds since epoch, 0 if absent
    17      4     rule_num        be32 (0 if has_rulenum=0)
    21      1     packet_family   4, 6, or 0 if has_packet=0
    22      1     packet_proto    IANA L4 proto, 0 if unknown
    23      2     sport           be16, 0 if no L4 ports
    25      2     dport           be16
    27      4     pkt_len         be32 L3 total length, 0 if unknown
    31      1     indev_len       0..32 chars, ifname length
    32      1     outdev_len      0..32 chars
    33      2     reserved        0x0000

Variable payload::

    35           saddr_bytes     0/4/16 bytes (per packet_family)
    +saddr_len   daddr_bytes     same length as saddr
    +…           indev_bytes     ASCII ifname, length = indev_len
    +indev_len   outdev_bytes    ASCII ifname, length = outdev_len
    +outdev_len  chain_bytes     UTF-8 (ASCII in practice)
    +chain_len   disp_bytes      UTF-8 (ASCII in practice)

Max datagram size: 35 + 32 (v6 saddr+daddr) + 32 + 32 (ifnames) + 510
(chain+disp) = 641 bytes — still well under SEQPACKET MTU.

Backward compat: if the parent sees ``log_wire_ver == 1`` it decodes
the old 21-byte header form (no packet info). Worker is upgraded
together with parent (single shorewalld package), so production
encoding is always v2.

Encoder is ``pack_into``-based on a caller-owned buffer so the steady
state is allocation-free; decoder returns a brand-new
:class:`LogEvent`, which is the IPC boundary's first point where
Python-object allocations are cheaper than the zero-copy budget's gain
would be.
"""

from __future__ import annotations

import struct

from .batch_codec import WIRE_VERSION  # noqa: F401  (kept for historic re-exports)
from .log_prefix import LogEvent

MAGIC_NFLOG = 0x53574C47          # b"SWLG"

#: Independent of batch_codec.WIRE_VERSION — only this codec needs a bump.
LOG_WIRE_VERSION_V1 = 1
LOG_WIRE_VERSION = 2

LOG_HEADER_LEN_V1 = 21
LOG_HEADER_LEN = 35

#: bit-flag layout in the ``flags`` byte at offset 6
_FLAG_HAS_RULENUM = 0x01
_FLAG_HAS_PACKET = 0x02

# Header structs.
_STRUCT_LOG_HEADER_V1 = struct.Struct(">I H B B B Q I")  # 21 bytes
_STRUCT_LOG_HEADER = struct.Struct(">I H B B B Q I B B H H I B B H")  # 35 bytes

# Safety cap: chain_len + disp_len are u8 each → max body = 510 bytes.
# v6 addresses 32 bytes + 2 ifnames 64 bytes → ≤96. Header 35 + body 606
# = 641 bytes worst case. 1024 keeps headroom.
LOG_ENCODE_BUF_SIZE = 1024


class LogWireError(Exception):
    """Malformed NFLOG-event datagram."""


def encode_log_event_into(buf: bytearray, ev: LogEvent) -> memoryview:
    """Serialise *ev* into *buf* and return the written prefix as a view.

    Always emits the v2 wire format. Packet metadata (saddr/daddr/proto/
    sport/dport/pkt_len) and indev/outdev names are included whenever
    ``ev.packet_family`` is non-zero.

    Raises :class:`LogWireError` on field overflow (chain/disp >255,
    ifname >255, rule_num >u32, address family invalid).
    """
    chain_b = ev.chain.encode("ascii")
    disp_b = ev.disposition.encode("ascii")
    indev_b = ev.indev.encode("ascii", "replace")
    outdev_b = ev.outdev.encode("ascii", "replace")

    if len(chain_b) > 255:
        raise LogWireError(f"chain too long for wire: {len(chain_b)}")
    if len(disp_b) > 255:
        raise LogWireError(f"disposition too long for wire: {len(disp_b)}")
    if len(indev_b) > 255 or len(outdev_b) > 255:
        raise LogWireError("ifname too long for wire")
    if ev.rule_num is not None and not 0 <= ev.rule_num <= 0xFFFFFFFF:
        raise LogWireError(f"rule_num out of u32 range: {ev.rule_num}")

    flags = 0
    if ev.rule_num is not None:
        flags |= _FLAG_HAS_RULENUM
    if ev.packet_family in (4, 6):
        flags |= _FLAG_HAS_PACKET
        addr_len = 4 if ev.packet_family == 4 else 16
    else:
        addr_len = 0

    body_len = (2 * addr_len) + len(indev_b) + len(outdev_b) \
        + len(chain_b) + len(disp_b)
    total = LOG_HEADER_LEN + body_len
    if total > len(buf):
        raise LogWireError(
            f"encode buffer too small: need {total}, have {len(buf)}")

    rule_num = ev.rule_num if ev.rule_num is not None else 0
    _STRUCT_LOG_HEADER.pack_into(
        buf, 0,
        MAGIC_NFLOG,
        LOG_WIRE_VERSION,
        flags,
        len(chain_b),
        len(disp_b),
        ev.timestamp_ns,
        rule_num,
        ev.packet_family if (flags & _FLAG_HAS_PACKET) else 0,
        ev.packet_proto if (flags & _FLAG_HAS_PACKET) else 0,
        ev.packet_sport if (flags & _FLAG_HAS_PACKET) else 0,
        ev.packet_dport if (flags & _FLAG_HAS_PACKET) else 0,
        ev.packet_len if (flags & _FLAG_HAS_PACKET) else 0,
        len(indev_b),
        len(outdev_b),
        0,  # reserved
    )
    off = LOG_HEADER_LEN
    mv = memoryview(buf)

    if flags & _FLAG_HAS_PACKET:
        try:
            saddr_bytes = _addr_str_to_bytes(ev.packet_saddr, ev.packet_family)
            daddr_bytes = _addr_str_to_bytes(ev.packet_daddr, ev.packet_family)
        except (ValueError, OSError) as e:
            raise LogWireError(f"invalid address in event: {e}") from e
        mv[off:off + addr_len] = saddr_bytes
        off += addr_len
        mv[off:off + addr_len] = daddr_bytes
        off += addr_len

    mv[off:off + len(indev_b)] = indev_b
    off += len(indev_b)
    mv[off:off + len(outdev_b)] = outdev_b
    off += len(outdev_b)
    mv[off:off + len(chain_b)] = chain_b
    off += len(chain_b)
    mv[off:off + len(disp_b)] = disp_b
    off += len(disp_b)
    return mv[:off]


def _addr_str_to_bytes(s: str, family: int) -> bytes:
    """Pack an IPv4/IPv6 address string into raw network bytes."""
    import socket
    if family == 4:
        return socket.inet_pton(socket.AF_INET, s)
    return socket.inet_pton(socket.AF_INET6, s)


def _addr_bytes_to_str(b: bytes, family: int) -> str:
    """Inverse of :func:`_addr_str_to_bytes`."""
    import socket
    if family == 4:
        return socket.inet_ntop(socket.AF_INET, b)
    return socket.inet_ntop(socket.AF_INET6, b)


def decode_log_event(view: memoryview | bytes, *, netns: str = "") -> LogEvent:
    """Parse a ``MAGIC_NFLOG`` datagram into a :class:`LogEvent`.

    Decodes both v1 (21-byte header, chain+disp only) and v2 (35-byte
    header with packet 5-tuple + ifnames) wire formats. *netns* is
    stamped on the returned event — the worker does not know its own
    netns label as a string (pinned via ``setns``, not labelled), so
    the parent supplies it at decode time.
    """
    if len(view) < 6:
        raise LogWireError(f"log-event shorter than version header: {len(view)}")
    magic = (view[0] << 24) | (view[1] << 16) | (view[2] << 8) | view[3]
    if magic != MAGIC_NFLOG:
        raise LogWireError(f"unexpected log-event magic 0x{magic:08x}")
    version = (view[4] << 8) | view[5]

    if version == LOG_WIRE_VERSION_V1:
        return _decode_v1(view, netns=netns)
    if version == LOG_WIRE_VERSION:
        return _decode_v2(view, netns=netns)
    raise LogWireError(f"unsupported log-event version {version}")


def _decode_v1(view, *, netns: str) -> LogEvent:
    if len(view) < LOG_HEADER_LEN_V1:
        raise LogWireError(f"log-event v1 shorter than header: {len(view)}")
    (
        _magic, _ver, has_rulenum, chain_len, disp_len, timestamp_ns, rule_num,
    ) = _STRUCT_LOG_HEADER_V1.unpack_from(view, 0)
    total = LOG_HEADER_LEN_V1 + chain_len + disp_len
    if total > len(view):
        raise LogWireError(f"log-event v1 truncated: need {total}, have {len(view)}")
    off = LOG_HEADER_LEN_V1
    chain = bytes(view[off:off + chain_len]).decode("ascii", "replace")
    off += chain_len
    disposition = bytes(view[off:off + disp_len]).decode("ascii", "replace")
    return LogEvent(
        chain=chain,
        disposition=disposition,
        rule_num=rule_num if has_rulenum else None,
        timestamp_ns=timestamp_ns,
        netns=netns,
    )


def _decode_v2(view, *, netns: str) -> LogEvent:
    if len(view) < LOG_HEADER_LEN:
        raise LogWireError(f"log-event v2 shorter than header: {len(view)}")
    (
        _magic, _ver, flags, chain_len, disp_len, timestamp_ns, rule_num,
        family, proto, sport, dport, pkt_len, indev_len, outdev_len, _resv,
    ) = _STRUCT_LOG_HEADER.unpack_from(view, 0)

    has_packet = bool(flags & _FLAG_HAS_PACKET)
    addr_len = 4 if family == 4 else 16 if family == 6 else 0
    if not has_packet:
        addr_len = 0

    body_len = (2 * addr_len) + indev_len + outdev_len + chain_len + disp_len
    total = LOG_HEADER_LEN + body_len
    if total > len(view):
        raise LogWireError(f"log-event v2 truncated: need {total}, have {len(view)}")

    off = LOG_HEADER_LEN
    saddr = daddr = ""
    if has_packet and addr_len:
        try:
            saddr = _addr_bytes_to_str(bytes(view[off:off + addr_len]), family)
            off += addr_len
            daddr = _addr_bytes_to_str(bytes(view[off:off + addr_len]), family)
            off += addr_len
        except (ValueError, OSError):
            saddr = daddr = ""
            off += 2 * addr_len
    indev = bytes(view[off:off + indev_len]).decode("ascii", "replace")
    off += indev_len
    outdev = bytes(view[off:off + outdev_len]).decode("ascii", "replace")
    off += outdev_len
    chain = bytes(view[off:off + chain_len]).decode("ascii", "replace")
    off += chain_len
    disposition = bytes(view[off:off + disp_len]).decode("ascii", "replace")

    return LogEvent(
        chain=chain,
        disposition=disposition,
        rule_num=rule_num if (flags & _FLAG_HAS_RULENUM) else None,
        timestamp_ns=timestamp_ns,
        netns=netns,
        packet_family=family if has_packet else 0,
        packet_proto=proto if has_packet else 0,
        packet_saddr=saddr,
        packet_daddr=daddr,
        packet_sport=sport if has_packet else 0,
        packet_dport=dport if has_packet else 0,
        packet_len=pkt_len if has_packet else 0,
        indev=indev,
        outdev=outdev,
    )
