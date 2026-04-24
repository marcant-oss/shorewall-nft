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

Wire format
-----------

Header (21 bytes, big-endian)::

    offset  size  field         notes
    0       4     magic         0x53574C47 ('SWLG')
    4       2     version       WIRE_VERSION (shared with batch_codec)
    6       1     has_rulenum   0 or 1
    7       1     chain_len     0..255
    8       1     disp_len      0..255
    9       8     timestamp_ns  be64 nanoseconds since epoch, 0 if absent
    17      4     rule_num      be32 (0 if has_rulenum=0)

Variable payload::

    21      N     chain_bytes   UTF-8 (ASCII in practice, per parse_log_prefix)
    21+N    M     disp_bytes    UTF-8 (ASCII in practice)

Max datagram size: 21 + 255 + 255 = 531 bytes — a fraction of SEQPACKET
MTU. Typical: chain ~6 + disposition ~4 = ~31 bytes.

Encoder is ``pack_into``-based on a caller-owned buffer so the steady
state is allocation-free; decoder returns a brand-new
:class:`LogEvent`, which is the IPC boundary's first point where
Python-object allocations are cheaper than the zero-copy budget's gain
would be.
"""

from __future__ import annotations

import struct

from .batch_codec import WIRE_VERSION
from .log_prefix import LogEvent

MAGIC_NFLOG = 0x53574C47          # b"SWLG"

LOG_HEADER_LEN = 21

_STRUCT_LOG_HEADER = struct.Struct(">I H B B B Q I")  # 21 bytes

# Safety cap: chain_len and disp_len are u8 each → max body = 510 bytes.
# Header (21) + body (510) = 531. Round up to 1024 for the worker-side
# encode buffer so there is headroom if we grow the header later.
LOG_ENCODE_BUF_SIZE = 1024


class LogWireError(Exception):
    """Malformed NFLOG-event datagram."""


def encode_log_event_into(buf: bytearray, ev: LogEvent) -> memoryview:
    """Serialise *ev* into *buf* and return the written prefix as a view.

    Raises :class:`LogWireError` if chain or disposition exceed the
    255-byte u8 cap (cannot happen for Shorewall-generated prefixes, but
    check explicitly so a rogue user-LOG rule can't overflow the wire).
    """
    chain_b = ev.chain.encode("ascii")
    disp_b = ev.disposition.encode("ascii")
    if len(chain_b) > 255:
        raise LogWireError(f"chain too long for wire: {len(chain_b)}")
    if len(disp_b) > 255:
        raise LogWireError(f"disposition too long for wire: {len(disp_b)}")
    if ev.rule_num is not None and not 0 <= ev.rule_num <= 0xFFFFFFFF:
        raise LogWireError(f"rule_num out of u32 range: {ev.rule_num}")

    total = LOG_HEADER_LEN + len(chain_b) + len(disp_b)
    if total > len(buf):
        raise LogWireError(
            f"encode buffer too small: need {total}, have {len(buf)}")

    has_rulenum = 1 if ev.rule_num is not None else 0
    rule_num = ev.rule_num if ev.rule_num is not None else 0
    _STRUCT_LOG_HEADER.pack_into(
        buf, 0,
        MAGIC_NFLOG,
        WIRE_VERSION,
        has_rulenum,
        len(chain_b),
        len(disp_b),
        ev.timestamp_ns,
        rule_num,
    )
    off = LOG_HEADER_LEN
    mv = memoryview(buf)
    mv[off:off + len(chain_b)] = chain_b
    off += len(chain_b)
    mv[off:off + len(disp_b)] = disp_b
    off += len(disp_b)
    return mv[:off]


def decode_log_event(view: memoryview | bytes, *, netns: str = "") -> LogEvent:
    """Parse a ``MAGIC_NFLOG`` datagram into a :class:`LogEvent`.

    *netns* is stamped on the returned event — the worker does not know
    its own netns label as a string (it's pinned via ``setns``, not
    labelled), so the parent supplies it at decode time. This is the
    same pattern the daemon uses for other per-worker metrics.
    """
    if len(view) < LOG_HEADER_LEN:
        raise LogWireError(
            f"log-event shorter than header: {len(view)}")
    (
        magic,
        version,
        has_rulenum,
        chain_len,
        disp_len,
        timestamp_ns,
        rule_num,
    ) = _STRUCT_LOG_HEADER.unpack_from(view, 0)
    if magic != MAGIC_NFLOG:
        raise LogWireError(
            f"unexpected log-event magic 0x{magic:08x}")
    if version != WIRE_VERSION:
        raise LogWireError(
            f"unsupported log-event version {version}")
    total = LOG_HEADER_LEN + chain_len + disp_len
    if total > len(view):
        raise LogWireError(
            f"log-event truncated: need {total}, have {len(view)}")

    off = LOG_HEADER_LEN
    chain_b = bytes(view[off:off + chain_len])
    off += chain_len
    disp_b = bytes(view[off:off + disp_len])

    try:
        chain = chain_b.decode("ascii")
        disposition = disp_b.decode("ascii")
    except UnicodeDecodeError as e:
        raise LogWireError(f"non-ASCII chain/disposition: {e}") from e

    return LogEvent(
        chain=chain,
        disposition=disposition,
        rule_num=rule_num if has_rulenum else None,
        timestamp_ns=timestamp_ns,
        netns=netns,
    )
