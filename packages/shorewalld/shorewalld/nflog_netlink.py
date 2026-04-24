"""Minimal ``nfnetlink_log`` consumer for shorewalld's log dispatcher.

Opens an ``AF_NETLINK`` / ``NETLINK_NETFILTER`` socket, binds to a single
NFULOG group, and yields raw log frames with zero-copy access to prefix
and payload slices. Runs inside the per-netns worker child — the caller
has already ``setns(2)``'d to the target netns before construction.

Why hand-rolled instead of ``pyroute2.NFLOGSocket``
---------------------------------------------------
``pyroute2.NFLOGSocket`` does **not** exist — verified against
``pyroute2==0.9.6`` (latest PyPI 2025-04-02) and upstream master; no
open/closed issue or PR tracks it. ``NETLINK_NFLOG = 5`` in the pyroute2
constants refers to the *legacy* ``ipt_ULOG`` family (Linux 2.4-era),
not modern ``nfnetlink_log``.

Rather than build a full ``nla``-class subclass (which allocates Python
objects per attribute and breaks the zero-copy budget), we speak the
stable nfnetlink_log wire directly via stdlib ``socket`` + ``struct``.
The protocol is frozen — ``nfnetlink_log.h`` has been untouched since
Linux 3.x — so there is no pyroute2 feature we are foregoing. This
module is small enough to lift upstream to pyroute2 as
``pyroute2/netlink/nfnetlink/nflogsocket.py`` once the API stabilises.

Protocol refs: ``include/uapi/linux/netfilter/nfnetlink_log.h`` and
``libnetfilter_log`` (``git.netfilter.org/libnetfilter_log/``).

Threading + zero-copy contract
------------------------------
* One socket = one consumer thread. Not thread-safe.
* Caller owns the recv buffer; :meth:`recv_into` writes into it and
  returns a ``memoryview`` valid until the next ``recv_into``. All
  ``memoryview`` fields on the returned :class:`NflogFrame` reference
  slices of that same buffer — copy (``mv.tobytes()``) only what
  survives the next recv.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Protocol constants — subset of <linux/netfilter/nfnetlink.h> and
# <linux/netfilter/nfnetlink_log.h> that we actually exchange.
# ---------------------------------------------------------------------------

NETLINK_NETFILTER = 12

NLMSG_NOOP = 0x1
NLMSG_ERROR = 0x2
NLMSG_DONE = 0x3

NLM_F_REQUEST = 0x001
NLM_F_ACK = 0x004

NFNL_SUBSYS_ULOG = 4

# Message types — upper byte = subsys, lower = operation.
NFULNL_MSG_PACKET = (NFNL_SUBSYS_ULOG << 8) | 0
NFULNL_MSG_CONFIG = (NFNL_SUBSYS_ULOG << 8) | 1

# Config commands (NFULA_CFG_CMD payload).
NFULNL_CFG_CMD_NONE = 0
NFULNL_CFG_CMD_BIND = 1
NFULNL_CFG_CMD_UNBIND = 2
NFULNL_CFG_CMD_PF_BIND = 3
NFULNL_CFG_CMD_PF_UNBIND = 4

# Copy modes (NFULA_CFG_MODE payload — range + mode).
NFULNL_COPY_NONE = 0
NFULNL_COPY_META = 1
NFULNL_COPY_PACKET = 2

# Config attributes.
NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2
NFULA_CFG_NLBUFSIZ = 3
NFULA_CFG_TIMEOUT = 4
NFULA_CFG_QTHRESH = 5
NFULA_CFG_FLAGS = 6

# Packet attributes (subset — everything we'd actually surface).
NFULA_PACKET_HDR = 1         # struct nfulnl_msg_packet_hdr (be16 hw_proto, u8 hook, u8 pad)
NFULA_MARK = 2               # be32 nfmark
NFULA_TIMESTAMP = 3          # struct nfulnl_msg_packet_timestamp (be64 sec, be64 usec)
NFULA_IFINDEX_INDEV = 4      # be32
NFULA_IFINDEX_OUTDEV = 5     # be32
NFULA_PAYLOAD = 9            # raw L3 bytes
NFULA_PREFIX = 10            # NUL-terminated LOGFORMAT prefix
NFULA_UID = 11               # be32
NFULA_GID = 14               # be32

# Netlink/netfilter layouts.
_STRUCT_NLMSGHDR = struct.Struct("=IHHII")   # len, type, flags, seq, pid
_STRUCT_NFGENMSG = struct.Struct("=BBH")     # family, version, res_id  (res_id native; see note)
_STRUCT_NLATTR = struct.Struct("=HH")        # len, type
_STRUCT_NFULNL_PKT_HDR = struct.Struct(">HBB")   # hw_protocol (be16), hook (u8), pad
_STRUCT_NFULNL_TIMESTAMP = struct.Struct(">QQ")  # sec, usec (both be64)
_STRUCT_BE32 = struct.Struct(">I")

NLMSGHDR_SIZE = _STRUCT_NLMSGHDR.size  # 16
NFGENMSG_SIZE = _STRUCT_NFGENMSG.size  # 4
NLATTR_SIZE = _STRUCT_NLATTR.size      # 4


def _nla_align(n: int) -> int:
    """Align *n* up to NLA boundary (4 bytes)."""
    return (n + 3) & ~3


# res_id in nfgenmsg is ``__be16`` per kernel — but the rest of nlmsg is
# native byte order. ``struct.pack("=BBH", ...)`` gives us native u16, so
# we must pre-swap the group to network byte order before packing.
def _nfgen(family: int, group: int) -> bytes:
    return _STRUCT_NFGENMSG.pack(family, 0, socket.htons(group))


def _pack_nla(ntype: int, payload: bytes) -> bytes:
    length = NLATTR_SIZE + len(payload)
    hdr = _STRUCT_NLATTR.pack(length, ntype)
    pad = b"\x00" * (_nla_align(length) - length)
    return hdr + payload + pad


# ---------------------------------------------------------------------------
# Frame + parse
# ---------------------------------------------------------------------------


class NflogWireError(Exception):
    """Malformed NFLOG netlink frame."""


@dataclass(frozen=True, slots=True)
class NflogFrame:
    """Decoded NFLOG packet — TLV slices over the caller's recv buffer.

    Every ``memoryview`` attribute is a slice of the buffer handed to
    :meth:`NFULogSocket.recv_into`. They become invalid after the next
    ``recv_into`` call. Fields absent in the frame surface as ``None``
    / ``0`` (not missing-key errors) so sinks can branch cheaply.
    """
    hook: int
    hw_protocol: int
    timestamp_ns: int       # 0 if the kernel did not attach NFULA_TIMESTAMP
    mark: int
    indev: int
    outdev: int
    uid: int
    gid: int
    prefix_mv: memoryview | None   # excludes trailing NUL
    payload_mv: memoryview | None


def parse_frame(msg_mv: memoryview) -> NflogFrame:
    """Parse one NFULNL_MSG_PACKET datagram into an :class:`NflogFrame`.

    *msg_mv* must span the whole netlink message starting at the
    ``nlmsghdr`` (offset 0). Zero-copy: prefix / payload views slice the
    incoming buffer, no intermediate ``bytes`` copies.

    Raises :class:`NflogWireError` on truncation / wrong message type.
    """
    if len(msg_mv) < NLMSGHDR_SIZE + NFGENMSG_SIZE:
        raise NflogWireError(
            f"frame shorter than nlmsg+nfgen header: {len(msg_mv)}")
    nlmsg_len, mtype, _flags, _seq, _pid = \
        _STRUCT_NLMSGHDR.unpack_from(msg_mv, 0)
    if mtype != NFULNL_MSG_PACKET:
        raise NflogWireError(f"unexpected nlmsg type 0x{mtype:04x}")
    if nlmsg_len > len(msg_mv):
        raise NflogWireError(
            f"nlmsg_len={nlmsg_len} exceeds buffer {len(msg_mv)}")

    # Walk TLVs starting after nfgenmsg.
    hook = 0
    hw_protocol = 0
    timestamp_ns = 0
    mark = 0
    indev = 0
    outdev = 0
    uid = 0
    gid = 0
    prefix_mv: memoryview | None = None
    payload_mv: memoryview | None = None

    off = NLMSGHDR_SIZE + NFGENMSG_SIZE
    end = nlmsg_len
    while off + NLATTR_SIZE <= end:
        nla_len, nla_type = _STRUCT_NLATTR.unpack_from(msg_mv, off)
        if nla_len < NLATTR_SIZE:
            raise NflogWireError(f"nla_len={nla_len} < header")
        if off + nla_len > end:
            raise NflogWireError(
                f"nla at off={off} overflows frame ({nla_len} > {end - off})")
        val_off = off + NLATTR_SIZE
        val_end = off + nla_len

        if nla_type == NFULA_PACKET_HDR:
            if val_end - val_off < _STRUCT_NFULNL_PKT_HDR.size:
                raise NflogWireError("NFULA_PACKET_HDR truncated")
            hw_protocol, hook, _ = _STRUCT_NFULNL_PKT_HDR.unpack_from(
                msg_mv, val_off)
        elif nla_type == NFULA_TIMESTAMP:
            if val_end - val_off < _STRUCT_NFULNL_TIMESTAMP.size:
                raise NflogWireError("NFULA_TIMESTAMP truncated")
            sec, usec = _STRUCT_NFULNL_TIMESTAMP.unpack_from(
                msg_mv, val_off)
            timestamp_ns = sec * 1_000_000_000 + usec * 1_000
        elif nla_type == NFULA_MARK:
            if val_end - val_off < 4:
                raise NflogWireError("NFULA_MARK truncated")
            (mark,) = _STRUCT_BE32.unpack_from(msg_mv, val_off)
        elif nla_type == NFULA_IFINDEX_INDEV:
            if val_end - val_off < 4:
                raise NflogWireError("NFULA_IFINDEX_INDEV truncated")
            (indev,) = _STRUCT_BE32.unpack_from(msg_mv, val_off)
        elif nla_type == NFULA_IFINDEX_OUTDEV:
            if val_end - val_off < 4:
                raise NflogWireError("NFULA_IFINDEX_OUTDEV truncated")
            (outdev,) = _STRUCT_BE32.unpack_from(msg_mv, val_off)
        elif nla_type == NFULA_UID:
            if val_end - val_off >= 4:
                (uid,) = _STRUCT_BE32.unpack_from(msg_mv, val_off)
        elif nla_type == NFULA_GID:
            if val_end - val_off >= 4:
                (gid,) = _STRUCT_BE32.unpack_from(msg_mv, val_off)
        elif nla_type == NFULA_PREFIX:
            # NUL-terminated C string; exclude trailing NUL so callers
            # don't have to strip.
            pref_end = val_end
            if pref_end > val_off and msg_mv[pref_end - 1] == 0:
                pref_end -= 1
            prefix_mv = msg_mv[val_off:pref_end]
        elif nla_type == NFULA_PAYLOAD:
            payload_mv = msg_mv[val_off:val_end]
        # Unknown attrs are silently skipped (forward-compat).

        off += _nla_align(nla_len)

    return NflogFrame(
        hook=hook,
        hw_protocol=hw_protocol,
        timestamp_ns=timestamp_ns,
        mark=mark,
        indev=indev,
        outdev=outdev,
        uid=uid,
        gid=gid,
        prefix_mv=prefix_mv,
        payload_mv=payload_mv,
    )


# ---------------------------------------------------------------------------
# Socket
# ---------------------------------------------------------------------------


class NFULogSocket:
    """Single-group NFLOG subscription socket (``NETLINK_NETFILTER``).

    Lifecycle: ``NFULogSocket(group)`` → :meth:`bind` → repeated
    :meth:`recv_into` on a caller-owned buffer → :meth:`close`. Use as a
    context manager for auto-close.

    This class is deliberately thin: the config dance (PF_BIND, CMD_BIND,
    CFG_MODE = COPY_PACKET) is a one-time setup and has no perf budget;
    the hot path is ``sock.recv_into(buf)`` + :func:`parse_frame` on a
    ``memoryview`` of that buffer, neither of which allocates.
    """

    __slots__ = ("_group", "_seq", "_sock", "_ack_buf")

    def __init__(self, group: int, *, rcvbuf: int = 4 * 1024 * 1024) -> None:
        if not 0 <= group <= 0xFFFF:
            raise ValueError(f"nflog group out of range (0..65535): {group}")
        self._group = group
        self._seq = 0

        sock = socket.socket(
            socket.AF_NETLINK,
            socket.SOCK_RAW | socket.SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        )
        # Raise rcvbuf first; sink-stall is the typical drop cause, so
        # 4 MiB of kernel-side queue ≈ 1 s of headroom at 10 k pps.
        # SO_RCVBUFFORCE (33) bypasses ``rmem_max`` but needs CAP_NET_ADMIN;
        # Python's ``socket`` module doesn't expose the constant so we
        # use the raw number. Fall back to SO_RCVBUF for unprivileged
        # callers (mostly the test-suite smoke).
        _SO_RCVBUFFORCE = 33
        try:
            sock.setsockopt(socket.SOL_SOCKET, _SO_RCVBUFFORCE, rcvbuf)
        except (PermissionError, OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        # Port = 0 → kernel auto-assigns.
        sock.bind((0, 0))
        self._sock = sock
        self._ack_buf = bytearray(8192)

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "NFULogSocket":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------
    def bind(self) -> None:
        """Perform the CFG_CMD_BIND + CFG_MODE dance.

        The leading PF_UNBIND / PF_BIND pair is the ``libnetfilter_log``
        compatibility dance required for very old kernels; modern kernels
        tolerate both presence and EPERM on those messages, so we send
        without requiring an ACK.
        """
        self._send_cfg_cmd(NFULNL_CFG_CMD_PF_UNBIND,
                           family=socket.AF_INET, require_ack=False)
        self._send_cfg_cmd(NFULNL_CFG_CMD_PF_BIND,
                           family=socket.AF_INET, require_ack=False)
        self._send_cfg_cmd(NFULNL_CFG_CMD_BIND,
                           family=socket.AF_UNSPEC, require_ack=True)
        self._send_cfg_mode(NFULNL_COPY_PACKET, 0xFFFF, require_ack=True)

    def _send_cfg_cmd(
        self, cmd: int, *, family: int, require_ack: bool,
    ) -> None:
        payload = struct.pack("=B", cmd)
        nla = _pack_nla(NFULA_CFG_CMD, payload)
        body = _nfgen(family, self._group) + nla
        self._send_config(body, require_ack=require_ack)

    def _send_cfg_mode(
        self, mode: int, rng: int, *, require_ack: bool,
    ) -> None:
        # struct nfulnl_msg_config_mode: __be32 copy_range; __u8 copy_mode; __u8 pad
        payload = struct.pack(">IBxx", rng, mode)  # 7 bytes, NLA pads to 8
        nla = _pack_nla(NFULA_CFG_MODE, payload)
        body = _nfgen(socket.AF_UNSPEC, self._group) + nla
        self._send_config(body, require_ack=require_ack)

    def _send_config(self, body: bytes, *, require_ack: bool) -> None:
        self._seq += 1
        flags = NLM_F_REQUEST | (NLM_F_ACK if require_ack else 0)
        hdr = _STRUCT_NLMSGHDR.pack(
            NLMSGHDR_SIZE + len(body),
            NFULNL_MSG_CONFIG,
            flags,
            self._seq,
            0,
        )
        self._sock.send(hdr + body)
        if require_ack:
            self._wait_ack(self._seq)

    def _wait_ack(self, expect_seq: int) -> None:
        n = self._sock.recv_into(self._ack_buf)
        if n < NLMSGHDR_SIZE:
            raise OSError(f"netlink ack short read: {n} bytes")
        _len, mtype, _flags, seq, _pid = \
            _STRUCT_NLMSGHDR.unpack_from(self._ack_buf, 0)
        if mtype != NLMSG_ERROR:
            raise OSError(f"unexpected ack mtype 0x{mtype:04x}")
        # struct nlmsgerr: __s32 error; struct nlmsghdr msg;
        err = struct.unpack_from("=i", self._ack_buf, NLMSGHDR_SIZE)[0]
        if err != 0:
            raise OSError(-err, f"netlink config err seq={seq} err={err}")

    # ------------------------------------------------------------------
    # Receive
    # ------------------------------------------------------------------
    def recv_into(self, buf: bytearray) -> memoryview:
        """Read one datagram; return a ``memoryview`` of the valid prefix.

        Caller owns *buf*. Returned view becomes invalid on next call.
        Typical sizing: 64 KiB buffer covers the largest nfnetlink
        datagram the kernel will emit.
        """
        n = self._sock.recv_into(buf)
        return memoryview(buf)[:n]


def _main() -> int:
    """One-shot dump mode — used for the M0 kernel smoke test.

    ``sudo .venv/bin/python -m shorewalld.nflog_netlink --group 42``

    Requires CAP_NET_ADMIN. Matching traffic (``nft add rule ... log
    group 42 prefix "..."``) prints one decoded line per frame until
    interrupted.
    """
    import argparse

    from shorewalld.log_prefix import parse_log_prefix

    ap = argparse.ArgumentParser(
        description="Dump NFLOG frames for a group (M0 smoke tool).")
    ap.add_argument("--group", type=int, required=True,
                    help="nfnetlink_log group number to subscribe to")
    ap.add_argument("--buf-size", type=int, default=65536,
                    help="recv buffer size (bytes, default 64 KiB)")
    args = ap.parse_args()

    buf = bytearray(args.buf_size)
    with NFULogSocket(group=args.group) as sock:
        sock.bind()
        print(f"nflog: listening on group {args.group}", flush=True)
        try:
            while True:
                mv = sock.recv_into(buf)
                try:
                    frame = parse_frame(mv)
                except NflogWireError as exc:
                    print(f"nflog: decode error: {exc}", flush=True)
                    continue
                ev = parse_log_prefix(
                    frame.prefix_mv,
                    timestamp_ns=frame.timestamp_ns,
                )
                print(
                    f"hook={frame.hook} proto=0x{frame.hw_protocol:04x} "
                    f"mark={frame.mark} indev={frame.indev} "
                    f"outdev={frame.outdev} "
                    f"prefix={bytes(frame.prefix_mv).decode('ascii', 'replace') if frame.prefix_mv else ''!r} "
                    f"event={ev}",
                    flush=True,
                )
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
