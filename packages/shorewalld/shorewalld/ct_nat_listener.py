"""Conntrack-event NAT listener for shorewalld.

Subscribes to ``NFNLGRP_CONNTRACK_NEW`` (multicast group 1) **and**
``NFNLGRP_CONNTRACK_DESTROY`` (group 3) inside the worker's netns and
synthesises a :class:`~shorewalld.log_prefix.LogEvent` for every
NAT-tracked flow at both lifecycle ends. UPDATE events (group 2) are
deliberately not subscribed — for TCP they fire on every state
transition and the volume is two orders of magnitude higher than
new/destroy without adding NAT-relevant info.

The listener is allocation-light: each event yields one ``LogEvent``
that piggybacks on the existing NFLOG SEQPACKET wire (``MAGIC_NFLOG``
in :mod:`~shorewalld.log_codec`). Chain encodes the lifecycle phase
so operators can grep / filter by phase + by translation kind:

    chain=ct-nat-new  disposition=DNAT->10.0.0.5:80
    chain=ct-nat-end  disposition=DNAT->10.0.0.5:80
    chain=ct-nat-new  disposition=SNAT->217.14.160.75:34521
    chain=ct-nat-new  disposition=DNAT->10.0.0.5:80,SNAT->217.14.160.75:34521

Pre/post addresses end up in the standard packet fields:

* ``packet_saddr`` / ``packet_sport`` — ORIG.src (pre-NAT source)
* ``packet_daddr`` / ``packet_dport`` — ORIG.dst (pre-NAT destination
  — what the client targeted before DNAT rewrote it)
* The translated tuple is encoded into ``disposition`` (REPLY.src is
  the post-DNAT real backend; REPLY.dst is the post-SNAT public source).

Conntrack-tuple semantics (Linux ``CTA_TUPLE_ORIG`` / ``CTA_TUPLE_REPLY``):

  ORIG = (src, dst, sport, dport)            — what the client sent
  REPLY = (post-DNAT-dst, post-SNAT-src,      — what backend would send back
          post-DNAT-dport, post-SNAT-sport)

* DNAT: ``ORIG.dst != REPLY.src`` → backend = REPLY.src
* SNAT: ``ORIG.src != REPLY.dst`` → public src = REPLY.dst

Degrades silently when:

* pyroute2 is not installed (worker drops the import, no NAT events emitted)
* netns does not allow ``NETLINK_NETFILTER`` (rare; capability missing)
* event flood saturates the SEQPACKET — the `nft_worker`'s
  ``send_nowait`` drop-on-full applies (same path as NFLOG).
"""

from __future__ import annotations

import logging
import time

try:
    from pyroute2.netlink.nfnetlink.nfctsocket import NFCTSocket
    _PYROUTE2_AVAILABLE = True
except ImportError:
    NFCTSocket = None  # type: ignore[assignment]
    _PYROUTE2_AVAILABLE = False

from .log_prefix import LogEvent

log = logging.getLogger("shorewalld.ct_nat_listener")

#: Conntrack multicast group bitmasks (NFNLGRP_CONNTRACK_*).
_GROUP_NEW = 1 << 0
_GROUP_DESTROY = 1 << 2

#: Conntrack status flags from ``<linux/netfilter/nf_conntrack_common.h>``.
IPS_SRC_NAT = 1 << 4   # 0x10 — src was translated by SNAT
IPS_DST_NAT = 1 << 5   # 0x20 — dst was translated by DNAT


def open_sockets() -> list[tuple["NFCTSocket", str]]:
    """Bind NFCTSocket per group; return list of ``(sock, chain_label)``.

    One socket per multicast group so events are unambiguously categorised
    (NEW vs DESTROY both arrive as ``IPCTNL_MSG_CT_NEW`` / ``CT_DELETE`` —
    the kernel doesn't tag the originating group on the wire). Each socket
    fd ends up registered separately in the worker's selector loop with
    the chain-label as the user-data tag.

    Empty list if pyroute2 is unavailable or every bind fails.
    """
    if not _PYROUTE2_AVAILABLE:
        return []
    out: list[tuple[NFCTSocket, str]] = []
    for group_mask, chain_label in (
        (_GROUP_NEW, "ct-nat-new"),
        (_GROUP_DESTROY, "ct-nat-end"),
    ):
        try:
            s = NFCTSocket()
            target = getattr(s, "asyncore", s)
            target.bind(groups=group_mask)
        except OSError as exc:
            log.warning("ct-nat: bind(group=%d) failed: %s — skipping",
                        group_mask, exc)
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
            continue
        out.append((s, chain_label))
    return out


# ── Backward-compat shim ────────────────────────────────────────────────
# Older code paths called ``open_socket()`` (singular) and got just the
# NEW-group subscriber. Keep the name working in case test fixtures hit
# the older API.
def open_socket() -> "NFCTSocket | None":
    pairs = open_sockets()
    return pairs[0][0] if pairs else None


def drain_events(
    sock: "NFCTSocket",
    netns: str,
    chain_label: str = "ct-nat-new",
) -> list[LogEvent]:
    """Pull all queued events from *sock*, decode NAT entries to LogEvents.

    *chain_label* tags the lifecycle phase on the resulting LogEvent
    (``ct-nat-new`` / ``ct-nat-end``). Non-NAT events (i.e. flows whose
    ``CTA_STATUS`` lacks IPS_SRC_NAT and IPS_DST_NAT) are silently
    dropped. Decoder errors are logged at DEBUG and the event is skipped
    — never raised, since the listener runs inside the worker's main
    selector loop and an exception would propagate into the IPC reply
    pump.
    """
    out: list[LogEvent] = []
    try:
        msgs = sock.get()
    except OSError as exc:
        log.debug("ct-nat: recv error: %s", exc)
        return out
    for m in msgs:
        try:
            ev = _decode_nat_event(m, netns, chain_label)
        except Exception as exc:  # noqa: BLE001
            log.debug("ct-nat: decode failed: %s", exc)
            continue
        if ev is not None:
            out.append(ev)
    return out


def _decode_nat_event(
    msg, netns: str, chain_label: str = "ct-nat-new",
) -> "LogEvent | None":
    """Decode one ctnetlink message into a LogEvent if it carries NAT bits."""
    attrs = dict(msg.get("attrs", []))
    status = attrs.get("CTA_STATUS")
    if status is None or not (status & (IPS_SRC_NAT | IPS_DST_NAT)):
        return None

    orig_attrs = _attrs_dict(attrs.get("CTA_TUPLE_ORIG"))
    reply_attrs = _attrs_dict(attrs.get("CTA_TUPLE_REPLY"))
    orig_ip = _attrs_dict(orig_attrs.get("CTA_TUPLE_IP"))
    reply_ip = _attrs_dict(reply_attrs.get("CTA_TUPLE_IP"))
    orig_proto = _attrs_dict(orig_attrs.get("CTA_TUPLE_PROTO"))
    reply_proto = _attrs_dict(reply_attrs.get("CTA_TUPLE_PROTO"))

    if "CTA_IP_V4_SRC" in orig_ip:
        family = 4
        orig_src = str(orig_ip.get("CTA_IP_V4_SRC", ""))
        orig_dst = str(orig_ip.get("CTA_IP_V4_DST", ""))
        reply_src = str(reply_ip.get("CTA_IP_V4_SRC", ""))
        reply_dst = str(reply_ip.get("CTA_IP_V4_DST", ""))
    elif "CTA_IP_V6_SRC" in orig_ip:
        family = 6
        orig_src = str(orig_ip.get("CTA_IP_V6_SRC", ""))
        orig_dst = str(orig_ip.get("CTA_IP_V6_DST", ""))
        reply_src = str(reply_ip.get("CTA_IP_V6_SRC", ""))
        reply_dst = str(reply_ip.get("CTA_IP_V6_DST", ""))
    else:
        return None

    proto_num = int(orig_proto.get("CTA_PROTO_NUM", 0))
    orig_sport = int(orig_proto.get("CTA_PROTO_SRC_PORT", 0) or 0)
    orig_dport = int(orig_proto.get("CTA_PROTO_DST_PORT", 0) or 0)
    reply_sport = int(reply_proto.get("CTA_PROTO_SRC_PORT", 0) or 0)
    reply_dport = int(reply_proto.get("CTA_PROTO_DST_PORT", 0) or 0)

    bits: list[str] = []
    if status & IPS_DST_NAT:
        # DNAT translates the destination — REPLY.src is the real backend.
        if reply_sport:
            bits.append(f"DNAT->{reply_src}:{reply_sport}")
        else:
            bits.append(f"DNAT->{reply_src}")
    if status & IPS_SRC_NAT:
        # SNAT translates the source — REPLY.dst is the public src.
        if reply_dport:
            bits.append(f"SNAT->{reply_dst}:{reply_dport}")
        else:
            bits.append(f"SNAT->{reply_dst}")
    disposition = ",".join(bits) or "NAT"
    # The disposition wire field is a u8-length string; keep within limit.
    if len(disposition) > 240:
        disposition = disposition[:237] + "..."

    return LogEvent(
        chain=chain_label,
        disposition=disposition,
        rule_num=None,
        timestamp_ns=time.time_ns(),
        netns=netns,
        packet_family=family,
        packet_proto=proto_num,
        packet_saddr=orig_src,
        packet_daddr=orig_dst,
        packet_sport=orig_sport,
        packet_dport=orig_dport,
    )


def _attrs_dict(node) -> dict:
    """Convert a pyroute2-nested-attrs node to a flat dict."""
    if not node or not isinstance(node, dict):
        return {}
    return dict(node.get("attrs", []))
