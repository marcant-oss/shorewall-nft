"""Conntrack-event NAT listener for shorewalld.

Subscribes to ``NFNLGRP_CONNTRACK_NEW`` (multicast group 1) inside the
worker's netns and synthesises a :class:`~shorewalld.log_prefix.LogEvent`
for every newly-tracked flow that carries a SRC_NAT or DST_NAT bit.

The listener is allocation-light: each event yields one ``LogEvent``
that piggybacks on the existing NFLOG SEQPACKET wire (``MAGIC_NFLOG``
in :mod:`~shorewalld.log_codec`). Disposition encodes the translation
target so operators can grep for ``DNAT->`` / ``SNAT->`` in logs:

    chain=ct-nat disposition=DNAT->10.0.0.5:80
    chain=ct-nat disposition=SNAT->217.14.160.75:34521
    chain=ct-nat disposition=DNAT->10.0.0.5:80,SNAT->217.14.160.75:34521

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

#: ``NFNLGRP_CONNTRACK_NEW`` multicast group bitmask.
_GROUP_NEW = 1 << 0

#: Conntrack status flags from ``<linux/netfilter/nf_conntrack_common.h>``.
IPS_SRC_NAT = 1 << 4   # 0x10 — src was translated by SNAT
IPS_DST_NAT = 1 << 5   # 0x20 — dst was translated by DNAT


def open_socket() -> "NFCTSocket | None":
    """Bind a NFCTSocket to the NEW multicast group; returns None on error."""
    if not _PYROUTE2_AVAILABLE:
        return None
    try:
        s = NFCTSocket()
        # pyroute2 0.9 moved bind() onto an inner asyncore attribute.
        target = getattr(s, "asyncore", s)
        target.bind(groups=_GROUP_NEW)
        return s
    except OSError as exc:
        log.warning("ct-nat: bind(NFNLGRP_CONNTRACK_NEW) failed: %s — disabled", exc)
        return None


def drain_events(sock: "NFCTSocket", netns: str) -> list[LogEvent]:
    """Pull all queued events from *sock*, decode NAT entries to LogEvents.

    Non-NAT events (i.e. flows whose ``CTA_STATUS`` lacks IPS_SRC_NAT and
    IPS_DST_NAT) are silently dropped. Decoder errors are logged at DEBUG
    and the event is skipped — never raised, since the listener runs
    inside the worker's main selector loop and an exception would
    propagate into the IPC reply pump.
    """
    out: list[LogEvent] = []
    try:
        msgs = sock.get()
    except OSError as exc:
        log.debug("ct-nat: recv error: %s", exc)
        return out
    for m in msgs:
        try:
            ev = _decode_nat_event(m, netns)
        except Exception as exc:  # noqa: BLE001
            log.debug("ct-nat: decode failed: %s", exc)
            continue
        if ev is not None:
            out.append(ev)
    return out


def _decode_nat_event(msg, netns: str) -> "LogEvent | None":
    """Decode one CTA_NEW message into a LogEvent if it carries NAT bits."""
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
        chain="ct-nat",
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
