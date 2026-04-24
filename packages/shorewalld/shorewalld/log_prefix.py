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
    """
    chain: str
    disposition: str
    rule_num: int | None
    timestamp_ns: int
    netns: str


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
