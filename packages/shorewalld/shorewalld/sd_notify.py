"""Pure-Python ``sd_notify(3)`` client for shorewalld.

Implements the systemd notification protocol over the unix datagram
socket pointed to by ``$NOTIFY_SOCKET``. No libsystemd link, no
extras dependency — when the env var is missing every call is a
silent no-op so unit tests, dev runs, and non-systemd containers
just work.

Typical use from :mod:`shorewalld.core`::

    from shorewalld import sd_notify

    sd_notify.ready(status="initialised, scraping 3 netns")
    while running:
        sd_notify.watchdog_ping()
        sd_notify.status("...")
        await asyncio.sleep(sd_notify.status_interval_sec())
    sd_notify.stopping()

The watchdog interval is exposed via :func:`watchdog_interval_sec`;
ping at half that cadence per ``sd_watchdog_enabled(3)``.
"""
from __future__ import annotations

import logging
import os
import socket

log = logging.getLogger("shorewalld.core")

_socket: socket.socket | None = None
_addr: str | bytes | None = None
_watchdog_usec: int = 0
_initialised: bool = False


def _resolve_addr(env: str) -> str | bytes | None:
    """Translate ``$NOTIFY_SOCKET`` to a usable socket address.

    A leading ``@`` selects the Linux abstract namespace (encoded as
    a leading NUL byte). An empty string disables notifications.
    """
    if not env:
        return None
    if env[0] == "@":
        return b"\x00" + env[1:].encode("utf-8")
    return env


def _init() -> None:
    global _socket, _addr, _watchdog_usec, _initialised
    if _initialised:
        return
    _initialised = True

    addr = _resolve_addr(os.environ.get("NOTIFY_SOCKET", ""))
    if addr is None:
        return

    try:
        _socket = socket.socket(
            socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
        _addr = addr
    except OSError as e:
        log.debug("sd_notify: socket() failed: %s", e)
        _socket = None
        _addr = None
        return

    # Honour WATCHDOG_PID if set: only the named PID may emit
    # WATCHDOG=1 pings (sd_watchdog_enabled(3)).
    wd_pid = os.environ.get("WATCHDOG_PID")
    if wd_pid and wd_pid.isdigit() and int(wd_pid) != os.getpid():
        _watchdog_usec = 0
        return
    try:
        _watchdog_usec = int(os.environ.get("WATCHDOG_USEC", "0"))
    except ValueError:
        _watchdog_usec = 0


def enabled() -> bool:
    """Return ``True`` if ``$NOTIFY_SOCKET`` was set at process start."""
    _init()
    return _socket is not None


def watchdog_interval_sec() -> float:
    """Recommended ping cadence in seconds, or ``0.0`` when disabled.

    Per ``sd_watchdog_enabled(3)`` services should ping at half the
    configured ``WATCHDOG_USEC`` to leave headroom for jitter.
    """
    _init()
    if _watchdog_usec <= 0:
        return 0.0
    return _watchdog_usec / 2_000_000.0


def status_interval_sec() -> float:
    """Cadence at which :func:`watchdog_ping` + :func:`status` should fire.

    Picks the shorter of 10 s and the watchdog cadence so the same
    timer can drive both. Returns 10 s when the watchdog is off so
    the status text still refreshes for ``systemctl status``.
    """
    wd = watchdog_interval_sec()
    if wd > 0:
        return min(10.0, wd)
    return 10.0


def notify(line: str) -> None:
    """Send a single ``KEY=value`` (or multi-line) notification.

    No-op when ``$NOTIFY_SOCKET`` is unset. Send errors are logged
    at DEBUG and swallowed — the daemon must never abort because a
    systemd notification could not be delivered.
    """
    _init()
    if _socket is None or _addr is None:
        return
    try:
        _socket.sendto(line.encode("utf-8"), _addr)
    except OSError as e:
        log.debug("sd_notify send failed: %s", e)


def ready(status_text: str | None = None) -> None:
    """Signal init complete (``READY=1``) plus optional ``STATUS=``."""
    msg = "READY=1"
    if status_text:
        msg = f"{msg}\nSTATUS={status_text}"
    notify(msg)


def reloading() -> None:
    """Signal reload in progress (``RELOADING=1``).

    Pair with a follow-up :func:`ready` call once the reload
    finishes so ``systemctl reload`` reports completion.
    """
    notify("RELOADING=1")


def stopping() -> None:
    """Signal shutdown in progress (``STOPPING=1``)."""
    notify("STOPPING=1")


def watchdog_ping() -> None:
    """Send ``WATCHDOG=1`` if the manager configured a watchdog timeout."""
    _init()
    if _watchdog_usec <= 0:
        return
    notify("WATCHDOG=1")


def status(text: str) -> None:
    """Update the ``systemctl status`` one-liner (``STATUS=…``)."""
    if not text:
        return
    notify(f"STATUS={text}")


def reset_for_tests() -> None:
    """Reset module state so a unit test can re-initialise from scratch."""
    global _socket, _addr, _watchdog_usec, _initialised
    if _socket is not None:
        try:
            _socket.close()
        except OSError:
            pass
    _socket = None
    _addr = None
    _watchdog_usec = 0
    _initialised = False
