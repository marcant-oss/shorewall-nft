"""Tests for the pure-Python sd_notify(3) client.

Exercises the wire format against a captive ``AF_UNIX SOCK_DGRAM``
socket — no real systemd needed. Covers:

* ``$NOTIFY_SOCKET`` unset → every call is a silent no-op.
* Filesystem path + abstract namespace addresses.
* ``READY=1`` / ``RELOADING=1`` / ``STOPPING=1`` / ``STATUS=…`` payloads.
* Watchdog gating: ``WATCHDOG_USEC`` parsing, ``WATCHDOG_PID``
  belonging to a foreign PID disables the ping.
"""
from __future__ import annotations

import os
import socket

import pytest

from shorewalld import sd_notify


@pytest.fixture(autouse=True)
def _reset() -> None:
    sd_notify.reset_for_tests()
    yield
    sd_notify.reset_for_tests()


def _bind_path(tmp_path) -> tuple[socket.socket, str]:
    sock_path = str(tmp_path / "notify.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(sock_path)
    s.settimeout(1.0)
    return s, sock_path


def test_no_op_when_env_unset(monkeypatch) -> None:
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert sd_notify.enabled() is False
    # None of these may raise.
    sd_notify.ready("startup")
    sd_notify.reloading()
    sd_notify.watchdog_ping()
    sd_notify.status("hello")
    sd_notify.stopping()


def test_ready_with_status(monkeypatch, tmp_path) -> None:
    sock, path = _bind_path(tmp_path)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    monkeypatch.delenv("WATCHDOG_PID", raising=False)

    assert sd_notify.enabled() is True
    sd_notify.ready("netns=3 sets=8 elements=412")

    data, _ = sock.recvfrom(4096)
    assert data == b"READY=1\nSTATUS=netns=3 sets=8 elements=412"
    sock.close()


def test_reloading_then_ready(monkeypatch, tmp_path) -> None:
    sock, path = _bind_path(tmp_path)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)

    sd_notify.reloading()
    sd_notify.ready()

    first, _ = sock.recvfrom(4096)
    second, _ = sock.recvfrom(4096)
    assert first == b"RELOADING=1"
    assert second == b"READY=1"
    sock.close()


def test_stopping_and_status(monkeypatch, tmp_path) -> None:
    sock, path = _bind_path(tmp_path)
    monkeypatch.setenv("NOTIFY_SOCKET", path)

    sd_notify.status("warming caches")
    sd_notify.stopping()

    first, _ = sock.recvfrom(4096)
    second, _ = sock.recvfrom(4096)
    assert first == b"STATUS=warming caches"
    assert second == b"STOPPING=1"
    sock.close()


def test_status_empty_text_is_no_op(monkeypatch, tmp_path) -> None:
    sock, path = _bind_path(tmp_path)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    sock.settimeout(0.05)

    sd_notify.status("")  # must NOT send anything

    with pytest.raises(socket.timeout):
        sock.recvfrom(4096)
    sock.close()


def test_watchdog_disabled_when_usec_missing(monkeypatch, tmp_path) -> None:
    sock, path = _bind_path(tmp_path)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)
    sock.settimeout(0.05)

    assert sd_notify.watchdog_interval_sec() == 0.0
    assert sd_notify.status_interval_sec() == 10.0
    sd_notify.watchdog_ping()  # no-op without WATCHDOG_USEC

    with pytest.raises(socket.timeout):
        sock.recvfrom(4096)
    sock.close()


def test_watchdog_enabled_pings(monkeypatch, tmp_path) -> None:
    sock, path = _bind_path(tmp_path)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    monkeypatch.setenv("WATCHDOG_USEC", "30000000")  # 30 s
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid()))

    assert sd_notify.watchdog_interval_sec() == pytest.approx(15.0)
    assert sd_notify.status_interval_sec() == pytest.approx(10.0)
    sd_notify.watchdog_ping()

    data, _ = sock.recvfrom(4096)
    assert data == b"WATCHDOG=1"
    sock.close()


def test_watchdog_ignored_for_foreign_pid(monkeypatch, tmp_path) -> None:
    sock, path = _bind_path(tmp_path)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    monkeypatch.setenv("WATCHDOG_USEC", "30000000")
    monkeypatch.setenv("WATCHDOG_PID", str(os.getpid() + 99999))
    sock.settimeout(0.05)

    assert sd_notify.watchdog_interval_sec() == 0.0
    sd_notify.watchdog_ping()

    with pytest.raises(socket.timeout):
        sock.recvfrom(4096)
    sock.close()


def test_abstract_namespace_address(monkeypatch) -> None:
    # Bind a server in the abstract namespace and verify the
    # client correctly translates the leading '@' to NUL.
    abs_name = "shorewalld-sd-notify-test"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind("\x00" + abs_name)
    server.settimeout(1.0)

    monkeypatch.setenv("NOTIFY_SOCKET", "@" + abs_name)
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)

    sd_notify.notify("READY=1")
    data, _ = server.recvfrom(4096)
    assert data == b"READY=1"
    server.close()


def test_send_failure_swallowed(monkeypatch, tmp_path) -> None:
    # Point at a path that does NOT have a listener — sendto should
    # raise ECONNREFUSED, but notify() must swallow it silently.
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "nonexistent.sock"))
    monkeypatch.delenv("WATCHDOG_USEC", raising=False)

    sd_notify.ready("never delivered")  # no exception expected
    sd_notify.stopping()
