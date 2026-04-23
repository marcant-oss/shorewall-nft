"""Unit tests for shorewall_nft.verify.netns_topology.

These tests run without root and without any real netns by patching the
three guards that block construction and execution:

  1. ``os.geteuid``        — returns 0 to satisfy the root check.
  2. ``os.open``           — returns a sentinel int; never touches /proc.
  3. ``netns.listnetns``   — returns [] so ns_create always calls create.
  4. ``netns.create``      — no-op fake.
  5. ``netns.remove``      — no-op fake.
  6. ``NetNS``             — replaced with a MagicMock so no kernel access.

All helper fixtures use a ``pytest.fixture`` that wires those patches so
individual tests just receive a ready-to-use ``NetnsTopology`` instance.
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import MagicMock, call, patch

import pytest

import shorewall_nft.verify.netns_topology as _mod
from shorewall_nft.verify.netns_topology import NetnsTopology


# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------

_FAKE_FD = 42  # sentinel fd value returned by all fake os.open calls


def _make_fake_ns_handle():
    """Return a MagicMock that looks like a pyroute2 NetNS instance."""
    handle = MagicMock()
    handle.link_lookup.return_value = [1]  # any non-empty list → index 1
    return handle


class _FakeNetNS:
    """Drop-in for pyroute2.NetNS that returns a fresh MagicMock per name.

    Keeps one handle per name so that topo.ns("X") called twice returns
    the same fake object (matching the real caching behaviour).
    """

    _handles: dict[str, MagicMock] = {}

    @classmethod
    def reset(cls) -> None:
        cls._handles.clear()

    def __new__(cls, name: str):  # type: ignore[override]
        if name not in cls._handles:
            h = _make_fake_ns_handle()
            cls._handles[name] = h
        return cls._handles[name]


@pytest.fixture()
def topo(monkeypatch):
    """A NetnsTopology instance constructed without root or real netns.

    Patches applied for the duration of the test:
      - os.geteuid → 0
      - os.open    → _FAKE_FD (never opens /proc or /run/netns)
      - os.close   → no-op
      - netns.listnetns → []
      - netns.create    → no-op
      - netns.remove    → no-op
      - NetNS           → _FakeNetNS (returns per-name MagicMock handles)
    """
    _FakeNetNS.reset()
    monkeypatch.setattr(_mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_mod.os, "open", lambda *a, **kw: _FAKE_FD)
    monkeypatch.setattr(_mod.os, "close", lambda fd: None)
    monkeypatch.setattr(_mod.netns, "listnetns", lambda: [])
    monkeypatch.setattr(_mod.netns, "create", lambda name: None)
    monkeypatch.setattr(_mod.netns, "remove", lambda name: None)
    monkeypatch.setattr(_mod, "NetNS", _FakeNetNS)

    t = NetnsTopology()
    yield t
    # close() without the real os.close calls
    t.close()
    _FakeNetNS.reset()


# ---------------------------------------------------------------------------
# 1. Construction / root guard
# ---------------------------------------------------------------------------

class TestConstruction:
    """NetnsTopology raises on non-root and on missing pyroute2."""

    def test_raises_if_not_root(self, monkeypatch):
        monkeypatch.setattr(_mod.os, "geteuid", lambda: 1000)
        with pytest.raises(PermissionError, match="requires root"):
            NetnsTopology()

    def test_raises_if_pyroute2_missing(self, monkeypatch):
        monkeypatch.setattr(_mod, "_PYROUTE_OK", False)
        monkeypatch.setattr(_mod.os, "geteuid", lambda: 0)
        with pytest.raises(RuntimeError, match="pyroute2 is not available"):
            NetnsTopology()

    def test_constructs_with_root_and_pyroute2(self, monkeypatch):
        monkeypatch.setattr(_mod.os, "geteuid", lambda: 0)
        monkeypatch.setattr(_mod.os, "open", lambda *a, **kw: _FAKE_FD)
        monkeypatch.setattr(_mod.os, "close", lambda fd: None)
        t = NetnsTopology()
        assert t._host_fd == _FAKE_FD
        t.close()

    def test_host_fd_set_after_init(self, topo):
        assert topo._host_fd == _FAKE_FD


# ---------------------------------------------------------------------------
# 2. ns_create / ns_delete lifecycle
# ---------------------------------------------------------------------------

class TestNsCreateDelete:
    """ns_create populates _fds; ns_delete clears caches."""

    def test_ns_create_adds_fd(self, topo):
        topo.ns_create("NS_CLIENT")
        assert "NS_CLIENT" in topo._fds
        assert topo._fds["NS_CLIENT"] == _FAKE_FD

    def test_ns_create_idempotent(self, topo, monkeypatch):
        """Second call must not re-open; fd must stay the same."""
        topo.ns_create("NS_FW")
        first_fd = topo._fds["NS_FW"]
        topo.ns_create("NS_FW")
        assert topo._fds["NS_FW"] == first_fd

    def test_ns_create_skips_netns_create_when_already_listed(
            self, topo, monkeypatch):
        """If listnetns already contains the name, netns.create is not called."""
        create_calls: list[str] = []
        monkeypatch.setattr(_mod.netns, "listnetns", lambda: ["NS_SERVER"])
        monkeypatch.setattr(_mod.netns, "create",
                            lambda name: create_calls.append(name))
        topo.ns_create("NS_SERVER")
        assert create_calls == []

    def test_ns_delete_clears_handle_and_fd(self, topo):
        topo.ns_create("NS_FW")
        _ = topo.ns("NS_FW")          # populates _handles
        assert "NS_FW" in topo._handles
        topo.ns_delete("NS_FW")
        assert "NS_FW" not in topo._handles
        assert "NS_FW" not in topo._fds

    def test_ns_delete_nonexistent_does_not_raise(self, topo):
        topo.ns_delete("does_not_exist")   # must not raise


# ---------------------------------------------------------------------------
# 3. ns() / ns_fd() handle caching
# ---------------------------------------------------------------------------

class TestHandleCaching:
    """ns() caches handles; ns_fd() caches fds."""

    def test_ns_returns_handle(self, topo):
        h = topo.ns("NS_CLIENT")
        assert h is not None

    def test_ns_caches_handle(self, topo):
        h1 = topo.ns("NS_CLIENT")
        h2 = topo.ns("NS_CLIENT")
        assert h1 is h2

    def test_ns_fd_returns_int(self, topo):
        fd = topo.ns_fd("NS_FW")
        assert isinstance(fd, int)

    def test_ns_fd_cached(self, topo):
        fd1 = topo.ns_fd("NS_FW")
        fd2 = topo.ns_fd("NS_FW")
        assert fd1 == fd2

    def test_refresh_handles_clears_cache(self, topo):
        topo.ns("NS_CLIENT")
        topo.refresh_handles()
        # After refresh the internal cache is empty
        assert topo._handles == {}
        # ns() must still work (re-populates the cache)
        h2 = topo.ns("NS_CLIENT")
        assert h2 is not None
        assert "NS_CLIENT" in topo._handles


# ---------------------------------------------------------------------------
# 4. close()
# ---------------------------------------------------------------------------

class TestClose:
    """close() drops all handles, fds, and host_fd."""

    def test_close_clears_everything(self, topo):
        topo.ns_create("NS_FW")
        topo.ns_create("NS_CLIENT")
        _ = topo.ns("NS_FW")
        topo.close()
        assert topo._handles == {}
        assert topo._fds == {}
        assert topo._host_fd is None

    def test_close_idempotent(self, topo):
        topo.close()
        topo.close()   # must not raise


# ---------------------------------------------------------------------------
# 5. veth_add_peer
# ---------------------------------------------------------------------------

class TestVethAddPeer:
    """veth_add_peer calls link('add', ...) when the interface is absent."""

    def test_veth_add_called_when_missing(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = []   # interface does not exist
        topo.veth_add_peer("NS_FW", "veth-fw-cl", "veth-cl-fw")
        handle.link.assert_called_once_with(
            "add", ifname="veth-fw-cl", kind="veth",
            peer={"ifname": "veth-cl-fw"})

    def test_veth_add_skipped_when_present(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = [5]  # interface already exists
        topo.veth_add_peer("NS_FW", "veth-fw-cl", "veth-cl-fw")
        handle.link.assert_not_called()

    def test_veth_add_ignores_eexist(self, topo):
        """EEXIST (code 17) from link() must be silently ignored."""
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = []
        # Build a NetlinkError with code=17 (EEXIST).
        # NetlinkError(code, msg=None) — code is required.
        from pyroute2.netlink.exceptions import NetlinkError as _NLE
        exc = _NLE(17)
        handle.link.side_effect = exc
        topo.veth_add_peer("NS_FW", "veth-fw-cl", "veth-cl-fw")   # must not raise


# ---------------------------------------------------------------------------
# 6. link_set_netns / link_rename / link_up
# ---------------------------------------------------------------------------

class TestLinkHelpers:
    """link_set_netns, link_rename, link_up call link('set', ...) correctly."""

    def test_link_set_netns_moves_interface(self, topo):
        src_handle = topo.ns("NS_FW")
        src_handle.link_lookup.return_value = [3]
        topo.link_set_netns("NS_FW", "veth-fw-cl", "NS_CLIENT")
        src_handle.link.assert_called_once_with(
            "set", index=3, net_ns_fd=_FAKE_FD)

    def test_link_set_netns_noop_when_missing(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = []
        topo.link_set_netns("NS_FW", "missing", "NS_CLIENT")
        handle.link.assert_not_called()

    def test_link_rename(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = [7]
        topo.link_rename("NS_FW", "eth0", "bond0")
        handle.link.assert_called_once_with("set", index=7, ifname="bond0")

    def test_link_up(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = [2]
        topo.link_up("NS_FW", "eth0")
        handle.link.assert_called_once_with("set", index=2, state="up")

    def test_link_up_noop_when_missing(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = []
        topo.link_up("NS_FW", "eth0")
        handle.link.assert_not_called()


# ---------------------------------------------------------------------------
# 7. addr_add
# ---------------------------------------------------------------------------

class TestAddrAdd:
    """addr_add issues addr('add', ...) with the correct AF constant."""

    def test_addr_add_ipv4(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = [4]
        topo.addr_add("NS_FW", "eth0", "10.0.0.1", 24, family=4)
        handle.addr.assert_called_once_with(
            "add", index=4, address="10.0.0.1", prefixlen=24,
            family=2)   # AF_INET = 2

    def test_addr_add_ipv6(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = [4]
        topo.addr_add("NS_FW", "eth0", "fd00::1", 64, family=6)
        handle.addr.assert_called_once_with(
            "add", index=4, address="fd00::1", prefixlen=64,
            family=10)  # AF_INET6 = 10

    def test_addr_add_noop_when_iface_missing(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = []
        topo.addr_add("NS_FW", "missing", "10.0.0.1", 24)
        handle.addr.assert_not_called()


# ---------------------------------------------------------------------------
# 8. route_add / rule_add
# ---------------------------------------------------------------------------

class TestRouteAdd:
    """route_add builds the correct kwargs for ns().route('add', ...)."""

    def test_route_add_with_dev(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = [3]
        topo.route_add("NS_FW", "10.0.1.0/24", dev="eth0")
        handle.route.assert_called_once_with(
            "add", dst="10.0.1.0/24", family=2, oif=3)

    def test_route_add_with_gw(self, topo):
        handle = topo.ns("NS_FW")
        topo.route_add("NS_FW", "0.0.0.0/0", gw="10.0.0.1")
        handle.route.assert_called_once_with(
            "add", dst="0.0.0.0/0", family=2, gateway="10.0.0.1")

    def test_route_add_ipv6(self, topo):
        handle = topo.ns("NS_FW")
        topo.route_add("NS_FW", "::/0", gw="fd00::1", family=6)
        handle.route.assert_called_once_with(
            "add", dst="::/0", family=10, gateway="fd00::1")

    def test_route_add_with_table(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = [2]
        topo.route_add("NS_FW", "10.0.0.0/8", dev="eth0", table=100)
        call_kwargs = handle.route.call_args
        assert call_kwargs.kwargs.get("table") == 100

    def test_route_add_noop_when_dev_missing(self, topo):
        handle = topo.ns("NS_FW")
        handle.link_lookup.return_value = []
        topo.route_add("NS_FW", "10.0.0.0/8", dev="missing")
        handle.route.assert_not_called()

    def test_rule_add(self, topo):
        handle = topo.ns("NS_FW")
        topo.rule_add("NS_FW", "10.0.0.0/24", table=100)
        handle.rule.assert_called_once_with(
            "add", src="10.0.0.0/24", table=100, family=2)

    def test_rule_add_ipv6(self, topo):
        handle = topo.ns("NS_FW")
        topo.rule_add("NS_FW", "fd00::/48", table=200, family=6)
        handle.rule.assert_called_once_with(
            "add", src="fd00::/48", table=200, family=10)


# ---------------------------------------------------------------------------
# 9. sysctl_set
# ---------------------------------------------------------------------------

class TestSysctlSet:
    """sysctl_set enters the target ns, writes /proc/sys/..., then restores."""

    def _make_sysctl_patches(self, monkeypatch, topo, captured):
        """Patch _setns and open(path, 'w') for sysctl tests."""
        setns_calls: list[int] = []
        monkeypatch.setattr(_mod, "_setns", lambda fd: setns_calls.append(fd))
        captured["setns_calls"] = setns_calls

        written: list[tuple[str, str]] = []
        original_open = open

        def _fake_open(path, mode="r", *args, **kwargs):
            if mode == "w" and path.startswith("/proc/sys/"):
                class _FakeFile:
                    def __enter__(self2): return self2
                    def __exit__(self2, *a): return False
                    def write(self2, v): written.append((path, v))
                return _FakeFile()
            return original_open(path, mode, *args, **kwargs)

        import builtins
        monkeypatch.setattr(builtins, "open", _fake_open)
        captured["written"] = written

    def test_sysctl_set_string_key(self, topo, monkeypatch):
        topo.ns_create("NS_FW")
        captured: dict = {}
        self._make_sysctl_patches(monkeypatch, topo, captured)
        topo.sysctl_set("NS_FW", "net/ipv4/ip_forward", "1")
        assert ("/proc/sys/net/ipv4/ip_forward", "1") in captured["written"]

    def test_sysctl_set_list_key(self, topo, monkeypatch):
        """List form avoids splitting on dots in interface names."""
        topo.ns_create("NS_FW")
        captured: dict = {}
        self._make_sysctl_patches(monkeypatch, topo, captured)
        topo.sysctl_set("NS_FW",
                        ["net", "ipv4", "conf", "bond0.20", "rp_filter"], "2")
        assert ("/proc/sys/net/ipv4/conf/bond0.20/rp_filter", "2") in captured["written"]

    def test_sysctl_restores_ns_after_write(self, topo, monkeypatch):
        """_setns must be called twice: once to enter, once to restore."""
        topo.ns_create("NS_FW")
        captured: dict = {}
        self._make_sysctl_patches(monkeypatch, topo, captured)
        topo.sysctl_set("NS_FW", "net/ipv4/ip_forward", "1")
        # setns called at least twice: enter target + restore host
        assert len(captured["setns_calls"]) >= 2


# ---------------------------------------------------------------------------
# 10. exec_in_ns
# ---------------------------------------------------------------------------

class TestExecInNs:
    """exec_in_ns delegates to subprocess.run with a setns preexec_fn."""

    def test_exec_in_ns_calls_subprocess_run(self, topo, monkeypatch):
        runs: list[dict] = []

        def _fake_run(argv, *, capture_output, text, timeout, preexec_fn):
            runs.append({"argv": argv, "preexec_fn": preexec_fn})
            return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

        monkeypatch.setattr(_mod.subprocess, "run", _fake_run)
        result = topo.exec_in_ns("NS_FW", ["nft", "list", "ruleset"])
        assert len(runs) == 1
        assert runs[0]["argv"] == ["nft", "list", "ruleset"]
        assert result.returncode == 0
        assert result.stdout == "ok\n"

    def test_exec_in_ns_passes_timeout(self, topo, monkeypatch):
        captured: list[int] = []

        def _fake_run(argv, *, capture_output, text, timeout, preexec_fn):
            captured.append(timeout)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(_mod.subprocess, "run", _fake_run)
        topo.exec_in_ns("NS_FW", ["ping", "-c1", "10.0.0.1"], timeout=30)
        assert captured == [30]

    def test_exec_in_ns_uses_capture_output_true_by_default(self, topo, monkeypatch):
        captured: list[bool] = []

        def _fake_run(argv, *, capture_output, text, timeout, preexec_fn):
            captured.append(capture_output)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(_mod.subprocess, "run", _fake_run)
        topo.exec_in_ns("NS_FW", ["id"])
        assert captured == [True]
