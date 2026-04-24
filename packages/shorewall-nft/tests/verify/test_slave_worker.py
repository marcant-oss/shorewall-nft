"""Unit tests for shorewall_nft.verify.slave_worker.

All tests are pure-logic: no real subprocess spawns, no netns, no root.

Seams patched:
  - ``slave_worker._setns_net`` — avoids the setns() syscall and
    /run/netns filesystem dependency.
  - ``slave_worker._probe_tcp`` / ``_probe_udp`` / ``_probe_icmp`` — avoids
    real socket connections so individual probe verdicts are controllable.
  - ``multiprocessing.get_context`` — prevents real Process.fork() when
    testing ``spawn_worker``; replaced with a fake context that returns a
    mock Process and a real Pipe for the connection object.

The worker_main loop is exercised directly (no fork) by constructing a
real ``multiprocessing.Pipe`` pair and calling ``worker_main`` in a
thread with a mocked ``_setns_net``.
"""

from __future__ import annotations

import multiprocessing as mp
import threading
from unittest.mock import MagicMock, patch


from shorewall_nft.verify.slave_worker import (
    spawn_worker,
    worker_main,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_worker_in_thread(ns_name: str, conn, setns_side_effect=None):
    """Start worker_main in a daemon thread with _setns_net patched out.

    Returns the thread so the caller can join it.
    """
    def _target():
        with patch("shorewall_nft.verify.slave_worker._setns_net",
                   side_effect=setns_side_effect):
            worker_main(ns_name, conn)

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    return t


def _pipe():
    """Return (parent_conn, child_conn) using the default mp context."""
    ctx = mp.get_context("fork")
    return ctx.Pipe(duplex=True)


# ---------------------------------------------------------------------------
# Protocol: probe tuple serialisation round-trip
# ---------------------------------------------------------------------------

class TestProtocolRoundTrip:
    """Verify that probe/result tuples survive the Pipe intact."""

    def test_probe_tuple_round_trip(self):
        """A probe tuple written to one end is received unchanged on the other."""
        parent, child = _pipe()
        msg = ("probe", "tcp", "10.0.0.1", "10.0.0.2", 443, 4, 1.0)
        parent.send(msg)
        received = child.recv()
        parent.close()
        child.close()
        assert received == msg

    def test_ok_result_round_trip(self):
        """An ok result tuple written from child is received unchanged by parent."""
        parent, child = _pipe()
        result = ("ok", "ACCEPT", 42)
        child.send(result)
        received = parent.recv()
        parent.close()
        child.close()
        assert received == result

    def test_err_result_round_trip(self):
        """An err result tuple survives the pipe serialisation."""
        parent, child = _pipe()
        result = ("err", "ConnectionRefusedError('refused')", 7)
        child.send(result)
        received = parent.recv()
        parent.close()
        child.close()
        assert received == result

    def test_quit_tuple_round_trip(self):
        """The quit sentinel survives serialisation."""
        parent, child = _pipe()
        parent.send(("quit",))
        assert child.recv() == ("quit",)
        parent.close()
        child.close()


# ---------------------------------------------------------------------------
# worker_main — direct invocation via thread
# ---------------------------------------------------------------------------

class TestWorkerMain:
    """Exercise worker_main logic without forking a real process."""

    def _run(self, messages, probe_returns=None, setns_error=None):
        """
        Feed ``messages`` to worker_main via a pipe (thread-local), collect
        all replies until a final "ok"/"err" per probe, then return replies.

        ``probe_returns`` is a list of return values for the patched
        _probe_tcp/udp/icmp (applied in order via side_effect).
        ``setns_error`` if set is raised by the patched _setns_net.
        """
        parent, child = _pipe()
        for msg in messages:
            parent.send(msg)

        patches = {"shorewall_nft.verify.slave_worker._setns_net": MagicMock(side_effect=setns_error)}
        if probe_returns is not None:
            patches["shorewall_nft.verify.slave_worker._probe_tcp"] = MagicMock(
                side_effect=probe_returns
            )

        with patch.multiple("shorewall_nft.verify.slave_worker", **{
            k.split(".")[-1]: v for k, v in patches.items()
        }):
            t = _run_worker_in_thread("ns0", child, setns_side_effect=setns_error)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()
        return replies

    def test_quit_exits_cleanly(self):
        """Sending only quit causes worker to exit without replies."""
        replies = self._run([("quit",)])
        assert replies == []

    def test_single_tcp_probe_accept(self):
        """A single tcp probe returns ("ok", "ACCEPT", <ms>)."""
        parent, child = _pipe()
        parent.send(("probe", "tcp", "10.0.0.1", "10.0.0.2", 80, 4, 1.0))
        parent.send(("quit",))

        with patch("shorewall_nft.verify.slave_worker._setns_net"), \
             patch("shorewall_nft.verify.slave_worker._probe_tcp", return_value="ACCEPT"):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()

        assert len(replies) == 1
        status, verdict, ms = replies[0]
        assert status == "ok"
        assert verdict == "ACCEPT"
        assert ms >= 0

    def test_single_tcp_probe_drop(self):
        """A tcp probe that returns DROP is reported as ("ok", "DROP", …)."""
        parent, child = _pipe()
        parent.send(("probe", "tcp", "10.0.0.1", "10.0.0.2", 443, 4, 0.5))
        parent.send(("quit",))

        with patch("shorewall_nft.verify.slave_worker._setns_net"), \
             patch("shorewall_nft.verify.slave_worker._probe_tcp", return_value="DROP"):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()

        assert replies[0][1] == "DROP"

    def test_multiple_probes_all_returned(self):
        """Multiple sequential probes each produce exactly one reply."""
        parent, child = _pipe()
        probes = [
            ("probe", "tcp",  "10.0.0.1", "10.0.0.2", 80,   4, 1.0),
            ("probe", "udp",  "10.0.0.1", "10.0.0.2", 53,   4, 1.0),
            ("probe", "tcp",  "::1",      "::2",       443,  6, 1.0),
        ]
        for p in probes:
            parent.send(p)
        parent.send(("quit",))

        with patch("shorewall_nft.verify.slave_worker._setns_net"), \
             patch("shorewall_nft.verify.slave_worker._probe_tcp", return_value="ACCEPT"), \
             patch("shorewall_nft.verify.slave_worker._probe_udp", return_value="ACCEPT"):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()

        assert len(replies) == len(probes)
        assert all(r[0] == "ok" for r in replies)

    def test_setns_failure_sends_err_and_exits(self):
        """If setns raises, worker sends ("err", …) and exits."""
        parent, child = _pipe()
        # Don't send anything; the worker should fail on setns and exit.

        with patch("shorewall_nft.verify.slave_worker._setns_net",
                   side_effect=OSError("setns: no such file")):
            # Call worker_main directly in this thread (safe because _setns_net is patched)
            t = threading.Thread(target=worker_main, args=("nonexistent", child), daemon=True)
            t.start()
            t.join(timeout=3)

        assert parent.poll(timeout=1)
        reply = parent.recv()
        parent.close()
        child.close()

        assert reply[0] == "err"
        assert "setns" in reply[1]

    def test_unknown_command_returns_err(self):
        """An unknown command produces an err reply and the loop continues."""
        parent, child = _pipe()
        parent.send(("bogus_cmd", "arg1"))
        parent.send(("quit",))

        with patch("shorewall_nft.verify.slave_worker._setns_net"):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()

        assert len(replies) == 1
        assert replies[0][0] == "err"
        assert "bogus_cmd" in replies[0][1]

    def test_unknown_proto_returns_skip(self):
        """An unknown protocol field produces verdict 'SKIP'."""
        parent, child = _pipe()
        parent.send(("probe", "gre", "10.0.0.1", "10.0.0.2", 0, 4, 1.0))
        parent.send(("quit",))

        with patch("shorewall_nft.verify.slave_worker._setns_net"):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()

        assert len(replies) == 1
        assert replies[0] == ("ok", "SKIP", replies[0][2])

    def test_probe_exception_propagates_as_err(self):
        """If a probe function raises, the worker sends ("err", …) and continues."""
        parent, child = _pipe()
        parent.send(("probe", "tcp", "10.0.0.1", "10.0.0.2", 80, 4, 1.0))
        parent.send(("quit",))

        with patch("shorewall_nft.verify.slave_worker._setns_net"), \
             patch("shorewall_nft.verify.slave_worker._probe_tcp",
                   side_effect=RuntimeError("socket exploded")):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()

        assert len(replies) == 1
        assert replies[0][0] == "err"
        assert "socket exploded" in replies[0][1]

    def test_elapsed_ms_field_is_non_negative(self):
        """The elapsed_ms field in the response must be >= 0."""
        parent, child = _pipe()
        parent.send(("probe", "udp", "10.0.0.1", "10.0.0.2", 53, 4, 0.5))
        parent.send(("quit",))

        with patch("shorewall_nft.verify.slave_worker._setns_net"), \
             patch("shorewall_nft.verify.slave_worker._probe_udp", return_value="DROP"):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        replies = []
        while parent.poll():
            replies.append(parent.recv())
        parent.close()
        child.close()

        assert replies[0][2] >= 0

    def test_eof_on_pipe_exits_gracefully(self):
        """If the parent closes the connection, worker_main exits without error."""
        parent, child = _pipe()
        parent.close()  # EOF to the worker

        with patch("shorewall_nft.verify.slave_worker._setns_net"):
            t = _run_worker_in_thread("ns0", child)
            t.join(timeout=3)

        # Thread must have exited; nothing to assert about pipe output
        assert not t.is_alive()
        child.close()


# ---------------------------------------------------------------------------
# spawn_worker — parent-side API
# ---------------------------------------------------------------------------

class TestSpawnWorker:
    """Verify spawn_worker returns the right types without forking a real process."""

    def test_returns_process_and_connection(self):
        """spawn_worker must return (Process, Connection) with the expected types."""
        fake_proc = MagicMock(spec=mp.Process)
        fake_proc.start = MagicMock()

        fake_ctx = MagicMock()
        # Use a real Pipe so the Connection type is genuine
        real_ctx = mp.get_context("fork")
        p_conn, c_conn = real_ctx.Pipe(duplex=True)
        fake_ctx.Pipe.return_value = (p_conn, c_conn)
        fake_ctx.Process.return_value = fake_proc

        with patch("shorewall_nft.verify.slave_worker.mp.get_context", return_value=fake_ctx):
            proc, conn = spawn_worker("test-ns")

        assert proc is fake_proc
        fake_proc.start.assert_called_once()
        # Connection must be the parent-side end (child end is closed)
        p_conn.close()

    def test_child_conn_closed_after_spawn(self):
        """spawn_worker must close the child-side connection to avoid descriptor leak."""
        fake_proc = MagicMock(spec=mp.Process)
        fake_proc.start = MagicMock()

        real_ctx = mp.get_context("fork")
        p_conn, c_conn = real_ctx.Pipe(duplex=True)
        c_conn_mock = MagicMock(wraps=c_conn)

        fake_ctx = MagicMock()
        fake_ctx.Pipe.return_value = (p_conn, c_conn_mock)
        fake_ctx.Process.return_value = fake_proc

        with patch("shorewall_nft.verify.slave_worker.mp.get_context", return_value=fake_ctx):
            spawn_worker("test-ns2")

        c_conn_mock.close.assert_called_once()
        p_conn.close()

    def test_worker_named_after_ns(self):
        """The Process name must contain the namespace name."""
        fake_proc = MagicMock(spec=mp.Process)
        fake_proc.start = MagicMock()

        real_ctx = mp.get_context("fork")
        p_conn, c_conn = real_ctx.Pipe(duplex=True)

        fake_ctx = MagicMock()
        fake_ctx.Pipe.return_value = (p_conn, c_conn)
        fake_ctx.Process.return_value = fake_proc

        with patch("shorewall_nft.verify.slave_worker.mp.get_context", return_value=fake_ctx):
            spawn_worker("myzone")

        call_kwargs = fake_ctx.Process.call_args
        name_arg = call_kwargs.kwargs.get("name") or call_kwargs[1].get("name", "")
        assert "myzone" in name_arg
        p_conn.close()
