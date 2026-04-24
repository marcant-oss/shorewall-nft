"""Shared helpers for the shorewall-nft CLI subgroups.

Symbols here are consumed by multiple files under ``shorewall_nft.runtime.cli``
(apply, config, generate, debug, plugin command modules) and by external
callers (a few tests import helpers from ``shorewall_nft.runtime.cli``
directly). Everything in this module is re-exported from
``shorewall_nft.runtime.cli.__init__`` so import paths stay stable.

Groups of helpers:
- Config resolution: directory precedence + ``config_options`` decorator
- Progress reporting: ``_Step`` / ``_Progress`` for the ``start`` lifecycle
- Compile pipeline: ``_compile`` / ``_compile_from_cli`` / overlay loading
- Shorewalld notification: socket protocol + result classification
- Seed helpers: DNS/DNSR registry extraction + shorewalld seed request
- Misc: ``_load_static_nft``, ``_load_sets``
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

import click

# ──────────────────────────────────────────────────────────────────────
# Config directory resolution
# ──────────────────────────────────────────────────────────────────────

# Default config directory — same as Shorewall
DEFAULT_CONFIG_DIR = Path("/etc/shorewall")
MERGED_CONFIG_DIR = Path("/etc/shorewall46")


def _extract_table(ruleset_text: str, family: str, name: str) -> str | None:
    """Extract a single `table FAMILY NAME { ... }` block from
    `nft list ruleset` output.

    Returns a standalone nft script that contains just that table
    (with a leading `delete table` for atomic replacement), or None
    if the table is not present. Used by `shorewall-nft debug` to
    restore the original shorewall table without touching unrelated
    tables loaded by other services.
    """
    lines = ruleset_text.splitlines()
    start = -1
    depth = 0
    end = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start < 0:
            if stripped.startswith(f"table {family} {name}"):
                start = i
                depth = 1 if "{" in stripped else 0
                continue
        else:
            depth += line.count("{")
            depth -= line.count("}")
            if depth == 0:
                end = i
                break
    if start < 0 or end < 0:
        return None
    body = "\n".join(lines[start:end + 1])
    return (
        f"table {family} {name}\n"
        f"delete table {family} {name}\n"
        f"{body}\n"
    )


def _get_config_dir(directory: Path | None) -> Path:
    """Resolve config directory with shorewall-next precedence rules.

    Resolution order:
      1. Explicit `directory` argument (CLI --config-dir or positional) wins.
      2. If /etc/shorewall46 exists (produced by merge-config), it is used as
         the authoritative dual-stack source. /etc/shorewall and /etc/shorewall6
         are ignored.
      3. Fall back to /etc/shorewall (legacy mode, auto-merges with shorewall6
         if present).
    """
    if directory is not None:
        return directory
    if MERGED_CONFIG_DIR.is_dir():
        return MERGED_CONFIG_DIR
    return DEFAULT_CONFIG_DIR


def _derive_v4_sibling(v6_dir: Path) -> Path | None:
    """Given a v6 directory (e.g. /etc/shorewall6), return the v4 sibling
    (e.g. /etc/shorewall) if it exists, else None."""
    name = v6_dir.name
    if name.endswith("6"):
        candidate = v6_dir.parent / name[:-1]
        if candidate.is_dir():
            return candidate
    return None


def _resolve_config_paths(
    positional: Path | None,
    config_dir: Path | None,
    config_dir_v4: Path | None,
    config_dir_v6: Path | None,
    no_auto_v4: bool,
    no_auto_v6: bool,
) -> tuple[Path, Path | None, bool]:
    """Resolve CLI config options into (primary, secondary, skip_sibling).

    primary: the Path passed as first arg to load_config
    secondary: optional config_dir_v6 kwarg for load_config (explicit v6 dir)
    skip_sibling: if True, disable parser's v6 sibling auto-detection

    Modes supported:
      --config-dir /srv/merged
            → merged mode, single dir, no sibling merge
      --config-dir-v4 /srv/v4 --config-dir-v6 /srv/v6
            → explicit dual mode
      --config-dir-v4 /srv/v4
            → v4 + auto-detected v6 sibling (legacy behavior)
      --config-dir-v4 /srv/v4 --no-auto-v6
            → v4-only, no sibling merge
      --config-dir-v6 /srv/v6
            → v6 + auto-detected v4 sibling (symmetric)
      --config-dir-v6 /srv/v6 --no-auto-v4
            → v6-only
      positional /srv/foo
            → equivalent to --config-dir-v4 /srv/foo (or --config-dir if
              the name ends in "46" — auto-detect via load_config)
      (no args)
            → /etc/shorewall46 if present, else /etc/shorewall + sibling
    """
    # Conflict checks
    if config_dir is not None and (config_dir_v4 is not None
                                   or config_dir_v6 is not None):
        raise click.UsageError(
            "--config-dir is mutually exclusive with "
            "--config-dir-v4/--config-dir-v6")
    if positional is not None and (config_dir is not None
                                   or config_dir_v4 is not None
                                   or config_dir_v6 is not None):
        raise click.UsageError(
            "Positional directory cannot be combined with --config-dir, "
            "--config-dir-v4 or --config-dir-v6")

    # 1. Explicit merged dir
    if config_dir is not None:
        return config_dir, None, True

    # 2. Explicit v4 + v6 (fully specified dual mode)
    if config_dir_v4 is not None and config_dir_v6 is not None:
        return config_dir_v4, config_dir_v6, True

    # 3. v4 only (with optional no-auto-v6)
    if config_dir_v4 is not None:
        return config_dir_v4, None, bool(no_auto_v6)

    # 4. v6 only / v6 + auto v4 sibling
    if config_dir_v6 is not None:
        if no_auto_v4:
            return config_dir_v6, None, True
        v4_sibling = _derive_v4_sibling(config_dir_v6)
        if v4_sibling is not None:
            return v4_sibling, config_dir_v6, True
        return config_dir_v6, None, True

    # 5. Positional arg (legacy behavior — parser auto-detects sibling)
    if positional is not None:
        return positional, None, bool(no_auto_v6)

    # 6. Defaults: prefer /etc/shorewall46, fall back to /etc/shorewall
    default = _get_config_dir(None)
    # If default is the merged dir, it implicitly has no sibling.
    # If it's the legacy /etc/shorewall, let parser auto-detect sibling
    # unless the user explicitly said --no-auto-v6.
    return default, None, bool(no_auto_v6) or default.name.endswith("46")


def config_options(f):
    """Click decorator: add config directory override options to a command.

    Adds:
      -c, --config-dir    explicit merged config directory
      --config-dir-v4     explicit IPv4 config directory
      --config-dir-v6     explicit IPv6 config directory
      --no-auto-v4        disable auto-detection of a v4 sibling
      --no-auto-v6        disable auto-detection of a v6 sibling
    """
    f = click.option("--no-auto-v6", is_flag=True, default=False,
                     help="Disable auto-detection of a v6 sibling "
                          "directory.")(f)
    f = click.option("--no-auto-v4", is_flag=True, default=False,
                     help="Disable auto-detection of a v4 sibling "
                          "directory.")(f)
    f = click.option("--config-dir-v6", "config_dir_v6",
                     type=click.Path(exists=True, file_okay=False,
                                     path_type=Path),
                     default=None,
                     help="Explicit IPv6 config directory "
                          "(use with --config-dir-v4 for dual mode).")(f)
    f = click.option("--config-dir-v4", "config_dir_v4",
                     type=click.Path(exists=True, file_okay=False,
                                     path_type=Path),
                     default=None,
                     help="Explicit IPv4 config directory.")(f)
    f = click.option("-c", "--config-dir", "config_dir",
                     type=click.Path(exists=True, file_okay=False,
                                     path_type=Path),
                     default=None,
                     help="Explicit merged config directory "
                          "(overrides /etc/shorewall46 default).")(f)
    return f


# ──────────────────────────────────────────────────────────────────────
# Start-command progress reporter
# ──────────────────────────────────────────────────────────────────────


class _Step:
    """Detail / warning collector yielded inside a :class:`_Progress` step."""

    def __init__(self) -> None:
        self._detail: list[str] = []
        self._warnings: list[str] = []
        self._notes: list[str] = []

    def info(self, msg: str) -> None:
        self._detail.append(msg)

    def warn(self, msg: str) -> None:
        self._warnings.append(msg)

    def note(self, msg: str) -> None:
        """Plain indented sub-line, not prefixed with 'warn:'."""
        self._notes.append(msg)

    @property
    def has_warnings(self) -> bool:
        return bool(self._warnings)

    def _detail_str(self) -> str:
        return ", ".join(self._detail)


class _Progress:
    """Step-by-step progress for interactive terminals and journal output.

    TTY: inline overwrite  ``  … label`` → ``  ✓ label  (detail)``
    with ANSI colour via :func:`click.style`.

    Non-TTY (journal, pipe): one plain text line per step, no \\\\r, no
    ANSI — clean for ``journalctl`` and log files.
    """

    def __init__(self) -> None:
        self._tty = sys.stdout.isatty()

    def header(self, msg: str) -> None:
        if self._tty:
            click.secho(msg, bold=True)
        else:
            click.echo(msg)

    @contextlib.contextmanager
    def step(self, label: str):
        s = _Step()
        if self._tty:
            sys.stdout.write(f"  \033[2m…\033[0m {label}")
            sys.stdout.flush()
        try:
            yield s
        except Exception as exc:
            detail = s._detail_str()
            suffix = f"  ({detail})" if detail else ""
            err_msg = str(exc)
            if self._tty:
                marker = click.style("✗", fg="red", bold=True)
                sys.stdout.write(
                    f"\r  {marker} {label}{suffix}"
                    + (f"\n    {err_msg}" if err_msg else "") + "\n")
                sys.stdout.flush()
            else:
                click.echo(f"  ✗ {label}{suffix}"
                           + (f": {err_msg}" if err_msg else ""))
            raise
        else:
            detail = s._detail_str()
            suffix = f"  ({detail})" if detail else ""
            if s.has_warnings:
                if self._tty:
                    marker = click.style("⚠", fg="yellow", bold=True)
                    sys.stdout.write(f"\r  {marker} {label}{suffix}\n")
                    sys.stdout.flush()
                    for w in s._warnings:
                        click.secho(f"    ⚠  {w}", fg="yellow")
                    for n in s._notes:
                        click.secho(f"      {n}", dim=True)
                else:
                    click.echo(f"  ⚠ {label}{suffix}")
                    for w in s._warnings:
                        click.echo(f"    warn: {w}")
                    for n in s._notes:
                        click.echo(f"      {n}")
            else:
                if self._tty:
                    marker = click.style("✓", fg="green", bold=True)
                    sys.stdout.write(f"\r  {marker} {label}{suffix}\n")
                    sys.stdout.flush()
                    for n in s._notes:
                        click.secho(f"      {n}", dim=True)
                else:
                    click.echo(f"  ✓ {label}{suffix}")
                    for n in s._notes:
                        click.echo(f"      {n}")

    def done(self, msg: str) -> None:
        if self._tty:
            click.secho(msg, fg="green", bold=True)
        else:
            click.echo(msg)


# ──────────────────────────────────────────────────────────────────────
# Compile pipeline + overlay loading
# ──────────────────────────────────────────────────────────────────────


def _check_loaded_hash(config_dir: Path, netns: str | None) -> tuple[str, str | None]:
    """Compare the hash of the on-disk config vs the loaded ruleset.

    Returns (source_hash, loaded_hash_or_None). ``loaded_hash_or_None``
    is None when no ruleset is loaded or no hash marker is found.
    Uses :meth:`NftInterface.run_in_netns` — enters the namespace via
    in-process ``setns()`` on root, falls back to ``ip netns exec`` otherwise.
    """
    from shorewall_nft.config.hash import compute_config_hash, extract_hash_from_ruleset
    from shorewall_nft.nft.netlink import NftInterface

    source_hash = compute_config_hash(config_dir)
    nft = NftInterface()
    try:
        r = nft.run_in_netns(
            [nft._nft_bin, "list", "table", "inet", "shorewall"],
            netns=netns, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return source_hash, None
        loaded_hash = extract_hash_from_ruleset(r.stdout)
        return source_hash, loaded_hash
    except (OSError, ValueError, TimeoutError):
        # nft binary missing, netns inaccessible, or query timed out —
        # caller treats None as "loaded hash unknown".
        return source_hash, None
    except Exception:  # noqa: BLE001 — probe; any failure means unknown hash
        return source_hash, None


def _compile(config_dir: Path, config6_dir: Path | None = None,
             debug: bool = False,
             skip_sibling_merge: bool = False,
             override: dict | None = None):
    """Compile helper — returns (ir, script, sets).

    ``override`` is a structured JSON blob (see
    ``docs/cli/override-json.md``) applied on top of the parsed
    config via :func:`shorewall_nft.config.importer.apply_overlay`.
    Load order is *defaults → on-disk → override*, so the overlay
    always wins on collisions.
    """
    from shorewall_nft.compiler.ir import build_ir
    from shorewall_nft.config.hash import compute_config_hash
    from shorewall_nft.config.parser import load_config
    from shorewall_nft.nft.emitter import emit_nft

    config = load_config(config_dir, config6_dir=config6_dir,
                         skip_sibling_merge=skip_sibling_merge)
    if override:
        from shorewall_nft.config.importer import apply_overlay
        apply_overlay(config, override)
    ir = build_ir(config)
    static_nft = _load_static_nft(config_dir)
    nft_sets = _load_sets(config_dir)
    config_hash = compute_config_hash(config_dir)
    script = emit_nft(ir, static_nft=static_nft, nft_sets=nft_sets,
                      debug=debug, config_hash=config_hash)
    return ir, script, nft_sets


def _compile_from_cli(directory, config_dir, config_dir_v4, config_dir_v6,
                      no_auto_v4, no_auto_v6, debug=False,
                      override=None):
    """Helper for commands using @config_options + positional directory.

    Resolves the CLI flags to (primary, secondary, skip) and calls _compile.
    """
    primary, secondary, skip = _resolve_config_paths(
        directory, config_dir, config_dir_v4, config_dir_v6,
        no_auto_v4, no_auto_v6)
    if override is None:
        # Pick up the ctx-stashed overlay if a subcommand caller
        # didn't explicitly pass one.
        try:
            override = click.get_current_context().obj.get(
                "override_json")
        except (AttributeError, TypeError, RuntimeError):
            # ctx.obj may be None or not a dict when called outside a
            # full CLI invocation (e.g. tests calling helpers directly).
            override = None
    return _compile(primary, config6_dir=secondary,
                    skip_sibling_merge=skip, debug=debug,
                    override=override), (primary, secondary, skip)


def _load_override_arg(arg: str) -> dict:
    """Read a --override-json argument.

    Accepts a literal JSON string, ``@path`` (reads from file), or
    ``-`` (reads from stdin). File extension may be ``.yaml`` for
    YAML, default is JSON.
    """
    import json as _json
    if arg == "-":
        text = sys.stdin.read()
        suffix = ""
    elif arg.startswith("@"):
        p = Path(arg[1:])
        text = p.read_text()
        suffix = p.suffix
    else:
        text = arg
        suffix = ""
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            raise click.ClickException(
                "--override-json YAML requested but PyYAML not installed")
        return yaml.safe_load(text)
    return _json.loads(text)


# ──────────────────────────────────────────────────────────────────────
# shorewalld control-socket notification
# ──────────────────────────────────────────────────────────────────────

DEFAULT_SHOREWALLD_SOCKET = "/run/shorewalld/control.sock"


def _detect_current_netns() -> str | None:
    """Return the named netns the process is running in, or None for root ns.

    Compares /proc/self/ns/net inode against /run/netns/ entries.  Used when
    shorewall-nft runs inside a netns via JoinsNamespaceOf (no --netns flag)
    so the shorewalld registration carries the correct netns name.
    """
    import os as _os
    try:
        self_ino = _os.stat("/proc/self/ns/net").st_ino
        for entry in _os.scandir("/run/netns"):
            try:
                if _os.stat(entry.path).st_ino == self_ino:
                    return entry.name
            except OSError:
                pass
    except OSError:
        pass
    return None


def _resolve_instance_name(
    cli_name: str | None,
    settings: dict | None,
    netns: str | None,
    config_dir: Path,
) -> str:
    """Resolve the instance name for the shorewalld control socket.

    Precedence:
      1. Explicit CLI flag (``--instance-name``).
      2. ``INSTANCE_NAME`` from ``shorewall.conf``.
      3. The netns name (if set).
      4. The ``config_dir`` basename.

    The last two are deterministic: running ``shorewall-nft start`` twice
    on the same config yields the same name, which is what shorewalld
    needs for idempotent register/deregister.
    """
    if cli_name:
        return cli_name.strip()
    if settings:
        from_conf = str(settings.get("INSTANCE_NAME", "")).strip()
        if from_conf:
            return from_conf
    if netns:
        return netns
    return config_dir.name


def _notify_shorewalld(
    action: str,
    instance_name: str,
    config_dir: Path,
    netns: str | None,
    socket_path: str,
    dns_reg=None,
    dnsr_reg=None,
    nfset_reg=None,
) -> dict:
    """Send register-instance or deregister-instance to shorewalld.

    The *register* payload carries the full :class:`InstanceConfig`
    equivalent (name, netns, config_dir) plus the DNS/DNSR registries
    serialised inline — no on-disk allowlist file is written or read.

    Returns the response dict. Raises OSError subtypes on transport
    failure (FileNotFoundError, PermissionError, ConnectionRefusedError,
    socket.timeout); callers classify severity via
    :func:`_report_shorewalld_result`.
    """
    import json as _json
    import socket as _sock

    if action == "register":
        req: dict = {
            "cmd": "register-instance",
            "name": instance_name,
            "netns": netns or "",
            "config_dir": str(config_dir),
        }
        if dns_reg is not None or dnsr_reg is not None:
            from shorewall_nft.nft.dns_sets import registry_to_payload
            req.update(registry_to_payload(dns_reg, dnsr_reg))
        # Always include nfsets key so shorewalld can distinguish "empty
        # registry" from "no nfsets support in this compiler version".
        from shorewall_nft.nft.nfsets import nfset_registry_to_payload
        _nfsets_payload: dict = {}
        if nfset_reg is not None and nfset_reg.entries:
            _nfsets_payload = nfset_registry_to_payload(nfset_reg)
        req["nfsets"] = _nfsets_payload
    elif action == "deregister":
        req = {"cmd": "deregister-instance", "name": instance_name}
    else:
        raise ValueError(f"unknown action {action!r}")

    payload = _json.dumps(req, separators=(",", ":")).encode() + b"\n"
    s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    s.settimeout(10.0)
    try:
        s.connect(socket_path)
        s.sendall(payload)
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    if not buf:
        raise OSError("shorewalld closed the connection without a response")
    return _json.loads(buf.split(b"\n", 1)[0])


def _report_shorewalld_result(
    step,
    action: str,
    has_dns_sets: bool,
    exc: Exception | None,
    resp: dict | None,
    socket_path: str,
) -> None:
    """Emit a user-visible message about the shorewalld contact result.

    *step* is a ``_Step`` from ``_Progress.step()`` — if ``None``, falls
    back to :func:`click.echo`.

    Severity rules:

    * ``FileNotFoundError`` → INFO (no DNS sets) or WARN (with DNS sets);
      never fatal — shorewalld not running is a common operator state.
    * ``PermissionError`` → WARN; continue.
    * Any other failure on ``register`` with DNS/DNSR sets present →
      raises :class:`click.ClickException` (sets will not be populated).
    * ``deregister`` failures are always non-fatal — the daemon will
      age entries out via their per-element TTL.
    """
    def _emit(level: str, msg: str) -> None:
        if step is not None:
            getattr(step, "warn" if level != "info" else "info")(msg)
        else:
            click.echo(
                f"shorewalld: {msg}",
                err=(level in ("warn", "error")),
            )

    if exc is None:
        n = (resp or {}).get("qnames")
        suffix = f" ({n} name(s))" if n is not None else ""
        _emit("info", f"{action}ed{suffix}")
        return

    if isinstance(exc, FileNotFoundError):
        msg = f"socket not found ({socket_path}) — skipped"
        _emit("warn" if has_dns_sets else "info", msg)
        return

    if isinstance(exc, PermissionError):
        _emit("warn", f"permission denied on {socket_path}")
        return

    # Any other error (connection refused, timeout, JSON decode,
    # ok=false response …)
    _emit("warn", f"{action} failed: {exc}")
    if has_dns_sets and action == "register":
        raise click.ClickException(
            "DNS/DNSR sets present but shorewalld registration failed — "
            "sets will not be populated. Check shorewalld status or set "
            "--shorewalld-socket / SHOREWALLD_SOCKET."
        )


def _try_notify_shorewalld(
    step,
    action: str,
    instance_name: str,
    config_dir: Path,
    netns: str | None,
    socket_path: str,
    has_dns_sets: bool,
    dns_reg=None,
    dnsr_reg=None,
    nfset_reg=None,
) -> None:
    """Send notify + classify the outcome in one call."""
    try:
        resp = _notify_shorewalld(
            action, instance_name, config_dir, netns, socket_path,
            dns_reg=dns_reg, dnsr_reg=dnsr_reg, nfset_reg=nfset_reg)
        if not resp.get("ok", False):
            raise RuntimeError(resp.get("error", "unknown daemon error"))
        _report_shorewalld_result(
            step, action, has_dns_sets, None, resp, socket_path)
    except click.ClickException:
        raise
    except Exception as exc:  # noqa: BLE001 — we classify by type
        _report_shorewalld_result(
            step, action, has_dns_sets, exc, None, socket_path)


# ──────────────────────────────────────────────────────────────────────
# Seed-handshake helpers
# ──────────────────────────────────────────────────────────────────────


def _parse_seed_duration_ms(s: str) -> int:
    """Parse a duration string (``10s``, ``5000``) to milliseconds."""
    s = s.strip()
    if s.endswith("s"):
        try:
            return max(1, int(float(s[:-1]) * 1000))
        except ValueError:
            return 10_000
    try:
        return max(1, int(s))
    except ValueError:
        return 10_000


def _resolve_seed_config(
    cli_enabled: bool | None,
    cli_timeout: str | None,
    cli_wait_passive: bool | None,
    settings: dict | None,
) -> tuple[bool, int, bool]:
    """Resolve seed config to ``(enabled, timeout_ms, wait_passive)``.

    Precedence: CLI flag → environment variable → shorewall.conf → default.
    """
    # enabled
    if cli_enabled is not None:
        enabled = cli_enabled
    else:
        env = os.environ.get("SHOREWALLD_SEED_ENABLED", "").strip().lower()
        if env in ("yes", "1", "true", "no", "0", "false"):
            enabled = env in ("yes", "1", "true")
        elif settings:
            cv = str(settings.get("SHOREWALLD_SEED_ENABLED", "")).strip().lower()
            enabled = cv not in ("no", "0", "false")
        else:
            enabled = True

    # timeout_ms
    if cli_timeout:
        timeout_ms = _parse_seed_duration_ms(cli_timeout)
    else:
        env = os.environ.get("SHOREWALLD_SEED_TIMEOUT", "").strip()
        if env:
            timeout_ms = _parse_seed_duration_ms(env)
        elif settings:
            cv = str(settings.get("SHOREWALLD_SEED_TIMEOUT", "")).strip()
            timeout_ms = _parse_seed_duration_ms(cv) if cv else 10_000
        else:
            timeout_ms = 10_000

    # wait_passive
    if cli_wait_passive is not None:
        wait_passive = cli_wait_passive
    else:
        env = os.environ.get("SHOREWALLD_SEED_WAIT_PASSIVE", "").strip().lower()
        if env in ("yes", "1", "true", "no", "0", "false"):
            wait_passive = env in ("yes", "1", "true")
        elif settings:
            cv = str(settings.get("SHOREWALLD_SEED_WAIT_PASSIVE", "")).strip().lower()
            wait_passive = cv not in ("no", "0", "false")
        else:
            wait_passive = True

    return enabled, timeout_ms, wait_passive


def _extract_seed_qnames(dns_reg: object | None, dnsr_reg: object | None) -> list[str]:
    """Collect primary qnames from DNS and DNSR registries for a seed request."""
    seen: set[str] = set()
    result: list[str] = []
    if dns_reg is not None:
        for spec in dns_reg.iter_sorted():  # type: ignore[union-attr]
            if getattr(spec, "declare_set", True) and spec.qname not in seen:
                seen.add(spec.qname)
                result.append(spec.qname)
    if dnsr_reg is not None:
        for group in dnsr_reg.iter_sorted():  # type: ignore[union-attr]
            if group.primary_qname not in seen:
                seen.add(group.primary_qname)
                result.append(group.primary_qname)
    return result


def _do_seed_request(
    prog: "_Progress | None",
    script: str,
    ir: object,
    netns: str | None,
    instance_name: str | None,
    cfg_primary: Path,
    shorewalld_socket: str,
    seed_enabled: bool,
    seed_timeout: str | None,
    seed_wait_passive: bool | None,
) -> str:
    """Request a seed from shorewalld and inject elements into *script*.

    Returns the (possibly modified) script.  On any failure the original
    script is returned unchanged and a warning is emitted.
    """
    if not seed_enabled:
        return script

    _dns_reg = getattr(ir, "dns_registry", None)
    _dnsr_reg = getattr(ir, "dnsr_registry", None)
    _settings = getattr(ir, "settings", None)

    _enabled, _timeout_ms, _wait_passive = _resolve_seed_config(
        None, seed_timeout, seed_wait_passive, _settings)
    if not _enabled:
        return script

    _qnames = _extract_seed_qnames(_dns_reg, _dnsr_reg)
    if not _qnames:
        return script

    _reg_netns = netns or _detect_current_netns()
    _instance = _resolve_instance_name(
        instance_name, _settings, _reg_netns, cfg_primary)

    try:
        from shorewall_nft.nft.dns_sets import inject_seed_elements
        from shorewall_nft.runtime.seed import request_seeds_from_shorewalld
        seed_result = request_seeds_from_shorewalld(
            socket_path=shorewalld_socket,
            netns=_reg_netns or "",
            name=_instance,
            qnames=_qnames,
            iplist_sets=[],
            timeout_ms=_timeout_ms,
            wait_for_passive=_wait_passive,
        )
        if seed_result is not None and seed_result.dns:
            script, n = inject_seed_elements(script, seed_result.dns)
            srcs = ",".join(seed_result.sources_contributed) or "-"
            n_iplist = sum(len(v) for v in seed_result.iplist.values())
            parts = [f"{n} DNS"]
            if n_iplist:
                parts.append(f"{n_iplist} iplist")
            summary = " + ".join(parts)
            flag = " (partial)" if seed_result.timeout_hit else ""
            prefix = "  " if prog is not None else ""
            click.echo(f"{prefix}Seed: {summary} in {seed_result.elapsed_ms}ms [{srcs}]{flag}")
            # per-qname detail
            for qname, fams in sorted(seed_result.dns.items()):
                n4 = len(fams.get("v4") or [])
                n6 = len(fams.get("v6") or [])
                ttls = [e["ttl"] for f in fams.values() for e in f if e.get("ttl")]
                ttl_info = f"  ttl {min(ttls)}–{max(ttls)}s" if ttls else ""
                click.echo(f"{prefix}  {qname}: {n4}×v4  {n6}×v6{ttl_info}")
            # per-iplist-set detail
            for sname, prefixes in sorted(seed_result.iplist.items()):
                click.echo(f"{prefix}  {sname}: {len(prefixes)} prefixes")
        elif seed_result is None:
            _w = "seed request failed — sets will start empty"
            if prog is not None:
                click.echo(f"  warn: {_w}", err=True)
            else:
                click.echo(f"warn: {_w}", err=True)
    except Exception as exc:  # noqa: BLE001 — seed is best-effort; any error just warns
        _w = f"seed error: {exc}"
        if prog is not None:
            click.echo(f"  warn: {_w}", err=True)
        else:
            click.echo(f"warn: {_w}", err=True)

    return script


# ──────────────────────────────────────────────────────────────────────
# Misc helpers
# ──────────────────────────────────────────────────────────────────────


def _load_static_nft(config_dir: Path) -> str | None:
    static_path = config_dir / "static.nft"
    if static_path.exists():
        return static_path.read_text()
    return None


def _load_sets(config_dir: Path) -> list | None:
    from shorewall_nft.nft.sets import parse_init_for_sets
    init_path = config_dir / "init"
    sets = parse_init_for_sets(init_path, config_dir)
    return sets if sets else None
