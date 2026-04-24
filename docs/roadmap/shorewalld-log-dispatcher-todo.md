# TODO — shorewalld as log dispatcher (WP-E1 extension "C")

**Status**: pending design + investigation
**Owner**: unassigned
**Priority**: medium — operator quality-of-life for per-netns deployments
**Depends on**: WP-E1 Option B landed (LOG_BACKEND={LOG, netlink/NFLOG} switching).

## Context

WP-E1 was implemented as Option B (see commit message): `LOG_BACKEND` is honoured and `nft log group <N>` is emitted when `LOG_BACKEND=netlink` is set. But **what listens on that netlink group** is left to the operator (typically `ulogd2`).

For the per-netns deployment scenario (shorewalld already runs in fork-and-setns mode, one instance per firewall netns), `ulogd2` per netns means:

- One `ulogd2.conf` per netns
- One systemd unit per netns with `NetworkNamespacePath=...`
- Operator-managed group-number allocation
- Separate log file output per netns

That's a lot of moving parts. Since shorewalld is already the
per-netns daemon for stats/conntrack/dynamic-set work, it could
**also** absorb log-dispatch duty:

- shorewalld opens `nfnetlink_log` group `LOG_GROUP` inside its netns.
- Log entries are demultiplexed into structured records.
- Records are exported via:
  - **Prometheus counters** (per chain, per disposition) — fits the
    existing exporter surface.
  - Optional **structured event stream** (JSON over Unix socket, or
    push to a log endpoint) for downstream log aggregators.
  - Optional **on-disk log file** for `shorewall-nft show log`.

This eliminates the per-netns ulogd2 plumbing entirely.

## Scope (proposed)

### LOGFORMAT + LOGRULENUMBERS support (the "Option C" pure-compiler piece)

Independent of the shorewalld dispatcher work — just a printf-style
template parser and emitter:

- `LOGFORMAT` setting (default `Shorewall:%s:%s:`) — `%s` slots for
  chain name and disposition. Substitute at compile time per rule.
- `LOGRULENUMBERS=Yes` — append rule sequence number to the prefix.
- `MAXZONENAMELENGTH` — truncate zone names in the prefix per the
  setting.

Files: `shorewall_nft/nft/emitter.py` log fragment builder.

### shorewalld log-dispatcher (the per-netns runtime piece)

New shorewalld component `shorewalld/log_dispatcher.py`:

- Opens `pyroute2.NFLOGSocket` (or equivalent — verify pyroute2 has
  this; the netlink subsystem is `NFNL_SUBSYS_ULOG`) inside the
  per-netns worker.
- Subscribes to group `LOG_GROUP` (read from shorewalld config or
  shorewall.conf).
- Decodes each log entry: prefix, payload header, packet metadata.
- Parses the prefix per `LOGFORMAT` to extract chain + disposition +
  optional rule number.
- Emits Prometheus counter increments:
  ```
  shorewall_log_total{chain="net2fw",disposition="DROP",netns="fw1"}
  ```
- Optional: writes a structured JSON line to `LOG_DISPATCH_SOCKET`
  (configurable Unix socket path) for log aggregators to subscribe to.
- Optional: writes plain-text to `LOG_DISPATCH_FILE` so `show log`
  works.

### Wiring

- `shorewall.conf`: new settings `LOG_DISPATCH=shorewalld|ulogd2|none`
  (default `none` to preserve current behaviour),
  `LOG_DISPATCH_SOCKET`, `LOG_DISPATCH_FILE`.
- `shorewall-nft generate-systemd --netns ...`: when
  `LOG_DISPATCH=shorewalld`, the generated unit ensures shorewalld
  is configured to dispatch (no separate ulogd2 unit needed).
- `shorewalld` exporter: new collector `LogCollector` that surfaces
  the per-chain/per-disposition counter in `/metrics`.

## Open questions

1. **pyroute2 NFLOGSocket** — does pyroute2 have a stable API for
   `nfnetlink_log` consumption? The audit doc notes `NFCTSocket` as
   used in shorewalld; need to verify the log equivalent exists.
   If not, fall back to `socket.AF_NETLINK` raw + `struct` decoding,
   or shell out to a one-shot helper (less ideal — would violate the
   pyroute2-first standard).
2. **Log-volume back-pressure** — high-volume logging from a busy
   firewall could overwhelm shorewalld. Need a rate-limit or drop
   policy in the dispatcher (mirror what nft `limit rate` would do
   server-side).
3. **Multi-group dispatch** — operator may want different chain
   classes on different groups (e.g. blacklist hits on group 2,
   normal drops on group 1). Either dispatcher subscribes to a list
   of groups, or a single group is the design constraint.
4. **Per-netns identification in metrics** — when shorewalld runs
   per-netns, the `netns` label is implicit. When centralised, the
   netns name needs to come from the log prefix or sidechannel.

## Done when

- LOGFORMAT / LOGRULENUMBERS / MAXZONENAMELENGTH compile-time work
  lands and is tested.
- `shorewalld/log_dispatcher.py` runs in-netns, decodes nflog group
  N, exposes Prometheus counters.
- `shorewall.conf` has `LOG_DISPATCH` knobs documented in
  `docs/cli/shorewall.conf.md`.
- Integration test: generate firewall with `LOG_BACKEND=netlink`,
  apply, generate test traffic that hits a logging rule, assert the
  Prometheus counter increments.
- Operator doc: when to choose shorewalld vs ulogd2 vs LOG backend.

## Out of scope (deferred further)

- Log shipping to remote sinks (Loki, Elasticsearch). Operator can
  set up a Promtail/Vector tap on the Unix socket.
- Sampling / aggregation in shorewalld itself. Counters are exported
  raw; downstream tools handle aggregation.

## See also

- `docs/roadmap/pyroute2-audit-2026-04-24.md` — pyroute2-first
  standard; this work must comply.
- `packages/shorewalld/CLAUDE.md` — daemon architecture overview.
- `docs/cli/shorewall.conf.md` — settings reference (new entries
  to be added).
