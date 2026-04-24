# TODO — shorewalld as log dispatcher (WP-E1 extension "C")

**Status**: pending design + investigation
**Owner**: unassigned
**Priority**: medium — operator quality-of-life for per-netns deployments
**Depends on**: WP-E1 Option B landed (LOG_BACKEND={LOG, netlink/NFLOG} switching).

## Hard requirements (2026-04-24 user directive)

1. **Dual-format output** — every dispatched event must be available
   simultaneously as **plain text** (for `shorewall-nft show log`,
   grep pipelines, `tail -f`) **and** **structured JSON** (for SIEM
   ingest, specifically **Wazuh** as the named primary consumer).
   Both outputs emerge from one decode pass — the nflog payload is
   decoded exactly once and fanned out to per-sink writers. No race
   between two listeners on the same group.
2. **Performance + efficiency is first-class** — this is not an
   add-on knob. Design for 10k+ pps sustained logging without
   kernel drops. Specific budget targets:
   - Zero-copy where possible: lazy header decode; only pay for
     fields a sink actually references.
   - Batched netlink reads via `recvmmsg` (must verify pyroute2
     exposure — see open questions).
   - Decoder thread + per-sink async writers with ring-buffer
     fan-out — a slow sink (stalled Wazuh endpoint) must never
     block the nflog reader.
   - Explicit drop counters per sink (`shorewall_log_sink_dropped_total{sink="json"}`)
     so back-pressure is operator-visible.
   - Sampling per disposition (`LOG_SAMPLE_ACCEPT=1:100`,
     `LOG_SAMPLE_DEFAULT=1:1`) — no longer "out of scope" (see
     earlier version of this doc); sampling is a required knob.
3. **Multiple channels per netns** — one netns can (and will)
   subscribe to several nflog groups, each with its own sink
   configuration. Example convention:
   - Group 1 — default firewall log (plain + json)
   - Group 2 — blacklist hits (plain + json, no sampling)
   - Group 3 — audit / A_DROP (json-only, direct to SIEM)
   Per-group: which sinks, which file/socket path, which sample
   rate, which JSON schema. Worker topology is one decoder per
   (netns, group); fan-out to K sinks is cheap within that worker.

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

New shorewalld component `shorewalld/log_dispatcher.py` with a
three-stage pipeline:

**Stage 1 — Reader (one per (netns, group))**
- Opens `pyroute2.NFLOGSocket` (or raw `AF_NETLINK` + `NFNL_SUBSYS_ULOG`
  if pyroute2 lacks a stable NFLOG API — see open questions) **inside
  the target netns**.
- Subscribes to one nflog group per worker.
- Batched read via `recvmmsg` (verify availability; fall back to
  single-recv with tuned `LOG_NETLINK_RCVBUF` if unavailable).
- Pushes raw events into a bounded ring buffer; oldest-dropped on
  overrun, with dropped-count exported.

**Stage 2 — Decoder (one per worker, same thread as reader is fine)**
- Decodes each netlink message exactly once into an internal event
  dataclass with lazy-decoded fields (prefix always, L3/L4 headers
  only if any subscribed sink references them).
- Parses the prefix per `LOGFORMAT` to extract chain + disposition +
  optional rule number.
- Applies per-disposition sampling (`LOG_SAMPLE_*`) before fan-out.

**Stage 3 — Sink fan-out (per-sink async workers)**
- Each sink (plain, json, prom-counter) consumes the decoded event
  from its own queue. Sink-local back-pressure does not propagate.
- Sink types:
  - **plain**: line-based write to `LOG_SINK_PLAIN_FILE` (or Unix
    socket) — for `shorewall-nft show log` + classic grep.
  - **json**: newline-delimited JSON to `LOG_SINK_JSON_SOCKET` (Unix
    socket preferred — backpressure-safe) or file. Schema selectable
    via `LOG_SINK_JSON_SCHEMA={wazuh, ecs, raw}`. Wazuh schema is
    ECS-compatible with `agent`, `rule.groups`, RFC3339 `@timestamp`
    — Wazuh `localfile` decoder ingests it without custom XML.
  - **prom-counter**: per-chain/per-disposition counter updates
    (always on — zero I/O, lives in the existing exporter process).

### Wiring

- `shorewall.conf`: new settings
  - `LOG_DISPATCH={shorewalld, ulogd2, none}` (default `none` —
    preserves current behaviour).
  - `LOG_GROUPS=1,2,3` (comma list; default `1`).
  - `LOG_GROUP_<N>_SINKS={plain, json, prom, plain+json, ...}`
    (default inferred from convention: group 1 = plain+json+prom;
    groups 2+ = json+prom unless overridden).
  - `LOG_SINK_PLAIN_FILE=/var/log/shorewall-nft.log`
  - `LOG_SINK_JSON_SOCKET=/run/shorewalld/log.sock`
  - `LOG_SINK_JSON_SCHEMA={wazuh, ecs, raw}` (default `raw`).
  - `LOG_SAMPLE_DEFAULT=1:1`, `LOG_SAMPLE_ACCEPT=1:100`, etc.
  - `LOG_NETLINK_RCVBUF` (bytes; default 4 MiB).
- `shorewall-nft generate-systemd --netns ...`: when
  `LOG_DISPATCH=shorewalld`, the generated unit ensures shorewalld
  is configured to dispatch (no separate ulogd2 unit needed).
- `shorewalld` exporter: new collector `LogCollector` surfaces:
  - `shorewall_log_total{chain,disposition,netns,group}` — event counts
  - `shorewall_log_sink_dropped_total{sink,reason}` — visible back-pressure
  - `shorewall_log_decode_errors_total{reason}` — malformed prefix etc.

## Open questions

1. **pyroute2 NFLOGSocket + recvmmsg** — does pyroute2 have a stable
   API for `nfnetlink_log` consumption and batched reads? The audit
   doc notes `NFCTSocket` used in shorewalld; need to verify the log
   equivalent exists and exposes `recvmmsg`. If not, fall back to
   `socket.AF_NETLINK` raw + `struct` decoding (still pyroute2-first
   compliant — we own the syscall wrapper). **Performance budget
   depends on this answer** — single-recv caps ~2-3k pps, batched
   reaches 10k+.
2. **Wazuh decoder choice** — ECS-compatible JSON through Wazuh's
   built-in `localfile` + `json` decoder (zero Wazuh-side config,
   low decoder precision) vs. ship a custom decoder XML + rules
   XML (high precision, operator must install). Recommendation:
   start with ECS-compatible `localfile`, add a Wazuh ruleset pack
   in `contrib/wazuh/` as a follow-up once schema stabilises.
3. **Kernel receive buffer** — nfnetlink_log defaults to 4 MiB per
   socket. At 10k pps with a sink stall that's ~1 s headroom. Must
   expose `LOG_NETLINK_RCVBUF` and document the sizing rule.
4. **Worker topology under multi-netns × multi-group** — with N
   netns × M groups × K sinks the naive "one worker per sink" blows
   up. Design decision locked: **one decoder worker per (netns,
   group); sink fan-out is in-worker (cheap) via per-sink async
   queues**. Each sink queue has its own backpressure.
5. **Per-netns identification in metrics** — when shorewalld runs
   per-netns, the `netns` label is implicit (daemon knows its own
   netns). When centralised across multiple netns, the netns name
   comes from the worker's own setns identity, not the log prefix.
6. **JSON schema stability** — once Wazuh rulesets depend on our
   field names, we're locked. Tag the schema with a version field
   (`_schema_version: 1`) from day one; treat breaking changes as
   major-bumps that require a dual-emit grace period.

## Done when

- LOGFORMAT / LOGRULENUMBERS / MAXZONENAMELENGTH compile-time work
  lands and is tested.
- `shorewalld/log_dispatcher.py` runs in-netns, decodes nflog groups
  from `LOG_GROUPS`, emits events to all configured sinks.
- Dual-format output working: plain line file + JSON (Wazuh-compatible
  schema) from one decode pass.
- Multi-group dispatch working: ≥2 groups subscribed in the same
  netns with different sink configurations, tested end-to-end.
- Performance verified: sustained 10k pps logging in integration test
  without drop-counter increments (at default `LOG_NETLINK_RCVBUF`
  with one sink stalled for ≥200ms, the other sinks continue without
  drops).
- `shorewall.conf` has all `LOG_DISPATCH*`, `LOG_GROUPS*`,
  `LOG_SINK_*`, `LOG_SAMPLE_*`, `LOG_NETLINK_RCVBUF` knobs documented
  in `docs/cli/shorewall.conf.md`.
- Integration test: generate firewall with `LOG_BACKEND=netlink` and
  two groups, apply, generate test traffic, assert Prometheus counter
  increments AND plain log line AND Wazuh-schema JSON line all appear
  for the same event.
- Operator doc: when to choose shorewalld vs ulogd2 vs LOG backend;
  per-sink sizing guidance for 1k / 10k / 100k pps tiers.
- `contrib/wazuh/README.md` showing minimal Wazuh `ossec.conf`
  `<localfile>` entry that ingests our JSON socket/file.

## Out of scope (deferred further)

- Full Wazuh ruleset pack (custom decoder XML + high-level rules XML).
  Start with ECS-compatible JSON that Wazuh's built-in decoder
  consumes; ship a ruleset pack as a follow-up after schema freezes.
- Log shipping to remote sinks directly from shorewalld (Loki,
  Elastic HTTP, Kafka). Operator can set up a Promtail / Vector /
  Filebeat / Wazuh agent tap on the Unix socket or file.
- In-process aggregation beyond counters (percentile histograms,
  top-N source IPs). Let downstream (Prometheus + PromQL, or Wazuh
  rules) handle it.

## See also

- `docs/roadmap/pyroute2-audit-2026-04-24.md` — pyroute2-first
  standard; this work must comply.
- `packages/shorewalld/CLAUDE.md` — daemon architecture overview.
- `docs/cli/shorewall.conf.md` — settings reference (new entries
  to be added).
