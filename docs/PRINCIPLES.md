# Project principles

Load-bearing design rules for this monorepo. Adherence is non-negotiable;
deviations require explicit justification in the PR description.

## P1 — AI-discoverable tooling

**Any AI agent (Claude, Copilot, Cursor, etc.) must be able to determine
from the docs alone:**

1. **What the tool can be used for** — the capability set (what scenarios
   it runs, what reports it produces, what standards it covers).
2. **How to instruct it** — the invocation surface (CLI flags, required
   config fields, environment variables, prerequisites).
3. **What the tool CANNOT do** — the out-of-scope boundary, so the AI
   doesn't hallucinate features that don't exist.
4. **How to verify it worked** — the expected outputs, log lines, exit
   codes, and how to read the audit report.

Corollary rules:

- Every new CLI must ship with a top-of-file docstring / `--help` block
  that answers the four points above in ≤50 lines.
- Every new YAML schema field must land with one-line purpose + expected
  value shape (type, enum, example).
- Any non-obvious dependency chain (load order, env vars, file paths)
  goes in a `docs/testing/*.md` or the relevant package `CLAUDE.md`.
- Pointer from the root CLAUDE.md or a package CLAUDE.md is mandatory;
  orphan docs are drift.
- If a concept takes > 2 reads for a competent engineer to grok, the
  doc is wrong, not the engineer.

**The test**: an AI agent handed only the docs should be able to write
a correct `stagelab run …` or `tools/run-security-test-plan.sh …` invocation
for a new standard without reading source code. If they have to `grep` or
`Read` a Python file to figure out flags, the docs are incomplete.

### Practical checks on every PR

- [ ] New CLI / subcommand has `--help` that describes purpose + required
      flags + an example.
- [ ] New YAML field has a sentence or example in `docs/testing/*.md`.
- [ ] New scenario kind appears in `docs/testing/security-test-plan.md`
      with its acceptance-criteria shape.
- [ ] New dependency (pip extra, system package, external binary) is
      listed in `tools/setup-remote-test-host.sh` AND the relevant
      package `CLAUDE.md`.
- [ ] `README.md` or `CLAUDE.md` of the touched package links to the new
      feature so it's discoverable from the top of the tree.

## P2 — No secrets in git

- Community strings, API keys, passwords: ONLY via `${ENV_VAR}`
  placeholders in YAML. Never a literal value, even in an example file.
- Exceptions: well-known public defaults (`public` SNMP community on a
  lab-only network) may appear in docs but NEVER in a production config.
- If you catch a secret in a diff, halt and rotate.

## P3 — Deployment names are scoped

- Commit messages, `CHANGELOG.md`, and release notes refer to the
  **reference HA firewall** / **reference config** — never the real
  deployment name (fw-primary, fw-secondary, etc.).
- Internal files (repo-local `CLAUDE.md`, operator runbooks, `tools/`,
  `nodes/<name>/`) may use the real name.
- Published history is public; keep it generic.

## P4 — Point of truth for verification

Ranking when signals disagree (from `docs/testing/point-of-truth.md`):

1. **`iptables.txt` + `ip6tables.txt`** (reference-HA dumps, kept outside this repo) — live dumps from the reference-HA primary. The authoritative "what is the firewall actually doing" signal.
2. **`etc/shorewall{,6}/`** (in the same reference-dump directory) — the Shorewall config that produces (1). Use when (1) looks stale.
3. **simlab output** is the WEAKEST signal. When simlab disagrees with (1), assume simlab is wrong and investigate: probe generator → topology → emit.

## P5 — Test reports split false-drop vs false-accept

- Never just "N mismatches". Always split into:
  - `fail_drop_count` (expected ACCEPT, got DROP) — *unnecessary restriction*
  - `fail_accept_count` (expected DROP, got ACCEPT) — *security hole*
- Include the oracle reason (which rule fired, which chain matched).
- Random-probe mismatches need full provenance so they can be triaged
  vs. dismissed as known noise.

## P6 — Two-scope edits

When a change touches both a **core package** and a **consumer package**:

- Core first: ship + release + test-in-isolation.
- Consumer next: bump dep floor + update, referencing the core release.

Resists the temptation to edit both at once — atomic cross-cutting changes
are painful to revert if the core turns out to need revisions.

## P7 — Versions stay in sync

Every `pyproject.toml` + `__init__.py` + RPM spec + Debian changelog +
`CHANGELOG.md` moves together in a single commit. Never a divergent
version floor across the monorepo. See `CLAUDE.md` release-state
section for the full list of files.

## P8 — Backend-pluggable architecture

The compiler must keep `IR → backend emit` and `IR → backend apply`
behind clean interfaces so that **alternative kernel backends can
replace nftables without touching the IR or the parser**. Concrete
near-term target: **VPP** (Vector Packet Processing) as a userspace
fast-path alternative.

Practical implications for every change:

- `shorewall_nft.compiler.ir.*` is **backend-agnostic** — no nft,
  iptables, or VPP-specific concepts in `Rule`, `Chain`, `Match`,
  `Verdict`, `FirewallIR`, or any field on them. Specifically:
  - Match field names describe **what** is matched (`saddr`, `dport`,
    `proto`, `iif`, `ct_state`), not **how** the backend expresses it.
  - Verdicts describe semantic intent (`SnatVerdict`, `MarkVerdict`,
    `LogVerdict`), not the backend syntax.
- `shorewall_nft.nft.*` is **one** backend. Adding a sibling
  `shorewall_nft.vpp.*` (or `shorewall_nft.bpf.*`, etc.) must not
  require any change to `compiler/` or `config/`.
- Runtime apply paths live alongside the backend they target. A
  backend selector in `runtime/` decides which `apply_*()` to call
  based on a `BACKEND` setting in `shorewall.conf` (default `nft`).
- Capability probing is per-backend (`nft/capabilities.py` already
  exists; future `vpp/capabilities.py` would be the parallel).
- Tests that assert on emitted nft strings live under
  `tests/backends/nft/` (or are tagged `backend=nft`); IR-level tests
  must stay backend-agnostic so the same suite catches regressions
  for any backend.

The test for whether code violates this principle: would adding a
new backend require editing this file? If yes, the abstraction is
wrong. Refactor before adding the new backend, not after.

This is a **direction**, not a current implementation. The codebase
today has `nft` baked deeply into many places (chain types, hook
priorities, set semantics). Each refactor that touches those areas
should leave them more backend-neutral than it found them.

## P9 — Resource-efficient agent execution

Every multi-step task — especially Sonnet-agent dispatch — must be
planned for **token + time + cost** efficiency before the first
agent call:

- Bundle related work into clusters; one PR per cluster, not per WP.
- Extract upstream / reference material **once** into compact excerpts
  (see `docs/roadmap/upstream-excerpts/` for the model) so each
  agent reads excerpts, not the full source tree.
- Use the **cheapest model** that can do the job correctly:
  - Haiku for trivial / well-specified mechanical tasks.
  - Sonnet for code-writing with judgement calls.
  - Opus for architecture decisions and review.
- Run truly independent agents **in parallel** (background dispatch,
  await notifications). Sequence only when files conflict.
- Defer or drop low-value work surfaced during planning — explicit
  deferral with reason beats silent skipping.
- Reuse fixtures across tests instead of building one per WP.
- Verify with `pytest -q` and commit incrementally; do not let work
  pile up unverified.

The yardstick: would a human reviewer think the dispatch / commit
cadence is sensible? If a single agent run takes 5 minutes when a
parallel pair could finish in 3, the dispatcher (this assistant) is
the bottleneck — fix that.
