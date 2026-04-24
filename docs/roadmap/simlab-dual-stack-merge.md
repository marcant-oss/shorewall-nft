# Plan: dual-stack production parity + shared infrastructure for simulate.py and simlab

## Context (revised 2026-04-24)

Earlier framing was wrong: the goal is **not** to retire
`verify/simulate.py`. The user wants:

1. **IPv4 and IPv6 both production-ready, both fully working.** Either
   family may be optional (a v4-only or v6-only deployment is fine),
   but whichever families are configured must be fully supported.
2. **Merge infrastructure where sensible** so the two runtimes share
   as much code as possible — validators, test-derivation, netns
   primitives, probe generators.
3. **Do not delete simulate.py.** Keep both runtimes coexisting; the
   user has later ideas for a deeper merge.

Both runtimes are rootless via `unshare --user --map-root-user --net
--mount`, so the infrastructure question is purely about code
factoring, not privilege mode.

## Four phases, all additive (no deletion)

| Phase | Theme | Dependency |
|---|---|---|
| **I — Dual-stack production readiness** | Fix every IPv6 gap in both runtimes so v6 is first-class in parallel with v4. | Spike at start (nft v6-probe parity sanity check), then implementation. |
| **II — Shared-infrastructure merge** | Move validators (tc_validate, connstate) into netkit, rebuild them to accept a `ns_name` parameter, parameterise probe-derivation for family. Both runtimes consume the shared layer; neither is retired. | Phase I done. |
| **III — Feature-parity additions in simlab** | Port INPUT-chain coverage + REJECT-vs-DROP distinction into simlab so it covers the same semantic surface as simulate.py. simulate.py keeps those features; simlab gains them. | Phase II done. |
| **IV — NAT + deep conntrack verification** | **New capability, missing from both runtimes today.** Verify that DNAT/SNAT actually rewrote the packet (daddr / saddr + reverse-direction symmetry); verify conntrack state (NEW / ESTABLISHED / RELATED) and tuplehash_orig/reply divergence on NAT'd flows; verify mark is set as expected for fw-mark-based routing. | Phase II done (leverages the shared-validator layer). |

Nothing is deleted. Tests for both runtimes run side-by-side; CI
gate ensures verdicts stay consistent across the two.

---

## Phase I — IPv6 production-ready parity

Audit finds these concrete gaps:

### simulate.py IPv6 audit targets

- `TestCase.family: int = 4` at `simulate.py:75` — defaults to 4;
  confirm every caller sets family explicitly where a v6 probe is
  intended. Random-probe generator branch must produce v6 test-cases
  at the same ratio as v4.
- `_tcp_probe` / `_udp_probe` / `_icmp_probe` at `simulate.py:731-766`
  — family parameter threading + v6 socket flags
  (`socket.AF_INET6`). Audit whether all three branches honour
  `family=6`.
- NS addressing: `SRC_FW_GW6`, `SRC_PEER6`, etc. at `simulate.py:56`
  — v6 addresses declared, verify used symmetrically.

### simlab IPv6 audit targets

- Oracle coverage: "Known limitations" section of
  `docs/testing/simlab.md` previously said "oracle + random generator
  stick to v4". **Verify** whether this is still accurate post-Phase
  6 commit history; fix if still true.
- `RulesetOracle` at `shorewall-nft-simlab/shorewall_nft_simlab/oracle.py`
  — ensure both ipv4 and ipv6 iptables dumps feed it (the `ip6tables_path`
  at `smoketest.py:1274` hint is already there but may be partial).
- `fast_extract_*` helpers in `packets.py` — IPv6 header offsets
  differ (40-byte header vs 20, next-header chain). v6 variants
  may be missing or partial.
- `controller.py::_on_observed_fast` — correlator keys; must handle
  v4 + v6 addresses without truncation.

### Shared toggles

- Parser-level auto-detect: when only `iptables.txt` is present →
  v4-only. When only `ip6tables.txt` is present → v6-only. When both
  → dual. No hard dependency; either family optional.
- New flag `--family {4,6,both}` (default `both`) on both CLI
  entry points. Rejects v6 probes at plan time if the operator
  explicitly asked for v4-only.

### Phase I exit criteria

- Both CLIs produce v6 probes at feature parity with v4 (random +
  per-rule coverage).
- Integration test passes with a pure-IPv6 fixture (no v4
  addresses anywhere).
- Integration test passes with a dual-stack fixture and verifies
  v4 + v6 probes fire in proportion.
- Integration test passes with a pure-IPv4 fixture (back-compat).

Effort: **~2–3 days**.

---

## Phase II — Shared-infrastructure merge

### Candidate merges (ranked by ROI)

| Rank | Candidate | Current state | Merge action |
|---|---|---|---|
| **1** | Validators (`tc_validate`, `connstate`) | shorewall-nft `verify/*.py`; hardcoded `NS_FW`; simulate.py-only callers | Move to `shorewall-nft-netkit/shorewall_nft_netkit/validators/`; parameterise `ns_name`; both runtimes import from netkit. |
| **2** | netns topology primitives | `verify/netns_topology.py` (simulate.py) + simlab's `SimFwTopology` partly duplicate veth/TUN creation | Extract common primitives (setup netns, add loopback, bring iface up) into `netkit.netns_primitives`; keep the veth-vs-TUN divergence in each runtime. |
| **3** | Probe derivation | `iptables_parser` + `derive_tests_all_zones` already shared via `shorewall_nft.verify` imports in simlab | **Already merged**; audit for any remaining copy-paste. |
| **4** | Packet construction | simulate.py uses real sockets; simlab uses scapy frames | **Do not merge** — fundamentally different execution model. Keep each runtime's builders. |

### Phase II exit criteria

- `shorewall-nft-netkit` exposes `validate_tc(config_dir, *, ns_name=...)`
  and `run_small_conntrack_probe(dst_ip, port, *, ns_name=..., src_via_socket=True)`.
- Both runtimes call these from netkit; `verify/tc_validate.py`
  and `verify/connstate.py` become re-export shims for backward
  compat (not deleted; thin proxies).
- Dual CI gate: the same probe list, derived from a shared fixture,
  executed by both runtimes, yields the same ACCEPT/DROP verdict
  per probe (allowing for the known REJECT/DROP simulation
  semantics differences that Phase III fixes).

Effort: **~2 days**.

---

## Phase III — simlab feature-parity additions

Add to simlab, in parallel with simulate.py's existing
implementations. After this, simlab covers the same semantic
surface; simulate.py still works identically.

### G1 — INPUT-chain coverage in simlab

Pattern: copy `verify/slave_worker.py::spawn_worker` semantics
into `shorewall_nft_simlab/input_worker.py`, but target
**simlab-fw itself** as the source netns (no per-zone slave NS —
INPUT-chain traffic originates from the firewall's own process
space). Implementation: fork inside simlab-fw via
`netkit.netns_fork.run_in_netns_fork`, open a normal Python socket,
record connect/sendto outcome as verdict. No TUN/TAP involvement
for INPUT probes; they take a separate code path that never
injects into the reader thread.

### G2 — Tie the shared validators in

Wire `netkit.validators.validate_tc` + `run_small_conntrack_probe`
into simlab's `cmd_full` post-load hook. Results land in
`report.json` under `validation_warnings`.

### G3 — REJECT vs DROP distinction in simlab

Extractors added to `packets.py`:
- `fast_extract_tcp_flags(frame) -> int | None`
- `fast_extract_icmp_unreachable(frame) -> (code, inner_5tuple)` (v4 + v6 variants)

Correlator state machine in `controller.py::_on_observed_fast`:
- TCP RST with matching probe's 5-tuple → REJECT
- ICMP-unreachable carrying probe's 5-tuple in the inner packet → REJECT
- SYN-ACK / expected reply → ACCEPT
- Timeout → DROP

Verdict enum gains `REJECT`. Reverse-lookup LRU keyed by
`(family, proto, saddr, daddr, sport, dport)` — sized to
`max_per_pair × N_pairs` with ~64-byte entries.

### Phase III exit criteria

- simlab's `--all-zones` mode now includes `fw_input` category
  with INPUT-chain test cases.
- simlab's report distinguishes REJECT from DROP on the six
  TCP/UDP/ICMP × v4/v6 combinations.
- Validators run post-load; warnings appear in the structured
  report.
- CI dual-gate confirms simulate.py and simlab agree on
  every probe including REJECT/DROP distinction.

Effort: **~3 days**.

---

## Phase IV — NAT + deep conntrack verification (new capability)

Neither runtime verifies NAT today. Confirmed by read-only grep:
no `DNAT`/`SNAT` verdict assertions, no `tuplehash_reply` checks,
no NAT-rewrite observability in either `verify/connstate.py` or
`shorewall-nft-simlab`. `connstate.py` today only **counts**
conntrack entries per protocol.

### Scope

Add four verification categories to the shared `netkit.validators`
module (available to both runtimes after Phase II):

| Category | What it asserts |
|---|---|
| **NAT rewrite — DNAT** | For a rule `iifname X ip daddr V dnat to I:P`, send a probe to `V` from `X`. Assert (a) the backend at `I` sees `daddr=I, dport=P`; (b) reverse-direction reply leaves the firewall with `saddr=V`. Both v4 and v6. |
| **NAT rewrite — SNAT / MASQUERADE** | Send a probe from an internal source, assert the egress packet has the SNAT target as `saddr`; reply symmetry likewise. |
| **Conntrack state** | For a triggered flow, read the conntrack entry via `NFCTSocket.dump()` and assert the state is as expected (NEW → ESTABLISHED after handshake). Extend for RELATED (e.g. ICMP error related to a TCP flow). |
| **Conntrack NAT tuple** | When the flow traversed a NAT rule, read `tuplehash_orig` and `tuplehash_reply` from the ct entry and assert they diverge on the NAT'd field (proves the NAT was applied at the conntrack layer, not just textually in a rule). |

### Implementation sketch

`netkit.validators.nat_verify` (new):

```python
def verify_dnat(
    probe: ProbeSpec,
    *,
    src_ns: str,      # where to inject from
    fw_ns: str,       # where to inspect ct
    dst_ns: str,      # where to observe arrival
) -> NatResult:
    """Inject probe, assert daddr rewrite, assert reverse-path saddr."""

def verify_snat(probe: ProbeSpec, *, src_ns, fw_ns, dst_ns) -> NatResult:
    """Symmetric for SNAT / MASQUERADE."""

def verify_ct_state(
    *, fw_ns: str, flow_tuple: tuple[str, str, int, int, str]
) -> CtStateResult:
    """Read NFCTSocket, assert expected state (NEW/ESTABLISHED/...)."""

def verify_ct_nat_tuple(
    *, fw_ns: str, orig_tuple, expected_rewrite
) -> CtNatResult:
    """Assert tuplehash_reply diverges from orig on the NAT field."""
```

**simulate.py integration**: `verify/connstate.py` gets new methods
that call into the above — runs alongside the existing conntrack-
count probes.

**simlab integration**: adds a new probe category `"nat_verify"`
that exercises each NAT rule in the iptables dump with a
matching probe, checks the four assertions above.

### Rule-source for NAT probes

Both runtimes already parse the iptables dump via
`verify/iptables_parser.py`. Extract the DNAT / SNAT /
MASQUERADE target lines into a list of `NatRule` dataclasses and
pass them to the new validator. v4 and v6 handled uniformly
(different table names but same rule shape).

### Phase IV exit criteria

- Shared `netkit.validators.nat_verify` module lands with four
  methods + unit tests (mock NFCTSocket).
- Both runtimes expose a new `--verify-nat` CLI flag (default on).
- Integration test: dual-stack fixture with at least one DNAT + one
  SNAT rule; both runtimes verify the rewrite and the conntrack
  tuple divergence, both agree on the verdict.

Effort: **~3 days** (heaviest phase because it's new capability,
not just porting; adds ~600 LOC of validator + tests).

---

## Risk for Phase IV

- **Conntrack availability for ICMP** — not every distribution
  has `nf_conntrack_proto_icmpv6` module loaded by default. Fall
  back gracefully: if `NFCTSocket.dump(tuple_orig=...)` returns
  empty for an ICMP probe, flag as "inconclusive" rather than
  "fail".
- **Timing** — conntrack entries persist after the flow closes
  (default 60-120s). verify_ct_state must either sample at a
  specific moment in the probe lifecycle or filter on timestamp.
  Mitigation: flush ct before each probe, read immediately after.
- **MASQUERADE with ephemeral source ports** — the specific
  egress sport is random; assertion must allow a port range or
  match on proto+daddr only.

---

## Rollback / risk posture

All three phases are purely **additive**. No deletions, no
signature changes on public APIs. Every phase's code is revertable
via a single-commit revert. Worst-case if Phase III correlator
regresses: we disable it via a feature flag; v1 behaviour
(ACCEPT/DROP only) returns.

Primary risks:

1. **IPv6 ICMP-unreachable layout** — IPv6 ICMP type 1 (Destination
   Unreachable) carries the inner invoking packet starting at
   offset 8 of the ICMPv6 payload. Extractor must skip the 8-byte
   ICMPv6 header. Covered by explicit unit tests.
2. **Validator import cycles** — moving validators into netkit
   may expose import ordering bugs (netkit → shorewall-nft for
   `config_dir` parsing?). Design: netkit validators accept
   pre-parsed data structures; callers do the config load.
3. **REJECT false-positives from unrelated flows** — if two
   concurrent probes share ports (possible on a busy test run),
   the reverse-lookup LRU must key on full 5-tuple. Unit test
   with two overlapping probes.

---

## Existing building blocks surveyed (read-only research)

Reading the current code confirmed these integration points:

- **`verify/slave_worker.py::spawn_worker`** (line 266) —
  self-contained fork + pipe worker. Directly portable into
  simlab with no conceptual adaptation. Keeps existing
  simulate.py use intact.
- **`verify/connstate.py::run_small_conntrack_probe`** (line 341)
  — already uses `NFCTSocket` (Task #66 migration); only the
  injector uses `ns(NS_SRC, "nc ...")` at line 367. Replace
  with `socket.create_connection()` to make it runtime-neutral.
- **`verify/tc_validate.py::validate_tc`** (line 101) — hardcoded
  `NS_FW` via `_ns(…)` at lines 44/68/77/90/132. Parameterise
  `ns_name` in all six call sites; default keeps simulate.py
  behaviour.
- **`shorewall-nft-simlab/.../controller.py::_on_observed_fast`**
  (line 410) — single-lookup pass; needs verdict state-machine
  extension for G3. No refactor to existing surface.
- **`shorewall-nft-simlab/.../packets.py::fast_extract_*`** —
  pattern for new extractors (see G3).
- **`RulesetOracle`** imports both `iptables_dump` and optional
  `ip6t_dump` (`smoketest.py:1274-1278`). IPv6 branch is already
  wired; Phase I audit verifies no `family=4` shortcut
  downstream.

Dependency count for file-deletion — **moot under this plan**
since we are not deleting anything. Kept for completeness:

- `verify/simulate.py` callers: `runtime/cli/debug_cmds.py` +
  4 test files.
- `verify/slave_worker.py` callers: `verify/simulate.py` only.
- `verify/netns_topology.py` callers: `verify/simulate.py` +
  `verify/tc_validate.py::validate_nft_loaded`.
- `verify/tc_validate.py` callers: `verify/simulate.py` +
  `runtime/cli/debug_cmds.py`.
- `verify/connstate.py` callers: `verify/simulate.py` only.

All of these keep working after Phase II (re-export shims); all
of these keep working after Phase III (new simlab capabilities
are parallel, not replacing).

---

## Documentation coverage

Every phase ships documentation as a first-class deliverable.

| Phase | Doc target | Change |
|---|---|---|
| I | `docs/testing/simlab.md` | Drop the IPv4-only caveat from "Known limitations". Add `--family` flag + v6-only / v4-only examples. |
| I | `docs/testing/point-of-truth.md` | Note that simulate.py and simlab now agree on v6 verdicts; tie-breaker ranking unchanged. |
| I | `tools/man/shorewall-nft-simlab.8` | Add `--family` flag; update synopsis + `--help` excerpt. |
| II | `docs/testing/simlab.md` | "Shared infrastructure" section describing netkit-backed validators and how to read `validation_warnings` from a report. |
| II | `packages/shorewall-nft-netkit/CLAUDE.md` | Document the new validator API + why it moved. |
| II | `tools/man/shorewall-nft.8` | `verify` / `simulate` subcommands: cross-ref the netkit-shared validator surface. |
| III | `docs/testing/simlab.md` | "Feature parity" section covering INPUT-chain + REJECT distinction. Move the comparison table from my earlier answer into this doc (NOT marked as retirement; marked as reference). |
| III | `tools/man/shorewall-nft-simlab.8` | INPUT-chain category + REJECT verdict semantics. |
| III | `tools/man/shorewall-nft.8` | `simulate` subcommand: update --data-path behaviour to match the new capability surface. |
| All phases | `CHANGELOG.md` | One `[Unreleased]` entry per phase. |

Man pages are **not optional** — every phase that adds a CLI flag
or behaviour visible to operators updates the relevant `.8` / `.1`
file and a `groff -man -Tutf8` validation passes in the commit.

---

## Verification

### Phase I (dual-stack readiness)

**Unit gate** (rootless):
```bash
unshare --user --map-root-user --net --mount -- \
    .venv/bin/pytest packages/shorewall-nft/tests \
                     packages/shorewall-nft-simlab/tests \
                     -q -k "ipv6 or dualstack"
```
Target: at least 20 new test cases covering v6-only / v4-only /
dual-stack paths on both runtimes.

**Integration smoke** (rootless):
```bash
# Pure-v6 fixture
unshare --user --map-root-user --net --mount -- bash -c '
    shorewall-nft-simlab --config tests/fixtures/v6-only --data /tmp/v6-snap full
    shorewall-nft simulate --config-dir tests/fixtures/v6-only --iptables /tmp/v6-snap/ip6tables.txt
'
# Pure-v4 fixture — same commands against tests/fixtures/v4-only
# Dual-stack — same commands against tests/fixtures/ref-ha-minimal
```

### Phase II (shared infrastructure)

- `from shorewall_nft_netkit.validators import validate_tc,
  run_small_conntrack_probe` works both in `verify/simulate.py`
  and in `simlab.smoketest`.
- The same pytest run exercises both runtimes against the same
  probe list and asserts identical verdicts.

### Phase III (feature parity)

- simlab report now includes `fw_input` category.
- REJECT-vs-DROP distinction round-trips: a fixture with a
  `REJECT` rule shows `expected=REJECT, observed=REJECT` in
  simlab's report.
- CI parity gate: run both runtimes on the same fixture with the
  same seed; per-probe verdict agreement rate ≥ 98 %
  (allowing for the small topology-model differences that
  remain — documented in simlab.md).

---

## Effort total

| Phase | Effort | Gated on |
|---|---|---|
| I   — dual-stack | ~2–3 days | spike of nft v6 probe primitives on target kernel |
| II  — shared infra | ~2 days | Phase I done |
| III — simlab parity | ~3 days | Phase II done |
| IV  — NAT + deep ct | ~3 days | Phase II done (parallel with III possible) |

**Wall-clock**: ~10–11 days Sonnet-agent time. Waits on the
shorewalld-Claude's keepalived feat branch to land before Phase I
starts (to avoid branch/stash churn that has already cost time
twice this session).

---

## Post-approval execution (when shorewalld-Claude's feat branch lands)

1. Copy this plan to `docs/roadmap/simlab-dual-stack-merge.md`.
2. Link from `docs/roadmap/index.md`.
3. Create four TaskCreate entries (one per phase) with
   - Phase II blocked on Phase I
   - Phase III blocked on Phase II
   - Phase IV blocked on Phase II (parallel to III)
4. Commit `docs(roadmap): dual-stack parity + shared-infra +
   NAT verification plan — TODO`.
5. Push.

---

## Pre-implementation research notes (carried over from earlier analysis)

The file and line pointers below are the read-only results from
this plan-mode session. Agents starting Phase I/II/III can skip
the discovery pass.

### G1 source — slave_worker pattern

`verify/slave_worker.py::spawn_worker` (line 266). Fork + duplex
Pipe. `worker_main` accepts
`("probe", proto, src_ip, dst_ip, port, family, timeout)` and
returns `("ok", verdict, ms)`. Direct copy into simlab as
`input_worker.py` with no API change.

### G2 sources — validators

- `verify/tc_validate.py::validate_tc` (line 101). Hardcoded
  `NS_FW`; six `_ns(NS_FW, …)` reads to parameterise.
- `verify/connstate.py::run_small_conntrack_probe` (line 341).
  Already `NFCTSocket`-based; replace one `ns(NS_SRC, "nc …")`
  injector (line 367) with `socket.create_connection()`.

### G3 state machine

Current `_on_observed_fast` (`controller.py:410`):

```python
probe = self._probes.get(probe_id)
if probe is None: return
if probe.expect_iface != obs_iface: return
probe.verdict = "ACCEPT"
```

Extends to a verdict state machine keyed on new packet
extractors:

```python
if is_tcp(frame):
    flags = fast_extract_tcp_flags(frame)
    if flags & RST:  verdict = "REJECT"
    elif flags & (SYN|ACK): verdict = "ACCEPT"
elif is_icmp_unreachable(frame):
    inner = fast_extract_icmp_unreachable(frame)
    match = self._rlookup.get(inner)
    if match: self._probes[match].verdict = "REJECT"
else:
    probe.verdict = "ACCEPT"
```

Correlation structure: `_rlookup: dict[5tuple, probe_id]`
populated at inject time, bounded LRU sized by
`max_per_pair × N_pairs × 2`.

### Open questions

1. **Fwstate synthesis fall-back** (for a `simulate --data`-less
   run): generate minimal topology from config + zone subnets.
   Operator warning in output. Optional for Phase I; implement
   in Phase III alongside INPUT-chain addition if time permits.
2. **Probe ordering** — commit on first-observed verdict for a
   probe; a subsequent RST after SYN-ACK is reported as ACCEPT
   (matches simulate.py behaviour since `connect()` returns
   before a kernel-level reset).
3. **IPv6-only deployments** without any v4 address anywhere —
   must not crash the `NS_FW` setup; default-address assignment
   in netkit should be family-aware.

### IPv6 readiness — current state

Contrary to the stale "IPv4 only for the moment" note in
`docs/testing/simlab.md`:

- **simulate.py** — topology add-v6-addresses / add-v6-routes
  covered at lines 240, 281-428. Probe dispatch code paths
  accept `family=4|6` and should work; verify at Phase I spike.
- **simlab** — `RulesetOracle` already branches on `family == 6`
  at oracle.py:71, handles ICMPv6 aliases at line 147-149, and
  `smoketest.py` handles v6 addresses at lines 573, 689, 702,
  704, 722.

So Phase I is **mostly an audit + fill-in** rather than a big
port. Expected outcome: delete the "IPv4 only" limitation note
from simlab.md, add explicit v4-only / v6-only / dual CLI tests,
and document the `--family` flag.

### NAT + conntrack check (Phase IV) — baseline

- `verify/connstate.py::run_small_conntrack_probe` only counts
  ct entries per protocol — no state assertions, no NAT tuple
  inspection, no mark verification.
- Neither runtime has any code that verifies NAT-rewrite success
  (grep for "DNAT", "SNAT", "tuplehash" in simulate.py and
  simlab returns zero assertion sites).
- Phase IV is therefore a **new capability** exposed to both
  runtimes via the shared `netkit.validators` layer introduced
  by Phase II.

End of research.

---

## Status

**Saved 2026-04-24 as a pending TODO.** Implementation starts when
the shorewalld-Claude's `feat/keepalived-snmp-unix` branch lands +
the user signals RW go.

Tracked: TaskList entries for Phase I / II / III / IV.
