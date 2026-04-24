# Maintainability audit — post Phase 6 (2026-04-24)

## Context

Phase 6 added 539 tests (1041 → 1580) and four new compiler subsystems
— SNAT full (`nat.py` +437 LOC), providers full (`providers.py`),
TC full (`tc.py` +480 LOC), and the OPTIONS family — across 16 commits
(`e732d49..fee6782`). The baseline audit's 18 issues are fully closed;
new debt is confined to the Phase-6 growth areas plus one structural
readiness concern (P8 backend-pluggable).

---

## Findings (10 items, ranked by heat)

### Hot

**1. `_idx` / pyroute2 boilerplate — 8 copies across 4 files**
Evidence: `iface_idx: dict[str, int]` + inner `def _idx(name) -> int | None`
is copy-pasted verbatim in `runtime/apply.py` (×4), `compiler/tc.py`
(×2), `compiler/proxyarp.py` (×2). The pattern is identical each time:
cache, `link_lookup`, store, return. A `runtime/pyroute2_helpers.py`
module with a single `def resolve_iface_idx(ipr, name, cache) -> int | None`
would eliminate all copies and give a natural home for future pyroute2
helpers (`_bool_setting`, `IPRoute(netns=…)` construction).
Effort: ~2h.

**2. `_bool_setting` inline triplication inside `providers.py` /
`apply.py`**
Evidence: The identical 3-line closure
(`val = settings.get(key, …).strip().lower(); return val in ("yes", "1", "true")`)
appears at `providers.py:365`, `apply.py:300`, and `apply.py:579`. The
broader pattern (27 in-line `in ("yes", "1"…)` checks across the
compiler) indicates no shared utility. A single `settings_bool(settings,
key, default)` function in `compiler/ir/_data.py` (or the proposed
pyroute2_helpers module) would remove all 27 sites and prevent future
drift. Effort: ~1.5h.

**3. Untyped `list` fields in `FirewallIR` (`providers`, `routes`,
`rtrules`, `tcinterfaces`, `tcpris`)**
Evidence: `_data.py:312–320` — five fields typed `list` (bare, no type
parameter) while the concrete types (`Provider`, `Route`, `RoutingRule`,
`TcInterface`, `TcPri`) exist in `compiler/providers.py` and
`compiler/tc.py`. The reason appears to be circular-import avoidance
(IR cannot import from compiler modules that import from IR). Resolving
this via `TYPE_CHECKING`-guarded forward references — or by moving the
five dataclasses into `compiler/ir/_data.py` directly — would give full
mypy coverage over `FirewallIR.providers` etc. This is the main remaining
type-safety gap in the IR. Effort: ~3h.

### Warm

**4. `compiler/ir/_build.py` — 1817 LOC, 20 top-level `_process_*`
functions**
Second-largest file in the codebase. Functions are well-named, well-
sized (longest is `_process_routestopped` at 218 lines, `_process_stoppedrules`
at 196 — complex but readable). A natural seam exists between
"connectivity processing" (lines 51–680: policies, notrack, conntrack,
interface options, host options, dhcp interfaces) and "security-feature
processing" (lines 681–1817: blacklist through synparams). A split into
`_build_zones.py` + `_build_security.py` would keep each file under
~900 LOC without changing any public interface. Not urgent; do as
"while you're in there" the next time a feature lands. Effort: ~4h.

**5. `LogSettings` threading in `nft/emitter.py`**
Evidence: `LogSettings | None` appears as an Optional parameter at
`_emit_chain` (604), `_emit_rule_lines` (1171), and `_emit_rule` (1212),
and is constructed twice at the top of `emit_nft` (351, 530, 579). The
`None` fallback at use-sites (1335, 1339, 1342) implies it *should
never* be None in practice — the Optional is a leaky guard. A thin
`EmitContext` dataclass carrying `log_settings`, `debug_ctx`, and
`capabilities` as non-optional fields would collapse the three separate
optional params and make None cases explicit. Low urgency because the
current code is correct. Effort: ~2h.

**6. `compiler/nat.py::_process_snat_line` — implicit helper sprawl**
Evidence: Function body (lines 297–416, ~120 lines) is clean, but
`_add_snat_matches` is called for 6 optional columns (IPSEC, MARK,
USER, SWITCH, ORIGDEST, PROBABILITY) without docstring, type
annotation, or per-column validation feedback. Extracting ORIGDEST and
PROBABILITY handling into their own helpers (mirroring the existing
`_parse_snat_action`) would make adding future columns safer. No hot-
path complexity concern. Effort: ~1h.

**7. `test_emitter_features.py` — 871 LOC, 15 test classes, 75 tests**
Only test file above 800 LOC. Natural split between `TestFlowtable`
through `TestDnatConcatMap` (35–344, emitter feature tests) vs.
`TestRoutestopped` through `TestEcn` (473–871, build-pipeline feature
tests). The second group arguably belongs in a `test_build_features.py`
or `test_ir_features.py`. Not blocking — all 75 tests are independent.
Effort: ~30 min rename/move.

**8. `shorewall.conf` settings access — 37 scattered `settings.get(...)` calls**
Most unique keys appear only once, so a full typed `Settings` dataclass
(analogous to `MarkGeometry`) is not yet warranted. Highest-leverage
partial step: a `settings_bool()` utility (item 2) plus documenting the
canonical defaults in one place. A full `Settings` dataclass becomes
the right move only when a second pass audits whether keys are
mis-typed or have inconsistent defaults across access sites. Effort
for partial: 1h; full dataclass: ~8h.

### Cold

**9. `FirewallIR` dataclass field count and `default_factory` sprawl**
13 `field(default_factory=…)` entries; 6 added in Phase 6
(`ip_aliases`, `providers`, `routes`, `rtrules`, `tcinterfaces`,
`tcpris`). Each is justified and independently documented; no
consolidation opportunity that would not reduce clarity. The only
structural improvement (typing the 5 lists) is captured in item 3.
No further action.

**10. `compiler/tc.py::emit_tcinterfaces_shell` — shell template
assembly**
Lines 272–344 produce shell `tc` commands via f-string concatenation.
Code is readable, output is straightforward, function is covered by
`test_tcinterfaces.py`. The `CLEAR_TC` branch (299–305) has a dead
duplicate (both branches produce identical output) but it is cosmetic.
No refactor needed; the pyroute2-first standard means this function
is on the deprecation path anyway once `apply_tcinterfaces` is fully
promoted as the default.

---

## Recommendations (priority order)

1. **Create `runtime/pyroute2_helpers.py`** with `resolve_iface_idx()`,
   `open_ipr()`, and `settings_bool()`. Eliminates all 8 `_idx` copies
   and all 3 `_bool_setting` closures in one pass. Highest-leverage
   cleanup available (items 1+2 together, ~3h).

2. **Fix the 5 untyped `list` fields in `FirewallIR`** (item 3). Move
   `Provider`, `Route`, `RoutingRule`, `TcInterface`, `TcPri` dataclasses
   into `compiler/ir/_data.py` — no runtime dependency on compiler
   internals — and drop the bare-`list` annotations. Unblocks mypy
   strict mode on the IR layer (~3h).

3. **Split `_build.py`** (item 4) as a background task when the next
   feature lands in that file. Avoids the 2000-LOC threshold without
   forced effort.

4. **Introduce `EmitContext`** (item 5) the next time `_emit_chain` or
   `_emit_rule` is touched. Eliminates the `LogSettings | None`
   anti-pattern.

5. **P8 backend-pluggable first step** — see below.

### Backend-pluggable (P8) — top 5 leak points + suggested first step

The five places where adding a VPP or eBPF backend would require IR or
parser changes today:

1. **`FirewallIR.dns_registry` / `dnsr_registry` / `nfset_registry`** —
   `_data.py:284–294`. Instances of nft-specific classes
   (`DnsSetRegistry`, `DnsrRegistry`, `NfSetRegistry`) imported directly
   from `shorewall_nft.nft.*`. A non-nft backend cannot consume these.
   Should be abstracted to generic protocols/interfaces in `compiler/ir/`.

2. **`split_nft_zone_pair` in `_data.py:504`** — the naming convention
   for zone-pair chains (`src-dst`) is nft-specific and encoded in the
   IR. A VPP backend uses different identifiers. Function and
   convention should become a backend parameter.

3. **`ChainType.ROUTE` and `Hook.*` enums** — values like `"filter"`,
   `"nat"`, `"route"`, `"prerouting"` are nft wire strings embedded in
   the IR. A non-nft backend would need to translate or replace them.

4. **`emitter.py:152`** — `"table inet shorewall"` hardcoded. The
   `NftInterface.load_file()` chain assumes nft -f input format
   throughout. The emitter is not behind any interface; it is called
   directly from `apply_cmds.py`.

5. **`compiler/proxyarp.py::emit_proxyarp_nft` and `emit_proxyndp_nft`**
   — emit nft-specific set/map syntax directly. The runtime apply
   counterparts use pyroute2 (backend-agnostic), but compile-time
   nft paths have no abstraction layer.

**Suggested first step**: extract a `BackendEmitter` protocol in a new
`compiler/backends/__init__.py` with a single method
`emit(ir: FirewallIR) -> str`. Move `nft/emitter.py::emit_nft` behind
this protocol. Does not change behaviour; makes the nft coupling
explicit and provides the hook for a VPP/eBPF implementation. Effort
~2–3h for the protocol + adapter wrapper. The DNS/nfset registry
abstraction is a separate ~1-day task.

---

## Comparison vs baseline

| Metric | 2026-04-23 baseline | 2026-04-24 now | Δ |
|---|---|---|---|
| `ir.py` LOC | 3398 (1 file) | 4524 (5 files: `_data.py` 534, `_build.py` 1817, `rules.py` 1141, `spec_rewrite.py` 616, `__init__.py` 416) | split; largest file −46% vs monolith |
| `cli.py` LOC | 2929 (1 file) | ~2739 (7 files: `apply_cmds.py` 904, `_common.py` 842, `debug_cmds.py` 556, `config_cmds.py` 437 + 3 smaller) | split; largest file −69% vs monolith |
| Test count | 688 | 1580 | +892 (+130 %) |
| Test:code ratio | 0.43:1 | 18687 / 28116 = **0.66:1** | +0.23 |
| God-modules >2000 LOC | 2 | **0** | −2 |
| Files 1500–2000 LOC | unknown | 2 (`_build.py` 1817, `emitter.py` 1657) | watch list |
| Untyped `list` IR fields | 0 | 5 (Phase-6 lists) | new debt |
| `_idx` copy count | ~2 (proxyarp) | 8 (proxyarp ×2, tc ×2, apply ×4) | new debt |
