# TODO — Simlab alignment with `(config_dir, iptables_dump)` model

**Status**: pending investigation (Task #38)
**Owner**: unassigned
**Priority**: low — not on the critical path; pure refactor opportunity.

## Context

Two packet-level validators currently coexist:

- `packages/shorewall-nft/shorewall_nft/verify/simulate.py` — veth +
  subprocess + config-compile model. Internal-only; consumed by
  `runtime/cli/debug_cmds.py` (`shorewall-nft simulate`).
- `packages/shorewall-nft-simlab/` — TUN/TAP + asyncio + live-dump
  replay model. Modern, but has no `(config_dir, iptables_dump)`
  entry point that the CLI could call.

Without alignment, `simulate.py` stays a permanent internal tool and
the simlab package can't replace it.

## Goal

Investigate the feasibility of adding a simlab entry point that
consumes `(config_dir, iptables_dump)` directly so:
- `runtime/cli/debug_cmds.py` can forward to simlab.
- `simulate.py` can be deleted.

## Output

A written analysis at `docs/testing/simlab-alignment-analysis.md`
that lands one of:

1. **Concrete migration plan** + new simlab API surface (function
   signatures, required refactors, test coverage gaps), with effort
   estimate and risk list.
2. **Formal decision that `simulate.py` is permanent**, with reasons
   (incompatible execution model, test-coverage cost, etc.) and a
   one-paragraph rationale that closes the question for future work.

## Files to consult (read-only)

- `packages/shorewall-nft/shorewall_nft/verify/simulate.py` — current
  veth-based validator.
- `packages/shorewall-nft-simlab/` — entire package (especially the
  asyncio replay loop and TUN/TAP setup).
- `packages/shorewall-nft/shorewall_nft/runtime/cli/debug_cmds.py` —
  current call site for `simulate.py`.

## Constraints

- **Doc only** — no code changes in this WP.
- **Do not start implementation** — the migration itself is a
  follow-up task that this analysis files.

## Done when

- The analysis doc lands at `docs/testing/simlab-alignment-analysis.md`.
- Any follow-up implementation tasks are filed via TaskCreate.
- Task #38 is marked completed.

## Out of scope

- Any change to runtime CLI behaviour for end users.
- Performance comparison between the two models (separate concern).

## See also

- `packages/shorewall-nft/CLAUDE.md` — describes the long-term
  intent for `verify/simulate.py` (internal-only; consider simlab
  for new validation work).
