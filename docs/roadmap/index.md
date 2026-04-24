# Roadmap

**Audience**: developers
**Scope**: Planned features, architecture designs, and AI-agent HOWTO guides for future work.

---

## Files in this area

| File | Description |
|------|-------------|
| [hw-offload-eswitch.md](hw-offload-eswitch.md) | Architecture and plan for TC Flower / nft flowtable hardware offload |
| [post-1.0-nft-features.md](post-1.0-nft-features.md) | Post-1.0 nftables feature wishlist, ranked by impact |
| [nfsets-deferred.md](nfsets-deferred.md) | Deferred nfsets features + shorewalld audit backlog (W7b) |
| [HOWTO-CLAUDE-hw-offload-addition.md](HOWTO-CLAUDE-hw-offload-addition.md) | AI-agent entry point for the hardware-offload feature addition |
| [phase6-coverage-plan.md](phase6-coverage-plan.md) | Phase 6 work-package plan: close upstream-Shorewall config-coverage gaps (Sonnet-agent runbook) |
| [simlab-alignment-todo.md](simlab-alignment-todo.md) | Standalone TODO (Task #38) — investigate aligning simlab with `simulate.py` so the latter can be retired |
| [pyroute2-audit-2026-04-24.md](pyroute2-audit-2026-04-24.md) | Baseline audit of where the codebase still shells out to legacy iproute2/iptables tools instead of pyroute2 |
| [pyroute2-audit-2026-04-24-final.md](pyroute2-audit-2026-04-24-final.md) | Post-Phase-6 audit — verdict: PASS (zero new production shell-outs) |
| [shorewalld-log-dispatcher-todo.md](shorewalld-log-dispatcher-todo.md) | Standalone TODO — extend WP-E1 with LOGFORMAT/LOGRULENUMBERS + shorewalld as the per-netns nflog dispatcher (replaces ulogd2 plumbing) |
| [maintainability-audit-2026-04-24.md](maintainability-audit-2026-04-24.md) | Post-Phase-6 maintainability audit — 3 hot items, 5 warm, 2 cold; P8 leak points + suggested first step |
| [nfset-map-bindings-todo.md](nfset-map-bindings-todo.md) | TODO — extend nfsets with map (value=mark) + `nfset_bindings` file: ingress-mark / membership-gate / GRE tunnel-key egress+ingress. nft-only (no tc); dual-stack first-class |
| [rawnat-stateless-todo.md](rawnat-stateless-todo.md) | TODO — true stateless bidirectional rawnat via `ip[6] (s\|d)addr set` + `notrack`. STATIC supports single IP / CIDR prefix / range; nft-only; dual-stack; rootless integration via `unshare` |
| [simlab-dual-stack-merge.md](simlab-dual-stack-merge.md) | TODO (4 phases) — dual-stack v4/v6 production parity on both simulate.py + simlab, shared-infra merge into netkit, simlab feature parity (INPUT / REJECT), + new NAT + deep conntrack verification. No deletion of simulate.py. |

## See also

- [docs/shorewall-nft/optimizer.md](../shorewall-nft/optimizer.md) — current optimizer passes
- [docs/shorewall-nft/flowtable.md](../shorewall-nft/flowtable.md) — flowtable / software offload
- [docs/index.md](../index.md) — documentation root
