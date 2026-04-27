# reference-replay — known-issue ledger

Mismatches against `shorewall-config/reference/` (rossini snapshot,
2026-04-24) that the auto-loop should *not* page on. Each entry
explains why the divergence is intentional / out-of-scope, so the
loop's diff output can sticky-ignore it instead of looping forever.

The loop driver does *not* read this file directly today — operators
consult it when triaging diff output. Promote an entry to a
suppression filter when it shows up in three consecutive iterations.

## Anycast / loopback destinations outside the netns

- `2001:db8::2` and `2001:db8::53:2` are anycast / loopback addresses
  outside the simlab namespace. Without dummy routes they surface
  as `fail_drop` against rules that target them.
- Tracked in `shorewall-nft-simlab/CLAUDE.md` open item #2.
- Mitigation: add stub routes in `topology.py` once the loop runs
  green on everything else.

## DNAT coverage gap — per-rule path

- The `dnat_mismatch` bucket is populated from random-probe runs,
  not from per-rule probe enumeration. Some PREROUTING DNAT rules
  may go untested when the random walker doesn't happen to pick
  the rule's matching tuple.
- This means `dnat_mismatch == 0` is necessary but not sufficient
  to prove DNAT correctness.
- Mitigation: dedicated NAT-table probe walker (deferred — promote
  if a real DNAT compiler bug slips past the loop).

## ipset-membership rules

- Rules guarded by `-m set --match-set <name>` are skipped by the
  oracle (we don't load `ipset.save` at classify time).
- Probes that hit such rules go into `unknown_expected` — not
  counted as mismatches. Loop ignores them.

## conntrack-state rules

- Pure `--ctstate` rules (e.g. `ESTABLISHED,RELATED -j ACCEPT`) are
  skipped by the oracle. simlab probes are first-packet only.
- Same handling as ipset: `unknown_expected`.

## frr-routes.txt missing

- `tools/simlab-collect.sh` records `frr-routes: skipped-permission`
  on hosts where vtysh is configured but the collecting user lacks
  the FRR socket. The reference snapshot has this state.
- simlab does not consume `frr-routes.txt` today — no impact on
  the run, just a noisy manifest entry.

## v6 NAT empty in the reference

- The rossini snapshot has 0 IPv6 DNAT rules.
  `oracle.classify_dnat(family=6)` returns `None` and the random
  builder never sets `expected_rewrite_*` on v6 probes.
- v6 `dnat_mismatch == 0` is the *expected* steady state, not
  evidence of v6 coverage.

## net→<internal> ICMP echo-request fail_drops (open, ~15 cases)

- Probes from external (217.14.x non-FW) IPs to internal targets
  (192.168.x / 172.31.x) with `icmp type 8` are oracle-classified
  as `direct accept` (matches `-A net2X -p icmp --icmp-type 8 -j
  ACCEPT` in iptables.txt).  Compiled chain has an equivalent
  `meta nfproto ipv4 meta l4proto icmp icmp type 8 accept` rule.
  Yet the simlab FW drops them — `nft monitor trace` shows the
  chain returning `drop` after no rule matches.  Hypotheses:
  - simlab probe payload sets icmp type 8 but with a code or other
    field that the compiled rule's match doesn't cover identically
  - compiled rule guards on `meta nfproto ipv4` evaluating False
    for some reason (probe is IPv4 but the meta-detection edge
    case)
- Tracked separately; not blocking the loop.  Investigate by
  comparing nft trace probe-by-probe against the rule's match
  predicate.
