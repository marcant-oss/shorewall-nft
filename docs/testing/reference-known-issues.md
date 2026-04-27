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

## net→<internal> ICMP echo-request fail_drops (RESOLVED 2026-04-27)

Resolved by ``oracle.py``'s ``--ctorigdst`` evaluator (commit
``eb31d51``).  The fail_drops were oracle false-positives:
classic ``-A net2X -m conntrack --ctorigdst 192.168.0.0/16
-g ~log75`` rules drop RFC1918 anti-spoof traffic; the oracle
previously skipped these and over-predicted ACCEPT.  Now treats
``--ctorigdst <CIDR>`` as a dst constraint and sees the drop.
14 fail_drops eliminated (iter 5 → iter 6).

## shorewall-nft IPv4 ctorigdst FILTER rules missing (open, ~23 cases)

The DNAT per-rule enumerator in shorewall-nft-simlab (commit
``f221efe``) surfaced this: classic Shorewall emits
``-A net2voice -d 192.168.192.7 -p tcp -m conntrack --ctorigdst
203.0.113.85 -m tcp --dport 80 -j ACCEPT`` (and similar) into
the FILTER chain to gate access to a DNAT'd internal IP by the
*pre*-DNAT public address.  shorewall-nft's compiled nft chain
is missing the corresponding IPv4 rule:

    ip daddr 192.168.192.7 ct original daddr 203.0.113.85 \
        meta l4proto tcp tcp dport 80 accept

The IPv6 counterparts of these rules ARE emitted in the same
chain; only the IPv4 forms are dropped.  Result: every DNAT'd
IPv4 service to a private internal IP is rejected by the FILTER
chain after PREROUTING does the rewrite.

Likely fix surface: ``shorewall-nft/packages/shorewall-nft/
shorewall_nft/compiler/ir/rules.py`` — the ``-m conntrack
--ctorigdst`` predicate handling probably has the same
case-sensitivity / family-detection issue as the earlier
``$SIP_V6`` / chain-complete fix-set: pre-expand ``$VAR`` in
ctorigdst args before the family heuristic runs, or treat the
ctorigdst presence itself as a family-agnostic match marker.

Tracked separately; loop's ``dnat_mismatch`` bucket is still 0
(the DNAT rewrite itself is correct) — this manifests as
``fail_drop`` on the per-rule DNAT probes.

## simlab cold-start NDP/ARP race (largely RESOLVED 2026-04-28)

Resolved by two complementary mechanisms in
shorewall-nft-simlab (commit ``003b2aa``):

* ``topology.py``: sets ``net.ipv4.conf.{all,default}.arp_accept=1``
  in NS_FW so the kernel CREATES neighbour entries from
  received gratuitous ARP replies (default ``0`` only updates
  existing entries).  IPv6 NDP with the Override flag is
  accepted by default and creates entries unconditionally.
* ``controller.SimController.announce_neighbours()`` replaces
  the probe-based ``_ndp_warmup`` with protocol-correct GARP
  (IPv4) + unsolicited Neighbor Advertisement (IPv6) frames
  written into each iface's TAP fd before the first probe
  batch.  The frame's source MAC is ``_WORKER_MAC`` (the same
  fake MAC the simulator's ARP/NDP responder hands out) so
  the kernel doesn't see the announcement as coming "from its
  own address" and discard it as a martian.

Effect on the rossini snapshot:

* Before any warmup:                  17 fail_drops (fresh full).
* With ``--trace on`` only:           2 fail_drops.
* With GARP/NA warmup + ``--trace``:  1 transient flake.

``tools/simlab-reference-loop.sh`` keeps ``--trace on`` in
``RUN_FLAGS`` as belt-and-braces — empirically catches the
last few cases the announcement warmup doesn't preempt.  The
combination converges the loop to ≤1 flaky probe per fresh
sweep; that flake is non-deterministic (different probe each
run) and represents simulator noise rather than a compiler
bug.

## tun0 / point-to-point peer routes (RESOLVED 2026-04-27)

* ``voice→vpn`` cluster resolved by:
  - ``shorewall-nft-simlab`` ``3cc32c9`` — ``inet X peer Y/PLEN``
    parser support.
  - ``shorewall-nft-simlab`` ``3283b7b`` — topology installs
    PtP addresses with the ``peer=Y`` kwarg so the kernel
    synthesises the link route.
* ``Address`` carries a new ``peer`` field; pyroute2's
  ``addr("add", ...)`` is called with ``local=X address=peer
  prefixlen=32`` for PtP forms.

