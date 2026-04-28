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

## Mangle table not validated (deferred)

simlab + the static checks in ``tools/`` cover ``*filter``,
``*nat``, and ``*raw`` (NOTRACK + CT helpers).  ``*mangle`` is
not validated today.  On the rossini and portalfw snapshots the
mangle table content is trivial:

* rossini: 1 rule (``-A FORWARD -j MARK --set-xmark 0x0/0xff``,
  the standard mark-reset).
* portalfw: 6 rules — same mark-reset plus 5 jump-to-tc-stub
  shells (``tcpre``/``tcin``/``tcfor``/``tcout``/``tcpost``)
  used as TC priority anchors.

Mangle validation is deferred until a snapshot exercises a
non-trivial use case (TPROXY, marker-driven policy routing,
MSS clamping).  The simlab oracle currently classifies probes
purely by FILTER + NAT + raw verdicts — a packet whose mark
diverges from the captured value would be missed.

## ``*security`` table

Unused on every captured snapshot.  Skipped by the oracle and
both static checks; revisit if a future snapshot lands rules
there.

## Worker post-egress stub-classification (4 fail_drop stragglers)

After the DNAT FILTER ACCEPT companion fix + saddr-aware DNAT
walker land, the rossini reference replay converges to 4 stable
``fail_drop`` cases.  All four follow the same pattern:

* Oracle classifies as ACCEPT (correctly).
* Compiler emits the correct rule.
* FILTER chain on the post-DNAT tuple does ACCEPT.
* But the simlab worker classifies the upstream stub's
  port-unreach / RST as ``observed=REJECT``.

Concrete cases on the snapshot:

| ID    | Path                                    | Why classified REJECT                            |
|-------|-----------------------------------------|--------------------------------------------------|
| 3     | ``net→int``  tcp:22 → 192.168.191.8     | No listener at post-DNAT dst; stub TCP-RST       |
| 96    | ``test→net`` udp:69 → 217.14.168.5      | UDP TFTP, post-DNAT dst public, no listener      |
| 10032 | ``cam→voice`` udp:33495 (Trcrt range)   | UDP traceroute probe, no listener at dst         |
| 10209 | ``inst→voice`` udp:33468 (Trcrt range)  | dito                                             |

Mitigation (deferred): the worker should treat post-egress
behaviour as out-of-scope once the rewritten frame has been
observed on the expected iface — what we're validating here is
the FW's emit, not the upstream listener's response.  Either:

* Worker classifies "egress observed + no return frame" as PASS
  for any probe whose dst falls outside the simlab netns'
  responder set, OR
* Per-rule walker skips probes whose rewrite target leaves the
  simlab netns, OR
* simlab grows a per-iface response-stub registry and the user
  configures which dst-IPs should auto-RST / auto-port-unreach
  vs. silently absorb.

None of these need to land for compiler-correctness validation;
the 4 stragglers are noise on the rossini snapshot.

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

## shorewall-nft DNAT FILTER ACCEPT companion missing (RESOLVED 2026-04-27)

Resolved in ``shorewall-nft/packages/shorewall-nft/shorewall_nft/
compiler/nat.py`` by ``_synthesize_dnat_filter_accept`` +
``_split_dnat_dest_for_filter`` (covered by ``test_nat.py::
TestDnatFilterCompanion``).

Symptom: classic Shorewall splits each ``DNAT`` rules-file row
into a NAT rewrite *and* a FILTER ``ACCEPT`` gating the post-DNAT
zone-pair chain by ``ct original daddr <ORIG_DEST>``.  Without
the companion the rewritten packet hits the chain's default
DROP/REJECT policy.  shorewall-nft was emitting only the NAT
rewrite — every DNAT'd IPv4 service to a private internal IP
was rejected post-PREROUTING.  The ~23 ``fail_drop`` probes seen
on the rossini snapshot's ``net→voice``, ``net→int``,
``net→linux``, ``net→mgmt``, ``net→srv`` clusters all stemmed
from this single missing emit.

Fix: ``extract_nat_rules`` now also synthesises an ``ACCEPT``
``ConfigLine`` for every ``DNAT`` row and feeds it through the
regular rules pipeline.  IPv6 covered too (DNAT-column ``[v6]``
syntax is rewritten to the rules-file ``<v6>`` form so
``_parse_zone_spec`` lands the rule in the IPv6 family slot).

Compiled output now contains the missing rules, e.g.:

    ip daddr 192.168.192.7 ct original daddr 203.0.113.85 \
        meta l4proto tcp tcp dport 80 accept
    ip6 daddr 2001:db8:cafe::5 ct original daddr 2001:db8:public::1 \
        meta l4proto tcp tcp dport 443 accept

The IPv6 ACCEPT rules that used to appear in the same chain
were *not* DNAT-derived — they came from regular ``ACCEPT``
rows in ``rules`` (Shorewall6's snapshot has 0 v6 DNAT rules).
The fix is a no-op for those.

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

## Static-check TODO (mangle / security / flowtable)

* **Mangle: missing chains**. shorewall-nft compiler currently
  emits mangle rules only to ``mangle-prerouting``, missing
  ``mangle-forward``, ``mangle-input``, ``mangle-output``,
  ``mangle-postrouting``. The portalfw snapshot has 6 mangle
  rules across all 5 base chains, all reading 0 in the IR.

* **Security: richer test coverage**. SECMARK rules need a
  snapshot with real usage beyond the newly-added
  ``complex/secmarks`` fixture (which is the first end-to-end
  coverage). Neither rossini nor portalfw snapshots have SECMARK
  rules today.

* **Flowtable / fastpath: end-to-end validated (RESOLVED 2026-04-28)**.
  Four pieces close the loop:
    - static check: ``simlab-raw-check.py --table flowtable``
      diffs the IR's emitted flowtable declaration against the
      snapshot's ``nft-ruleset.txt`` (collector still TODO in
      ``simlab-collect.sh``);
    - dynamic check: ``smoketest._flowtable_state`` reports the
      per-flowtable definition count, the libnftables ``flow``
      array length, AND the count of conntrack entries with
      ``IPS_OFFLOAD`` set — the latter is the *authoritative*
      signal;
    - warmup driver: ``smoketest --flowtable-warmup N`` tags the
      first N TCP positive probes; the controller follows the
      bidi SYN+ACK return with a 3rd-handshake ACK injection on
      inject_iface so conntrack reaches ESTABLISHED;
    - the inactive-warning gate now requires *both* counts to be
      zero — non-zero ct[OFFLOAD] alone is sufficient evidence.

  Key empirical finding: ``nft list flowtable inet shorewall ft``
  returns an empty ``flow`` array even when offload IS active.
  Verified against a real veth-router-veth setup
  (root@192.168.203.79, kernel 6.11): 64 KiB of bidirectional
  TCP between two endpoint netnses drove the kernel to flag the
  ct entry with ``[OFFLOAD]`` (visible in ``conntrack -L``)
  while ``nft list flowtable | jq '.. | .flow?'`` still showed
  ``null``.  The IPS_OFFLOAD bit on ``CTA_STATUS`` is the only
  Python-readable signal — exposed via the new
  ``shorewall_nft_netkit.validators.count_offloaded_ct`` helper.

  Re-run on rossini-patched (``FLOWTABLE=bond0,br1,bond1``, no
  offload flag, ``--flowtable-warmup 30``) reports
  ``inet/shorewall/ft (3 devs, 0 flows, 192 ct[OFFLOAD])`` —
  the simlab's TAP topology IS in fact populating the kernel's
  fastpath; the original "0 flows" reading was misleading
  output, not a missing offload.

  Open follow-ups (low priority):
    - ``simlab-collect.sh`` to capture ``nft-ruleset.txt`` so the
      static diff has snapshot ground-truth on the flowtable side
      instead of being IR-only;
    - investigate why the ct[OFFLOAD] count (192) exceeds the
      tagged warmup count (30) — the simlab's bidi mode alone
      seems to drive enough non-tagged TCP probes to offload on
      this kernel.

* **CT-helper: per-snapshot capabilities override**. The snapshot
  loader parses ``__*_HELPER=1`` defaults globally across all
  snapshots. A ``--capabilities`` flag pointing at an
  iptables-capabilities dump would let the diff filter
  known-loaded helpers without printing 12 spurious "extra in IR"
  rows on every rossini run.

