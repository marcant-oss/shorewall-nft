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

## simlab dmz→net NDP/ARP cold-start race (mitigation: ``--trace on``)

* Without ``--trace on``, fresh full runs of the loop produce
  ~17 fail_drops, dominated by ``dmz→net`` to public IPs (DNS /
  NTP probes to 217.14.x).  The compiled FILTER chain ACCEPTs
  the packet (``nft monitor trace`` with ``--trace`` confirms),
  but the simlab worker on bond1 doesn't see the egress packet
  in time → ``observed=DROP`` (timeout).
* With ``--trace on``, the same probes pass cleanly.  The kernel
  trace hook at priority -300 introduces a small per-packet
  delay that lets the simlab reader thread complete its
  ARP-responder + dispatch loop on the cold-start NDP/ARP
  exchange before the actual probe packet arrives.
* ``tools/simlab-reference-loop.sh`` therefore ships with
  ``--trace on`` in ``RUN_FLAGS``.  The trade-off: nft-trace
  output adds ~few hundred KB per iter to the run dir (still
  far smaller than the per-pcap detail ``--summary-only``
  drops).  Removing ``--trace`` re-introduces the cold-start
  fail_drops and is not recommended for loop runs.
* Tracked as an open simlab follow-up: rework the worker's
  cold-start ARP/NDP handling so it doesn't depend on the
  trace-induced delay.  Most likely fix is to install static
  neighbor entries for default-gateway IPs in ``topology.py``
  before the first probe batch fires.

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

## tun0 / point-to-point peer routes (open, 1 case)

- ``voice→vpn 192.168.192.254→10.8.1.42 udp:5060`` fails because
  simlab's NS_FW installs ``10.8.1.1/32`` on ``tun0`` but the
  kernel's auto-installed peer route (``10.8.1.2 dev tun0`` from
  the PtP semantics of ``inet X peer Y/PLEN``) is missing in the
  simulated namespace.  Result: routes ``10.8.1.0/24 via 10.8.1.2
  dev tun0`` fail to install (next-hop unreachable), the kernel
  falls through to the default route via ``bond1``, and the
  forward dispatcher matches ``voice-net`` instead of
  ``voice-vpn`` — ``voice-net`` chain has no rule for
  ``10.8.1.42:5060`` and rejects.
- The ``inet X peer Y/PLEN`` parsing already lands in
  ``state.interfaces['tun0'].addrs4`` (commit pending — extends
  ``_INET_RE``); the missing piece is ``topology.py`` installing
  the address with explicit ``peer=Y`` so the kernel synthesises
  the peer route as it would in production.
- Tracked as ``simlab/topology.py`` open follow-up; not blocking
  the loop.
