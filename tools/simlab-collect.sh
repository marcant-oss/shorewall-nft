#!/usr/bin/env bash
# simlab-collect.sh — capture a firewall's live topology + netfilter
# snapshot for consumption by shorewall-nft-simlab's `--data DIR` path
# and for migration / audit diffs against the installed ruleset.
#
# Output layout (files that exist depend on privilege level + installed
# daemons). See tools/man/shorewall-nft-simlab-collect.1 for the full
# catalogue. manifest.txt reports per-capture status so operators can
# tell at a glance what ran and what was skipped.
#
# Two tiers:
#   Tier 1 — unprivileged rtnetlink reads + readable config files +
#            routing-daemon socket queries. Work under any uid on any
#            kernel with userns; no special setup.
#   Tier 2 — privileged netfilter dumps (iptables-save, nft list ruleset,
#            ipset save, ...).  Require CAP_NET_ADMIN; when run as a
#            non-root user they are skipped with a manifest note.
#
# Usage:
#   tools/simlab-collect.sh [--output DIR] [--host NAME] [-h|--help]
#
# Examples:
#   ./tools/simlab-collect.sh                       # unprivileged; Tier 1 only
#   sudo ./tools/simlab-collect.sh                  # Tier 1 + Tier 2
#   ip netns exec fw1 ./tools/simlab-collect.sh     # inside a named netns

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: simlab-collect.sh [--output DIR] [--host NAME]

Captures live firewall state into a directory compatible with
shorewall-nft-simlab's --data flag.  Runs unprivileged; privileged
netfilter dumps are captured additionally when run as root / sudo.

Options:
  --output DIR   Directory to create and populate
                 (default: ./simlab-dump-<host>-<UTC>)
  --host NAME    Hostname label for the manifest
                 (default: hostname -s)
  -h, --help     Show this help and exit.

Outputs (Tier 1, always):
  ip4add ip4routes ip6add ip6routes         — simlab FwState input
  ip4rules ip6rules ip4routes-all           — policy routing
  rt_tables ip-link-details                 — context
  bird-routes.txt frr-routes.txt            — dynamic-routing RIB (best-effort)

Outputs (Tier 2, require root):
  iptables.txt ip6tables.txt          — simlab ruleset input;
                                        iptables-save(8) syntax
  ebtables.save arptables.save
  nft-ruleset.nft ipset.save
  conntrack.txt

Status of every capture is recorded in manifest.txt as
"LABEL: captured" / "LABEL: skipped-permission" /
"LABEL: skipped-binary-absent".
EOF
}

OUT=""
HOST="$(hostname -s 2>/dev/null || echo localhost)"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) OUT="$2"; shift 2 ;;
        --host)   HOST="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done
OUT="${OUT:-./simlab-dump-${HOST}-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"

MANIFEST="$OUT/manifest.txt"
: > "$MANIFEST"

# _try LABEL OUTFILE CMD [ARG ...]
# Runs CMD with its stdout captured to OUTFILE.  Records the outcome
# in the manifest; never aborts the script on a single capture failure.
_try() {
    local label="$1" outfile="$2"
    shift 2
    if ! command -v "$1" >/dev/null 2>&1; then
        printf '%s: skipped-binary-absent\n' "$label" >> "$MANIFEST"
        return 0
    fi
    local errfile="${outfile}.err"
    if "$@" > "$outfile" 2>"$errfile"; then
        rm -f "$errfile"
        printf '%s: captured\n' "$label" >> "$MANIFEST"
    else
        local rc=$?
        printf '%s: skipped-permission (rc=%d)\n' "$label" "$rc" >> "$MANIFEST"
        rm -f "$outfile"
        [[ -s "$errfile" ]] && mv "$errfile" "${outfile}.stderr" || rm -f "$errfile"
    fi
}

# ── Tier 1 — unprivileged rtnetlink reads ────────────────────────────
_try ip4add         "$OUT/ip4add"           ip -4 addr show
_try ip4routes      "$OUT/ip4routes"        ip -4 route show
_try ip6add         "$OUT/ip6add"           ip -6 addr show
_try ip6routes      "$OUT/ip6routes"        ip -6 route show table all
_try ip4rules       "$OUT/ip4rules"         ip -4 rule show
_try ip6rules       "$OUT/ip6rules"         ip -6 rule show
_try ip4routes-all  "$OUT/ip4routes-all"    ip -4 route show table all
_try link-details   "$OUT/ip-link-details"  ip -details link show

if [[ -r /etc/iproute2/rt_tables ]]; then
    cp /etc/iproute2/rt_tables "$OUT/rt_tables"
    printf 'rt_tables: captured\n' >> "$MANIFEST"
else
    printf 'rt_tables: skipped-file-absent\n' >> "$MANIFEST"
fi

# ── Tier 1 — dynamic-routing daemon views (best-effort) ─────────────
_try bird-routes    "$OUT/bird-routes.txt"  birdc show route
_try frr-routes     "$OUT/frr-routes.txt"   vtysh -c 'show ip route' -c 'show ipv6 route'

# ── Tier 2 — privileged netfilter dumps ─────────────────────────────
# iptables.txt / ip6tables.txt match simlab's expected --data layout
# (smoketest.py reads <data>/iptables.txt and <data>/ip6tables.txt).
_try iptables.txt   "$OUT/iptables.txt"     iptables-save
_try ip6tables.txt  "$OUT/ip6tables.txt"    ip6tables-save
_try ebtables.save  "$OUT/ebtables.save"    ebtables-save
_try arptables.save "$OUT/arptables.save"   arptables-save
_try nft-ruleset    "$OUT/nft-ruleset.nft"  nft list ruleset
_try ipset.save     "$OUT/ipset.save"       ipset save
_try conntrack      "$OUT/conntrack.txt"    conntrack -L

# ── Metadata epilogue ────────────────────────────────────────────────
{
    printf '\n--- metadata ---\n'
    printf 'host: %s\n' "$HOST"
    printf 'captured: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'kernel: %s\n' "$(uname -srm)"
    printf 'euid: %s\n' "$EUID"
    printf 'collector: shorewall-nft tools/simlab-collect.sh v1\n'
} >> "$MANIFEST"

echo "Wrote $OUT" >&2
echo "Summary:" >&2
grep -E '^[a-z0-9_.-]+:' "$MANIFEST" | sort >&2
