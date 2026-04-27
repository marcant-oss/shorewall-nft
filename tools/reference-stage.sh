#!/usr/bin/env bash
# reference-stage.sh — turn a simlab-collect snapshot of a *live*
# firewall (which has separate /etc/shorewall + /etc/shorewall6
# trees) into the unified layout simlab-smoketest expects:
#
#     <out>/etc/shorewall46/        ← merged config (merge-config)
#     <out>/data/                   ← captured dumps (iptables.txt,
#                                     ip4add, ip4routes, ip4rules,
#                                     ip6*, ip6tables.txt, ...)
#     <out>/manifest.txt            ← provenance + checksums
#
# The captured iptables.txt is *not* recompiled — it stays the
# source-of-truth for the oracle.  ``shorewall-nft compile`` is
# invoked separately (inside smoketest) on the merged config to
# build the nft ruleset that will be loaded into NS_FW.  Any
# divergence between the two surfaces as a real mismatch — that's
# how compiler bugs are caught.
#
# Usage:
#   reference-stage.sh --reference <dir> --out <dir> [--shorewall-nft <cmd>]
#
# The reference directory must look like the output of
# tools/simlab-collect.sh, *plus* an etc/ tree containing
# shorewall/ and shorewall6/ subtrees (i.e. the source config the
# captured iptables.txt was compiled from).

set -euo pipefail

REFERENCE=""
OUT=""
SHOREWALL_NFT="${SHOREWALL_NFT:-shorewall-nft}"

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reference)    REFERENCE="$2"; shift 2 ;;
        --out)          OUT="$2";       shift 2 ;;
        --shorewall-nft) SHOREWALL_NFT="$2"; shift 2 ;;
        -h|--help)      usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

[[ -n "$REFERENCE" ]] || { echo "error: --reference required" >&2; exit 2; }
[[ -n "$OUT" ]]       || { echo "error: --out required" >&2; exit 2; }
[[ -d "$REFERENCE" ]] || { echo "error: reference dir not found: $REFERENCE" >&2; exit 2; }

V4_CFG="$REFERENCE/etc/shorewall"
V6_CFG="$REFERENCE/etc/shorewall6"
[[ -d "$V4_CFG" ]] || { echo "error: missing $V4_CFG" >&2; exit 2; }
[[ -d "$V6_CFG" ]] || { echo "error: missing $V6_CFG (merge-config requires both families)" >&2; exit 2; }

# Resolve to absolute paths so output paths under $OUT don't depend on cwd.
REFERENCE="$(cd "$REFERENCE" && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

mkdir -p "$OUT/data" "$OUT/etc"

# ── 1. Merge config trees via shorewall-nft merge-config ──────────────
# merge-config emits the unified layout the simlab smoketest needs.
# Runs in --auto mode (no prompts) — we want a deterministic, scripted
# pipeline.  --no-plugins keeps the result purely structural so
# subsequent compiler passes operate on the same material the live
# firewall was built from.
echo "[stage] merge-config $V4_CFG + $V6_CFG → $OUT/etc/shorewall46"
"$SHOREWALL_NFT" merge-config \
    "$V4_CFG" "$V6_CFG" \
    -o "$OUT/etc/shorewall46" \
    --no-plugins

# ── 2. Copy captured netstate + ruleset dumps verbatim ────────────────
# Plural rule-file names per simlab-collect.sh v1; matched by
# shorewall_nft_simlab.dumps.load_fw_state.
DATA_FILES=(
    ip4add ip4routes ip4routes-all ip4rules
    ip6add ip6routes              ip6rules
    iptables.txt ip6tables.txt
    ip-link-details rt_tables
    ipset.save conntrack.txt
    bird-routes.txt
)
echo "[stage] copy data files → $OUT/data"
for f in "${DATA_FILES[@]}"; do
    if [[ -f "$REFERENCE/$f" ]]; then
        cp -p "$REFERENCE/$f" "$OUT/data/$f"
    fi
done

# manifest.txt from collect, if present, becomes the source-of-truth
# upstream half of our manifest.
[[ -f "$REFERENCE/manifest.txt" ]] && cp -p "$REFERENCE/manifest.txt" "$OUT/manifest.upstream.txt"

# ── 3. Emit local manifest with checksums for diff/audit traceability ─
{
    printf 'reference: %s\n' "$REFERENCE"
    printf 'staged:    %s\n' "$OUT"
    printf 'staged_at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'merge_cmd: %s merge-config\n' "$SHOREWALL_NFT"
    printf -- '--- data checksums ---\n'
    (cd "$OUT/data" && find . -maxdepth 1 -type f -print0 \
        | xargs -0 sha256sum 2>/dev/null | sort)
} > "$OUT/manifest.txt"

echo "[stage] done"
echo "  config: $OUT/etc/shorewall46"
echo "  data:   $OUT/data"
echo "  manifest: $OUT/manifest.txt"
