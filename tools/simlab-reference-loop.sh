#!/usr/bin/env bash
# simlab-reference-loop.sh — drive iterative reference-replay against
# the disposable simlab host.  One iteration per call: stage the
# reference, run a (subset|replay) simlab pass, fetch the report,
# diff against the previous one.
#
# The driver is *idempotent* — call it from a CI loop or by hand.
# It does NOT loop on its own (run from cron / Make / a watchdog
# instead) so the operator stays in control of resource budgets.
#
# Inputs (env or flags):
#   SHOREWALL_SIMLAB_HOST   — required.  ssh target (root user assumed,
#                             keypair-based, no password prompt).  CLAUDE.md
#                             documents the bootstrap.
#   --reference DIR         — local reference snapshot (default:
#                             $REPO_ROOT/../shorewall-config/reference)
#   --out DIR               — local output dir (default:
#                             docs/testing/simlab-reports/loop)
#   --random N              — initial-iter random probe count (default 200)
#   --max-per-pair M        — initial-iter cap (default 30)
#   --seed S                — deterministic seed (default 42)
#   --iter N                — iteration number; 0 = full subset, ≥1 =
#                             replay failed probes from iter-(N-1)
#                             (default: auto-detect from --out dir)
#
# Outputs (per iteration):
#   <out>/iter-<N>/report.json            simlab summary report
#   <out>/iter-<N>/diff-vs-prev.txt       report-diff vs iter-(N-1)
#   <out>/iter-<N>/failed-probes.json     replay seed for iter-(N+1)
#
# Exit codes:
#   0  = run completed; *and* no regressions vs previous iter
#   1  = run completed; new regressions present (loop should investigate)
#   2  = setup error (missing reference, bad ssh, …) — stop the loop
#   3  = remote run failed (simlab non-zero exit) — stop the loop

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"

REFERENCE="${REFERENCE:-$WORKSPACE_ROOT/shorewall-config/reference}"
OUT="${OUT:-$REPO_ROOT/docs/testing/simlab-reports/loop}"
RANDOM_N=200
MAX_PER_PAIR=30
SEED=42
ITER=""
HOST="${SHOREWALL_SIMLAB_HOST:-}"

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reference)    REFERENCE="$2"; shift 2 ;;
        --out)          OUT="$2";       shift 2 ;;
        --random)       RANDOM_N="$2";  shift 2 ;;
        --max-per-pair) MAX_PER_PAIR="$2"; shift 2 ;;
        --seed)         SEED="$2";      shift 2 ;;
        --iter)         ITER="$2";      shift 2 ;;
        --host)         HOST="$2";      shift 2 ;;
        -h|--help)      usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

if [[ -z "$HOST" ]]; then
    echo "error: SHOREWALL_SIMLAB_HOST not set and --host not given" >&2
    exit 2
fi
if [[ ! -d "$REFERENCE" ]]; then
    echo "error: reference dir $REFERENCE not found" >&2
    exit 2
fi

mkdir -p "$OUT"

# ── Determine iteration number ────────────────────────────────────────
if [[ -z "$ITER" ]]; then
    last=-1
    for d in "$OUT"/iter-*; do
        [[ -d "$d" ]] || continue
        n="${d##*/iter-}"
        [[ "$n" =~ ^[0-9]+$ ]] || continue
        (( n > last )) && last="$n"
    done
    ITER=$((last + 1))
fi

ITER_DIR="$OUT/iter-$ITER"
PREV_ITER=$((ITER - 1))
PREV_DIR="$OUT/iter-$PREV_ITER"
mkdir -p "$ITER_DIR"

echo "=== simlab-reference-loop iter $ITER ==="
echo "  host:      $HOST"
echo "  reference: $REFERENCE"
echo "  out:       $ITER_DIR"

# ── Stage reference + sync repos to remote ────────────────────────────
echo "[loop] rsync repos to $HOST:/root/"
rsync -aq --delete --exclude '__pycache__' --exclude '.git' \
    --exclude '.venv' --exclude '*.egg-info' \
    "$WORKSPACE_ROOT/shorewall-nft/" \
    "root@$HOST:/root/shorewall-nft/"
rsync -aq --delete --exclude '__pycache__' --exclude '.git' \
    --exclude '.venv' --exclude '*.egg-info' \
    "$WORKSPACE_ROOT/shorewall-nft-simlab/" \
    "root@$HOST:/root/shorewall-nft-simlab/"
rsync -aq --delete --exclude '__pycache__' --exclude '.git' \
    --exclude '.venv' --exclude '*.egg-info' \
    "$WORKSPACE_ROOT/shorewall-nft-netkit/" \
    "root@$HOST:/root/shorewall-nft-netkit/" 2>/dev/null || true
rsync -aq --delete \
    "$REFERENCE/" \
    "root@$HOST:/root/reference/"

# ── Stage the merged config + dumps on the remote (one-shot) ─────────
echo "[loop] stage reference (merge config + collect dumps)"
ssh -n "root@$HOST" \
    "/root/shorewall-nft/tools/reference-stage.sh \
        --reference /root/reference \
        --out /root/ref-stage \
        --shorewall-nft /root/shorewall-nft/.venv/bin/shorewall-nft" \
    >> "$ITER_DIR/stage.log" 2>&1 || {
        echo "ERROR: reference-stage failed (see $ITER_DIR/stage.log)" >&2
        exit 3
    }

# ── Build smoketest invocation ────────────────────────────────────────
COMMON_FLAGS="--data /root/ref-stage/data \
              --config /root/ref-stage/etc/shorewall46 \
              --report-dir /root/simlab-reports"
RUN_FLAGS="full --random $RANDOM_N --max-per-pair $MAX_PER_PAIR \
                --seed $SEED --summary-only --probe-timeout 1.0 --trace on"

REPLAY_PATH=""
if (( ITER >= 1 )) && [[ -f "$PREV_DIR/failed-probes.json" ]]; then
    # Empty failed-probes.json → previous iter was clean.  Re-run as
    # a fresh full sweep (not replay) so the stop-condition's "2
    # consecutive zero-failure iters" check exercises the full
    # probe surface twice, not just the empty replay set.
    if grep -q '"probe_ids": \[\]' "$PREV_DIR/failed-probes.json"; then
        echo "[loop] previous iter had no failures — running fresh full sweep"
    else
        REPLAY_PATH="/root/replay-iter-$ITER.json"
        rsync -aq "$PREV_DIR/failed-probes.json" "root@$HOST:$REPLAY_PATH"
        RUN_FLAGS="$RUN_FLAGS --replay $REPLAY_PATH"
    fi
fi

UNIT="simlab-iter-$ITER-$$"
echo "[loop] simlab run on $HOST (unit=$UNIT)"
ssh -n "root@$HOST" \
    "systemd-run --unit=$UNIT --collect --wait \
        --working-directory=/root/shorewall-nft \
        --property=StandardOutput=file:/tmp/$UNIT.log \
        --property=StandardError=file:/tmp/$UNIT.log \
        /root/shorewall-nft/.venv/bin/python \
        -m shorewall_nft_simlab.smoketest \
        $COMMON_FLAGS $RUN_FLAGS" \
    > "$ITER_DIR/run.log" 2>&1 \
    || {
        echo "ERROR: simlab run failed (see $ITER_DIR/run.log + remote /tmp/$UNIT.log)" >&2
        ssh -n "root@$HOST" "cat /tmp/$UNIT.log" >> "$ITER_DIR/run.log" 2>/dev/null || true
        exit 3
    }

# ── Fetch report.json (tiny under --summary-only) ─────────────────────
LATEST_REPORT="$(
    ssh -n "root@$HOST" \
        "ls -1dt /root/simlab-reports/* 2>/dev/null | head -n1"
)"
if [[ -z "$LATEST_REPORT" ]]; then
    echo "ERROR: no report directory found on remote" >&2
    exit 3
fi
rsync -aq "root@$HOST:$LATEST_REPORT/report.json" "$ITER_DIR/report.json"

# Stash the report-md too if it's small (under summary-only it stays
# proportional to the failure count).
rsync -aq "root@$HOST:$LATEST_REPORT/report.md" "$ITER_DIR/report.md" 2>/dev/null || true

# ── Build the replay seed for iter+1 ─────────────────────────────────
echo "[loop] derive failed-probes for next iter"
"$SCRIPT_DIR/simlab-rerun-failed.py" \
    "$ITER_DIR/report.json" \
    --out "$ITER_DIR/failed-probes.json" \
    > "$ITER_DIR/rerun-summary.log" 2>&1 || {
        echo "WARN: rerun-failed.py failed; iter+1 will fall back to full subset" >&2
}

# ── Diff vs previous iter ────────────────────────────────────────────
DIFF_RC=0
if [[ -f "$PREV_DIR/report.json" ]]; then
    "$SCRIPT_DIR/simlab-report-diff.py" \
        "$PREV_DIR/report.json" "$ITER_DIR/report.json" \
        > "$ITER_DIR/diff-vs-prev.txt" \
        || DIFF_RC=$?
    cat "$ITER_DIR/diff-vs-prev.txt"
else
    echo "(no previous iter to diff against)" \
        > "$ITER_DIR/diff-vs-prev.txt"
    DIFF_RC=0
fi

echo "[loop] iter $ITER done; diff exit=$DIFF_RC"
exit "$DIFF_RC"
