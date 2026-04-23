#!/usr/bin/env bash
# shorewall-compile.sh — compile a Shorewall config to iptables-save +
# nft text without root, without loading rules into the kernel.
#
# Workflow:
#   1. Bootstrap classic Shorewall (Perl) into a cache dir from upstream
#      gitlab.com/shorewall/code.git (configurable via --ref).
#   2. Compile each requested family inside an unprivileged user namespace
#      so the compiler sees uid 0 and can probe iptables capabilities
#      against locally-installed iptables binaries.
#   3. Pipe the result through iptables-restore-translate /
#      ip6tables-restore-translate to produce equivalent nft scripts.
#
# Output (in --output dir, defaults to $PWD):
#   iptables.txt    iptables-save format from shorewall  (if --shorewall)
#   ip6tables.txt   ip6tables-save format                 (if --shorewall6)
#   iptables.nft    nft equivalent via translate          (if not --no-translate)
#   ip6tables.nft   nft equivalent for v6                 (if not --no-translate)
#
# Known limitations (v1):
#   * Bootstrap stages the upstream source tree as symlinks rather than
#     running install.sh. This is enough for most configs, but two
#     things differ from a real install:
#       - Drop/Reject default-policy actions (DROP_DEFAULT=Drop /
#         REJECT_DEFAULT=Reject) are deprecated upstream and not
#         shipped as separate action files. Configs that need them
#         must either set DROP_DEFAULT=none / REJECT_DEFAULT=none in
#         shorewall.conf, or compile against a system shorewall
#         install instead. The script writes minimal stubs for both
#         but the compiler also needs them registered in actions.std,
#         which we do not auto-patch.
#       - Some less-common actions installed by install.sh from
#         deprecated/ may also be missing.
#   * shorewall6 configs that set BROADCAST=detect on an interface
#     fail compile (IPv6 has no broadcast). This is a config bug, not
#     a script issue.
#
# Usage:
#   shorewall-compile.sh [--shorewall PATH] [--shorewall6 PATH]
#                        [--output DIR] [--cache DIR] [--ref TAG]
#                        [--src DIR] [--no-translate] [-h|--help]
#
# At least one of --shorewall or --shorewall6 is required. Use --src
# to point at an existing Shorewall checkout (skips git clone) — handy
# for local development.
#
# GitLab CI snippet:
#   shorewall-compile:
#     image: debian:trixie-slim
#     before_script:
#       - apt-get update -qq
#       - apt-get install -y --no-install-recommends \
#           git perl iptables ca-certificates util-linux
#     cache:
#       key: shorewall-src-v1
#       paths: [.cache/shorewall-compile/]
#     script:
#       - tools/shorewall-compile.sh
#           --shorewall  fixtures/cfg/shorewall
#           --shorewall6 fixtures/cfg/shorewall6
#           --output     out
#           --cache      .cache/shorewall-compile
#     artifacts:
#       paths: [out/]
#       expire_in: 30 days

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Defaults + arg parsing
# ─────────────────────────────────────────────────────────────────────

SHOREWALL_DIR=""
SHOREWALL6_DIR=""
OUTPUT_DIR="$PWD"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/shorewall-compile"
REF=""              # empty = latest tag
SRC_OVERRIDE=""     # if set, skip git clone and use this dir
NO_TRANSLATE=0
UPSTREAM_URL="https://gitlab.com/shorewall/code.git"

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --shorewall)   SHOREWALL_DIR="$2";   shift 2 ;;
        --shorewall6)  SHOREWALL6_DIR="$2";  shift 2 ;;
        --output)      OUTPUT_DIR="$2";      shift 2 ;;
        --cache)       CACHE_DIR="$2";       shift 2 ;;
        --ref)         REF="$2";             shift 2 ;;
        --src)         SRC_OVERRIDE="$2";    shift 2 ;;
        --no-translate) NO_TRANSLATE=1;      shift   ;;
        -h|--help)     usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

if [[ -z "$SHOREWALL_DIR" && -z "$SHOREWALL6_DIR" ]]; then
    echo "error: must provide --shorewall and/or --shorewall6" >&2
    usage 2
fi

if [[ -n "$SHOREWALL_DIR"  && ! -d "$SHOREWALL_DIR"  ]]; then
    echo "error: --shorewall path is not a directory: $SHOREWALL_DIR" >&2
    exit 2
fi
if [[ -n "$SHOREWALL6_DIR" && ! -d "$SHOREWALL6_DIR" ]]; then
    echo "error: --shorewall6 path is not a directory: $SHOREWALL6_DIR" >&2
    exit 2
fi

mkdir -p "$OUTPUT_DIR" "$CACHE_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
CACHE_DIR="$(cd "$CACHE_DIR" && pwd)"

# ─────────────────────────────────────────────────────────────────────
# Stage 0 — host-state warning banner (always)
# ─────────────────────────────────────────────────────────────────────

emit_banner() {
    local color_on="" color_off=""
    if [[ -t 2 ]]; then
        color_on=$'\e[1;33m'   # bold yellow
        color_off=$'\e[0m'
    fi
    cat >&2 <<EOF
${color_on}================================================================
  WARNING — output may differ from the live firewall

  Shorewall reads live host state at compile time. When this
  script runs anywhere other than on the actual firewall host,
  the following features silently produce different output:

    * routeback        — reads 'ip route' to learn return paths
    * BROADCAST=detect / GATEWAY=detect — read 'ip addr' / 'ip route'
    * &iface / %iface  — substitutes runtime IP at compile time
    * DETECT_DNAT_IPADDRS=Yes — replaces detect-syntax with live IPs
    * proxyarp HAVEROUTE handling — verifies routes
    * providers (multi-ISP) — probes physical interfaces
    * dhcp-discovered addresses

  If your config uses any of the above, treat the generated
  iptables/ip6tables/nft files as a structural reference only,
  not as a byte-exact match against the live firewall ruleset.
================================================================${color_off}
EOF
}

emit_banner

# ─────────────────────────────────────────────────────────────────────
# Stage 1 — bootstrap shorewall source (cacheable)
# ─────────────────────────────────────────────────────────────────────

if [[ -n "$SRC_OVERRIDE" ]]; then
    SRCDIR="$(cd "$SRC_OVERRIDE" && pwd)"
    echo "==> using --src override: $SRCDIR" >&2
else
    SRCDIR="$CACHE_DIR/shorewall-src"

    # Single-flight under flock so concurrent invocations don't race.
    exec 9>"$CACHE_DIR/.bootstrap.lock"
    flock 9

    if [[ -z "$REF" ]]; then
        echo "==> resolving latest upstream tag..." >&2
        REF="$(git ls-remote --tags --sort=-v:refname "$UPSTREAM_URL" \
               | awk -F/ '/refs\/tags\/[0-9]/ {print $NF; exit}')"
        if [[ -z "$REF" ]]; then
            echo "error: could not resolve latest tag from $UPSTREAM_URL" >&2
            exit 1
        fi
        echo "==> latest tag: $REF" >&2
    fi

    if [[ -d "$SRCDIR/.git" ]]; then
        cur="$(git -C "$SRCDIR" describe --tags --exact-match 2>/dev/null || echo)"
        if [[ "$cur" == "$REF" ]]; then
            echo "==> cache hit: $SRCDIR @ $REF" >&2
        else
            echo "==> updating cached clone to $REF" >&2
            git -C "$SRCDIR" fetch --depth 1 origin "refs/tags/$REF:refs/tags/$REF" --quiet
            git -C "$SRCDIR" -c advice.detachedHead=false checkout --quiet "$REF"
        fi
    else
        echo "==> cloning shorewall @ $REF into $SRCDIR" >&2
        git clone --depth 1 --branch "$REF" "$UPSTREAM_URL" "$SRCDIR" --quiet
    fi

    exec 9>&-
fi

# ─────────────────────────────────────────────────────────────────────
# Stage 2 — compile (parallel v4 + v6) inside user namespace
# ─────────────────────────────────────────────────────────────────────

SRC_PERL="$SRCDIR/Shorewall/Perl"
SRC_COMPILER="$SRC_PERL/compiler.pl"

if [[ ! -f "$SRC_COMPILER" ]]; then
    echo "error: compiler.pl not found at $SRC_COMPILER" >&2
    echo "       The shorewall source layout may have changed at $REF." >&2
    exit 1
fi

WORKDIR="$(mktemp -d -t shorewall-compile.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# The compiler shells out to getparams via "$FindBin::Bin/getparams"
# (Config.pm:5871). $FindBin::Bin is the dir of compiler.pl, so we
# need a writable Perl/ tree where getparams is patched to source the
# right shorewallrc. Mirror the source Perl/ tree as symlinks plus a
# patched getparams.
PERLLIB="$WORKDIR/perl"
COMPILER="$PERLLIB/compiler.pl"
mkdir -p "$PERLLIB/Shorewall"
for entry in "$SRC_PERL"/*; do
    name="$(basename "$entry")"
    if [[ "$name" == "getparams" ]]; then
        continue   # patched copy below
    fi
    ln -sfn "$entry" "$PERLLIB/$name"
done
for entry in "$SRC_PERL/Shorewall"/*; do
    ln -sfn "$entry" "$PERLLIB/Shorewall/$(basename "$entry")"
done

# Hardcoded VERSION inside Config.pm (the canonical compile-time
# version, separate from the git tag). Read it so coreversion +
# version files match and we don't trigger the "Version Mismatch"
# warning that aborts the params-load downstream.
ver="$(awk -F"'" '/VERSION +=> *.[0-9]/ {print $2; exit}' \
       "$SRC_PERL/Shorewall/Config.pm" 2>/dev/null)"
ver="${ver:-${REF:-source-tree}}"

# Compiler expects $SHAREDIR/shorewall/* and $SHAREDIR/shorewall6/*
# (lowercase, as installed by upstream). Source tree uses Shorewall/
# and Shorewall6/ (capitalised). Stage lowercase symlinks once.
mkdir -p "$WORKDIR/share" "$WORKDIR/etc/shorewall" \
         "$WORKDIR/etc/shorewall6" "$WORKDIR/var/shorewall" \
         "$WORKDIR/var/shorewall6"
ln -sfn "$SRCDIR/Shorewall"  "$WORKDIR/share/shorewall"
ln -sfn "$SRCDIR/Shorewall6" "$WORKDIR/share/shorewall6"

# Source tree only has $SRCDIR/Shorewall (read-only target of the
# symlink); to drop fabricated install-only files (coreversion,
# version, patched getparams, shorewallrc) alongside, replace the
# top-level symlink with a directory of per-file symlinks.
# Both Shorewall and Shorewall6 install dirs are populated from
# Shorewall-core/* (lib.cli, lib.common, etc.) PLUS their own
# per-product files (Shorewall/macro.*, Shorewall/configfiles/, etc.).
rm "$WORKDIR/share/shorewall" "$WORKDIR/share/shorewall6"
mkdir -p "$WORKDIR/share/shorewall" "$WORKDIR/share/shorewall6"
for entry in "$SRCDIR/Shorewall-core"/*; do
    name="$(basename "$entry")"
    [[ "$name" == install.sh || "$name" == uninstall.sh \
       || "$name" == configure* || "$name" == COPYING \
       || "$name" == INSTALL || "$name" == manpages \
       || "$name" == shorewallrc.* || "$name" == init.* ]] && continue
    ln -sfn "$entry" "$WORKDIR/share/shorewall/$name"
    ln -sfn "$entry" "$WORKDIR/share/shorewall6/$name"
done
for entry in "$SRCDIR/Shorewall"/*; do
    ln -sfn "$entry" "$WORKDIR/share/shorewall/$(basename "$entry")"
done
for entry in "$SRCDIR/Shorewall6"/*; do
    ln -sfn "$entry" "$WORKDIR/share/shorewall6/$(basename "$entry")"
done
# Actions/ and Macros/ subdirs are flattened into the install root
# by install.sh — replicate the same flattening with symlinks so the
# compiler finds action.* and macro.* files at $SHAREDIR/shorewall/.
for prod_src in "$SRCDIR/Shorewall" "$SRCDIR/Shorewall6"; do
    [[ "$prod_src" == */Shorewall ]] && dest=shorewall || dest=shorewall6
    for sub in Actions Macros; do
        [[ -d "$prod_src/$sub" ]] || continue
        for entry in "$prod_src/$sub"/*; do
            ln -sfn "$entry" "$WORKDIR/share/$dest/$(basename "$entry")"
        done
    done
done

# Install.sh writes coreversion + version files with the package
# version. Compiler refuses to start without coreversion and aborts
# the params load on coreversion ↔ Config.pm-VERSION mismatch.
printf '%s\n' "$ver" > "$WORKDIR/share/shorewall/coreversion"
printf '%s\n' "$ver" > "$WORKDIR/share/shorewall/version"
printf '%s\n' "$ver" > "$WORKDIR/share/shorewall6/coreversion"
printf '%s\n' "$ver" > "$WORKDIR/share/shorewall6/version"

# Patched getparams in $PERLLIB (where the compiler invokes it via
# $FindBin::Bin/getparams) — sources our local shorewallrc instead
# of the install-time /usr/share/shorewall/shorewallrc.
sed "s|/usr/share/shorewall/shorewallrc|$WORKDIR/shorewallrc|g" \
    "$SRC_PERL/getparams" \
    > "$PERLLIB/getparams"
chmod +x "$PERLLIB/getparams"

# Drop and Reject default-policy action files are not in the source
# tree (older Shorewall shipped action.Drop/action.Reject; current
# install.sh actively deletes them as deprecated). Many real configs
# still set DROP_DEFAULT=Drop / REJECT_DEFAULT=Reject. Drop in
# minimal stubs that perform the bare verdict so DEFAULT settings
# resolve cleanly.
for prod in shorewall shorewall6; do
    cat > "$WORKDIR/share/$prod/action.Drop" <<'EOF'
# Auto-generated by shorewall-compile.sh — minimal Drop action stub.
?format 1
DROP   -   -
EOF
    cat > "$WORKDIR/share/$prod/action.Reject" <<'EOF'
# Auto-generated by shorewall-compile.sh — minimal Reject action stub.
?format 1
REJECT   -   -
EOF
done

# Synthesise a shorewallrc that points the compiler at our staging area.
SHOREWALLRC="$WORKDIR/shorewallrc"
cat > "$SHOREWALLRC" <<EOF
PRODUCT=shorewall
HOST=generic
PREFIX=$WORKDIR
SHAREDIR=$WORKDIR/share
LIBEXECDIR=$WORKDIR/share
PERLLIBDIR=$PERLLIB
CONFDIR=$WORKDIR/etc
SBINDIR=$WORKDIR/sbin
MANDIR=$WORKDIR/share/man
VARLIB=$WORKDIR/var
VARDIR=$WORKDIR/var/shorewall
ANNOTATED=
SPARSE=Yes
DEFAULT_PAGER=
EOF

compile_family() {
    local family="$1" cfg="$2" out="$3" suffix
    suffix="${family/4/}"  # 4 → "", 6 → "6"

    local logfile="$WORKDIR/compile.${family}.log"
    local rawout="$WORKDIR/iptables${suffix}.raw"

    echo "==> compiling family=$family from $cfg" >&2

    # Run compiler under user-namespace fake-root so capability probing
    # against the local iptables binaries works without real root.
    # Inside the user-namespace we appear as root, but the host's
    # /run/xtables.lock is mode 600 owned by real root and iptables
    # can't open it. Work around by adding --net --mount to the
    # unshare so we get a fresh netns + private mount namespace,
    # then tmpfs-mount /run so iptables can drop its lock there.
    # The fresh netns is empty (no rules from the host), which is
    # exactly what we want for capability probing.
    if ! unshare --user --map-root-user --net --mount -- \
        sh -c '
            mount -t tmpfs tmpfs /run 2>/dev/null || true
            exec perl "$1" \
                --shorewallrc="$2" \
                --directory="$3" \
                --family="$4" \
                --preview \
                --log=/dev/null
        ' _ "$COMPILER" "$SHOREWALLRC" "$cfg" "$family" \
            > "$rawout" 2> "$logfile"; then
        echo "ERROR: shorewall compile failed for family=$family" >&2
        echo "--- compile log ($logfile) ---" >&2
        sed -n '1,80p' "$logfile" >&2
        return 1
    fi

    # --preview prints "Compiling..." progress lines as comments + the
    # iptables-restore input. We pass everything through; iptables-save
    # consumers ignore non-table comment lines anyway.
    cp "$rawout" "$out"
    echo "==> wrote $out ($(wc -l < "$out") lines)" >&2
}

declare -a JOBS=()

if [[ -n "$SHOREWALL_DIR" ]]; then
    SHOREWALL_DIR="$(cd "$SHOREWALL_DIR" && pwd)"
    compile_family 4 "$SHOREWALL_DIR" "$OUTPUT_DIR/iptables.txt" &
    JOBS+=($!)
fi
if [[ -n "$SHOREWALL6_DIR" ]]; then
    SHOREWALL6_DIR="$(cd "$SHOREWALL6_DIR" && pwd)"
    compile_family 6 "$SHOREWALL6_DIR" "$OUTPUT_DIR/ip6tables.txt" &
    JOBS+=($!)
fi

# Collect parallel compile results.
fail=0
for pid in "${JOBS[@]}"; do
    wait "$pid" || fail=1
done
if [[ $fail -ne 0 ]]; then
    echo "ERROR: at least one compile failed; aborting before translate" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────
# Stage 3 — translate iptables-save → nft
# ─────────────────────────────────────────────────────────────────────

translate_one() {
    local family="$1" txt="$2" nft="$3" tool="$4"
    if ! command -v "$tool" >/dev/null 2>&1 \
       && [[ ! -x "/usr/sbin/$tool" ]] \
       && [[ ! -x "/sbin/$tool" ]]; then
        echo "warn: $tool not installed; skipping nft translation for family=$family" >&2
        return 0
    fi
    local bin
    bin="$(command -v "$tool" 2>/dev/null \
           || { for p in /usr/sbin /sbin; do [[ -x "$p/$tool" ]] && echo "$p/$tool" && break; done; })"
    "$bin" -f "$txt" > "$nft"
    echo "==> wrote $nft ($(wc -l < "$nft") lines, via $bin)" >&2
}

if [[ $NO_TRANSLATE -eq 0 ]]; then
    if [[ -f "$OUTPUT_DIR/iptables.txt"  ]]; then
        translate_one 4 "$OUTPUT_DIR/iptables.txt"  "$OUTPUT_DIR/iptables.nft"  iptables-restore-translate
    fi
    if [[ -f "$OUTPUT_DIR/ip6tables.txt" ]]; then
        translate_one 6 "$OUTPUT_DIR/ip6tables.txt" "$OUTPUT_DIR/ip6tables.nft" ip6tables-restore-translate
    fi
fi

# ─────────────────────────────────────────────────────────────────────
# Stage 4 — sanity check
# ─────────────────────────────────────────────────────────────────────

sanity_check_iptables() {
    local f="$1"
    [[ -s "$f" ]] || { echo "error: $f is empty" >&2; return 1; }
    grep -q '^\*filter' "$f" || { echo "error: $f missing *filter table" >&2; return 1; }
    grep -q '^COMMIT'  "$f" || { echo "error: $f missing COMMIT marker" >&2; return 1; }
}

[[ -f "$OUTPUT_DIR/iptables.txt"  ]] && sanity_check_iptables "$OUTPUT_DIR/iptables.txt"
[[ -f "$OUTPUT_DIR/ip6tables.txt" ]] && sanity_check_iptables "$OUTPUT_DIR/ip6tables.txt"

echo "==> done. outputs in $OUTPUT_DIR" >&2
