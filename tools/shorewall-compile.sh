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
# Bootstrap mechanics:
#   The cache uses upstream's own install.sh (per Shorewall component:
#   Shorewall-core, Shorewall, Shorewall6) with SHAREDIR / CONFDIR /
#   etc. pointed at the cache dir directly (no DESTDIR), so install.sh
#   runs its getparams sed-patcher and produces a fully-installed,
#   self-contained Shorewall tree. After install we patch:
#     - coreversion / version files (install.sh writes the literal
#       "xxx" placeholder; we write the real version from Config.pm)
#     - actions.std + action.Drop + action.Reject stubs (Drop/Reject
#       default-policy actions are upstream-deprecated; many real
#       configs still set DROP_DEFAULT=Drop / REJECT_DEFAULT=Reject)
#
# Known limitations:
#   * Configs that use shorewall-nft-specific syntax extensions
#     (CT:helper:NAME, ?FAMILY directive, nfsets:NAME tokens) won't
#     compile under classic Shorewall — they are extensions on the
#     Python compiler side, not part of upstream. This script targets
#     classic-Shorewall-compatible configs only.
#   * shorewall6 configs that set BROADCAST=detect fail compile
#     (IPv6 has no broadcast — config bug, not a script issue).
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

# Run upstream install.sh from each Shorewall component with
# DESTDIR pointing at our cache, so we get a complete, properly-
# patched install (action files, getparams, version files,
# Drop/Reject defaults, etc.) without root.
#
# The install is cached per (REF, install-rc) pair; subsequent runs
# reuse it. -n skips the configure step (systemctl-enable etc.); we
# strip OWNERSHIP from the rc so install.sh does not chown.
STAGING_KEY="${REF:-localsrc}"
STAGING="$CACHE_DIR/staging-$STAGING_KEY"

mkdir -p "$WORKDIR/etc/shorewall" "$WORKDIR/etc/shorewall6"

if [[ ! -f "$STAGING/.installed" ]]; then
    echo "==> staging shorewall via install.sh into $STAGING" >&2
    rm -rf "$STAGING"
    mkdir -p "$STAGING"

    INSTALL_RC="$WORKDIR/install-shorewallrc"
    # NOTE: do not set PRODUCT here — install.sh detects per-component
    # (Shorewall vs Shorewall6) via shorewall.service presence in cwd.
    #
    # SHAREDIR / CONFDIR etc. point at the staging dir directly (no
    # DESTDIR prefix) so install.sh's getparams sed-patcher (which
    # only fires when SHAREDIR != /usr/share) runs against our path.
    # That patches the installed getparams to source our shorewallrc
    # at $STAGING/usr/share/shorewall/shorewallrc.
    cat > "$INSTALL_RC" <<EOF
HOST=linux
PREFIX=$STAGING
SHAREDIR=$STAGING/usr/share
LIBEXECDIR=$STAGING/usr/share
PERLLIBDIR=$STAGING/usr/share/shorewall
CONFDIR=$STAGING/etc
SBINDIR=$STAGING/usr/sbin
MANDIR=$STAGING/usr/share/man
INITDIR=
INITFILE=
INITSOURCE=
ANNOTATED=
SYSCONFFILE=
SERVICEFILE=
SYSCONFDIR=$STAGING/etc/default
SERVICEDIR=
SPARSE=Yes
VARLIB=$STAGING/var/lib
VARDIR=$STAGING/var/lib/shorewall
DEFAULT_PAGER=
OWNER=
GROUP=
OWNERSHIP=
EOF

    # Shorewall6 shares the install.sh from Shorewall (auto-detects
    # PRODUCT via shorewall.service presence). Source tree only ships
    # one copy. Stage a symlink so we can ``cd Shorewall6 && ./install.sh``.
    if [[ -d "$SRCDIR/Shorewall6" && ! -f "$SRCDIR/Shorewall6/install.sh" ]]; then
        ln -sfn "$SRCDIR/Shorewall/install.sh" "$SRCDIR/Shorewall6/install.sh"
    fi
    # Shorewall and Shorewall6 install.sh source ./lib.installer
    # which only ships in Shorewall-core. Stage symlinks so each
    # per-product install.sh can find it. Same for shorewallrc.*
    # template files (referenced for HOST detection).
    for product_dir in "$SRCDIR/Shorewall" "$SRCDIR/Shorewall6"; do
        [[ -d "$product_dir" ]] || continue
        ln -sfn "$SRCDIR/Shorewall-core/lib.installer" \
                "$product_dir/lib.installer"

        # install.sh references *.annotated config files which the
        # upstream Build script generates but the source tree omits.
        # Stub them as symlinks to their non-annotated source so the
        # install completes; we never use the annotated copies.
        if [[ -d "$product_dir/configfiles" ]]; then
            for cfg in "$product_dir/configfiles"/*; do
                base="$(basename "$cfg")"
                [[ "$base" == *.annotated ]] && continue
                ann="$product_dir/configfiles/$base.annotated"
                [[ -e "$ann" ]] || ln -sfn "$base" "$ann"
            done
        fi
    done

    # No DESTDIR: rc points SHAREDIR etc. at the staging dir directly.
    # Shorewall-core install.sh accepts only -h/-v; the per-product
    # ones accept -n / -s / -p too. Pass the configure-skip / sparse
    # / non-annotated flags only where they are recognised.
    for component in Shorewall-core Shorewall Shorewall6; do
        [[ -d "$SRCDIR/$component" ]] || continue
        echo "==> install.sh: $component" >&2
        flags=()
        if [[ "$component" != "Shorewall-core" ]]; then
            flags=(-n -s -p)
        fi
        if ! ( cd "$SRCDIR/$component" && \
               OWNER= GROUP= \
               sh ./install.sh "${flags[@]}" "$INSTALL_RC" \
               > "$WORKDIR/install.$component.log" 2>&1 ); then
            echo "ERROR: install.sh failed for $component" >&2
            sed -n '1,40p' "$WORKDIR/install.$component.log" >&2
            exit 1
        fi
    done

    # install.sh writes coreversion = "xxx" (source-tree placeholder).
    # The compiler's hardcoded VERSION (Config.pm) is the real one.
    # Pre-fix coreversion + version files so the compiler does not
    # abort with a mismatch warning during params load.
    real_ver="$(awk -F"'" '/VERSION +=> *.[0-9]/ {print $2; exit}' \
                "$SRCDIR/Shorewall/Perl/Shorewall/Config.pm" 2>/dev/null)"
    real_ver="${real_ver:-${REF:-source-tree}}"
    for prod in shorewall shorewall6; do
        for f in coreversion version; do
            [[ -f "$STAGING/usr/share/$prod/$f" ]] && \
                printf '%s\n' "$real_ver" > "$STAGING/usr/share/$prod/$f"
        done
    done

    # Older Shorewall shipped Drop / Reject default-policy action
    # files; upstream removed them as deprecated. Many real-world
    # configs still set DROP_DEFAULT=Drop / REJECT_DEFAULT=Reject.
    # Inject minimal stubs + register them in actions.std so configs
    # using the legacy default names compile cleanly. Users who want
    # the modern (no-default) behaviour can set DROP_DEFAULT=none
    # in shorewall.conf — the stubs are harmless either way.
    for prod in shorewall shorewall6; do
        share_d="$STAGING/usr/share/$prod"
        [[ -d "$share_d" ]] || continue
        cat > "$share_d/action.Drop" <<'EOF'
# Auto-generated by shorewall-compile.sh — minimal Drop policy action.
?format 1
DROP   -   -
EOF
        cat > "$share_d/action.Reject" <<'EOF'
# Auto-generated by shorewall-compile.sh — minimal Reject policy action.
?format 1
REJECT   -   -
EOF
        # Register both in actions.std so the compiler accepts them
        # as valid action names. The "noinline" attribute matches
        # how A_REJECT (the analogous audit-then-reject action) is
        # declared upstream.
        if ! grep -qE "^Drop\b" "$share_d/actions.std" 2>/dev/null; then
            {
                echo "Drop      noinline   # shorewall-compile.sh stub"
                echo "Reject    noinline   # shorewall-compile.sh stub"
            } >> "$share_d/actions.std"
        fi
    done

    touch "$STAGING/.installed"
    echo "==> staging complete: $STAGING" >&2
else
    echo "==> staging cache hit: $STAGING" >&2
fi


# shorewallrc the compiler reads at runtime — points at the staged
# install. install.sh dropped the same content into $STAGING but
# we re-synthesise here with $WORKDIR-local CONFDIR/VARDIR (so the
# compiler does not try to write into the cache).
SHOREWALLRC="$WORKDIR/shorewallrc"
cat > "$SHOREWALLRC" <<EOF
PRODUCT=shorewall
HOST=generic
PREFIX=$STAGING/usr
SHAREDIR=$STAGING/usr/share
LIBEXECDIR=$STAGING/usr/share
PERLLIBDIR=$STAGING/usr/share/shorewall
CONFDIR=$WORKDIR/etc
SBINDIR=$STAGING/usr/sbin
MANDIR=$STAGING/usr/share/man
VARLIB=$WORKDIR/var
VARDIR=$WORKDIR/var/shorewall
ANNOTATED=
SPARSE=Yes
DEFAULT_PAGER=
EOF

# The Perl compiler from the install lives at
# $STAGING/usr/share/shorewall/compiler.pl; $FindBin::Bin will be
# that dir, so getparams alongside it is the install-patched copy.
COMPILER="$STAGING/usr/share/shorewall/Perl/compiler.pl"
[[ -f "$COMPILER" ]] || COMPILER="$STAGING/usr/share/shorewall/compiler.pl"
if [[ ! -f "$COMPILER" ]]; then
    echo "error: install.sh did not produce compiler.pl in expected location" >&2
    echo "       searched under $STAGING/usr/share/shorewall/" >&2
    find "$STAGING/usr/share/shorewall" -name compiler.pl -print >&2 || true
    exit 1
fi

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

    # --preview wraps the iptables-restore input inside the bash-script
    # boilerplate that Shorewall would normally execute:
    #   cat << __EOF__ >&3
    #   <iptables-save text>
    #   __EOF__
    # plus a trailing "Shorewall configuration verified" line.
    # Extract just the heredoc body so iptables-restore-translate
    # gets clean iptables-save input.
    awk '
        /^[[:space:]]*cat << __EOF__/ { in_body = 1; next }
        in_body && /^__EOF__/         { in_body = 0; next }
        in_body                       { print }
    ' "$rawout" > "$out"
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
