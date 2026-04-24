# tools/ — operator and test scripts

| File | Purpose |
|------|---------|
| [`run-tests.sh`](run-tests.sh) | Run pytest in an isolated private namespace |
| [`setup-remote-test-host.sh`](setup-remote-test-host.sh) | Bootstrap a remote test host over SSH |
| [`release.sh`](release.sh) | Bump version, update changelogs, commit, tag |
| [`gen-rpm-spec.sh`](gen-rpm-spec.sh) | Generate the RPM spec from `.spec.in` |
| [`shorewall-compile.sh`](shorewall-compile.sh) | Compile a Shorewall config to iptables-save + nft, no root |

## Running tests

Tests must run as **root** on a dedicated host (not on a production firewall).
No extra tooling needs to be installed — `run-tests.sh` handles isolation.

```bash
# Bootstrap a remote host once:
tools/setup-remote-test-host.sh root@<host>

# Run the full test suite via systemd-run (survives SSH disconnect):
ssh root@<host> systemd-run --unit=shorewall-pytest --collect \
  --property=StandardOutput=file:/tmp/pytest.log \
  --property=StandardError=file:/tmp/pytest.log \
  /root/shorewall-nft/tools/run-tests.sh \
    packages/shorewall-nft/tests/ \
    packages/shorewalld/tests/ \
    packages/shorewall-nft-simlab/tests/ -v

# Follow progress:
ssh root@<host> 'systemctl is-active shorewall-pytest; tail -f /tmp/pytest.log'
```

### How `run-tests.sh` isolates tests

On first invocation it re-execs itself via `unshare --mount --net`, creating:

- **Private network namespace** — nft rules and sysctl changes cannot escape.
- **Private mount namespace** — `ip netns add/delete` bind-mounts go to a
  private `tmpfs` overlay on `/run/netns`, invisible to the host.
- **Loopback up** — `ip link set lo up` so UDP-based tests work.

This means tests cannot crash the test host's networking, even if a test
loads a broken nftables ruleset or kills a namespace badly.

No sudoers rules, no helper binary, no group membership needed.

## Compiling a Shorewall config without root

`shorewall-compile.sh` produces `iptables.txt` / `ip6tables.txt`
(`iptables-save` format) and `iptables.nft` / `ip6tables.nft` (nft
equivalents via `iptables-restore-translate`) from a Shorewall
config dir, without loading anything into the kernel and without
requiring root.

The script bootstraps upstream Shorewall (Perl) from
`gitlab.com/shorewall/code.git` into a per-user cache, runs the
real upstream `install.sh` against that cache (so all action files,
macros, and version markers are produced exactly as a real install
would), and invokes `compiler.pl --preview` inside an unprivileged
user+net+mount namespace. The compile output is post-filtered out
of its bash-script wrapper to give you clean `iptables-save` text,
which is then piped through `iptables-restore-translate` for the
nft equivalent.

```bash
# Compile both families against the local config:
tools/shorewall-compile.sh \
    --shorewall  /etc/shorewall \
    --shorewall6 /etc/shorewall6 \
    --output     /tmp/swc-out

# Lock to a specific upstream tag (otherwise: latest tag is resolved):
tools/shorewall-compile.sh --ref 5.2.6.1 --shorewall ./mycfg --output ./out

# Skip the nft-translate step:
tools/shorewall-compile.sh --no-translate --shorewall ./mycfg --output ./out

# Use an existing local Shorewall checkout (skips git clone):
tools/shorewall-compile.sh --src ~/src/shorewall --shorewall ./mycfg
```

Every invocation prints a yellow **WARNING** banner to stderr
listing the Shorewall features whose compile output depends on
**live host state** (`routeback`, `BROADCAST=detect`,
`DETECT_DNAT_IPADDRS`, `&iface`, proxyarp `HAVEROUTE`, providers,
DHCP-discovered addresses). When this script runs anywhere other
than on the actual firewall host, those reads return the runner's
state instead, and the output may silently miss or misclassify
rules. The banner is intentionally not suppressible.

GitLab-CI snippet (also documented inline in the script header):

```yaml
shorewall-compile:
  image: debian:trixie-slim
  before_script:
    - apt-get update -qq
    - apt-get install -y --no-install-recommends \
        git perl iptables ca-certificates util-linux
  cache:
    key: shorewall-src-v1
    paths: [.cache/shorewall-compile/]
  script:
    - tools/shorewall-compile.sh
        --shorewall  fixtures/cfg/shorewall
        --shorewall6 fixtures/cfg/shorewall6
        --output     out
        --cache      .cache/shorewall-compile
  artifacts:
    paths: [out/]
    expire_in: 30 days
```

Limitations:

- Configs that use shorewall-nft-specific syntax extensions
  (`CT:helper:NAME`, `?FAMILY` directive, `nfsets:NAME` tokens)
  do not compile under classic Shorewall — they are extensions
  on the Python compiler side, not part of upstream.
- `shorewall6` configs that set `BROADCAST=detect` on an interface
  fail compile (IPv6 has no broadcast — config bug, not a script
  issue).

## Releasing

```bash
tools/release.sh [--dry-run] [--push] vX.Y.Z "Short summary"
```

Updates version in all `pyproject.toml` files, `__init__.py`,
`CHANGELOG.md`, and `packaging/debian/changelog`, then creates a release
commit and an annotated tag.  With `--push` it also pushes the branch and
tag to trigger CI (builds wheels + .deb + .rpm → GitHub Release).
