# KEEPALIVED-MIB provenance

Source: <https://github.com/acassen/keepalived/blob/master/doc/KEEPALIVED-MIB.txt>

**Pinned at upstream commit:** `b3631012262e` (committed 2025-11-03T22:28:17Z)

Refreshed on: 2026-04-24

## How to refresh

```bash
curl -sSL https://raw.githubusercontent.com/acassen/keepalived/master/doc/KEEPALIVED-MIB.txt \
    -o third_party/keepalived-mib/KEEPALIVED-MIB.txt

# Update the pinned SHA + date in this file.
NEW_SHA=$(curl -sSL https://api.github.com/repos/acassen/keepalived/commits/master?path=doc/KEEPALIVED-MIB.txt \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['sha'][:12])")
NEW_DATE=$(curl -sSL https://api.github.com/repos/acassen/keepalived/commits/master?path=doc/KEEPALIVED-MIB.txt \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['commit']['committer']['date'])")
echo "new pin: $NEW_SHA ($NEW_DATE)"

# Regenerate the Python constants module.
python3 tools/gen_keepalived_mib.py --emit packages/shorewalld/shorewalld/keepalived/mib.py

# Review the diff of mib.py — every change should come from a real
# upstream MIB change, not parser drift.
git diff packages/shorewalld/shorewalld/keepalived/mib.py
```

## CI drift check

Runs on every PR that touches either the MIB or the generated module:

```bash
python3 tools/gen_keepalived_mib.py \
    --check packages/shorewalld/shorewalld/keepalived/mib.py
```

Exits 1 if the committed `mib.py` doesn't match a fresh regeneration
from the pinned MIB. Fails the PR with a diff so the reviewer knows
to run `--emit`.
