#!/bin/bash
# clean_reproduce.sh — full clean reproduction from a fresh copy of this pack.
#
# Builds the pinned stack from pack/fixtures/ into a throwaway workdir,
# regenerates the test certificates, re-runs the FULL measurement suite
# (bench_kem run1+run2, baselines hybrid+fallback run1+run2, adversarial
# run1+run2 — the same scripts/run_all.sh, with a "fresh-clone-" filename
# prefix), writes every fresh log under outputs/fresh-clone-*, and prints a
# comparison of re-derived vs shipped headline numbers to stdout and to
# outputs/fresh-clone-compare.txt. Exits non-zero if any comparison check
# fails.
#
# Usage: clean_reproduce.sh
# The temp workdir is removed on exit. Runtime is ~10 minutes (build +
# full suite). Requires: cmake, gcc, python3, openssl 3.0.13.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$PACK/outputs"
WORK="$(mktemp -d /tmp/lattice-adv-repro.XXXXXX)"
echo "clean_reproduce: pack=$PACK"
echo "clean_reproduce: work=$WORK (temporary, removed on exit)"
echo "clean_reproduce: date $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
trap 'rm -rf "$WORK"' EXIT

bash "$PACK/scripts/build_all.sh" "$WORK" || { echo "clean_reproduce: BUILD FAILED"; exit 1; }
TLS_CERTDIR="$WORK/certs" bash "$PACK/scripts/make_certs.sh" || { echo "clean_reproduce: CERTS FAILED"; exit 1; }
bash "$PACK/scripts/run_all.sh" "$WORK" "fresh-clone-" || { echo "clean_reproduce: SUITE FAILED"; exit 1; }

echo "clean_reproduce: comparing fresh-clone numbers vs shipped numbers"
python3 "$PACK/scripts/compare_reproduce.py" "$OUT" > "$OUT/fresh-clone-compare.txt" 2>&1
RC=$?
cat "$OUT/fresh-clone-compare.txt"
echo "clean_reproduce: exit $RC"
exit $RC
