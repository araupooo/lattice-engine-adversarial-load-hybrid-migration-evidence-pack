#!/bin/bash
# run_all.sh — run the full measurement suite for this assessment and write
# every output under pack/outputs/:
#   1. bench_kem (ML-KEM-768 sizes + timing, 200 iterations) — run1 + run2
#   2. baseline handshakes: hybrid X25519MLKEM768 and fallback X25519,
#      N=30 each, run1 + run2
#   3. adversarial harness (malformed ClientHello, truncated handshake,
#      connection flood, slow-loris stalls) — run1 + run2
# Usage: run_all.sh [workdir] [log-prefix]
# workdir defaults to <task>/work. log-prefix (default "") is prepended to
# every output filename; scripts/clean_reproduce.sh passes "fresh-clone-"
# so a reproduction run never overwrites the shipped outputs.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
PREFIX="${2:-}"
OUT="$PACK/outputs"
mkdir -p "$OUT"
PROV="$WORK/oqs-opt-mod"
export TLS_CERTDIR="$WORK/certs"

[ -f "$PROV/oqsprovider.so" ] || { echo "FATAL: provider not built: $PROV/oqsprovider.so (run scripts/build_all.sh first)"; exit 1; }
[ -f "$WORK/certs/ecdsa-server.crt" ] || { echo "FATAL: certs missing (run scripts/make_certs.sh first)"; exit 1; }

echo "run_all: provider=$PROV work=$WORK out=$OUT prefix=$PREFIX"
echo "run_all: date $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

echo "=== bench_kem run1 ==="
"$WORK/bench_kem" 200 > "$OUT/${PREFIX}bench-kem-run1.log" 2>&1
echo "=== bench_kem run2 ==="
"$WORK/bench_kem" 200 > "$OUT/${PREFIX}bench-kem-run2.log" 2>&1

echo "=== baseline hybrid run1 ==="
bash "$PACK/scripts/run_baseline.sh" "$PROV" X25519MLKEM768 hybrid-run1 30 "$OUT/${PREFIX}baseline-hybrid-run1.log"
echo "=== baseline hybrid run2 ==="
bash "$PACK/scripts/run_baseline.sh" "$PROV" X25519MLKEM768 hybrid-run2 30 "$OUT/${PREFIX}baseline-hybrid-run2.log"
echo "=== baseline fallback (X25519) run1 ==="
bash "$PACK/scripts/run_baseline.sh" "$PROV" X25519 fallback-run1 30 "$OUT/${PREFIX}baseline-fallback-run1.log"
echo "=== baseline fallback (X25519) run2 ==="
bash "$PACK/scripts/run_baseline.sh" "$PROV" X25519 fallback-run2 30 "$OUT/${PREFIX}baseline-fallback-run2.log"

echo "=== adversarial run1 ==="
bash "$PACK/scripts/run_adversarial.sh" "$PROV" "${PREFIX}adversarial-run1" "$OUT/${PREFIX}adversarial-run1.log"
echo "=== adversarial run2 ==="
bash "$PACK/scripts/run_adversarial.sh" "$PROV" "${PREFIX}adversarial-run2" "$OUT/${PREFIX}adversarial-run2.log"

echo "run_all: DONE — outputs in $OUT"
ls -l "$OUT"
