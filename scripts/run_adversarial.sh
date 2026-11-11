#!/bin/bash
# run_adversarial.sh — run the adversarial-load harness against a LOCAL
# openssl s_server test deployment (127.0.0.1 only). Never contacts any
# external host. All tests target the local test server started by this
# script on the same machine.
#
# Usage: run_adversarial.sh <provider_dir> <label> <out_log>
#   provider_dir: directory containing oqsprovider.so
#   label:        run label, e.g. adversarial-run1 (used in output filenames)
#   out_log:      log file for the unedited harness stdout
#
# Sub-steps (all localhost-only):
#   capture    — record one real ClientHello from openssl s_client via a
#                dummy local listener (port 18445)
#   malformed  — 6 malformed ClientHello variants x 10 trials, each followed
#                by a legitimate-handshake probe
#   truncated  — 20 B / 100 B ClientHello prefixes, RST-close, x 10 trials
#   flood      — 200 rapid full handshakes at concurrency 10, server CPU/RSS
#                sampled from /proc before/after
#   slowloris  — 30 stalled partial-handshake connections held 30 s; a
#                legitimate handshake is attempted during the hold and again
#                after release
# Outputs (under the same directory as <out_log>):
#   <label>-clienthello.bin  <label>-malformed.csv  <label>-truncated.csv
#   <label>-flood.csv  <label>-flood-summary.txt  <label>-slowloris-summary.txt
set -u
PROV_DIR="$1"; LABEL="$2"; OUT="$3"

HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$(cd "$HERE/.." && pwd)"
OUTDIR="$(cd "$(dirname "$OUT")" && pwd)"
CERTDIR="${TLS_CERTDIR:-$PACK/../work/certs}"
export TLS_CAFILE="${TLS_CAFILE:-$CERTDIR/ecdsa-ca.crt}"
export TLS_CERT="${TLS_CERT:-$CERTDIR/ecdsa-server.crt}"
export TLS_KEY="${TLS_KEY:-$CERTDIR/ecdsa-server.key}"
export OPENSSL_CONF="${TLS_OPENSSL_CONF:-$PACK/configs/openssl-providers.cnf}"
export OPENSSL_MODULES="$PROV_DIR"
PORT="${TLS_PORT_ADV:-18444}"
CAP_PORT="${TLS_PORT_CAPTURE:-18445}"
GROUP="${TLS_GROUP:-X25519MLKEM768}"
CH_BIN="$OUTDIR/$LABEL-clienthello.bin"

[ -f "$PROV_DIR/oqsprovider.so" ] || { echo "FATAL: provider not built: $PROV_DIR/oqsprovider.so"; exit 1; }
[ -f "$TLS_CERT" ] || { echo "FATAL: server cert missing: $TLS_CERT (run scripts/make_certs.sh first)"; exit 1; }

: > "$OUT"
{
echo "adversarial: label=$LABEL group=$GROUP provider_dir=$PROV_DIR server_port=$PORT capture_port=$CAP_PORT"
echo "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "openssl version: $(openssl version)"
echo "provider sha256: $(sha256sum "$PROV_DIR"/oqsprovider.so 2>/dev/null | cut -d' ' -f1)"
echo "server cert: $(openssl x509 -in "$TLS_CERT" -noout -text 2>/dev/null | grep -m1 'Signature Algorithm' || echo MISSING)"
echo "note: openssl s_server is single-threaded; a stalled connection blocks later handshakes."
echo "note: that is a property of this test deployment, NOT a production-server claim."
} | tee -a "$OUT"

# --- capture one real ClientHello (dummy local listener) ---
echo "=== capture ===" | tee -a "$OUT"
python3 "$PACK/src/adv_harness.py" capture --port "$CAP_PORT" --group "$GROUP" --out "$CH_BIN" 2>&1 | tee -a "$OUT"
[ -s "$CH_BIN" ] || { echo "FATAL: ClientHello capture failed" | tee -a "$OUT"; exit 1; }

# --- start the local test server ---
openssl s_server -accept "127.0.0.1:$PORT" \
  -cert "$TLS_CERT" -key "$TLS_KEY" \
  -groups "$GROUP" -tls1_3 \
  -provider default -provider oqsprovider \
  -naccept 1000 -quiet >> "$OUT" 2>&1 &
SRV_PID=$!
sleep 2
if ! kill -0 "$SRV_PID" 2>/dev/null; then
  echo "FATAL: s_server failed to start (see log)" | tee -a "$OUT"
  exit 1
fi
echo "server pid=$SRV_PID procstat-before: $(python3 "$HERE/procstat.py" "$SRV_PID")" | tee -a "$OUT"

# --- malformed ClientHello variants ---
echo "=== malformed ===" | tee -a "$OUT"
python3 "$PACK/src/adv_harness.py" malformed --port "$PORT" --group "$GROUP" \
  --clienthello "$CH_BIN" --trials 10 --csv "$OUTDIR/$LABEL-malformed.csv" 2>&1 | tee -a "$OUT"

# --- truncated handshake ---
echo "=== truncated ===" | tee -a "$OUT"
python3 "$PACK/src/adv_harness.py" truncated --port "$PORT" --group "$GROUP" \
  --clienthello "$CH_BIN" --trials 10 --csv "$OUTDIR/$LABEL-truncated.csv" 2>&1 | tee -a "$OUT"

# --- connection flood ---
echo "=== flood ===" | tee -a "$OUT"
python3 "$PACK/src/adv_harness.py" flood --port "$PORT" --group "$GROUP" \
  --server-pid "$SRV_PID" --n 200 --concurrency 10 \
  --csv "$OUTDIR/$LABEL-flood.csv" --summary "$OUTDIR/$LABEL-flood-summary.txt" 2>&1 | tee -a "$OUT"

# --- slow-loris stalls ---
echo "=== slowloris ===" | tee -a "$OUT"
python3 "$PACK/src/adv_harness.py" slowloris --port "$PORT" --group "$GROUP" \
  --server-pid "$SRV_PID" --stalls 30 --hold 30 \
  --summary "$OUTDIR/$LABEL-slowloris-summary.txt" 2>&1 | tee -a "$OUT"

echo "server pid=$SRV_PID procstat-after: $(python3 "$HERE/procstat.py" "$SRV_PID")" | tee -a "$OUT"

# --- final liveness probe, then stop the server ---
python3 "$PACK/src/adv_harness.py" probe --port "$PORT" --group "$GROUP" 2>&1 | tee -a "$OUT"
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null || true
echo "adversarial: DONE label=$LABEL" | tee -a "$OUT"
