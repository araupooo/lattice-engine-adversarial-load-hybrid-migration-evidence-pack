#!/bin/bash
# make_certs.sh — generate the test ECDSA P-384 CA + server certificate used
# by the TLS harness. Test artifacts only (CN=localhost / test CA, 2-day
# validity), regenerated fresh by every clean reproduction; never committed.
# The served certificate is ECDSA P-384, the post-remediation choice of the
# lattice-integration pack: OpenSSL 3.0.13 cannot serve an ML-DSA-65
# certificate ("ca md too weak", then "unknown certificate type" — finding
# B-1 of that pack, reproduced there). The post-quantum part of this
# assessment is the hybrid X25519MLKEM768 key exchange, not the signature.
# Usage: make_certs.sh
# Certificates go to ${TLS_CERTDIR:-<task>/work/certs}.
set -eu
CERTDIR="${TLS_CERTDIR:-$(cd "$(dirname "$0")/../.." && pwd)/work/certs}"
mkdir -p "$CERTDIR"
cd "$CERTDIR"
echo "generating ECDSA P-384 CA + server cert (default provider)"
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout ecdsa-ca.key -out ecdsa-ca.crt -days 2 -nodes -subj "/CN=Test ECDSA P-384 CA"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout ecdsa-server.key -out ecdsa-server.csr -nodes -subj "/CN=localhost"
openssl x509 -req -in ecdsa-server.csr -CA ecdsa-ca.crt -CAkey ecdsa-ca.key \
  -CAcreateserial -out ecdsa-server.crt -days 2
echo "certs in $CERTDIR:"
for c in ecdsa-server.crt; do
  echo "$c: $(openssl x509 -in "$c" -noout -text | grep -m1 'Signature Algorithm' | xargs)"
done
ls -l "$CERTDIR"
