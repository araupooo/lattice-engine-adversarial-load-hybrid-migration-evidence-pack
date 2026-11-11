# Lattice-Engine Adversarial-Load and Hybrid Migration Assessment

Local measurements of a hybrid TLS 1.3 test deployment
(X25519MLKEM768 vs classical X25519) under baseline and adversarial
load, plus a migration plan derived from those measurements.

## Headline results

- **Hybrid handshake costs +2–3 ms** over the classical fallback at the
  median (17–18 ms vs 15 ms, n=30 each, 0 failures). Server CPU per
  handshake: hybrid 2.26–2.58 ms, fallback 1.94–2.26 ms.
- **ClientHello grows 202 → 1378 bytes** (key_share 32 → 1216 bytes).
- **Flood (200 handshakes, concurrency 10): 200/200 succeed**, ~78/s,
  median latency ~118 ms (queueing on the single-threaded test server),
  server RSS delta 0 KiB.
- **Slow-loris (30 stalled partial handshakes, 30 s): a legitimate
  handshake TIMED OUT during the hold** in both runs; all 30 stalls
  still open after 30 s; the server recovered immediately after release.
  This is a property of the single-threaded `openssl s_server` test
  deployment, not a production-server claim — see `docs/methodology.md`.
- **Malformed ClientHello (6 variants) and truncated handshakes never
  killed the server**: fatal alerts (`protocol_version`,
  `handshake_failure`) or silence, and 160/160 post-trial probes
  succeeded.
- **ML-KEM-768** (liboqs 0.16.0): encaps ~20 us, decaps ~25 us, sizes
  match FIPS 203 Table 3 exactly, 0/200 shared-secret mismatches.

## Pinned environment

OpenSSL 3.0.13, liboqs 0.16.0 (optimized, `OQS_OPT_TARGET=auto`),
oqs-provider 0.12.0 (built `.so` SHA256
`2470693d7154a6d877bf918c4c7c220606e358b19013ac495f2687afe8863c54`),
ECDSA P-384 server certificate generated at runtime (never committed).

## Contents

- `docs/methodology.md` — environment, test deployment, measurement
  matrix, how CPU/memory were measured, headline table, limitations.
- `docs/migration-plan.md` — rollout stages, fallback policy, rollback
  criteria, monitoring signals, slow-loris mitigations.
- `docs/evidence-index.md` — every measured claim → its unedited log
  line; every spec claim → its primary source.
- `docs/citations.md` — primary sources: RFC 8446, FIPS 203,
  draft-ietf-tls-mlkem, OpenSSL / liboqs / oqs-provider docs.
- `docs/index.html` — the findings page (same tables as the docs).
- `outputs/` — unedited logs, CSVs, and summaries for every run
  (run1 + run2), plus `fresh-clone-*` reproduction outputs and
  `run-manifest.md`.
- `scripts/` — the full harness: `build_all.sh`, `make_certs.sh`,
  `run_baseline.sh`, `run_adversarial.sh`, `run_all.sh`,
  `clean_reproduce.sh`, `verify_digests.sh`, `make_sha256sums.sh`,
  `procstat.py`.
- `src/` — `bench_kem.c` (ML-KEM-768 size/timing harness) and
  `adv_harness.py` (malformed / truncated / flood / slow-loris tests,
  localhost only).
- `configs/openssl-providers.cnf` — OpenSSL provider configuration.
- `fixtures/` — pinned source tarballs (liboqs 0.16.0, oqs-provider
  0.12.0) with SHA256 verification in `scripts/build_all.sh`.

## Reproduce

```sh
# Full clean reproduction from a fresh copy of this pack:
# rebuilds from fixtures, regenerates certs, re-runs the whole suite,
# writes fresh logs to outputs/fresh-clone-*, and compares headline
# numbers against the shipped ones.
bash scripts/clean_reproduce.sh

# Verify every shipped file against its recorded digest:
bash scripts/verify_digests.sh
```

Runtime for a clean reproduction is ~10 minutes. All tests run against
a local `openssl s_server` on `127.0.0.1` only; no external host is
contacted.

## Scope notes

- The test server is single-threaded `openssl s_server`; stall and
  flood behaviour is a property of that deployment, not of production
  TLS servers. Re-measure on the production stack before setting
  timeouts or limits from these numbers.
- The served certificate is classical ECDSA P-384; only the key
  exchange is hybrid. OpenSSL 3.0.13 cannot serve an ML-DSA-65
  certificate.
