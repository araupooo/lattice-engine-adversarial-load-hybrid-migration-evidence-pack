# Run Manifest — outputs/

All files in this directory are the unedited stdout / CSV output of the
scripts in `scripts/`, produced by `scripts/run_all.sh` (shipped runs)
and by `scripts/clean_reproduce.sh` (fresh-clone reproduction runs).
Dates are UTC 2026-11-11. Pinned stack: OpenSSL 3.0.13, liboqs 0.16.0
(optimized), oqs-provider 0.12.0, built `oqsprovider.so` SHA256
`2470693d7154a6d877bf918c4c7c220606e358b19013ac495f2687afe8863c54`.

## Shipped runs (produced by scripts/run_all.sh, 03:39–03:52 UTC)

| File | Contents |
|---|---|
| `bench-kem-run1.log`, `bench-kem-run2.log` | ML-KEM-768 size checks (FIPS 203 Table 3) + keypair/encaps/decaps timing, n=200 each |
| `baseline-hybrid-run1.log`, `baseline-hybrid-run2.log` | 30 timed X25519MLKEM768 handshakes each + one `-msg` trace (ClientHello 1378 B, key_share 1216 B, group 0x11ec) + server /proc CPU+RSS before/after |
| `baseline-hybrid-run1.log.times`, `baseline-hybrid-run2.log.times` | The 30 per-handshake wall times (ms) behind each hybrid summary |
| `baseline-hybrid-run1.log.trace`, `baseline-hybrid-run2.log.trace` | Full `s_client -msg` trace for the measured hybrid handshake |
| `baseline-fallback-run1.log`, `baseline-fallback-run2.log` | 30 timed X25519 handshakes each + trace (ClientHello 202 B, key_share 32 B, group 0x001d) + server /proc CPU+RSS |
| `baseline-fallback-run1.log.times`, `baseline-fallback-run2.log.times` | The 30 per-handshake wall times (ms) behind each fallback summary |
| `baseline-fallback-run1.log.trace`, `baseline-fallback-run2.log.trace` | Full `s_client -msg` trace for the measured fallback handshake |
| `adversarial-run1.log`, `adversarial-run2.log` | Full unedited stdout of the adversarial harness (capture, malformed, truncated, flood, slow-loris, final probe) incl. server-side `unexpected eof` errors |
| `adversarial-run1-clienthello.bin`, `adversarial-run2-clienthello.bin` | The captured real ClientHello (1383 bytes) each run was built from |
| `adversarial-run1-malformed.csv`, `adversarial-run2-malformed.csv` | 60 rows each: 6 malformed variants x 10 trials (server reply + post-trial probe) |
| `adversarial-run1-truncated.csv`, `adversarial-run2-truncated.csv` | 20 rows each: 20 B / 100 B ClientHello prefixes x 10 trials |
| `adversarial-run1-flood.csv`, `adversarial-run2-flood.csv` | 200 rows each: one per flood handshake attempt (ok, ms, detail) |
| `adversarial-run1-flood-summary.txt`, `adversarial-run2-flood-summary.txt` | Flood success rate, latency distribution, server CPU/RSS delta |
| `adversarial-run1-slowloris-summary.txt`, `adversarial-run2-slowloris-summary.txt` | Slow-loris outcome: stalls opened, probe during hold, stalls still open, probe after release, server CPU/RSS |

## Clean-reproduction runs (produced by scripts/clean_reproduce.sh, 04:04–04:15 UTC)

Same file set with a `fresh-clone-` prefix, produced from a fresh build
in a throwaway workdir (`/tmp/lattice-adv-repro.*`, removed after the
run) with freshly generated certificates. The fresh logs contain the
temporary workdir path in their headers; that is expected and is not
edited out.

| File | Contents |
|---|---|
| `fresh-clone-bench-kem-run1.log`, `fresh-clone-bench-kem-run2.log` | Re-derived ML-KEM-768 sizes + timing |
| `fresh-clone-baseline-hybrid-run*.log` (+ `.times`, `.trace`) | Re-derived hybrid baselines |
| `fresh-clone-baseline-fallback-run*.log` (+ `.times`, `.trace`) | Re-derived fallback baselines |
| `fresh-clone-adversarial-run*.log` | Re-derived adversarial harness stdout |
| `fresh-clone-adversarial-run*-clienthello.bin` | Re-captured real ClientHello |
| `fresh-clone-adversarial-run*-malformed.csv` / `*-truncated.csv` / `*-flood.csv` | Re-derived per-trial rows |
| `fresh-clone-adversarial-run*-flood-summary.txt` / `*-slowloris-summary.txt` | Re-derived flood / slow-loris summaries |
| `fresh-clone-compare.txt` | Comparison of re-derived vs shipped headline numbers: **ALL CHECKS PASSED** (see `scripts/compare_reproduce.py` for tolerances) |

## Notes

- The `.times` and `.trace` files are side outputs of
  `scripts/run_baseline.sh`, named after the log they belong to.
- No file in this directory was edited after it was written. Paths
  inside the logs are the paths on the machine that produced them
  (shipped runs: the pack's `work/` directory; fresh-clone runs: a
  temporary directory). Test certificates are generated at runtime and
  are not shipped.
