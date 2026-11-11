# Claims-to-Evidence Index

Every measured claim in this pack maps to the unedited output that
supports it. Spec claims map to their primary source in `citations.md`.
File paths are relative to the pack root. "Shipped" logs are the run1/run2
outputs; `fresh-clone-*` logs are the independent reproduction (see
`methodology.md`, Reproduction).

## Measured claims

| # | Claim | Evidence (file : line / excerpt) |
|---|---|---|
| C1 | ML-KEM-768 sizes match FIPS 203 Table 3: ek 1184, dk 2400, ct 1088, ss 32 | `outputs/bench-kem-run1.log`: `length_public_key=1184 … OK`, `length_secret_key=2400 … OK`, `length_ciphertext=1088 … OK`, `length_shared_secret=32 … OK`; same in `run2.log` and `fresh-clone-bench-kem-run*.log` |
| C2 | ML-KEM-768 encaps mean ~20 us, decaps mean ~25 us (n=200) | `outputs/bench-kem-run1.log`: `encaps … mean= 19.79 us`, `decaps … mean= 25.63 us`; run2: 20.11 / 25.28 us |
| C3 | ML-KEM-768 keypair mean 31–57 us, outlier-sensitive (max 7474 us run1) | `outputs/bench-kem-run1.log`: `keypair … mean= 56.63 us … max= 7474.45 us`; run2: `mean= 31.20 us … max= 2430.83 us` |
| C4 | Full KEM round (keypair+encaps+decaps) mean 102.05 us run1, 76.59 us run2 | `outputs/bench-kem-run1.log` / `run2.log`: `full KEM round … mean:` lines |
| C5 | 0 / 200 shared-secret mismatches in both bench runs | `outputs/bench-kem-run1.log` / `run2.log`: `shared-secret mismatches: 0 / 200` |
| C6 | Hybrid handshake median 18.00 ms (run1) / 17.00 ms (run2), n=30, 0 failures | `outputs/baseline-hybrid-run1.log`: `handshake summary (hybrid-run1, X25519MLKEM768): n=30 mean=18.87 ms median=18.00 ms min=17 ms max=24 ms`; `handshake failures: 0 / 30`; run2: mean=17.37, median=17.00, `0 / 30` |
| C7 | Fallback handshake median 15.00 ms both runs, n=30, 0 failures | `outputs/baseline-fallback-run1.log`: `n=30 mean=15.53 ms median=15.00 ms`; `handshake failures: 0 / 30`; run2 identical median |
| C8 | Hybrid ClientHello 1378 bytes; key_share 1216 bytes, group 0x11ec | `outputs/baseline-hybrid-run1.log`: `trace: ClientHello total bytes=1378`, `trace: key_share extension length=1222 list_len=1220 group=0x11ec key_exchange_len=1216`; run2 identical |
| C9 | Fallback ClientHello 202 bytes; key_share 32 bytes, group 0x001d | `outputs/baseline-fallback-run1.log`: `trace: ClientHello total bytes=202`, `trace: key_share extension length=38 list_len=36 group=0x001d key_exchange_len=32`; run2 identical |
| C10 | Negotiated cipher TLS_AES_256_GCM_SHA384, TLS 1.3, verify ok (both groups) | `outputs/baseline-hybrid-run1.log` and `baseline-fallback-run1.log`: `New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384` and `Verify return code: 0 (ok)` |
| C11 | Server CPU per hybrid handshake 2.26 ms (run1) / 2.58 ms (run2) | `outputs/baseline-hybrid-run1.log`: procstat-before `cpu_total_s=0.090`, after `0.160` → 0.070 s / 31 handshakes = 2.26 ms; run2: 0.080 → 0.160 = 0.080 s / 31 = 2.58 ms |
| C12 | Server CPU per fallback handshake 1.94 ms (run1) / 2.26 ms (run2) | `outputs/baseline-fallback-run1.log`: 0.090 → 0.150 = 0.060 s / 31 = 1.94 ms; run2: 0.080 → 0.150 = 0.070 s / 31 = 2.26 ms |
| C13 | Server RSS warm-up growth, then flat: hybrid +1392/+1500 KiB over 31 handshakes; flood 0 KiB over 200 | `outputs/baseline-hybrid-run1.log`: rss 9616 → 11008 KiB; run2: 9568 → 11068 KiB; `outputs/adversarial-run1-flood-summary.txt`: `rss_delta_kib=0`; run2 likewise |
| C14 | Flood: 200/200 handshakes succeed, ~78/s, median latency ~118 ms, server CPU 2.70 ms/attempt | `outputs/adversarial-run1-flood-summary.txt`: `flood summary n=200 success=200 wall_s=2.57 rate_per_s=77.89`, `latency_ms min=28.9 median=117.2 p95=165.1 max=169.8`, `server_cpu_delta_s=0.540 cpu_ms_per_attempt=2.70`; run2: 78.34/s, median 118.7 ms, same 2.70 ms; per-attempt rows in `adversarial-run*-flood.csv` |
| C15 | Slow-loris: legitimate handshake TIMED OUT during the 30-stall hold (both runs) | `outputs/adversarial-run1-slowloris-summary.txt`: `probe_during_stall ok=False ms=10006.0 detail=TIMEOUT`; run2: `ms=10007.3` |
| C16 | Slow-loris: 30/30 stalls still open after the 30 s hold (both runs) | `outputs/adversarial-run1-slowloris-summary.txt`: `stalls_still_open_after_hold=30`; run2 likewise |
| C17 | Slow-loris: handshake succeeds after release (20.4 ms run1, 35.8 ms run2); server CPU delta ~0.01 s, RSS unchanged | `outputs/adversarial-run1-slowloris-summary.txt`: `probe_after_release ok=True ms=20.4 detail=verified`, `cpu_delta_s=0.010`, `server_rss_before_kib=11024 server_rss_mid_kib=11024 server_rss_after_kib=11024`; run2: 35.8 ms, `cpu_delta_s=0.000` |
| C18 | Malformed V4 (TLS 1.0 offer) → fatal alert `protocol_version` (70), 10/10 both runs | `outputs/adversarial-run1-malformed.csv`, rows `variant=V4-bad-version-tls10`: `server_reply="alert level=2 desc=70 (protocol_version)"`; run2 identical |
| C19 | Malformed V5 (zero key_share) → fatal alert `handshake_failure` (40), 10/10 both runs | `outputs/adversarial-run1-malformed.csv`, rows `variant=V5-bad-keyshare-zero-ek`: `server_reply="alert level=2 desc=40 (handshake_failure)"`; run2 identical |
| C20 | Malformed V1/V2/V3/V6 → no TLS record within 5 s, server stays alive | `outputs/adversarial-run1-malformed.csv`, rows V1/V2/V3/V6: `server_reply=no-tls-record`; every row `probe_ok=True` |
| C21 | Truncated handshakes (20 B / 100 B prefixes) → no TLS record, server stays alive, 20/20 probes ok per run | `outputs/adversarial-run1-truncated.csv` / `run2`: all rows `server_reply=no-tls-record`, `probe_ok=True` |
| C22 | Server logged 41 `unexpected eof` errors per adversarial run but stayed alive (final probe verified) | `outputs/adversarial-run1.log`: 41 lines `ssl3_read_n:unexpected eof while reading`; ends `probe: ok=True … detail=verified`, `adversarial: DONE`; run2 identical |
| C23 | Pinned environment: OpenSSL 3.0.13, oqsprovider.so SHA256 2470693d… | Every log header: `openssl version: OpenSSL 3.0.13 …`, `provider sha256: 2470693d7154a6d877bf918c4c7c220606e358b19013ac495f2687afe8863c54` |
| C24 | Clean reproduction re-derives the headline numbers | `outputs/fresh-clone-compare.txt` (all checks PASS) and `outputs/fresh-clone-*.log` / `*.csv` |

## Spec claims (primary sources in citations.md)

| # | Claim | Primary source |
|---|---|---|
| S1 | TLS 1.3 ClientHello carries `key_share`, `supported_versions`, `supported_groups` extensions | RFC 8446 §4.1.2, §4.2.7, §4.2.8 |
| S2 | Fatal alerts: 70 = `protocol_version`, 40 = `handshake_failure` | RFC 8446 §6 |
| S3 | ML-KEM-768 parameters: ek 1184, dk 2400, ct 1088, ss 32 bytes | FIPS 203 §8, Table 3 |
| S4 | X25519MLKEM768 is the hybrid of X25519 (32-byte share) and ML-KEM-768 (1184-byte encapsulation key); group code point 0x11ec | draft-ietf-tls-mlkem (TLS WG draft); group code point confirmed by the measured trace (C8) |
| S5 | TLS 1.3 handshake is 1-RTT for a full handshake with (EC)DHE / hybrid KEX | RFC 8446 §2 |

## Claims NOT made (limitations)

- No claim about production-server stall/flood behaviour (single-threaded
  test server — methodology L1).
- No claim about ML-DSA certificates (not servable by OpenSSL 3.0.13 —
  methodology L2).
- No claim about WAN, middlebox, or client-diversity behaviour
  (localhost only — methodology L3).
- No tight figure for ML-KEM-768 keypair mean (outlier-sensitive —
  methodology L4).
