# Methodology

## What was measured

This assessment measures a local hybrid TLS 1.3 test deployment under
baseline and adversarial load, and derives a migration plan from the
measurements. Every number in this pack comes from a script in `scripts/`
run against the pinned stack below; no number is taken from documentation
or from another pack. Spec claims are cited separately in `citations.md`
and indexed claim-by-claim in `evidence-index.md`.

## Pinned environment

| Component | Version / value | Source |
|---|---|---|
| OpenSSL | 3.0.13 (system, 30 Jan 2024) | `openssl version` in every log |
| liboqs | 0.16.0, optimized build (`OQS_OPT_TARGET=auto`) | `fixtures/liboqs-0.16.0.tar.gz`, SHA256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae` |
| oqs-provider | 0.12.0 | `fixtures/oqs-provider-0.12.0.tar.gz`, SHA256 `81b1362af4276cb44afc98213cf0d8caeed8b966130844847163ad3a3b54b18f` |
| oqsprovider.so (built) | SHA256 `2470693d7154a6d877bf918c4c7c220606e358b19013ac495f2687afe8863c54` | printed in every log header |
| Hybrid group | X25519MLKEM768, group `0x11ec` | `openssl s_client -groups X25519MLKEM768` |
| Fallback group | X25519, group `0x001d` | `openssl s_client -groups X25519` |
| Server certificate | ECDSA P-384, `ecdsa-with-SHA256`, CN=localhost, 2-day validity | generated at runtime by `scripts/make_certs.sh`; never committed |
| Cipher (negotiated) | TLS_AES_256_GCM_SHA384 | `openssl s_client` output in baseline logs |
| OS / CPU | Linux x86_64, 4 vCPU, ~7.8 GiB RAM, ~380–434 MiB available during runs | `free -m` at run time |
| Python | 3.12.3 | `python3 --version` |
| GCC / CMake | 13.3.0 / 3.28.3 | build logs |

Build: `scripts/build_all.sh` (single optimized liboqs build + provider
build + `src/bench_kem.c` harness). Certificates: `scripts/make_certs.sh`
(CA + server cert, ECDSA P-384). The post-quantum part of this assessment
is the hybrid key exchange; the served certificate is classical ECDSA P-384
because OpenSSL 3.0.13 cannot serve an ML-DSA-65 certificate (see
Limitation L2).

## Test deployment

The endpoint under test is `openssl s_server` on `127.0.0.1` only
(ports 18443 baseline, 18444 adversarial, 18445 ClientHello capture).
**No external host was contacted at any point.** Every adversarial test
targets the local server started by `scripts/run_adversarial.sh` on the
same machine.

**Single-threaded server (scope note, read first).** `openssl s_server`
processes one connection at a time: a stalled connection blocks later
handshakes until it closes or times out. This is a property of this test
deployment, measured below, and is **not** a claim about production TLS
servers, which are normally multi-threaded or event-driven. Any migration
decision that depends on stall behaviour must be re-measured against the
production server software, not this harness.

## Measurement matrix

All steps are run by `scripts/run_all.sh`; every run is executed twice
(run1, run2) and both runs are shipped.

| Step | Script | What is recorded |
|---|---|---|
| ML-KEM-768 sizes + timing | `src/bench_kem.c` via `run_all.sh`, 200 iterations | FIPS 203 Table 3 size checks, keypair/encaps/decaps means, shared-secret equality |
| Baseline hybrid | `scripts/run_baseline.sh`, X25519MLKEM768, N=30 | full-handshake wall time per handshake (incl. `s_client` process spawn, ~2–4 ms, identical for both labels), ClientHello/key_share sizes from one `-msg` trace, server CPU (utime+stime) and VmRSS from `/proc` before/after |
| Baseline fallback | same script, X25519, N=30 | same as hybrid, for the classical fallback |
| Malformed ClientHello | `src/adv_harness.py malformed`, 6 variants x 10 trials | bytes sent, server reply (first TLS record / alert), per-trial legitimate-handshake probe |
| Truncated handshake | `src/adv_harness.py truncated`, 20 B / 100 B prefixes x 10 trials | server reply, per-trial legitimate-handshake probe |
| Connection flood | `src/adv_harness.py flood`, 200 handshakes at concurrency 10 | per-attempt success, latency distribution, server CPU/RSS delta from `/proc` |
| Slow-loris stalls | `src/adv_harness.py slowloris`, 30 stalled partial handshakes held 30 s | legitimate handshake during the hold and after release, stalls still open, server CPU/RSS |

### How CPU and memory were measured

Server cost is sampled from `/proc/<pid>/stat` (utime+stime, `CLK_TCK`
= 100) and `/proc/<pid>/status` (VmRSS) by `scripts/procstat.py` and by
the same code inside `src/adv_harness.py`, immediately before and after
each phase. Per-handshake CPU is the delta divided by the number of
handshakes accepted in that phase. Baseline phases accept 31 connections
(30 timed + 1 traced). Flood phases accept 200. Slow-loris phases accept
30 stalls + 2 probes. RSS deltas include first-handshake warm-up
allocations; the flood phases (200 handshakes, RSS delta 0 KiB in both
runs) are the steady-state memory evidence.

### How the malformed variants were built

A real ClientHello was captured once per run (`adv_harness.py capture`:
a dummy local listener records what `openssl s_client` sends for
X25519MLKEM768 — 1383 bytes). Variants:

- **V1 truncated-record**: first 15 bytes of the real ClientHello, RST-close.
- **V2 garbage-100B**: 100 deterministic random bytes (seed 7).
- **V3 oversized-length**: record header claiming a 16384-byte record
  (`0x16 0x03 0x01 0x40 0x00`) followed by 50 bytes of the real ClientHello.
- **V4 bad-version-tls10**: hand-built ClientHello with legacy version
  0x0301 and supported_versions offering only TLS 1.0.
- **V5 bad-keyshare-zero-ek**: hand-built ClientHello, group 0x11ec,
  1216-byte key_share of all zero bytes.
- **V6 empty-close**: connect and close immediately, sending nothing.

The hand-built ClientHellos use the same structure as the real one
(supported_versions, supported_groups, key_share, signature_algorithms)
with a fixed 32-byte random (seed 42). Truncated tests send a 20-byte or
100-byte prefix of the real ClientHello and RST-close.

### What "server reply" means

`no-tls-record` means the server sent no TLS record within the 5 s
observe window (it was still waiting for the rest of the record, or it
closed silently on the RST). It is **not** a crash: after every trial a
legitimate handshake probe is run, and all probes succeeded (see
`evidence-index.md`). `alert level=2 desc=N` is a fatal TLS alert; the
names are from RFC 8446 §6 (e.g. 70 = protocol_version, 40 =
handshake_failure).

## Results (headline)

| Measurement | Run 1 | Run 2 |
|---|---|---|
| ML-KEM-768 keypair mean | 56.63 us | 31.20 us |
| ML-KEM-768 encaps mean | 19.79 us | 20.11 us |
| ML-KEM-768 decaps mean | 25.63 us | 25.28 us |
| Full KEM round mean | 102.05 us | 76.59 us |
| Shared-secret mismatches | 0 / 200 | 0 / 200 |
| Hybrid handshake median (n=30) | 18.00 ms | 17.00 ms |
| Fallback handshake median (n=30) | 15.00 ms | 15.00 ms |
| Hybrid handshake failures | 0 / 30 | 0 / 30 |
| Fallback handshake failures | 0 / 30 | 0 / 30 |
| ClientHello total bytes, hybrid / fallback | 1378 / 202 | 1378 / 202 |
| key_share bytes, hybrid / fallback | 1216 / 32 | 1216 / 32 |
| Server CPU per handshake, hybrid | 2.26 ms | 2.58 ms |
| Server CPU per handshake, fallback | 1.94 ms | 2.26 ms |
| Flood success (n=200, concurrency 10) | 200 / 200 | 200 / 200 |
| Flood median latency | 117.2 ms | 118.7 ms |
| Flood server CPU per attempt | 2.70 ms | 2.70 ms |
| Flood server RSS delta | 0 KiB | 0 KiB |
| Slow-loris: legitimate handshake during 30-stall hold | TIMEOUT (10,006 ms) | TIMEOUT (10,007 ms) |
| Slow-loris: stalls still open after 30 s hold | 30 / 30 | 30 / 30 |
| Slow-loris: legitimate handshake after release | ok, 20.4 ms | ok, 35.8 ms |
| Malformed trials, server alive after every trial | 60 / 60 | 60 / 60 |
| Truncated trials, server alive after every trial | 20 / 20 | 20 / 20 |

### Reading the numbers

- **Hybrid costs about +2–3 ms per handshake** over the classical
  fallback at the median (+20.0% run 1, +13.3% run 2). The ML-KEM-768
  decaps itself is ~26 us; the rest of the delta is the 1216-byte
  key_share (vs 32 bytes), the extra keypair generation, and process
  spawn jitter. The measured handshake times include `s_client` spawn
  (~2–4 ms), so the server-side share of the delta is best read from
  the server CPU figures: +0.32 ms (run 1) / +0.32 ms (run 2) per
  handshake for the hybrid.
- **Flood latency is dominated by queueing, not crypto.** Flood median
  latency (~118 ms) is ~7x the single-handshake median (~17–18 ms)
  because 10 concurrent clients queue on the single-threaded server;
  server CPU per attempt (2.70 ms) is close to the baseline server CPU
  (2.26–2.58 ms). Throughput was ~78 handshakes/s at concurrency 10
  with zero failures — the server degraded gracefully (slow, not dead).
- **One stalled partial handshake blocks the whole test server.**
  During the 30-stall hold a legitimate handshake timed out at the
  10 s probe limit in both runs, and all 30 stalls were still open
  after 30 s (the server holds no handshake timeout of its own in this
  configuration). After the stalls were released the next handshake
  succeeded in 20.4 / 35.8 ms and the server was fully usable. This is
  the single-threaded-`s_server` property noted above, not a
  production-server result — but it is exactly the failure mode a
  migration plan must budget a mitigation for (handshake timeout,
  per-IP limits, or a concurrent server).
- **Malformed input never killed the server.** All six variants in both
  runs (120 trials) ended with either a fatal alert (V4
  `protocol_version`, V5 `handshake_failure`) or silence, and the
  following probe always succeeded. The server did log 41
  `ssl3_read_n:unexpected eof while reading` errors per adversarial run
  (visible in `outputs/adversarial-run1.log` / `run2.log`) — errors, not
  a crash.
- **Keypair timing is noisy on first use.** ML-KEM-768 keypair mean was
  56.63 us in run 1 (max 7474.45 us, a first-call outlier) vs 31.20 us
  in run 2 (max 2430.83 us). Encaps/decaps are stable (~20 / ~25 us).
  Do not quote the keypair mean as a tight figure; the medians are not
  recorded by the harness (see Limitation L4).

## Reproduction

`scripts/clean_reproduce.sh` rebuilds the pinned stack from
`fixtures/` into a throwaway directory, regenerates certificates,
re-runs the full suite with a `fresh-clone-` filename prefix, and
compares re-derived headline numbers against the shipped ones
(tolerances: KEM encaps/decaps means within 25%, handshake medians within
25% or 5 ms, flood median within 50% or 20 ms, exact match for failure
counts, key_share lengths, and slow-loris outcomes; the keypair mean is
outlier-sensitive and is compared by its min within 25% and its mean
within 2x — see limitation L4). Its output is
`outputs/fresh-clone-compare.txt`; the fresh logs are
`outputs/fresh-clone-*.log` / `*.csv`. `scripts/verify_digests.sh`
checks every shipped file against `SHA256SUMS`.

## Limitations

- **L1 — Single-threaded test server.** All load and stall results are
  properties of `openssl s_server` in this configuration. Production
  servers differ; re-measure stall/flood behaviour on the production
  stack before setting timeouts or limits from these numbers.
- **L2 — Classical certificate.** The served certificate is ECDSA P-384.
  OpenSSL 3.0.13 cannot serve an ML-DSA-65 certificate (see the
  lattice-integration pack, finding B-1: "ca md too weak", then "unknown
  certificate type"). Signature-side post-quantum migration is out of
  scope here; only the key exchange is hybrid.
- **L3 — Localhost only, small N.** 30 handshakes per baseline, 200 per
  flood, 10 trials per malformed variant, 30 stalls. No WAN latency,
  no real client diversity, no long soak. Treat the medians as
  order-of-magnitude guidance for capacity planning, not as SLAs.
- **L4 — No per-operation medians in bench_kem.** The harness prints
  mean/min/max only; the keypair mean is outlier-sensitive (see above).
  Encaps/decaps means are stable across runs and are the figures to
  quote.
- **L5 — One optimized build only.** No reference-vs-optimized
  comparison in this pack; the lattice-integration pack covers that
  axis. All timings are for `OQS_OPT_TARGET=auto`.
- **L6 — Harness timing includes process spawn.** Baseline handshake
  times include `openssl s_client` process spawn (~2–4 ms). Cross-label
  comparisons are valid (same harness); absolute times are not
  server-only times. Use the server CPU figures for the server-side
  share.
- **L7 — Slow-loris hold is 30 s, stalls are silent.** The stalls send
  a 5-byte record header claiming 512 bytes and then nothing. A real
  slow-loris client might trickle bytes; that variant was not tested.
- **L8 — No TLS 1.2 / no client certificates.** Only TLS 1.3,
  server-authenticated, no client certificates, no session resumption
  measurements in this pack.
