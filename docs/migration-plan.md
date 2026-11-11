# Hybrid Key-Exchange Migration Plan

## Scope

This plan covers migrating a TLS 1.3 deployment from classical X25519 to
the hybrid X25519MLKEM768 key exchange, using only the measurements in
this pack. **Guidance** (unmeasured recommendations, marked as such) is
kept separate from **measured** facts; every measured claim points to its
log in `evidence-index.md`. The plan assumes the production server is a
concurrent TLS implementation, not the single-threaded `openssl s_server`
used for measurement — see Limitation L1 in `methodology.md`.

## Measured facts the plan rests on

- **M1.** Hybrid handshake median 17–18 ms vs fallback 15 ms (n=30 each,
  0 failures): +2–3 ms, +13–20% at the median.
  (`outputs/baseline-hybrid-run*.log`, `outputs/baseline-fallback-run*.log`)
- **M2.** Hybrid ClientHello 1378 bytes vs fallback 202 bytes; key_share
  1216 bytes vs 32 bytes (group 0x11ec vs 0x001d).
  (`outputs/baseline-*-run1.log`, `trace:` lines)
- **M3.** Server CPU per handshake: hybrid 2.26–2.58 ms, fallback
  1.94–2.26 ms (+0.32 ms for the hybrid in both runs). Flood server CPU
  2.70 ms per attempt at concurrency 10.
  (`outputs/baseline-*-run*.log`, `outputs/adversarial-run*-flood-summary.txt`)
- **M4.** Flood (200 handshakes, concurrency 10): 200/200 success both
  runs, ~78 handshakes/s, median latency ~118 ms (queueing on the
  single-threaded test server), RSS delta 0 KiB.
  (`outputs/adversarial-run*-flood.csv`, `*-flood-summary.txt`)
- **M5.** Slow-loris (30 stalled partial handshakes, 30 s hold):
  legitimate handshake TIMED OUT at 10 s during the hold in both runs;
  30/30 stalls still open after 30 s; handshake succeeded 20.4 /
  35.8 ms after release; server CPU delta ~0.01 s, RSS unchanged.
  (`outputs/adversarial-run*-slowloris-summary.txt`)
- **M6.** Malformed ClientHello (6 variants x 10 trials x 2 runs) and
  truncated handshakes (2 prefixes x 10 trials x 2 runs): the server
  always answered with a fatal alert (`protocol_version` for TLS 1.0,
  `handshake_failure` for a zero key_share) or silence, and stayed alive
  — 160/160 post-trial probes succeeded.
  (`outputs/adversarial-run*-malformed.csv`, `*-truncated.csv`)
- **M7.** ML-KEM-768 primitives (liboqs 0.16.0, optimized): encaps
  ~20 us, decaps ~25 us, keypair mean 31–57 us (outlier-sensitive);
  sizes match FIPS 203 Table 3 exactly; 0/200 shared-secret mismatches.
  (`outputs/bench-kem-run*.log`)

## Rollout stages

### Stage 0 — Preconditions (guidance)

1. Pin the stack: OpenSSL 3.0.13 (or newer, re-measured), liboqs 0.16.0,
   oqs-provider 0.12.0, group X25519MLKEM768. Record the provider
   SHA256 in the deployment record, as this pack does.
2. Re-run this pack's suite against the **production server software**
   (not `s_server`) at production concurrency before setting any
   timeout or limit from M4/M5 — those numbers are test-deployment
   properties.
3. Confirm middlebox tolerance for a 1378-byte ClientHello (M2):
   some middleboxes and load balancers truncate or drop large
   ClientHellos. Test the actual network path with the real ClientHello
   (the capture in `outputs/adversarial-run1-clienthello.bin` is 1383
   bytes on the wire). **Guidance:** if the path drops large
   ClientHellos, do not proceed past Stage 1 until the path is fixed or
   an exception is recorded.

### Stage 1 — Canary: hybrid preferred, classical fallback enabled

- Configure the server to offer X25519MLKEM768 first and X25519 second,
  and the client to offer both. Negotiate hybrid when both ends support
  it; fall back to X25519 otherwise. No client is ever left without a
  working handshake.
- Roll out to a small canary population (guidance: 1–5% of traffic, or
  one canary fleet) and watch the monitoring signals in the next
  section for at least one full traffic cycle.
- **Measured expectation:** median handshake latency rises ~2–3 ms
  (M1) and server CPU per handshake rises ~0.32 ms (M3). Budget
  capacity for roughly +15–20% handshake CPU at the same connection
  rate; the ML-KEM operations themselves are ~50 us of that (M7).

### Stage 2 — Broad rollout

- Extend the hybrid preference to all traffic once the canary meets the
  rollback criteria below (none triggered) for the full observation
  window. Keep X25519 in the offered list — it is the fallback, not a
  legacy to remove yet.
- **Guidance:** announce the change to relying parties that pin
  ClientHello sizes or negotiate groups explicitly; a 1378-byte
  ClientHello (M2) can break clients or intermediaries with fixed-size
  buffers.

### Stage 3 — Hybrid-only (optional, later)

- Remove X25519 from the offered groups only after every supported
  client negotiates the hybrid (measured from server logs, not assumed)
  and after a documented decision that classical-only peers are out of
  support. **Guidance:** do not set a date for this stage now; it
  depends on client adoption that this pack does not measure.

## Fallback policy

- **Automatic, per-handshake.** If either peer does not offer
  X25519MLKEM768, the handshake negotiates X25519 (M1/M2 show the
  fallback is healthy: 0/30 failures, 15 ms median). The fallback is
  not an error condition and must not page.
- **No downgrade to TLS 1.2 or to a weaker group.** A peer offering
  only TLS 1.0 receives a `protocol_version` alert (M6, variant V4) —
  that is the correct behaviour; do not add a compatibility path for
  it.
- **A zero or malformed key_share is a fatal alert, not a retry.**
  The server answers `handshake_failure` (M6, variant V5); clients
  must not retry the same malformed offer in a loop.
- **Fallback monitoring:** alert (not page) if the hybrid negotiation
  rate drops below the canary baseline by more than 10 points for
  15 minutes — that signals a middlebox or client regression, not
  normal variation. **Guidance:** thresholds are illustrative; set
  them from the canary's own baseline.

## Rollback criteria

Roll back Stage 1 or Stage 2 (restore X25519-first ordering, or disable
the hybrid group) if any of the following is observed during the
observation window:

1. **Handshake failure rate** above 1% for hybrid negotiations over any
   5-minute window (measured baseline: 0/30 and 200/200, M1/M4).
2. **Median handshake latency** more than 10 ms above the pre-rollout
   baseline over any 15-minute window (measured delta: +2–3 ms, M1).
   The 10 ms bound leaves room for the measured delta plus jitter;
   tighten it after the canary.
3. **Server CPU per handshake** more than 1 ms above baseline (measured
   delta: +0.32 ms, M3).
4. **ClientHello-size failures**: any confirmed case of a peer or
   middlebox dropping the 1378-byte ClientHello (M2). Even one confirmed
   case pauses the rollout for that path.
5. **Stall-related unavailability**: any incident where stalled partial
   handshakes block legitimate handshakes (the failure mode measured in
   M5 — the test server blocked completely; the production server must
   be shown not to, per Stage 0 step 2, before Stage 2).

Rollback is a configuration change only (group ordering / offered
groups); no code deploy and no certificate change is required, because
the certificate is classical ECDSA P-384 and unchanged by this plan.

## Monitoring signals

Collect these from the production server (not from this harness):

| Signal | Why | Measured reference |
|---|---|---|
| Handshake success rate by negotiated group | Detects a hybrid-specific failure mode | 0 failures in 60 hybrid + 60 fallback baselines; 200/200 flood |
| Handshake latency percentiles (p50/p95/p99) by group | Detects the +2–3 ms delta growing under load | hybrid median 17–18 ms, fallback 15 ms |
| Server CPU per handshake by group | Capacity planning; the hybrid adds ~0.32 ms | 2.26–2.58 ms hybrid vs 1.94–2.26 ms fallback |
| ClientHello size distribution / drops | The 1378-byte ClientHello is the largest new failure surface | 1378 B hybrid vs 202 B fallback |
| Negotiated-group mix (hybrid vs fallback share) | Detects client/middlebox regression | — (guidance; not measured here) |
| Half-open / stalled handshake count and age | The slow-loris failure mode (M5) must be visible before it becomes an outage | 30 stalls blocked the test server for the full 30 s hold |
| Handshake timeouts and alert counts by type | `protocol_version` / `handshake_failure` rates show malformed-input pressure | V4 → alert 70, V5 → alert 40, 10/10 each |
| Memory (RSS) per worker over a soak | Confirms no per-handshake growth | 0 KiB delta over 200 flood handshakes |

## Mitigations for the slow-loris finding (M5)

The measured failure — one stalled partial handshake blocking the
whole test server — must be mitigated in production regardless of
whether the production server is single-threaded. **Guidance**
(unmeasured here; verify on the production stack):

1. **Handshake timeout**: close handshakes that do not complete within
   a short bound (e.g. 5–10 s). The test server held stalls for the
   full 30 s with no timeout of its own.
2. **Per-IP / per-client connection limits** on half-open handshakes.
3. **Prefer a concurrent server**: a thread-per-connection or
   event-driven server bounds the blast radius of a stall to one
   worker, not the whole endpoint.
4. **Alert on half-open handshake age**, not only on count, so a
   slow build-up is visible.

## What this plan does not cover

- **Signature migration.** The certificate stays ECDSA P-384. Moving
  to ML-DSA certificates is a separate workstream (OpenSSL 3.0.13
  cannot serve ML-DSA-65 certificates — Limitation L2).
- **Client-side rollout.** Only the server side is measured here.
- **Long-term key management / rotation.** See the release-signing
  assessment for key lifecycle; this pack measures the handshake only.
- **WAN / middlebox behaviour.** Only localhost was measured. Stage 0
  step 3 is mandatory.
