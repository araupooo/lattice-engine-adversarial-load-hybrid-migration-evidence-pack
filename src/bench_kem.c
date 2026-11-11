/* bench_kem.c — ML-KEM-768 liboqs-level check for the adversarial-load pack.
 *
 * Asserts the FIPS 203 Table 3 sizes for ML-KEM-768 (ek 1184, dk 2400,
 * ct 1088, ss 32), then times keypair / encaps / decaps over N iterations
 * and verifies shared-secret equality on every iteration. This is the
 * crypto-layer reference point for the TLS-layer measurements: the per-
 * handshake CPU cost measured at the server includes one server-side
 * decaps (plus one keypair) per hybrid handshake.
 * Usage: bench_kem [iterations]   (default 200)
 * Compile: cc -O2 -I<liboqs include> bench_kem.c -L<liboqs lib> -loqs -o bench_kem
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <oqs/oqs.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

typedef struct { double total_s, min_us, max_us; int n; } Stats;
static void s_init(Stats *s) { s->total_s = 0; s->min_us = 1e18; s->max_us = 0; s->n = 0; }
static void s_add(Stats *s, double dt) {
    double us = dt * 1e6;
    s->total_s += dt;
    if (us < s->min_us) s->min_us = us;
    if (us > s->max_us) s->max_us = us;
    s->n++;
}
static void s_print(const char *label, const Stats *s) {
    printf("%-28s n=%-5d mean=%9.2f us  min=%9.2f us  max=%9.2f us  rate=%9.2f ops/s\n",
           label, s->n, s->total_s * 1e6 / s->n, s->min_us, s->max_us, s->n / s->total_s);
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 200;
    printf("bench_kem: ML-KEM-768 throughput + size check\n");
    printf("liboqs version: %s\n", OQS_VERSION_TEXT);
    printf("iterations: %d\n", n);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) { fprintf(stderr, "FATAL: OQS_KEM_new(ML-KEM-768) failed\n"); return 1; }
    printf("[KEM] algorithm: %s\n", kem->method_name);
    printf("[KEM] length_public_key=%zu (FIPS 203 Table 3: 1184) %s\n",
           kem->length_public_key, kem->length_public_key == 1184 ? "OK" : "MISMATCH");
    printf("[KEM] length_secret_key=%zu (FIPS 203 Table 3: 2400) %s\n",
           kem->length_secret_key, kem->length_secret_key == 2400 ? "OK" : "MISMATCH");
    printf("[KEM] length_ciphertext=%zu (FIPS 203 Table 3: 1088) %s\n",
           kem->length_ciphertext, kem->length_ciphertext == 1088 ? "OK" : "MISMATCH");
    printf("[KEM] length_shared_secret=%zu (FIPS 203 Table 3: 32) %s\n",
           kem->length_shared_secret, kem->length_shared_secret == 32 ? "OK" : "MISMATCH");

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_e = malloc(kem->length_shared_secret);
    uint8_t *ss_d = malloc(kem->length_shared_secret);
    if (!pk || !sk || !ct || !ss_e || !ss_d) { fprintf(stderr, "FATAL: malloc\n"); return 1; }

    Stats kg, enc, dec;
    s_init(&kg); s_init(&enc); s_init(&dec);
    int ss_mismatch = 0;
    for (int i = 0; i < n; i++) {
        double t0 = now_s();
        if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: keypair\n"); return 1; }
        s_add(&kg, now_s() - t0);
        t0 = now_s();
        if (OQS_KEM_encaps(kem, ct, ss_e, pk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: encaps\n"); return 1; }
        s_add(&enc, now_s() - t0);
        t0 = now_s();
        if (OQS_KEM_decaps(kem, ss_d, ct, sk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: decaps\n"); return 1; }
        s_add(&dec, now_s() - t0);
        if (memcmp(ss_e, ss_d, kem->length_shared_secret) != 0) ss_mismatch++;
    }
    s_print("ML-KEM-768 keypair", &kg);
    s_print("ML-KEM-768 encaps", &enc);
    s_print("ML-KEM-768 decaps", &dec);
    printf("shared-secret mismatches: %d / %d\n", ss_mismatch, n);
    printf("full KEM round (keypair+encaps+decaps) mean: %.2f us\n",
           (kg.total_s + enc.total_s + dec.total_s) * 1e6 / n);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("peak RSS: %ld KiB\n", ru.ru_maxrss);
    printf("bench_kem: DONE\n");
    return ss_mismatch ? 1 : 0;
}
