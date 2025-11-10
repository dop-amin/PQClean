#ifndef PQCLEAN_MLDSA44_CLEAN_SIGN_H
#define PQCLEAN_MLDSA44_CLEAN_SIGN_H
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stddef.h>
#include <stdint.h>

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/* Trace structure for capturing intermediate values */
typedef struct {
    int32_t s1[L * N];             /* Secret s1 vector (L polynomials) */
    int32_t s1_ntt[L * N];         /* s1 in NTT domain */
    int32_t y[L * N];              /* Sampled y vector (L polynomials) */
    int32_t y_ntt[L * N];          /* y in NTT domain */
    int32_t c_ntt[N];              /* Challenge c in NTT domain (single polynomial) */
    int32_t cs1_ntt[L * N];        /* c*s1 in NTT domain (before INTT) */
    int32_t cs1[L * N];            /* c*s1 result (L polynomials) */
    int32_t z[L * N];              /* z = y + c*s1 (final masked value) */
    uint8_t challenge[CTILDEBYTES]; /* Challenge c (packed) */
    int rejection_count;           /* Number of rejections before success */
    int success;                   /* 1 if signature succeeded, 0 if failed */
} PQCLEAN_MLDSA44_CLEAN_trace_t;

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx_trace(
        PQCLEAN_MLDSA44_CLEAN_trace_t *trace,
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *sk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);

#endif
