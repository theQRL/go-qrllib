/*
 * falcon1024_crossverify_ref.c - Cross-verify go-qrllib Falcon-1024 against
 * PQClean's falcon-1024 "clean" implementation (the round-3 reference code).
 *
 * Compile from the PQClean checkout root, without common/randombytes.c:
 *   gcc -std=c99 -O2 -Icrypto_sign/falcon-1024/clean -Icommon \
 *       falcon1024_crossverify_ref.c \
 *       crypto_sign/falcon-1024/clean/codec.c crypto_sign/falcon-1024/clean/common.c \
 *       crypto_sign/falcon-1024/clean/fft.c crypto_sign/falcon-1024/clean/fpr.c \
 *       crypto_sign/falcon-1024/clean/keygen.c crypto_sign/falcon-1024/clean/pqclean.c \
 *       crypto_sign/falcon-1024/clean/rng.c crypto_sign/falcon-1024/clean/sign.c \
 *       crypto_sign/falcon-1024/clean/vrfy.c common/fips202.c
 *
 * randombytes() is defined here as a SHAKE256 stream over a fixed label, the
 * same stream the Go program (falcon1024_crossverify.go) draws from, so the
 * two implementations must produce byte-identical keys and signatures.
 *
 * Usage: falcon1024_ref <go-qrllib file> <output file>
 *   1. Reads the go-qrllib file, regenerates every entry from the same stream,
 *      compares byte for byte, and opens/verifies go-qrllib's outputs.
 *   2. Generates its own entries from the second stream into the output file
 *      for go-qrllib to regenerate, compare, open and verify.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "fips202.h"
#include "randombytes.h"

#define ENTRIES   8
#define PK_LEN    PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#define SK_LEN    PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES
#define SIG_MAX   PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES
#define MSG_MAX   (33 * ENTRIES)

static const char LABEL_GO[]  = "go-qrllib Falcon-1024 cross-verification: go-qrllib generates";
static const char LABEL_REF[] = "go-qrllib Falcon-1024 cross-verification: PQClean generates";

/* Deterministic randombytes() over SHAKE256(label), replacing common/randombytes.c. */
static shake256incctx drbg;

int randombytes(uint8_t *output, size_t n) {
    shake256_inc_squeeze(output, n, &drbg);
    return 0;
}

static void drbg_seed(const char *label) {
    shake256_inc_init(&drbg);
    shake256_inc_absorb(&drbg, (const uint8_t *)label, strlen(label));
    shake256_inc_finalize(&drbg);
}

typedef struct {
    uint8_t pk[PK_LEN];
    uint8_t sk[SK_LEN];
    uint8_t msg[MSG_MAX];
    size_t msglen;
    uint8_t sm[MSG_MAX + SIG_MAX];
    size_t smlen;
    uint8_t sig[SIG_MAX];
    size_t siglen;
} entry;

static int fail(const char *what, int i) {
    printf("FAIL: entry %d: %s\n", i, what);
    return 1;
}

/* Generates ENTRIES entries from the current stream, self-verifying each. */
static int generate(entry *es) {
    for (int i = 0; i < ENTRIES; i++) {
        entry *e = &es[i];
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(e->pk, e->sk) != 0) {
            return fail("crypto_sign_keypair failed", i);
        }
        e->msglen = 33 * (size_t)(i + 1);
        randombytes(e->msg, e->msglen);
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign(e->sm, &e->smlen, e->msg, e->msglen, e->sk) != 0) {
            return fail("crypto_sign failed", i);
        }
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(e->sig, &e->siglen, e->msg, e->msglen, e->sk) != 0) {
            return fail("crypto_sign_signature failed", i);
        }
        uint8_t m[MSG_MAX];
        size_t mlen;
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(m, &mlen, e->sm, e->smlen, e->pk) != 0
                || mlen != e->msglen || memcmp(m, e->msg, mlen) != 0) {
            return fail("self-check of the signed message failed", i);
        }
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(e->sig, e->siglen, e->msg, e->msglen, e->pk) != 0) {
            return fail("self-check of the detached signature failed", i);
        }
    }
    return 0;
}

static int write_field(FILE *f, const uint8_t *p, size_t n) {
    uint8_t len[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
    return fwrite(len, 1, 4, f) == 4 && fwrite(p, 1, n, f) == n ? 0 : 1;
}

static int read_field(FILE *f, uint8_t *p, size_t max, size_t *n) {
    uint8_t len[4];
    if (fread(len, 1, 4, f) != 4) {
        return 1;
    }
    *n = ((size_t)len[0] << 24) | ((size_t)len[1] << 16) | ((size_t)len[2] << 8) | (size_t)len[3];
    if (*n > max) {
        return 1;
    }
    return fread(p, 1, *n, f) == *n ? 0 : 1;
}

static int write_entries(const char *path, const entry *es) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        printf("FAIL: cannot write %s\n", path);
        return 1;
    }
    for (int i = 0; i < ENTRIES; i++) {
        const entry *e = &es[i];
        if (write_field(f, e->pk, PK_LEN) || write_field(f, e->sk, SK_LEN)
                || write_field(f, e->msg, e->msglen) || write_field(f, e->sm, e->smlen)
                || write_field(f, e->sig, e->siglen)) {
            fclose(f);
            printf("FAIL: cannot write %s\n", path);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int read_entries(const char *path, entry *es) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("FAIL: cannot read %s\n", path);
        return 1;
    }
    for (int i = 0; i < ENTRIES; i++) {
        entry *e = &es[i];
        size_t n;
        if (read_field(f, e->pk, PK_LEN, &n) || n != PK_LEN
                || read_field(f, e->sk, SK_LEN, &n) || n != SK_LEN
                || read_field(f, e->msg, MSG_MAX, &e->msglen)
                || read_field(f, e->sm, sizeof e->sm, &e->smlen)
                || read_field(f, e->sig, SIG_MAX, &e->siglen)) {
            fclose(f);
            printf("FAIL: malformed %s\n", path);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* Regenerates go-qrllib's entries from its stream and compares byte for byte. */
static int check(const entry *theirs) {
    static entry ours[ENTRIES];
    drbg_seed(LABEL_GO);
    if (generate(ours)) {
        return 1;
    }
    for (int i = 0; i < ENTRIES; i++) {
        const entry *a = &ours[i], *b = &theirs[i];
        if (memcmp(a->pk, b->pk, PK_LEN) != 0) {
            return fail("public key differs from go-qrllib's", i);
        }
        if (memcmp(a->sk, b->sk, SK_LEN) != 0) {
            return fail("private key differs from go-qrllib's", i);
        }
        if (a->msglen != b->msglen || memcmp(a->msg, b->msg, a->msglen) != 0) {
            return fail("message differs from go-qrllib's", i);
        }
        if (a->smlen != b->smlen || memcmp(a->sm, b->sm, a->smlen) != 0) {
            return fail("signed message differs from go-qrllib's", i);
        }
        if (a->siglen != b->siglen || memcmp(a->sig, b->sig, a->siglen) != 0) {
            return fail("detached signature differs from go-qrllib's", i);
        }

        uint8_t m[MSG_MAX];
        size_t mlen;
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_open(m, &mlen, b->sm, b->smlen, b->pk) != 0
                || mlen != b->msglen || memcmp(m, b->msg, mlen) != 0) {
            return fail("crypto_sign_open rejected go-qrllib's signed message", i);
        }
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(b->sig, b->siglen, b->msg, b->msglen, b->pk) != 0) {
            return fail("crypto_sign_verify rejected go-qrllib's detached signature", i);
        }
        uint8_t tampered[MSG_MAX];
        memcpy(tampered, b->msg, b->msglen);
        tampered[0] ^= 1;
        if (PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(b->sig, b->siglen, tampered, b->msglen, b->pk) == 0) {
            return fail("crypto_sign_verify accepted go-qrllib's signature for a different message", i);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    static entry theirs[ENTRIES], ours[ENTRIES];
    if (argc != 3) {
        printf("usage: falcon1024_ref <go-qrllib file> <output file>\n");
        return 2;
    }

    if (read_entries(argv[1], theirs) || check(theirs)) {
        return 1;
    }
    printf("PQClean falcon-1024 <- go-qrllib: %d entries PASSED\n", ENTRIES);
    printf("  - same stream -> identical public key, private key, signed message and detached signature\n");
    printf("  - go-qrllib signed message opens under PQClean\n");
    printf("  - go-qrllib detached signature verifies under PQClean, and not for a different message\n");

    drbg_seed(LABEL_REF);
    if (generate(ours) || write_entries(argv[2], ours)) {
        return 1;
    }
    printf("PQClean falcon-1024: wrote %d entries to %s\n", ENTRIES, argv[2]);
    return 0;
}
