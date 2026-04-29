/*
 * xmss_sign_ref.c - Generate XMSS-SHA2_10_256 signature using the
 * RFC 8391 reference implementation.
 *
 * This is the reverse-direction cross-verify counterpart to the
 * existing xmss_sign.go: instead of go-qrllib producing a signature
 * for the reference to verify, here the *reference* produces a
 * signature for go-qrllib to verify (via the rfc8391 sub-package).
 *
 * The reference implementation's public xmss_keypair() takes no seed
 * parameter, so we call the lower-level xmss_core_seed_keypair()
 * directly. This is the same entry point the go-qrllib
 * crypto/xmss/rfc8391 sub-package mirrors (NewKeyPair takes 96 bytes
 * directly, bypassing QRL's 48-byte SHAKE256 expansion).
 *
 * Both sides should produce the SAME public key from the same 96-byte
 * seed; that is the property the xmss_verify.go round-trip test
 * checks.
 *
 * Compile: gcc -I. -o xmss_sign_ref xmss_sign_ref.c \
 *     params.c hash.c hash_address.c randombytes.c utils.c \
 *     wots.c xmss.c xmss_commons.c xmss_core.c -lcrypto
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "xmss.h"
#include "xmss_core.h"

/* XMSS-SHA2_10_256 parameter set */
#define XMSS_SHA2_10_256_OID 0x00000001
#define PARAM_N 32
#define PARAM_HEIGHT 10
#define EXPANDED_SEED_BYTES (3 * PARAM_N)                        /* 96 */
#define REF_PK_BYTES        (4 + 2 * PARAM_N)                    /* 68 */
#define REF_SK_BYTES        (4 + 4 * PARAM_N + 4 + 2 * PARAM_N)  /* 4+128+4+64 = 200 (oid+sk_inner+...) */
#define REF_SIG_BYTES       (4 + PARAM_N + 67 * PARAM_N + PARAM_HEIGHT * PARAM_N) /* 2500 */

int main(void) {
    /* The same deterministic 96-byte expanded seed that xmss_verify.go
     * will pass into rfc8391.NewKeyPair on the go-qrllib side. */
    uint8_t expanded_seed[EXPANDED_SEED_BYTES];
    for (size_t i = 0; i < EXPANDED_SEED_BYTES; i++) {
        expanded_seed[i] = (uint8_t)i;
    }

    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_SHA2_10_256_OID) != 0) {
        fprintf(stderr, "xmss_parse_oid failed\n");
        return 1;
    }

    /* Reference SK has an OID prefix and a randomness suffix; we need
     * params.sk_bytes + 4 bytes for the OID. The reference's
     * xmss_keypair() entry point handles the OID prefix itself, but
     * xmss_core_seed_keypair() does not — it just writes the inner
     * sk. We allocate enough for the full sk and write the OID prefix
     * manually to keep the file format compatible with reference
     * xmss_sign(). */
    unsigned char *sk = calloc(1, params.sk_bytes + XMSS_OID_LEN);
    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    if (!sk) { fprintf(stderr, "alloc fail\n"); return 1; }

    /* Write OID prefixes. */
    for (int i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (XMSS_SHA2_10_256_OID >> (8 * i)) & 0xff;
        sk[XMSS_OID_LEN - i - 1] = (XMSS_SHA2_10_256_OID >> (8 * i)) & 0xff;
    }

    if (xmss_core_seed_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN, expanded_seed) != 0) {
        fprintf(stderr, "xmss_core_seed_keypair failed\n");
        free(sk);
        return 1;
    }

    uint8_t msg[64];
    memcpy(msg, "XMSS reference -> go-qrllib bidirectional verification", 54);
    size_t msglen = 54;

    unsigned char *sm = malloc(REF_SIG_BYTES + msglen);
    unsigned long long smlen;
    if (xmss_sign(sk, sm, &smlen, msg, msglen) != 0) {
        fprintf(stderr, "xmss_sign failed\n");
        free(sk);
        free(sm);
        return 1;
    }

    /* xmss_sign emits sig || msg; split sig out for the verifier. */
    size_t siglen = (size_t)(smlen - msglen);
    unsigned char *sig = sm;

    /* Write the artefacts the go-qrllib verifier needs. The pk is
     * written WITHOUT the OID prefix (just root || pub_seed) because
     * that's what xmss.Verify consumes; rfc8391.UnmarshalPublicKey
     * gets the full RFC 8391 layout (OID || root || pub_seed) so we
     * write that too. */
    FILE *f;

    f = fopen("/tmp/xmss_ref_pk.bin", "wb");
    if (!f) { fprintf(stderr, "open xmss_ref_pk.bin\n"); return 1; }
    fwrite(pk + XMSS_OID_LEN, 1, params.pk_bytes, f);
    fclose(f);

    f = fopen("/tmp/xmss_ref_pk_rfc.bin", "wb");
    if (!f) { fprintf(stderr, "open xmss_ref_pk_rfc.bin\n"); return 1; }
    fwrite(pk, 1, XMSS_OID_LEN + params.pk_bytes, f);
    fclose(f);

    f = fopen("/tmp/xmss_ref_sig.bin", "wb");
    if (!f) { fprintf(stderr, "open xmss_ref_sig.bin\n"); return 1; }
    fwrite(sig, 1, siglen, f);
    fclose(f);

    f = fopen("/tmp/xmss_ref_msg.bin", "wb");
    if (!f) { fprintf(stderr, "open xmss_ref_msg.bin\n"); return 1; }
    fwrite(msg, 1, msglen, f);
    fclose(f);

    f = fopen("/tmp/xmss_ref_expanded_seed.bin", "wb");
    if (!f) { fprintf(stderr, "open xmss_ref_expanded_seed.bin\n"); return 1; }
    fwrite(expanded_seed, 1, EXPANDED_SEED_BYTES, f);
    fclose(f);

    printf("Reference XMSS-SHA2_10_256 signer:\n");
    printf("  PK size (root||pub_seed):       %llu bytes\n", (unsigned long long)params.pk_bytes);
    printf("  PK size (OID||root||pub_seed):  %llu bytes\n", (unsigned long long)(XMSS_OID_LEN + params.pk_bytes));
    printf("  Sig size:                       %zu bytes\n", siglen);
    printf("  Msg size:                       %zu bytes\n", msglen);
    printf("  Expanded seed size:             %d bytes\n", EXPANDED_SEED_BYTES);

    free(sk);
    free(sm);
    return 0;
}
