/*
 * xmss_sign_ref.c - Reverse-direction cross-verify signer.
 *
 * Counterpart to xmss_sign.go: instead of go-qrllib producing a
 * signature for the reference to verify, here the reference produces
 * a signature for go-qrllib to verify (via the rfc8391 sub-package).
 *
 * Determinism: the reference is pinned to commit `7793c40` — the last
 * revision on the original RFC 8391 expand_seed construction, which
 * is the construction QRL XMSS implements (see SECURITY.md
 * "Parameter-set provenance"). At this pin the reference does not
 * yet expose a public seeded-keypair API, so we override
 * `randombytes()` with an implementation that consumes a fixed
 * 96-byte buffer in order. `xmssmt_core_keypair` then makes two calls
 * (64 bytes for SK_SEED || SK_PRF, then 32 bytes for PUB_SEED) which
 * matches the 96-byte expanded-seed convention QRL's
 * `crypto/xmss/rfc8391.NewKeyPair` uses on the Go side. The link
 * command for this file therefore omits the upstream `randombytes.c`
 * to avoid duplicate-symbol errors; `xmss_verify_ref.c` still
 * includes it.
 *
 * Compile (note: no randombytes.c):
 *   gcc -I. -o xmss_sign_ref xmss_sign_ref.c \
 *       params.c hash.c hash_address.c utils.c \
 *       wots.c xmss.c xmss_commons.c xmss_core.c -lcrypto
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "xmss.h"

#define XMSS_SHA2_10_256_OID 0x00000001
#define EXPANDED_SEED_BYTES  96

/* ---------- deterministic randombytes override ----------
 * The pinned reference's xmssmt_core_keypair calls randombytes() twice:
 *   randombytes(sk + index_bytes,        2 * n);   // SK_SEED || SK_PRF
 *   randombytes(sk + index_bytes + 3*n,      n);   // PUB_SEED
 * Sequential consumption of a 96-byte buffer laid out as
 * [SK_SEED | SK_PRF | PUB_SEED] therefore reproduces the 96-byte
 * expanded-seed semantics QRL's rfc8391.NewKeyPair uses. */
static const unsigned char *g_seed_buf;
static size_t               g_seed_pos;
static size_t               g_seed_len;

void randombytes(unsigned char *x, unsigned long long xlen) {
    if (g_seed_pos + (size_t)xlen > g_seed_len) {
        fprintf(stderr,
                "deterministic randombytes underrun: pos=%zu xlen=%llu len=%zu\n",
                g_seed_pos, (unsigned long long)xlen, g_seed_len);
        exit(2);
    }
    memcpy(x, g_seed_buf + g_seed_pos, (size_t)xlen);
    g_seed_pos += (size_t)xlen;
}

int main(void) {
    /* The same deterministic 96-byte expanded seed that xmss_verify.go
     * will pass into rfc8391.NewKeyPair on the go-qrllib side. */
    unsigned char expanded_seed[EXPANDED_SEED_BYTES];
    for (size_t i = 0; i < EXPANDED_SEED_BYTES; i++) {
        expanded_seed[i] = (unsigned char)i;
    }
    g_seed_buf = expanded_seed;
    g_seed_pos = 0;
    g_seed_len = EXPANDED_SEED_BYTES;

    xmss_params params;
    if (xmss_parse_oid(&params, XMSS_SHA2_10_256_OID) != 0) {
        fprintf(stderr, "xmss_parse_oid failed\n");
        return 1;
    }

    unsigned char  pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char *sk = calloc(1, XMSS_OID_LEN + params.sk_bytes);
    if (!sk) { fprintf(stderr, "alloc fail\n"); return 1; }

    /* xmss_keypair is the public API; it writes the OID prefix, then
     * dispatches to xmss_core_keypair → xmssmt_core_keypair, which
     * calls our deterministic randombytes. The resulting (pk, sk) is
     * therefore deterministic in the 96-byte expanded seed. */
    if (xmss_keypair(pk, sk, XMSS_SHA2_10_256_OID) != 0) {
        fprintf(stderr, "xmss_keypair failed\n");
        free(sk);
        return 1;
    }

    unsigned char msg[64];
    memcpy(msg, "XMSS reference -> go-qrllib bidirectional verification", 54);
    size_t msglen = 54;

    unsigned char *sm = malloc(params.sig_bytes + msglen);
    if (!sm) { fprintf(stderr, "alloc fail\n"); free(sk); return 1; }
    unsigned long long smlen;
    if (xmss_sign(sk, sm, &smlen, msg, msglen) != 0) {
        fprintf(stderr, "xmss_sign failed\n");
        free(sk);
        free(sm);
        return 1;
    }

    /* xmss_sign emits sig || msg; split sig out for the verifier. */
    size_t siglen = (size_t)(smlen - msglen);

    /* Write the artefacts the go-qrllib verifier needs. The pk is
     * written WITHOUT the OID prefix (just root || pub_seed) because
     * that's what go-qrllib's internal pk format consumes;
     * rfc8391.UnmarshalPublicKey gets the full RFC 8391 layout
     * (OID || root || pub_seed) so we write that too. */
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
    fwrite(sm, 1, siglen, f);
    fclose(f);

    f = fopen("/tmp/xmss_ref_msg.bin", "wb");
    if (!f) { fprintf(stderr, "open xmss_ref_msg.bin\n"); return 1; }
    fwrite(msg, 1, msglen, f);
    fclose(f);

    f = fopen("/tmp/xmss_ref_expanded_seed.bin", "wb");
    if (!f) { fprintf(stderr, "open xmss_ref_expanded_seed.bin\n"); return 1; }
    fwrite(expanded_seed, 1, EXPANDED_SEED_BYTES, f);
    fclose(f);

    printf("Reference XMSS-SHA2_10_256 signer (pre-SP-800-208 pin):\n");
    printf("  PK size (root||pub_seed):       %u bytes\n", params.pk_bytes);
    printf("  PK size (OID||root||pub_seed):  %u bytes\n",
           (unsigned)(XMSS_OID_LEN + params.pk_bytes));
    printf("  Sig size:                       %zu bytes\n", siglen);
    printf("  Msg size:                       %zu bytes\n", msglen);
    printf("  Expanded seed size:             %d bytes\n", EXPANDED_SEED_BYTES);

    free(sk);
    free(sm);
    return 0;
}
