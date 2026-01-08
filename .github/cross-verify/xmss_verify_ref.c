/*
 * xmss_verify_ref.c - Verify go-qrllib XMSS signature with reference implementation
 *
 * This verifier constructs a reference-compatible public key from go-qrllib's
 * pk format and verifies the signature.
 *
 * go-qrllib pk format: [root(32) | pub_seed(32)] = 64 bytes
 * Reference pk format: [OID(4) | root(32) | pub_seed(32)] = 68 bytes
 *
 * go-qrllib sig format: [idx(4) | r(32) | WOTS_SIG(2144) | AUTH(h*32)] = 2500 bytes for h=10
 * Reference sig format: Same (no OID in signature)
 *
 * Compile: gcc -I. -o xmss_verify xmss_verify_ref.c -L. -lxmss -lcrypto
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "xmss.h"

/* XMSS-SHA2_10_256 parameters */
#define XMSS_SHA2_10_256_OID 0x00000001
#define PARAM_N 32
#define PARAM_HEIGHT 10
#define REF_PK_BYTES (4 + 2*PARAM_N)  /* OID + root + pub_seed = 68 */
#define REF_SIG_BYTES (4 + PARAM_N + 67*PARAM_N + PARAM_HEIGHT*PARAM_N) /* 2500 */

int main() {
    uint8_t goqrllib_pk[64];     /* go-qrllib pk: root || pub_seed */
    uint8_t ref_pk[REF_PK_BYTES];  /* reference pk: OID || root || pub_seed */
    uint8_t sig[REF_SIG_BYTES];
    uint8_t msg[256];
    uint8_t msg_out[256 + REF_SIG_BYTES];
    unsigned long long msg_out_len;
    size_t msglen, siglen;
    FILE *f;
    int ret;

    /* Read go-qrllib public key */
    f = fopen("/tmp/xmss_pk.bin", "rb");
    if (!f) { printf("Cannot open pk\n"); return 1; }
    if (fread(goqrllib_pk, 1, 64, f) != 64) {
        printf("Failed to read pk\n"); return 1;
    }
    fclose(f);

    /* Read signature */
    f = fopen("/tmp/xmss_sig.bin", "rb");
    if (!f) { printf("Cannot open sig\n"); return 1; }
    siglen = fread(sig, 1, REF_SIG_BYTES, f);
    fclose(f);

    /* Read message */
    f = fopen("/tmp/xmss_msg.bin", "rb");
    if (!f) { printf("Cannot open msg\n"); return 1; }
    msglen = fread(msg, 1, sizeof(msg), f);
    fclose(f);

    /* Construct reference pk: [OID || root || pub_seed] */
    /* OID for XMSS-SHA2_10_256 is 0x00000001 (big-endian) */
    ref_pk[0] = 0x00;
    ref_pk[1] = 0x00;
    ref_pk[2] = 0x00;
    ref_pk[3] = 0x01;
    memcpy(ref_pk + 4, goqrllib_pk, 64);  /* root || pub_seed */

    printf("XMSS reference (XMSS-SHA2_10_256) verifier:\n");
    printf("  PK size (go-qrllib):  64 bytes\n");
    printf("  PK size (reference):  %d bytes\n", REF_PK_BYTES);
    printf("  Sig size: %zu bytes (expected %d)\n", siglen, REF_SIG_BYTES);
    printf("  Msg size: %zu bytes\n", msglen);

    /* Construct signed message format: sig || msg */
    uint8_t *sm = malloc(siglen + msglen);
    if (!sm) { printf("Memory allocation failed\n"); return 1; }
    memcpy(sm, sig, siglen);
    memcpy(sm + siglen, msg, msglen);

    /* Verify using reference */
    ret = xmss_sign_open(msg_out, &msg_out_len, sm, siglen + msglen, ref_pk);
    free(sm);

    printf("  Verification: %s\n", ret == 0 ? "PASSED" : "FAILED");

    return ret != 0 ? 1 : 0;
}
