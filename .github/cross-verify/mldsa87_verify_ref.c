/*
 * mldsa87_verify_ref.c - Verify go-qrllib ML-DSA-87 signature with pq-crystals reference
 * Compile: gcc -DDILITHIUM_MODE=5 -I. -O2
 */
#include <stdio.h>
#include <stdint.h>
#include "params.h"
#include "sign.h"

int main() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t msg[256];
    uint8_t ctx[256];
    size_t msglen, siglen, ctxlen;
    FILE *f;

    f = fopen("/tmp/mldsa_pk.bin", "rb");
    if (!f) { printf("Cannot open pk\n"); return 1; }
    if (fread(pk, 1, CRYPTO_PUBLICKEYBYTES, f) != CRYPTO_PUBLICKEYBYTES) {
        printf("Failed to read pk\n"); return 1;
    }
    fclose(f);

    f = fopen("/tmp/mldsa_sig.bin", "rb");
    if (!f) { printf("Cannot open sig\n"); return 1; }
    siglen = fread(sig, 1, CRYPTO_BYTES, f);
    fclose(f);

    f = fopen("/tmp/mldsa_msg.bin", "rb");
    if (!f) { printf("Cannot open msg\n"); return 1; }
    msglen = fread(msg, 1, sizeof(msg), f);
    fclose(f);

    f = fopen("/tmp/mldsa_ctx.bin", "rb");
    if (!f) { printf("Cannot open ctx\n"); return 1; }
    ctxlen = fread(ctx, 1, sizeof(ctx), f);
    fclose(f);

    printf("pq-crystals ML-DSA-87 verifier:\n");
    printf("  PK size:  %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("  Sig size: %zu bytes\n", siglen);
    printf("  Msg size: %zu bytes\n", msglen);
    printf("  Ctx size: %zu bytes\n", ctxlen);

    int ret = crypto_sign_verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
    printf("  Verification: %s\n", ret == 0 ? "PASSED" : "FAILED");

    return ret != 0 ? 1 : 0;
}
