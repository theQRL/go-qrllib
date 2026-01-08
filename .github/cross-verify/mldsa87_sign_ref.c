/*
 * mldsa87_sign_ref.c - Generate ML-DSA-87 signature with pq-crystals reference
 * Compile: gcc -DDILITHIUM_MODE=5 -I. -O2
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "sign.h"

int main() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    size_t siglen;
    FILE *f;

    crypto_sign_keypair(pk, sk);

    uint8_t ctx[] = "refctx";
    size_t ctxlen = strlen((char*)ctx);
    uint8_t msg[] = "ML-DSA-87 cross-verification from pq-crystals";
    size_t msglen = strlen((char*)msg);

    crypto_sign_signature(sig, &siglen, msg, msglen, ctx, ctxlen, sk);

    /* Self-verify */
    int ret = crypto_sign_verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
    if (ret != 0) {
        printf("Self-verification failed!\n");
        return 1;
    }

    f = fopen("/tmp/ref_mldsa_pk.bin", "wb");
    fwrite(pk, 1, CRYPTO_PUBLICKEYBYTES, f);
    fclose(f);

    f = fopen("/tmp/ref_mldsa_sig.bin", "wb");
    fwrite(sig, 1, siglen, f);
    fclose(f);

    f = fopen("/tmp/ref_mldsa_msg.bin", "wb");
    fwrite(msg, 1, msglen, f);
    fclose(f);

    f = fopen("/tmp/ref_mldsa_ctx.bin", "wb");
    fwrite(ctx, 1, ctxlen, f);
    fclose(f);

    printf("pq-crystals ML-DSA-87 signer:\n");
    printf("  PK size:  %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("  Sig size: %zu bytes\n", siglen);
    printf("  Context:  %s\n", ctx);
    printf("  Self-verify: PASSED\n");

    return 0;
}
