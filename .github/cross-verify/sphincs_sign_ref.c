/*
 * sphincs_sign_ref.c - Generate SPHINCS+ signature with reference implementation
 * Compile: gcc -DPARAMS=sphincs-shake-256s -DTHASH=robust -I. -O2
 *
 * SPHINCS+ seed format: [sk_seed (32) | sk_prf (32) | pub_seed (32)] = 96 bytes
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "params.h"

int main() {
    uint8_t pk[SPX_PK_BYTES];
    uint8_t sk[SPX_SK_BYTES];
    uint8_t seed[3 * SPX_N];
    uint8_t sig[SPX_BYTES];
    size_t siglen;
    FILE *f;

    /* Read deterministic seed written by go-qrllib */
    f = fopen("/tmp/sphincs_seed.bin", "rb");
    if (!f) { printf("Cannot open seed\n"); return 1; }
    if (fread(seed, 1, sizeof(seed), f) != sizeof(seed)) {
        printf("Failed to read seed\n"); return 1;
    }
    fclose(f);

    /* Generate keypair from seed components */
    /* Reference implementation structure:
     * sk = [sk_seed | sk_prf | pk]
     * pk = [pub_seed | root]
     * The reference crypto_sign_seed_keypair expects a 3*SPX_N seed
     */
    int ret = crypto_sign_seed_keypair(pk, sk, seed);
    if (ret != 0) {
        printf("Key generation failed\n");
        return 1;
    }

    /* Use same message format */
    const uint8_t msg[] = "SPHINCS+ cross-implementation verification";
    size_t msglen = sizeof(msg) - 1;

    ret = crypto_sign_signature(sig, &siglen, msg, msglen, sk);
    if (ret != 0) {
        printf("Signing failed\n");
        return 1;
    }

    /* Write output for go-qrllib to verify */
    f = fopen("/tmp/ref_sphincs_pk.bin", "wb");
    fwrite(pk, 1, SPX_PK_BYTES, f);
    fclose(f);

    f = fopen("/tmp/ref_sphincs_sig.bin", "wb");
    fwrite(sig, 1, siglen, f);
    fclose(f);

    f = fopen("/tmp/ref_sphincs_msg.bin", "wb");
    fwrite(msg, 1, msglen, f);
    fclose(f);

    printf("SPHINCS+ reference (sphincs-shake-256s-robust) signer:\n");
    printf("  PK size:  %d bytes\n", SPX_PK_BYTES);
    printf("  SK size:  %d bytes\n", SPX_SK_BYTES);
    printf("  Sig size: %zu bytes\n", siglen);

    /* Self-verify */
    ret = crypto_sign_verify(sig, siglen, msg, msglen, pk);
    printf("  Self-verify: %s\n", ret == 0 ? "PASSED" : "FAILED");

    return ret != 0 ? 1 : 0;
}
