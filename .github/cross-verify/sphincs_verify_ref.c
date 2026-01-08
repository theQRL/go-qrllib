/*
 * sphincs_verify_ref.c - Verify go-qrllib SPHINCS+ signature with reference
 * Compile: gcc -DPARAMS=sphincs-shake-256s -DTHASH=robust -I. -O2
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "params.h"

int main() {
    uint8_t pk[SPX_PK_BYTES];
    uint8_t sig[SPX_BYTES];
    uint8_t msg[256];
    size_t msglen, siglen;
    FILE *f;

    f = fopen("/tmp/sphincs_pk.bin", "rb");
    if (!f) { printf("Cannot open pk\n"); return 1; }
    if (fread(pk, 1, SPX_PK_BYTES, f) != SPX_PK_BYTES) {
        printf("Failed to read pk\n"); return 1;
    }
    fclose(f);

    f = fopen("/tmp/sphincs_sig.bin", "rb");
    if (!f) { printf("Cannot open sig\n"); return 1; }
    siglen = fread(sig, 1, SPX_BYTES, f);
    fclose(f);

    f = fopen("/tmp/sphincs_msg.bin", "rb");
    if (!f) { printf("Cannot open msg\n"); return 1; }
    msglen = fread(msg, 1, sizeof(msg), f);
    fclose(f);

    printf("SPHINCS+ reference (sphincs-shake-256s-robust) verifier:\n");
    printf("  PK size:  %d bytes\n", SPX_PK_BYTES);
    printf("  Sig size: %zu bytes (expected %d)\n", siglen, SPX_BYTES);
    printf("  Msg size: %zu bytes\n", msglen);

    int ret = crypto_sign_verify(sig, siglen, msg, msglen, pk);
    printf("  Verification: %s\n", ret == 0 ? "PASSED" : "FAILED");

    return ret != 0 ? 1 : 0;
}
