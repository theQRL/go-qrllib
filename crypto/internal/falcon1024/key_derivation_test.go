package falcon1024

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strconv"
	"testing"
)

func TestKeyDerivationDoesNotDependOnArchitecture(t *testing.T) {
	// A seed must expand to the same key pair on every machine. Key
	// generation uses floating-point arithmetic when it checks the
	// Gram-Schmidt norm and when it reduces F and G, and its rejection loop
	// turns a differently rounded intermediate value into different f and g,
	// hence a different public key.
	//
	// The Go compiler may fuse x*y + z into a single instruction, which rounds
	// once instead of twice, on targets that have such an instruction: arm64,
	// and amd64 built with GOAMD64=v3, but not amd64 with the default
	// GOAMD64=v1. The package blocks that fusion with explicit conversions so
	// that every build rounds like the reference implementation. Most seeds
	// would not notice the difference; these two were found to: without the
	// guards both expanded to a different key pair on arm64, and the second
	// one also with GOAMD64=v3.
	//
	// The digests are SHA-256 of the encoded public and private key computed
	// with the reference implementation's rounding.
	testCases := []struct {
		seed          string
		publicKey     string
		encodedSecret string
	}{
		{
			seed:          "f0df1fb67e6c98493a8073308367acb59a14d8296b3849c3011e5a985f998a99df94a03c120d16898fa32fa8dd07ecb6",
			publicKey:     "de3a7e53632f67a6cd84c7a59ba1ec8b6aeb363e314fcdc46e60a9c89befd478",
			encodedSecret: "a0c1fa34e6da969be4567a14089e4c4e61796d0d12613b047eb73ca4e474b7a1",
		},
		{
			seed:          "f304a51b76fcfd80c4cdc27c617c3b41acdca39529af22adf1920f701827a4e377379ef484dea2521ea067feac23d591",
			publicKey:     "f14d7e7fcce2c5674f78ec46d730142cc30c15d64ae68f062608cc5edcaa9cbc",
			encodedSecret: "ea55c41af57d01c0b9226389e791a3b6b0f9c3b8e83d5f712740bf19a8ab338e",
		},
	}

	for i, tc := range testCases {
		t.Run("seed-"+strconv.Itoa(i), func(t *testing.T) {
			priv, err := NewPrivateKeyFromSeed(mustDecodeHex(t, tc.seed))
			if err != nil {
				t.Fatal(err)
			}
			encoded := priv.Bytes()

			gotPublic := sha256.Sum256(priv.PublicKey().Bytes())
			if hex.EncodeToString(gotPublic[:]) != tc.publicKey {
				t.Errorf("on %s the seed expands to a different public key: digest %x, want %s",
					runtime.GOARCH, gotPublic, tc.publicKey)
			}
			gotSecret := sha256.Sum256(encoded)
			if hex.EncodeToString(gotSecret[:]) != tc.encodedSecret {
				t.Errorf("on %s the seed expands to a different private key: digest %x, want %s",
					runtime.GOARCH, gotSecret, tc.encodedSecret)
			}
		})
	}
}
