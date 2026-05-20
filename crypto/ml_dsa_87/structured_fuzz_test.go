// Structured fuzz tests for ML-DSA-87, contributed by Trail of Bits
// during the audit engagement (TOB-QRLLIB). Light adaptations applied
// for current go-qrllib API surface (post TOB-6 / TOB-12 / TOB-14):
//   - attached-signature API renamed to `SignAttached`
//   - `Open` now returns `([]byte, error)`
//   - the `randomized bool` parameter was removed from
//     `cryptoSignSignature` (hedged is now the default)

package ml_dsa_87

import (
	"bytes"
	"crypto"
	"strings"
	"testing"
)

const (
	fuzzMaxContextLen  = 256
	fuzzMaxMessageLen  = 4096
	fuzzMaxMutationLen = 64
)

func limitFuzzBytes(b []byte, max int) []byte {
	if len(b) > max {
		return b[:max]
	}
	return b
}

func fuzzSeed32(seedBytes []byte) [SEED_BYTES]uint8 {
	var seed [SEED_BYTES]uint8
	copy(seed[:], limitFuzzBytes(seedBytes, SEED_BYTES))
	return seed
}

func mutateSlice(base []byte, mutation []byte) []byte {
	out := append([]byte(nil), base...)
	if len(out) == 0 {
		if len(mutation) == 0 {
			return []byte{1}
		}
		return []byte{mutation[0] ^ 0x01}
	}

	idx := 0
	mask := byte(0x01)
	if len(mutation) > 0 {
		idx = int(mutation[0]) % len(out)
	}
	if len(mutation) > 1 {
		mask = mutation[1]
		if mask == 0 {
			mask = 0x01
		}
	}

	out[idx] ^= mask
	return out
}

func mutateSignature(sig [CRYPTO_BYTES]uint8, mutation []byte) [CRYPTO_BYTES]uint8 {
	mutated := sig
	idx := 0
	mask := byte(0x01)
	if len(mutation) > 0 {
		idx = int(mutation[0]) % len(mutated)
	}
	if len(mutation) > 1 {
		mask = mutation[1]
		if mask == 0 {
			mask = 0x01
		}
	}
	mutated[idx] ^= mask
	return mutated
}

func mutatePublicKey(pk [CRYPTO_PUBLIC_KEY_BYTES]uint8, mutation []byte) [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	mutated := pk
	idx := 0
	mask := byte(0x01)
	if len(mutation) > 0 {
		idx = int(mutation[0]) % len(mutated)
	}
	if len(mutation) > 1 {
		mask = mutation[1]
		if mask == 0 {
			mask = 0x01
		}
	}
	mutated[idx] ^= mask
	return mutated
}

func FuzzMLDSA87SignVerifyRoundTripMutate(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte("ctx"), []byte("message"), []byte{0, 1})
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 255), []byte{}, []byte{17, 0x80})
	f.Add([]byte("seed"), bytes.Repeat([]byte{0x42}, 256), bytes.Repeat([]byte("m"), 128), []byte{3, 7})

	f.Fuzz(func(t *testing.T, seedBytes, ctx, message, mutation []byte) {
		ctx = limitFuzzBytes(ctx, fuzzMaxContextLen)
		message = limitFuzzBytes(message, fuzzMaxMessageLen)
		mutation = limitFuzzBytes(mutation, fuzzMaxMutationLen)

		mldsa, err := NewMLDSA87FromSeed(fuzzSeed32(seedBytes))
		if err != nil {
			t.Fatalf("NewMLDSA87FromSeed failed: %v", err)
		}

		sig, err := mldsa.Sign(ctx, message)
		if len(ctx) > 255 {
			if err == nil {
				t.Fatal("Sign succeeded with oversized context")
			}
			return
		}
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.GetPK()
		if !Verify(ctx, message, sig, &pk) {
			t.Fatal("Valid signature failed verification")
		}

		mutatedCtx := mutateSlice(ctx, mutation)
		if bytes.Equal(mutatedCtx, ctx) {
			t.Fatal("Context mutation did not change the input")
		}
		if Verify(mutatedCtx, message, sig, &pk) {
			t.Fatal("Signature verified with mutated context")
		}

		mutatedMsg := mutateSlice(message, mutation)
		if bytes.Equal(mutatedMsg, message) {
			t.Fatal("Message mutation did not change the input")
		}
		if Verify(ctx, mutatedMsg, sig, &pk) {
			t.Fatal("Signature verified with mutated message")
		}

		mutatedSig := mutateSignature(sig, mutation)
		if Verify(ctx, message, mutatedSig, &pk) {
			t.Fatal("Mutated signature verified")
		}

		mutatedPK := mutatePublicKey(pk, mutation)
		if Verify(ctx, message, sig, &mutatedPK) {
			t.Fatal("Signature verified with mutated public key")
		}
	})
}

func FuzzMLDSA87SignAttachedOpenRoundTripMutate(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte("ctx"), []byte("message"), []byte{0, 1})
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 255), []byte{}, []byte{9, 0x40})
	f.Add([]byte("seed"), bytes.Repeat([]byte{0x42}, 256), bytes.Repeat([]byte("m"), 512), []byte{5, 7})

	f.Fuzz(func(t *testing.T, seedBytes, ctx, message, mutation []byte) {
		ctx = limitFuzzBytes(ctx, fuzzMaxContextLen)
		message = limitFuzzBytes(message, fuzzMaxMessageLen)
		mutation = limitFuzzBytes(mutation, fuzzMaxMutationLen)

		mldsa, err := NewMLDSA87FromSeed(fuzzSeed32(seedBytes))
		if err != nil {
			t.Fatalf("NewMLDSA87FromSeed failed: %v", err)
		}

		sealed, err := mldsa.SignAttached(ctx, message)
		if len(ctx) > 255 {
			if err == nil {
				t.Fatal("SignAttached succeeded with oversized context")
			}
			return
		}
		if err != nil {
			t.Fatalf("SignAttached failed: %v", err)
		}

		pk := mldsa.GetPK()
		opened, err := Open(ctx, sealed, &pk)
		if err != nil {
			t.Fatalf("Open returned an error for a valid attached-signature message: %v", err)
		}
		if !bytes.Equal(opened, message) {
			t.Fatal("Open did not recover the original message")
		}

		mutatedCtx := mutateSlice(ctx, mutation)
		if _, err := Open(mutatedCtx, sealed, &pk); err == nil {
			t.Fatal("Open succeeded with mutated context")
		}

		mutatedSealed := mutateSlice(sealed, mutation)
		if _, err := Open(ctx, mutatedSealed, &pk); err == nil {
			t.Fatal("Open succeeded with mutated attached-signature message")
		}

		mutatedPK := mutatePublicKey(pk, mutation)
		if _, err := Open(ctx, sealed, &mutatedPK); err == nil {
			t.Fatal("Open succeeded with mutated public key")
		}
	})
}

func FuzzMLDSA87FromHexSeedAndSigner(f *testing.F) {
	validHexSeed := strings.Repeat("00", SEED_BYTES)
	f.Add(validHexSeed, []byte("ctx"), []byte("digest"))
	f.Add("0x"+validHexSeed, bytes.Repeat([]byte{0x41}, 255), []byte{})
	f.Add("abc", bytes.Repeat([]byte{0x42}, 256), bytes.Repeat([]byte("d"), 128))

	f.Fuzz(func(t *testing.T, hexSeed string, ctx, digest []byte) {
		ctx = limitFuzzBytes(ctx, fuzzMaxContextLen)
		digest = limitFuzzBytes(digest, fuzzMaxMessageLen)

		mldsa, err := NewMLDSA87FromHexSeed(hexSeed)
		if err != nil {
			return
		}

		roundTrip, err := NewMLDSA87FromHexSeed(mldsa.GetHexSeed())
		if err != nil {
			t.Fatalf("Round-trip seed decode failed: %v", err)
		}
		if mldsa.GetPK() != roundTrip.GetPK() {
			t.Fatal("Hex seed round-trip changed the derived public key")
		}

		signer := NewCryptoSigner(mldsa)
		sigBytes, err := signer.Sign(nil, digest, &SignerOpts{Context: ctx})
		if len(ctx) > 255 {
			if err == nil {
				t.Fatal("CryptoSigner.Sign succeeded with oversized context")
			}
			return
		}
		if err != nil {
			t.Fatalf("CryptoSigner.Sign failed: %v", err)
		}
		if len(sigBytes) != CRYPTO_BYTES {
			t.Fatalf("Unexpected signature length %d", len(sigBytes))
		}

		var sig [CRYPTO_BYTES]uint8
		copy(sig[:], sigBytes)
		pk := mldsa.GetPK()
		if !Verify(ctx, digest, sig, &pk) {
			t.Fatal("CryptoSigner produced a signature that does not verify")
		}

		if _, err := signer.Sign(nil, digest, crypto.SHA256); err == nil {
			t.Fatal("CryptoSigner accepted unsupported signer opts")
		}
	})
}
