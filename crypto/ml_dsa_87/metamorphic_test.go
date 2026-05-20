//go:build metamorphic

// Exhaustive metamorphic tests for ML-DSA-87, contributed by Trail of
// Bits during the audit engagement (TOB-QRLLIB). Guarded by the
// `metamorphic` build tag because they iterate bit-by-bit over public
// keys, signatures, and secret-key regions — useful as a deep
// invariant sweep but too slow for the default test path. Run with:
//
//	go test -tags metamorphic -timeout 30m ./crypto/ml_dsa_87/
//
// Light adaptations applied for current go-qrllib API surface
// (post TOB-6 / TOB-12 / TOB-14):
//   - attached-signature API renamed to `SignAttached`
//   - `Open` now returns `([]byte, error)`
//   - `cryptoSignSignature` no longer takes the `randomized bool` parameter
//   - tests whose assertions depend on byte-equality of signatures (the
//     deterministic-signing metamorphic property and the secret-key
//     feature-scan) route through `cryptoSignSignatureWithRnd` with
//     `rnd = 0^32` so the comparisons remain meaningful under
//     hedged-by-default signing.

package ml_dsa_87

import (
	"bytes"
	"fmt"
	"testing"
)

type metamorphicVector struct {
	name    string
	seed    [SEED_BYTES]uint8
	ctx     []byte
	message []byte
}

func metamorphicCorpus() []metamorphicVector {
	var zeroSeed [SEED_BYTES]uint8

	var ascendingSeed [SEED_BYTES]uint8
	for i := range ascendingSeed {
		ascendingSeed[i] = uint8(i)
	}

	maxCtx := bytes.Repeat([]byte{0x42}, 255)
	msg32 := make([]byte, 32)
	for i := range msg32 {
		msg32[i] = uint8(i)
	}

	return []metamorphicVector{
		{
			name:    "zero-seed-empty-ctx",
			seed:    zeroSeed,
			ctx:     nil,
			message: msg32,
		},
		{
			name:    "ascending-seed-max-ctx",
			seed:    ascendingSeed,
			ctx:     maxCtx,
			message: msg32,
		},
	}
}

func flipSingleBit(src []byte, bit int) []byte {
	out := append([]byte(nil), src...)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// signWithSecretKeyDeterministic produces a deterministic ML-DSA-87
// signature using the FIPS 204 §3.5 deterministic mode (`rnd = 0^32`),
// allowing the byte-equality comparisons in the feature-scan to remain
// meaningful under hedged-by-default signing (TOB-QRLLIB-6).
func signWithSecretKeyDeterministic(ctx, message []byte, sk *[CRYPTO_SECRET_KEY_BYTES]uint8) ([CRYPTO_BYTES]uint8, error) {
	var sig [CRYPTO_BYTES]uint8
	var rnd [RND_BYTES]uint8 // zero — FIPS 204 §3.5 deterministic mode
	err := cryptoSignSignatureWithRnd(sig[:], message, ctx, sk, rnd)
	return sig, err
}

func mustSignerFromSeed(t *testing.T, seed [SEED_BYTES]uint8) *MLDSA87 {
	t.Helper()
	mldsa, err := NewMLDSA87FromSeed(seed)
	if err != nil {
		t.Fatalf("NewMLDSA87FromSeed failed: %v", err)
	}
	return mldsa
}

func mustSign(t *testing.T, mldsa *MLDSA87, ctx, message []byte) [CRYPTO_BYTES]uint8 {
	t.Helper()
	sig, err := mldsa.Sign(ctx, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	return sig
}

func mustSignDeterministic(t *testing.T, mldsa *MLDSA87, ctx, message []byte) [CRYPTO_BYTES]uint8 {
	t.Helper()
	sig, err := mldsa.SignDeterministic(ctx, message)
	if err != nil {
		t.Fatalf("SignDeterministic failed: %v", err)
	}
	return sig
}

func TestMetamorphicVerifyRejectsBitMauledPublicKeys(t *testing.T) {
	for _, tc := range metamorphicCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			mldsa := mustSignerFromSeed(t, tc.seed)
			sig := mustSign(t, mldsa, tc.ctx, tc.message)
			pk := mldsa.GetPK()

			if !Verify(tc.ctx, tc.message, sig, &pk) {
				t.Fatal("baseline signature failed verification")
			}

			for bit := 0; bit < len(pk)*8; bit++ {
				mutated := flipSingleBit(pk[:], bit)
				var mauledPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
				copy(mauledPK[:], mutated)

				if Verify(tc.ctx, tc.message, sig, &mauledPK) {
					t.Fatalf("single-bit mauled public key verified at bit %d", bit)
				}
			}
		})
	}
}

func TestMetamorphicVerifyRejectsBitMauledMessages(t *testing.T) {
	for _, tc := range metamorphicCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			mldsa := mustSignerFromSeed(t, tc.seed)
			sig := mustSign(t, mldsa, tc.ctx, tc.message)
			pk := mldsa.GetPK()

			if !Verify(tc.ctx, tc.message, sig, &pk) {
				t.Fatal("baseline signature failed verification")
			}

			for bit := 0; bit < len(tc.message)*8; bit++ {
				mauledMsg := flipSingleBit(tc.message, bit)
				if Verify(tc.ctx, mauledMsg, sig, &pk) {
					t.Fatalf("single-bit mauled message verified at bit %d", bit)
				}
			}
		})
	}
}

func TestMetamorphicVerifyRejectsBitMauledSignatures(t *testing.T) {
	for _, tc := range metamorphicCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			mldsa := mustSignerFromSeed(t, tc.seed)
			sig := mustSign(t, mldsa, tc.ctx, tc.message)
			pk := mldsa.GetPK()

			if !Verify(tc.ctx, tc.message, sig, &pk) {
				t.Fatal("baseline signature failed verification")
			}

			for bit := 0; bit < len(sig)*8; bit++ {
				mutated := flipSingleBit(sig[:], bit)
				var mauledSig [CRYPTO_BYTES]uint8
				copy(mauledSig[:], mutated)

				if Verify(tc.ctx, tc.message, mauledSig, &pk) {
					t.Fatalf("single-bit mauled signature verified at bit %d", bit)
				}
			}
		})
	}
}

// TestMetamorphicDeterministicSigningChangesOnBitMauledMessages asserts
// the metamorphic property "different msg → different signature bytes"
// for deterministic signing. Routed through [MLDSA87.SignDeterministic]
// so the byte-equality assertion is genuinely testing message-influences-
// signature (under hedged signing the assertion would hold trivially
// because every call uses fresh randomness).
func TestMetamorphicDeterministicSigningChangesOnBitMauledMessages(t *testing.T) {
	for _, tc := range metamorphicCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			mldsa := mustSignerFromSeed(t, tc.seed)
			baseSig := mustSignDeterministic(t, mldsa, tc.ctx, tc.message)

			for bit := 0; bit < len(tc.message)*8; bit++ {
				mauledMsg := flipSingleBit(tc.message, bit)
				mauledSig := mustSignDeterministic(t, mldsa, tc.ctx, mauledMsg)

				if mauledSig == baseSig {
					t.Fatalf("deterministic signing collision after single-bit message maul at bit %d", bit)
				}
			}
		})
	}
}

// TestMetamorphicSecretKeyMaulingFeatureScan exhaustively flips each
// bit in three named regions of the secret key (rho / key / tr) and
// records (a) how many bit flips still produce a signature that
// verifies under the *original* public key (a structural-redundancy
// signal) and (b) how many preserve the *exact* baseline signature
// bytes. Both signings use the deterministic path so the byte-equality
// counter is meaningful under hedged-by-default signing (TOB-QRLLIB-6).
func TestMetamorphicSecretKeyMaulingFeatureScan(t *testing.T) {
	for _, tc := range metamorphicCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			mldsa := mustSignerFromSeed(t, tc.seed)
			baseSig := mustSignDeterministic(t, mldsa, tc.ctx, tc.message)
			pk := mldsa.GetPK()
			sk := mldsa.GetSK()

			regions := []struct {
				name      string
				startByte int
				endByte   int
			}{
				{name: "rho", startByte: 0, endByte: SEED_BYTES},
				{name: "key", startByte: SEED_BYTES, endByte: 2 * SEED_BYTES},
				{name: "tr", startByte: 2 * SEED_BYTES, endByte: 2*SEED_BYTES + TR_BYTES},
			}

			for _, region := range regions {
				validCount := 0
				sameSigCount := 0
				totalBits := (region.endByte - region.startByte) * 8

				for relBit := 0; relBit < totalBits; relBit++ {
					absBit := region.startByte*8 + relBit
					mutated := flipSingleBit(sk[:], absBit)

					var mauledSK [CRYPTO_SECRET_KEY_BYTES]uint8
					copy(mauledSK[:], mutated)

					sig, err := signWithSecretKeyDeterministic(tc.ctx, tc.message, &mauledSK)
					if err != nil {
						t.Fatalf("Sign failed for %s bit %d: %v", region.name, relBit, err)
					}

					if sig == baseSig {
						sameSigCount++
					}
					if Verify(tc.ctx, tc.message, sig, &pk) {
						validCount++
					}
				}

				t.Logf("%s: %d/%d bit flips still produced signatures valid under the original public key; %d/%d preserved the exact original signature",
					region.name, validCount, totalBits, sameSigCount, totalBits)

				if region.name == "key" && validCount == 0 {
					t.Fatal("expected at least one key-region bit flip to preserve signing validity under the original public key")
				}
			}
		})
	}
}

func TestMetamorphicSignAttachedOpenRejectsBitMauledAttachedSignatures(t *testing.T) {
	for _, tc := range metamorphicCorpus() {
		t.Run(tc.name, func(t *testing.T) {
			mldsa := mustSignerFromSeed(t, tc.seed)
			sealed, err := mldsa.SignAttached(tc.ctx, tc.message)
			if err != nil {
				t.Fatalf("SignAttached failed: %v", err)
			}
			pk := mldsa.GetPK()

			opened, err := Open(tc.ctx, sealed, &pk)
			if err != nil {
				t.Fatalf("baseline attached-signature message returned error from Open: %v", err)
			}
			if !bytes.Equal(opened, tc.message) {
				t.Fatalf("baseline attached-signature message failed to open: got %q", fmt.Sprintf("%x", opened))
			}

			for bit := 0; bit < CRYPTO_BYTES*8; bit++ {
				mauledSealed := flipSingleBit(sealed, bit)
				if _, err := Open(tc.ctx, mauledSealed, &pk); err == nil {
					t.Fatalf("single-bit mauled attached signature opened successfully at bit %d", bit)
				}
			}
		})
	}
}
