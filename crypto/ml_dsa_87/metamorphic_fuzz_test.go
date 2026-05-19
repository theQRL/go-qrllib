// Metamorphic fuzz tests for ML-DSA-87, contributed by Trail of Bits
// during the audit engagement (TOB-QRLLIB). Light adaptations applied
// for current go-qrllib API surface (post TOB-6 / TOB-12 / TOB-14):
//   - `Seal` renamed to `SignAttached`
//   - `Open` now returns `([]byte, error)`
//   - `Sign` is hedged-by-default; tests that assert "different message
//     → different signature" as a property of *deterministic* signing
//     route through [MLDSA87.SignDeterministic] so the assertion is
//     genuinely testing the metamorphic property rather than trivially
//     observing per-call freshness.

package ml_dsa_87

import (
	"bytes"
	"testing"
)

const (
	metamorphicFuzzMaxContextLen = 255
	metamorphicFuzzMaxMessageLen = 256
)

func metamorphicFuzzSeed(seedBytes []byte) [SEED_BYTES]uint8 {
	var seed [SEED_BYTES]uint8
	copy(seed[:], limitFuzzBytes(seedBytes, SEED_BYTES))
	return seed
}

func metamorphicMaulSingleBit(src []byte, bitIndex uint32) []byte {
	out := append([]byte(nil), src...)
	if len(out) == 0 {
		return []byte{1}
	}
	bit := int(bitIndex) % (len(out) * 8)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

func mustMetamorphicSigner(t *testing.T, seedBytes []byte) *MLDSA87 {
	t.Helper()
	mldsa, err := NewMLDSA87FromSeed(metamorphicFuzzSeed(seedBytes))
	if err != nil {
		t.Fatalf("NewMLDSA87FromSeed failed: %v", err)
	}
	return mldsa
}

func fuzzableCtx(ctx []byte) []byte {
	return limitFuzzBytes(ctx, metamorphicFuzzMaxContextLen)
}

func fuzzableMsg(msg []byte) []byte {
	msg = limitFuzzBytes(msg, metamorphicFuzzMaxMessageLen)
	if len(msg) == 0 {
		return []byte{0}
	}
	return msg
}

func FuzzMetamorphicVerifyRejectsMauledPublicKey(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		sig, err := mldsa.Sign(ctx, msg)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.GetPK()
		if !Verify(ctx, msg, sig, &pk) {
			t.Fatal("baseline signature failed verification")
		}

		mauledBytes := metamorphicMaulSingleBit(pk[:], bitIndex)
		var mauledPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		copy(mauledPK[:], mauledBytes)

		if Verify(ctx, msg, sig, &mauledPK) {
			t.Fatalf("single-bit mauled public key verified (bitIndex=%d)", bitIndex)
		}
	})
}

func FuzzMetamorphicVerifyRejectsMauledMessage(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		sig, err := mldsa.Sign(ctx, msg)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.GetPK()
		if !Verify(ctx, msg, sig, &pk) {
			t.Fatal("baseline signature failed verification")
		}

		mauledMsg := metamorphicMaulSingleBit(msg, bitIndex)
		if bytes.Equal(mauledMsg, msg) {
			t.Fatal("message maul did not change the input")
		}
		if Verify(ctx, mauledMsg, sig, &pk) {
			t.Fatalf("single-bit mauled message verified (bitIndex=%d)", bitIndex)
		}
	})
}

func FuzzMetamorphicVerifyRejectsMauledSignature(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		sig, err := mldsa.Sign(ctx, msg)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		pk := mldsa.GetPK()
		if !Verify(ctx, msg, sig, &pk) {
			t.Fatal("baseline signature failed verification")
		}

		mauledBytes := metamorphicMaulSingleBit(sig[:], bitIndex)
		var mauledSig [CRYPTO_BYTES]uint8
		copy(mauledSig[:], mauledBytes)

		if Verify(ctx, msg, mauledSig, &pk) {
			t.Fatalf("single-bit mauled signature verified (bitIndex=%d)", bitIndex)
		}
	})
}

// FuzzMetamorphicDeterministicSigningChangesOnMauledMessage asserts the
// metamorphic property "same key, same ctx, different msg → different
// signature bytes" for deterministic signing. Under hedged signing this
// property holds trivially (every call uses fresh randomness so any two
// signs differ); routing through [MLDSA87.SignDeterministic] makes the
// assertion genuinely test that the message *content* influences the
// signature bytes.
func FuzzMetamorphicDeterministicSigningChangesOnMauledMessage(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		baseSig, err := mldsa.SignDeterministic(ctx, msg)
		if err != nil {
			t.Fatalf("SignDeterministic failed: %v", err)
		}

		mauledMsg := metamorphicMaulSingleBit(msg, bitIndex)
		mauledSig, err := mldsa.SignDeterministic(ctx, mauledMsg)
		if err != nil {
			t.Fatalf("SignDeterministic on mauled message failed: %v", err)
		}

		if mauledSig == baseSig {
			t.Fatalf("deterministic signing collision after single-bit message maul (bitIndex=%d)", bitIndex)
		}
	})
}

func FuzzMetamorphicOpenRejectsMauledAttachedSignature(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x00}, SEED_BYTES), []byte{}, []byte("message"), uint32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, SEED_BYTES), bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte("m"), 64), uint32(17))

	f.Fuzz(func(t *testing.T, seedBytes, ctx, msg []byte, bitIndex uint32) {
		ctx = fuzzableCtx(ctx)
		msg = fuzzableMsg(msg)

		mldsa := mustMetamorphicSigner(t, seedBytes)
		sealed, err := mldsa.SignAttached(ctx, msg)
		if err != nil {
			t.Fatalf("SignAttached failed: %v", err)
		}

		pk := mldsa.GetPK()
		opened, err := Open(ctx, sealed, &pk)
		if err != nil {
			t.Fatalf("baseline sealed message returned error from Open: %v", err)
		}
		if !bytes.Equal(opened, msg) {
			t.Fatal("baseline sealed message did not round-trip through Open")
		}

		// Restrict mauling to the attached signature prefix, mirroring the
		// metamorphic test that mauls only sigma and not the message suffix.
		mauledPrefix := metamorphicMaulSingleBit(sealed[:CRYPTO_BYTES], bitIndex)
		mauledSealed := append([]byte(nil), mauledPrefix...)
		mauledSealed = append(mauledSealed, sealed[CRYPTO_BYTES:]...)

		if _, err := Open(ctx, mauledSealed, &pk); err == nil {
			t.Fatalf("single-bit mauled attached signature opened successfully (bitIndex=%d)", bitIndex)
		}
	})
}
