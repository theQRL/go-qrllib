package ml_dsa_87

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// Packed secret-key layout offsets: rho || K || tr || s1 || s2 || t0.
const (
	skS1Offset = 2*SEED_BYTES + TR_BYTES
	skS2Offset = skS1Offset + L*POLY_ETA_PACKED_BYTES
	skT0Offset = skS2Offset + K*POLY_ETA_PACKED_BYTES
)

func seededSK(t *testing.T, tag uint8) [CRYPTO_SECRET_KEY_BYTES]uint8 {
	t.Helper()
	var seed [SEED_BYTES]uint8
	for i := range seed {
		seed[i] = uint8(i) ^ tag
	}
	d, err := NewMLDSA87FromSeed(seed)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return d.GetSK()
}

// TestValidateSecretKey_AcceptsGenerated checks that keys from key
// generation pass, and that nil is reported rather than dereferenced.
func TestValidateSecretKey_AcceptsGenerated(t *testing.T) {
	for tag := uint8(0); tag < 16; tag++ {
		sk := seededSK(t, tag)
		if err := ValidateSecretKey(&sk); err != nil {
			t.Fatalf("tag %d: generated key rejected: %v", tag, err)
		}
	}
	if err := ValidateSecretKey(nil); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Fatalf("nil: err = %v, want ErrSecretKeyNil", err)
	}
}

// TestValidateSecretKey_RejectsOutOfRange sets single 3-bit fields of s1
// and s2 to the three encodings key generation never produces (5, 6, 7
// decode to -3, -4, -5) at the first and last coefficient positions, and
// checks that the in-range extreme (4, decoding to -ETA) still passes and
// that bytes outside s1/s2 are not what the check looks at.
func TestValidateSecretKey_RejectsOutOfRange(t *testing.T) {
	base := seededSK(t, 1)
	setLow3 := func(sk *[CRYPTO_SECRET_KEY_BYTES]uint8, off int, v uint8) { sk[off] = (sk[off] &^ 7) | v }
	setHigh3 := func(sk *[CRYPTO_SECRET_KEY_BYTES]uint8, off int, v uint8) { sk[off] = (sk[off] & 0x1f) | (v << 5) }

	for _, v := range []uint8{5, 6, 7} {
		sk := base
		setLow3(&sk, skS1Offset, v) // first coefficient of s1
		if err := ValidateSecretKey(&sk); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
			t.Fatalf("s1[0] field %d: err = %v, want ErrInvalidSecretKey", v, err)
		}
		sk = base
		setHigh3(&sk, skT0Offset-1, v) // last coefficient of s2
		if err := ValidateSecretKey(&sk); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
			t.Fatalf("s2[last] field %d: err = %v, want ErrInvalidSecretKey", v, err)
		}
		sk = base
		setLow3(&sk, skS2Offset, v) // first coefficient of s2
		if err := ValidateSecretKey(&sk); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
			t.Fatalf("s2[0] field %d: err = %v, want ErrInvalidSecretKey", v, err)
		}
	}
	sk := base
	setLow3(&sk, skS1Offset, 4) // ETA - 4 = -2, the in-range extreme
	setHigh3(&sk, skT0Offset-1, 4)
	if err := ValidateSecretKey(&sk); err != nil {
		t.Fatalf("in-range extreme rejected: %v", err)
	}
	sk = base
	for i := 0; i < skS1Offset; i++ { // rho, K, tr are opaque
		sk[i] ^= 0xff
	}
	for i := skT0Offset; i < CRYPTO_SECRET_KEY_BYTES; i++ { // every t0 encoding decodes
		sk[i] ^= 0xff
	}
	if err := ValidateSecretKey(&sk); err != nil {
		t.Fatalf("corrupting fields outside s1/s2 changed the verdict: %v", err)
	}
}

// TestSign_RejectsOutOfRangeSecretKey checks that both raw-key signing
// entry points refuse an out-of-range key before doing any work.
func TestSign_RejectsOutOfRangeSecretKey(t *testing.T) {
	sk := seededSK(t, 2)
	sk[skS1Offset] = (sk[skS1Offset] &^ 7) | 7
	ctx, msg := []uint8("ZOND"), []uint8("out of range")
	var sig [CRYPTO_BYTES]uint8
	if err := cryptoSignSignatureWithRnd(sig[:], msg, ctx, &sk, [RND_BYTES]uint8{}); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
		t.Fatalf("cryptoSignSignatureWithRnd: err = %v, want ErrInvalidSecretKey", err)
	}
	if sm, err := cryptoSign(msg, ctx, &sk); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) || sm != nil {
		t.Fatalf("cryptoSign: sm=%v err=%v, want nil + ErrInvalidSecretKey", sm, err)
	}
}

// TestSign_AttemptBound exercises the bounded rejection loop. With the
// bound set to a single attempt, deterministic signing over a fixed key and
// a fixed message sequence must both succeed and fail (a candidate is
// accepted with probability about 0.26), every success must verify, and
// the production bound must accept every message.
func TestSign_AttemptBound(t *testing.T) {
	if signMaxAttempts != 1024 {
		t.Fatalf("signMaxAttempts = %d, want 1024", signMaxAttempts)
	}
	var seed [SEED_BYTES]uint8
	for i := range seed {
		seed[i] = uint8(i * 3)
	}
	d, err := NewMLDSA87FromSeed(seed)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sk := d.GetSK()
	pk := d.PublicKey()
	ctx := []uint8("ZOND")
	pre := append([]uint8{0, uint8(len(ctx))}, ctx...)
	var rnd [RND_BYTES]uint8

	ok, exhausted := 0, 0
	for i := 0; i < 2000; i++ {
		msg := []uint8{uint8(i), uint8(i >> 8), 'b', 'o', 'u', 'n', 'd'}
		var sig [CRYPTO_BYTES]uint8
		switch err := cryptoSignSignatureAttempts(sig[:], msg, pre, rnd, &sk, 1); {
		case err == nil:
			ok++
			if !Verify(ctx, msg, sig, pk) {
				t.Fatalf("message %d: single-attempt signature did not verify", i)
			}
		case errors.Is(err, cryptoerrors.ErrSigningFailed):
			exhausted++
		default:
			t.Fatalf("message %d: unexpected error %v", i, err)
		}
	}
	if ok == 0 || exhausted == 0 {
		t.Fatalf("single-attempt bound: ok=%d exhausted=%d, want both non-zero", ok, exhausted)
	}
	t.Logf("single-attempt signing: %d accepted, %d rejected (acceptance %.2f)", ok, exhausted, float64(ok)/2000)

	for i := 0; i < 200; i++ {
		msg := []uint8{uint8(i), 'f', 'u', 'l', 'l'}
		var sig [CRYPTO_BYTES]uint8
		if err := cryptoSignSignatureAttempts(sig[:], msg, pre, rnd, &sk, signMaxAttempts); err != nil {
			t.Fatalf("message %d: production bound failed: %v", i, err)
		}
	}
}
