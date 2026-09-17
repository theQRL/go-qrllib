package ml_dsa_87

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// TestParsePublicKey_RoundTrip checks that a generated key parses, that
// Bytes() returns the packed encoding, and that it equals MLDSA87.PublicKey.
func TestParsePublicKey_RoundTrip(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	packed := d.GetPK()
	pk, err := ParsePublicKey(packed[:])
	if err != nil {
		t.Fatalf("ParsePublicKey rejected a generated key: %v", err)
	}
	if pk.Bytes() != packed {
		t.Fatal("Bytes() does not round-trip the packed encoding")
	}
	if !pk.Equal(d.PublicKey()) || !d.PublicKey().Equal(pk) {
		t.Fatal("ParsePublicKey and MLDSA87.PublicKey disagree for the same key")
	}
}

// TestParsePublicKey_WrongLength checks that anything but exactly
// CRYPTO_PUBLIC_KEY_BYTES is rejected before validation runs.
func TestParsePublicKey_WrongLength(t *testing.T) {
	for _, n := range []int{0, 1, CRYPTO_PUBLIC_KEY_BYTES - 1, CRYPTO_PUBLIC_KEY_BYTES + 1} {
		_, err := ParsePublicKey(make([]byte, n))
		if !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
			t.Fatalf("len %d: err = %v, want ErrInvalidPublicKey", n, err)
		}
	}
}

// TestParsePublicKey_RejectsZeroT1 checks the validation hook: the
// universally forgeable key cannot be constructed from outside the package.
func TestParsePublicKey_RejectsZeroT1(t *testing.T) {
	for _, rho := range []uint8{0x00, 0xab} {
		pk := zeroT1PK(rho)
		if _, err := ParsePublicKey(pk[:]); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
			t.Fatalf("rho=%#x: err = %v, want ErrWeakPublicKey", rho, err)
		}
	}
}

// TestVerify_ParsedKey checks that a key obtained via ParsePublicKey
// verifies and opens genuine signatures — the production path.
func TestVerify_ParsedKey(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	packed := d.GetPK()
	pk, err := ParsePublicKey(packed[:])
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	ctx, msg := []uint8("ZOND"), []uint8("parsed-key verification")
	sig, err := d.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(ctx, msg, sig, pk) {
		t.Fatal("Verify rejected a genuine signature under a parsed key")
	}
	sealed := append(append([]uint8{}, sig[:]...), msg...)
	if got, err := Open(ctx, sealed, pk); err != nil || string(got) != string(msg) {
		t.Fatalf("Open failed under a parsed key: got %q err %v", got, err)
	}
}

// TestPublicKey_ZeroValueRejected drives the exact attack the validity
// marker exists to stop: Go lets any package declare `var pk PublicKey`,
// and that zero value's bytes are the forgeable all-zero-t1 key. Verify and
// Open must refuse it even when handed the working forgery for that key.
func TestPublicKey_ZeroValueRejected(t *testing.T) {
	ctx, msg := []uint8("ZOND"), []uint8("zero-value forgery")
	var zero PublicKey // rho = 0, t1 = 0, valid = false

	// The forgery for the all-zero key does verify at the raw primitive —
	// that is FIPS 204 behaviour and is pinned elsewhere. Here it must not
	// get past the exported API via the zero value.
	sig := forgeZeroT1Sig(t, zeroT1PK(0), ctx, msg)
	if Verify(ctx, msg, sig, &zero) {
		t.Fatal("SECURITY: Verify accepted a forgery under a zero-value PublicKey{}")
	}
	sealed := append(append([]uint8{}, sig[:]...), msg...)
	if got, err := Open(ctx, sealed, &zero); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) || got != nil {
		t.Fatalf("Open on zero-value key: got %v err %v, want nil + ErrInvalidPublicKey", got, err)
	}

	// The same bytes through the validating constructor are refused too, so
	// there is no route by which those bytes become a usable key.
	if _, err := ParsePublicKey(zero.packed[:]); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
		t.Fatalf("ParsePublicKey on zero bytes: err = %v, want ErrWeakPublicKey", err)
	}

	// Zero values never compare equal, even to themselves.
	if zero.Equal(&zero) {
		t.Fatal("zero-value PublicKey compared equal to itself")
	}
	d, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.PublicKey().Equal(&zero) || zero.Equal(d.PublicKey()) {
		t.Fatal("zero-value PublicKey compared equal to a real key")
	}
}

// TestPublicKey_EqualEdgeCases covers the nil-receiver, nil-argument and
// wrong-type branches of Equal.
func TestPublicKey_EqualEdgeCases(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pk := d.PublicKey()
	var nilPK *PublicKey
	if nilPK.Equal(pk) {
		t.Fatal("nil receiver compared equal")
	}
	if pk.Equal(nilPK) {
		t.Fatal("nil argument compared equal")
	}
	if pk.Equal("not a key") {
		t.Fatal("wrong type compared equal")
	}
	if !pk.Equal(pk) {
		t.Fatal("key not equal to itself")
	}
}
