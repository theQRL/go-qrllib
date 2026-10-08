package ml_dsa_87

import (
	"bytes"
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// TestMLDSA87_ZeroValue drives the gap the lifecycle state closes: a
// MLDSA87{} declared without a constructor must not hand out a usable
// public key (its bytes are the weakest key there is) and must not sign.
func TestMLDSA87_ZeroValue(t *testing.T) {
	ctx, msg := []uint8("ZOND"), []uint8("zero-value keypair")
	var d MLDSA87

	if pk := d.PublicKey(); pk != nil {
		t.Fatal("zero-value MLDSA87 handed out a PublicKey")
	}
	// Verify on the nil it returns is a plain rejection, so the forgery
	// for the all-zero key has no route through here.
	if Verify(ctx, msg, forgeZeroT1Sig(t, zeroT1PK(0), ctx, msg), d.PublicKey()) {
		t.Fatal("SECURITY: forgery verified via a zero-value keypair's PublicKey()")
	}
	if _, err := d.Sign(ctx, msg); !errors.Is(err, cryptoerrors.ErrKeyUninitialised) {
		t.Fatalf("Sign: err = %v, want ErrKeyUninitialised", err)
	}
	if _, err := d.SignDeterministic(ctx, msg); !errors.Is(err, cryptoerrors.ErrKeyUninitialised) {
		t.Fatalf("SignDeterministic: err = %v, want ErrKeyUninitialised", err)
	}
	if _, err := d.SignAttached(ctx, msg); !errors.Is(err, cryptoerrors.ErrKeyUninitialised) {
		t.Fatalf("SignAttached: err = %v, want ErrKeyUninitialised", err)
	}
	if s := NewCryptoSigner(&d); s.Public() != nil {
		t.Fatal("CryptoSigner over a zero-value keypair returned a public key")
	} else if _, err := s.Sign(nil, msg, nil); !errors.Is(err, cryptoerrors.ErrKeyUninitialised) {
		t.Fatalf("CryptoSigner.Sign: err = %v, want ErrKeyUninitialised", err)
	}
	var nilD *MLDSA87
	if nilD.PublicKey() != nil {
		t.Fatal("nil *MLDSA87 returned a PublicKey")
	}
}

// TestMLDSA87_PublicKeyRechecks covers the defensive validation in
// PublicKey: an initialised keypair whose bytes fail validation (only
// constructible in-package) yields nil rather than a valid-marked key.
func TestMLDSA87_PublicKeyRechecks(t *testing.T) {
	d := MLDSA87{state: keyStateReady} // pk all zero
	if d.PublicKey() != nil {
		t.Fatal("PublicKey trusted an initialised keypair with weak bytes")
	}
}

// TestMLDSA87_SignAfterZeroize checks that a zeroized keypair refuses to
// sign on every path, that Zeroize is idempotent, and that the public key
// stays available.
func TestMLDSA87_SignAfterZeroize(t *testing.T) {
	ctx, msg := []uint8("ZOND"), []uint8("after zeroize")
	d, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pk := d.PublicKey()
	genuine, err := d.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	d.Zeroize()

	if sig, err := d.Sign(ctx, msg); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) || sig != ([CRYPTO_BYTES]uint8{}) {
		t.Fatalf("Sign after Zeroize: err = %v (sig zero=%v), want ErrSecretKeyZeroized", err, sig == [CRYPTO_BYTES]uint8{})
	}
	if _, err := d.SignDeterministic(ctx, msg); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Fatalf("SignDeterministic after Zeroize: err = %v", err)
	}
	if sm, err := d.SignAttached(ctx, msg); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) || sm != nil {
		t.Fatalf("SignAttached after Zeroize: sm=%v err=%v", sm, err)
	}
	s := NewCryptoSigner(d)
	if _, err := s.Sign(nil, msg, nil); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Fatalf("CryptoSigner.Sign (crypto/rand path) after Zeroize: err = %v", err)
	}
	if _, err := s.Sign(bytes.NewReader(make([]byte, RND_BYTES)), msg, nil); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Fatalf("CryptoSigner.Sign (caller rand path) after Zeroize: err = %v", err)
	}
	if !d.PublicKey().Equal(pk) || !s.Public().(*PublicKey).Equal(pk) {
		t.Fatal("public key not available after Zeroize")
	}
	if !Verify(ctx, msg, genuine, pk) {
		t.Fatal("pre-Zeroize signature must still verify under the public key")
	}
	d.Zeroize()
	if _, err := d.Sign(ctx, msg); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Fatal("Zeroize is not idempotent")
	}
}

// TestCryptoSigner_NilSafe checks that a signer built over nil, and a nil
// signer, report errors instead of panicking.
func TestCryptoSigner_NilSafe(t *testing.T) {
	s := NewCryptoSigner(nil)
	if s.Public() != nil {
		t.Fatal("NewCryptoSigner(nil).Public() returned a key")
	}
	if _, err := s.Sign(nil, []byte("x"), nil); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Fatalf("NewCryptoSigner(nil).Sign: err = %v, want ErrSecretKeyNil", err)
	}
	var nilS *CryptoSigner
	if nilS.Public() != nil {
		t.Fatal("nil *CryptoSigner returned a key")
	}
	if _, err := nilS.Sign(nil, []byte("x"), nil); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Fatalf("nil *CryptoSigner Sign: err = %v", err)
	}
}
