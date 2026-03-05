package ml_dsa_87

import (
	"crypto"
	"testing"
)

func TestCryptoSignerInterface(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)

	// Verify it satisfies crypto.Signer at compile time.
	var _ crypto.Signer = signer

	// Public key round-trip
	pub := signer.Public()
	cpk, ok := pub.(*CryptoPublicKey)
	if !ok {
		t.Fatal("Public() did not return *CryptoPublicKey")
	}
	if cpk.Bytes() != d.GetPK() {
		t.Error("Public key mismatch between CryptoSigner and underlying MLDSA87")
	}
}

func TestCryptoSignerSignVerify(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("test message")
	ctx := []byte("test-context")

	sig, err := signer.Sign(nil, msg, &SignerOpts{Context: ctx})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != CRYPTO_BYTES {
		t.Fatalf("Signature length %d, expected %d", len(sig), CRYPTO_BYTES)
	}

	pk := d.GetPK()
	var sigArr [CRYPTO_BYTES]uint8
	copy(sigArr[:], sig)
	if !Verify(ctx, msg, sigArr, &pk) {
		t.Error("Signature verification failed")
	}
}

func TestCryptoSignerNilOpts(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("test message")

	// nil opts should use empty context
	sig, err := signer.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("Sign with nil opts failed: %v", err)
	}

	pk := d.GetPK()
	var sigArr [CRYPTO_BYTES]uint8
	copy(sigArr[:], sig)
	if !Verify(nil, msg, sigArr, &pk) {
		t.Error("Signature with nil opts failed verification with empty context")
	}
}

func TestCryptoSignerEmptyContext(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("test message")

	// Signing via CryptoSigner with empty SignerOpts should match direct Sign with nil ctx
	sig1, err := signer.Sign(nil, msg, &SignerOpts{})
	if err != nil {
		t.Fatalf("CryptoSigner sign failed: %v", err)
	}

	sig2, err := d.Sign(nil, msg)
	if err != nil {
		t.Fatalf("Direct sign failed: %v", err)
	}

	if string(sig1) != string(sig2[:]) {
		t.Error("CryptoSigner with empty context produced different signature than direct Sign with nil context")
	}
}

func TestCryptoSignerDeterministic(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("determinism test")
	opts := &SignerOpts{Context: []byte("ctx")}

	sig1, err := signer.Sign(nil, msg, opts)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := signer.Sign(nil, msg, opts)
	if err != nil {
		t.Fatal(err)
	}

	if string(sig1) != string(sig2) {
		t.Error("Deterministic signing produced different signatures for same input")
	}
}

func TestCryptoSignerWrongContext(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("test message")

	sig, err := signer.Sign(nil, msg, &SignerOpts{Context: []byte("context-a")})
	if err != nil {
		t.Fatal(err)
	}

	pk := d.GetPK()
	var sigArr [CRYPTO_BYTES]uint8
	copy(sigArr[:], sig)

	// Verify with wrong context should fail
	if Verify([]byte("context-b"), msg, sigArr, &pk) {
		t.Error("Signature verified with wrong context")
	}
}

func TestCryptoPublicKeyEqual(t *testing.T) {
	d1, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d1.Zeroize()

	d2, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Zeroize()

	s1 := NewCryptoSigner(d1)
	s2 := NewCryptoSigner(d2)

	pk1 := s1.Public()
	pk1Again := s1.Public()
	pk2 := s2.Public()

	cpk1 := pk1.(*CryptoPublicKey)

	if !cpk1.Equal(pk1Again) {
		t.Error("Same public key should be equal to itself")
	}
	if cpk1.Equal(pk2) {
		t.Error("Different public keys should not be equal")
	}
	if cpk1.Equal("not a key") {
		t.Error("Public key should not be equal to a non-key type")
	}
}

func TestCryptoSignerTypedNilOpts(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("test message")

	// A typed nil *SignerOpts should behave like empty context
	var opts *SignerOpts // typed nil
	sig, err := signer.Sign(nil, msg, opts)
	if err != nil {
		t.Fatalf("Sign with typed nil *SignerOpts failed: %v", err)
	}

	pk := d.GetPK()
	var sigArr [CRYPTO_BYTES]uint8
	copy(sigArr[:], sig)
	if !Verify(nil, msg, sigArr, &pk) {
		t.Error("Signature with typed nil *SignerOpts failed verification with empty context")
	}
}

func TestCryptoSignerUnsupportedOpts(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("test message")

	// Passing a non-*SignerOpts type should return an error
	_, err = signer.Sign(nil, msg, crypto.SHA256)
	if err == nil {
		t.Error("Expected error for unsupported SignerOpts type")
	}
}

func TestCryptoSignerContextTooLong(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("test message")
	longCtx := make([]byte, 256) // max is 255

	_, err = signer.Sign(nil, msg, &SignerOpts{Context: longCtx})
	if err == nil {
		t.Error("Expected error for context > 255 bytes")
	}
}

func TestSignerOptsHashFunc(t *testing.T) {
	opts := &SignerOpts{Context: []byte("test")}
	if opts.HashFunc() != 0 {
		t.Errorf("HashFunc() = %d, want 0", opts.HashFunc())
	}
}
