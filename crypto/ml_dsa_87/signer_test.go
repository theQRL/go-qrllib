package ml_dsa_87

import (
	"bytes"
	"crypto"
	"errors"
	"testing"
)

// zeroReader is an io.Reader that always returns zero bytes. Used
// in TestCryptoSignerCallerSuppliedRand to demonstrate that the
// caller-supplied rand really feeds the per-signature rnd value
// (so two calls with the same zero source produce identical
// signatures, matching the FIPS 204 §3.5 deterministic mode).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// errReader is an io.Reader that always returns a fixed error before
// producing any bytes. Used to exercise the io.ReadFull failure path
// in CryptoSigner.Sign when the caller supplies a broken rand source.
type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

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

	// Hedged signing (TOB-QRLLIB-6): signatures from CryptoSigner and
	// direct MLDSA87.Sign won't match byte-for-byte even with the same
	// (empty) context. The meaningful invariant is that BOTH verify
	// under the same public key with the same context.
	sig1, err := signer.Sign(nil, msg, &SignerOpts{})
	if err != nil {
		t.Fatalf("CryptoSigner sign failed: %v", err)
	}

	sig2, err := d.Sign(nil, msg)
	if err != nil {
		t.Fatalf("Direct sign failed: %v", err)
	}

	pk := d.GetPK()
	var sigArr1, sigArr2 [CRYPTO_BYTES]uint8
	copy(sigArr1[:], sig1)
	copy(sigArr2[:], sig2[:])
	if !Verify(nil, msg, sigArr1, &pk) {
		t.Error("CryptoSigner signature with empty context did not verify")
	}
	if !Verify(nil, msg, sigArr2, &pk) {
		t.Error("Direct Sign signature with empty context did not verify")
	}
}

// TestCryptoSignerHedged confirms the public CryptoSigner path is
// hedged (TOB-QRLLIB-6): two Sign calls with the same key, message,
// context, and nil rand reader produce DISTINCT signatures, both of
// which verify. The previous TestCryptoSignerDeterministic asserted
// the opposite — was retired alongside the deterministic-default path.
func TestCryptoSignerHedged(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()

	signer := NewCryptoSigner(d)
	msg := []byte("hedged-signing test")
	opts := &SignerOpts{Context: []byte("ctx")}

	sig1, err := signer.Sign(nil, msg, opts)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := signer.Sign(nil, msg, opts)
	if err != nil {
		t.Fatal(err)
	}

	if string(sig1) == string(sig2) {
		t.Error("Hedged CryptoSigner.Sign should produce distinct signatures for the same input; got identical bytes")
	}

	pk := d.GetPK()
	var sigArr1, sigArr2 [CRYPTO_BYTES]uint8
	copy(sigArr1[:], sig1)
	copy(sigArr2[:], sig2)
	if !Verify(opts.Context, msg, sigArr1, &pk) {
		t.Error("First hedged signature failed verification")
	}
	if !Verify(opts.Context, msg, sigArr2, &pk) {
		t.Error("Second hedged signature failed verification")
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

// TestCryptoSignerCallerSuppliedRand verifies that CryptoSigner.Sign
// honours the caller-supplied io.Reader as the per-signature RND
// source (FIPS 204 §3.5). Pre-TOB-QRLLIB-6 fix: the rand parameter
// was discarded. Post-fix: two calls with the same zero-source reader
// produce identical signatures (matching FIPS-204 deterministic mode),
// while two calls with crypto/rand-derived sources produce distinct
// signatures.
func TestCryptoSignerCallerSuppliedRand(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()
	signer := NewCryptoSigner(d)

	msg := []byte("rand-source test")
	opts := &SignerOpts{Context: []byte("ctx")}

	// Two signs from the same zero-reader → identical sigs (proves rand IS being read).
	sig1, err := signer.Sign(zeroReader{}, msg, opts)
	if err != nil {
		t.Fatalf("first Sign with zeroReader failed: %v", err)
	}
	sig2, err := signer.Sign(zeroReader{}, msg, opts)
	if err != nil {
		t.Fatalf("second Sign with zeroReader failed: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("Sign with zero-source reader should be deterministic; got differing signatures (rand was not honoured)")
	}

	// Sanity: the deterministic-rnd signature still verifies under
	// the public key.
	pk := d.GetPK()
	var sigArr [CRYPTO_BYTES]uint8
	copy(sigArr[:], sig1)
	if !Verify(opts.Context, msg, sigArr, &pk) {
		t.Error("Caller-rnd-driven signature failed verification under its own pk")
	}

	// Nil rand (default path) still produces hedged signatures.
	sigA, err := signer.Sign(nil, msg, opts)
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := signer.Sign(nil, msg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sigA, sigB) {
		t.Error("Sign with nil rand should be hedged (crypto/rand); got identical signatures")
	}
}

// TestCryptoSignerRandReaderError exercises the io.ReadFull failure
// path in CryptoSigner.Sign: if the caller supplies a non-nil rand
// io.Reader that errors before producing RND_BYTES, Sign must
// surface the underlying reader error rather than panic or silently
// fall back to crypto/rand. Closes the coverage gap on this branch.
func TestCryptoSignerRandReaderError(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()
	signer := NewCryptoSigner(d)

	wantErr := errors.New("simulated rand source failure")
	_, err = signer.Sign(errReader{err: wantErr}, []byte("msg"), &SignerOpts{Context: []byte("ctx")})
	if err == nil {
		t.Fatal("expected an error from a failing rand io.Reader, got nil")
	}
	if err != wantErr {
		t.Errorf("expected the underlying reader error to surface; got %v, want %v", err, wantErr)
	}
}

// TestCryptoSignerRandSuppliedContextTooLong exercises the
// cryptoSignSignatureWithRnd failure path in CryptoSigner.Sign when
// the caller supplies a valid rand source but an oversized context.
// Closes the coverage gap on this branch (the existing
// TestCryptoSignerContextTooLong uses nil rand and so exercises the
// MLDSA87.Sign error path instead).
func TestCryptoSignerRandSuppliedContextTooLong(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Zeroize()
	signer := NewCryptoSigner(d)

	longCtx := make([]byte, 256) // FIPS 204 max is 255

	_, err = signer.Sign(zeroReader{}, []byte("msg"), &SignerOpts{Context: longCtx})
	if err == nil {
		t.Error("expected an error for context > 255 bytes via the rand-supplied path")
	}
}
