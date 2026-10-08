package falcon1024

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}

func testPrivateKey(t *testing.T) *PrivateKey {
	t.Helper()
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// degeneratePrivateKey builds f = 1, g = 0, F = G = 0 directly, bypassing
// NewPrivateKey. The reference's own checks accept this key (f is invertible,
// G is small) but it is outside the key-generation bounds: its lattice basis
// is singular, the sampled lattice point is always zero and every signing
// attempt is rejected.
func degeneratePrivateKey(t *testing.T) *PrivateKey {
	t.Helper()
	var f, g, ntruF, ntruG smallPolynomial
	f[0] = 1
	h, ok := computePublic(f, g)
	if !ok {
		t.Fatal("f = 1 is invertible mod q")
	}
	priv, err := initPrivateKey(&PrivateKey{}, f, g, ntruF, ntruG, h)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestGenerateKeyReportsReaderFailure(t *testing.T) {
	boom := errors.New("boom")
	if _, err := GenerateKey(iotest.ErrReader(boom)); !errors.Is(err, boom) || !errors.Is(err, cryptoerrors.ErrSeedGeneration) {
		t.Fatalf("GenerateKey with a failing reader: error = %v; want boom wrapped in ErrSeedGeneration", err)
	}
	priv := testPrivateKey(t)
	if _, signErr := Sign(iotest.ErrReader(boom), priv, []byte("m")); !errors.Is(signErr, boom) || !errors.Is(signErr, cryptoerrors.ErrSeedGeneration) {
		t.Fatalf("Sign with a failing reader: error = %v; want boom wrapped in ErrSeedGeneration", signErr)
	}
	if _, shortErr := SignDetached(bytes.NewReader(make([]byte, nonceSize+1)), priv, []byte("m")); !errors.Is(shortErr, io.ErrUnexpectedEOF) || !errors.Is(shortErr, cryptoerrors.ErrSeedGeneration) {
		t.Fatalf("SignDetached with a short reader: error = %v; want ErrUnexpectedEOF wrapped in ErrSeedGeneration", shortErr)
	}
}

// The zero value is uninitialised, distinct from nil and from zeroized, as
// in the ML-DSA-87 lifecycle model.
func TestUninitialisedKeyIsRefused(t *testing.T) {
	var zero PrivateKey
	message := []byte("uninitialised")
	if _, err := Sign(zeroReader{}, &zero, message); !errors.Is(err, cryptoerrors.ErrKeyUninitialised) {
		t.Errorf("Sign on a zero-value key: error = %v; want ErrKeyUninitialised", err)
	}
	if _, err := SignDetached(zeroReader{}, &zero, message); !errors.Is(err, cryptoerrors.ErrKeyUninitialised) {
		t.Errorf("SignDetached on a zero-value key: error = %v; want ErrKeyUninitialised", err)
	}
	if zero.Bytes() != nil || zero.PublicKey() != nil || zero.Equal(&zero) {
		t.Error("zero-value key is not inert")
	}
	ready := testPrivateKey(t)
	if ready.Equal(&zero) || zero.Equal(ready) {
		t.Error("uninitialised key compared Equal to a ready key")
	}
}

func TestShortSignaturesAreSizeErrors(t *testing.T) {
	priv := testPrivateKey(t)
	pub := priv.PublicKey()
	message := []byte("sizes")
	sig, err := SignDetached(zeroReader{}, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	if sizeErr := Verify(pub, message, sig[:detachedSignaturePrefixSize-1]); !errors.Is(sizeErr, cryptoerrors.ErrInvalidSignatureSize) {
		t.Errorf("Verify of a 40-byte signature: error = %v; want ErrInvalidSignatureSize", sizeErr)
	}
	if encErr := Verify(pub, message, sig[:detachedSignaturePrefixSize]); !errors.Is(encErr, cryptoerrors.ErrInvalidSignature) || errors.Is(encErr, cryptoerrors.ErrInvalidSignatureSize) {
		t.Errorf("Verify of a prefix-only signature: error = %v; want ErrInvalidSignature only", encErr)
	}
	sm, err := Sign(zeroReader{}, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	if _, openErr := Open(pub, sm[:signedMessagePrefixSize-1]); !errors.Is(openErr, cryptoerrors.ErrInvalidSignatureSize) {
		t.Errorf("Open of a 41-byte signed message: error = %v; want ErrInvalidSignatureSize", openErr)
	}
}

// A signature that does not fit its encoding is a signing failure.
func TestEncodingFailuresAreSigningFailures(t *testing.T) {
	var nonce [nonceSize]byte
	outOfRange := smallPolynomial{0: maxCompressedCoefficient + 1}
	if _, err := detachedSignatureEncode(nonce, outOfRange); !errors.Is(err, cryptoerrors.ErrSigningFailed) {
		t.Errorf("out-of-range coefficient: error = %v; want ErrSigningFailed", err)
	}
	if _, err := signedMessageEncode(nonce, nil, outOfRange); !errors.Is(err, cryptoerrors.ErrSigningFailed) {
		t.Errorf("out-of-range coefficient in a signed message: error = %v; want ErrSigningFailed", err)
	}
	var buf [8]byte
	if _, err := compressedEncode(buf[:], smallPolynomial{}); !errors.Is(err, cryptoerrors.ErrSigningFailed) {
		t.Errorf("short buffer: error = %v; want ErrSigningFailed", err)
	}
}

func TestNilKeysAreRefused(t *testing.T) {
	priv := testPrivateKey(t)
	message := []byte("nil")
	sm, err := Sign(zeroReader{}, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignDetached(zeroReader{}, priv, message)
	if err != nil {
		t.Fatal(err)
	}

	var nilPub *PublicKey
	var nilPriv *PrivateKey

	if m, err := Open(nilPub, sm); m != nil || !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("Open(nil) = %v, %v", m, err)
	}
	if err := Verify(nilPub, message, sig); !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("Verify(nil) = %v", err)
	}
	if nilPub.Bytes() != nil || nilPub.Equal(priv.PublicKey()) || priv.PublicKey().Equal(nilPub) {
		t.Error("nil public key is not inert")
	}

	if _, err := Sign(zeroReader{}, nilPriv, message); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Errorf("Sign(nil) = %v", err)
	}
	if _, err := SignDetached(zeroReader{}, nilPriv, message); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Errorf("SignDetached(nil) = %v", err)
	}
	if nilPriv.Bytes() != nil || nilPriv.PublicKey() != nil || nilPriv.Equal(priv) || priv.Equal(nilPriv) {
		t.Error("nil private key is not inert")
	}
	nilPriv.Zeroize()
}

func TestZeroizeWipesSecretsAndKeepsPublicKey(t *testing.T) {
	priv := testPrivateKey(t)
	message := []byte("zeroize")
	sig, err := SignDetached(zeroReader{}, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	same := testPrivateKey(t)
	if !priv.Equal(same) {
		t.Fatal("identical keys are not Equal")
	}
	heldPub := priv.PublicKey()

	priv.Zeroize()

	if priv.Bytes() != nil {
		t.Error("Bytes after Zeroize is not nil")
	}
	if priv.raw != [PrivateKeySize]byte{} {
		t.Error("encoded key not wiped")
	}
	for _, p := range []*fftPolynomial{&priv.b00, &priv.b01, &priv.b10, &priv.b11} {
		if *p != (fftPolynomial{}) {
			t.Error("FFT basis not wiped")
		}
	}
	if priv.tree != (fprTree{}) {
		t.Error("LDL tree not wiped")
	}
	if _, err := Sign(zeroReader{}, priv, message); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Errorf("Sign after Zeroize = %v", err)
	}
	if _, err := SignDetached(zeroReader{}, priv, message); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Errorf("SignDetached after Zeroize = %v", err)
	}
	if priv.Equal(same) || same.Equal(priv) {
		t.Error("zeroized key compared Equal")
	}
	if err := Verify(heldPub, message, sig); err != nil {
		t.Errorf("held public key no longer verifies: %v", err)
	}
	if err := Verify(priv.PublicKey(), message, sig); err != nil {
		t.Errorf("public key of a zeroized key no longer verifies: %v", err)
	}
	priv.Zeroize() // idempotent
}

func TestPublicKeyIsACopy(t *testing.T) {
	priv := testPrivateKey(t)
	first := priv.PublicKey()
	first.raw[1] ^= 0xFF
	if second := priv.PublicKey(); second.raw[1] == first.raw[1] {
		t.Error("PublicKey returned a pointer into the private key")
	}
}

func TestNewPrivateKeyAppliesKeygenBounds(t *testing.T) {
	valid := testPrivateKey(t).Bytes()

	// f = 1, g = 0, F = 0: the Gram-Schmidt norm bound fails.
	degenerate := make([]byte, PrivateKeySize)
	degenerate[0], degenerate[1] = privateKeyHeader, 0x08
	if _, err := NewPrivateKey(degenerate); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
		t.Errorf("degenerate key: error = %v; want ErrInvalidSecretKey", err)
	}

	// f = 15 everywhere, g = 0, F = 0: the squared norm bound fails first.
	large := make([]byte, PrivateKeySize)
	large[0] = privateKeyHeader
	copy(large[1:], bytes.Repeat([]byte{0x7B, 0xDE, 0xF7, 0xBD, 0xEF}, 128))
	if _, err := NewPrivateKey(large); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
		t.Errorf("large-norm key: error = %v; want ErrInvalidSecretKey", err)
	}

	// An F that does not belong to (f, g) fails the G recomputation.
	inconsistent := bytes.Clone(valid)
	inconsistent[1281] ^= 0x01
	if _, err := NewPrivateKey(inconsistent); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
		t.Errorf("inconsistent F: error = %v; want ErrInvalidSecretKey", err)
	}

	// The forbidden encodings reach NewPrivateKey through skDecode.
	for name, mutate := range map[string]func([]byte){
		"f = -16":  func(sk []byte) { sk[1] = sk[1]&0x07 | 0x80 },
		"g = -16":  func(sk []byte) { sk[641] = sk[641]&0x07 | 0x80 },
		"F = -128": func(sk []byte) { sk[1281] = 0x80 },
	} {
		sk := bytes.Clone(valid)
		mutate(sk)
		if _, err := NewPrivateKey(sk); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
			t.Errorf("%s: error = %v; want ErrInvalidSecretKey", name, err)
		}
	}

	if _, err := NewPrivateKey(valid); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
}

func TestSignLoopIsBounded(t *testing.T) {
	priv := degeneratePrivateKey(t)
	message := []byte("bounded")

	h := sha3.NewSHAKE256()
	_, _ = h.Write(message)
	c0 := hashToPoint(h)
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("bounded sampler"))
	if _, err := sign(rng, priv, c0); !errors.Is(err, cryptoerrors.ErrSigningFailed) {
		t.Fatalf("sign with a singular basis: error = %v; want ErrSigningFailed", err)
	}
	// Sign and SignDetached propagate the error through signCore; the
	// zeroized-key test exercises that path without another full run.
}

func TestNewPublicKeyRejectsBadEncodings(t *testing.T) {
	pk := testPrivateKey(t).PublicKey().Bytes()
	atQ := bytes.Clone(pk)
	atQ[1], atQ[2] = 0xC0, atQ[2]&0x03|0x04
	for name, bad := range map[string][]byte{
		"nil":            nil,
		"short":          pk[:PublicKeySize-1],
		"long":           append(bytes.Clone(pk), 0),
		"header":         append([]byte{pk[0] ^ 0xFF}, pk[1:]...),
		"coefficient q":  atQ,
		"all 0x3FFF":     append([]byte{publicKeyHeader}, bytes.Repeat([]byte{0xFF}, PublicKeySize-1)...),
		"body too short": pk[:headerSize],
	} {
		if _, err := NewPublicKey(bad); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
			t.Errorf("%s: error = %v; want ErrInvalidPublicKey", name, err)
		}
	}
	if _, err := polyByteDecode(pk[headerSize : PublicKeySize-1]); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
		t.Errorf("polyByteDecode short input: error = %v; want ErrInvalidPublicKey", err)
	}
}

func TestCompressedDecodeRejectsTruncatedUnaryRun(t *testing.T) {
	// Eight zero bits for the sign and low magnitude, then a unary run of
	// zeros that ends before its terminating one bit.
	if _, _, err := compressedDecode([]byte{0x00, 0x00}); !errors.Is(err, errInvalidSignatureEncoding) {
		t.Fatalf("error = %v; want errInvalidSignatureEncoding", err)
	}
	// The same error wraps the library sentinel.
	if _, _, err := compressedDecode([]byte{0x00, 0x00}); !errors.Is(err, cryptoerrors.ErrInvalidSignature) {
		t.Fatalf("error = %v does not wrap ErrInvalidSignature", err)
	}
}

func TestCompressedEncodeNeedsRoomForFinalPartialByte(t *testing.T) {
	var s2 smallPolynomial
	s2[0] = 128 // 10 bits; the other 1023 coefficients take 9 bits each: 9217 bits
	var buf [MaxSignatureSize]byte
	written, err := compressedEncode(buf[:], s2)
	if err != nil {
		t.Fatal(err)
	}
	if written != 1153 {
		t.Fatalf("encoded %d bytes, want 1153", written)
	}
	if _, err := compressedEncode(buf[:written-1], s2); !errors.Is(err, errCompressedSignatureTooLarge) {
		t.Fatalf("one byte short: error = %v; want errCompressedSignatureTooLarge", err)
	}
}

func TestSkEncodeRejectsOutOfRangeCoefficients(t *testing.T) {
	var dst [PrivateKeySize]byte
	var f, g, ntruF smallPolynomial
	tooLarge := smallPolynomial{0: 16}
	if err := skEncode(dst[:], tooLarge, g, ntruF); err == nil {
		t.Error("f = 16 accepted")
	}
	if err := skEncode(dst[:], f, tooLarge, ntruF); err == nil {
		t.Error("g = 16 accepted")
	}
	if err := skEncode(dst[:], f, g, smallPolynomial{0: 128}); err == nil {
		t.Error("F = 128 accepted")
	}
	if err := skEncode(dst[:PrivateKeySize-1], f, g, ntruF); !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) {
		t.Errorf("short buffer: error = %v; want ErrInvalidSecretKey", err)
	}
	if err := skEncode(dst[:], f, g, ntruF); err != nil {
		t.Errorf("zero polynomials rejected: %v", err)
	}
	if _, err := trimI8Encode(dst[:], f, 7); err == nil {
		t.Error("trimI8Encode accepted an unsupported width")
	}
	if _, err := trimI8Encode(dst[:10], f, fgBits); err == nil {
		t.Error("trimI8Encode accepted a short buffer")
	}
	if _, _, err := trimI8Decode(dst[:], 7); err == nil {
		t.Error("trimI8Decode accepted an unsupported width")
	}
	if _, _, err := trimI8Decode(dst[:10], fgBits); err == nil {
		t.Error("trimI8Decode accepted a short input")
	}
	if err := pkEncode(dst[:PublicKeySize-1], ringElement{}); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
		t.Errorf("pkEncode short buffer: error = %v; want ErrInvalidPublicKey", err)
	}
}

func TestCoefficientsExceedBound(t *testing.T) {
	var p smallPolynomial
	if coefficientsExceedBound(p, 0) {
		t.Error("zero polynomial exceeds bound 0")
	}
	p[1023] = -16
	if !coefficientsExceedBound(p, 15) {
		t.Error("-16 does not exceed bound 15")
	}
	p[1023] = 16
	if !coefficientsExceedBound(p, 15) {
		t.Error("16 does not exceed bound 15")
	}
}

// solveNTRU rejects (f, g) whose resultants with x^n+1 are not coprime; f = g
// is the simplest such pair and fails in the deepest stage.
func TestSolveNTRURejectsEqualFG(t *testing.T) {
	var f smallPolynomial
	f[0], f[1], f[5] = 3, -2, 1
	if _, _, ok := solveNTRU(f, f); ok {
		t.Fatal("solveNTRU solved f = g")
	}
}

// For (f, g) inside the key-generation bounds the solver still rejects a
// fraction of inputs at the intermediate depths; key generation retries.
// The search below is deterministic and small enough to run every time.
func TestSolveNTRUIntermediateRejection(t *testing.T) {
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("ntru intermediate rejection"))
	for range 400 {
		f := sampleGaussianPolynomial(rng)
		g := sampleGaussianPolynomial(rng)
		if squaredNormExceedsBound(f, g, keygenSqNormBound) ||
			orthogonalizedNormExceedsBound(f, g, keygenBNormBound) {
			continue
		}
		if _, ok := computePublic(f, g); !ok {
			continue
		}
		if _, _, ok := solveNTRU(f, g); !ok {
			return
		}
	}
	t.Fatal("no in-bound (f, g) rejected by the solver within the search budget")
}

func TestScratchExhaustionPanics(t *testing.T) {
	expectPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s did not panic", name)
			}
		}()
		f()
	}
	expectPanic("uint32Scratch", func() {
		s := newUint32Scratch(make([]uint32, 1))
		_ = s.take(2)
	})
	expectPanic("fprScratch", func() {
		s := newFPRScratch(make([]fpr, 1))
		_ = s.take(2)
	})
	expectPanic("ffLDLFFT short scratch", func() {
		var tree [8]fpr
		var g [2]fpr
		ffLDLFFT(tree[:], g[:], g[:], g[:], 1, nil)
	})
}

func TestDegreeOneAndEmptyPaths(t *testing.T) {
	one := []fpr{3}
	fft(one, 0)
	if one[0] != 3 {
		t.Error("fft at degree 1 changed its input")
	}
	var tree [1]fpr
	ffLDLFFT(tree[:], []fpr{5}, []fpr{0}, []fpr{0}, 0, nil)
	if tree[0] != 5 {
		t.Error("ffLDLFFT at degree 1 did not copy g00")
	}
	dst := []fpr{1, 2, 3, 4}
	polyBigToFP(dst, nil, 0, 1, 2)
	if dst[0] != 0 || dst[3] != 0 {
		t.Error("polyBigToFP with no words did not clear the output")
	}

	// makeFG at depth 0 with NTT output: the result is the NTT of f and g.
	var f, g smallPolynomial
	f[0], g[1] = 1, 1
	data := make([]uint32, makeFGScratchLen)
	makeFG(data, f, g, 0, true)
	p := smallPrimes[0].p
	for i := range n {
		if data[i] != modPSet(1, p) {
			t.Fatal("NTT of the constant 1 is not all ones")
		}
	}
	if data[n] == data[n+1] {
		t.Fatal("NTT of x is constant")
	}
}

// Falcon public keys carry no structural check: a constant polynomial close
// to sqrt(q) lets anyone round a hash to a short lattice point and produce a
// signature the verifier accepts. Keys from GenerateKey never have this
// shape. This test pins the documented absence of validation; if a rule for
// such keys is adopted, it must change to expect rejection.
func TestConstantPublicKeyIsNotRejected(t *testing.T) {
	const k = 111
	var h ringElement
	h[0] = k
	pub, err := newPublicKeyFromH(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, parseErr := NewPublicKey(pub.Bytes()); parseErr != nil {
		t.Fatalf("constant key rejected by NewPublicKey: %v", parseErr)
	}

	message := []byte("constant public key")
	var nonce [nonceSize]byte
	hash := sha3.NewSHAKE256()
	_, _ = hash.Write(nonce[:])
	_, _ = hash.Write(message)
	c0 := hashToPoint(hash)

	var s2 smallPolynomial
	for i, c := range c0 {
		v := int32(c)
		if v > q/2 {
			v -= q
		}
		// Nearest multiple of k, rounding half away from zero.
		s2[i] = (2*v + k) / (2 * k)
		if v < 0 {
			s2[i] = -((-2*v + k) / (2 * k))
		}
	}
	sig, err := detachedSignatureEncode(nonce, s2)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(&pub, message, sig); err != nil {
		t.Fatalf("forged signature under a constant key rejected: %v (adopting a key rule? update this test)", err)
	}
}
