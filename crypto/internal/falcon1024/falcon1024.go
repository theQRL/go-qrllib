package falcon1024

import (
	"crypto/sha3"
	"crypto/subtle"
	"fmt"
	"io"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// This package follows the NIST API of the Falcon round-3 reference
// implementation (nist.c) with the size constants of PQClean's api.h: key
// generation expands SeedSize random bytes with SHAKE256 exactly as
// crypto_sign_keypair expands the bytes it draws from randombytes, private
// and public keys use the CRYPTO_SECRETKEYBYTES and
// CRYPTO_PUBLICKEYBYTES encodings, and Sign and Open produce and consume the
// crypto_sign signed-message format. SignDetached and Verify add the
// compressed detached-signature format of the reference library API
// (falcon.h, FALCON_SIG_COMPRESSED), which carries the same nonce and
// compressed polynomial as the signed message under the header byte 0x3A.
const (
	// SeedSize is the number of random bytes key generation consumes, which
	// the reference crypto_sign_keypair draws with randombytes.
	SeedSize = 48

	// PublicKeySize is the size in bytes of an encoded public key
	// (CRYPTO_PUBLICKEYBYTES).
	PublicKeySize = 1793

	// PrivateKeySize is the size in bytes of an encoded private key
	// (CRYPTO_SECRETKEYBYTES).
	PrivateKeySize = 2305

	// MaxSignedMessageOverhead is the most a signed message exceeds the
	// message it carries, in bytes: CRYPTO_BYTES of PQClean's api.h at the
	// pinned commit (0586a824), which equals FALCON_SIG_COMPRESSED_MAXSIZE.
	// The round-3 submission's api.h said 1330, so its crypto_sign stopped at
	// a 1,287-byte body; bodies are 1,230 +/- 3 bytes, so neither limit is
	// reached by an in-bound key.
	MaxSignedMessageOverhead = 1462

	// MaxSignatureSize is the maximum size in bytes of a detached signature
	// (FALCON_SIG_COMPRESSED_MAXSIZE of the reference library API for degree
	// 1024).
	MaxSignatureSize = 1462
)

// Every error the package returns wraps a sentinel from crypto/errors, so
// callers can route on errors.Is(err, cryptoerrors.ErrInvalidSignature) and
// the like, as they can for the other schemes in the library. A failing
// randomness reader is reported through randomnessError, which wraps
// ErrSeedGeneration together with the reader's own error; a signature that
// does not fit its encoding wraps ErrSigningFailed (codec.go).
var (
	errInvalidSeedLength = fmt.Errorf("falcon-1024: invalid seed length: %w", cryptoerrors.ErrInvalidSeed)
	errInvalidPrivateKey = fmt.Errorf("falcon-1024: invalid private key: %w", cryptoerrors.ErrInvalidSecretKey)
	errPublicKeyNil      = fmt.Errorf("falcon-1024: %w", cryptoerrors.ErrPublicKeyNil)
	errSecretKeyNil      = fmt.Errorf("falcon-1024: %w", cryptoerrors.ErrSecretKeyNil)
	errSecretKeyZeroized = fmt.Errorf("falcon-1024: %w", cryptoerrors.ErrSecretKeyZeroized)
	errKeyUninitialised  = fmt.Errorf("falcon-1024: %w", cryptoerrors.ErrKeyUninitialised)
	errSigningFailed     = fmt.Errorf("falcon-1024: %w", cryptoerrors.ErrSigningFailed)
	errInvalidSignature  = fmt.Errorf("falcon-1024: %w", cryptoerrors.ErrInvalidSignature)
)

// randomnessError reports a failure of the caller's io.Reader. The reader's
// error stays in the chain for inspection; ErrSeedGeneration is the sentinel
// the other schemes use for the same failure.
func randomnessError(err error) error {
	return fmt.Errorf("falcon-1024: reading randomness: %w: %w", cryptoerrors.ErrSeedGeneration, err)
}

// keyState is the keypair lifecycle, the same three states the ML-DSA-87
// package uses (SECURITY.md, "Keypair lifecycle"): a zero value that never
// went through a constructor is uninitialised, a constructed key is ready,
// and a key stays zeroized after Zeroize.
type keyState uint8

const (
	keyStateUninitialised keyState = iota
	keyStateReady
	keyStateZeroized
)

// PrivateKey holds the encoded key together with the FFT basis and LDL tree
// signing uses. It is read-only after construction, so concurrent Sign calls
// on one key are safe; Zeroize is the one mutation and must not run
// concurrently with them.
type PrivateKey struct {
	raw                [PrivateKeySize]byte
	pub                PublicKey
	b00, b01, b10, b11 fftPolynomial
	tree               fprTree
	state              keyState
}

// signable reports whether the key may sign: nil for a ready key, an error
// wrapping ErrKeyUninitialised or ErrSecretKeyZeroized otherwise.
func (priv *PrivateKey) signable() error {
	switch priv.state {
	case keyStateReady:
		return nil
	case keyStateZeroized:
		return errSecretKeyZeroized
	default:
		return errKeyUninitialised
	}
}

// Equal reports whether priv and x hold the same key. A key that is nil,
// uninitialised or zeroized equals nothing.
func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	if priv == nil || x == nil || priv.state != keyStateReady || x.state != keyStateReady {
		return false
	}
	return subtle.ConstantTimeCompare(priv.raw[:], x.raw[:]) == 1
}

// Bytes returns the PrivateKeySize-byte encoding of priv: the header byte
// 0x5A, then f and g at five bits per coefficient and F at eight. It returns
// nil for a key that is nil, uninitialised or zeroized.
func (priv *PrivateKey) Bytes() []byte {
	if priv == nil || priv.state != keyStateReady {
		return nil
	}
	sk := priv.raw
	return sk[:]
}

// PublicKey returns a copy of the public key, so that holding it does not
// keep the private key reachable. It returns nil for a nil or uninitialised
// key, and stays available after Zeroize.
func (priv *PrivateKey) PublicKey() *PublicKey {
	if priv == nil || priv.state == keyStateUninitialised {
		return nil
	}
	pub := priv.pub
	return &pub
}

// Zeroize overwrites the secret material of priv: the encoded key, the FFT
// basis and the LDL tree. The public key stays available. Signing with a
// zeroized key returns an error wrapping ErrSecretKeyZeroized. Calling it on
// a nil key or more than once is harmless.
func (priv *PrivateKey) Zeroize() {
	if priv == nil {
		return
	}
	zeroBytes(priv.raw[:])
	zeroFFTPolynomials(&priv.b00, &priv.b01, &priv.b10, &priv.b11)
	zeroFPRs(priv.tree[:])
	priv.state = keyStateZeroized
}

type PublicKey struct {
	raw  [PublicKeySize]byte
	hNTT ringElement
}

// Equal reports whether pub and x hold the same key; a nil key equals
// nothing.
func (pub *PublicKey) Equal(x *PublicKey) bool {
	if pub == nil || x == nil {
		return false
	}
	return subtle.ConstantTimeCompare(pub.raw[:], x.raw[:]) == 1
}

// Bytes returns the PublicKeySize-byte encoding of pub, or nil for a nil key.
func (pub *PublicKey) Bytes() []byte {
	if pub == nil {
		return nil
	}
	pk := pub.raw
	return pk[:]
}

// GenerateKey reads SeedSize bytes from random and generates the private key
// from them, as the reference crypto_sign_keypair does with randombytes.
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	var seed [SeedSize]byte
	defer zeroBytes(seed[:])
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, randomnessError(err)
	}
	return NewPrivateKeyFromSeed(seed[:])
}

// NewPrivateKeyFromSeed deterministically generates the private key from a
// SeedSize-byte seed, the way the reference crypto_sign_keypair expands the
// bytes it draws from randombytes.
func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, errInvalidSeedLength
	}

	rng := sha3.NewSHAKE256()
	defer rng.Reset()
	_, _ = rng.Write(seed)

	f, g, ntruF, ntruG, h := generateKeyComponents(rng)
	defer zeroSmallPolynomials(&f, &g, &ntruF, &ntruG)
	return initPrivateKey(&PrivateKey{}, f, g, ntruF, ntruG, h)
}

// NewPrivateKey decodes a PrivateKeySize-byte private key. As the reference
// crypto_sign does, it recomputes G from f, g and F and rejects encodings for
// which that fails. It then checks what the reference does not check on
// import: that (f, g, F, G) solve the NTRU equation f*G - g*F = q, that the
// public half passes the weak-key rule, and that (f, g) satisfy the bounds
// key generation enforces. An encoding failing any of these keeps the signing
// loop rejecting, drives the sampler out of the domain in which its
// arithmetic matches the reference, or both. Every key the reference or this
// package generates passes.
func NewPrivateKey(privateKey []byte) (*PrivateKey, error) {
	f, g, ntruF, err := skDecode(privateKey)
	if err != nil {
		return nil, err
	}
	defer zeroSmallPolynomials(&f, &g, &ntruF)

	ntruG, ok := completePrivate(f, g, ntruF)
	if !ok {
		return nil, errInvalidPrivateKey
	}
	defer zeroSmallPolynomials(&ntruG)

	h, ok := computePublic(f, g)
	if !ok {
		//coverage:ignore
		//rationale: completePrivate has already inverted f mod q; computePublic
		//           inverts the same NTT coefficients and cannot fail after it.
		return nil, errInvalidPrivateKey
	}

	// The public half an encoding derives is held to the same rule as a key
	// received on its own.
	if err := validatePublicPolynomial(h); err != nil {
		return nil, err
	}

	// completePrivate only checks that the recomputed G is small. The four
	// polynomials must also satisfy f*G - g*F = q, or the matrix built from
	// them is not a basis of the key's lattice: its determinant is off, the
	// second half of the LDL tree falls outside the sampler's domain, and
	// signing never passes the norm check (F replaced by x*F or -F) or never
	// gets a sample (F replaced by f). Such an encoding derives the correct
	// public key, so nothing else can tell it from the genuine one.
	if !ntruEquationHolds(f, g, ntruF, ntruG) {
		return nil, errInvalidPrivateKey
	}

	// The five-bit encoding cannot hold a coefficient outside [-15, 15], so
	// the coefficient bound of key generation needs no re-check here.
	if squaredNormExceedsBound(f, g, keygenSqNormBound) ||
		orthogonalizedNormExceedsBound(f, g, keygenBNormBound) {
		return nil, errInvalidPrivateKey
	}

	return initPrivateKey(&PrivateKey{}, f, g, ntruF, ntruG, h)
}

const (
	fgBound           = 15
	keygenSqNormBound = 16823
	keygenBNormBound  = 16822.4121
)

func generateKeyComponents(rng *sha3.SHAKE) (f, g, ntruF, ntruG smallPolynomial, h ringElement) {
	// Falcon key generation is rejection-based; this loop is intentionally
	// unbounded to match the reference.
	for {
		f = sampleGaussianPolynomial(rng)
		g = sampleGaussianPolynomial(rng)

		if coefficientsExceedBound(f, fgBound) ||
			coefficientsExceedBound(g, fgBound) {
			//coverage:ignore
			//rationale: one draw of the keygen Gaussian is at most 26 in magnitude
			//           (field.go gauss1024Q12289), so a sampled polynomial exceeds
			//           15 only on a tail event; the check mirrors the reference.
			continue
		}

		if squaredNormExceedsBound(f, g, keygenSqNormBound) {
			continue
		}

		if orthogonalizedNormExceedsBound(f, g, keygenBNormBound) {
			continue
		}

		var ok bool
		h, ok = computePublic(f, g)
		if !ok {
			continue
		}

		if c, _ := weakPublicKeyMultiplier(h); c != 0 {
			//coverage:ignore
			//rationale: h = g/f is uniform for sampled f and g, so a weak public
			//           half is a sub-2^-1562 event; the check keeps key generation
			//           under the same rule as import (see ValidatePublicKey).
			continue
		}

		ntruF, ntruG, ok = solveNTRU(f, g)
		if !ok {
			continue
		}

		return f, g, ntruF, ntruG, h
	}
}

func computePublic(f, g smallPolynomial) (ringElement, bool) {
	var fNTT, hNTT ringElement
	defer zeroRingElements(&fNTT)
	for i := range fNTT {
		fNTT[i] = fieldFromSmall(f[i])
		hNTT[i] = fieldFromSmall(g[i])
	}

	ntt(fNTT[:])
	ntt(hNTT[:])

	if !divideNTTByBatchedInverse(hNTT[:], fNTT[:]) {
		return ringElement{}, false
	}

	inverseNTT(hNTT[:])
	return hNTT, true
}

func initPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial, h ringElement) (*PrivateKey, error) {
	defer zeroSmallPolynomials(&f, &g, &ntruF, &ntruG)

	if err := skEncode(priv.raw[:], f, g, ntruF); err != nil {
		//coverage:ignore
		//rationale: priv.raw has exactly PrivateKeySize bytes and f, g, F come
		//           from the sampler or the decoder, which keep them in range.
		return nil, err
	}

	pub, err := newPublicKeyFromH(h)
	if err != nil {
		//coverage:ignore
		//rationale: pub.raw has exactly PublicKeySize bytes; pkEncode cannot fail.
		return nil, err
	}
	priv.pub = pub

	expandPrivateKey(priv, f, g, ntruF, ntruG)
	priv.state = keyStateReady

	return priv, nil
}

func newPublicKeyFromH(h ringElement) (PublicKey, error) {
	var pub PublicKey
	if err := pkEncode(pub.raw[:], h); err != nil {
		//coverage:ignore
		//rationale: pub.raw has exactly PublicKeySize bytes; pkEncode cannot fail.
		return PublicKey{}, err
	}
	pub.hNTT = h
	toNTTMonty(pub.hNTT[:])
	return pub, nil
}

// expandPrivateKey computes the FFT basis and the LDL tree with the same
// arithmetic as the reference expand_privkey and, equivalently, the Gram
// matrix and on-the-fly LDL of the reference sign_dyn.
func expandPrivateKey(priv *PrivateKey, f, g, ntruF, ntruG smallPolynomial) {
	defer zeroSmallPolynomials(&f, &g, &ntruF, &ntruG)

	fftFromSmall(priv.b01[:], f)
	fftFromSmall(priv.b00[:], g)
	fftFromSmall(priv.b11[:], ntruF)
	fftFromSmall(priv.b10[:], ntruG)

	fftNeg(priv.b01[:], logN)
	fftNeg(priv.b11[:], logN)

	var g00, g01, g11, tmp fftPolynomial
	defer zeroFFTPolynomials(&g00, &g01, &g11, &tmp)

	fftSelfAdj(g00[:], priv.b00[:], logN)
	fftSelfAdj(tmp[:], priv.b01[:], logN)
	fftAdd(g00[:], tmp[:], logN)

	fftMulAdj(g01[:], priv.b00[:], priv.b10[:], logN)
	fftMulAdj(tmp[:], priv.b01[:], priv.b11[:], logN)
	fftAdd(g01[:], tmp[:], logN)

	fftSelfAdj(g11[:], priv.b10[:], logN)
	fftSelfAdj(tmp[:], priv.b11[:], logN)
	fftAdd(g11[:], tmp[:], logN)

	var ffLDLScratch [3 * n]fpr
	defer zeroFPRs(ffLDLScratch[:])
	ffLDLFFT(priv.tree[:], g00[:], g01[:], g11[:], logN, ffLDLScratch[:])
	ffLDLBinaryNormalize(priv.tree[:], logN, logN)
}

func completePrivate(f, g, ntruF smallPolynomial) (smallPolynomial, bool) {
	var gNTT, ntruFNTT, fNTT ringElement
	defer zeroRingElements(&gNTT, &ntruFNTT, &fNTT)
	for i := range gNTT {
		gNTT[i] = fieldFromSmall(g[i])
		ntruFNTT[i] = fieldFromSmall(ntruF[i])
		fNTT[i] = fieldFromSmall(f[i])
	}

	ntt(gNTT[:])
	ntt(ntruFNTT[:])
	ntt(fNTT[:])

	for i := range gNTT {
		gNTT[i] = fieldMontgomeryMul(gNTT[i], r2)
	}
	nttMul(gNTT[:], ntruFNTT[:])

	if !divideNTTByBatchedInverse(gNTT[:], fNTT[:]) {
		return smallPolynomial{}, false
	}

	inverseNTT(gNTT[:])

	var ntruG smallPolynomial
	for i := range ntruG {
		gi := completePrivateCenter(uint32(gNTT[i]))
		if gi < -ntruCoeffBound || gi > ntruCoeffBound {
			return smallPolynomial{}, false
		}
		ntruG[i] = gi
	}

	return ntruG, true
}

// completePrivateCenter maps a residue modulo q to the centered range the
// way the reference complete_private does: every residue of q/2 and above
// has q subtracted. (verify_raw centers differently and keeps q/2 itself.)
// ntruEquationHolds reports whether f*G - g*F = q, using a scratch buffer of
// its own that is wiped afterwards (it holds the four polynomials modulo a
// small prime).
func ntruEquationHolds(f, g, ntruF, ntruG smallPolynomial) bool {
	var scratch [6 * n]uint32
	defer zeroUint32s(scratch[:])
	return checkNTRUEquation(f, g, ntruF, ntruG, scratch[:])
}

func completePrivateCenter(w uint32) int32 {
	w -= q & ^(-((w - q/2) >> 31))
	return int32(w)
}

// NewPublicKey decodes a PublicKeySize-byte public key and applies the
// weak-key rule of [ValidatePublicKey]; a key under which anyone could sign
// is refused with an error wrapping ErrWeakPublicKey.
func NewPublicKey(pubBytes []byte) (*PublicKey, error) {
	h, err := pkDecode(pubBytes)
	if err != nil {
		return nil, err
	}
	if err := validatePublicPolynomial(h); err != nil {
		return nil, err
	}

	pub := &PublicKey{hNTT: h}
	toNTTMonty(pub.hNTT[:])
	copy(pub.raw[:], pubBytes)
	return pub, nil
}

const nonceSize = 40

// signCore performs the signing steps Sign and SignDetached share: it draws
// the 40-byte nonce and then the SeedSize-byte sampler seed from random, in
// the order the reference crypto_sign calls randombytes, hashes the nonce and
// message to a point and signs it.
func signCore(random io.Reader, priv *PrivateKey, message []byte) (nonce [nonceSize]byte, s2 smallPolynomial, err error) {
	if priv == nil {
		return nonce, smallPolynomial{}, errSecretKeyNil
	}
	if err = priv.signable(); err != nil {
		return nonce, smallPolynomial{}, err
	}

	if _, err = io.ReadFull(random, nonce[:]); err != nil {
		return nonce, smallPolynomial{}, randomnessError(err)
	}

	hashData := sha3.NewSHAKE256()
	_, _ = hashData.Write(nonce[:])
	_, _ = hashData.Write(message)

	c0 := hashToPoint(hashData)

	// The sampler seed determines the Gaussian samples, which together with
	// the signature reveal the private basis; it is wiped like the key.
	var seed [SeedSize]byte
	defer zeroBytes(seed[:])
	if _, err = io.ReadFull(random, seed[:]); err != nil {
		return nonce, smallPolynomial{}, randomnessError(err)
	}

	rng := sha3.NewSHAKE256()
	defer rng.Reset()
	_, _ = rng.Write(seed[:])

	s2, err = sign(rng, priv, c0)
	return nonce, s2, err
}

// Sign signs message with priv and returns the signed message in the format
// of the reference crypto_sign: a two-byte big-endian signature length, the
// nonce, the message, and the signature, which is the header byte 0x2A
// followed by the compressed polynomial s2. random supplies the 40-byte nonce
// and then the SeedSize-byte sampler seed, in the order crypto_sign draws
// them with randombytes. As in the reference, Sign fails instead of retrying
// if the compressed polynomial does not fit MaxSignedMessageOverhead.
func Sign(random io.Reader, priv *PrivateKey, message []byte) ([]byte, error) {
	nonce, s2, err := signCore(random, priv, message)
	if err != nil {
		return nil, err
	}

	return signedMessageEncode(nonce, message, s2)
}

// SignDetached signs message with priv and returns a detached signature in
// the compressed format of the reference library API (FALCON_SIG_COMPRESSED):
// the header byte 0x3A, the 40-byte nonce and the compressed polynomial s2,
// at most MaxSignatureSize bytes. It draws randomness exactly as Sign does,
// so the same random bytes yield the nonce and polynomial Sign embeds in its
// signed message.
func SignDetached(random io.Reader, priv *PrivateKey, message []byte) ([]byte, error) {
	nonce, s2, err := signCore(random, priv, message)
	if err != nil {
		return nil, err
	}

	return detachedSignatureEncode(nonce, s2)
}

// maxSignAttempts bounds the rejection loop of sign. For a key within the
// key-generation bounds the norm check rejects an attempt with probability
// well below one in a thousand (the bound is 1.1 times the expected norm of
// a 2048-dimensional Gaussian), so 128 consecutive rejections cannot happen
// in honest use even at a far higher rate; the bound exists so that a basis
// built outside the import checks cannot make signing spin in the attempt
// loop. The sampler's own rejection loop is bounded separately, by
// maxSamplerDraws. The reference loops without bound in both places.
const maxSignAttempts = 128

// sign mirrors the reference sign_dyn loop: each attempt seeds a fresh
// sampler PRNG from the continuing SHAKE stream.
func sign(rng *sha3.SHAKE, priv *PrivateKey, c0 ringElement) (smallPolynomial, error) {
	var prng samplerPRNG
	defer prng.zeroize()

	for range maxSignAttempts {
		initSamplerPRNG(&prng, rng)
		s2, ok := signAttempt(&prng, priv, c0)
		if ok {
			return s2, nil
		}
		if prng.exhausted {
			// The sampler could not produce a coordinate within its draw
			// budget. That is a property of the basis, not of this attempt's
			// randomness, so further attempts would only repeat it.
			break
		}
	}

	return smallPolynomial{}, errSigningFailed
}

// signAttempt mirrors the reference do_sign_dyn, with the Gram matrix and LDL
// values taken from the precomputed expansion of the key.
func signAttempt(prng *samplerPRNG, priv *PrivateKey, c0 ringElement) (smallPolynomial, bool) {
	var t0, t1 fftPolynomial
	defer zeroFFTPolynomials(&t0, &t1)
	for i := range t0 {
		t0[i] = fpr(c0[i])
	}
	fft(t0[:], logN)

	copy(t1[:], t0[:])
	fftMul(t1[:], priv.b01[:], logN)
	fftMulConst(t1[:], -fprInverseOfQ, logN)
	fftMul(t0[:], priv.b11[:], logN)
	fftMulConst(t0[:], fprInverseOfQ, logN)

	var sampleX, sampleY fftPolynomial
	defer zeroFFTPolynomials(&sampleX, &sampleY)
	ffSamplingFFT(sampleFFTPoint, prng, sampleX[:], sampleY[:], t0[:], t1[:], priv.tree[:], logN)
	if prng.exhausted {
		return smallPolynomial{}, false
	}

	var latticeX, latticeY, tmp fftPolynomial
	defer zeroFFTPolynomials(&latticeX, &latticeY, &tmp)
	copy(latticeX[:], sampleX[:])
	fftMul(latticeX[:], priv.b00[:], logN)
	copy(tmp[:], sampleY[:])
	fftMul(tmp[:], priv.b10[:], logN)
	fftAdd(latticeX[:], tmp[:], logN)

	copy(latticeY[:], sampleX[:])
	fftMul(latticeY[:], priv.b01[:], logN)
	copy(tmp[:], sampleY[:])
	fftMul(tmp[:], priv.b11[:], logN)
	fftAdd(latticeY[:], tmp[:], logN)

	inverseFFT(latticeX[:], logN)
	inverseFFT(latticeY[:], logN)

	var s2 smallPolynomial
	var sqn uint32
	var ng uint32

	for i := range s2 {
		s1 := int32(c0[i]) - int32(fprRint(latticeX[i]))
		sqn += uint32(s1 * s1)
		ng |= sqn

		// The reference stores s2 in 16-bit integers before checking the
		// norm, so the value is truncated the same way here.
		s2[i] = int32(int16(-fprRint(latticeY[i])))
	}

	sqn |= -(ng >> 31)

	if signatureNormExceedsPartialBound(sqn, s2) {
		return smallPolynomial{}, false
	}

	return s2, true
}

// Open verifies signedMessage against pub and returns the message it
// carries, as the reference crypto_sign_open does. A nil pub is refused with
// an error wrapping ErrPublicKeyNil.
func Open(pub *PublicKey, signedMessage []byte) ([]byte, error) {
	if pub == nil {
		return nil, errPublicKeyNil
	}

	nonce, message, s2, err := signedMessageDecode(signedMessage)
	if err != nil {
		return nil, err
	}

	h := sha3.NewSHAKE256()
	_, _ = h.Write(nonce)
	_, _ = h.Write(message)

	c0 := hashToPoint(h)

	if !verifyRaw(c0, s2, pub.hNTT) {
		return nil, errInvalidSignature
	}

	out := make([]byte, len(message))
	copy(out, message)
	return out, nil
}

// Verify checks a detached signature of message against pub, with the
// checks the reference library's falcon_verify applies to the compressed
// format. A nil pub is refused with an error wrapping ErrPublicKeyNil.
func Verify(pub *PublicKey, message, signature []byte) error {
	if pub == nil {
		return errPublicKeyNil
	}

	nonce, s2, err := detachedSignatureDecode(signature)
	if err != nil {
		return err
	}

	h := sha3.NewSHAKE256()
	_, _ = h.Write(nonce)
	_, _ = h.Write(message)

	c0 := hashToPoint(h)

	if !verifyRaw(c0, s2, pub.hNTT) {
		return errInvalidSignature
	}

	return nil
}

func verifyRaw(c0 ringElement, s2 smallPolynomial, hNTT ringElement) bool {
	var t ringElement
	for i := range t {
		t[i] = fieldFromSmall(s2[i])
	}

	ntt(t[:])
	nttMul(t[:], hNTT[:])
	inverseNTT(t[:])

	var s1 smallPolynomial
	for i := range s1 {
		s1[i] = fieldCenteredMod(fieldSub(c0[i], t[i]))
	}

	return signatureNormWithinBound(s1, s2)
}
