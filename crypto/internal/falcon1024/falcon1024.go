package falcon1024

import (
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"io"
)

// This package follows the NIST API of the Falcon round-3 reference
// implementation (nist.c): key generation expands SeedSize random bytes with
// SHAKE256 exactly as crypto_sign_keypair expands the bytes it draws from
// randombytes, private and public keys use the CRYPTO_SECRETKEYBYTES and
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
	// message it carries, in bytes (CRYPTO_BYTES).
	MaxSignedMessageOverhead = 1330

	// MaxSignatureSize is the maximum size in bytes of a detached signature
	// (FALCON_SIG_COMPRESSED_MAXSIZE of the reference library API for degree
	// 1024).
	MaxSignatureSize = 1462
)

type PrivateKey struct {
	raw                [PrivateKeySize]byte
	pub                PublicKey
	b00, b01, b10, b11 fftPolynomial
	tree               fprTree
}

func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	return subtle.ConstantTimeCompare(priv.raw[:], x.raw[:]) == 1
}

// Bytes returns the PrivateKeySize-byte encoding of priv: the header byte
// 0x5A, then f and g at five bits per coefficient and F at eight.
func (priv *PrivateKey) Bytes() []byte {
	sk := priv.raw
	return sk[:]
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	// Returning a pointer to the embedded public key can keep the whole
	// PrivateKey reachable for as long as the PublicKey is retained.
	return &priv.pub
}

type PublicKey struct {
	raw  [PublicKeySize]byte
	hNTT ringElement
}

func (pub *PublicKey) Equal(x *PublicKey) bool {
	return subtle.ConstantTimeCompare(pub.raw[:], x.raw[:]) == 1
}

func (pub *PublicKey) Bytes() []byte {
	pk := pub.raw
	return pk[:]
}

var (
	errInvalidSeedLength = errors.New("falcon-1024: invalid seed length")
	errInvalidPrivateKey = errors.New("falcon-1024: invalid private key")
)

// GenerateKey reads SeedSize bytes from random and generates the private key
// from them, as the reference crypto_sign_keypair does with randombytes.
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, err
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
	_, _ = rng.Write(seed)

	f, g, ntruF, ntruG, h := generateKeyComponents(rng)
	return initPrivateKey(&PrivateKey{}, f, g, ntruF, ntruG, h)
}

// NewPrivateKey decodes a PrivateKeySize-byte private key. As the reference
// crypto_sign does, it recomputes G from f, g and F and rejects encodings for
// which that fails.
func NewPrivateKey(privateKey []byte) (*PrivateKey, error) {
	f, g, ntruF, err := skDecode(privateKey)
	if err != nil {
		return nil, err
	}

	ntruG, ok := completePrivate(f, g, ntruF)
	if !ok {
		return nil, errInvalidPrivateKey
	}

	h, ok := computePublic(f, g)
	if !ok {
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

		ntruF, ntruG, ok = solveNTRU(f, g)
		if !ok {
			continue
		}

		return f, g, ntruF, ntruG, h
	}
}

func computePublic(f, g smallPolynomial) (ringElement, bool) {
	var fNTT, hNTT ringElement
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
	if err := skEncode(priv.raw[:], f, g, ntruF); err != nil {
		return nil, err
	}

	pub, err := newPublicKeyFromH(h)
	if err != nil {
		return nil, err
	}
	priv.pub = pub

	expandPrivateKey(priv, f, g, ntruF, ntruG)

	return priv, nil
}

func newPublicKeyFromH(h ringElement) (PublicKey, error) {
	var pub PublicKey
	if err := pkEncode(pub.raw[:], h); err != nil {
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
	fftFromSmall(priv.b01[:], f)
	fftFromSmall(priv.b00[:], g)
	fftFromSmall(priv.b11[:], ntruF)
	fftFromSmall(priv.b10[:], ntruG)

	fftNeg(priv.b01[:], logN)
	fftNeg(priv.b11[:], logN)

	var g00, g01, g11, tmp fftPolynomial

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
	ffLDLFFT(priv.tree[:], g00[:], g01[:], g11[:], logN, ffLDLScratch[:])
	ffLDLBinaryNormalize(priv.tree[:], logN, logN)
}

func completePrivate(f, g, ntruF smallPolynomial) (smallPolynomial, bool) {
	var gNTT, ntruFNTT, fNTT ringElement
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
func completePrivateCenter(w uint32) int32 {
	w -= q & ^(-((w - q/2) >> 31))
	return int32(w)
}

func NewPublicKey(pubBytes []byte) (*PublicKey, error) {
	h, err := pkDecode(pubBytes)
	if err != nil {
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
	if _, err = io.ReadFull(random, nonce[:]); err != nil {
		return nonce, smallPolynomial{}, err
	}

	hashData := sha3.NewSHAKE256()
	_, _ = hashData.Write(nonce[:])
	_, _ = hashData.Write(message)

	c0 := hashToPoint(hashData)

	var seed [SeedSize]byte
	if _, err = io.ReadFull(random, seed[:]); err != nil {
		return nonce, smallPolynomial{}, err
	}

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write(seed[:])

	return nonce, sign(rng, priv, c0), nil
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

// sign mirrors the reference sign_dyn loop: each attempt seeds a fresh
// sampler PRNG from the continuing SHAKE stream.
func sign(rng *sha3.SHAKE, priv *PrivateKey, c0 ringElement) smallPolynomial {
	// Falcon's signing step is rejection-based; this loop is intentionally
	// unbounded to match the reference.
	for {
		var prng samplerPRNG
		initSamplerPRNG(&prng, rng)
		s2, ok := signAttempt(&prng, priv, c0)
		if ok {
			return s2
		}
	}
}

// signAttempt mirrors the reference do_sign_dyn, with the Gram matrix and LDL
// values taken from the precomputed expansion of the key.
func signAttempt(prng *samplerPRNG, priv *PrivateKey, c0 ringElement) (smallPolynomial, bool) {
	var t0, t1 fftPolynomial
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
	ffSamplingFFT(sampleFFTPoint, prng, sampleX[:], sampleY[:], t0[:], t1[:], priv.tree[:], logN)

	var latticeX, latticeY, tmp fftPolynomial
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

var errInvalidSignature = errors.New("falcon-1024: invalid signature")

// Open verifies signedMessage against pub and returns the message it
// carries, as the reference crypto_sign_open does.
func Open(pub *PublicKey, signedMessage []byte) ([]byte, error) {
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
// format.
func Verify(pub *PublicKey, message, signature []byte) error {
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
