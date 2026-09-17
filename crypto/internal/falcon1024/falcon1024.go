package falcon1024

import (
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"io"
)

const (
	SeedSize              = 48
	PublicKeySize         = 1793
	encodedPrivateKeySize = 2305
	SignatureSize         = 1280
)

type PrivateKey struct {
	seed               [SeedSize]byte
	pub                PublicKey
	b00, b01, b10, b11 fftPolynomial
	tree               fprTree
}

func (priv *PrivateKey) Equal(x *PrivateKey) bool {
	return subtle.ConstantTimeCompare(priv.seed[:], x.seed[:]) == 1
}

func (priv *PrivateKey) Bytes() []byte {
	seed := priv.seed
	return seed[:]
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

var errInvalidSeedLength = errors.New("falcon-1024: invalid seed length")

func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, errInvalidSeedLength
	}

	priv := &PrivateKey{}
	copy(priv.seed[:], seed)

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write(seed)

	return keygen(priv, rng)
}

const (
	fgBound           = 15
	keygenSqNormBound = 16823
	keygenBNormBound  = 16822.4121
)

func keygen(priv *PrivateKey, rng *sha3.SHAKE) (*PrivateKey, error) {
	f, g, ntruF, ntruG, h := generateKeyComponents(rng)
	return initPrivateKey(priv, f, g, ntruF, ntruG, h)
}

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
		gi := fieldCenteredMod(gNTT[i])
		if gi < -ntruCoeffBound || gi > ntruCoeffBound {
			return smallPolynomial{}, false
		}
		ntruG[i] = gi
	}

	return ntruG, true
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

func Sign(random io.Reader, priv *PrivateKey, message []byte) ([]byte, error) {
	var seed [SeedSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, err
	}

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write(seed[:])

	var nonce [nonceSize]byte
	_, _ = rng.Read(nonce[:])

	hashData := sha3.NewSHAKE256()
	_, _ = hashData.Write(nonce[:])
	_, _ = hashData.Write(message)

	c0 := hashToPoint(hashData)

	signature := make([]byte, SignatureSize)
	// Retry until the sampled signature fits the padded compressed encoding,
	// matching the Falcon reference signing loop.
	for {
		s2 := signTree(rng, priv, c0)

		if err := sigEncode(signature, nonce, s2); err != nil {
			if errors.Is(err, errCompressedSignatureTooLarge) ||
				errors.Is(err, errCompressedCoefficientOutOfRange) {
				continue
			}
			return nil, err
		}

		return signature, nil
	}
}

func signTree(rng *sha3.SHAKE, priv *PrivateKey, c0 ringElement) smallPolynomial {
	// Falcon's tree-based signing step is rejection-based; this loop is
	// intentionally unbounded to match the reference.
	for {
		var prng samplerPRNG
		initSamplerPRNG(&prng, rng)
		s2, ok := signTreeAttempt(&prng, priv, c0)
		if ok {
			return s2
		}
	}
}

func signTreeAttempt(prng *samplerPRNG, priv *PrivateKey, c0 ringElement) (smallPolynomial, bool) {
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
	ffSamplingFFT(prng, sampleX[:], sampleY[:], t0[:], t1[:], priv.tree[:], logN)

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

		s2[i] = -int32(fprRint(latticeY[i]))
	}

	sqn |= -(ng >> 31)

	if signatureNormExceedsPartialBound(sqn, s2) {
		return smallPolynomial{}, false
	}

	return s2, true
}

var errInvalidSignature = errors.New("falcon-1024: invalid signature")

func Verify(pub *PublicKey, message, sig []byte) error {
	nonce, s2, err := sigDecode(sig)
	if err != nil {
		return err
	}

	h := sha3.NewSHAKE256()
	_, _ = h.Write(nonce[:])
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
