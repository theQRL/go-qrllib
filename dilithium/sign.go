package dilithium

import "golang.org/x/crypto/sha3"
import "crypto/rand"

func expandMat(mat *[K]polyVecL, rho *[SeedBytes]byte) {
	var inbuf [SeedBytes + 1]byte
	/* Don't change this to smaller values,
	 * sampling later assumes sufficient SHAKE output!
	 * Probability that we need more than 5 blocks: < 2^{-132}.
	 * Probability that we need more than 6 blocks: < 2^{-546}. */
	var outbuf [5 * Shake128Rate]byte
	var val uint32

	copy(inbuf[:], rho[:])

	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			ctr, pos := 0, 0
			inbuf[SeedBytes] = byte(i + (j << 4))

			sha3.ShakeSum128(outbuf[:], inbuf[:])

			for ctr < N {
				val = uint32(outbuf[pos])
				val |= uint32(outbuf[pos+1]) << 8
				val |= uint32(outbuf[pos+2]) << 16
				val &= 0x7FFFFF
				pos += 3

				/* Rejection sampling */
				if val < Q {
					mat[i].vec[j].coeffs[ctr] = val
					ctr++
				}
			}
		}
	}
}

func challenge(c *poly, mu *[CrhBytes]byte, w1 *polyVecK) {
	var inbuf [CrhBytes + K*PolW1SizePacked]byte
	var outbuf [Shake256Rate]byte

	copy(inbuf[:], mu[:])
	for i := 0; i < K; i++ {
		polyW1Pack(inbuf[CrhBytes+i*PolW1SizePacked:], &w1.vec[i])
	}

	state := sha3.NewShake256()
	state.Write(inbuf[:])
	state.Read(outbuf[:])

	signs := uint64(0)
	for i := uint(0); i < 8; i++ {
		signs |= uint64(outbuf[i]) << (8 * i)
	}

	mask := uint64(1)

	*c = poly{}
	pos := 8
	for i := 196; i < 256; i++ {
		var b int
		// randomly truncated hash outputs, huh?
		for {
			if pos >= Shake256Rate {
				state.Read(outbuf[:])
				pos = 0
			}
			b = int(outbuf[pos])
			pos++
			if b <= i {
				break
			}
		}
		c.coeffs[i] = c.coeffs[b]

		// TODO FIXME vartime
		if (signs & mask) != 0 {
			c.coeffs[b] = Q - 1
		} else {
			c.coeffs[b] = 1
		}
		mask <<= 1
	}
}

// Take a random seed, and compute sk/pk pair.
func cryptoSignKeypair(seed []byte, pk *[PKSizePacked]byte, sk *[SKSizePacked]byte) []byte {
	var tr [CrhBytes]byte
	var rho, rhoprime, key [SeedBytes]byte
	var s2, t, t1, t0 polyVecK
	var s1, s1hat polyVecL
	var mat [K]polyVecL
	var nonce uint16

	if seed == nil {
		seed = make([]byte, SeedBytes)
		rand.Read(seed)
	}
	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	state := sha3.NewShake256()
	state.Write(seed)
	state.Read(rho[:])
	state.Read(rhoprime[:])
	state.Read(key[:])

	/* Expand matrix */
	expandMat(&mat, &rho)

	/* Sample short vectors s1 and s2 */
	for i := 0; i < L; i++ {
		if nonce > 255 {
			panic("bad mode")
		}
		polyUniformEta(&s1.vec[i], &rhoprime, byte(nonce))
		nonce++
	}
	for i := 0; i < K; i++ {
		if nonce > 255 {
			panic("bad mode")
		}
		polyUniformEta(&s2.vec[i], &rhoprime, byte(nonce))
		nonce++
	}

	/* Matrix-vector multiplication */
	s1hat = s1
	polyVecLNTT(&s1hat)
	for i := 0; i < K; i++ {
		polyVecLPointWiseAccInvMontgomery(&t.vec[i], &mat[i], &s1hat)
		polyInvNTTMontgomery(&t.vec[i])
	}

	/* Add noise vector s2 */
	polyVecKAdd(&t, &t, &s2)

	/* Extract t1 and write public key */
	polyVecKFreeze(&t)
	polyVecKPower2Round(&t1, &t0, &t)
	packPk(pk, &rho, &t1)

	/* Compute tr = CRH(rho, t1) and write secret key */
	sha3.ShakeSum256(tr[:], pk[:])
	packSk(sk, &rho, &key, &tr, &s1, &s2, &t0)

	return seed
}

func cryptoSignAttached(sm *[SigSizePacked]byte, m []byte, sk *[SKSizePacked]byte) {
	z, h, c := cryptoSignRaw(m, sk)
	/* Write signature */
	packSig(sm, z, h, c)
}
func cryptoSignDetached(sm *[SigSizePacked]byte, m []byte, sk *[SKSizePacked]byte) []byte {
	z, h, c := cryptoSignRaw(m, sk)
	/* Write signature */
	return packSigDetached(sm, z, h, c)
}

func cryptoSignRaw(m []byte, sk *[SKSizePacked]byte) (*polyVecL, *polyVecK, *poly) {
	var rho, key [SeedBytes]byte
	var tr, mu [CrhBytes]byte
	var s1, y, yhat, z polyVecL
	var mat [K]polyVecL
	var s2, t0, w, w1, h, wcs2, wcs20, ct0, tmp polyVecK
	var nonce uint16
	var c, chat poly

	unpackSk(&rho, &key, &tr, &s1, &s2, &t0, sk)

	/* Compute CRH(tr, msg) */
	state := sha3.NewShake256()
	state.Write(tr[:])
	state.Write(m)
	state.Read(mu[:])

	/* Expand matrix and transform vectors */
	expandMat(&mat, &rho)
	polyVecLNTT(&s1)
	polyVecKNTT(&s2)
	polyVecKNTT(&t0)

rej:

	/* Sample intermediate vector y */
	for i := 0; i < L; i++ {
		polyUniformGamma1m1(&y.vec[i], &key, &mu, nonce)
		nonce++
	}

	/* Matrix-vector multiplication */
	yhat = y
	polyVecLNTT(&yhat)
	for i := 0; i < K; i++ {
		polyVecLPointWiseAccInvMontgomery(&w.vec[i], &mat[i], &yhat)
		polyInvNTTMontgomery(&w.vec[i])
	}

	/* Decompose w and call the random oracle */
	polyVecKFreeze(&w)
	polyVecKDecompose(&w1, &tmp, &w)
	challenge(&c, &mu, &w1)

	/* Compute z, reject if it reveals secret */
	chat = c
	polyNTT(&chat)
	for i := 0; i < L; i++ {
		polyPointWiseInvMontgomery(&z.vec[i], &chat, &s1.vec[i])
		polyInvNTTMontgomery(&z.vec[i])
	}
	polyVecLAdd(&z, &z, &y)
	polyVecLFreeze(&z)
	if polyVecLChkNorm(&z, GAMMA1-BETA) != 0 {
		goto rej
	}

	/* Compute w - cs2, reject if w1 can not be computed from it */
	for i := 0; i < K; i++ {
		polyPointWiseInvMontgomery(&wcs2.vec[i], &chat, &s2.vec[i])
		polyInvNTTMontgomery(&wcs2.vec[i])
	}
	polyVecKSub(&wcs2, &w, &wcs2)
	polyVecKFreeze(&wcs2)
	polyVecKDecompose(&tmp, &wcs20, &wcs2)
	polyVecKFreeze(&wcs20)
	if polyVecKChkNorm(&wcs20, GAMMA2-BETA) != 0 {
		goto rej
	}

	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j] {
				goto rej
			}
		}
	}

	/* Compute hints for w1 */
	for i := 0; i < K; i++ {
		polyPointWiseInvMontgomery(&ct0.vec[i], &chat, &t0.vec[i])
		polyInvNTTMontgomery(&ct0.vec[i])
	}

	polyVecKFreeze(&ct0)
	if polyVecKChkNorm(&ct0, GAMMA2) != 0 {
		goto rej
	}

	polyVecKAdd(&tmp, &wcs2, &ct0)
	polyVecKNeg(&ct0)
	polyVecKFreeze(&tmp)
	n := polyVecKMakeHint(&h, &tmp, &ct0)
	if n > OMEGA {
		goto rej
	}

	return &z, &h, &c
}

func cryptoVerifyAttached(sm *[SigSizePacked]byte, m []byte, pk *[PKSizePacked]byte) bool {
	var z polyVecL
	var h polyVecK
	var c poly
	if !unpackSig(&z, &h, &c, sm) {
		return false
	}
	return cryptoVerifyRaw(&z, &h, &c, m, pk)
}

func cryptoVerifyDetached(sm []byte, m []byte, pk *[PKSizePacked]byte) bool {
	var z polyVecL
	var h polyVecK
	var c poly
	if !unpackSigDetached(&z, &h, &c, sm) {
		return false
	}
	return cryptoVerifyRaw(&z, &h, &c, m, pk)
}

func cryptoVerifyRaw(z *polyVecL, h *polyVecK, c *poly, m []byte, pk *[PKSizePacked]byte) bool {
	var rho [SeedBytes]byte
	var tr, mu [CrhBytes]byte
	var chat, cp poly
	var mat [K]polyVecL
	var t1, w1, tmp1, tmp2 polyVecK

	unpackPk(&rho, &t1, pk)
	if polyVecLChkNorm(z, GAMMA1-BETA) != 0 {
		return false
	}

	/* Compute mu = CRH(CRH(pk), msg) (pk = (rho, t1))  */
	sha3.ShakeSum256(tr[:], pk[:])
	state := sha3.NewShake256()
	state.Write(tr[:])
	state.Write(m)
	state.Read(mu[:])

	/* Expand rho matrix */
	expandMat(&mat, &rho)

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	polyVecLNTT(z)
	for i := 0; i < K; i++ {
		polyVecLPointWiseAccInvMontgomery(&tmp1.vec[i], &mat[i], z)
	}

	chat = *c
	polyNTT(&chat)
	polyVecKShiftL(&t1, D)
	polyVecKNTT(&t1)
	for i := 0; i < K; i++ {
		polyPointWiseInvMontgomery(&tmp2.vec[i], &chat, &t1.vec[i])
	}

	polyVecKSub(&tmp1, &tmp1, &tmp2)
	polyVecKFreeze(&tmp1) // reduce32 would be sufficient
	polyVecKInvNTTMontgomery(&tmp1)

	/* Reconstruct w1 */
	polyVecKFreeze(&tmp1)
	polyVecKUseHint(&w1, &tmp1, h)

	/* Call random oracle and verify challenge */
	challenge(&cp, &mu, &w1)
	for i := 0; i < N; i++ {
		if c.coeffs[i] != cp.coeffs[i] {
			return false
		}
	}

	return true
}

// attached sig wrappers
func cryptoSign(msg []byte, sk *[SKSizePacked]byte) []byte {
	var sig [SigSizePacked]byte
	cryptoSignAttached(&sig, msg, sk)
	return append(sig[:], msg...)
}

func cryptoSignOpen(msg []byte, pk *[PKSizePacked]byte) []byte {
	var sig [SigSizePacked]byte
	if len(msg) < SigSizePacked {
		return nil
	}
	copy(sig[:], msg)
	d := msg[SigSizePacked:]
	if cryptoVerifyAttached(&sig, d, pk) {
		return d
	}
	return nil
}
