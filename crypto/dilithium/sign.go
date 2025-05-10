package dilithium

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Take a random seed, and compute sk/pk pair.
func cryptoSignKeypair(seed *[SeedBytes]uint8, pk *[CryptoPublicKeyBytes]uint8, sk *[CryptoSecretKeyBytes]uint8) (*[SeedBytes]uint8, error) {
	var tr [TRBytes]uint8
	var rho, key [SeedBytes]uint8
	var rhoPrime [CRHBytes]uint8

	var mat [K]polyVecL
	var s1, s1hat polyVecL
	var s2, t1, t0 polyVecK

	if seed == nil {
		seed = new([SeedBytes]uint8)
		_, err := rand.Read(seed[:])
		if err != nil {
			return nil, fmt.Errorf("failed to generate random seed: %v", err)
		}
	}
	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	state := sha3.NewShake256()
	if _, err := state.Write(seed[:]); err != nil {
		return nil, err
	}
	extraData := []byte{K, L}
	if _, err := state.Write(extraData); err != nil {
		return nil, err
	}
	if _, err := state.Read(rho[:]); err != nil {
		return nil, err
	}
	if _, err := state.Read(rhoPrime[:]); err != nil {
		return nil, err
	}
	if _, err := state.Read(key[:]); err != nil {
		return nil, err
	}

	/* Expand matrix */
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		return nil, err
	}

	/* Sample short vectors s1 and s2 */
	if err := polyVecLUniformETA(&s1, &rhoPrime, 0); err != nil {
		return nil, err
	}
	if err := polyVecKUniformETA(&s2, &rhoPrime, L); err != nil {
		return nil, err
	}

	/* Matrix-vector multiplication */
	s1hat = s1
	polyVecLNTT(&s1hat)
	polyVecMatrixPointWiseMontgomery(&t1, &mat, &s1hat)
	polyVecKReduce(&t1)
	polyVecKInvNTTToMont(&t1)

	/* Add noise vector s2 */
	polyVecKAdd(&t1, &t1, &s2)

	/* Extract t1 and write public key */
	polyVecKCAddQ(&t1)
	polyVecKPower2Round(&t1, &t0, &t1)
	packPk(pk, rho, &t1)

	/* Compute tr = CRH(rho, t1) and write secret key */
	sha3.ShakeSum256(tr[:], pk[:])
	packSk(sk, rho, tr, key, &t0, &s1, &s2)

	return seed, nil
}

func cryptoSignSignatureInternal(sig, m []uint8, pre []uint8, rnd [RNDBytes]uint8, sk *[CryptoSecretKeyBytes]uint8) error {
	var rho, key [SeedBytes]uint8
	var tr [TRBytes]uint8
	var mu, rhoPrime [CRHBytes]uint8
	var s1, y, z polyVecL
	var mat [K]polyVecL
	var s2, t0, w1, h, w0 polyVecK
	var cp poly
	var nonce uint16

	unpackSk(&rho, &tr, &key, &t0, &s1, &s2, sk)

	/* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
	state := sha3.NewShake256()
	state.Write(tr[:])
	state.Write(pre)
	state.Write(m)
	state.Read(mu[:])

	/* Compute rhoprime = CRH(key, rnd, mu) */
	state = sha3.NewShake256()
	state.Write(key[:])
	state.Write(rnd[:])
	state.Write(mu[:])
	state.Read(rhoPrime[:])

	/* Expand matrix and transform vectors */
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		return err
	}
	polyVecLNTT(&s1)
	polyVecKNTT(&s2)
	polyVecKNTT(&t0)

rej:

	/* Sample intermediate vector y */
	polyVecLUniformGamma1(&y, rhoPrime, nonce)
	nonce++

	/* Matrix-vector multiplication */
	z = y
	polyVecLNTT(&z)
	polyVecMatrixPointWiseMontgomery(&w1, &mat, &z)
	polyVecKReduce(&w1)
	polyVecKInvNTTToMont(&w1)

	/* Decompose w and call the random oracle */
	polyVecKCAddQ(&w1)
	polyVecKDecompose(&w1, &w0, &w1)
	if err := polyVecKPackW1(sig[:K*PolyW1PackedBytes], &w1); err != nil {
		return err
	}

	state = sha3.NewShake256()
	if _, err := state.Write(mu[:]); err != nil {
		return err
	}
	if _, err := state.Write(sig[:K*PolyW1PackedBytes]); err != nil {
		return err
	}
	if _, err := state.Read(sig[:CTILDEBytes]); err != nil {
		return err
	}
	if err := polyChallenge(&cp, sig[:CTILDEBytes]); err != nil {
		return err
	}
	polyNTT(&cp)

	/* Compute z, reject if it reveals secret */
	polyVecLPointWisePolyMontgomery(&z, &cp, &s1)
	polyVecLInvNTTToMont(&z)
	polyVecLAdd(&z, &z, &y)
	polyVecLReduce(&z)
	if polyVecLChkNorm(&z, GAMMA1-BETA) != 0 {
		goto rej
	}

	/* Check that subtracting cs2 does not change high bits of w and low bits
	 * do not reveal secret information */
	polyVecKPointWisePolyMontgomery(&h, &cp, &s2)
	polyVecKInvNTTToMont(&h)
	polyVecKSub(&w0, &w0, &h)
	polyVecKReduce(&w0)
	if polyVecKChkNorm(&w0, GAMMA2-BETA) != 0 {
		goto rej
	}

	/* Compute hints for w1 */
	polyVecKPointWisePolyMontgomery(&h, &cp, &t0)
	polyVecKInvNTTToMont(&h)
	polyVecKReduce(&h)
	if polyVecKChkNorm(&h, GAMMA2) != 0 {
		goto rej
	}

	polyVecKAdd(&w0, &w0, &h)
	n := polyVecKMakeHint(&h, &w0, &w1)
	if n > OMEGA {
		goto rej
	}
	var c [CTILDEBytes]uint8
	copy(c[:], sig[:CTILDEBytes])
	if err := packSig(sig[:CryptoBytes], c, &z, &h); err != nil {
		return err
	}
	return nil
}

func cryptoSignSignature(sig, m []uint8, ctx []uint8, sk *[CryptoSecretKeyBytes]uint8, randomizedSigning bool) error {
	if len(ctx) > 255 {
		return fmt.Errorf("invalid context length: %d, expected less than %d", len(ctx), 255)
	}

	var rnd [RNDBytes]uint8

	pre := make([]uint8, len(ctx)+2)
	pre[0] = 0
	pre[1] = uint8(len(ctx))
	copy(pre[2:], ctx)

	if randomizedSigning {
		_, err := rand.Read(rnd[:])
		if err != nil {
			return fmt.Errorf("failed to generate random seed: %v", err)
		}
	}

	return cryptoSignSignatureInternal(sig, m, pre[:], rnd, sk)
}

// attached sig wrappers
func cryptoSign(msg []uint8, ctx []uint8, sk *[CryptoSecretKeyBytes]uint8, randomizedSigning bool) ([]uint8, error) {
	sm := make([]uint8, CryptoBytes+len(msg))
	copy(sm[CryptoBytes:], msg)
	err := cryptoSignSignature(sm[:CryptoBytes], sm[CryptoBytes:], ctx, sk, randomizedSigning)
	return sm, err
}

func cryptoSignVerifyInternal(sig [CryptoBytes]uint8, m []uint8, pre []uint8, pk *[CryptoPublicKeyBytes]uint8) (bool, error) {
	var buf [K * PolyW1PackedBytes]uint8
	var rho [SeedBytes]uint8
	var mu [CRHBytes]uint8
	var c, c2 [CTILDEBytes]uint8
	var cp poly
	var mat [K]polyVecL
	var z polyVecL
	var t1, w1, h polyVecK

	unpackPk(&rho, &t1, pk)
	if unpackSig(&c, &z, &h, sig) != 0 {
		return false, nil
	}
	if polyVecLChkNorm(&z, GAMMA1-BETA) != 0 {
		return false, nil
	}

	/* Compute CRH(H(rho, t1), pre, msg) */
	sha3.ShakeSum256(mu[:TRBytes], pk[:CryptoPublicKeyBytes])
	state := sha3.NewShake256()
	if _, err := state.Write(mu[:TRBytes]); err != nil {
		return false, err
	}
	if _, err := state.Write(pre); err != nil {
		return false, err
	}
	if _, err := state.Write(m); err != nil {
		return false, err
	}
	if _, err := state.Read(mu[:CRHBytes]); err != nil {
		return false, err
	}

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	if err := polyChallenge(&cp, c[:]); err != nil {
		return false, err
	}
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		return false, err
	}

	polyVecLNTT(&z)
	polyVecMatrixPointWiseMontgomery(&w1, &mat, &z)

	polyNTT(&cp)
	polyVecKShiftL(&t1)
	polyVecKNTT(&t1)
	polyVecKPointWisePolyMontgomery(&t1, &cp, &t1)

	polyVecKSub(&w1, &w1, &t1)
	polyVecKReduce(&w1)
	polyVecKInvNTTToMont(&w1)

	/* Reconstruct w1 */
	polyVecKCAddQ(&w1)
	polyVecKUseHint(&w1, &w1, &h)
	if err := polyVecKPackW1(buf[:], &w1); err != nil {
		return false, err
	}

	/* Call random oracle and verify challenge */
	state = sha3.NewShake256()
	if _, err := state.Write(mu[:CRHBytes]); err != nil {
		return false, err
	}
	if _, err := state.Write(buf[:K*PolyW1PackedBytes]); err != nil {
		return false, err
	}
	if _, err := state.Read(c2[:CTILDEBytes]); err != nil {
		return false, err
	}
	for i := 0; i < CTILDEBytes; i++ {
		if c[i] != c2[i] {
			return false, nil
		}
	}

	return true, nil
}

func cryptoSignVerify(sig [CryptoBytes]uint8, m []uint8, ctx []uint8, pk *[CryptoPublicKeyBytes]uint8) (bool, error) {
	if len(ctx) > 255 {
		return false, fmt.Errorf("invalid context length: %d, expected less than %d", len(ctx), 255)
	}

	pre := make([]uint8, len(ctx)+2)
	pre[0] = 0
	pre[1] = uint8(len(ctx))
	copy(pre[2:], ctx)

	return cryptoSignVerifyInternal(sig, m, pre[:], pk)
}

func cryptoSignOpen(sm []uint8, ctx []uint8, pk *[CryptoPublicKeyBytes]uint8) ([]uint8, error) {
	if len(sm) < CryptoBytes {
		return nil, nil
	}

	var sig [CryptoBytes]uint8
	msg := make([]uint8, len(sm)-CryptoBytes)

	copy(sig[:], sm)
	copy(msg, sm[CryptoBytes:])

	if result, err := cryptoSignVerify(sig, msg, ctx, pk); err != nil || !result {
		return nil, err
	}

	return msg, nil
}
