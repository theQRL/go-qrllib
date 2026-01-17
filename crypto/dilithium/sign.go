package dilithium

import (
	"crypto/rand"
	"crypto/subtle"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"golang.org/x/crypto/sha3"
)

// cryptoSignKeypair generates a Dilithium keypair from a seed.
//
// The function expands the seed using SHAKE-256 into three components:
//   - rho: public random seed for matrix A expansion
//   - rhoPrime: secret seed for sampling s1, s2
//   - key: secret key material for deterministic signing
//
// Key generation follows the Dilithium specification:
//  1. Expand seed into (rho, rhoPrime, key)
//  2. Generate matrix A from rho
//  3. Sample secret vectors s1, s2 with coefficients in [-eta, eta]
//  4. Compute t = A*s1 + s2
//  5. Split t into (t1, t0) using Power2Round
//  6. Pack public key as (rho, t1)
//  7. Pack secret key as (rho, key, tr, t0, s1, s2) where tr = H(pk)
//
// If seed is nil, a random 32-byte seed is generated.
// Returns the seed used and any error encountered.
func cryptoSignKeypair(seed []uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8, sk *[CRYPTO_SECRET_KEY_BYTES]uint8) ([]uint8, error) {
	var tr [TR_BYTES]uint8
	//var rho, rhoprime, key [SEED_BYTES]byte
	var rho, key [SEED_BYTES]uint8
	var rhoPrime [CRH_BYTES]uint8

	var mat [K]polyVecL
	var s1, s1hat polyVecL
	var s2, t1, t0 polyVecK

	if seed == nil {
		//coverage:ignore
		//rationale: all public API callers (New, NewDilithiumFromSeed) always provide a seed
		seed = make([]uint8, SEED_BYTES)
		_, err := rand.Read(seed)
		if err != nil {
			//coverage:ignore
			//rationale: crypto/rand.Read only fails if system entropy source is broken
			return nil, cryptoerrors.ErrSeedGeneration
		}
	}
	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	state := sha3.NewShake256()
	if _, err := state.Write(seed); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return nil, err
	}
	if _, err := state.Read(rho[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return nil, err
	}
	if _, err := state.Read(rhoPrime[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return nil, err
	}
	if _, err := state.Read(key[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return nil, err
	}

	/* Expand matrix */
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		//coverage:ignore
		//rationale: polyVecMatrixExpand's sha3 operations never return errors
		return nil, err
	}

	/* Sample short vectors s1 and s2 */
	if err := polyVecLUniformETA(&s1, &rhoPrime, 0); err != nil {
		//coverage:ignore
		//rationale: polyVecLUniformETA's sha3 operations never return errors
		return nil, err
	}
	if err := polyVecKUniformETA(&s2, &rhoPrime, L); err != nil {
		//coverage:ignore
		//rationale: polyVecKUniformETA's sha3 operations never return errors
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

// cryptoSignSignature generates a Dilithium signature for message m.
//
// The signing algorithm uses rejection sampling to find a valid signature:
//  1. Unpack secret key components (rho, tr, key, t0, s1, s2)
//  2. Compute mu = H(tr || m) as the message representative
//  3. Derive rhoPrime for masking (deterministic or random based on randomizedSigning)
//  4. Loop (rejection sampling at label "rej:"):
//     a. Sample masking vector y with coefficients in [-GAMMA1+1, GAMMA1]
//     b. Compute w = A*y and decompose into (w1, w0)
//     c. Compute challenge c = H(mu || w1)
//     d. Compute z = y + c*s1
//     e. Reject if ||z||∞ >= GAMMA1 - BETA (≈30% rejection rate)
//     f. Reject if ||w0 - c*s2||∞ >= GAMMA2 - BETA (≈5% rejection rate)
//     g. Reject if ||c*t0||∞ >= GAMMA2 (<1% rejection rate)
//     h. Compute hints h; reject if count > OMEGA (≈1% rejection rate)
//  5. Pack signature as (c, z, h)
//
// The rejection sampling loop typically completes in 4-7 iterations on average.
// The loop is probabilistically bounded - see const.go for detailed probability analysis.
// Setting randomizedSigning=false enables deterministic signatures for testing.
func cryptoSignSignature(sig, m []uint8, sk *[CRYPTO_SECRET_KEY_BYTES]uint8, randomizedSigning bool) error {
	var rho, key [SEED_BYTES]uint8
	var tr [TR_BYTES]uint8
	var mu, rhoPrime [CRH_BYTES]uint8
	var s1, y, z polyVecL
	var mat [K]polyVecL
	var s2, t0, w1, h, w0 polyVecK
	var cp poly
	var nonce uint16

	unpackSk(&rho, &key, &tr, &t0, &s1, &s2, sk)

	/* Compute CRH(tr, msg) */
	state := getShake256()
	defer putShake256(state)
	_, _ = state.Write(tr[:])
	_, _ = state.Write(m)
	_, _ = state.Read(mu[:]) // ShakeHash.Read never returns an error

	if randomizedSigning {
		//coverage:ignore
		//rationale: randomizedSigning is always false in current API (deterministic signing)
		if _, err := rand.Read(rhoPrime[:]); err != nil {
			//coverage:ignore
			//rationale: crypto/rand.Read only fails if system entropy source is broken
			return err
		}
	} else {
		var dataToBeHashed [SEED_BYTES + CRH_BYTES]uint8
		copy(dataToBeHashed[:], key[:SEED_BYTES])
		copy(dataToBeHashed[SEED_BYTES:], mu[:CRH_BYTES])
		sha3.ShakeSum256(rhoPrime[:], dataToBeHashed[:])
	}

	/* Expand matrix and transform vectors */
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		//coverage:ignore
		//rationale: polyVecMatrixExpand's sha3 operations never return errors
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
	if err := polyVecKPackW1(sig[:K*POLY_W1_PACKED_BYTES], &w1); err != nil {
		//coverage:ignore
		//rationale: polyVecKPackW1's sha3 operations never return errors
		return err
	}

	state.Reset() // Reuse pooled hasher
	if _, err := state.Write(mu[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Write(sig[:K*POLY_W1_PACKED_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(sig[:SEED_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return err
	}
	if err := polyChallenge(&cp, sig[:SEED_BYTES]); err != nil {
		//coverage:ignore
		//rationale: polyChallenge's sha3 operations never return errors
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
		//coverage:ignore
		//rationale: rejection condition rarely triggers; signature typically succeeds on first attempt
		goto rej
	}

	polyVecKAdd(&w0, &w0, &h)
	n := polyVecKMakeHint(&h, &w0, &w1)
	if n > OMEGA {
		//coverage:ignore
		//rationale: rejection condition rarely triggers; signature typically succeeds on first attempt
		goto rej
	}

	if err := packSig(sig[:CRYPTO_BYTES], sig[:SEED_BYTES], &z, &h); err != nil {
		//coverage:ignore
		//rationale: packSig only fails for invalid hint count, but rejection loop ensures n <= OMEGA
		return err
	}
	return nil
}

// cryptoSign creates a signed message by prepending a signature to the message.
// Returns signature || message as a single byte slice.
// This is the "attached signature" format where the message is included with the signature.
func cryptoSign(msg []uint8, sk *[CRYPTO_SECRET_KEY_BYTES]uint8, randomizedSigning bool) ([]uint8, error) {
	sm := make([]uint8, CRYPTO_BYTES+len(msg))
	copy(sm[CRYPTO_BYTES:], msg)
	err := cryptoSignSignature(sm[:CRYPTO_BYTES], sm[CRYPTO_BYTES:], sk, randomizedSigning)
	return sm, err
}

// cryptoSignVerify verifies a Dilithium signature against a message and public key.
//
// Verification algorithm:
//  1. Unpack public key (rho, t1) and signature (c, z, h)
//  2. Check that z has coefficients within valid bounds
//  3. Compute mu = H(H(pk) || m)
//  4. Recompute w'1 = UseHint(h, Az - c*t1*2^d)
//  5. Recompute c' = H(mu || w'1)
//  6. Accept if c == c'
//
// Returns (true, nil) if signature is valid, (false, nil) if invalid,
// or (false, error) if verification encountered an error.
func cryptoSignVerify(sig [CRYPTO_BYTES]uint8, m []uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) (bool, error) {
	var buf [K * POLY_W1_PACKED_BYTES]uint8
	var rho, c, c2 [SEED_BYTES]uint8
	var mu [CRH_BYTES]uint8
	var z polyVecL
	var mat [K]polyVecL
	var t1, w1, h polyVecK
	var cp poly

	unpackPk(&rho, &t1, pk)
	if unpackSig(&c, &z, &h, sig) != 0 {
		return false, nil
	}
	if polyVecLChkNorm(&z, GAMMA1-BETA) != 0 {
		return false, nil
	}

	/* Compute CRH(H(rho, t1), msg) */
	sha3.ShakeSum256(mu[:TR_BYTES], pk[:CRYPTO_PUBLIC_KEY_BYTES])
	state := getShake256()
	defer putShake256(state)
	if _, err := state.Write(mu[:TR_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Write(m); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Read(mu[:CRH_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return false, err
	}

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	if err := polyChallenge(&cp, c[:]); err != nil {
		//coverage:ignore
		//rationale: polyChallenge's sha3 operations never return errors
		return false, err
	}
	if err := polyVecMatrixExpand(&mat, &rho); err != nil {
		//coverage:ignore
		//rationale: polyVecMatrixExpand's sha3 operations never return errors
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
		//coverage:ignore
		//rationale: polyVecKPackW1's sha3 operations never return errors
		return false, err
	}

	/* Call random oracle and verify challenge */
	state.Reset() // Reuse pooled hasher
	if _, err := state.Write(mu[:CRH_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Write(buf[:K*POLY_W1_PACKED_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return false, err
	}
	if _, err := state.Read(c2[:SEED_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return false, err
	}

	// Use constant-time comparison to prevent timing side-channel attacks
	return subtle.ConstantTimeCompare(c[:], c2[:]) == 1, nil
}

// cryptoSignOpen verifies and extracts a message from a signed message.
// The signed message format is signature || message (attached signature).
// Returns the original message if valid, or nil if verification fails.
func cryptoSignOpen(sm []uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) ([]uint8, error) {
	if len(sm) < CRYPTO_BYTES {
		return nil, nil
	}

	var sig [CRYPTO_BYTES]uint8
	msg := make([]uint8, len(sm)-CRYPTO_BYTES)

	copy(sig[:], sm)
	copy(msg, sm[CRYPTO_BYTES:])

	if result, err := cryptoSignVerify(sig, msg, pk); err != nil || !result {
		return nil, err
	}

	return msg, nil
}
