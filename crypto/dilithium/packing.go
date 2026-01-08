package dilithium

import "fmt"

// packPk serializes a public key into bytes.
// Format: rho (32 bytes) || t1[0] || t1[1] || ... || t1[K-1]
// where each t1[i] is packed using 10 bits per coefficient.
func packPk(pkb *[CRYPTO_PUBLIC_KEY_BYTES]uint8, rho [SEED_BYTES]uint8, t1 *polyVecK) {
	pk := pkb[:]
	copy(pk[:], rho[:])
	pk = pk[SEED_BYTES:]
	for i := 0; i < K; i++ {
		polyT1Pack(pk[i*POLY_T1_PACKED_BYTES:], &t1.vec[i])
	}
}

// unpackPk deserializes a public key from bytes.
// Extracts rho and t1 vector from the packed representation.
func unpackPk(rho *[SEED_BYTES]uint8,
	t1 *polyVecK,
	pkb *[CRYPTO_PUBLIC_KEY_BYTES]uint8) {
	pk := pkb[:]
	copy(rho[:], pk[:])
	pk = pk[SEED_BYTES:]
	for i := 0; i < K; i++ {
		polyT1Unpack(&t1.vec[i], pk[i*POLY_T1_PACKED_BYTES:])
	}
}

// packSk serializes a secret key into bytes.
// Format: rho (32) || key (32) || tr (64) || s1 || s2 || t0
// where s1, s2 use eta-encoding and t0 uses 13-bit coefficients.
func packSk(skb *[CRYPTO_SECRET_KEY_BYTES]uint8,
	rho [SEED_BYTES]uint8, tr [TR_BYTES]uint8, key [SEED_BYTES]uint8,
	t0 *polyVecK,
	s1 *polyVecL,
	s2 *polyVecK) {
	sk := skb[:]
	copy(sk[:], rho[:])

	copy(sk[SEED_BYTES:], key[:])
	copy(sk[SEED_BYTES*2:], tr[:])

	sk = sk[2*SEED_BYTES+TR_BYTES:]

	for i := 0; i < L; i++ {
		polyEtaPack(sk[i*POLY_ETA_PACKED_BYTES:], &s1.vec[i])
	}
	sk = sk[L*POLY_ETA_PACKED_BYTES:]

	for i := 0; i < K; i++ {
		polyEtaPack(sk[i*POLY_ETA_PACKED_BYTES:], &s2.vec[i])
	}
	sk = sk[K*POLY_ETA_PACKED_BYTES:]

	for i := 0; i < K; i++ {
		polyT0Pack(sk[i*POLY_T0_PACKED_BYTES:], &t0.vec[i])
	}
}

// unpackSk deserializes a secret key from bytes.
// Extracts rho, tr, key, t0, s1, s2 from the packed representation.
func unpackSk(rho,
	key *[SEED_BYTES]byte,
	tr *[TR_BYTES]byte,
	t0 *polyVecK,
	s1 *polyVecL,
	s2 *polyVecK,
	skb *[CRYPTO_SECRET_KEY_BYTES]byte) {
	sk := skb[:]
	copy(rho[:], sk[:])
	copy(key[:], sk[SEED_BYTES:])
	copy(tr[:], sk[SEED_BYTES*2:])
	sk = sk[2*SEED_BYTES+TR_BYTES:]

	for i := 0; i < L; i++ {
		polyEtaUnpack(&s1.vec[i], sk[i*POLY_ETA_PACKED_BYTES:])
	}
	sk = sk[L*POLY_ETA_PACKED_BYTES:]

	for i := 0; i < K; i++ {
		polyEtaUnpack(&s2.vec[i], sk[i*POLY_ETA_PACKED_BYTES:])
	}
	sk = sk[K*POLY_ETA_PACKED_BYTES:]

	for i := 0; i < K; i++ {
		polyT0Unpack(&t0.vec[i], sk[i*POLY_T0_PACKED_BYTES:])
	}
}

// packSig serializes a signature into bytes.
// Format: c (32 bytes) || z (L polynomials) || h (hint encoding)
//
// The hint encoding uses OMEGA+K bytes:
//   - First OMEGA bytes: indices where h[i][j] = 1
//   - Last K bytes: cumulative count of hints per polynomial
//
// This encoding ensures strong unforgeability by requiring hint indices
// to be strictly increasing within each polynomial.
func packSig(sigb []uint8, c []uint8, z *polyVecL, h *polyVecK) error {
	if len(sigb) != CRYPTO_BYTES {
		return fmt.Errorf("invalid sigb length | length expected %v | found %v", CRYPTO_BYTES, len(sigb))
	}
	if len(c) != SEED_BYTES {
		return fmt.Errorf("invalid c length | length expected %v | found %v", SEED_BYTES, len(c))
	}
	sig := sigb[:]

	copy(sig[:SEED_BYTES], c[:SEED_BYTES])
	sig = sig[SEED_BYTES:]

	for i := 0; i < L; i++ {
		polyZPack(sig[i*POLY_Z_PACKED_BYTES:], &z.vec[i])
	}
	sig = sig[L*POLY_Z_PACKED_BYTES:]

	/* Encode h */
	for i := 0; i < OMEGA+K; i++ {
		sig[i] = 0
	}

	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if h.vec[i].coeffs[j] != 0 {
				sig[k] = uint8(j)
				k++
			}
			sig[OMEGA+i] = uint8(k)
		}
	}
	return nil
}

// unpackSig deserializes a signature from bytes.
// Extracts challenge c, response z, and hints h.
//
// Returns 0 on success, 1 if the signature format is invalid.
// Validity checks include:
//   - Hint count does not exceed OMEGA
//   - Hint indices are strictly increasing (prevents malleability)
//   - Unused hint bytes are zero-padded
func unpackSig(c *[SEED_BYTES]uint8,
	z *polyVecL,
	h *polyVecK,
	sigBytes [CRYPTO_BYTES]uint8) int {

	sig := sigBytes[:]
	copy(c[:SEED_BYTES], sig[:SEED_BYTES])

	sig = sig[SEED_BYTES:]
	for i := 0; i < L; i++ {
		polyZUnpack(&z.vec[i], sig[i*POLY_Z_PACKED_BYTES:])
	}
	sig = sig[L*POLY_Z_PACKED_BYTES:]

	/* Decode h */
	k := uint(0)
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			h.vec[i].coeffs[j] = 0
		}
		if uint(sig[OMEGA+i]) < k || sig[OMEGA+i] > OMEGA {
			return 1
		}
		for j := k; j < uint(sig[OMEGA+i]); j++ {
			/* Coefficients are ordered for strong unforgeability */
			if j > k && sig[j] <= sig[j-1] {
				return 1
			}
			h.vec[i].coeffs[sig[j]] = 1
		}
		k = uint(sig[OMEGA+i])
	}

	for j := k; j < OMEGA; j++ {
		if sig[j] != 0 {
			return 1
		}
	}

	return 0
}
