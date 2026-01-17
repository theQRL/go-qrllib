package ml_dsa_87

import cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"

func packPk(pkb *[CRYPTO_PUBLIC_KEY_BYTES]uint8, rho [SEED_BYTES]uint8, t1 *polyVecK) {
	pk := pkb[:]
	copy(pk[:], rho[:])
	pk = pk[SEED_BYTES:]
	for i := 0; i < K; i++ {
		polyT1Pack(pk[i*POLY_T1_PACKED_BYTES:], &t1.vec[i])
	}
}

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

func packSk(skb *[CRYPTO_SECRET_KEY_BYTES]uint8,
	rho [SEED_BYTES]uint8, tr [TR_BYTES]uint8, key [SEED_BYTES]uint8,
	t0 *polyVecK,
	s1 *polyVecL,
	s2 *polyVecK) {
	sk := skb[:]
	copy(sk[:], rho[:])

	copy(sk[SEED_BYTES:], key[:])
	copy(sk[SEED_BYTES*2:], tr[:])

	sk = sk[SEED_BYTES*2+TR_BYTES:]

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

func unpackSk(rho *[SEED_BYTES]byte,
	tr *[TR_BYTES]byte,
	key *[SEED_BYTES]byte,
	t0 *polyVecK,
	s1 *polyVecL,
	s2 *polyVecK,
	skb *[CRYPTO_SECRET_KEY_BYTES]byte) {
	sk := skb[:]
	copy(rho[:], sk[:])
	copy(key[:], sk[SEED_BYTES:])
	copy(tr[:], sk[SEED_BYTES*2:])
	sk = sk[SEED_BYTES*2+TR_BYTES:]

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

func packSig(sigb []uint8, c [C_TILDE_BYTES]uint8, z *polyVecL, h *polyVecK) error {
	if len(sigb) != CRYPTO_BYTES {
		//coverage:ignore
		//rationale: internal callers always pass correctly sized buffers
		return cryptoerrors.ErrInvalidSignatureSize
	}
	sig := sigb[:]

	copy(sig[:C_TILDE_BYTES], c[:C_TILDE_BYTES])
	sig = sig[C_TILDE_BYTES:]

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

func unpackSig(c *[C_TILDE_BYTES]uint8,
	z *polyVecL,
	h *polyVecK,
	sigBytes [CRYPTO_BYTES]uint8) int {

	sig := sigBytes[:]
	copy(c[:C_TILDE_BYTES], sig[:C_TILDE_BYTES])

	sig = sig[C_TILDE_BYTES:]
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
