package dilithium

import "fmt"

func packPk(pkb *[CryptoPublicKeyBytes]uint8, rho [SeedBytes]uint8, t1 *polyVecK) {
	pk := pkb[:]
	copy(pk[:], rho[:])
	pk = pk[SeedBytes:]
	for i := 0; i < K; i++ {
		polyT1Pack(pk[i*PolyT1PackedBytes:], &t1.vec[i])
	}
}

func unpackPk(rho *[SeedBytes]uint8,
	t1 *polyVecK,
	pkb *[CryptoPublicKeyBytes]uint8) {
	pk := pkb[:]
	copy(rho[:], pk[:])
	pk = pk[SeedBytes:]
	for i := 0; i < K; i++ {
		polyT1Unpack(&t1.vec[i], pk[i*PolyT1PackedBytes:])
	}
}

func packSk(skb *[CryptoSecretKeyBytes]uint8,
	rho, tr, key [SeedBytes]uint8,
	t0 *polyVecK,
	s1 *polyVecL,
	s2 *polyVecK) {
	sk := skb[:]
	copy(sk[:], rho[:])

	copy(sk[SeedBytes:], key[:])
	copy(sk[SeedBytes*2:], tr[:])

	sk = sk[SeedBytes*3:]

	for i := 0; i < L; i++ {
		polyEtaPack(sk[i*PolyETAPackedBytes:], &s1.vec[i])
	}
	sk = sk[L*PolyETAPackedBytes:]

	for i := 0; i < K; i++ {
		polyEtaPack(sk[i*PolyETAPackedBytes:], &s2.vec[i])
	}
	sk = sk[K*PolyETAPackedBytes:]

	for i := 0; i < K; i++ {
		polyT0Pack(sk[i*PolyT0PackedBytes:], &t0.vec[i])
	}
}

func unpackSk(rho,
	tr,
	key *[SeedBytes]byte,
	t0 *polyVecK,
	s1 *polyVecL,
	s2 *polyVecK,
	skb *[CryptoSecretKeyBytes]byte) {
	sk := skb[:]
	copy(rho[:], sk[:])
	copy(key[:], sk[SeedBytes:])
	copy(tr[:], sk[SeedBytes*2:])
	sk = sk[SeedBytes*3:]

	for i := 0; i < L; i++ {
		polyEtaUnpack(&s1.vec[i], sk[i*PolyETAPackedBytes:])
	}
	sk = sk[L*PolyETAPackedBytes:]

	for i := 0; i < K; i++ {
		polyEtaUnpack(&s2.vec[i], sk[i*PolyETAPackedBytes:])
	}
	sk = sk[K*PolyETAPackedBytes:]

	for i := 0; i < K; i++ {
		polyT0Unpack(&t0.vec[i], sk[i*PolyT0PackedBytes:])
	}
}

func packSig(sigb []uint8, c []uint8, z *polyVecL, h *polyVecK) error {
	if len(sigb) != CryptoBytes {
		return fmt.Errorf("invalid sigb length | length expected %v | found %v", CryptoBytes, len(sigb))
	}
	if len(c) != SeedBytes {
		return fmt.Errorf("invalid c length | length expected %v | found %v", SeedBytes, len(c))
	}
	sig := sigb[:]

	copy(sig[:SeedBytes], c[:SeedBytes])
	sig = sig[SeedBytes:]

	for i := 0; i < L; i++ {
		polyZPack(sig[i*PolyZPackedBytes:], &z.vec[i])
	}
	sig = sig[L*PolyZPackedBytes:]

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

func unpackSig(c *[SeedBytes]uint8,
	z *polyVecL,
	h *polyVecK,
	sigBytes [CryptoBytes]uint8) int {

	sig := sigBytes[:]
	copy(c[:SeedBytes], sig[:SeedBytes])

	sig = sig[SeedBytes:]
	for i := 0; i < L; i++ {
		polyZUnpack(&z.vec[i], sig[i*PolyZPackedBytes:])
	}
	sig = sig[L*PolyZPackedBytes:]

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
