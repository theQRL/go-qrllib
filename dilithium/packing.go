package dilithium

func packPk(pkb *[PKSizePacked]byte, rho *[SeedBytes]byte, t1 *polyVecK) {
	pk := pkb[:]
	copy(pk[:], rho[:])
	pk = pk[SeedBytes:]
	for i := 0; i < K; i++ {
		polyT1Pack(pk[i*PolT1SizePacked:], &t1.vec[i])
	}
}

func unpackPk(rho *[SeedBytes]byte,
	t1 *polyVecK,
	pkb *[PKSizePacked]byte) {
	pk := pkb[:]
	copy(rho[:], pk[:])
	pk = pk[SeedBytes:]
	for i := 0; i < K; i++ {
		polyT1Unpack(&t1.vec[i], pk[i*PolT1SizePacked:])
	}
}

func packSk(skb *[SKSizePacked]byte,
	rho, key *[SeedBytes]byte,
	tr *[CrhBytes]byte,
	s1 *polyVecL,
	s2, t0 *polyVecK) {
	sk := skb[:]
	copy(sk[:], rho[:])

	copy(sk[SeedBytes:], key[:])
	copy(sk[SeedBytes*2:], tr[:])

	sk = sk[SeedBytes*2+CrhBytes:]

	for i := 0; i < L; i++ {
		polyEtaPack(sk[i*PolETASizePacked:], &s1.vec[i])
	}
	sk = sk[L*PolETASizePacked:]

	for i := 0; i < K; i++ {
		polyEtaPack(sk[i*PolETASizePacked:], &s2.vec[i])
	}
	sk = sk[K*PolETASizePacked:]

	for i := 0; i < K; i++ {
		polyT0Pack(sk[i*PolT0SizePacked:], &t0.vec[i])
	}
}

func unpackSk(rho *[SeedBytes]byte,
	key *[SeedBytes]byte,
	tr *[CrhBytes]byte,
	s1 *polyVecL,
	s2, t0 *polyVecK,
	skb *[SKSizePacked]byte) {
	sk := skb[:]
	copy(rho[:], sk[:])
	copy(key[:], sk[SeedBytes:])
	copy(tr[:], sk[SeedBytes*2:])
	sk = sk[SeedBytes*2+CrhBytes:]

	for i := 0; i < L; i++ {
		polyEtaUnpack(&s1.vec[i], sk[i*PolETASizePacked:])
	}
	sk = sk[L*PolETASizePacked:]

	for i := 0; i < K; i++ {
		polyEtaUnpack(&s2.vec[i], sk[i*PolETASizePacked:])
	}
	sk = sk[K*PolETASizePacked:]

	for i := 0; i < K; i++ {
		polyT0Unpack(&t0.vec[i], sk[i*PolT0SizePacked:])
	}
}

func packSig(sigb *[SigSizePacked]byte, z *polyVecL, h *polyVecK, c *poly) {
	sig := sigb[:]

	for i := 0; i < L; i++ {
		polyZPack(sigb[i*PolZSizePacked:], &z.vec[i])
	}
	sig = sig[L*PolZSizePacked:]

	/* Encode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if h.vec[i].coeffs[j] == 1 {
				sig[k] = byte(j)
				k++
			}
			sig[OMEGA+i] = byte(k)
		}
	}
	for k < OMEGA {
		sig[k] = 0
		k++
	}
	sig = sig[OMEGA+K:]

	/* Encode c */
	signs := uint64(0)
	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		sig[i] = 0
		for j := uint(0); j < 8; j++ {
			if c.coeffs[8*i+j] != 0 {
				sig[i] |= byte(1 << j)
				if c.coeffs[8*i+j] == (Q - 1) {
					signs |= mask
				}
				mask <<= 1
			}
		}
	}
	sig = sig[N/8:]
	for i := uint(0); i < 8; i++ {
		sig[i] = byte(signs >> (8 * i))
	}
}

func unpackSig(z *polyVecL,
	h *polyVecK,
	c *poly,
	sigb *[SigSizePacked]byte) bool {

	sig := sigb[:]
	for i := 0; i < L; i++ {
		polyZUnpack(&z.vec[i], sigb[i*PolZSizePacked:])
	}
	sig = sig[L*PolZSizePacked:]
	rem := len(sig)

	/* Decode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			h.vec[i].coeffs[j] = 0
		}
		limit := int(sig[OMEGA+i])
		if limit > rem {
			return false
		}
		for j := k; j < limit; j++ {
			h.vec[i].coeffs[sig[j]] = 1
		}
		k = int(sig[OMEGA+i])
	}
	sig = sig[OMEGA+K:]

	/* Decode c */
	*c = poly{}

	signs := uint64(0)
	for i := uint(0); i < 8; i++ {
		signs |= uint64(sig[N/8+i]) << (8 * i)
	}

	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		for j := uint(0); j < 8; j++ {
			if ((sig[i] >> j) & 0x01) != 0 {
				if (signs & mask) != 0 {
					c.coeffs[8*i+j] = Q - 1
				} else {
					c.coeffs[8*i+j] = 1
				}

				mask <<= 1
			}
		}
	}
	return true
}

func packSigDetached(sigb *[SigSizePacked]byte, z *polyVecL, h *polyVecK, c *poly) []byte {
	sig := sigb[:]

	for i := 0; i < L; i++ {
		polyZPack(sigb[i*PolZSizePacked:], &z.vec[i])
	}
	sig = sig[L*PolZSizePacked:]

	/* Encode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if h.vec[i].coeffs[j] == 1 {
				sig[K+k] = byte(j)
				k++
			}
			sig[i] = byte(k)
		}
	}
	sig = sig[K+k:]

	/* Encode c */
	signs := uint64(0)
	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		sig[i] = 0
		for j := uint(0); j < 8; j++ {
			if c.coeffs[8*i+j] != 0 {
				sig[i] |= byte(1 << j)
				if c.coeffs[8*i+j] == (Q - 1) {
					signs |= mask
				}
				mask <<= 1
			}
		}
	}
	sig = sig[N/8:]
	for i := uint(0); i < 8; i++ {
		sig[i] = byte(signs >> (8 * i))
	}
	sig = sig[8:]

	return sigb[0 : SigSizePacked-len(sig)]
}

func unpackSigDetached(z *polyVecL,
	h *polyVecK,
	c *poly,
	sig []byte) bool {

	for i := 0; i < L; i++ {
		polyZUnpack(&z.vec[i], sig[i*PolZSizePacked:])
	}
	sig = sig[L*PolZSizePacked:]
	rem := len(sig)

	/* Decode h */
	k := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			h.vec[i].coeffs[j] = 0
		}
		limit := int(sig[i])
		if limit > rem {
			return false
		}
		for j := k; j < limit; j++ {
			h.vec[i].coeffs[sig[K+j]] = 1
		}
		k = int(sig[i])
	}
	if len(sig)-(K+k) < (N/8 + 8) {
		return false
	}
	sig = sig[K+k:]

	/* Decode c */
	*c = poly{}

	signs := uint64(0)
	for i := uint(0); i < 8; i++ {
		signs |= uint64(sig[N/8+i]) << (8 * i)
	}

	mask := uint64(1)
	for i := uint(0); i < N/8; i++ {
		for j := uint(0); j < 8; j++ {
			if ((sig[i] >> j) & 0x01) != 0 {
				if (signs & mask) != 0 {
					c.coeffs[8*i+j] = Q - 1
				} else {
					c.coeffs[8*i+j] = 1
				}

				mask <<= 1
			}
		}
	}
	return true
}
