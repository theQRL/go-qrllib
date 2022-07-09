package dilithium

type polyVecK struct {
	vec [K]poly
}

type polyVecL struct {
	vec [L]poly
}

func polyVecLFreeze(v *polyVecL) {
	for i := 0; i < L; i++ {
		polyFreeze(&v.vec[i])
	}
}

func polyVecLAdd(w, u, v *polyVecL) {
	for i := 0; i < L; i++ {
		polyAdd(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func polyVecLNTT(v *polyVecL) {
	for i := 0; i < L; i++ {
		polyNTT(&v.vec[i])
	}
}

func polyVecLPointWiseAccInvMontgomery(w *poly, u, v *polyVecL) {
	var t poly

	polyPointWiseInvMontgomery(w, &u.vec[0], &v.vec[0])

	for i := 1; i < L; i++ {
		polyPointWiseInvMontgomery(&t, &u.vec[i], &v.vec[i])
		polyAdd(w, w, &t)
	}

	for i := 0; i < N; i++ {
		w.coeffs[i] = reduce32(w.coeffs[i])
	}
}

func polyVecLChkNorm(v *polyVecL, bound uint32) (ret int) {
	for i := 0; i < L; i++ {
		ret |= polyChkNorm(&v.vec[i], bound)
	}

	return ret
}

func polyVecKFreeze(v *polyVecK) {
	for i := 0; i < K; i++ {
		polyFreeze(&v.vec[i])
	}
}

func polyVecKAdd(w, u, v *polyVecK) {
	for i := 0; i < K; i++ {
		polyAdd(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}
func polyVecKSub(w, u, v *polyVecK) {
	for i := 0; i < K; i++ {
		polySub(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func polyVecKNeg(v *polyVecK) {
	for i := 0; i < K; i++ {
		polyNeg(&v.vec[i])
	}
}

func polyVecKShiftL(v *polyVecK, k uint) {
	for i := 0; i < K; i++ {
		polyShiftL(&v.vec[i], k)
	}
}

func polyVecKNTT(v *polyVecK) {
	for i := 0; i < K; i++ {
		polyNTT(&v.vec[i])
	}
}
func polyVecKInvNTTMontgomery(v *polyVecK) {
	for i := 0; i < K; i++ {
		polyInvNTTMontgomery(&v.vec[i])
	}
}

func polyVecKChkNorm(v *polyVecK, bound uint32) (ret int) {
	for i := 0; i < K; i++ {
		ret |= polyChkNorm(&v.vec[i], bound)
	}
	return ret
}

func polyVecKPower2Round(v1, v0, v *polyVecK) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			v1.vec[i].coeffs[j] = powerToRound(v.vec[i].coeffs[j],
				&v0.vec[i].coeffs[j])

		}
	}
}

func polyVecKDecompose(v1, v0, v *polyVecK) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			v1.vec[i].coeffs[j] = decompose(v.vec[i].coeffs[j],
				&v0.vec[i].coeffs[j])
		}
	}
}

func polyVecKMakeHint(h, u, v *polyVecK) (s uint32) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			h.vec[i].coeffs[j] = makeHint(u.vec[i].coeffs[j], v.vec[i].coeffs[j])
			s += h.vec[i].coeffs[j]
		}
	}
	return s
}

func polyVecKUseHint(w, u, h *polyVecK) {
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			w.vec[i].coeffs[j] = useHint(u.vec[i].coeffs[j], h.vec[i].coeffs[j])
		}
	}
}
