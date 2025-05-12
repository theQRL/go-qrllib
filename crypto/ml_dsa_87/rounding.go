package ml_dsa_87

func power2Round(a0 *int32, a int32) int32 {
	var a1 int32

	a1 = (a + (1 << (D - 1)) - 1) >> D
	*a0 = a - (a1 << D)
	return a1
}

func decompose(a0 *int32, a int32) int32 {
	a1 := (a + 127) >> 7
	a1 = (a1*1025 + (1 << 21)) >> 22
	a1 &= 15

	*a0 = a - a1*2*GAMMA2
	*a0 -= (((Q-1)/2 - *a0) >> 31) & Q

	return a1
}

func makeHint(a0, a1 int32) uint {
	if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
		return 1
	}

	return 0
}

func useHint(a int32, hint int) int32 {
	var a0, a1 int32

	a1 = decompose(&a0, a)
	if hint == 0 {
		return a1
	}

	if a0 > 0 {
		return (a1 + 1) & 15
	} else {
		return (a1 - 1) & 15
	}
}
