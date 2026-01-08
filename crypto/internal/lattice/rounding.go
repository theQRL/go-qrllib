package lattice

// Power2Round computes a1, a0 such that a = a1*2^D + a0 with -2^(D-1) < a0 <= 2^(D-1)
func Power2Round(a0 *int32, a int32) int32 {
	a1 := (a + (1 << (D - 1)) - 1) >> D
	*a0 = a - (a1 << D)
	return a1
}

// Decompose computes a1, a0 such that a mod Q = a1*2*GAMMA2 + a0
func Decompose(a0 *int32, a int32) int32 {
	a1 := (a + 127) >> 7
	a1 = (a1*1025 + (1 << 21)) >> 22
	a1 &= 15

	*a0 = a - a1*2*GAMMA2
	*a0 -= (((Q-1)/2 - *a0) >> 31) & Q

	return a1
}

// MakeHint computes hint bit for a0, a1
// Returns 1 if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)
// This is a constant-time implementation to prevent timing side-channels.
func MakeHint(a0, a1 int32) uint {
	// Constant-time comparisons using arithmetic
	// For signed comparison a > b: (b - a) >> 31 gives 1 if b - a < 0 (i.e., a > b)

	// Check a0 > GAMMA2: true if (GAMMA2 - a0) is negative
	gtGamma2 := uint32(GAMMA2-a0) >> 31

	// Check a0 < -GAMMA2: true if (a0 + GAMMA2) is negative
	ltNegGamma2 := uint32(a0+GAMMA2) >> 31

	// Check a0 == -GAMMA2: true if (a0 + GAMMA2) == 0
	// isZero(x) = 1 - (((x) | -(x)) >> 31) gives 1 for x == 0, 0 otherwise
	diff := a0 + GAMMA2
	eqNegGamma2 := 1 - (uint32(diff|(-diff)) >> 31)

	// Check a1 != 0: (a1 | -a1) >> 31 gives 1 if a1 != 0, 0 if a1 == 0
	a1NonZero := uint32(a1|(-a1)) >> 31

	// Combine: gtGamma2 | ltNegGamma2 | (eqNegGamma2 & a1NonZero)
	result := gtGamma2 | ltNegGamma2 | (eqNegGamma2 & a1NonZero)

	return uint(result & 1)
}

// UseHint uses hint to correct high bits
// This is a constant-time implementation to prevent timing side-channels.
func UseHint(a int32, hint int) int32 {
	var a0, a1 int32
	a1 = Decompose(&a0, a)

	// Compute all possible results
	result0 := a1              // when hint == 0
	resultPos := (a1 + 1) & 15 // when hint != 0 && a0 > 0
	resultNeg := (a1 - 1) & 15 // when hint != 0 && a0 <= 0

	// Constant-time conditions using arithmetic
	// hintIsZero: 1 if hint == 0, 0 otherwise
	hint32 := int32(hint)
	hintIsZero := int32(1 - ((uint32(hint32|(-hint32)) >> 31) & 1))

	// a0Positive: 1 if a0 > 0, 0 if a0 <= 0
	// When a0 > 0, -a0 < 0, so sign bit of -a0 is 1
	a0Positive := int32((uint32(-a0) >> 31) & 1)

	// Convert to masks (0 or -1 which is all 1s)
	hintNonZero := 1 - hintIsZero
	mask0 := -hintIsZero           // all 1s if hint == 0
	maskHintNZ := -hintNonZero     // all 1s if hint != 0
	maskA0Pos := -a0Positive       // all 1s if a0 > 0
	maskA0NotPos := ^maskA0Pos     // all 1s if a0 <= 0

	// Final condition masks
	maskPos := maskHintNZ & maskA0Pos    // all 1s if hint != 0 && a0 > 0
	maskNeg := maskHintNZ & maskA0NotPos // all 1s if hint != 0 && a0 <= 0

	// Select result using masks (exactly one mask is all-1s)
	return (result0 & mask0) | (resultPos & maskPos) | (resultNeg & maskNeg)
}
