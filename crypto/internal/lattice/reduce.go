package lattice

// MontgomeryReduce computes a * R^-1 mod Q where R = 2^32
func MontgomeryReduce(a int64) int32 {
	t := int32(int64(int32(a)) * QInv)
	t = int32((a - int64(t)*Q) >> 32)
	return t
}

// Reduce32 reduces a mod Q
func Reduce32(a int32) int32 {
	t := (a + (1 << 22)) >> 23
	t = a - t*Q
	return t
}

// CAddQ conditionally adds Q to a
func CAddQ(a int32) int32 {
	a += (a >> 31) & Q
	return a
}
