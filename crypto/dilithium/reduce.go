package dilithium

func montgomeryReduce(a int64) int32 {
	var t int32
	t = int32(int64(int32(a)) * QInv)
	t = int32((a - int64(t)*Q) >> 32)

	return t
}

func reduce32(a int32) int32 {
	var t int32

	t = (a + (1 << 22)) >> 23
	t = a - t*Q

	return t
}

func cAddQ(a int32) int32 {
	a += (a >> 31) & Q
	return a
}
