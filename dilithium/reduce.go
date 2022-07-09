package dilithium

func montgomeryReduce(a uint64) uint32 {
	qinv := uint64(QInv)
	t := a * qinv
	t &= (uint64(1) << 32) - 1
	t *= uint64(Q)
	t = a + t
	return uint32(t >> 32)
}

func reduce32(a uint32) uint32 {
	t := a & 0x7FFFFF
	a >>= 23
	t += ((a << 13) - a)
	return t
}

func freeze(a uint32) uint32 {
	a = reduce32(a)
	a -= Q
	a += uint32(int32(a)>>31) & Q
	return a
}
