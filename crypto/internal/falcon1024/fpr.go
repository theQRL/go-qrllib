package falcon1024

import (
	"math"
	"math/bits"
)

const (
	fprInverseOfQ    fpr = 1.0 / q
	sigmaMin1024     fpr = 1.2982803343442918539708792538826807
	inv2SqrSigma0    fpr = 0.150865048875372721532312163019
	invSqrt2         fpr = 0.707106781186547524400844362105
	invSqrt8         fpr = 0.353553390593273762200422181052
	log2             fpr = 0.693147180559945309417232121458176568
	invLog2          fpr = 1.44269504088896340735992468100189214
	twoTo52              = 4503599627370496.0
	twoTo31          fpr = 2147483648.0
	twoTo63          fpr = 9223372036854775808
	twoTo31Minus1    fpr = 2147483647
	negTwoTo31Minus1 fpr = -2147483647
	twoTo63Minus1    fpr = 9223372036854775807
	negTwoTo63Minus1 fpr = -9223372036854775807
)

// Falcon's fpr layer uses native float64, matching the reference FPNATIVE path.
type fpr float64

var fprP2Tab = [...]fpr{
	2.0,
	1.0,
	0.5,
	0.25,
	0.125,
	0.0625,
	0.03125,
	0.015625,
	0.0078125,
	0.00390625,
	0.001953125,
}

func fprRint(x fpr) int64 {
	v := float64(x)
	sx := int64(v - 1.0)
	tx := int64(v)
	rp := int64(v+twoTo52) - twoTo52
	rn := int64(v-twoTo52) + twoTo52

	m := sx >> 63
	rn &= m
	rp &= ^m

	ub := uint32(uint64(tx) >> 52)
	m = -int64(((((ub + 1) & 0xFFF) - 2) >> 31))
	rp &= m
	rn &= m
	tx &= ^m

	return tx | rn | rp
}

func fprTrunc(x fpr) int64 {
	return int64(math.Trunc(float64(x)))
}

var fprExpmP63Coefficients = [...]uint64{
	0x00000004741183A3,
	0x00000036548CFC06,
	0x0000024FDCBF140A,
	0x0000171D939DE045,
	0x0000D00CF58F6F84,
	0x000680681CF796E3,
	0x002D82D8305B0FEA,
	0x011111110E066FD0,
	0x0555555555070F00,
	0x155555555581FF00,
	0x400000000002B400,
	0x7FFFFFFFFFFF4800,
	0x8000000000000000,
}

func fprExpmP63(x, ccs fpr) uint64 {
	y := fprExpmP63Coefficients[0]
	z := uint64(fprTrunc(x*twoTo63)) << 1
	for _, ci := range fprExpmP63Coefficients[1:] {
		hi, _ := bits.Mul64(z, y)
		y = ci - hi
	}

	z = uint64(fprTrunc(ccs*twoTo63)) << 1
	hi, _ := bits.Mul64(z, y)
	return hi
}
