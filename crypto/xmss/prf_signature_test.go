// Compile-time signature pin for the prf function (TOB-QRLLIB-5).
//
// The prf function in hash.go takes its in parameter as *[32]uint8
// rather than []uint8 so the 32-byte input length is enforced at the
// type system level: every call site already passes a stack-allocated
// 32-byte array, and a future drift back to []uint8 would re-introduce
// the latent runtime panic on short slices that the audit flagged.
//
// The package-level assignment below pins the signature at compile
// time. If anyone widens or narrows the signature, this file fails to
// compile and the package's test build fails with a clear type-mismatch
// error pointing at this line. Do not remove or relax without an
// accompanying audit-finding remediation.

package xmss

// Compile-time assertion: prf must keep this exact signature.
// See crypto/xmss/hash.go and TOB-QRLLIB-5.
var _ func(HashFunction, []uint8, *[32]uint8, []uint8, uint32) = prf
