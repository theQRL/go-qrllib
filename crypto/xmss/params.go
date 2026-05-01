package xmss

import (
	"math"
)

const (
	WOTSParamK = uint32(2)
	WOTSParamW = uint32(16)
	WOTSParamN = uint32(32)
)

type WOTSParams struct {
	len1    uint32
	len2    uint32
	len     uint32
	n       uint32
	w       uint32
	logW    uint32
	keySize uint32
}

type XMSSParams struct {
	wotsParams *WOTSParams
	n          uint32
	h          uint32
	k          uint32
}

// NewWOTSParams constructs a WOTS+ parameter set from `(n, w)`. The
// only `w` value supported by RFC 8391 / the QRL XMSS implementation is
// `w = 16`; the additional logW values (2, 8) covered by the panic
// guard below correspond to RFC 8391's other published WOTS+ choices
// (`w = 4`, `w = 256`) and are accepted here defensively in case a
// future caller needs them.
//
// Panic policy (see SECURITY.md "Panic policy"). Every supported
// upstream call site reaches this constructor with `w = WOTSParamW`
// (16) — `xmss.HeightToXMSSParams`, `XMSSFastGenKeyPair`'s parameter
// validator (`validateXMSSFastParams`), and the wallet constructors
// all use the package-level `WOTSParamW` constant. The panic below is
// therefore an invariant tripwire that a future regression which lets
// an unsupported `w` reach this function fails loudly rather than
// producing a `WOTSParams` whose buffer arithmetic silently corrupts
// downstream key material. Direct external callers passing an
// unsupported `w` will likewise hit the tripwire.
func NewWOTSParams(n, w uint32) *WOTSParams {
	logW := uint32(math.Log2(float64(w)))
	if logW != 2 && logW != 4 && logW != 8 {
		// Invariant tripwire — see godoc above and SECURITY.md
		// "Panic policy". All supported callers pass w = WOTSParamW (16);
		// the buffer arithmetic below assumes integer logW, so any other
		// w value would produce a malformed WOTSParams.
		panic("xmss: NewWOTSParams reached with unsupported w; logW must be 2, 4, or 8 (i.e. w ∈ {4, 16, 256})")
	}
	len1 := (8*n + logW - 1) / logW // ceiling division
	len2 := uint32(math.Floor(math.Log2(float64(len1*(w-1)))/float64(logW)) + 1)
	totalLen := len1 + len2
	keySize := totalLen * n

	return &WOTSParams{
		len1:    len1,
		len2:    len2,
		len:     totalLen,
		n:       n,
		w:       w,
		logW:    logW,
		keySize: keySize,
	}
}

// NewXMSSParams constructs an XMSS parameter set from `(n, h, w, k)`.
// The supported QRL tuple is `(WOTSParamN=32, h, WOTSParamW=16,
// WOTSParamK=2)`; passing other values inherits the panic-tripwire
// behaviour of [NewWOTSParams] for unsupported `w` (see its godoc and
// SECURITY.md "Panic policy"). The `XMSSFastGenKeyPair` boundary
// validator (`validateXMSSFastParams`) ensures supported callers never
// reach the tripwire.
func NewXMSSParams(n, h, w, k uint32) *XMSSParams {
	return &XMSSParams{
		NewWOTSParams(n, w),
		n,
		h,
		k,
	}
}
