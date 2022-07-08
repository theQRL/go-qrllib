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

func NewWOTSParams(n, w uint32) *WOTSParams {
	logW := uint32(math.Log2(float64(w)))
	len1 := uint32(math.Ceil(float64((8 * n) / logW)))
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

func NewXMSSParams(n, h, w, k uint32) *XMSSParams {
	return &XMSSParams{
		NewWOTSParams(n, w),
		n,
		h,
		k,
	}
}
