package xmss

import "fmt"

type Height uint8

func ToHeight(val uint8) Height {
	h := Height(val)
	if !h.IsValid() {
		panic(fmt.Errorf("invalid XMSS height: %d", val))
	}
	return h
}

func UInt32ToHeight(val uint32) Height {
	// Need a check here before we convert it to uint8
	if val > MaxHeight {
		panic(fmt.Errorf("invalid XMSS height: %d", val))
	}
	return ToHeight(uint8(val))
}

func HeightFromDescriptorByte(val uint8) Height {
	return ToHeight((val & 0x0f) << 1)
}

func (h Height) ToDescriptorByte() byte {
	if !h.IsValid() {
		panic(fmt.Errorf("invalid XMSS height: %d", h))
	}
	return uint8((h >> 1) & 0x0f)
}

func (h Height) ToUInt32() uint32 {
	return uint32(h)
}

func (h Height) IsValid() bool {
	if h > MaxHeight || h < 2 || h%2 != 0 {
		return false
	}
	return true
}

func GetHeightFromSigSize(sigSize, wotsParamW uint32) Height {
	wotsParam := NewWOTSParams(WOTSParamN, wotsParamW)
	signatureBaseSize := calculateSignatureBaseSize(wotsParam.keySize)
	if sigSize < signatureBaseSize {
		panic("Invalid signature size")
	}

	if (sigSize-4)%32 != 0 {
		panic("Invalid signature size")
	}

	return UInt32ToHeight((sigSize - signatureBaseSize) / 32)
}
