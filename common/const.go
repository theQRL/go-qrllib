package common

type SignatureType uint

const (
	DescriptorSize = 3

	AddressSize = 20
)

const (
	XMSSSig SignatureType = iota + 1
	DilithiumSig
)

type AddrFormatType uint

const (
	SHA256_2X AddrFormatType = iota
)
