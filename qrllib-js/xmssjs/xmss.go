package xmssjs

import (
	"encoding/hex"
	"fmt"
	"github.com/gopherjs/gopherjs/js"
	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/xmss"
)

type XMSSJS struct {
	*js.Object
	x    *xmss.XMSS
	pk   string `js:"pk"`
	sk   string `js:"sk"`
	seed string `js:"seed"`
}

func newXMSSJS(x *xmss.XMSS) *js.Object {
	binPK := x.GetPK()
	binSK := x.GetSK()
	binSeed := x.GetSeed()

	xmssjs := XMSSJS{Object: js.Global.Get("Object").New()}
	xmssjs.x = x
	xmssjs.pk = hex.EncodeToString(binPK[:])
	xmssjs.sk = hex.EncodeToString(binSK[:])
	xmssjs.seed = hex.EncodeToString(binSeed[:])

	xmssjs.Object.Set("GetPK", xmssjs.GetPK)
	xmssjs.Object.Set("GetSK", xmssjs.GetSK)
	xmssjs.Object.Set("GetSeed", xmssjs.GetSeed)
	xmssjs.Object.Set("GetMnemonic", xmssjs.x.GetMnemonic)
	xmssjs.Object.Set("GetAddress", xmssjs.GetAddress)
	xmssjs.Object.Set("Sign", xmssjs.Sign)

	return xmssjs.Object
}

func NewXMSSJSFromHeight(height uint8, hashFunction xmss.HashFunction) *js.Object {
	x := xmss.NewXMSSFromHeight(height, hashFunction)
	return newXMSSJS(x)
}

func NewXMSSJSFromSeed(seed string, height uint8, hashFunction xmss.HashFunction, addrFormatType common.AddrFormatType) *js.Object {
	binSeed, err := hex.DecodeString(seed)
	if err != nil {

	}
	var sizedBinSeed [common.SeedSize]uint8
	copy(sizedBinSeed[:], binSeed)

	x := xmss.NewXMSSFromSeed(sizedBinSeed, height, hashFunction, addrFormatType)

	return newXMSSJS(x)
}

func (x *XMSSJS) GetPK() string {
	return x.pk
}

func (x *XMSSJS) GetSK() string {
	return x.sk
}

func (x *XMSSJS) GetSeed() string {
	return x.seed
}

func (x *XMSSJS) GetAddress() string {
	binAddr := x.x.GetAddress()
	return hex.EncodeToString(binAddr[:])
}

func (x *XMSSJS) Sign(message string) string {
	binSignature, err := x.x.Sign([]uint8(message))
	if err != nil {
		panic(fmt.Errorf("signing failed %v", err.Error()))
	}
	return hex.EncodeToString(binSignature[:])
}

func XMSSVerify(message string, signature string, pk string) bool {
	binMessage := []uint8(message)
	binSignature, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	binPK, err := hex.DecodeString(pk)
	if err != nil {
		return false
	}

	var sizedBinPK [xmss.ExtendedPKSize]uint8
	copy(sizedBinPK[:], binPK)

	return xmss.Verify(binMessage, binSignature, sizedBinPK)
}

func GetXMSSAddressFromPK(pk string) string {
	binPK, err := hex.DecodeString(pk)
	if err != nil {
		return ""
	}

	var sizedBinPK [xmss.ExtendedPKSize]uint8
	copy(sizedBinPK[:], binPK)

	binAddress := xmss.GetXMSSAddressFromPK(sizedBinPK)

	return hex.EncodeToString(binAddress[:])
}

func IsValidXMSSAddress(address string) bool {
	binAddr, err := hex.DecodeString(address)
	if err != nil {
		return false
	}

	var sizedBinAddr [common.AddressSize]uint8
	copy(sizedBinAddr[:], binAddr)

	return xmss.IsValidXMSSAddress(sizedBinAddr)
}
