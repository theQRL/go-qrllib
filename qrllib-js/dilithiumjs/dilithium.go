package dilithiumjs

import (
	"encoding/hex"
	"strings"

	"github.com/gopherjs/gopherjs/js"
	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/dilithium"
)

type DilithiumJS struct {
	*js.Object
	d    *dilithium.Dilithium
	pk   string `js:"pk"`
	sk   string `js:"sk"`
	seed string `js:"seed"`
}

func newDilithiumJS(d *dilithium.Dilithium) *js.Object {
	binPK := d.GetPK()
	binSK := d.GetSK()
	binSeed := d.GetSeed()

	djs := DilithiumJS{Object: js.Global.Get("Object").New()}
	djs.d = d
	djs.pk = "0x" + hex.EncodeToString(binPK[:])
	djs.sk = "0x" + hex.EncodeToString(binSK[:])
	djs.seed = "0x" + hex.EncodeToString(binSeed[:])

	djs.Object.Set("GetPK", djs.GetPK)
	djs.Object.Set("GetSK", djs.GetSK)
	djs.Object.Set("GetSeed", djs.GetSeed)
	djs.Object.Set("GetMnemonic", djs.d.GetMnemonic)
	djs.Object.Set("GetAddress", djs.GetAddress)
	djs.Object.Set("Sign", djs.Sign)

	return djs.Object
}

func NewDilithiumJS() *js.Object {
	d, _ := dilithium.New()
	return newDilithiumJS(d)
}

func NewDilithiumJSFromSeed(seed string) *js.Object {
	seed = clearPrefix0x(seed)
	binSeed, err := hex.DecodeString(seed)
	if err != nil {
		return nil
	}
	var sizedBinSeed [common.SeedSize]uint8
	copy(sizedBinSeed[:], binSeed)
	d, _ := dilithium.NewDilithiumFromSeed(sizedBinSeed)

	return newDilithiumJS(d)
}

func (d *DilithiumJS) GetPK() string {
	return d.pk
}

func (d *DilithiumJS) GetSK() string {
	return d.sk
}

func (d *DilithiumJS) GetSeed() string {
	return d.seed
}

func (d *DilithiumJS) GetAddress() string {
	binAddr := d.d.GetAddress()
	return "0x" + hex.EncodeToString(binAddr[:])
}

func (d *DilithiumJS) Sign(message []uint8) string {
	binSignature, _ := d.d.Sign(message)
	return "0x" + hex.EncodeToString(binSignature[:])
}

func DilithiumVerify(message []uint8, signature string, pk string) bool {
	signature = clearPrefix0x(signature)
	pk = clearPrefix0x(pk)

	binSignature, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	binPK, err := hex.DecodeString(pk)
	if err != nil {
		return false
	}

	var sizedBinPK [dilithium.CryptoPublicKeyBytes]uint8
	copy(sizedBinPK[:], binPK)

	var sizedBinSignature [dilithium.CryptoBytes]uint8
	copy(sizedBinSignature[:], binSignature)

	return dilithium.Verify(message, sizedBinSignature, &sizedBinPK)
}

func GetDilithiumAddressFromPK(pk string) string {
	pk = clearPrefix0x(pk)
	binPK, err := hex.DecodeString(pk)
	if err != nil {
		return ""
	}

	var sizedBinPK [dilithium.CryptoPublicKeyBytes]uint8
	copy(sizedBinPK[:], binPK)

	binAddress := dilithium.GetDilithiumAddressFromPK(sizedBinPK)

	return "0x" + hex.EncodeToString(binAddress[:])
}

func IsValidDilithiumAddress(address string) bool {
	address = clearPrefix0x(address)
	binAddr, err := hex.DecodeString(address)
	if err != nil {
		return false
	}

	var sizedBinAddr [common.AddressSize]uint8
	copy(sizedBinAddr[:], binAddr)

	return dilithium.IsValidDilithiumAddress(sizedBinAddr)
}

func clearPrefix0x(data string) string {
	if strings.HasPrefix(data, "0x") {
		return data[2:]
	}
	return data
}
