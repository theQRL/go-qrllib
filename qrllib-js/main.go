package main

//go:generate gopherjs build --minify

import (
	"github.com/gopherjs/gopherjs/js"
	"github.com/theQRL/go-qrllib/qrllib-js/dilithiumjs"
)

func main() {
	js.Global.Set("dilithium", map[string]interface{}{
		"New":              dilithiumjs.NewDilithiumJS,
		"NewFromSeed":      dilithiumjs.NewDilithiumJSFromSeed,
		"Verify":           dilithiumjs.DilithiumVerify,
		"GetAddressFromPK": dilithiumjs.GetDilithiumAddressFromPK,
		"IsValidAddress":   dilithiumjs.IsValidDilithiumAddress,
	})

	//js.Global.Set("xmss", map[string]interface{}{
	//"NewFromHeight": xmssjs.NewXMSSJSFromHeight,
	//"NewFromSeed":      xmssjs.NewXMSSJSFromSeed,
	//"Verify":           xmssjs.XMSSVerify,
	//"GetAddressFromPK": xmssjs.GetXMSSAddressFromPK,
	//"IsValidAddress":   xmssjs.IsValidXMSSAddress,

	//"hashFunction": map[string]interface{}{
	//	"SHA2_256":  xmss.SHA2_256,
	//	"SHAKE_128": xmss.SHAKE_128,
	//	"SHAKE_256": xmss.SHAKE_256,
	//},
	//
	//"addressFormatType": map[string]interface{}{
	//	"SHA256_2X": common.SHA256_2X,
	//},
	//})

}
