package falcon1024

import "testing"

// These vectors are derived from the Falcon reference implementation
// test_falcon.c ntru_f_1024, ntru_g_1024, ntru_F_1024, and ntru_G_1024
// arrays.
// Source: https://falcon-sign.info/impl/test_falcon.c.html
var ntruReferenceVectors = []struct {
	name string
	f    string
	g    string
	F    string
	G    string
}{
	{
		name: "Falcon-1024/test_falcon.c",
		f:    ntruSmallF1024Hex,
		g:    ntruSmallG1024Hex,
		F:    ntruF1024Hex,
		G:    ntruG1024Hex,
	},
}

func TestSolveNTRU(t *testing.T) {
	for _, tc := range ntruReferenceVectors {
		t.Run(tc.name, func(t *testing.T) {
			f := mustDecodeSmallPolynomialHex(t, tc.f)
			g := mustDecodeSmallPolynomialHex(t, tc.g)
			wantF := mustDecodeSmallPolynomialHex(t, tc.F)
			wantG := mustDecodeSmallPolynomialHex(t, tc.G)

			gotF, gotG, ok := solveNTRU(f, g)
			if !ok {
				t.Fatal("solveNTRU rejected reference f/g pair")
			}
			if gotF != wantF {
				t.Fatal("solveNTRU returned unexpected F")
			}
			if gotG != wantG {
				t.Fatal("solveNTRU returned unexpected G")
			}
			scratch := make([]uint32, 6*n)
			if !checkNTRUEquation(f, g, gotF, gotG, scratch) {
				t.Fatal("solveNTRU returned polynomials that fail the NTRU equation")
			}

			testCases := []struct {
				name   string
				mutate func(f, g, F, G *smallPolynomial)
			}{
				{
					name: "corrupt f",
					mutate: func(f, g, F, G *smallPolynomial) {
						f[0]++
					},
				},
				{
					name: "corrupt g",
					mutate: func(f, g, F, G *smallPolynomial) {
						g[0]++
					},
				},
				{
					name: "corrupt F",
					mutate: func(f, g, F, G *smallPolynomial) {
						F[0]++
					},
				},
				{
					name: "corrupt G",
					mutate: func(f, g, F, G *smallPolynomial) {
						G[0]++
					},
				},
			}

			for _, corrupt := range testCases {
				t.Run(corrupt.name, func(t *testing.T) {
					corruptF, corruptG, corruptBigF, corruptBigG := f, g, gotF, gotG
					corrupt.mutate(&corruptF, &corruptG, &corruptBigF, &corruptBigG)

					if checkNTRUEquation(corruptF, corruptG, corruptBigF, corruptBigG, scratch) {
						t.Fatal("invalid NTRU equation accepted")
					}
				})
			}
		})
	}
}

const ntruSmallF1024Hex = "0302fcfd00fb04fdff01fe020300ff0000000000fefefd03fcffff0002fc00f7fd0503ff01fb01fffa00ffff05ff04ff" +
	"fe02fdff01fd0101fbfefe000005f8ffff0000020004fd0403fdfe06fefe00030000fffe0001feff0700fc01fffe02ff" +
	"fb05fffcfeff02ff02fffd03010201fe0303010402000300fd0007fb04fdff01fa00ff00fb01fe02fffffe0304ff00ff" +
	"000103fe0604010101ff0301fd0000ff02fd02fc01ffff01fefffefaf8fd03fe0003ff010005fe00fe010201fefbfdfe" +
	"02ff0101000101f70001fe0205000304fffbfefe000200fe0300fffefdfafe01f9fcfe01fffffdfd02fd020102fcfe05" +
	"ff01fe03fb0501010102fc0102fdfbfc02fd03fcfc050200fc03fdfd0300fefdfe00fd0508fe0202ff0affff01fc03ff" +
	"0301ff03fd050004fd04fb03fdfffc03010002fffcff04fbfa030504fe00050101ff01fd06fdfd01fa03fd03010000fe" +
	"fcff0100ffff04fd0202fb0403fdfeff0101fd04060004fdff01060203fefdfe03fb030000fefffd020500040203fefc" +
	"0301fbfe02fffffc05000002fefc030401050000010005feff01fdffffff0202fd0001fd0200fe03020003ff0002fc00" +
	"fd0303fffffe0302fffb0102030303fe0806fe0104fd0004010100000100ff0500fb04030502000003fe03fc02fdff03" +
	"fe01ff05010005ff00fffefffcfffe02fafe0500fbfe04fffdfdfe02fffe0000fc02fb01fcff00fffe05fc04fffe0603" +
	"0603fd010001060301fdfffeff0000fffffffefeffff0201fcfcfbfc0301010104fe000102030005fb03ff0304fdfdfc" +
	"f6fffe02fefd010200010002fd02010100fe0100fdff00fdfffcfb0303fffbff00ff02fd03010000ff020006fc05ff01" +
	"03feff01000102f902040201fdfa02fe0000fe020200fe010001000102fd02030101020700010000ff0201ffff000003" +
	"02010100fb050003030503fd000301040006ff0304ff050504fcfe0203f6fd01010402fd0402fefcfefc01000002fd01" +
	"fffc00ff0401fd00ff010302030102fdfd000204000006fefffefe04fffffffefcfa020101fafefe0100fdfdfd0303ff" +
	"01fdffff01faff02fffc0000fc020300fcff000200ff010303fffe0500ff010002fbff0001fbfcfc000104fafd010002" +
	"fbff0001fb01010001ff030403ffff010100fe00fffc000201020402fffc0202ff00ff0000fe0300fffc00fefefe0403" +
	"05040104fe0300fcfefd020200fa02f9ff0301fe04fe000102040001010000000104f6fefdfc07fafefd0404fcfe0602" +
	"fcff010103000100fefc010401fb010106fd0001fefc00fffd02060501ff03010101ff04fbfdfffefd0002020202fa07" +
	"07ff03fffefe05000101fd03fa0201030301ff000201fbfffc01fe05fdfe00030001ffff010003ff03ff010200fc02ff" +
	"fdfe00fdfe000100fbfe040107fb0101"

const ntruSmallG1024Hex = "03fff9ff04fe03fffdfdfb03ffff02fdfb000001fd0303fefe00fc0201ff03fb0500fffdfffe050304fefe00fc000303" +
	"000103fffefdfffe030100fe00fe00000103fefd03fdfffefffdfd0101080104fefffbfc0305000007040101fcfe0404" +
	"fdfc0503020001fa02fffdffff0102050003010300fcfdfdffff01010200fe00030303fc01fefc030305fcfbffff03fe" +
	"fcfffb01ff0002ff0101fdfefffcfcffff00ffff03fefe03fa02020002fd0003fefe02ff0104fe00000000040002fcff" +
	"05fefa02010301030003010200fcfefd040200f8fe0205020001fe00ff0003030100000202fffd03fe0301fe050104fe" +
	"03fefdfeff02fbfcfefdfafdfefdfdfdff01ff04fffbfd0003060002ff05ff00020706ff02fe040600010404000501fd" +
	"04010301fffefcff000003faff0204fdff00fd0201020401fffefffdfefaff0102fe000000fd01fe050101fbfc0000fe" +
	"0003040502fc00fc03fe00fdfcff0400fdfe01ff02fd010000fd000502fefc020000fd00ffffffff0307fffefb020501" +
	"0402fd00fbfc010001fd0402fbff02fc0001000100ff00fefc04fe00010100020000fcfbfd00fcfb020100fd04ff03fc" +
	"fbff04ff0001fc05ff0501ff00fdfd03fbfd01ff0004fe0201fefdfffefdfd01fe08fe0003fe030303fe040002030103" +
	"00ffff030101ff0501ff00fd01fc01fffcff06fc06fe00fe0004ff01060705ff030300ff01fafffc04ff030403fdff02" +
	"00fd02fffe01fd00fffbff04fefa0100060201fd0201ffff04fcfefe050105fefa0100010404fdfffc0100ff00fd04fe" +
	"04030104060201ff01fbfefd0200fffffb03fd020001fcff07ff02fe030000fc04020401010203fe03010000fc000201" +
	"01ff0404fcfd05ffff01030301f700fa050000fe030002fe03fa0101ff0301020003ff00fefd0701fdfffe03fd010403" +
	"fdfdfcfafbff06fb0300ff0004fbfe01fe030602fcfbfafd02fdfcfe01010001fe02feff010202fcfdff00ff02fc01ff" +
	"00fd0102fb0400fd030503fcfe020101fcfe01ff0000030001000101fffc0303010001ff01fe030305ff03fdff01feff" +
	"000101fe0003fffdfe010102f9fe0105000000fcfc0001ff040000030103fc0704fc000504fdff0000fdfc0300ff02fe" +
	"000600fe03010603fe0201fffefcfdfefe000200fcfdfffd0100fa0200040401fefffd03fcfcfe01fbff0201fe00fe02" +
	"ff0003fe01fafeff00fefe010004ff080300010501fd00020101ff04000406fe0000fd05fafd0502fe01ff0605fdfcfd" +
	"0203fb0202fefc06fc0200fc0502ff0100fe020200fd00f900ff01030302fbfe0005fc010202ff040502020200000201" +
	"0302fc04feff02fe0003feff060103000400feff0100fd030203fffdfd03fe03fe00ff03fdfe0104fc0205f90100fb01" +
	"02ff03fe03fffe02000000fdfe040701"

const ntruF1024Hex = "24f358010dbe09fef41e17eef108fe05130d0eeaea1dee08d31cfcd21e28e6fdfffeca0422dae037e7e804ddf7081718" +
	"23111d0729fdf3271918de12c916c3e9120301fd20ecfec11315f303f9ef05d8e30806d51b1f03e4d24c1ff0fc3b26fa" +
	"fafd22edf6d9ecf1fdf5d709a615e618feeedc12fefceebd0e07eaeae42ac7200719071ed3f7fe081cf213edd125de2d" +
	"e0f8dd34e123f2f624bff0ebfb0415c3160dc9fbea0ef6dd08fb1be1e00300f4e71bfbea03fa0015fb2d24d610fef7f0" +
	"d4002c03f7cde00bfcf9210ff70dfa0f0fe20a0ef81b14fdf6160e07f11fefecf204fe1a1bf920311bd8fcdd0b031123" +
	"0bf223fa070ada0c2bd62cecfd21230e010af7f5ec1f1efefefa11f6f6f631e9eefdff0c13d4ebf3ed1904e9ec06f1fe" +
	"1513fafc2be81f16f137fbfdf8faf2170020e430372b0211fc383a2003fa2b0bfdf7e6effa171d1ee1051b0b091e2042" +
	"0a21d8e61326f5040cc71ef21dfb0cf7ef1428ffedfbf0dae7e8ff15ebd1fff8cb2707dced0400021006140808f9d6ff" +
	"04eff9f6e800e3fff1fe0309ebfeecf1bcd615d8e9fdfbeefeefec110a10ca1b05eb1504cae7023d27e72ffb140c08eb" +
	"f410f317fcd1f4f10514fcea25d5f2e2eb0fe801f319fdf8fc09f3fff22713f8f52d20e7124d0d0e1526d60f1cef06fe" +
	"11dc15df0d0cfa24fb090701ef1ef0fdd9f4faebe403f3ef1d17f41123eef6011adf4539f4f12b121be1e325fb32c8ea" +
	"c7ff15f1e5d0ece4fce1ec090a0f0cf9da170009030f1c1ff8041303f91ef21bf9e7ecf6ec1bfae2f81bfbe934d4df30" +
	"ec0aeb07deff1a28f5042ee2f3f71b0df30dfc0b22e0fd3318d3270e0fc90ce4ebf203f0e7f32312f9e533f01de40501" +
	"e003e7f9f1210825ec1a190c0d0f08040b08e1ff080de116f9fd070c0af4c2cff4fbfdcbe2f9c8142d06d2e0f1f309ee" +
	"0bfb0cfa0ac2080bee1b10fbfa04e4fae2c60bf8d8cd141b110cf7e4f5f8eaeef0dc0e11d4022a10f7e1f0fdf229ea10" +
	"ff200c04dc12d70d1fdd0e08f613f7fcdcf1c20010e4ca0414f70e12e6e2130a0afbf60717f9e1fe13c1f200eefdebdf" +
	"0bccebfcd0ddfafcf2f3ff0ef0eb09dbe1f004ef02fcef02cdf0f0033b0df0e2110923f5e120f9e61c07131cefcfe2f7" +
	"1713fe01fd09300bca09ea190816cc25f2f6e21434030a113821fd29352904f9e708d31df5051d3cf1f80ef9dff206f4" +
	"fefef6f4f0eb0205f235293d0c1f0416f024fcd626e3f614142342100ccefb01f020212efd0b0bed1c05260fddfa01fa" +
	"ef02e4192a08fef50edfd61715e13ff80f1af00dfd27f03af2f2eae2e6cd04f7eefbc8d0c40acce4faf4dd1feae1f308" +
	"f2f817ecd3f41e080709f4f3fee312ff1eefe6d73abefa08b2191d00d8e51028f1e412ca10f401fc11eb0c1ef92df8e4" +
	"08d7ff2a03fad1162cb2d3290ce2e90d"

const ntruG1024Hex = "38fce40d041af2f6ebe015eb003b1afaaff9d6ff081425df2401fa0effb70f120722d30713e20808c8f30714ec0e040b" +
	"dc1513f0ef0ad3fcf412f7171401e5f9010121e5e93823fb102bff0bee053b0ed90bdec506ee2be716f909e4f7d82f00" +
	"f4eaf4d4eff4f6fb04ecf619260200ef0ef0060907e30b300e0a001804fb381401233e07e1242418eddf1309f3f00201" +
	"e303fd2a081bed33100e1cff1803012ff3d5091103151aedfa04dc071a1328d41bec09ff13ff00cd05fbd30b1aff0127" +
	"fa0ef2dee3faf1e918f910cd37e2020d01db21e30b0ed42e28d33bfa0312d21411fe001bec01f9f0e300feed13f610f1" +
	"fe02f6041bfc02000f2313191520f71ae4e9fe07e84bfd06152df8f415f4e3f922f3ea1c201412ea0211f42525df051c" +
	"1b37e2f70a170cf7e61e050218db09e7ce2103ebdaed2c2909012206e6d4e60ffdebe828d51c02e2f3f8d8011ffef0f0" +
	"e72101e9cdd8dbf4da4e0fe120291a1ae7c40fd51bca0019f9e50fee1414b4fd23d9141c150a06d7e3e1c9d700f804ef" +
	"15ebf40b04ef061a0b09f3d71df9fc150c02ffe903fb011ef60928c1e533e304fff91e1eeb20efcd1c2216fbfb2a07ff" +
	"f0f1e90af7fd011af41005120dff1c08ccd60cfde41efd0bf2fd22b5f306d90e48f012efdcfd05f7dad60407034a0209" +
	"e9e0d5c5f1fc1f0cf0e823f900f8fdf80601c70df8161f28f02322e0c4eb08fff3d90e11f921ddfaee001dfbf728edd3" +
	"18d7f920131c1cef0a12061d01ff111c12eaf0143308021210f728f8ece10bfb22e7d8d0f7dc04110f08ee1be8e7f316" +
	"15ebe7fee00714f8e6e915fd22f100efeb38dafe12d4f21ffee803ee1210e8ddd005dc1c0f0d20f20edaf7c2f50606e6" +
	"d248c1dd10fced2dece4011a24dd1ef327e310e20e0504f5fa16f705f70ee5e21717fef91e000620d5ef0b0ae3f16f0f" +
	"0a0d0710fe03fdfa26f6f505defe0ee0eb04fb00f81bcef91708efc1a9ff2205fff503fa21f7d3de02e92e2bf50cebf9" +
	"11d0d6fd0702180847060009f0061114fe06d4f32c171b0d25f63a08f4fcf10e1bd112bcfaf7f00207f1d12201dae7ed" +
	"01f60e0709ecffeb04f312e6f61f33c50ffdedbaef2ef218200f22e9dcf0f9f6022407f4cde7f817eeef07d009e62ce7" +
	"2c201cf60b0cef041006ed2016e110081ffc11eb01382415e1fc00d2e6d43dc302eb2d0ff2ddf305daf6edf9f9df21f5" +
	"f41d11e5d2d0e7f30619f4f4e3c6fee305f5f1ed20c60eddfdecf0e0e8d3eefd00ffd5f70ce3fe01f7e605fe09ef201b" +
	"fde502f9f304062e261ce5fdedda400d09f0232e08b00ff0ede6f63008f5f8fef0ea3209f2cc270b310205f50dfc0a0b" +
	"e9e9f60e1f2a1200312213e70fd71e08121dfa0fef051e02ed0c2be01fd9081510f4f8182508f3ca00d4f4e61f05ea33" +
	"0bf9ea1b110c14f809f530eb091802fc"
