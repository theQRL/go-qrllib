package misc

//var (
//	extendedSeed = map[string]string{
//		"0105005ece2c787198e40d843e9696d0cf67373a0c7e110c475651928ae49e6764368ecce53914f8dbc62fa2571d3bf93aeff6": "absorb filled golf thesis koran body thrive streak dome heroic spain warsaw darken peak lewis ballet enter hardly mutual quest panama karl dale twice tier mucky which rust cool cat brew saxon depth zebra",
//		"010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000": "absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback",
//		"0104005969b326db865bb694a878e95b627e4a79d844891a2e0790d8011ea59ee47a119e1bc0a734593911d35515eeb2c46cc6": "absorb drank fusion orange chalky ripple gender hernia pope mole gave cheeky exile pack edit mummy coke laden strap barn plant unkind last bond bowl are crush native barley curlew bestow truly shady slump",
//		"020600f429397626f9130f959cda184fa240b263a3699d481ce91141b718c733b53a8ba1a1f5a70972aa09cf5b0d100e27da5c": "action grape visa native kansas infant battle who owe pencil fifth cape recent demure heyday stamp break mrs due invade shrill desk deny roll peril game anyway clan appeal walker atlas abrupt cheek play",
//		"0006007a0946f171a8b4ca0d44d8d78136286bb1d408923c99f8e58f5a4013852675a76930e00b82e9fc666e1dd30203a96b53": "aback grape laser needle velvet booze renal pear effect mist lofty grudge horror brick angle canopy omega modify moon pilot beard flew june keep cotton above lovely pastel havoc test spouse burial pour repent",
//	}
//)
//
//func TestBinToMnemonic(t *testing.T) {
//	for eSeedStr, expectedMnemonic := range extendedSeed {
//		eSeedBin, err := hex.DecodeString(eSeedStr)
//		if err != nil {
//			t.Errorf("Error: %s", err)
//		}
//		var eSeed [51]uint8
//		copy(eSeed[:], eSeedBin)
//		mnemonic := ExtendedSeedBinToMnemonic(eSeed)
//		if mnemonic != expectedMnemonic {
//			t.Errorf("Mnemonic mismatch\nExpected: %s\nFound: %s", expectedMnemonic, mnemonic)
//		}
//	}
//
//}
//
//func TestMnemonicToBin(t *testing.T) {
//	for expectedESeed, mnemonic := range extendedSeed {
//		eSeed := MnemonicToExtendedSeedBin(mnemonic)
//		eSeedStr := hex.EncodeToString(eSeed[:])
//		if expectedESeed != eSeedStr {
//			t.Errorf("ExtendedSeed mismatch\nExpected: %s\nFound: %s", expectedESeed, eSeedStr)
//		}
//	}
//}
