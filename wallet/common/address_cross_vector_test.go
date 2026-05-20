package common

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
)

func TestAddressDerivationCrossImplementationVector(t *testing.T) {
	descBytes := [descriptor.DescriptorSize]uint8{1, 0, 0}
	desc := descriptor.New(descBytes)
	pk := bytes.Repeat([]byte{0x42}, MLDSA87PKSize)

	addr, err := GetAddress(pk, desc)
	if err != nil {
		t.Fatalf("GetAddress failed: %v", err)
	}

	got := "Q" + hex.EncodeToString(addr[:])
	const want = "Qf9e32f504239505ae25c8dd30a3837b8433602ce6ef5dd828806475878fea626757016824d8f08033f453ffeae85c0290b1ee7b55324884e12947d0086e6a040"
	if got != want {
		t.Fatalf("address mismatch\n got: %s\nwant: %s", got, want)
	}
}
