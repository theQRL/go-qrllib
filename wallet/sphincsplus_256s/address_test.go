package sphincsplus_256s

import (
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestGetSphincsPlus256sAddress_Valid(t *testing.T) {
	wallet, err := NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	pk := wallet.GetPK()
	desc := wallet.GetDescriptor()

	addr, err := GetSphincsPlus256sAddress(pk, desc)
	if err != nil {
		t.Fatalf("GetSphincsPlus256sAddress failed: %v", err)
	}

	// Should match wallet's address
	walletAddr := wallet.GetAddress()
	if addr != walletAddr {
		t.Error("address mismatch")
	}
}

func TestGetSphincsPlus256sAddress_InvalidDescriptor(t *testing.T) {
	var pk PK
	invalidDesc := Descriptor{byte(wallettype.ML_DSA_87), 0, 0}

	_, err := GetSphincsPlus256sAddress(pk, invalidDesc)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestGetSphincsPlus256sAddress_UnknownDescriptorType(t *testing.T) {
	var pk PK
	unknownDesc := Descriptor{99, 0, 0}

	_, err := GetSphincsPlus256sAddress(pk, unknownDesc)
	if err == nil {
		t.Error("expected error for unknown descriptor type")
	}
}
