package ml_dsa_87

import (
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestGetMLDSA87Address_Valid(t *testing.T) {
	wallet, err := NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	pk := wallet.GetPK()
	desc := wallet.GetDescriptor()

	addr, err := GetMLDSA87Address(pk, desc)
	if err != nil {
		t.Fatalf("GetMLDSA87Address failed: %v", err)
	}

	// Should match wallet's address
	walletAddr := wallet.GetAddress()
	if addr != walletAddr {
		t.Error("address mismatch")
	}
}

func TestGetMLDSA87Address_InvalidDescriptor(t *testing.T) {
	var pk PK
	invalidDesc := Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0}

	_, err := GetMLDSA87Address(pk, invalidDesc)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestGetMLDSA87Address_UnknownDescriptorType(t *testing.T) {
	var pk PK
	unknownDesc := Descriptor{99, 0, 0}

	_, err := GetMLDSA87Address(pk, unknownDesc)
	if err == nil {
		t.Error("expected error for unknown descriptor type")
	}
}
