package wallet

import (
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/sphincsplus_256s"
)

func TestValidatePKAndDescriptor_MLDSA87(t *testing.T) {
	wallet, err := ml_dsa_87.NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()

	err = validatePKAndDescriptor(pk[:], desc)
	if err != nil {
		t.Errorf("validatePKAndDescriptor failed for valid ML-DSA-87: %v", err)
	}
}

func TestValidatePKAndDescriptor_SPHINCS(t *testing.T) {
	wallet, err := sphincsplus_256s.NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()

	err = validatePKAndDescriptor(pk[:], desc)
	if err != nil {
		t.Errorf("validatePKAndDescriptor failed for valid SPHINCS+: %v", err)
	}
}

func TestValidatePKAndDescriptor_InvalidDescriptor(t *testing.T) {
	invalidDesc := descriptor.Descriptor{255, 0, 0}
	pk := make([]byte, ml_dsa_87.PKSize)

	err := validatePKAndDescriptor(pk, invalidDesc)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestValidatePKAndDescriptor_WrongPKSize(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	wrongPK := make([]byte, 64)

	err := validatePKAndDescriptor(wrongPK, desc)
	if err == nil {
		t.Error("expected error for wrong PK size")
	}
}

func TestValidatePKAndDescriptor_UnknownWalletType(t *testing.T) {
	desc := descriptor.Descriptor{100, 0, 0}
	pk := make([]byte, 64)

	err := validatePKAndDescriptor(pk, desc)
	if err == nil {
		t.Error("expected error for unknown wallet type")
	}
}

func TestGetAddressFromPKAndDescriptor_MLDSA87(t *testing.T) {
	wallet, err := ml_dsa_87.NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()

	addr, err := GetAddressFromPKAndDescriptor(pk[:], desc)
	if err != nil {
		t.Fatalf("GetAddressFromPKAndDescriptor failed: %v", err)
	}

	walletAddr := wallet.GetAddress()
	if addr != walletAddr {
		t.Error("address mismatch between GetAddressFromPKAndDescriptor and wallet.GetAddress")
	}
}

func TestGetAddressFromPKAndDescriptor_SPHINCS(t *testing.T) {
	wallet, err := sphincsplus_256s.NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()

	addr, err := GetAddressFromPKAndDescriptor(pk[:], desc)
	if err != nil {
		t.Fatalf("GetAddressFromPKAndDescriptor failed: %v", err)
	}

	walletAddr := wallet.GetAddress()
	if addr != walletAddr {
		t.Error("address mismatch between GetAddressFromPKAndDescriptor and wallet.GetAddress")
	}
}

func TestGetAddressFromPKAndDescriptor_InvalidPK(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	wrongPK := make([]byte, 32)

	_, err := GetAddressFromPKAndDescriptor(wrongPK, desc)
	if err == nil {
		t.Error("expected error for invalid PK")
	}
}

func TestGetAddressFromPKAndDescriptor_InvalidDescriptor(t *testing.T) {
	invalidDesc := descriptor.Descriptor{255, 0, 0}
	pk := make([]byte, ml_dsa_87.PKSize)

	_, err := GetAddressFromPKAndDescriptor(pk, invalidDesc)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestGetAddressFromPKAndDescriptor_CrossAlgorithm(t *testing.T) {
	mlWallet, _ := ml_dsa_87.NewWallet()
	sphincsWallet, _ := sphincsplus_256s.NewWallet()

	mlPK := mlWallet.GetPK()
	sphincsPK := sphincsWallet.GetPK()

	mlAddr, _ := GetAddressFromPKAndDescriptor(mlPK[:], mlWallet.GetDescriptor().ToDescriptor())
	sphincsAddr, _ := GetAddressFromPKAndDescriptor(sphincsPK[:], sphincsWallet.GetDescriptor().ToDescriptor())

	if mlAddr == sphincsAddr {
		t.Error("addresses from different algorithms should differ")
	}
}
