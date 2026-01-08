package ml_dsa_87

import (
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestMLDSA87DescriptorIsValid(t *testing.T) {
	tests := []struct {
		name     string
		desc     Descriptor
		expected bool
	}{
		{
			name:     "valid ML_DSA_87 descriptor",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0, 0},
			expected: true,
		},
		{
			name:     "invalid - SPHINCSPLUS_256S type",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expected: false,
		},
		{
			name:     "invalid - unknown type",
			desc:     Descriptor{99, 0, 0},
			expected: false,
		},
		{
			name:     "invalid - InvalidWalletType",
			desc:     Descriptor{byte(wallettype.InvalidWalletType), 0, 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.desc.IsValid(); got != tt.expected {
				t.Errorf("Descriptor.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMLDSA87DescriptorWalletType(t *testing.T) {
	tests := []struct {
		name     string
		desc     Descriptor
		expected wallettype.WalletType
	}{
		{
			name:     "valid ML_DSA_87 descriptor",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0, 0},
			expected: wallettype.ML_DSA_87,
		},
		{
			name:     "invalid - SPHINCSPLUS_256S type returns InvalidWalletType",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expected: wallettype.InvalidWalletType,
		},
		{
			name:     "invalid - unknown type returns InvalidWalletType",
			desc:     Descriptor{99, 0, 0},
			expected: wallettype.InvalidWalletType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.desc.WalletType()
			if got != tt.expected {
				t.Errorf("Descriptor.WalletType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewMLDSA87DescriptorFromDescriptorBytes(t *testing.T) {
	tests := []struct {
		name        string
		bytes       [descriptor.DescriptorSize]uint8
		expectError bool
	}{
		{
			name:        "valid ML_DSA_87",
			bytes:       [descriptor.DescriptorSize]uint8{byte(wallettype.ML_DSA_87), 0, 0},
			expectError: false,
		},
		{
			name:        "invalid - wrong type",
			bytes:       [descriptor.DescriptorSize]uint8{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expectError: true,
		},
		{
			name:        "invalid - unknown type",
			bytes:       [descriptor.DescriptorSize]uint8{99, 0, 0},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMLDSA87DescriptorFromDescriptorBytes(tt.bytes)
			if (err != nil) != tt.expectError {
				t.Errorf("NewMLDSA87DescriptorFromDescriptorBytes() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestNewMLDSA87Descriptor(t *testing.T) {
	desc, err := NewMLDSA87Descriptor()
	if err != nil {
		t.Fatalf("NewMLDSA87Descriptor() error: %v", err)
	}

	if !desc.IsValid() {
		t.Error("NewMLDSA87Descriptor() should return a valid descriptor")
	}

	if desc.WalletType() != wallettype.ML_DSA_87 {
		t.Errorf("NewMLDSA87Descriptor().WalletType() = %v, want %v", desc.WalletType(), wallettype.ML_DSA_87)
	}
}
