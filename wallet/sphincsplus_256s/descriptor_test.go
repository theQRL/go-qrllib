package sphincsplus_256s

import (
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestSphincsPlus256sDescriptorIsValid(t *testing.T) {
	tests := []struct {
		name     string
		desc     Descriptor
		expected bool
	}{
		{
			name:     "valid SPHINCSPLUS_256S descriptor",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expected: true,
		},
		{
			name:     "invalid - ML_DSA_87 type",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0, 0},
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

func TestSphincsPlus256sDescriptorWalletType(t *testing.T) {
	tests := []struct {
		name     string
		desc     Descriptor
		expected wallettype.WalletType
	}{
		{
			name:     "valid SPHINCSPLUS_256S descriptor",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expected: wallettype.SPHINCSPLUS_256S,
		},
		{
			name:     "invalid - ML_DSA_87 type returns InvalidWalletType",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0, 0},
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

func TestNewSphincsPlus256sDescriptorFromDescriptorBytes(t *testing.T) {
	tests := []struct {
		name        string
		bytes       [descriptor.DescriptorSize]uint8
		expectError bool
	}{
		{
			name:        "valid SPHINCSPLUS_256S",
			bytes:       [descriptor.DescriptorSize]uint8{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expectError: false,
		},
		{
			name:        "invalid - wrong type",
			bytes:       [descriptor.DescriptorSize]uint8{byte(wallettype.ML_DSA_87), 0, 0},
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
			_, err := NewSphincsPlus256sDescriptorFromDescriptorBytes(tt.bytes)
			if (err != nil) != tt.expectError {
				t.Errorf("NewSphincsPlus256sDescriptorFromDescriptorBytes() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestNewSphincsPlus256sDescriptor(t *testing.T) {
	desc := NewSphincsPlus256sDescriptor()

	if !desc.IsValid() {
		t.Error("NewSphincsPlus256sDescriptor() should return a valid descriptor")
	}

	if desc.WalletType() != wallettype.SPHINCSPLUS_256S {
		t.Errorf("NewSphincsPlus256sDescriptor().WalletType() = %v, want %v", desc.WalletType(), wallettype.SPHINCSPLUS_256S)
	}
}
