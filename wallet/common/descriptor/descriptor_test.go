package descriptor

import (
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestDescriptorIsValid(t *testing.T) {
	tests := []struct {
		name     string
		desc     Descriptor
		expected bool
	}{
		{
			name:     "SPHINCSPLUS_256S descriptor reserved but not valid today",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expected: false,
		},
		{
			name:     "valid ML_DSA_87 descriptor",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0, 0},
			expected: true,
		},
		{
			name:     "invalid descriptor type 2",
			desc:     Descriptor{2, 0, 0},
			expected: false,
		},
		{
			name:     "invalid descriptor type 255",
			desc:     Descriptor{255, 0, 0},
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

func TestDescriptorType(t *testing.T) {
	tests := []struct {
		name     string
		desc     Descriptor
		expected byte
	}{
		{"SPHINCSPLUS_256S", Descriptor{0, 1, 2}, 0},
		{"ML_DSA_87", Descriptor{1, 3, 4}, 1},
		{"unknown type", Descriptor{99, 0, 0}, 99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.desc.Type(); got != tt.expected {
				t.Errorf("Descriptor.Type() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFromBytes(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectError bool
	}{
		{"valid 3 bytes", []byte{0, 1, 2}, false},
		{"too short", []byte{0, 1}, true},
		{"too long", []byte{0, 1, 2, 3}, true},
		{"empty", []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromBytes(tt.input)
			if (err != nil) != tt.expectError {
				t.Errorf("FromBytes(%v) error = %v, expectError %v", tt.input, err, tt.expectError)
			}
		})
	}
}

func TestGetDescriptorBytes(t *testing.T) {
	tests := []struct {
		name       string
		walletType wallettype.WalletType
		metadata   [2]byte
		expected   [DescriptorSize]byte
	}{
		{
			name:       "SPHINCSPLUS_256S with zero metadata",
			walletType: wallettype.SPHINCSPLUS_256S,
			metadata:   [2]byte{0, 0},
			expected:   [3]byte{0, 0, 0},
		},
		{
			name:       "ML_DSA_87 with metadata",
			walletType: wallettype.ML_DSA_87,
			metadata:   [2]byte{0xAB, 0xCD},
			expected:   [3]byte{1, 0xAB, 0xCD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetDescriptorBytes(tt.walletType, tt.metadata)
			if got != tt.expected {
				t.Errorf("GetDescriptorBytes() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNew(t *testing.T) {
	input := [DescriptorSize]byte{1, 2, 3}
	desc := New(input)

	if desc[0] != 1 || desc[1] != 2 || desc[2] != 3 {
		t.Errorf("New() = %v, want %v", desc, input)
	}
}

func TestToBytes(t *testing.T) {
	desc := Descriptor{byte(wallettype.ML_DSA_87), 0xAB, 0xCD}
	bytes := desc.ToBytes()

	if len(bytes) != DescriptorSize {
		t.Errorf("ToBytes() length = %d, want %d", len(bytes), DescriptorSize)
	}

	if bytes[0] != byte(wallettype.ML_DSA_87) || bytes[1] != 0xAB || bytes[2] != 0xCD {
		t.Errorf("ToBytes() = %v, want [1, 0xAB, 0xCD]", bytes)
	}
}

func TestDescriptor_RoundTrip(t *testing.T) {
	original := [DescriptorSize]byte{byte(wallettype.SPHINCSPLUS_256S), 0x12, 0x34}
	desc := New(original)
	bytes := desc.ToBytes()

	recovered, err := FromBytes(bytes)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	if desc != recovered {
		t.Errorf("round-trip failed: got %v, want %v", recovered, desc)
	}
}

func TestFromBytes_ValidContent(t *testing.T) {
	input := []byte{byte(wallettype.ML_DSA_87), 0xFF, 0x00}
	desc, err := FromBytes(input)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	if desc.Type() != byte(wallettype.ML_DSA_87) {
		t.Errorf("Type() = %d, want %d", desc.Type(), wallettype.ML_DSA_87)
	}
	if desc[1] != 0xFF {
		t.Errorf("desc[1] = %d, want 0xFF", desc[1])
	}
	if desc[2] != 0x00 {
		t.Errorf("desc[2] = %d, want 0x00", desc[2])
	}
}

// TestDescriptor_IsIssuable / TestDescriptor_IsVerifiable verify that the
// per-type issuability/verifiability switches added on wallettype are
// proxied correctly through the Descriptor methods, and additionally
// require the descriptor itself to be canonical (metadata bytes zero).
// A descriptor that is not IsValid must never be IsIssuable / IsVerifiable.
// Added while remediating TOB-QRLLIB-4.
func TestDescriptor_IsIssuable(t *testing.T) {
	tests := []struct {
		name string
		desc Descriptor
		want bool
	}{
		{"ML_DSA_87 canonical is issuable", Descriptor{byte(wallettype.ML_DSA_87), 0, 0}, true},
		{"SPHINCSPLUS_256S canonical not currently issuable", Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0}, false},
		{"ML_DSA_87 with non-zero metadata not issuable (IsValid fails)", Descriptor{byte(wallettype.ML_DSA_87), 0x01, 0}, false},
		{"unknown type not issuable", Descriptor{99, 0, 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.desc.IsIssuable(); got != tt.want {
				t.Errorf("Descriptor.IsIssuable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDescriptor_IsVerifiable(t *testing.T) {
	tests := []struct {
		name string
		desc Descriptor
		want bool
	}{
		{"ML_DSA_87 canonical is verifiable", Descriptor{byte(wallettype.ML_DSA_87), 0, 0}, true},
		{"SPHINCSPLUS_256S canonical not currently verifiable", Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0}, false},
		{"ML_DSA_87 with non-zero metadata not verifiable (IsValid fails)", Descriptor{byte(wallettype.ML_DSA_87), 0, 0x01}, false},
		{"unknown type not verifiable", Descriptor{99, 0, 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.desc.IsVerifiable(); got != tt.want {
				t.Errorf("Descriptor.IsVerifiable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDescriptor_IsValid_WithMetadata(t *testing.T) {
	// Bytes 1 and 2 have no defined semantics for ML-DSA-87 and must be zero.
	// SPHINCSPLUS_256S remains reserved but is not a valid common wallet
	// descriptor until QRL activates a reviewed SLH-DSA wallet path.
	tests := []struct {
		name     string
		desc     Descriptor
		expected bool
	}{
		{
			name:     "SPHINCSPLUS_256S canonical reserved but invalid today",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0},
			expected: false,
		},
		{
			name:     "ML_DSA_87 canonical",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0, 0},
			expected: true,
		},
		{
			name:     "SPHINCSPLUS_256S with non-zero byte 1",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0x01, 0x00},
			expected: false,
		},
		{
			name:     "SPHINCSPLUS_256S with non-zero byte 2",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0x00, 0x01},
			expected: false,
		},
		{
			name:     "SPHINCSPLUS_256S with all metadata bits set",
			desc:     Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0xFF, 0xFF},
			expected: false,
		},
		{
			name:     "ML_DSA_87 with non-zero byte 1",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0x01, 0x00},
			expected: false,
		},
		{
			name:     "ML_DSA_87 with non-zero byte 2",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0x00, 0x01},
			expected: false,
		},
		{
			name:     "ML_DSA_87 with arbitrary metadata",
			desc:     Descriptor{byte(wallettype.ML_DSA_87), 0x12, 0x34},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.desc.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}
