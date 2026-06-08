package common

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

// Cross-implementation parity vectors. Identical bytes must produce identical
// checksummed strings in @theqrl/wallet.js, go-qrllib, and rust-qrllib. If any
// of these strings diverge between the three implementations the EIP-55-style
// scheme is broken at the spec level; do not patch one side to fit the other
// without coordinating with the others.
var parityVectors = []struct {
	name        string
	lower       string
	checksummed string
}{
	{
		name:        "ML-DSA-87 wallet 1",
		lower:       "Qd5812f6cf4a0f645aa620cd57319a0ed649dd8f5519a9dde7770ae5b0e49e547985f35eb972a2a07041561aa39c65a3991478f9b1e6749e05277dcf58a9a8b72",
		checksummed: "Qd5812F6Cf4a0f645aa620cd57319a0Ed649dd8f5519A9dde7770ae5b0E49e547985f35eB972A2a07041561aa39c65A3991478f9B1e6749e05277dcf58A9A8B72",
	},
	{
		name:        "ML-DSA-87 wallet 2",
		lower:       "Qbe95a82d87a6cb9c7ff4c64e0c15bb1dff20b1d77e6b571b28ad4736f2a2a3e5857e8c225d6d61399b15beef3b196936e490ed6e234374c4887cbbe86c13b1ba",
		checksummed: "QBe95a82D87a6CB9c7Ff4C64e0C15BB1DFF20b1d77E6B571B28Ad4736f2a2A3E5857E8c225D6D61399B15BEeF3B196936E490ed6E234374C4887CBBe86C13b1BA",
	},
	{
		name:        "ML-DSA-87 wallet 3",
		lower:       "Q31f654037d4d7bce04e9522e4d346ab47a90686ef20a6c19916e68d3c77950f54babb7725ad48a3201c0acb74271e790730f9f39f9ce2e9ba1be9e41a763caf9",
		checksummed: "Q31F654037D4d7BCE04E9522e4d346ab47a90686ef20A6c19916E68D3c77950f54bABB7725aD48A3201c0aCb74271E790730f9f39f9ce2e9Ba1BE9E41a763cAf9",
	},
	{
		name:        "ML-DSA-87 wallet 4",
		lower:       "Qafae844fa3be904799ccdb74e6f8b55d92f350df0b48605d1eaf4ffd63170d6c74a8db5f9f58309bec4cd18d500a8c6835ba53b886df50f962ec7dc98ec4e503",
		checksummed: "QaFAE844Fa3bE904799cCdB74E6F8B55d92F350DF0B48605D1Eaf4ffd63170D6C74a8db5f9F58309bEc4cd18D500A8c6835BA53B886df50f962ec7DC98ec4e503",
	},
	{
		name:        "ML-DSA-87 wallet 5",
		lower:       "Q09a4e13536ec5ac05a1080522898bae3210d473a0a9e9a900bdc98361d1a9e8c2cc0652344bd35b0590b537a527cc68fa2893bc6100c1da713e5431eebafb150",
		checksummed: "Q09A4E13536EC5aC05A1080522898bAE3210D473A0a9E9A900bDC98361D1A9e8C2cc0652344BD35B0590B537A527cc68fA2893bc6100c1dA713E5431EEbafb150",
	},
	{
		name:        "all-zero",
		lower:       "Q" + strings.Repeat("0", hexLen),
		checksummed: "Q" + strings.Repeat("0", hexLen),
	},
	{
		name:        "all-ff",
		lower:       "Q" + strings.Repeat("f", hexLen),
		checksummed: "QFFFfFFFFffFfffFfffFfFFfFFFFfffFFffFFfFfFFfFfFFfffFfFFFfFfFffFfFffffFfFFffFFFfFFFfFfffffFFFfffFffFfFfFFFFFfFFFFFFfFfFffFFFfffFfFF",
	},
}

func mustDecodeAddr(t *testing.T, lowerStr string) [AddressSize]byte {
	t.Helper()
	bytes, err := hex.DecodeString(lowerStr[1:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var addr [AddressSize]byte
	copy(addr[:], bytes)
	return addr
}

func TestIsValidAddress(t *testing.T) {
	// Valid address: "Q" + 128 hex chars (64 bytes * 2)
	validAddr := "Q" + strings.Repeat("ab", AddressSize)

	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "valid address (all lowercase)",
			addr:     validAddr,
			expected: true,
		},
		{
			name:     "valid address with uppercase hex",
			addr:     "Q" + strings.Repeat("AB", AddressSize),
			expected: true,
		},
		{
			// Mixed-case input now requires a valid EIP-55 checksum. A naive
			// "aB" repeat will not match the SHAKE-256-derived nibble pattern
			// and must be rejected.
			name:     "invalid - mixed case hex without valid checksum",
			addr:     "Q" + strings.Repeat("aB", AddressSize),
			expected: false,
		},
		{
			name:     "valid - canonical checksummed form",
			addr:     parityVectors[0].checksummed,
			expected: true,
		},
		{
			name:     "invalid - missing Q prefix",
			addr:     strings.Repeat("ab", AddressSize+1),
			expected: false,
		},
		{
			name:     "invalid - lowercase q prefix",
			addr:     "q" + strings.Repeat("ab", AddressSize),
			expected: false,
		},
		{
			name:     "invalid - too short",
			addr:     "Q" + strings.Repeat("ab", AddressSize-1),
			expected: false,
		},
		{
			name:     "invalid - too long",
			addr:     "Q" + strings.Repeat("ab", AddressSize+1),
			expected: false,
		},
		{
			name:     "invalid - non-hex characters",
			addr:     "Q" + strings.Repeat("zz", AddressSize),
			expected: false,
		},
		{
			name:     "invalid - empty string",
			addr:     "",
			expected: false,
		},
		{
			name:     "invalid - just Q",
			addr:     "Q",
			expected: false,
		},
		{
			name:     "invalid - contains spaces",
			addr:     "Q" + strings.Repeat("ab", AddressSize-1) + " a",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidAddress(tt.addr); got != tt.expected {
				t.Errorf("IsValidAddress(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestIsValidAddressLength(t *testing.T) {
	// Verify expected address length: Q + (AddressSize * 2) hex chars
	expectedLen := 1 + AddressSize*2

	validAddr := "Q" + strings.Repeat("00", AddressSize)
	if len(validAddr) != expectedLen {
		t.Errorf("Expected address length %d, got %d", expectedLen, len(validAddr))
	}

	if !IsValidAddress(validAddr) {
		t.Error("Address with correct length should be valid")
	}
}

func TestToChecksumAddressMatchesParityVectors(t *testing.T) {
	for _, v := range parityVectors {
		t.Run(v.name, func(t *testing.T) {
			addr := mustDecodeAddr(t, v.lower)
			got := ToChecksumAddress(addr)
			if got != v.checksummed {
				t.Errorf("checksum mismatch:\n  got  %s\n  want %s", got, v.checksummed)
			}
		})
	}
}

func TestIsValidChecksumAddress(t *testing.T) {
	v := parityVectors[0]
	upper := "Q" + strings.ToUpper(v.lower[1:])
	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{name: "canonical checksummed form", addr: v.checksummed, expected: true},
		{name: "strict: rejects all-lowercase with letters", addr: v.lower, expected: false},
		{name: "strict: rejects all-uppercase with letters", addr: upper, expected: false},
		{name: "strict: rejects lowercase q prefix", addr: "q" + v.checksummed[1:], expected: false},
		{name: "rejects too short", addr: "Q" + strings.Repeat("0", 127), expected: false},
		{name: "rejects non-hex", addr: "Q" + strings.Repeat("g", 128), expected: false},
		{name: "digit-only is valid (no checksum information)", addr: "Q" + strings.Repeat("0123456789", 12) + "01234567", expected: true},
		{name: "all-zero is valid", addr: "Q" + strings.Repeat("0", 128), expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidChecksumAddress(tt.addr); got != tt.expected {
				t.Errorf("IsValidChecksumAddress(%q) = %v, want %v", tt.addr, got, tt.expected)
			}
		})
	}
}

func TestStringToAddressAcceptsChecksummedAndUniformCase(t *testing.T) {
	for _, v := range parityVectors {
		t.Run(v.name, func(t *testing.T) {
			if !IsValidAddress(v.lower) {
				t.Errorf("lowercase form rejected: %s", v.lower)
			}
			if !IsValidAddress(v.checksummed) {
				t.Errorf("checksummed form rejected: %s", v.checksummed)
			}
			upper := "Q" + strings.ToUpper(v.lower[1:])
			if !IsValidAddress(upper) {
				t.Errorf("uppercase form rejected: %s", upper)
			}
		})
	}
}

func TestIsValidAddressRejectsCaseFlipInChecksum(t *testing.T) {
	v := parityVectors[0]
	body := []byte(v.checksummed[1:])
	// Flip the case of the first hex letter.
	flipIdx := -1
	for i, c := range body {
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			flipIdx = i
			break
		}
	}
	if flipIdx == -1 {
		t.Fatal("parity vector must contain at least one hex letter")
	}
	if body[flipIdx] >= 'a' && body[flipIdx] <= 'f' {
		body[flipIdx] -= 'a' - 'A'
	} else {
		body[flipIdx] += 'a' - 'A'
	}
	corrupted := "Q" + string(body)
	if IsValidAddress(corrupted) {
		t.Errorf("expected case-flipped checksum to be rejected, got accepted: %s", corrupted)
	}
}

func TestGetAddressMLDSA87(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	pk := make([]byte, MLDSA87PKSize)

	got, err := GetAddress(pk, desc)
	if err != nil {
		t.Fatalf("GetAddress returned error: %v", err)
	}

	want := UnsafeGetAddress(pk, desc)
	if got != want {
		t.Error("GetAddress output mismatch with UnsafeGetAddress")
	}
}

func TestGetAddressRejectsSphincsPlus256s(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	pk := make([]byte, SPHINCSPlus256sPKSize)

	if _, err := GetAddress(pk, desc); err == nil {
		t.Fatal("GetAddress accepted reserved SPHINCSPLUS_256S descriptor")
	}
}

func TestGetAddressInvalidDescriptor(t *testing.T) {
	desc := descriptor.New([descriptor.DescriptorSize]byte{0xFF, 0x00, 0x00})
	_, err := GetAddress(make([]byte, 64), desc)
	if err == nil {
		t.Error("Expected error for invalid descriptor")
	}
}

func TestGetAddressInvalidPKSize(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	_, err := GetAddress(make([]byte, 32), desc)
	if err == nil {
		t.Error("Expected error for invalid public key size")
	}
}
