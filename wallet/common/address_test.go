package common

import (
	"strings"
	"testing"
)

func TestIsValidAddress(t *testing.T) {
	// Valid address: "Q" + 40 hex chars (20 bytes * 2)
	validAddr := "Q" + strings.Repeat("ab", AddressSize) // Q + 40 hex chars

	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "valid address",
			addr:     validAddr,
			expected: true,
		},
		{
			name:     "valid address with uppercase hex",
			addr:     "Q" + strings.Repeat("AB", AddressSize),
			expected: true,
		},
		{
			name:     "valid address with mixed case hex",
			addr:     "Q" + strings.Repeat("aB", AddressSize),
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
