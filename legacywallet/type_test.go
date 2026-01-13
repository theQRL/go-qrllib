package legacywallet

import (
	"errors"
	"testing"
)

func TestToWalletType_Valid(t *testing.T) {
	wt, err := ToWalletType(uint8(WalletTypeXMSS))
	if err != nil {
		t.Fatalf("ToWalletType failed for valid type: %v", err)
	}

	if wt != WalletTypeXMSS {
		t.Errorf("got %d, want %d", wt, WalletTypeXMSS)
	}
}

func TestToWalletType_Invalid(t *testing.T) {
	invalidTypes := []uint8{1, 2, 100, 255}

	for _, val := range invalidTypes {
		_, err := ToWalletType(val)
		if err == nil {
			t.Errorf("expected error for invalid type %d", val)
		}
		if !errors.Is(err, ErrInvalidWalletType) {
			t.Errorf("expected ErrInvalidWalletType, got %v", err)
		}
	}
}

func TestWalletType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		wt       WalletType
		expected bool
	}{
		{"XMSS is valid", WalletTypeXMSS, true},
		{"type 1 invalid", WalletType(1), false},
		{"type 100 invalid", WalletType(100), false},
		{"type 255 invalid", WalletType(255), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wt.IsValid(); got != tt.expected {
				t.Errorf("WalletType(%d).IsValid() = %v, want %v", tt.wt, got, tt.expected)
			}
		})
	}
}

func TestWalletTypeXMSS_Value(t *testing.T) {
	// WalletTypeXMSS should be 0 (first iota)
	if WalletTypeXMSS != 0 {
		t.Errorf("WalletTypeXMSS = %d, want 0", WalletTypeXMSS)
	}
}
