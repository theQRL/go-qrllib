package wallettype

import (
	"testing"
)

func TestWalletTypeIsValid(t *testing.T) {
	tests := []struct {
		name     string
		wt       WalletType
		expected bool
	}{
		{"SPHINCSPLUS_256S is valid", SPHINCSPLUS_256S, true},
		{"ML_DSA_87 is valid", ML_DSA_87, true},
		{"InvalidWalletType is not valid", InvalidWalletType, false},
		{"Unknown type 100 is not valid", WalletType(100), false},
		{"Unknown type 2 is not valid", WalletType(2), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wt.IsValid(); got != tt.expected {
				t.Errorf("WalletType(%d).IsValid() = %v, want %v", tt.wt, got, tt.expected)
			}
		})
	}
}

func TestWalletTypeString(t *testing.T) {
	tests := []struct {
		wt       WalletType
		expected string
	}{
		{SPHINCSPLUS_256S, "SPHINCSPLUS_256S"},
		{ML_DSA_87, "ML_DSA_87"},
		{InvalidWalletType, "InvalidWalletType"},
		{WalletType(100), "UnknownWalletType(100)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.wt.String(); got != tt.expected {
				t.Errorf("WalletType(%d).String() = %q, want %q", tt.wt, got, tt.expected)
			}
		})
	}
}

func TestToWalletType(t *testing.T) {
	tests := []struct {
		name        string
		val         uint8
		expected    WalletType
		expectError bool
	}{
		{"valid SPHINCSPLUS_256S", 0, SPHINCSPLUS_256S, false},
		{"valid ML_DSA_87", 1, ML_DSA_87, false},
		{"invalid type 2", 2, InvalidWalletType, true},
		{"invalid type 100", 100, InvalidWalletType, true},
		{"invalid type 255", 255, InvalidWalletType, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToWalletType(tt.val)
			if (err != nil) != tt.expectError {
				t.Errorf("ToWalletType(%d) error = %v, expectError %v", tt.val, err, tt.expectError)
				return
			}
			if got != tt.expected {
				t.Errorf("ToWalletType(%d) = %v, want %v", tt.val, got, tt.expected)
			}
		})
	}
}

func TestToWalletTypeOf(t *testing.T) {
	tests := []struct {
		name        string
		val         uint8
		walletType  WalletType
		expected    WalletType
		expectError bool
	}{
		{"matching SPHINCSPLUS_256S", 0, SPHINCSPLUS_256S, SPHINCSPLUS_256S, false},
		{"matching ML_DSA_87", 1, ML_DSA_87, ML_DSA_87, false},
		{"mismatch - got ML_DSA_87 expected SPHINCSPLUS_256S", 1, SPHINCSPLUS_256S, InvalidWalletType, true},
		{"mismatch - got SPHINCSPLUS_256S expected ML_DSA_87", 0, ML_DSA_87, InvalidWalletType, true},
		{"invalid type", 100, SPHINCSPLUS_256S, InvalidWalletType, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToWalletTypeOf(tt.val, tt.walletType)
			if (err != nil) != tt.expectError {
				t.Errorf("ToWalletTypeOf(%d, %v) error = %v, expectError %v", tt.val, tt.walletType, err, tt.expectError)
				return
			}
			if got != tt.expected {
				t.Errorf("ToWalletTypeOf(%d, %v) = %v, want %v", tt.val, tt.walletType, got, tt.expected)
			}
		})
	}
}

// TestWalletType_IsIssuable pins the per-type issuability matrix added
// while remediating TOB-QRLLIB-4. SPHINCSPLUS_256S is recognised in the
// descriptor format (IsValid=true) but is not currently issuable; it is
// reserved as a forward placeholder for SLH-DSA (FIPS 205) adoption.
// ML_DSA_87 is the only currently-issuable wallet type. When SLH-DSA is
// activated this test will need updating to flip SPHINCSPLUS_256S to
// true; that update is the intended single point of change.
func TestWalletType_IsIssuable(t *testing.T) {
	tests := []struct {
		name string
		wt   WalletType
		want bool
	}{
		{"SPHINCSPLUS_256S not currently issuable", SPHINCSPLUS_256S, false},
		{"ML_DSA_87 issuable", ML_DSA_87, true},
		{"InvalidWalletType not issuable", InvalidWalletType, false},
		{"Unknown type 100 not issuable", WalletType(100), false},
		{"Unknown type 2 not issuable", WalletType(2), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wt.IsIssuable(); got != tt.want {
				t.Errorf("WalletType(%d).IsIssuable() = %v, want %v", tt.wt, got, tt.want)
			}
		})
	}
}

// TestWalletType_IsVerifiable pins the per-type verifiability matrix.
// Mirrors IsIssuable today; will need updating in lockstep with SLH-DSA
// activation.
func TestWalletType_IsVerifiable(t *testing.T) {
	tests := []struct {
		name string
		wt   WalletType
		want bool
	}{
		{"SPHINCSPLUS_256S not currently verifiable", SPHINCSPLUS_256S, false},
		{"ML_DSA_87 verifiable", ML_DSA_87, true},
		{"InvalidWalletType not verifiable", InvalidWalletType, false},
		{"Unknown type 100 not verifiable", WalletType(100), false},
		{"Unknown type 2 not verifiable", WalletType(2), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wt.IsVerifiable(); got != tt.want {
				t.Errorf("WalletType(%d).IsVerifiable() = %v, want %v", tt.wt, got, tt.want)
			}
		})
	}
}

// TestWalletType_IsValidVsIssuableContract documents the contract
// relationship between IsValid (parseable) and IsIssuable (constructable):
// every issuable type must also be valid; the converse is not required.
// This invariant prevents a future edit from making something issuable
// without making it parseable, which would be self-contradictory.
func TestWalletType_IsValidVsIssuableContract(t *testing.T) {
	for v := 0; v <= 255; v++ {
		w := WalletType(v)
		if w.IsIssuable() && !w.IsValid() {
			t.Errorf("WalletType(%d) is issuable but not valid; this violates the descriptor contract", v)
		}
		if w.IsVerifiable() && !w.IsValid() {
			t.Errorf("WalletType(%d) is verifiable but not valid; this violates the descriptor contract", v)
		}
	}
}

func TestInvalidWalletTypeConstant(t *testing.T) {
	// Verify InvalidWalletType has expected value
	if InvalidWalletType != 255 {
		t.Errorf("InvalidWalletType = %d, want 255", InvalidWalletType)
	}

	// Verify it's not valid
	if InvalidWalletType.IsValid() {
		t.Error("InvalidWalletType.IsValid() should return false")
	}

	// Verify string representation
	if InvalidWalletType.String() != "InvalidWalletType" {
		t.Errorf("InvalidWalletType.String() = %q, want %q", InvalidWalletType.String(), "InvalidWalletType")
	}
}
