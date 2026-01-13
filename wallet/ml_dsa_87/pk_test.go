package ml_dsa_87

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestBytesToPK_Valid(t *testing.T) {
	pkBytes := make([]byte, PKSize)
	for i := range pkBytes {
		pkBytes[i] = byte(i % 256)
	}

	pk, err := BytesToPK(pkBytes)
	if err != nil {
		t.Fatalf("BytesToPK failed: %v", err)
	}

	for i := range pk {
		if pk[i] != pkBytes[i] {
			t.Errorf("byte mismatch at %d: got %d, want %d", i, pk[i], pkBytes[i])
		}
	}
}

func TestBytesToPK_InvalidSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"too short", PKSize - 1},
		{"too long", PKSize + 1},
		{"empty", 0},
		{"half size", PKSize / 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkBytes := make([]byte, tt.size)
			_, err := BytesToPK(pkBytes)
			if err == nil {
				t.Errorf("expected error for size %d", tt.size)
			}
		})
	}
}

func TestHexStrToPK_Valid(t *testing.T) {
	pkBytes := make([]byte, PKSize)
	for i := range pkBytes {
		pkBytes[i] = byte(i % 256)
	}
	hexStr := hex.EncodeToString(pkBytes)

	pk, err := HexStrToPK(hexStr)
	if err != nil {
		t.Fatalf("HexStrToPK failed: %v", err)
	}

	for i := range pk {
		if pk[i] != pkBytes[i] {
			t.Errorf("byte mismatch at %d", i)
		}
	}
}

func TestHexStrToPK_InvalidHex(t *testing.T) {
	invalidHex := strings.Repeat("zz", PKSize)
	_, err := HexStrToPK(invalidHex)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestHexStrToPK_WrongLength(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
	}{
		{"too short", strings.Repeat("ab", PKSize-1)},
		{"too long", strings.Repeat("ab", PKSize+1)},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HexStrToPK(tt.hexStr)
			if err == nil {
				t.Error("expected error for wrong length")
			}
		})
	}
}

func TestHexStrToPK_UppercaseHex(t *testing.T) {
	pkBytes := make([]byte, PKSize)
	for i := range pkBytes {
		pkBytes[i] = byte(i % 256)
	}
	hexStr := strings.ToUpper(hex.EncodeToString(pkBytes))

	pk, err := HexStrToPK(hexStr)
	if err != nil {
		t.Fatalf("HexStrToPK with uppercase failed: %v", err)
	}

	for i := range pk {
		if pk[i] != pkBytes[i] {
			t.Errorf("byte mismatch at %d", i)
		}
	}
}

func TestPK_FromWallet(t *testing.T) {
	wallet, err := NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	pk := wallet.GetPK()

	// Round-trip through BytesToPK
	pkCopy, err := BytesToPK(pk[:])
	if err != nil {
		t.Fatalf("BytesToPK failed: %v", err)
	}

	if pk != pkCopy {
		t.Error("PK round-trip failed")
	}
}
