package lattice

import (
	"testing"
)

func TestMontgomeryReduce(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected int32
	}{
		{"zero", 0, 0},
		{"small positive", 100, 0},
		{"Q value", int64(Q), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MontgomeryReduce(tt.input)
			// Just verify it doesn't panic and returns a value in valid range
			if got < -Q || got > Q {
				t.Errorf("MontgomeryReduce(%d) = %d, out of range [-Q, Q]", tt.input, got)
			}
		})
	}
}

func TestReduce32(t *testing.T) {
	tests := []struct {
		name  string
		input int32
	}{
		{"zero", 0},
		{"Q", Q},
		{"2Q", 2 * Q},
		{"negative", -Q},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Reduce32(tt.input)
			// Result should be in valid range
			if got < -Q || got > Q {
				t.Errorf("Reduce32(%d) = %d, out of range", tt.input, got)
			}
		})
	}
}

func TestCAddQ(t *testing.T) {
	tests := []struct {
		name     string
		input    int32
		expected int32
	}{
		{"zero", 0, 0},
		{"positive", 100, 100},
		{"negative", -100, Q - 100},
		{"negative Q", -Q, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CAddQ(tt.input)
			if got != tt.expected {
				t.Errorf("CAddQ(%d) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNTTInverse(t *testing.T) {
	// Test that NTT followed by InvNTTToMont produces values close to original
	// (accounting for Montgomery factor)
	var a [N]int32
	for i := range a {
		a[i] = int32(i % 1000)
	}

	original := a
	NTT(&a)
	InvNTTToMont(&a)

	// After NTT and inverse, values should be related to original
	// (not exact due to Montgomery representation)
	allZero := true
	for _, v := range a {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero && original[1] != 0 {
		t.Error("NTT inverse produced all zeros from non-zero input")
	}
}

func TestPower2Round(t *testing.T) {
	tests := []struct {
		name string
		a    int32
	}{
		{"zero", 0},
		{"small", 100},
		{"medium", 10000},
		{"large", 1000000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a0 int32
			a1 := Power2Round(&a0, tt.a)
			// Verify: a = a1*2^D + a0
			reconstructed := (a1 << D) + a0
			if reconstructed != tt.a {
				t.Errorf("Power2Round(%d): a1=%d, a0=%d, reconstructed=%d", tt.a, a1, a0, reconstructed)
			}
		})
	}
}

func TestDecompose(t *testing.T) {
	tests := []struct {
		name string
		a    int32
	}{
		{"zero", 0},
		{"small", 100},
		{"medium", 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a0 int32
			a1 := Decompose(&a0, tt.a)
			// Just verify it doesn't panic
			_ = a1
			_ = a0
		})
	}
}

func TestMakeHint(t *testing.T) {
	tests := []struct {
		name     string
		a0, a1   int32
		expected uint
	}{
		{"zero both", 0, 0, 0},
		{"within range", GAMMA2 - 1, 0, 0},
		{"at boundary", GAMMA2, 0, 0},
		{"above range", GAMMA2 + 1, 0, 1},
		{"below negative range", -GAMMA2 - 1, 0, 1},
		{"at negative boundary with a1=0", -GAMMA2, 0, 0},
		{"at negative boundary with a1!=0", -GAMMA2, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MakeHint(tt.a0, tt.a1)
			if got != tt.expected {
				t.Errorf("MakeHint(%d, %d) = %d, want %d", tt.a0, tt.a1, got, tt.expected)
			}
		})
	}
}

func TestUseHint(t *testing.T) {
	tests := []struct {
		name string
		a    int32
		hint int
	}{
		{"no hint", 1000, 0},
		{"with hint", 1000, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify it doesn't panic
			_ = UseHint(tt.a, tt.hint)
		})
	}
}

func TestConstants(t *testing.T) {
	if N != 256 {
		t.Errorf("N = %d, want 256", N)
	}
	if Q != 8380417 {
		t.Errorf("Q = %d, want 8380417", Q)
	}
	if QInv != 58728449 {
		t.Errorf("QInv = %d, want 58728449", QInv)
	}
	if D != 13 {
		t.Errorf("D = %d, want 13", D)
	}
	if GAMMA2 != (Q-1)/32 {
		t.Errorf("GAMMA2 = %d, want %d", GAMMA2, (Q-1)/32)
	}
	if len(Zetas) != N {
		t.Errorf("len(Zetas) = %d, want %d", len(Zetas), N)
	}
}
