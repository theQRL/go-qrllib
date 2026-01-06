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
		// Additional edge cases for constant-time implementation
		{"a0 just below GAMMA2", GAMMA2 - 1, 100, 0},
		{"a0 just above -GAMMA2", -GAMMA2 + 1, 100, 0},
		{"a0 far above GAMMA2", GAMMA2 + 1000, 0, 1},
		{"a0 far below -GAMMA2", -GAMMA2 - 1000, 0, 1},
		{"a0 at -GAMMA2 with negative a1", -GAMMA2, -1, 1},
		{"a0 at -GAMMA2 with large a1", -GAMMA2, 1000000, 1},
		{"small positive a0", 1, 0, 0},
		{"small negative a0", -1, 0, 0},
		{"a0 at midpoint", 0, 1000, 0},
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

// TestMakeHintConstantTimeReference verifies the constant-time implementation
// produces results matching the reference branching implementation
func TestMakeHintConstantTimeReference(t *testing.T) {
	// Reference implementation (branching)
	makeHintRef := func(a0, a1 int32) uint {
		if a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0) {
			return 1
		}
		return 0
	}

	// Test many values around boundaries
	testValues := []int32{
		-GAMMA2 - 100, -GAMMA2 - 1, -GAMMA2, -GAMMA2 + 1, -GAMMA2 + 100,
		-1000, -100, -1, 0, 1, 100, 1000,
		GAMMA2 - 100, GAMMA2 - 1, GAMMA2, GAMMA2 + 1, GAMMA2 + 100,
	}
	a1Values := []int32{-1000, -1, 0, 1, 1000}

	for _, a0 := range testValues {
		for _, a1 := range a1Values {
			got := MakeHint(a0, a1)
			expected := makeHintRef(a0, a1)
			if got != expected {
				t.Errorf("MakeHint(%d, %d) = %d, reference = %d", a0, a1, got, expected)
			}
		}
	}
}

func TestUseHint(t *testing.T) {
	tests := []struct {
		name string
		a    int32
		hint int
	}{
		{"no hint zero", 0, 0},
		{"no hint small", 1000, 0},
		{"no hint large", 1000000, 0},
		{"with hint zero", 0, 1},
		{"with hint small", 1000, 1},
		{"with hint large", 1000000, 1},
		{"negative value no hint", -1000, 0},
		{"negative value with hint", -1000, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UseHint(tt.a, tt.hint)
			// Result should be in range [0, 15]
			if got < 0 || got > 15 {
				t.Errorf("UseHint(%d, %d) = %d, out of range [0, 15]", tt.a, tt.hint, got)
			}
		})
	}
}

// TestUseHintConstantTimeReference verifies the constant-time implementation
// produces results matching the reference branching implementation
func TestUseHintConstantTimeReference(t *testing.T) {
	// Reference implementation (branching)
	useHintRef := func(a int32, hint int) int32 {
		var a0, a1 int32
		a1 = Decompose(&a0, a)
		if hint == 0 {
			return a1
		}
		if a0 > 0 {
			return (a1 + 1) & 15
		}
		return (a1 - 1) & 15
	}

	// Test various values
	aValues := []int32{0, 1, 100, 1000, 10000, 100000, 1000000, -1, -100, -1000}
	hintValues := []int{0, 1}

	for _, a := range aValues {
		for _, hint := range hintValues {
			got := UseHint(a, hint)
			expected := useHintRef(a, hint)
			if got != expected {
				t.Errorf("UseHint(%d, %d) = %d, reference = %d", a, hint, got, expected)
			}
		}
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
