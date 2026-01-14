package xmss

import (
	"errors"
	"testing"
)

func TestToHashFunction(t *testing.T) {
	tests := []struct {
		name    string
		input   uint8
		want    HashFunction
		wantErr bool
	}{
		{"SHA2_256", 0, SHA2_256, false},
		{"SHAKE_128", 1, SHAKE_128, false},
		{"SHAKE_256", 2, SHAKE_256, false},
		{"invalid 3", 3, 0, true},
		{"invalid 255", 255, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToHashFunction(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ToHashFunction(%d) expected error, got nil", tc.input)
				}
				if !errors.Is(err, ErrInvalidHashFunction) {
					t.Errorf("ToHashFunction(%d) error = %v, want ErrInvalidHashFunction", tc.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ToHashFunction(%d) unexpected error: %v", tc.input, err)
				}
				if got != tc.want {
					t.Errorf("ToHashFunction(%d) = %v, want %v", tc.input, got, tc.want)
				}
			}
		})
	}
}

func TestHashFunctionFromDescriptorByte(t *testing.T) {
	// The hash function is stored in the upper nibble (bits 4-7)
	// HashFunctionFromDescriptorByte extracts: (val >> 4) & 0x0f
	tests := []struct {
		name       string
		descriptor uint8
		want       HashFunction
		wantErr    bool
	}{
		{"SHA2_256 in upper nibble", 0x00, SHA2_256, false},
		{"SHAKE_128 in upper nibble", 0x10, SHAKE_128, false},
		{"SHAKE_256 in upper nibble", 0x20, SHAKE_256, false},
		{"SHA2_256 with height bits set", 0x0F, SHA2_256, false},
		{"SHAKE_128 with height bits set", 0x1F, SHAKE_128, false},
		{"SHAKE_256 with height bits set", 0x2F, SHAKE_256, false},
		{"invalid upper nibble 0x30", 0x30, 0, true},
		{"invalid upper nibble 0xF0", 0xF0, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HashFunctionFromDescriptorByte(tc.descriptor)
			if tc.wantErr {
				if err == nil {
					t.Errorf("HashFunctionFromDescriptorByte(0x%02X) expected error", tc.descriptor)
				}
			} else {
				if err != nil {
					t.Errorf("HashFunctionFromDescriptorByte(0x%02X) unexpected error: %v", tc.descriptor, err)
				}
				if got != tc.want {
					t.Errorf("HashFunctionFromDescriptorByte(0x%02X) = %v, want %v", tc.descriptor, got, tc.want)
				}
			}
		})
	}
}

func TestHashFunction_ToDescriptorByte(t *testing.T) {
	tests := []struct {
		name string
		hf   HashFunction
		want byte
	}{
		{"SHA2_256", SHA2_256, 0x00},
		{"SHAKE_128", SHAKE_128, 0x10},
		{"SHAKE_256", SHAKE_256, 0x20},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.hf.ToDescriptorByte()
			if got != tc.want {
				t.Errorf("%s.ToDescriptorByte() = 0x%02X, want 0x%02X", tc.name, got, tc.want)
			}
		})
	}
}

func TestHashFunction_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		hf    HashFunction
		valid bool
	}{
		{"SHA2_256", SHA2_256, true},
		{"SHAKE_128", SHAKE_128, true},
		{"SHAKE_256", SHAKE_256, true},
		{"invalid 3", HashFunction(3), false},
		{"invalid 100", HashFunction(100), false},
		{"invalid 255", HashFunction(255), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.hf.IsValid()
			if got != tc.valid {
				t.Errorf("HashFunction(%d).IsValid() = %v, want %v", tc.hf, got, tc.valid)
			}
		})
	}
}

func TestHashFunction_String(t *testing.T) {
	tests := []struct {
		hf   HashFunction
		want string
	}{
		{SHA2_256, "SHA2_256"},
		{SHAKE_128, "SHAKE_128"},
		{SHAKE_256, "SHAKE_256"},
		{HashFunction(99), "UnknownHashFunction(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.hf.String()
			if got != tc.want {
				t.Errorf("HashFunction(%d).String() = %q, want %q", tc.hf, got, tc.want)
			}
		})
	}
}

func TestHashFunctionDescriptorRoundTrip(t *testing.T) {
	hashFunctions := []HashFunction{SHA2_256, SHAKE_128, SHAKE_256}

	for _, hf := range hashFunctions {
		// Convert to descriptor byte
		descriptor := hf.ToDescriptorByte()

		// Convert back
		recovered, err := HashFunctionFromDescriptorByte(descriptor)
		if err != nil {
			t.Errorf("Round trip failed for %v: %v", hf, err)
			continue
		}

		if recovered != hf {
			t.Errorf("Round trip: %v -> 0x%02X -> %v", hf, descriptor, recovered)
		}
	}
}
