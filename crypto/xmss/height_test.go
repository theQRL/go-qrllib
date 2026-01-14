package xmss

import (
	"errors"
	"testing"
)

func TestHeightFromDescriptorByte(t *testing.T) {
	// Height is stored in lower nibble as height/2
	// HeightFromDescriptorByte extracts: (val & 0x0f) << 1
	tests := []struct {
		name       string
		descriptor uint8
		want       Height
		wantErr    bool
	}{
		{"height 2", 0x01, Height(2), false},
		{"height 4", 0x02, Height(4), false},
		{"height 6", 0x03, Height(6), false},
		{"height 8", 0x04, Height(8), false},
		{"height 10", 0x05, Height(10), false},
		{"height 20", 0x0A, Height(20), false},
		{"height 30", 0x0F, Height(30), false},
		{"height 2 with hash bits", 0x21, Height(2), false},  // SHAKE_256 + height 2
		{"height 10 with hash bits", 0x15, Height(10), false}, // SHAKE_128 + height 10
		{"height 0 (invalid)", 0x00, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HeightFromDescriptorByte(tc.descriptor)
			if tc.wantErr {
				if err == nil {
					t.Errorf("HeightFromDescriptorByte(0x%02X) expected error", tc.descriptor)
				}
				if !errors.Is(err, ErrInvalidHeight) {
					t.Errorf("HeightFromDescriptorByte(0x%02X) error = %v, want ErrInvalidHeight", tc.descriptor, err)
				}
			} else {
				if err != nil {
					t.Errorf("HeightFromDescriptorByte(0x%02X) unexpected error: %v", tc.descriptor, err)
				}
				if got != tc.want {
					t.Errorf("HeightFromDescriptorByte(0x%02X) = %v, want %v", tc.descriptor, got, tc.want)
				}
			}
		})
	}
}

func TestHeight_ToDescriptorByte(t *testing.T) {
	tests := []struct {
		name    string
		height  Height
		want    byte
		wantErr bool
	}{
		{"height 2", Height(2), 0x01, false},
		{"height 4", Height(4), 0x02, false},
		{"height 6", Height(6), 0x03, false},
		{"height 8", Height(8), 0x04, false},
		{"height 10", Height(10), 0x05, false},
		{"height 20", Height(20), 0x0A, false},
		{"height 30", Height(30), 0x0F, false},
		{"height 0 (invalid)", Height(0), 0, true},
		{"height 1 (invalid)", Height(1), 0, true},
		{"height 3 (invalid odd)", Height(3), 0, true},
		{"height 32 (invalid > max)", Height(32), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.height.ToDescriptorByte()
			if tc.wantErr {
				if err == nil {
					t.Errorf("Height(%d).ToDescriptorByte() expected error", tc.height)
				}
			} else {
				if err != nil {
					t.Errorf("Height(%d).ToDescriptorByte() unexpected error: %v", tc.height, err)
				}
				if got != tc.want {
					t.Errorf("Height(%d).ToDescriptorByte() = 0x%02X, want 0x%02X", tc.height, got, tc.want)
				}
			}
		})
	}
}

func TestHeightDescriptorRoundTrip(t *testing.T) {
	validHeights := []Height{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30}

	for _, h := range validHeights {
		// Convert to descriptor byte
		descriptor, err := h.ToDescriptorByte()
		if err != nil {
			t.Errorf("Height(%d).ToDescriptorByte() failed: %v", h, err)
			continue
		}

		// Convert back
		recovered, err := HeightFromDescriptorByte(descriptor)
		if err != nil {
			t.Errorf("HeightFromDescriptorByte(0x%02X) failed: %v", descriptor, err)
			continue
		}

		if recovered != h {
			t.Errorf("Round trip: Height(%d) -> 0x%02X -> Height(%d)", h, descriptor, recovered)
		}
	}
}

func TestGetHeightFromSigSize(t *testing.T) {
	// With WOTSParamW=16 and WOTSParamN=32:
	// keySize = 67 * 32 = 2144
	// signatureBaseSize = 4 + 32 + 2144 = 2180
	// signature size for height h = 2180 + h*32

	tests := []struct {
		name    string
		sigSize uint32
		want    Height
		wantErr bool
	}{
		{"height 4", 2180 + 4*32, Height(4), false},
		{"height 10", 2180 + 10*32, Height(10), false},
		{"height 30", 2180 + 30*32, Height(30), false},
		{"too small", 100, 0, true},
		{"not aligned", 2180 + 4*32 + 1, 0, true},
		{"height 0 (invalid)", 2180, 0, true},
		{"height 32 (exceeds max)", 2180 + 32*32, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetHeightFromSigSize(tc.sigSize, WOTSParamW)
			if tc.wantErr {
				if err == nil {
					t.Errorf("GetHeightFromSigSize(%d) expected error", tc.sigSize)
				}
			} else {
				if err != nil {
					t.Errorf("GetHeightFromSigSize(%d) unexpected error: %v", tc.sigSize, err)
				}
				if got != tc.want {
					t.Errorf("GetHeightFromSigSize(%d) = %v, want %v", tc.sigSize, got, tc.want)
				}
			}
		})
	}
}

func TestUInt32ToHeight(t *testing.T) {
	tests := []struct {
		name    string
		input   uint32
		want    Height
		wantErr bool
	}{
		{"valid 2", 2, Height(2), false},
		{"valid 10", 10, Height(10), false},
		{"valid 30", 30, Height(30), false},
		{"exceeds max 31", 31, 0, true},
		{"exceeds max 100", 100, 0, true},
		{"exceeds max large", 0xFFFFFFFF, 0, true},
		{"invalid 0", 0, 0, true},
		{"invalid odd 3", 3, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UInt32ToHeight(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("UInt32ToHeight(%d) expected error", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("UInt32ToHeight(%d) unexpected error: %v", tc.input, err)
				}
				if got != tc.want {
					t.Errorf("UInt32ToHeight(%d) = %v, want %v", tc.input, got, tc.want)
				}
			}
		})
	}
}
