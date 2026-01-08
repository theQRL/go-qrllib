package misc

import (
	"testing"
)

// TestToByteLittleEndian verifies little-endian byte conversion.
// Little endian: LSB at lowest address (index 0).
func TestToByteLittleEndian(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		bytes    uint32
		expected []uint8
	}{
		{
			name:     "0x12345678 to 4 bytes",
			input:    0x12345678,
			bytes:    4,
			expected: []uint8{0x78, 0x56, 0x34, 0x12}, // LSB first
		},
		{
			name:     "0x00FF to 2 bytes",
			input:    0x00FF,
			bytes:    2,
			expected: []uint8{0xFF, 0x00},
		},
		{
			name:     "0xFF00 to 2 bytes",
			input:    0xFF00,
			bytes:    2,
			expected: []uint8{0x00, 0xFF},
		},
		{
			name:     "0x01 to 4 bytes",
			input:    0x01,
			bytes:    4,
			expected: []uint8{0x01, 0x00, 0x00, 0x00},
		},
		{
			name:     "0xDEADBEEF to 4 bytes",
			input:    0xDEADBEEF,
			bytes:    4,
			expected: []uint8{0xEF, 0xBE, 0xAD, 0xDE},
		},
		{
			name:     "zero value",
			input:    0x00000000,
			bytes:    4,
			expected: []uint8{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "max uint32",
			input:    0xFFFFFFFF,
			bytes:    4,
			expected: []uint8{0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make([]uint8, tt.bytes)
			ToByteLittleEndian(out, tt.input, tt.bytes)

			for i, b := range tt.expected {
				if out[i] != b {
					t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, out[i], b)
				}
			}
		})
	}
}

// TestToByteBigEndian verifies big-endian byte conversion.
// Big endian: MSB at lowest address (index 0).
func TestToByteBigEndian(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		bytes    uint32
		expected []uint8
	}{
		{
			name:     "0x12345678 to 4 bytes",
			input:    0x12345678,
			bytes:    4,
			expected: []uint8{0x12, 0x34, 0x56, 0x78}, // MSB first
		},
		{
			name:     "0x00FF to 2 bytes",
			input:    0x00FF,
			bytes:    2,
			expected: []uint8{0x00, 0xFF},
		},
		{
			name:     "0xFF00 to 2 bytes",
			input:    0xFF00,
			bytes:    2,
			expected: []uint8{0xFF, 0x00},
		},
		{
			name:     "0x01 to 4 bytes",
			input:    0x01,
			bytes:    4,
			expected: []uint8{0x00, 0x00, 0x00, 0x01},
		},
		{
			name:     "0xDEADBEEF to 4 bytes",
			input:    0xDEADBEEF,
			bytes:    4,
			expected: []uint8{0xDE, 0xAD, 0xBE, 0xEF},
		},
		{
			name:     "zero value",
			input:    0x00000000,
			bytes:    4,
			expected: []uint8{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "max uint32",
			input:    0xFFFFFFFF,
			bytes:    4,
			expected: []uint8{0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make([]uint8, tt.bytes)
			ToByteBigEndian(out, tt.input, tt.bytes)

			for i, b := range tt.expected {
				if out[i] != b {
					t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, out[i], b)
				}
			}
		})
	}
}

// TestAddrToByte verifies address serialization always uses big endian.
func TestAddrToByte(t *testing.T) {
	// Test with known address values
	addr := [8]uint32{
		0x00000001, // index 0
		0x00000002, // index 1
		0x00000003, // index 2
		0x00000004, // index 3 (type)
		0x00000005, // index 4 (ots/ltree)
		0x00000006, // index 5 (chain/height)
		0x00000007, // index 6 (hash/treeindex)
		0x00000008, // index 7 (key and mask)
	}

	var out [32]uint8
	AddrToByte(&out, &addr)

	// Should be big endian serialization of each uint32
	expected := []uint8{
		0x00, 0x00, 0x00, 0x01, // addr[0] = 1
		0x00, 0x00, 0x00, 0x02, // addr[1] = 2
		0x00, 0x00, 0x00, 0x03, // addr[2] = 3
		0x00, 0x00, 0x00, 0x04, // addr[3] = 4
		0x00, 0x00, 0x00, 0x05, // addr[4] = 5
		0x00, 0x00, 0x00, 0x06, // addr[5] = 6
		0x00, 0x00, 0x00, 0x07, // addr[6] = 7
		0x00, 0x00, 0x00, 0x08, // addr[7] = 8
	}

	for i, b := range expected {
		if out[i] != b {
			t.Errorf("byte %d: got 0x%02X, want 0x%02X", i, out[i], b)
		}
	}
}

// TestAddrToByteWithRealValues tests with realistic XMSS address values.
func TestAddrToByteWithRealValues(t *testing.T) {
	var addr [8]uint32

	// Set up a typical XMSS OTS address
	SetType(&addr, 0)      // OTS address type
	SetOTSAddr(&addr, 100) // OTS index 100
	SetChainAddr(&addr, 5) // Chain index 5
	SetHashAddr(&addr, 10) // Hash index 10

	var out [32]uint8
	AddrToByte(&out, &addr)

	// Verify addr[3] = 0 (type), addr[4] = 100 (ots), addr[5] = 5 (chain), addr[6] = 10 (hash)
	// Big endian: 100 = 0x64 → [0x00, 0x00, 0x00, 0x64]

	// Check OTS index at bytes 16-19 (addr[4])
	if out[16] != 0x00 || out[17] != 0x00 || out[18] != 0x00 || out[19] != 0x64 {
		t.Errorf("OTS address incorrect: got [%02X %02X %02X %02X], want [00 00 00 64]",
			out[16], out[17], out[18], out[19])
	}

	// Check chain index at bytes 20-23 (addr[5])
	if out[20] != 0x00 || out[21] != 0x00 || out[22] != 0x00 || out[23] != 0x05 {
		t.Errorf("Chain address incorrect: got [%02X %02X %02X %02X], want [00 00 00 05]",
			out[20], out[21], out[22], out[23])
	}

	// Check hash index at bytes 24-27 (addr[6])
	if out[24] != 0x00 || out[25] != 0x00 || out[26] != 0x00 || out[27] != 0x0A {
		t.Errorf("Hash address incorrect: got [%02X %02X %02X %02X], want [00 00 00 0A]",
			out[24], out[25], out[26], out[27])
	}
}

// TestEndianConsistency verifies that the endianness functions are inverse of each other
// when reading/writing with the same endianness.
func TestEndianConsistency(t *testing.T) {
	testValues := []uint32{0x12345678, 0xDEADBEEF, 0x00000001, 0xFFFFFFFF, 0x00FF00FF}

	for _, val := range testValues {
		// Test little endian round-trip
		leOut := make([]uint8, 4)
		ToByteLittleEndian(leOut, val, 4)

		// Reconstruct the value (little endian: LSB at index 0)
		leReconstructed := uint32(leOut[0]) | uint32(leOut[1])<<8 | uint32(leOut[2])<<16 | uint32(leOut[3])<<24
		if leReconstructed != val {
			t.Errorf("Little endian round-trip failed for 0x%08X: got 0x%08X", val, leReconstructed)
		}

		// Test big endian round-trip
		beOut := make([]uint8, 4)
		ToByteBigEndian(beOut, val, 4)

		// Reconstruct the value (big endian: MSB at index 0)
		beReconstructed := uint32(beOut[3]) | uint32(beOut[2])<<8 | uint32(beOut[1])<<16 | uint32(beOut[0])<<24
		if beReconstructed != val {
			t.Errorf("Big endian round-trip failed for 0x%08X: got 0x%08X", val, beReconstructed)
		}
	}
}

// TestGetEndian verifies the endianness detection works.
func TestGetEndian(t *testing.T) {
	endian := GetEndian()
	if endian != littleEndian && endian != bigEndian {
		t.Errorf("GetEndian returned invalid value: %d", endian)
	}
}

// TestHashFunctions verifies the hash wrappers work correctly.
func TestHashFunctions(t *testing.T) {
	msg := []byte("test message")

	t.Run("SHAKE128", func(t *testing.T) {
		out := make([]byte, 32)
		result := SHAKE128(out, msg)
		if result == nil {
			t.Error("SHAKE128 returned nil")
		}
		// Verify it's not all zeros
		allZero := true
		for _, b := range out {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("SHAKE128 returned all zeros")
		}
	})

	t.Run("SHAKE256", func(t *testing.T) {
		out := make([]byte, 32)
		result := SHAKE256(out, msg)
		if result == nil {
			t.Error("SHAKE256 returned nil")
		}
		// Verify it's not all zeros
		allZero := true
		for _, b := range out {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("SHAKE256 returned all zeros")
		}
	})

	t.Run("SHA256", func(t *testing.T) {
		out := make([]byte, 32)
		result := SHA256(out, msg)
		if result == nil {
			t.Error("SHA256 returned nil")
		}
		// Verify it's not all zeros
		allZero := true
		for _, b := range out {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("SHA256 returned all zeros")
		}
	})
}

// TestAddressSetters verifies the address setter functions.
func TestAddressSetters(t *testing.T) {
	var addr [8]uint32

	SetType(&addr, 42)
	if addr[3] != 42 {
		t.Errorf("SetType: got %d, want 42", addr[3])
	}
	// SetType should also zero indices 4-7
	for i := 4; i < 8; i++ {
		if addr[i] != 0 {
			t.Errorf("SetType: addr[%d] should be 0, got %d", i, addr[i])
		}
	}

	SetOTSAddr(&addr, 100)
	if addr[4] != 100 {
		t.Errorf("SetOTSAddr: got %d, want 100", addr[4])
	}

	SetChainAddr(&addr, 200)
	if addr[5] != 200 {
		t.Errorf("SetChainAddr: got %d, want 200", addr[5])
	}

	SetHashAddr(&addr, 300)
	if addr[6] != 300 {
		t.Errorf("SetHashAddr: got %d, want 300", addr[6])
	}

	// Reset and test tree-related setters
	addr = [8]uint32{}
	SetLTreeAddr(&addr, 10)
	if addr[4] != 10 {
		t.Errorf("SetLTreeAddr: got %d, want 10", addr[4])
	}

	SetTreeHeight(&addr, 20)
	if addr[5] != 20 {
		t.Errorf("SetTreeHeight: got %d, want 20", addr[5])
	}

	SetTreeIndex(&addr, 30)
	if addr[6] != 30 {
		t.Errorf("SetTreeIndex: got %d, want 30", addr[6])
	}

	SetKeyAndMask(&addr, 1)
	if addr[7] != 1 {
		t.Errorf("SetKeyAndMask: got %d, want 1", addr[7])
	}
}
