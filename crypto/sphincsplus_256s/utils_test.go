package sphincsplus_256s

import (
	"bytes"
	"testing"
)

func TestU32ToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected []byte
	}{
		{"zero", 0, []byte{0, 0, 0, 0}},
		{"one", 1, []byte{0, 0, 0, 1}},
		{"max byte", 255, []byte{0, 0, 0, 255}},
		{"256", 256, []byte{0, 0, 1, 0}},
		{"large value", 0x12345678, []byte{0x12, 0x34, 0x56, 0x78}},
		{"max uint32", 0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := make([]byte, 4)
			U32ToBytes(out, tc.input)
			if !bytes.Equal(out, tc.expected) {
				t.Errorf("U32ToBytes(%d) = %v, want %v", tc.input, out, tc.expected)
			}
		})
	}
}

func TestBytesToUll(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		inLen    int
		expected uint64
	}{
		{"single zero", []byte{0}, 1, 0},
		{"single byte", []byte{0x42}, 1, 0x42},
		{"two bytes", []byte{0x12, 0x34}, 2, 0x1234},
		{"four bytes", []byte{0x12, 0x34, 0x56, 0x78}, 4, 0x12345678},
		{"eight bytes", []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}, 8, 0x123456789ABCDEF0},
		{"max uint64", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 8, 0xFFFFFFFFFFFFFFFF},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := BytesToUll(tc.input, tc.inLen)
			if result != tc.expected {
				t.Errorf("BytesToUll(%v, %d) = 0x%X, want 0x%X", tc.input, tc.inLen, result, tc.expected)
			}
		})
	}
}

func TestUint32SliceToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint32
		expected []byte
	}{
		{"empty", []uint32{}, []byte{}},
		{"single zero", []uint32{0}, []byte{0, 0, 0, 0}},
		{"single value", []uint32{0x12345678}, []byte{0x12, 0x34, 0x56, 0x78}},
		{"two values", []uint32{0x12345678, 0xDEADBEEF}, []byte{0x12, 0x34, 0x56, 0x78, 0xDE, 0xAD, 0xBE, 0xEF}},
		{"max values", []uint32{0xFFFFFFFF, 0xFFFFFFFF}, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := Uint32SliceToBytes(tc.input)
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("Uint32SliceToBytes(%v) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestUllToBytesAndBytesToUllRoundTrip(t *testing.T) {
	testValues := []uint64{0, 1, 255, 256, 0x12345678, 0xFFFFFFFF, 0x123456789ABCDEF0}

	for _, val := range testValues {
		out := make([]byte, 8)
		UllToBytes(out, 8, val)
		result := BytesToUll(out, 8)
		if result != val {
			t.Errorf("Round trip failed for 0x%X: got 0x%X", val, result)
		}
	}
}
