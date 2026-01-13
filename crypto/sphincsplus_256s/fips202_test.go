package sphincsplus_256s

import (
	"bytes"
	"testing"
)

func TestShake256XOF(t *testing.T) {
	input := []byte("test input for SHAKE256 XOF")

	// Get XOF reader
	xof := Shake256XOF(input)

	// Read some output
	output1 := make([]byte, 32)
	n, err := xof.Read(output1)
	if err != nil {
		t.Fatalf("Shake256XOF read failed: %v", err)
	}
	if n != 32 {
		t.Errorf("Shake256XOF read %d bytes, want 32", n)
	}

	// Read more output (XOF should be extendable)
	output2 := make([]byte, 32)
	n, err = xof.Read(output2)
	if err != nil {
		t.Fatalf("Shake256XOF second read failed: %v", err)
	}
	if n != 32 {
		t.Errorf("Shake256XOF second read %d bytes, want 32", n)
	}

	// The two reads should produce different output (continuing the stream)
	if bytes.Equal(output1, output2) {
		t.Error("Shake256XOF produced identical output for consecutive reads")
	}
}

func TestShake256Simple(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		outputLen int
	}{
		{"empty input 32 bytes", []byte{}, 32},
		{"hello 32 bytes", []byte("hello"), 32},
		{"hello 64 bytes", []byte("hello"), 64},
		{"hello 16 bytes", []byte("hello"), 16},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := Shake256Simple(tc.input, tc.outputLen)
			if len(result) != tc.outputLen {
				t.Errorf("Shake256Simple output length = %d, want %d", len(result), tc.outputLen)
			}
		})
	}
}

func TestShake256SimpleConsistency(t *testing.T) {
	input := []byte("consistent test input")

	// Same input should produce same output
	result1 := Shake256Simple(input, 32)
	result2 := Shake256Simple(input, 32)

	if !bytes.Equal(result1, result2) {
		t.Error("Shake256Simple produced different outputs for same input")
	}
}

func TestShake256SimpleMatchesShake256(t *testing.T) {
	input := []byte("test matching outputs")
	outputLen := 64

	// Shake256Simple result
	simpleResult := Shake256Simple(input, outputLen)

	// Shake256 result
	directResult := make([]byte, outputLen)
	Shake256(directResult, input)

	if !bytes.Equal(simpleResult, directResult) {
		t.Error("Shake256Simple and Shake256 produced different outputs")
	}
}

func TestShake256XOFMatchesShake256(t *testing.T) {
	input := []byte("test XOF matching")
	outputLen := 32

	// XOF result
	xof := Shake256XOF(input)
	xofResult := make([]byte, outputLen)
	_, _ = xof.Read(xofResult)

	// Direct Shake256 result
	directResult := make([]byte, outputLen)
	Shake256(directResult, input)

	if !bytes.Equal(xofResult, directResult) {
		t.Error("Shake256XOF and Shake256 produced different outputs for same length")
	}
}
