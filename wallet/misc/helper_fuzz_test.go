package misc

import (
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/qrl"
)

// FuzzMnemonicToBin tests that MnemonicToBin handles arbitrary input without panicking
func FuzzMnemonicToBin(f *testing.F) {
	// Add seed corpus with valid and invalid mnemonics
	f.Add("")
	f.Add("invalid")
	f.Add("absorb bunny")
	f.Add("absorb bunny aback aback")
	f.Add("absorb bunny aback aback aback aback")
	f.Add("notaword notaword")
	f.Add("absorb")                                           // Odd word count
	f.Add("absorb bunny aback")                               // Odd word count
	f.Add(strings.Repeat("absorb ", 34)[:len("absorb ")*34-1]) // 34 words

	// Add a valid 34-word mnemonic (typical seed length)
	validMnemonic := strings.TrimSpace(strings.Repeat("absorb ", 34))
	f.Add(validMnemonic)

	f.Fuzz(func(t *testing.T, mnemonic string) {
		// This should never panic, regardless of input
		_, _ = MnemonicToBin(mnemonic)
	})
}

// FuzzBinToMnemonic tests that BinToMnemonic handles arbitrary input without panicking
func FuzzBinToMnemonic(f *testing.F) {
	// Add seed corpus with various byte lengths
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 3))  // Valid (multiple of 3)
	f.Add(make([]byte, 6))  // Valid
	f.Add(make([]byte, 48)) // Typical seed size
	f.Add(make([]byte, 51)) // Valid
	f.Add(make([]byte, 1))  // Invalid (not multiple of 3)
	f.Add(make([]byte, 2))  // Invalid
	f.Add(make([]byte, 4))  // Invalid
	f.Add([]byte{0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, input []byte) {
		// This should never panic, regardless of input
		_, _ = BinToMnemonic(input)
	})
}

// FuzzMnemonicRoundTrip tests that valid bin->mnemonic->bin round trips work
func FuzzMnemonicRoundTrip(f *testing.F) {
	// Add seed corpus with valid lengths (multiples of 3)
	f.Add(make([]byte, 3))
	f.Add(make([]byte, 6))
	f.Add(make([]byte, 48))
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC})

	f.Fuzz(func(t *testing.T, input []byte) {
		// Only test valid lengths (multiples of 3)
		if len(input)%3 != 0 || len(input) == 0 {
			return
		}

		// Ensure all values produce valid word indices (0-4095)
		// The algorithm uses 12-bit values, so max index is 4095
		// WordList has 4096 entries, so this should always be valid

		mnemonic, err := BinToMnemonic(input)
		if err != nil {
			// BinToMnemonic can fail for various reasons
			return
		}

		// Try to convert back
		result, err := MnemonicToBin(mnemonic)
		if err != nil {
			t.Errorf("Round trip failed: BinToMnemonic succeeded but MnemonicToBin failed: %v", err)
			return
		}

		// Verify round trip
		if len(result) != len(input) {
			t.Errorf("Round trip length mismatch: input %d, output %d", len(input), len(result))
			return
		}

		for i := range input {
			if input[i] != result[i] {
				t.Errorf("Round trip mismatch at byte %d: input 0x%02x, output 0x%02x", i, input[i], result[i])
				return
			}
		}
	})
}

// FuzzMnemonicWithValidWords tests MnemonicToBin with random combinations of valid words
func FuzzMnemonicWithValidWords(f *testing.F) {
	// Seed with indices into the word list
	f.Add(uint16(0), uint16(0))
	f.Add(uint16(0), uint16(1))
	f.Add(uint16(4095), uint16(4095))
	f.Add(uint16(1000), uint16(2000))

	f.Fuzz(func(t *testing.T, idx1, idx2 uint16) {
		// Constrain indices to valid range
		idx1 = idx1 % uint16(len(qrl.WordList))
		idx2 = idx2 % uint16(len(qrl.WordList))

		// Build a 2-word mnemonic (minimum even count)
		mnemonic := qrl.WordList[idx1] + " " + qrl.WordList[idx2]

		// This should succeed for valid words with even count
		result, err := MnemonicToBin(mnemonic)
		if err != nil {
			t.Errorf("MnemonicToBin failed for valid words: %v", err)
			return
		}

		if result == nil {
			t.Error("MnemonicToBin returned nil for valid input")
		}
	})
}
