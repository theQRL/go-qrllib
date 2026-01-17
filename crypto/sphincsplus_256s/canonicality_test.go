package sphincsplus_256s

import (
	"crypto/rand"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

// Canonicality tests for SPHINCS+ signature verification.
// SPHINCS+ is hash-based, meaning signatures are inherently canonical
// (no alternate encodings for the same signature). These tests verify
// that malformed signatures are rejected.
//
// Signature layout: R (n bytes) || FORS signature || WOTS signatures || auth paths

// TestCanonicalityTruncatedSignatures tests that truncated signatures are rejected.
func TestCanonicalityTruncatedSignatures(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message for canonicality")
	pk := spx.GetPK()

	validSig, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test various truncation points
	truncationPoints := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"partial_R", params.SPX_N / 2},
		{"exactly_R", params.SPX_N},
		{"partial_fors", params.SPX_N + params.SPX_FORS_BYTES/2},
		{"fors_complete", params.SPX_N + params.SPX_FORS_BYTES},
		{"partial_wots", params.SPX_N + params.SPX_FORS_BYTES + params.SPX_WOTS_BYTES/2},
		{"half_signature", params.SPX_BYTES / 2},
		{"ninety_percent", params.SPX_BYTES * 9 / 10},
		{"missing_last_byte", params.SPX_BYTES - 1},
	}

	for _, tc := range truncationPoints {
		t.Run(tc.name, func(t *testing.T) {
			if tc.length >= params.SPX_BYTES {
				t.Skip("Not a truncation test")
			}

			// Create truncated signature
			truncated := make([]byte, tc.length)
			copy(truncated, validSig[:tc.length])

			// Use Open which handles variable-length sealed messages
			sealed := append(truncated, msg...)
			if Open(sealed, &pk) != nil {
				t.Errorf("Truncated signature at %d bytes should not verify", tc.length)
			}
		})
	}
}

// TestCanonicalityCorruptedSignatureComponents tests corruption at key positions.
func TestCanonicalityCorruptedSignatureComponents(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message for canonicality")
	pk := spx.GetPK()

	validSig, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify valid signature works
	if !Verify(msg, validSig, &pk) {
		t.Fatal("Valid signature should verify")
	}

	// Define key positions in the signature
	positions := []struct {
		name     string
		position int
	}{
		{"R_first_byte", 0},
		{"R_middle", params.SPX_N / 2},
		{"R_last_byte", params.SPX_N - 1},
		{"FORS_start", params.SPX_N},
		{"FORS_middle", params.SPX_N + params.SPX_FORS_BYTES/2},
		{"FORS_end", params.SPX_N + params.SPX_FORS_BYTES - 1},
		{"WOTS_first", params.SPX_N + params.SPX_FORS_BYTES},
		{"auth_path_start", params.SPX_N + params.SPX_FORS_BYTES + params.SPX_D*params.SPX_WOTS_BYTES},
		{"signature_end", params.SPX_BYTES - 1},
	}

	for _, tc := range positions {
		t.Run(tc.name, func(t *testing.T) {
			if tc.position >= params.SPX_BYTES {
				t.Skip("Position out of bounds")
			}

			corruptedSig := validSig
			corruptedSig[tc.position] ^= 0xFF

			if Verify(msg, corruptedSig, &pk) {
				t.Errorf("Corrupted signature at %s (byte %d) should not verify", tc.name, tc.position)
			}
		})
	}
}

// TestCanonicalityAllZeroSignature tests that an all-zero signature is rejected.
func TestCanonicalityAllZeroSignature(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message")
	pk := spx.GetPK()

	var zeroSig [params.SPX_BYTES]uint8

	if Verify(msg, zeroSig, &pk) {
		t.Error("All-zero signature should not verify")
	}
}

// TestCanonicalityAllOnesSignature tests that an all-ones signature is rejected.
func TestCanonicalityAllOnesSignature(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message")
	pk := spx.GetPK()

	var onesSig [params.SPX_BYTES]uint8
	for i := range onesSig {
		onesSig[i] = 0xFF
	}

	if Verify(msg, onesSig, &pk) {
		t.Error("All-ones signature should not verify")
	}
}

// TestCanonicalityRandomSignatures tests that random signatures don't verify.
func TestCanonicalityRandomSignatures(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message")
	pk := spx.GetPK()

	// Test multiple random signatures (fewer due to SPHINCS+ performance)
	for i := 0; i < 10; i++ {
		var randomSig [params.SPX_BYTES]uint8
		_, _ = rand.Read(randomSig[:])

		if Verify(msg, randomSig, &pk) {
			t.Errorf("Random signature %d should not verify", i)
		}
	}
}

// TestCanonicalityFORSCorruption tests corruption of FORS signature components.
func TestCanonicalityFORSCorruption(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message for FORS canonicality")
	pk := spx.GetPK()

	validSig, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	forsStart := params.SPX_N
	forsEnd := params.SPX_N + params.SPX_FORS_BYTES

	// Test corruption at each FORS tree boundary
	treeSize := params.SPX_FORS_BYTES / params.SPX_FORS_TREES

	for tree := 0; tree < params.SPX_FORS_TREES; tree += 5 { // Sample every 5th tree
		t.Run("fors_tree", func(t *testing.T) {
			pos := forsStart + tree*treeSize
			if pos >= forsEnd {
				return
			}

			corruptedSig := validSig
			corruptedSig[pos] ^= 0x01

			if Verify(msg, corruptedSig, &pk) {
				t.Errorf("Corrupted FORS tree %d should not verify", tree)
			}
		})
	}
}

// TestCanonicalityWOTSCorruption tests corruption of WOTS signature components.
func TestCanonicalityWOTSCorruption(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message for WOTS canonicality")
	pk := spx.GetPK()

	validSig, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	wotsStart := params.SPX_N + params.SPX_FORS_BYTES

	// Test corruption at each WOTS signature (D layers)
	for layer := 0; layer < params.SPX_D; layer++ {
		t.Run("wots_layer", func(t *testing.T) {
			pos := wotsStart + layer*params.SPX_WOTS_BYTES
			if pos >= params.SPX_BYTES {
				return
			}

			corruptedSig := validSig
			corruptedSig[pos] ^= 0x01

			if Verify(msg, corruptedSig, &pk) {
				t.Errorf("Corrupted WOTS layer %d should not verify", layer)
			}
		})
	}
}

// TestCanonicalityAuthPathCorruption tests corruption of authentication path nodes.
func TestCanonicalityAuthPathCorruption(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message for auth path canonicality")
	pk := spx.GetPK()

	validSig, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	authStart := params.SPX_N + params.SPX_FORS_BYTES + params.SPX_D*params.SPX_WOTS_BYTES

	// Test corruption at various auth path heights
	for height := 0; height < params.SPX_FULL_HEIGHT; height += 8 { // Sample every 8th level
		t.Run("auth_path_height", func(t *testing.T) {
			pos := authStart + height*params.SPX_N
			if pos >= params.SPX_BYTES {
				return
			}

			corruptedSig := validSig
			corruptedSig[pos] ^= 0x01

			if Verify(msg, corruptedSig, &pk) {
				t.Errorf("Corrupted auth path at height %d should not verify", height)
			}
		})
	}
}

// TestCanonicalityValidSignatureVerifies ensures valid signatures still work.
func TestCanonicalityValidSignatureVerifies(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	messages := [][]byte{
		{},
		{0x00},
		[]byte("short"),
		[]byte("a longer message for testing signature verification"),
	}

	for i, msg := range messages {
		sig, err := spx.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}

		pk := spx.GetPK()
		if !Verify(msg, sig, &pk) {
			t.Errorf("Valid signature for message %d should verify", i)
		}
	}
}

// TestCanonicalitySignatureSize verifies exact signature size is required.
func TestCanonicalitySignatureSize(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message")
	pk := spx.GetPK()

	// Test various wrong sizes
	wrongSizes := []int{
		0,
		1,
		params.SPX_BYTES - 1,
		params.SPX_BYTES + 1,
		params.SPX_BYTES * 2,
	}

	for _, size := range wrongSizes {
		t.Run("wrong_size", func(t *testing.T) {
			wrongSig := make([]byte, size)
			if cryptoSignVerify(wrongSig, msg, pk[:]) {
				t.Errorf("Signature of size %d (expected %d) should not verify", size, params.SPX_BYTES)
			}
		})
	}
}
