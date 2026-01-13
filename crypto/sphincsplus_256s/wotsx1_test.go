package sphincsplus_256s

import (
	"testing"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func TestInitializeLeafInfoX1(t *testing.T) {
	var info LeafInfoX1
	var addr [8]uint32
	stepBuffer := make([]uint8, params.SPX_WOTS_LEN)

	// Set some values in addr
	for i := range addr {
		addr[i] = uint32(i * 10)
	}

	// Set some values in stepBuffer
	for i := range stepBuffer {
		stepBuffer[i] = uint8(i % 256)
	}

	InitializeLeafInfoX1(&info, &addr, stepBuffer)

	// Verify WotsSig is nil
	if info.WotsSig != nil {
		t.Error("WotsSig should be nil after initialization")
	}

	// Verify WotsSignLeaf is set to max uint32 (~0u)
	if info.WotsSignLeaf != ^uint32(0) {
		t.Errorf("WotsSignLeaf = %d, want %d", info.WotsSignLeaf, ^uint32(0))
	}

	// Verify WotsSteps points to the stepBuffer
	if len(info.WotsSteps) != len(stepBuffer) {
		t.Errorf("WotsSteps length = %d, want %d", len(info.WotsSteps), len(stepBuffer))
	}
	for i, v := range info.WotsSteps {
		if v != stepBuffer[i] {
			t.Errorf("WotsSteps[%d] = %d, want %d", i, v, stepBuffer[i])
		}
	}

	// Verify LeafAddr is copied from addr
	for i := range addr {
		if info.LeafAddr[i] != addr[i] {
			t.Errorf("LeafAddr[%d] = %d, want %d", i, info.LeafAddr[i], addr[i])
		}
	}

	// Verify PkAddr is copied from addr
	for i := range addr {
		if info.PkAddr[i] != addr[i] {
			t.Errorf("PkAddr[%d] = %d, want %d", i, info.PkAddr[i], addr[i])
		}
	}
}

func TestInitializeLeafInfoX1_ZeroAddr(t *testing.T) {
	var info LeafInfoX1
	var addr [8]uint32 // all zeros
	stepBuffer := make([]uint8, 10)

	InitializeLeafInfoX1(&info, &addr, stepBuffer)

	// Verify addresses are zeroed
	for i := range info.LeafAddr {
		if info.LeafAddr[i] != 0 {
			t.Errorf("LeafAddr[%d] = %d, want 0", i, info.LeafAddr[i])
		}
		if info.PkAddr[i] != 0 {
			t.Errorf("PkAddr[%d] = %d, want 0", i, info.PkAddr[i])
		}
	}
}
