package falcon1024

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestSamplerPRNGKAT(t *testing.T) {
	// Digests are derived from KAT_RNG_1 and KAT_RNG_2 in the Falcon
	// reference implementation's test_falcon.c.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("rng"))
	prng := newSamplerPRNG(rng)

	var rng1 [128 * 8]byte
	for i := range 128 {
		binary.LittleEndian.PutUint64(rng1[i*8:], prng.readUint64())
	}
	if got := sha256.Sum256(rng1[:]); hex.EncodeToString(got[:]) != "edc508303c516de4cee4dcd329ce19af316fae7ab396e0bf17932322ece5d81a" {
		t.Fatalf("KAT_RNG_1 digest mismatch: %x", got)
	}

	var rng2 [1024]byte
	for i := range rng2 {
		rng2[i] = prng.readByte()
	}
	if got := sha256.Sum256(rng2[:]); hex.EncodeToString(got[:]) != "93e76ab2a556cbded47c0eab9159ea4a6c20027f84c880cd5ab4d030a149fd59" {
		t.Fatalf("KAT_RNG_2 digest mismatch: %x", got)
	}
}
