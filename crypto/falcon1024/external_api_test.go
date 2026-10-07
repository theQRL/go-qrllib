package falcon1024_test

import (
	"bytes"
	"crypto/sha3"
	"testing"

	. "github.com/theQRL/go-qrllib/crypto/falcon1024"
)

func TestExternalAPILoop(t *testing.T) {
	// 12 rounds of key generation, public key re-derivation, signing and
	// verification through the exported API, including the rejection of a
	// signature for different data. Each round signs the same data twice,
	// detached, and checks that both signatures verify and that signing is
	// randomized, then signs it once more as a signed message and opens it.
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("external"))

	for i := range 12 {
		pub, priv, err := GenerateKey(rng)
		if err != nil {
			t.Fatalf("round %d: GenerateKey: %v", i, err)
		}
		if len(pub.Bytes()) != PublicKeySize {
			t.Fatalf("round %d: public key length = %d, want %d", i, len(pub.Bytes()), PublicKeySize)
		}

		// The public key must be recoverable from the private key alone.
		priv2, err := NewPrivateKey(priv.Bytes())
		if err != nil {
			t.Fatalf("round %d: NewPrivateKey: %v", i, err)
		}
		if !pub.Equal(priv2.Public()) {
			t.Fatalf("round %d: public key re-derived from private key differs", i)
		}
		pub2, err := NewPublicKey(pub.Bytes())
		if err != nil {
			t.Fatalf("round %d: NewPublicKey: %v", i, err)
		}
		if !pub.Equal(pub2) {
			t.Fatalf("round %d: public key encoding did not round-trip", i)
		}

		var signatures [2][]byte
		for j := range signatures {
			sig, signErr := SignDetached(rng, priv, []byte("data1"))
			if signErr != nil {
				t.Fatalf("round %d: SignDetached: %v", i, signErr)
			}
			if len(sig) > MaxSignatureSize {
				t.Fatalf("round %d: signature length = %d, want at most %d", i, len(sig), MaxSignatureSize)
			}
			if !Verify(pub, []byte("data1"), sig) {
				t.Fatalf("round %d: valid signature rejected", i)
			}
			if Verify(pub, []byte("data2"), sig) {
				t.Fatalf("round %d: signature accepted for different data", i)
			}
			signatures[j] = sig
		}
		if bytes.Equal(signatures[0], signatures[1]) {
			t.Fatalf("round %d: two signatures of the same data are identical", i)
		}

		signedMessage, err := Sign(rng, priv, []byte("data1"))
		if err != nil {
			t.Fatalf("round %d: Sign: %v", i, err)
		}
		if len(signedMessage) > len("data1")+MaxSignedMessageOverhead {
			t.Fatalf("round %d: signed message length = %d, want at most %d", i, len(signedMessage), len("data1")+MaxSignedMessageOverhead)
		}
		opened, err := Open(pub, signedMessage)
		if err != nil {
			t.Fatalf("round %d: Open: %v", i, err)
		}
		if !bytes.Equal(opened, []byte("data1")) {
			t.Fatalf("round %d: Open returned different data", i)
		}
	}
}
