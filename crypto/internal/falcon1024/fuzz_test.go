package falcon1024

import (
	"bytes"
	"crypto/sha3"
	"testing"
)

// fuzzSignatureSeeds returns a deterministic detached signature and signed
// message of one message under the test key, for the canonicality targets.
func fuzzSignatureSeeds(f *testing.F) (pub *PublicKey, message, sig, sm []byte) {
	f.Helper()
	seed := make([]byte, SeedSize)
	priv, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		f.Fatal(err)
	}
	message = []byte("falcon-1024 canonicality fuzz")
	stream := func() *sha3.SHAKE {
		s := sha3.NewSHAKE256()
		_, _ = s.Write([]byte("canonicality fuzz"))
		return s
	}
	if sig, err = SignDetached(stream(), priv, message); err != nil {
		f.Fatal(err)
	}
	if sm, err = Sign(stream(), priv, message); err != nil {
		f.Fatal(err)
	}
	return priv.PublicKey(), message, sig, sm
}

// FuzzDetachedSignatureCanonical checks the one-encoding rule on every input:
// whatever the decoder accepts must re-encode to exactly the bytes it was
// given, and whatever Verify accepts must be decodable. Any input that
// decodes but re-encodes differently would be a second encoding of the same
// signature.
func FuzzDetachedSignatureCanonical(f *testing.F) {
	pub, message, sig, _ := fuzzSignatureSeeds(f)
	f.Add(sig)
	f.Add(sig[:len(sig)-1])
	f.Add(append(bytes.Clone(sig), 0))
	f.Add(append([]byte{sig[0] ^ 0xFF}, sig[1:]...))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		nonce, s2, err := detachedSignatureDecode(input)
		if err != nil {
			if Verify(pub, message, input) == nil {
				t.Fatalf("Verify accepted an input the decoder rejects: %x", input)
			}
			return
		}
		var n [nonceSize]byte
		copy(n[:], nonce)
		encoded, err := detachedSignatureEncode(n, s2)
		if err != nil {
			t.Fatalf("decoded signature does not re-encode: %v", err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatalf("second encoding of a signature: decoded from %x, canonical form %x", input, encoded)
		}
	})
}

// FuzzSignedMessageCanonical is the signed-message counterpart: an accepted
// framing must re-encode to itself, and Open must return exactly the message
// the framing carries.
func FuzzSignedMessageCanonical(f *testing.F) {
	pub, _, _, sm := fuzzSignatureSeeds(f)
	f.Add(sm)
	f.Add(sm[:len(sm)-1])
	f.Add(append(bytes.Clone(sm), 0))
	f.Add(append([]byte{sm[0], sm[1] ^ 1}, sm[2:]...))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		nonce, message, s2, err := signedMessageDecode(input)
		if err != nil {
			if opened, openErr := Open(pub, input); openErr == nil {
				t.Fatalf("Open accepted an input the decoder rejects: %x (message %x)", input, opened)
			}
			return
		}
		var n [nonceSize]byte
		copy(n[:], nonce)
		encoded, err := signedMessageEncode(n, message, s2)
		if err != nil {
			t.Fatalf("decoded signed message does not re-encode: %v", err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatalf("second encoding of a signed message: decoded from %x, canonical form %x", input, encoded)
		}
		if opened, openErr := Open(pub, input); openErr == nil && !bytes.Equal(opened, message) {
			t.Fatalf("Open returned %x, the framing carries %x", opened, message)
		}
	})
}
