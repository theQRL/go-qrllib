package falcon1024_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	. "github.com/theQRL/go-qrllib/crypto/falcon1024"
)

// fuzzKeyPair returns the deterministic key pair the fuzz targets use, so
// that a crash reproduces from the corpus entry alone.
func fuzzKeyPair(f *testing.F) (*PublicKey, *PrivateKey) {
	f.Helper()
	priv, err := NewPrivateKeyFromSeed(testSeed())
	if err != nil {
		f.Fatal(err)
	}
	return priv.Public().(*PublicKey), priv
}

// constantPublicKeyEncoding encodes the public key whose polynomial is the
// constant k: the header byte, then k in the first 14-bit field and zeros.
func constantPublicKeyEncoding(k uint16) []byte {
	pk := make([]byte, PublicKeySize)
	pk[0] = 0x0A
	pk[1] = byte(k >> 6)
	pk[2] = byte(k&0x3F) << 2
	return pk
}

// degeneratePrivateKeyEncoding is f = 1, g = 0, F = 0: the reference's own
// checks accept it, the key-generation bounds reject it.
func degeneratePrivateKeyEncoding() []byte {
	sk := make([]byte, PrivateKeySize)
	sk[0], sk[1] = 0x5A, 0x08
	return sk
}

var (
	fuzzMessage  = []byte("falcon-1024 fuzz message")
	fuzzTampered = []byte("falcon-1024 fuzz messagf")
)

// signedMessagePrefix is the fixed part of the signed-message framing:
// length(2) || nonce(40), before the message and the signature.
const signedMessagePrefix = 42

func FuzzFalcon1024NewPublicKey(f *testing.F) {
	pub, _ := fuzzKeyPair(f)
	f.Add(pub.Bytes())
	f.Add(constantPublicKeyEncoding(111))
	f.Add([]byte{})
	f.Add(make([]byte, PublicKeySize))
	f.Add(bytes.Repeat([]byte{0xFF}, PublicKeySize))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		got, err := NewPublicKey(encoded)
		if (err == nil) != (got != nil) {
			t.Fatalf("NewPublicKey returned (%v, %v)", got, err)
		}
		if err == nil && !bytes.Equal(got.Bytes(), encoded) {
			t.Fatal("accepted public key does not round-trip")
		}
	})
}

func FuzzFalcon1024NewPrivateKey(f *testing.F) {
	_, priv := fuzzKeyPair(f)
	f.Add(priv.Bytes())
	f.Add(degeneratePrivateKeyEncoding())
	f.Add([]byte{})
	f.Add(make([]byte, PrivateKeySize))
	// The shared vectors: encodings the import must refuse although their
	// public half is fine (out-of-bound (f, g), F that is not an NTRU
	// solution), which byte-level mutation does not produce.
	for _, v := range weakKeyVectorFile(f).PrivateKeys {
		sk, err := hex.DecodeString(v.SK)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(sk)
	}

	f.Fuzz(func(t *testing.T, encoded []byte) {
		got, err := NewPrivateKey(encoded)
		if (err == nil) != (got != nil) {
			t.Fatalf("NewPrivateKey returned (%v, %v)", got, err)
		}
		if err != nil {
			return
		}
		if !bytes.Equal(got.Bytes(), encoded) {
			t.Fatal("accepted private key does not round-trip")
		}
		// An accepted key must sign, and its signature must verify under
		// the public key it derives.
		sig, err := SignDetached(zeroReader{}, got, fuzzMessage)
		if err != nil {
			t.Fatalf("accepted private key cannot sign: %v", err)
		}
		if !Verify(got.Public().(*PublicKey), fuzzMessage, sig) {
			t.Fatal("signature by an accepted private key does not verify")
		}
	})
}

// Any detached signature Verify accepts must be a well-formed one for this
// key and message and must not verify for another message. Signing is
// randomized, so another honest signature is a valid corpus entry; the
// one-encoding rule itself is checked per input by the internal package's
// FuzzDetachedSignatureCanonical, which decodes and re-encodes.
func FuzzFalcon1024Verify(f *testing.F) {
	pub, priv := fuzzKeyPair(f)
	valid, err := SignDetached(zeroReader{}, priv, fuzzMessage)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(append([]byte{valid[0] ^ 0xFF}, valid[1:]...))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, signature []byte) {
		if !Verify(pub, fuzzMessage, signature) {
			return
		}
		if len(signature) > MaxSignatureSize || signature[0] != 0x3A {
			t.Fatalf("accepted signature breaks the detached format: %d bytes, header %#x", len(signature), signature[0])
		}
		if Verify(pub, fuzzTampered, signature) {
			t.Fatalf("accepted signature also verifies for a different message: %x", signature)
		}
	})
}

// Any signed message Open accepts must return exactly the message its
// framing carries. Another honest signed message (a different nonce, or a
// different message) is a valid corpus entry; the one-encoding rule is
// checked per input by the internal package's FuzzSignedMessageCanonical.
func FuzzFalcon1024Open(f *testing.F) {
	pub, priv := fuzzKeyPair(f)
	valid, err := Sign(zeroReader{}, priv, fuzzMessage)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(append([]byte{valid[0], valid[1] ^ 1}, valid[2:]...))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, signedMessage []byte) {
		message, err := Open(pub, signedMessage)
		if err != nil {
			if message != nil {
				t.Fatal("Open returned a message together with an error")
			}
			return
		}
		// Framing: length(2) || nonce(40) || message || 0x2A || polynomial,
		// the length field covering the header byte and the polynomial.
		sigLen := int(signedMessage[0])<<8 | int(signedMessage[1])
		if len(signedMessage) < signedMessagePrefix+sigLen {
			t.Fatalf("accepted signed message is shorter than its framing: %x", signedMessage)
		}
		if !bytes.Equal(message, signedMessage[signedMessagePrefix:len(signedMessage)-sigLen]) {
			t.Fatalf("Open returned a message other than the one the framing carries: %x", signedMessage)
		}
	})
}
