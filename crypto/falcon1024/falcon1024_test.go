package falcon1024_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"testing"

	. "github.com/theQRL/go-qrllib/crypto/falcon1024"
	internal "github.com/theQRL/go-qrllib/crypto/internal/falcon1024"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	clear(buf)
	return len(buf), nil
}

func TestRoundTrip(t *testing.T) {
	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}
	if len(public.Bytes()) != PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(public.Bytes()), PublicKeySize)
	}
	if len(private.Bytes()) != PrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(private.Bytes()), PrivateKeySize)
	}

	derivedPublic := private.Public().(*PublicKey)
	if !bytes.Equal(derivedPublic.Bytes(), public.Bytes()) {
		t.Fatal("private key returned unexpected public key")
	}
	if !public.Equal(derivedPublic) {
		t.Fatal("derived public key is not equal to public key")
	}
	if !private.Equal(private) {
		t.Fatal("private key is not equal to itself")
	}

	publicBytes := public.Bytes()
	publicBytes[0] ^= 1
	if bytes.Equal(public.Bytes(), publicBytes) {
		t.Fatal("PublicKey.Bytes returned internal buffer")
	}
	privateBytes := private.Bytes()
	privateBytes[0] ^= 1
	if bytes.Equal(private.Bytes(), privateBytes) {
		t.Fatal("PrivateKey.Bytes returned internal buffer")
	}

	zeroSeed := make([]byte, SeedSize)
	privateFromSeed, err := NewPrivateKeyFromSeed(zeroSeed)
	if err != nil {
		t.Fatal(err)
	}
	publicFromSeed := privateFromSeed.Public().(*PublicKey)
	if !bytes.Equal(publicFromSeed.Bytes(), public.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKeyFromSeed returned different public keys")
	}
	if !bytes.Equal(privateFromSeed.Bytes(), private.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKeyFromSeed returned different private keys")
	}

	public1, err := NewPublicKey(public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(public.Bytes(), public1.Bytes()) {
		t.Fatal("public key encoding did not round-trip")
	}
	private1, err := NewPrivateKey(private.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private.Bytes(), private1.Bytes()) {
		t.Fatal("private key encoding did not round-trip")
	}
	if !private.Equal(private1) {
		t.Fatal("decoded private key is not equal to the original")
	}

	message := []byte("test message")
	signedMessage, err := Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(signedMessage) > len(message)+MaxSignedMessageOverhead {
		t.Fatalf("signed message length = %d, want at most %d", len(signedMessage), len(message)+MaxSignedMessageOverhead)
	}
	opened, err := Open(public1, signedMessage)
	if err != nil {
		t.Fatalf("valid signed message rejected: %v", err)
	}
	if !bytes.Equal(opened, message) {
		t.Fatal("Open returned a different message")
	}

	signedMessage1, err := private1.Sign(zero, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signedMessage1, signedMessage) {
		t.Fatal("decoded private key signed differently with the same randomness")
	}

	modified := bytes.Clone(signedMessage)
	modified[len(modified)-1] ^= 0x80
	if _, err = Open(public1, modified); err == nil {
		t.Fatal("modified signature accepted")
	}
	modified = bytes.Clone(signedMessage)
	modified[2+40] ^= 1
	if _, err = Open(public1, modified); err == nil {
		t.Fatal("modified message accepted")
	}

	signature, err := SignDetached(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) > MaxSignatureSize {
		t.Fatalf("detached signature length = %d, want at most %d", len(signature), MaxSignatureSize)
	}
	if !Verify(public1, message, signature) {
		t.Fatal("valid detached signature rejected")
	}
	if Verify(public1, []byte("wrong message"), signature) {
		t.Fatal("detached signature of different message accepted")
	}
	signature1, err := private1.SignDetached(zero, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature1, signature) {
		t.Fatal("decoded private key produced a different detached signature with the same randomness")
	}
	modifiedSignature := bytes.Clone(signature)
	modifiedSignature[len(modifiedSignature)-1] ^= 0x80
	if Verify(public1, message, modifiedSignature) {
		t.Fatal("modified detached signature accepted")
	}

	otherPublic, otherPrivate, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if public.Equal(otherPublic) {
		t.Fatal("different public keys are Equal")
	}
	if _, err = Open(otherPublic, signedMessage); err == nil {
		t.Fatal("signed message accepted with a different public key")
	}
	if Verify(otherPublic, message, signature) {
		t.Fatal("detached signature accepted with a different public key")
	}
	if private.Equal(otherPrivate) {
		t.Fatal("different private keys are Equal")
	}
	if bytes.Equal(private.Bytes(), otherPrivate.Bytes()) {
		t.Fatal("GenerateKey returned the same private key twice")
	}

	_, randomPrivate, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(private.Bytes(), randomPrivate.Bytes()) {
		t.Fatal("GenerateKey returned the same private key twice")
	}
	randomSigned, err := randomPrivate.Sign(nil, message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(randomPrivate.Public().(*PublicKey), randomSigned); err != nil {
		t.Fatalf("signed message with crypto/rand randomness rejected: %v", err)
	}

	seed := testSeed()
	_, generatedFromSeed, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	privateFromTestSeed, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generatedFromSeed.Bytes(), privateFromTestSeed.Bytes()) {
		t.Fatal("GenerateKey with seed gave different private key")
	}
}

func testSeed() []byte {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func TestInvalidInputs(t *testing.T) {
	for _, seed := range [][]byte{
		nil,
		make([]byte, SeedSize-1),
		make([]byte, SeedSize+1),
	} {
		if _, err := NewPrivateKeyFromSeed(seed); err == nil {
			t.Fatalf("NewPrivateKeyFromSeed accepted seed with length %d", len(seed))
		}
	}

	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("test message")
	signedMessage, err := Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}

	badHeaderPublic := bytes.Clone(public.Bytes())
	badHeaderPublic[0] ^= 0xFF
	for _, publicKey := range [][]byte{
		nil,
		make([]byte, PublicKeySize-1),
		make([]byte, PublicKeySize+1),
		badHeaderPublic,
	} {
		if _, err = NewPublicKey(publicKey); err == nil {
			t.Fatalf("NewPublicKey accepted invalid public key with length %d", len(publicKey))
		}
	}

	badHeaderPrivate := bytes.Clone(private.Bytes())
	badHeaderPrivate[0] ^= 0xFF
	for _, privateKey := range [][]byte{
		nil,
		make([]byte, PrivateKeySize-1),
		make([]byte, PrivateKeySize+1),
		badHeaderPrivate,
	} {
		if _, err = NewPrivateKey(privateKey); err == nil {
			t.Fatalf("NewPrivateKey accepted invalid private key with length %d", len(privateKey))
		}
	}

	sigOffset := 2 + 40 + len(message)
	for _, sm := range [][]byte{
		nil,
		signedMessage[:2+40-1],
		signedMessage[:len(signedMessage)-1],
		append(bytes.Clone(signedMessage), 0),
		append(bytes.Clone(signedMessage[:sigOffset]), signedMessage[sigOffset]^0xFF),
	} {
		if _, err = Open(public, sm); err == nil {
			t.Fatalf("Open accepted invalid signed message with length %d", len(sm))
		}
	}

	if _, err = Sign(bytes.NewReader(make([]byte, 40)), private, message); err == nil {
		t.Fatal("Sign succeeded without enough randomness for the sampler seed")
	}

	signature, err := SignDetached(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range [][]byte{
		nil,
		signature[:40],
		signature[:len(signature)-1],
		append(bytes.Clone(signature), 0),
		append([]byte{signature[0] ^ 0xFF}, signature[1:]...),
	} {
		if Verify(public, message, sig) {
			t.Fatalf("Verify accepted invalid detached signature with length %d", len(sig))
		}
	}
	if _, err := SignDetached(bytes.NewReader(make([]byte, 40)), private, message); err == nil {
		t.Fatal("SignDetached succeeded without enough randomness for the sampler seed")
	}
}

// TestAccumulated accumulates deterministic operations and checks the hash of
// the result instead of checking in large vector files.
func TestAccumulated(t *testing.T) {
	const expected = "73e6b1af517fdfe4dc674e7e9e5165c3460f5a02bb1e6bf412bb4bae55ad9b82"

	s := sha3.NewSHAKE128()
	o := sha3.NewSHAKE128()
	seed := make([]byte, SeedSize)
	randomness := make([]byte, 40+SeedSize)
	var message [32]byte

	for range 16 {
		_, _ = s.Read(seed)
		private, err := NewPrivateKeyFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		public := private.Public().(*PublicKey)
		_, _ = o.Write(public.Bytes())
		_, _ = o.Write(private.Bytes())

		_, _ = s.Read(message[:])
		_, _ = s.Read(randomness)
		signedMessage, err := Sign(bytes.NewReader(randomness), private, message[:])
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(public, signedMessage)
		if err != nil {
			t.Fatalf("valid signed message rejected: %v", err)
		}
		if !bytes.Equal(opened, message[:]) {
			t.Fatal("Open returned a different message")
		}
		_, _ = o.Write(signedMessage)

		signature, err := SignDetached(bytes.NewReader(randomness), private, message[:])
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(public, message[:], signature) {
			t.Fatal("valid detached signature rejected")
		}
		_, _ = o.Write(signature)
	}

	var digest [32]byte
	_, _ = o.Read(digest[:])
	got := hex.EncodeToString(digest[:])
	if got != expected {
		t.Errorf("got %s, expected %s", got, expected)
	}
}

func TestConstantSizes(t *testing.T) {
	if SeedSize != internal.SeedSize {
		t.Errorf("SeedSize mismatch: got %d, want %d", SeedSize, internal.SeedSize)
	}

	if PrivateKeySize != internal.PrivateKeySize {
		t.Errorf("PrivateKeySize mismatch: got %d, want %d", PrivateKeySize, internal.PrivateKeySize)
	}

	if PublicKeySize != internal.PublicKeySize {
		t.Errorf("PublicKeySize mismatch: got %d, want %d", PublicKeySize, internal.PublicKeySize)
	}

	if MaxSignedMessageOverhead != internal.MaxSignedMessageOverhead {
		t.Errorf("MaxSignedMessageOverhead mismatch: got %d, want %d", MaxSignedMessageOverhead, internal.MaxSignedMessageOverhead)
	}

	if MaxSignatureSize != internal.MaxSignatureSize {
		t.Errorf("MaxSignatureSize mismatch: got %d, want %d", MaxSignatureSize, internal.MaxSignatureSize)
	}
}

// sink keeps benchmark results observable so the compiler cannot eliminate the
// work being measured.
var sink byte

func BenchmarkGenerateKey(b *testing.B) {
	var zero zeroReader
	for b.Loop() {
		public, private, err := GenerateKey(zero)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= public.Bytes()[0] ^ private.Bytes()[0]
	}
}

func BenchmarkNewPrivateKeyFromSeed(b *testing.B) {
	seed := make([]byte, SeedSize)
	for b.Loop() {
		private, err := NewPrivateKeyFromSeed(seed)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= private.Bytes()[0]
	}
}

func BenchmarkNewPrivateKey(b *testing.B) {
	private, err := NewPrivateKeyFromSeed(make([]byte, SeedSize))
	if err != nil {
		b.Fatal(err)
	}
	encoded := private.Bytes()
	for b.Loop() {
		private, err := NewPrivateKey(encoded)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= private.Bytes()[0]
	}
}

func BenchmarkSign(b *testing.B) {
	var zero zeroReader
	_, private, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	for b.Loop() {
		signedMessage, err := Sign(zero, private, message)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= signedMessage[0]
	}
}

func BenchmarkOpen(b *testing.B) {
	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signedMessage, err := Sign(zero, private, message)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		opened, err := Open(public, signedMessage)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= opened[0]
	}
}

func BenchmarkSignDetached(b *testing.B) {
	var zero zeroReader
	_, private, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	for b.Loop() {
		signature, err := SignDetached(zero, private, message)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= signature[0]
	}
}

func BenchmarkVerify(b *testing.B) {
	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature, err := SignDetached(zero, private, message)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if !Verify(public, message, signature) {
			b.Fatal("signature rejected")
		}
	}
}
