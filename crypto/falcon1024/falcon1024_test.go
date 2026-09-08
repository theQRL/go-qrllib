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
	_, _ = zero.Read(zeroSeed)
	privateFromSeed, err := NewPrivateKey(zeroSeed)
	if err != nil {
		t.Fatal(err)
	}
	publicFromSeed := privateFromSeed.Public().(*PublicKey)
	if !bytes.Equal(publicFromSeed.Bytes(), public.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKey returned different public keys")
	}
	if !bytes.Equal(privateFromSeed.Bytes(), private.Bytes()) {
		t.Fatal("GenerateKey and NewPrivateKey returned different private keys")
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
		t.Fatal("private key seed did not round-trip")
	}

	message := []byte("test message")
	signature, err := Sign(zero, private, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(signature), SignatureSize)
	}
	if !Verify(public1, message, signature) {
		t.Fatal("valid signature rejected")
	}
	if Verify(public1, []byte("wrong message"), signature) {
		t.Fatal("signature of different message accepted")
	}

	signature1, err := private1.Sign(zero, message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(public1, message, signature1) {
		t.Fatal("PrivateKey.Sign signature rejected")
	}

	modifiedSignature := bytes.Clone(signature)
	modifiedSignature[SignatureSize-1] ^= 1
	if Verify(public1, message, modifiedSignature) {
		t.Fatal("modified signature accepted")
	}

	otherPublic, otherPrivate, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if public.Equal(otherPublic) {
		t.Fatal("different public keys are Equal")
	}
	if Verify(otherPublic, message, signature) {
		t.Fatal("signature accepted with a different public key")
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

	seed := testSeed()
	_, generatedFromSeed, err := GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	privateFromTestSeed, err := NewPrivateKey(seed)
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

func TestInvalidInputLengths(t *testing.T) {
	for _, seed := range [][]byte{
		nil,
		make([]byte, SeedSize-1),
		make([]byte, SeedSize+1),
	} {
		if _, err := NewPrivateKey(seed); err == nil {
			t.Fatalf("NewPrivateKey accepted seed with length %d", len(seed))
		}
	}

	var zero zeroReader
	public, private, err := GenerateKey(zero)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("test message")
	signature, err := Sign(zero, private, message)
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
		if _, err := NewPublicKey(publicKey); err == nil {
			t.Fatalf("NewPublicKey accepted invalid public key with length %d", len(publicKey))
		}
	}

	for _, sig := range [][]byte{
		nil,
		make([]byte, SignatureSize-1),
		make([]byte, SignatureSize+1),
		append([]byte{signature[0] ^ 0xFF}, signature[1:]...),
	} {
		if Verify(public, message, sig) {
			t.Fatalf("Verify accepted invalid signature with length %d", len(sig))
		}
	}
}

// TestAccumulated accumulates deterministic operations and checks the hash of
// the result instead of checking in large vector files.
func TestAccumulated(t *testing.T) {
	const expected = "ae200d33ef07d795d68e34bfa1b710c52f1ebb28e7c7ee7157c5443a552925c8"

	s := sha3.NewSHAKE128()
	o := sha3.NewSHAKE128()
	seed := make([]byte, SeedSize)
	signSeed := make([]byte, SeedSize)
	var message [32]byte

	for range 16 {
		_, _ = s.Read(seed)
		private, err := NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		public := private.Public().(*PublicKey)
		_, _ = o.Write(public.Bytes())
		_, _ = o.Write(private.Bytes())

		_, _ = s.Read(message[:])
		_, _ = s.Read(signSeed)
		signature, err := Sign(bytes.NewReader(signSeed), private, message[:])
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(public, message[:], signature) {
			t.Fatal("valid signature rejected")
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

	if PrivateKeySize != internal.SeedSize {
		t.Errorf("PrivateKeySize mismatch: got %d, want %d", PrivateKeySize, internal.SeedSize)
	}

	if PublicKeySize != internal.PublicKeySize {
		t.Errorf("PublicKeySize mismatch: got %d, want %d", PublicKeySize, internal.PublicKeySize)
	}

	if SignatureSize != internal.SignatureSize {
		t.Errorf("SignatureSize mismatch: got %d, want %d", SignatureSize, internal.SignatureSize)
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

func BenchmarkNewPrivateKey(b *testing.B) {
	seed := make([]byte, SeedSize)
	for b.Loop() {
		private, err := NewPrivateKey(seed)
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
		signature, err := Sign(zero, private, message)
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
	signature, err := Sign(zero, private, message)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if !Verify(public, message, signature) {
			b.Fatal("signature rejected")
		}
	}
}
