package mlkem1024

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
)

const (
	// ML-KEM global parameters.
	n = 256
	q = 3329

	// ML-KEM-1024 parameter.
	k = 4

	// Byte lengths of ByteEncode_d(f) output (FIPS 203, Algorithm 5).
	encodingSize1  = n * 1 / 8
	encodingSize5  = n * 5 / 8
	encodingSize11 = n * 11 / 8
	encodingSize12 = n * 12 / 8

	// ML-KEM messages are 32-byte values encoded as ByteEncode_1(m).
	messageSize = encodingSize1

	SharedKeySize = 32
	SeedSize      = 32 + 32

	// ML-KEM-1024 encoded sizes.
	CiphertextSize       = k*encodingSize11 + encodingSize5
	EncapsulationKeySize = k*encodingSize12 + 32
)

type DecapsulationKey struct {
	d, z [32]byte // decapsulation key seeds
	h    [32]byte // H(ekPKE)
	encryptionKey
	decryptionKey
}

func NewDecapsulationKey(seed []byte) (*DecapsulationKey, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("ml-kem-1024: invalid seed length")
	}

	dk := &DecapsulationKey{}
	d := (*[32]byte)(seed[:32])
	z := (*[32]byte)(seed[32:])

	generateKey(dk, d, z)

	return dk, nil
}

func (dk *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != CiphertextSize {
		return nil, errors.New("ml-kem-1024: invalid ciphertext length")
	}

	return decapsulate(dk, (*[CiphertextSize]byte)(ciphertext)), nil
}

func decapsulate(dk *DecapsulationKey, ct *[CiphertextSize]byte) (sharedKey []byte) {
	var m [messageSize]byte

	pkeDecrypt(&m, dk, ct)

	var gInput [messageSize + 32]byte
	copy(gInput[:messageSize], m[:])
	copy(gInput[messageSize:], dk.h[:])
	G := sha3.Sum512(gInput[:])
	K := G[:SharedKeySize]
	r := (*[32]byte)(G[SharedKeySize:])

	J := sha3.NewSHAKE256()
	_, _ = J.Write(dk.z[:])
	_, _ = J.Write(ct[:])
	Kout := make([]byte, SharedKeySize)
	_, _ = J.Read(Kout)

	var c [CiphertextSize]byte
	pkeEncrypt(&c, &dk.encryptionKey, &m, r)

	subtle.ConstantTimeCopy(subtle.ConstantTimeCompare(ct[:], c[:]), Kout, K)

	return Kout
}

func (dk *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	return &EncapsulationKey{
		h:             dk.h,
		encryptionKey: dk.encryptionKey,
	}
}

func (dk *DecapsulationKey) Bytes() []byte {
	var b [SeedSize]byte
	copy(b[:], dk.d[:])
	copy(b[32:], dk.z[:])

	return b[:]
}

type EncapsulationKey struct {
	h [32]byte // H(ek)
	encryptionKey
}

func NewEncapsulationKey(ekBytes []byte) (*EncapsulationKey, error) {
	if len(ekBytes) != EncapsulationKeySize {
		return nil, errors.New("ml-kem-1024: invalid encapsulation key length")
	}

	ek := &EncapsulationKey{}

	ek.h = sha3.Sum256(ekBytes)
	copy(ek.encoded[:], ekBytes)

	for i := range ek.t {
		if err := byteDecode12(&ek.t[i], (*[encodingSize12]byte)(ekBytes[:encodingSize12])); err != nil {
			return nil, err
		}
		ekBytes = ekBytes[encodingSize12:]
	}
	copy(ek.rho[:], ekBytes)

	for i := range k {
		for j := range k {
			sampleNTT(&ek.a[i*k+j], &ek.rho, byte(j), byte(i))
		}
	}

	return ek, nil
}

func (ek *EncapsulationKey) Encapsulate() (sharedKey, ciphertext []byte, err error) {
	var m [32]byte
	_, _ = rand.Read(m[:])

	var ct [CiphertextSize]byte
	sharedKey = encapsulateTo(&ct, ek, &m)

	return sharedKey, ct[:], nil
}

// EncapsulateInternal is a derandomized version of Encapsulate, exclusively for
// use in tests.
func EncapsulateInternal(ek *EncapsulationKey, m *[32]byte) (sharedKey, ciphertext []byte) {
	var ct [CiphertextSize]byte
	sharedKey = encapsulateTo(&ct, ek, m)

	return sharedKey, ct[:]
}

func encapsulateTo(dst *[CiphertextSize]byte, ek *EncapsulationKey, m *[32]byte) []byte {
	var gInput [messageSize + 32]byte
	copy(gInput[:messageSize], m[:])
	copy(gInput[messageSize:], ek.h[:])
	G := sha3.Sum512(gInput[:])
	K := G[:SharedKeySize]
	r := (*[32]byte)(G[SharedKeySize:])

	pkeEncrypt(dst, &ek.encryptionKey, m, r)

	sharedKey := make([]byte, SharedKeySize)
	copy(sharedKey, K)
	return sharedKey
}

func (ek *EncapsulationKey) Bytes() []byte {
	b := new([EncapsulationKeySize]byte)
	copy(b[:], ek.encoded[:])

	return b[:]
}

type encryptionKey struct {
	t       [k]ringElement             // public key vector in NTT domain
	a       [k * k]ringElement         // public matrix A in NTT domain
	rho     [32]byte                   // matrix seed
	encoded [EncapsulationKeySize]byte // encoded t || rho
}

type decryptionKey struct {
	s [k]ringElement // secret key vector in NTT domain
}

func GenerateKey() (*DecapsulationKey, error) {
	var d, z [32]byte
	_, _ = rand.Read(d[:])
	_, _ = rand.Read(z[:])
	dk := &DecapsulationKey{}

	generateKey(dk, &d, &z)

	return dk, nil
}

func generateKey(dk *DecapsulationKey, d, z *[32]byte) {
	dk.d, dk.z = *d, *z

	pkeKeyGen(dk, d)

	dk.h = sha3.Sum256(dk.encoded[:])
}

// GenerateKeyInternal is a derandomized version of GenerateKey,
// exclusively for use in tests.
func GenerateKeyInternal(d, z *[32]byte) *DecapsulationKey {
	dk := &DecapsulationKey{}
	generateKey(dk, d, z)
	return dk
}
