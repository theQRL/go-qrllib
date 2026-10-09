package ml_dsa_87

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// TestNilReceiversDoNotPanic pins the panic policy for methods called on a
// nil *MLDSA87 or *PublicKey: signing refuses with ErrSecretKeyNil, Zeroize
// is a no-op, and the accessors return zero values.
func TestNilReceiversDoNotPanic(t *testing.T) {
	var d *MLDSA87
	message := []byte("nil receiver")
	if _, err := d.Sign(nil, message); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Errorf("Sign on nil: error = %v, want ErrSecretKeyNil", err)
	}
	if _, err := d.SignDeterministic(nil, message); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Errorf("SignDeterministic on nil: error = %v, want ErrSecretKeyNil", err)
	}
	if _, err := d.SignAttached(nil, message); !errors.Is(err, cryptoerrors.ErrSecretKeyNil) {
		t.Errorf("SignAttached on nil: error = %v, want ErrSecretKeyNil", err)
	}
	d.Zeroize()
	if d.GetPK() != ([CRYPTO_PUBLIC_KEY_BYTES]uint8{}) || d.GetSK() != ([CRYPTO_SECRET_KEY_BYTES]uint8{}) || d.GetSeed() != ([SEED_BYTES]uint8{}) {
		t.Error("accessors on a nil receiver returned non-zero values")
	}
	if got := d.GetHexSeed(); got != "" {
		t.Errorf("GetHexSeed on nil = %q, want empty", got)
	}
	if d.PublicKey() != nil {
		t.Error("PublicKey on nil returned a key")
	}

	var pk *PublicKey
	if pk.Bytes() != ([CRYPTO_PUBLIC_KEY_BYTES]uint8{}) {
		t.Error("Bytes on a nil public key returned non-zero values")
	}
	if pk.Equal(pk) {
		t.Error("nil public key compared Equal to itself")
	}
}
