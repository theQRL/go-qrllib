package falcon1024_test

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	. "github.com/theQRL/go-qrllib/crypto/falcon1024"
)

// noPanic runs f and fails the test if it panics, so a guard that is removed
// later fails here rather than in a caller.
func noPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", name, r)
		}
	}()
	f()
}

// Every public entry point refuses a nil or zero-value key instead of
// panicking (SECURITY.md, "Panic policy").
func TestNilAndZeroValueKeys(t *testing.T) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("nil and zero-value keys")
	signature, err := SignDetached(nil, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	signedMessage, err := Sign(nil, priv, message)
	if err != nil {
		t.Fatal(err)
	}

	var nilPub *PublicKey
	var nilPriv *PrivateKey
	// A nil pointer and a zero value that never went through a constructor
	// are distinct states, reported with the sentinels ML-DSA-87 uses
	// (SECURITY.md, "Keypair lifecycle").
	publicKeys := map[string]struct {
		key  *PublicKey
		want error
	}{
		"nil":        {nilPub, cryptoerrors.ErrPublicKeyNil},
		"zero value": {&PublicKey{}, cryptoerrors.ErrInvalidPublicKey},
	}
	privateKeys := map[string]struct {
		key  *PrivateKey
		want error
	}{
		"nil":        {nilPriv, cryptoerrors.ErrSecretKeyNil},
		"zero value": {&PrivateKey{}, cryptoerrors.ErrKeyUninitialised},
	}

	for name, tc := range publicKeys {
		pk, want := tc.key, tc.want
		noPanic(t, "Verify/"+name, func() {
			if Verify(pk, message, signature) {
				t.Errorf("Verify(%s public key) = true", name)
			}
		})
		noPanic(t, "Open/"+name, func() {
			m, err := Open(pk, signedMessage)
			if m != nil || !errors.Is(err, want) {
				t.Errorf("Open(%s public key) = %v, %v; want nil, %v", name, m, err, want)
			}
		})
		noPanic(t, "PublicKey.Bytes/"+name, func() {
			if pk.Bytes() != nil {
				t.Errorf("(%s public key).Bytes() != nil", name)
			}
		})
		noPanic(t, "PublicKey.Equal/"+name, func() {
			if pk.Equal(pub) || pub.Equal(pk) || pk.Equal(pk) {
				t.Errorf("%s public key compared Equal", name)
			}
		})
	}

	for name, tc := range privateKeys {
		sk, want := tc.key, tc.want
		noPanic(t, "Sign/"+name, func() {
			sm, err := Sign(nil, sk, message)
			if sm != nil || !errors.Is(err, want) {
				t.Errorf("Sign(%s private key) = %v, %v; want nil, %v", name, sm, err, want)
			}
		})
		noPanic(t, "SignDetached/"+name, func() {
			sig, err := SignDetached(nil, sk, message)
			if sig != nil || !errors.Is(err, want) {
				t.Errorf("SignDetached(%s private key) = %v, %v; want nil, %v", name, sig, err, want)
			}
		})
		noPanic(t, "PrivateKey.Sign/"+name, func() {
			if _, err := sk.Sign(nil, message); !errors.Is(err, want) {
				t.Errorf("(%s private key).Sign error = %v; want %v", name, err, want)
			}
		})
		noPanic(t, "PrivateKey.SignDetached/"+name, func() {
			if _, err := sk.SignDetached(nil, message); !errors.Is(err, want) {
				t.Errorf("(%s private key).SignDetached error = %v; want %v", name, err, want)
			}
		})
		noPanic(t, "PrivateKey.Bytes/"+name, func() {
			if sk.Bytes() != nil {
				t.Errorf("(%s private key).Bytes() != nil", name)
			}
		})
		noPanic(t, "PrivateKey.Public/"+name, func() {
			if sk.Public() != nil {
				t.Errorf("(%s private key).Public() != nil", name)
			}
		})
		noPanic(t, "PrivateKey.Equal/"+name, func() {
			if sk.Equal(priv) || priv.Equal(sk) || sk.Equal(sk) {
				t.Errorf("%s private key compared Equal", name)
			}
		})
		noPanic(t, "PrivateKey.Zeroize/"+name, sk.Zeroize)
	}

	// Equal against a value of another type is false, not a panic.
	noPanic(t, "Equal/foreign type", func() {
		if pub.Equal("not a key") || priv.Equal(42) {
			t.Error("Equal reported a foreign type as equal")
		}
	})
}
