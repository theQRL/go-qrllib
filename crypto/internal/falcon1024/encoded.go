package falcon1024

import (
	"crypto/sha3"
	"errors"
)

var errInvalidPrivateKey = errors.New("falcon-1024: invalid private key")

// TestingOnlyNewPrivateKeyFromEncoded creates a private key from the Falcon
// encoded private-key form, for testing purposes.
//
// Bytes must not be called on the resulting key, as it will return a
// deterministic placeholder seed rather than the encoded private key.
func TestingOnlyNewPrivateKeyFromEncoded(privBytes []byte) (*PrivateKey, error) {
	f, g, ntruF, err := skDecode(privBytes)
	if err != nil {
		return nil, err
	}

	ntruG, ok := completePrivate(f, g, ntruF)
	if !ok {
		return nil, errInvalidPrivateKey
	}

	h, ok := computePublic(f, g)
	if !ok {
		return nil, errInvalidPrivateKey
	}

	priv := &PrivateKey{}
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write(privBytes)
	_, _ = shake.Read(priv.seed[:])

	return initPrivateKey(priv, f, g, ntruF, ntruG, h)
}

// TestingOnlyNewPrivateKeyWithEncodedBytes returns the seed-backed private key
// and Falcon encoded private-key bytes generated from seed, for testing
// purposes.
func TestingOnlyNewPrivateKeyWithEncodedBytes(seed []byte) (*PrivateKey, []byte, error) {
	if len(seed) != SeedSize {
		return nil, nil, errInvalidSeedLength
	}

	priv := &PrivateKey{}
	copy(priv.seed[:], seed)

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write(seed)

	f, g, ntruF, ntruG, h := generateKeyComponents(rng)

	privBytes := make([]byte, encodedPrivateKeySize)
	if err := skEncode(privBytes, f, g, ntruF); err != nil {
		return nil, nil, err
	}

	priv, err := initPrivateKey(priv, f, g, ntruF, ntruG, h)
	if err != nil {
		return nil, nil, err
	}

	return priv, privBytes, nil
}
