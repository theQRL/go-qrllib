package falcon1024

import (
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Seeds of the deterministic SHAKE256 streams that drive the loops below. The
// pinned digests depend on them.
const (
	signLoopSeed   = "sign :"
	keygenLoopSeed = "keygen :"
)

// SHAKE256 digests that pin the exact output of the loops below. Checking
// that signatures verify would not notice a change in key generation,
// sampling or signing arithmetic that still yields valid signatures; the
// digests do.
//
//   - keygenLoopDigest covers the 12 rounds of TestKeygenSelfSignLoop,
//     absorbing each encoded public key followed by its signature.
//   - signLoopDigest covers the 200 signatures that signLoop makes with the
//     first key of the keygen loop, each absorbed as n little-endian int16
//     values; see TestSignSelfVerifyLoop.
const (
	keygenLoopDigest = "72bcb4a3b250a8052d5f8069400ecb1f316d4fcacfdce850955cc64d1eff5b1f"
	signLoopDigest   = "250f93901c18fe41a1867869d25c0c10db32c35e10ee337f0d6ca3f73eee308a"
)

// absorbSmallPolynomial feeds a polynomial into a digest as little-endian
// 16-bit values.
func absorbSmallPolynomial(sc *sha3.SHAKE, p smallPolynomial) {
	var buf [2 * n]byte
	for i, x := range p {
		binary.LittleEndian.PutUint16(buf[2*i:], uint16(int16(x)))
	}
	_, _ = sc.Write(buf[:])
}

func requireDigest(t *testing.T, name string, sc *sha3.SHAKE, want string) {
	t.Helper()

	var got [32]byte
	_, _ = sc.Read(got[:])
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("%s digest = %x, want %s", name, got, want)
	}
}

// signLoop draws 200 random 50-byte messages (nonce + plain) and the
// randomness of every signature from one SHAKE stream, checks that every
// signature verifies, and returns a digest of all signatures.
func signLoop(t *testing.T, priv *PrivateKey, pub *PublicKey) *sha3.SHAKE {
	t.Helper()

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte(signLoopSeed))
	digest := sha3.NewSHAKE256()

	for i := range 200 {
		var msg [50]byte
		_, _ = rng.Read(msg[:])

		sc := sha3.NewSHAKE256()
		_, _ = sc.Write(msg[:])
		c0 := hashToPoint(sc)

		s2 := sign(rng, priv, c0)
		if !verifyRaw(c0, s2, pub.hNTT) {
			t.Fatalf("signature %d not verified", i)
		}
		absorbSmallPolynomial(digest, s2)
	}

	return digest
}

func TestSignSelfVerifyLoop(t *testing.T) {
	t.Run("fixed key", func(t *testing.T) {
		// This only checks that the signatures verify. The fixed key lies
		// outside of what Falcon-1024 key generation accepts: some leaves of
		// its LDL tree have 1/sigma above 1/sigma_min, so the sampler sees
		// ccs = sigma_min/sigma > 1 and fprExpmP63 overflows its fixed-point
		// conversion. The signatures are still valid, but their exact value
		// is not pinned. Keys made by key generation always have ccs <= 1;
		// their signatures are pinned below.
		f := mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex)
		g := mustDecodeSmallPolynomialHex(t, ntruSmallG1024Hex)
		ntruF := mustDecodeSmallPolynomialHex(t, ntruF1024Hex)
		ntruG := mustDecodeSmallPolynomialHex(t, ntruG1024Hex)

		h, ok := computePublic(f, g)
		if !ok {
			t.Fatal("computePublic rejected fixed f/g pair")
		}
		priv := &PrivateKey{}
		if _, err := initPrivateKey(priv, f, g, ntruF, ntruG, h); err != nil {
			t.Fatal(err)
		}
		pub, err := NewPublicKey(referencePublicKeyBytes(t))
		if err != nil {
			t.Fatal(err)
		}

		signLoop(t, priv, pub)
	})

	t.Run("generated key", func(t *testing.T) {
		rng := sha3.NewSHAKE256()
		_, _ = rng.Write([]byte(keygenLoopSeed))
		priv, err := keygen(&PrivateKey{}, rng)
		if err != nil {
			t.Fatal(err)
		}

		digest := signLoop(t, priv, priv.PublicKey())
		requireDigest(t, "signatures", digest, signLoopDigest)
	})
}

// isInvertible reports whether s2 is invertible modulo X^n+1 and q, which
// holds iff none of its NTT coefficients is zero.
func isInvertible(s2 smallPolynomial) bool {
	var t ringElement
	for i := range t {
		t[i] = fieldFromSmall(s2[i])
	}
	ntt(t[:])
	for _, x := range t {
		if x == 0 {
			return false
		}
	}
	return true
}

func TestKeygenSelfSignLoop(t *testing.T) {
	// Generate 12 key pairs and check that each one signs a random message
	// that its public key verifies.
	//
	// Signing is repeated until s2 is invertible, the condition under which a
	// public key could be recovered from a signature. With this seed that
	// takes three extra signatures, and the pinned digest depends on them.
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte(keygenLoopSeed))
	digest := sha3.NewSHAKE256()

	for i := range 12 {
		priv, err := keygen(&PrivateKey{}, rng)
		if err != nil {
			t.Fatal(err)
		}
		pub := priv.PublicKey()

		var msg [50]byte // nonce + message
		_, _ = rng.Read(msg[:])

		sc := sha3.NewSHAKE256()
		_, _ = sc.Write(msg[:])
		c0 := hashToPoint(sc)

		s2 := sign(rng, priv, c0)
		for !isInvertible(s2) {
			s2 = sign(rng, priv, c0)
		}
		if !verifyRaw(c0, s2, pub.hNTT) {
			t.Fatalf("key %d: self signature not verified", i)
		}

		_, _ = digest.Write(pub.Bytes())
		absorbSmallPolynomial(digest, s2)
	}

	requireDigest(t, "keys and signatures", digest, keygenLoopDigest)
}
