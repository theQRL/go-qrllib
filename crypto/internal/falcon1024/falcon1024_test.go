package falcon1024

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"hash"
	"strconv"
	"testing"
)

func TestVerifyRaw(t *testing.T) {
	vectors := readVerifyRawKATFixture(t)

	pubBytes := mustDecodeHex(t, vectors.PublicKeyHex)
	pub, err := NewPublicKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range vectors.Tests {
		t.Run(tc.Message, func(t *testing.T) {
			nonce := mustDecodeHex(t, tc.NonceHex)
			s2 := decodeVerifyRawKATS2(t, mustDecodeHex(t, tc.SignatureHex))

			h := sha3.NewSHAKE256()
			_, _ = h.Write(nonce)
			_, _ = h.Write([]byte(tc.Message))

			c0 := hashToPoint(h)
			if !verifyRaw(c0, s2, pub.hNTT) {
				t.Fatal("reference verify_raw vector rejected")
			}
		})
	}
}

func TestNewPublicKey(t *testing.T) {
	// Derived from the Falcon reference implementation test_falcon.c
	// ntru_pkey_1024 array.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	pubBytes := referencePublicKeyBytes(t)
	h, err := pkDecode(pubBytes)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := NewPublicKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	hNTT := h
	toNTTMonty(hNTT[:])
	if pub.hNTT != hNTT {
		t.Fatal("NewPublicKey cached unexpected public key polynomial")
	}
}

func TestComputePublic(t *testing.T) {
	// Derived from the Falcon reference implementation test_falcon.c
	// ntru_f_1024, ntru_g_1024, and ntru_pkey_1024 arrays.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	f := mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex)
	g := mustDecodeSmallPolynomialHex(t, ntruSmallG1024Hex)

	wantBytes := referencePublicKeyBytes(t)
	wantH, err := pkDecode(wantBytes)
	if err != nil {
		t.Fatal(err)
	}

	gotH, ok := computePublic(f, g)
	if !ok {
		t.Fatal("computePublic rejected reference f/g pair")
	}
	if gotH != wantH {
		t.Fatal("computePublic returned unexpected public key polynomial")
	}

	gotBytes := make([]byte, PublicKeySize)
	if err := pkEncode(gotBytes, gotH); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatal("computePublic encoded public key does not match reference ntru_pkey_1024")
	}
}

func TestCompletePrivate(t *testing.T) {
	// Derived from the Falcon reference implementation test_falcon.c
	// ntru_f_1024, ntru_g_1024, ntru_F_1024, and ntru_G_1024 arrays.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	f := mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex)
	g := mustDecodeSmallPolynomialHex(t, ntruSmallG1024Hex)
	ntruF := mustDecodeSmallPolynomialHex(t, ntruF1024Hex)
	wantG := mustDecodeSmallPolynomialHex(t, ntruG1024Hex)

	gotG, ok := completePrivate(f, g, ntruF)
	if !ok {
		t.Fatal("completePrivate rejected reference f/g/F tuple")
	}
	if gotG != wantG {
		t.Fatal("completePrivate returned unexpected G")
	}
}

func TestSignTree(t *testing.T) {
	// Derived from the Falcon reference implementation test_falcon.c
	// ntru_f_1024, ntru_g_1024, ntru_F_1024, ntru_G_1024, and
	// ntru_pkey_1024 arrays. The reference publishes the key components, not
	// deterministic sign-tree outputs, so this checks that signing with that
	// reference key produces signatures accepted by the reference public key.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	f := mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex)
	g := mustDecodeSmallPolynomialHex(t, ntruSmallG1024Hex)
	ntruF := mustDecodeSmallPolynomialHex(t, ntruF1024Hex)
	ntruG := mustDecodeSmallPolynomialHex(t, ntruG1024Hex)

	h, ok := computePublic(f, g)
	if !ok {
		t.Fatal("computePublic rejected reference f/g pair")
	}

	priv := &PrivateKey{}
	if _, err := initPrivateKey(priv, f, g, ntruF, ntruG, h); err != nil {
		t.Fatal(err)
	}

	pub, err := NewPublicKey(referencePublicKeyBytes(t))
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name    string
		message string
		seed    string
	}{
		{
			name:    "sample-0",
			message: "reference sign tree sample 0",
			seed:    "sign tree rng 0",
		},
		{
			name:    "sample-1",
			message: "reference sign tree sample 1",
			seed:    "sign tree rng 1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hashData := sha3.NewSHAKE256()
			_, _ = hashData.Write([]byte(tc.message))
			c0 := hashToPoint(hashData)

			rng := sha3.NewSHAKE256()
			_, _ = rng.Write([]byte(tc.seed))
			s2 := signTree(rng, priv, c0)
			if !verifyRaw(c0, s2, pub.hNTT) {
				t.Fatal("signTree output failed verifyRaw")
			}
		})
	}
}

func TestSignTreeRound3KATVectors(t *testing.T) {
	// These vectors are derived from Falcon Round 3 submission KATs, not
	// official NIST/FIPS validation vectors.
	// TestFalconRound3KATDigest checks the full 100-case transcript against the
	// Falcon reference digest; this test pins the internal signTree output
	// for every KAT case.
	// Source: https://falcon-sign.info/falcon-round3.zip
	testCases := readSignTreeRound3KATVectors(t)

	forEachRound3KATSignTreeInput(t, len(testCases), func(count int, priv *PrivateKey, c0 ringElement, rng *sha3.SHAKE) {
		tc := testCases[count]
		t.Run("count-"+strconv.Itoa(tc.Count), func(t *testing.T) {
			if tc.Count != count {
				t.Fatalf("count = %d, want %d", tc.Count, count)
			}
			s2 := signTree(rng, priv, c0)

			pub := priv.PublicKey()
			if !verifyRaw(c0, s2, pub.hNTT) {
				t.Fatal("signTree output failed verifyRaw")
			}

			comp := make([]byte, round3KATCompressedCapacity)
			written, err := compressedEncode(comp, s2)
			if err != nil {
				t.Fatal(err)
			}
			if written != tc.CompressedLength {
				t.Fatalf("compressed length = %d, want %d", written, tc.CompressedLength)
			}
			got := sha256.Sum256(comp[:written])
			if got := hex.EncodeToString(got[:]); got != tc.CompressedSHA256 {
				t.Fatalf("compressed SHA-256 = %s, want %s", got, tc.CompressedSHA256)
			}
		})
	})
}

func forEachRound3KATSignTreeInput(t *testing.T, count int, f func(int, *PrivateKey, ringElement, *sha3.SHAKE)) {
	t.Helper()

	var entropy [SeedSize]byte
	for i := range entropy {
		entropy[i] = byte(i)
	}

	drbg := newNISTDRBG(entropy[:])
	for i := range count {
		var seed [SeedSize]byte
		drbg.read(seed[:])

		msg := make([]byte, 33*(i+1))
		drbg.read(msg)

		state := drbg.save()
		drbg = newNISTDRBG(seed[:])

		var keySeed [SeedSize]byte
		drbg.read(keySeed[:])

		priv, err := NewPrivateKey(keySeed[:])
		if err != nil {
			t.Fatalf("NewPrivateKey: %v", err)
		}

		var nonce [nonceSize]byte
		drbg.read(nonce[:])

		hashData := sha3.NewSHAKE256()
		_, _ = hashData.Write(nonce[:])
		_, _ = hashData.Write(msg)

		c0 := hashToPoint(hashData)

		var signSeed [SeedSize]byte
		drbg.read(signSeed[:])
		rng := sha3.NewSHAKE256()
		_, _ = rng.Write(signSeed[:])

		f(i, priv, c0, rng)
		drbg.restore(state)
	}
}

const (
	round3KATSignatureSize         = 1330
	round3KATSignatureLengthSize   = 2
	round3KATMessageOffset         = round3KATSignatureLengthSize + nonceSize
	round3KATSignatureHeaderSize   = 1
	round3KATCompressedCapacity    = round3KATSignatureSize - round3KATMessageOffset - round3KATSignatureHeaderSize
	round3KATCompressedSignatureID = 0x20 + logN
)

type nistDRBG struct {
	key [32]byte
	v   [16]byte
}

type nistDRBGState struct {
	key [32]byte
	v   [16]byte
}

func newNISTDRBG(entropy []byte) *nistDRBG {
	d := &nistDRBG{}
	d.update(entropy)
	return d
}

func (d *nistDRBG) read(buf []byte) {
	block, err := aes.NewCipher(d.key[:])
	if err != nil {
		panic(err)
	}

	for len(buf) > 0 {
		d.increment()

		var tmp [aes.BlockSize]byte
		block.Encrypt(tmp[:], d.v[:])

		n := copy(buf, tmp[:])
		buf = buf[n:]
	}

	d.update(nil)
}

func (d *nistDRBG) update(provided []byte) {
	block, err := aes.NewCipher(d.key[:])
	if err != nil {
		panic(err)
	}

	var tmp [48]byte
	for i := range 3 {
		d.increment()
		block.Encrypt(tmp[i*aes.BlockSize:], d.v[:])
	}
	for i, b := range provided {
		tmp[i] ^= b
	}

	copy(d.key[:], tmp[:32])
	copy(d.v[:], tmp[32:])
}

func (d *nistDRBG) increment() {
	for i := len(d.v) - 1; i >= 0; i-- {
		d.v[i]++
		if d.v[i] != 0 {
			return
		}
	}
}

func (d *nistDRBG) save() nistDRBGState {
	return nistDRBGState{
		key: d.key,
		v:   d.v,
	}
}

func (d *nistDRBG) restore(state nistDRBGState) {
	d.key = state.key
	d.v = state.v
}

func TestFalconRound3KATDigest(t *testing.T) {
	// Reproduce the Falcon Round 3 submission KAT transcript compactly by
	// checking its SHA-1 digest.
	var entropy [SeedSize]byte
	for i := range entropy {
		entropy[i] = byte(i)
	}

	drbg := newNISTDRBG(entropy[:])
	h := sha1.New()

	katDigestWriteIntLine(h, "# Falcon-", n)
	katDigestWriteLine(h, "")

	for count := range 100 {
		var seed [SeedSize]byte
		drbg.read(seed[:])

		msg := make([]byte, 33*(count+1))
		drbg.read(msg)

		state := drbg.save()
		drbg = newNISTDRBG(seed[:])

		var keySeed [SeedSize]byte
		drbg.read(keySeed[:])

		priv, sk, err := TestingOnlyNewPrivateKeyWithEncodedBytes(keySeed[:])
		if err != nil {
			t.Fatalf("TestingOnlyNewPrivateKeyWithEncodedBytes: %v", err)
		}
		pub := priv.PublicKey().Bytes()

		var nonce [nonceSize]byte
		drbg.read(nonce[:])

		hashData := sha3.NewSHAKE256()
		_, _ = hashData.Write(nonce[:])
		_, _ = hashData.Write(msg)

		c0 := hashToPoint(hashData)

		var signSeed [SeedSize]byte
		drbg.read(signSeed[:])
		signRNG := sha3.NewSHAKE256()
		_, _ = signRNG.Write(signSeed[:])

		s2 := signTree(signRNG, priv, c0)

		comp := make([]byte, round3KATCompressedCapacity)
		written, err := compressedEncode(comp, s2)
		if err != nil {
			t.Fatalf("compressedEncode: %v", err)
		}

		sigLen := round3KATSignatureHeaderSize + written
		smLen := round3KATMessageOffset + len(msg) + sigLen
		sm := make([]byte, smLen)
		sm[0] = byte(sigLen >> 8)
		sm[1] = byte(sigLen)
		copy(sm[round3KATSignatureLengthSize:], nonce[:])
		copy(sm[round3KATMessageOffset:], msg)

		sigOffset := round3KATMessageOffset + len(msg)
		sm[sigOffset] = round3KATCompressedSignatureID
		copy(sm[sigOffset+round3KATSignatureHeaderSize:], comp[:written])

		drbg.restore(state)

		katDigestWriteIntLine(h, "count = ", count)
		katDigestWriteHexLine(h, "seed = ", seed[:])
		katDigestWriteIntLine(h, "mlen = ", len(msg))
		katDigestWriteHexLine(h, "msg = ", msg)
		katDigestWriteHexLine(h, "pk = ", pub)
		katDigestWriteHexLine(h, "sk = ", sk)
		katDigestWriteIntLine(h, "smlen = ", smLen)
		katDigestWriteHexLine(h, "sm = ", sm)
		katDigestWriteLine(h, "")
	}

	if got := h.Sum(nil); hex.EncodeToString(got) != "affdeb3aa83bf9a2039fa9c17d65fd3e3b9828e2" {
		t.Fatalf("Round 3 KAT digest mismatch: %x", got)
	}
}

func katDigestWriteLine(h hash.Hash, s string) {
	h.Write([]byte(s))
	h.Write([]byte{'\n'})
}

func katDigestWriteIntLine(h hash.Hash, s string, x int) {
	h.Write([]byte(s))
	if x == 0 {
		h.Write([]byte{'0', '\n'})
		return
	}

	var tmp [30]byte
	i := len(tmp)
	tmp[i-1] = '\n'
	i--
	for x != 0 {
		i--
		tmp[i] = byte('0' + x%10)
		x /= 10
	}
	h.Write(tmp[i:])
}

func katDigestWriteHexLine(h hash.Hash, s string, data []byte) {
	const hextab = "0123456789ABCDEF"

	h.Write([]byte(s))
	var buf [2]byte
	for _, b := range data {
		buf[0] = hextab[b>>4]
		buf[1] = hextab[b&0x0f]
		h.Write(buf[:])
	}
	h.Write([]byte{'\n'})
}
