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
			s2 := sign(rng, priv, c0)
			if !verifyRaw(c0, s2, pub.hNTT) {
				t.Fatal("sign output failed verifyRaw")
			}
		})
	}
}

func TestSignRound3KATVectors(t *testing.T) {
	// These vectors are derived from Falcon Round 3 submission KATs, not
	// official NIST/FIPS validation vectors.
	// TestFalconRound3KATDigest checks the full 100-case transcript against the
	// Falcon reference digest; this test pins the internal sign output
	// for every KAT case.
	// Source: https://falcon-sign.info/falcon-round3.zip
	testCases := readSignTreeRound3KATVectors(t)

	forEachRound3KATSignInput(t, len(testCases), func(count int, priv *PrivateKey, c0 ringElement, rng *sha3.SHAKE) {
		tc := testCases[count]
		t.Run("count-"+strconv.Itoa(tc.Count), func(t *testing.T) {
			if tc.Count != count {
				t.Fatalf("count = %d, want %d", tc.Count, count)
			}
			s2 := sign(rng, priv, c0)

			pub := priv.PublicKey()
			if !verifyRaw(c0, s2, pub.hNTT) {
				t.Fatal("sign output failed verifyRaw")
			}

			comp := make([]byte, maxCompressedSignatureSize)
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

func forEachRound3KATSignInput(t *testing.T, count int, f func(int, *PrivateKey, ringElement, *sha3.SHAKE)) {
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

		priv, err := NewPrivateKeyFromSeed(keySeed[:])
		if err != nil {
			t.Fatalf("NewPrivateKeyFromSeed: %v", err)
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

// Read lets the DRBG stand in for randombytes: every call is one randombytes
// invocation, which matters because the DRBG reseeds itself after each one.
func (d *nistDRBG) Read(buf []byte) (int, error) {
	d.read(buf)
	return len(buf), nil
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
	// checking its SHA-1 digest. The transcript is produced the way the NIST
	// KAT generator produces it: the DRBG stands in for randombytes, key
	// generation draws its seed from it, and Sign draws the nonce and then
	// the sampler seed from it.
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

		priv, err := GenerateKey(drbg)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		pub := priv.PublicKey()

		sm, err := Sign(drbg, priv, msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if len(sm) > len(msg)+MaxSignedMessageOverhead {
			t.Fatalf("count %d: signed message is %d bytes for a %d-byte message", count, len(sm), len(msg))
		}

		opened, err := Open(pub, sm)
		if err != nil {
			t.Fatalf("count %d: Open: %v", count, err)
		}
		if !bytes.Equal(opened, msg) {
			t.Fatalf("count %d: Open returned a different message", count)
		}

		drbg.restore(state)

		katDigestWriteIntLine(h, "count = ", count)
		katDigestWriteHexLine(h, "seed = ", seed[:])
		katDigestWriteIntLine(h, "mlen = ", len(msg))
		katDigestWriteHexLine(h, "msg = ", msg)
		katDigestWriteHexLine(h, "pk = ", pub.Bytes())
		katDigestWriteHexLine(h, "sk = ", priv.Bytes())
		katDigestWriteIntLine(h, "smlen = ", len(sm))
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

func TestPrivateKeyEncoding(t *testing.T) {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	sk := priv.Bytes()
	if len(sk) != PrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(sk), PrivateKeySize)
	}
	if sk[0] != privateKeyHeader {
		t.Fatalf("private key header = %#x, want %#x", sk[0], privateKeyHeader)
	}
	sk[0] ^= 1
	if bytes.Equal(priv.Bytes(), sk) {
		t.Fatal("Bytes returned the internal buffer")
	}
	sk[0] ^= 1

	decoded, err := NewPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(priv) || !bytes.Equal(decoded.Bytes(), sk) {
		t.Fatal("decoded private key differs from the generated one")
	}
	if !decoded.PublicKey().Equal(priv.PublicKey()) {
		t.Fatal("decoded private key has a different public key")
	}

	// The decoded key must sign identically: G and the expanded basis are
	// recomputed from f, g and F exactly as the reference crypto_sign does.
	randomness := bytes.Repeat([]byte{0x5c}, nonceSize+SeedSize)
	msg := []byte("falcon-1024 private key encoding")
	want, err := Sign(bytes.NewReader(randomness), priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Sign(bytes.NewReader(randomness), decoded, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("decoded private key signs differently")
	}

	zeroF := bytes.Clone(sk)
	clear(zeroF[headerSize : headerSize+trimI8Len(fgBits)])
	badHeader := bytes.Clone(sk)
	badHeader[0] ^= 0xff
	for _, tc := range []struct {
		name string
		sk   []byte
	}{
		{name: "nil", sk: nil},
		{name: "short", sk: sk[:PrivateKeySize-1]},
		{name: "long", sk: append(bytes.Clone(sk), 0)},
		{name: "bad header", sk: badHeader},
		{name: "f not invertible", sk: zeroF},
	} {
		if _, err := NewPrivateKey(tc.sk); err == nil {
			t.Fatalf("NewPrivateKey accepted %s private key", tc.name)
		}
	}

	for _, seed := range [][]byte{nil, make([]byte, SeedSize-1), make([]byte, SeedSize+1)} {
		if _, err := NewPrivateKeyFromSeed(seed); err == nil {
			t.Fatalf("NewPrivateKeyFromSeed accepted a %d-byte seed", len(seed))
		}
	}
}

func TestSignRandomnessOrder(t *testing.T) {
	// Sign draws the 40-byte nonce first and the 48-byte sampler seed second,
	// as the reference crypto_sign calls randombytes, and nothing else.
	priv, err := NewPrivateKeyFromSeed(make([]byte, SeedSize))
	if err != nil {
		t.Fatal(err)
	}

	randomness := make([]byte, nonceSize+SeedSize+1)
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	reader := bytes.NewReader(randomness)
	msg := []byte("falcon-1024 randomness order")
	sm, err := Sign(reader, priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if reader.Len() != 1 {
		t.Fatalf("Sign consumed %d random bytes, want %d", len(randomness)-reader.Len(), nonceSize+SeedSize)
	}
	if !bytes.Equal(sm[signedMessageLengthSize:signedMessagePrefixSize], randomness[:nonceSize]) {
		t.Fatal("signed message nonce is not the first 40 random bytes")
	}
	if !bytes.Equal(sm[signedMessagePrefixSize:signedMessagePrefixSize+len(msg)], msg) {
		t.Fatal("signed message does not carry the message after the nonce")
	}
	sigLen := int(sm[0])<<8 | int(sm[1])
	if sigLen != len(sm)-signedMessagePrefixSize-len(msg) {
		t.Fatalf("signature length field = %d, want %d", sigLen, len(sm)-signedMessagePrefixSize-len(msg))
	}
	if sm[signedMessagePrefixSize+len(msg)] != signatureHeader {
		t.Fatalf("signature header = %#x, want %#x", sm[signedMessagePrefixSize+len(msg)], signatureHeader)
	}

	for _, short := range []int{0, nonceSize - 1, nonceSize, nonceSize + SeedSize - 1} {
		if _, err := Sign(bytes.NewReader(randomness[:short]), priv, msg); err == nil {
			t.Fatalf("Sign succeeded with %d random bytes", short)
		}
	}
}

func TestOpen(t *testing.T) {
	priv, err := NewPrivateKeyFromSeed(make([]byte, SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	other, err := NewPrivateKeyFromSeed(bytes.Repeat([]byte{1}, SeedSize))
	if err != nil {
		t.Fatal(err)
	}

	randomness := bytes.Repeat([]byte{0xa5}, nonceSize+SeedSize)
	for _, msg := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("falcon-1024 open "), 50)} {
		sm, signErr := Sign(bytes.NewReader(randomness), priv, msg)
		if signErr != nil {
			t.Fatal(signErr)
		}
		opened, openErr := Open(pub, sm)
		if openErr != nil {
			t.Fatalf("Open rejected a valid %d-byte message: %v", len(msg), openErr)
		}
		if !bytes.Equal(opened, msg) {
			t.Fatal("Open returned a different message")
		}
		if len(msg) > 0 {
			opened[0] ^= 1
			if sm[signedMessagePrefixSize] == opened[0] {
				t.Fatal("Open returned a slice aliasing the signed message")
			}
		}
		if _, otherErr := Open(other.PublicKey(), sm); otherErr == nil {
			t.Fatal("Open accepted the signed message under another public key")
		}
	}

	msg := []byte("falcon-1024 open rejects")
	sm, err := Sign(bytes.NewReader(randomness), priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	sigOffset := signedMessagePrefixSize + len(msg)

	mutate := func(f func(sm []byte) []byte) []byte { return f(bytes.Clone(sm)) }
	for _, tc := range []struct {
		name string
		sm   []byte
	}{
		{name: "nil", sm: nil},
		{name: "shorter than the prefix", sm: sm[:signedMessagePrefixSize-1]},
		{name: "prefix only", sm: sm[:signedMessagePrefixSize]},
		{name: "signature length beyond the end", sm: mutate(func(sm []byte) []byte { sm[1]++; return sm })},
		{name: "signature length too small", sm: mutate(func(sm []byte) []byte { sm[1]--; return sm })},
		{name: "bad signature header", sm: mutate(func(sm []byte) []byte { sm[sigOffset] ^= 0x10; return sm })},
		{name: "extra byte inside the signature", sm: mutate(func(sm []byte) []byte {
			sigLen := int(sm[0])<<8 | int(sm[1]) + 1
			sm[0], sm[1] = byte(sigLen>>8), byte(sigLen)
			return append(sm, 0)
		})},
		{name: "extra byte after the signature", sm: append(bytes.Clone(sm), 0)},
		{name: "truncated signature", sm: sm[:len(sm)-1]},
		{name: "flipped nonce bit", sm: mutate(func(sm []byte) []byte { sm[signedMessageLengthSize] ^= 1; return sm })},
		{name: "flipped message bit", sm: mutate(func(sm []byte) []byte { sm[signedMessagePrefixSize] ^= 1; return sm })},
		{name: "flipped signature bit", sm: mutate(func(sm []byte) []byte { sm[len(sm)-1] ^= 0x80; return sm })},
	} {
		if _, err := Open(pub, tc.sm); err == nil {
			t.Fatalf("Open accepted a signed message with %s", tc.name)
		}
	}
}

// detachedFromSignedMessage re-encodes the signature a signed message carries
// in the detached format: the same nonce and compressed polynomial under the
// library header byte.
func detachedFromSignedMessage(t *testing.T, sm []byte, msgLen int) []byte {
	t.Helper()
	sigOffset := signedMessagePrefixSize + msgLen
	if sm[sigOffset] != signatureHeader {
		t.Fatalf("signed message signature header = %#x, want %#x", sm[sigOffset], signatureHeader)
	}
	sig := []byte{detachedSignatureHeader}
	sig = append(sig, sm[signedMessageLengthSize:signedMessagePrefixSize]...)
	return append(sig, sm[sigOffset+headerSize:]...)
}

func TestDetachedSignature(t *testing.T) {
	priv, err := NewPrivateKeyFromSeed(make([]byte, SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	other, err := NewPrivateKeyFromSeed(bytes.Repeat([]byte{1}, SeedSize))
	if err != nil {
		t.Fatal(err)
	}

	randomness := make([]byte, nonceSize+SeedSize)
	for i := range randomness {
		randomness[i] = byte(3 * i)
	}

	for _, msg := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("falcon-1024 detached "), 40)} {
		reader := bytes.NewReader(randomness)
		sig, signErr := SignDetached(reader, priv, msg)
		if signErr != nil {
			t.Fatal(signErr)
		}
		if reader.Len() != 0 {
			t.Fatalf("SignDetached consumed %d random bytes, want %d", len(randomness)-reader.Len(), len(randomness))
		}
		if len(sig) < detachedSignaturePrefixSize || len(sig) > MaxSignatureSize {
			t.Fatalf("detached signature length = %d", len(sig))
		}
		if sig[0] != detachedSignatureHeader {
			t.Fatalf("detached signature header = %#x, want %#x", sig[0], detachedSignatureHeader)
		}
		if !bytes.Equal(sig[headerSize:detachedSignaturePrefixSize], randomness[:nonceSize]) {
			t.Fatal("detached signature nonce is not the first 40 random bytes")
		}
		if verifyErr := Verify(pub, msg, sig); verifyErr != nil {
			t.Fatalf("Verify rejected a valid detached signature of a %d-byte message: %v", len(msg), verifyErr)
		}
		if otherErr := Verify(other.PublicKey(), msg, sig); otherErr == nil {
			t.Fatal("Verify accepted the signature under another public key")
		}

		// With the same randomness, Sign embeds the same nonce and polynomial.
		sm, smErr := Sign(bytes.NewReader(randomness), priv, msg)
		if smErr != nil {
			t.Fatal(smErr)
		}
		if want := detachedFromSignedMessage(t, sm, len(msg)); !bytes.Equal(sig, want) {
			t.Fatal("detached signature differs from the signature in the signed message")
		}
	}

	msg := []byte("falcon-1024 detached rejects")
	sig, err := SignDetached(bytes.NewReader(randomness), priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(sig []byte) []byte) []byte { return f(bytes.Clone(sig)) }
	for _, tc := range []struct {
		name string
		msg  []byte
		sig  []byte
	}{
		{name: "nil signature", msg: msg, sig: nil},
		{name: "shorter than the nonce", msg: msg, sig: sig[:detachedSignaturePrefixSize-1]},
		{name: "no polynomial", msg: msg, sig: sig[:detachedSignaturePrefixSize]},
		{name: "signed-message header", msg: msg, sig: mutate(func(sig []byte) []byte { sig[0] = signatureHeader; return sig })},
		{name: "constant-time format header", msg: msg, sig: mutate(func(sig []byte) []byte { sig[0] = 0x50 + logN; return sig })},
		{name: "degree-512 header", msg: msg, sig: mutate(func(sig []byte) []byte { sig[0] = 0x30 + 9; return sig })},
		{name: "trailing byte", msg: msg, sig: append(bytes.Clone(sig), 0)},
		{name: "truncated polynomial", msg: msg, sig: sig[:len(sig)-1]},
		{name: "flipped nonce bit", msg: msg, sig: mutate(func(sig []byte) []byte { sig[headerSize] ^= 1; return sig })},
		{name: "flipped polynomial bit", msg: msg, sig: mutate(func(sig []byte) []byte { sig[len(sig)-1] ^= 0x80; return sig })},
		{name: "different message", msg: []byte("falcon-1024 detached reject"), sig: sig},
	} {
		if err := Verify(pub, tc.msg, tc.sig); err == nil {
			t.Fatalf("Verify accepted %s", tc.name)
		}
	}

	for _, short := range []int{0, nonceSize, nonceSize + SeedSize - 1} {
		if _, err := SignDetached(bytes.NewReader(randomness[:short]), priv, msg); err == nil {
			t.Fatalf("SignDetached succeeded with %d random bytes", short)
		}
	}
}

func TestDetachedSignatureMatchesRound3KATSignedMessages(t *testing.T) {
	// Drive the first KAT entries exactly as TestFalconRound3KATDigest does,
	// and check that SignDetached, given the same randombytes stream, yields
	// the signature the official signed message carries.
	var entropy [SeedSize]byte
	for i := range entropy {
		entropy[i] = byte(i)
	}
	drbg := newNISTDRBG(entropy[:])

	for count := range 8 {
		var seed [SeedSize]byte
		drbg.read(seed[:])
		msg := make([]byte, 33*(count+1))
		drbg.read(msg)

		outer := drbg.save()
		drbg = newNISTDRBG(seed[:])
		priv, err := GenerateKey(drbg)
		if err != nil {
			t.Fatal(err)
		}

		signing := drbg.save()
		sm, err := Sign(drbg, priv, msg)
		if err != nil {
			t.Fatal(err)
		}
		drbg.restore(signing)
		sig, err := SignDetached(drbg, priv, msg)
		if err != nil {
			t.Fatal(err)
		}
		if want := detachedFromSignedMessage(t, sm, len(msg)); !bytes.Equal(sig, want) {
			t.Fatalf("count %d: detached signature differs from the KAT signed message's signature", count)
		}
		if err := Verify(priv.PublicKey(), msg, sig); err != nil {
			t.Fatalf("count %d: Verify: %v", count, err)
		}

		drbg.restore(outer)
	}
}
