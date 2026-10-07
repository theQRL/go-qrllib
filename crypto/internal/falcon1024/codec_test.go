package falcon1024

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestPublicKeyCodec(t *testing.T) {
	pub := referencePublicKeyBytes(t)

	t.Run("reference public key", func(t *testing.T) {
		// Derived from the Falcon reference implementation test_falcon.c
		// ntru_pkey_1024 array.
		// Source: https://falcon-sign.info/impl/test_falcon.c.html
		if len(pub) != PublicKeySize {
			t.Fatalf("reference public key length = %d, want %d", len(pub), PublicKeySize)
		}
		if pub[0] != publicKeyHeader {
			t.Fatalf("reference public key header = %#x, want %#x", pub[0], publicKeyHeader)
		}

		h, err := pkDecode(pub)
		if err != nil {
			t.Fatal(err)
		}

		got := make([]byte, PublicKeySize)
		if err := pkEncode(got, h); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pub) {
			t.Fatal("pkEncode(pkDecode(reference public key)) did not round-trip")
		}
	})

	t.Run("rejects invalid input", func(t *testing.T) {
		testCases := []struct {
			name string
			in   []byte
		}{
			{
				name: "short",
				in:   pub[:PublicKeySize-1],
			},
			{
				name: "long",
				in:   append(bytes.Clone(pub), 0),
			},
			{
				name: "invalid header",
				in: func() []byte {
					in := bytes.Clone(pub)
					in[0] ^= 0xff
					return in
				}(),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := pkDecode(tc.in); err == nil {
					t.Fatal("pkDecode accepted invalid public key")
				}
			})
		}
	})

	t.Run("rejects invalid output buffer", func(t *testing.T) {
		h, err := pkDecode(pub)
		if err != nil {
			t.Fatal(err)
		}

		for _, tc := range []struct {
			name string
			out  []byte
		}{
			{
				name: "short",
				out:  make([]byte, PublicKeySize-1),
			},
			{
				name: "long",
				out:  make([]byte, PublicKeySize+1),
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := pkEncode(tc.out, h); err == nil {
					t.Fatal("pkEncode accepted invalid public key buffer")
				}
			})
		}
	})
}

func TestPrivateKeyCodec(t *testing.T) {
	f := mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex)
	g := mustDecodeSmallPolynomialHex(t, ntruSmallG1024Hex)
	ntruF := mustDecodeSmallPolynomialHex(t, ntruF1024Hex)

	sk := make([]byte, PrivateKeySize)
	if err := skEncode(sk, f, g, ntruF); err != nil {
		t.Fatal(err)
	}

	t.Run("reference polynomials", func(t *testing.T) {
		// test_falcon.c publishes component private-key polynomials, not a
		// serialized secret key. Use those reference polynomials to check that our
		// private-key codec round-trips the reference components.
		// Source: https://falcon-sign.info/impl/test_falcon.c.html
		gotF, gotG, gotNTRUF, err := skDecode(sk)
		if err != nil {
			t.Fatal(err)
		}
		if gotF != f || gotG != g || gotNTRUF != ntruF {
			t.Fatal("skDecode(skEncode(reference polynomials)) did not round-trip")
		}
	})

	t.Run("rejects invalid input", func(t *testing.T) {
		testCases := []struct {
			name string
			in   []byte
		}{
			{
				name: "short",
				in:   sk[:PrivateKeySize-1],
			},
			{
				name: "long",
				in:   append(bytes.Clone(sk), 0),
			},
			{
				name: "invalid header",
				in: func() []byte {
					in := bytes.Clone(sk)
					in[0] ^= 0xff
					return in
				}(),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, _, err := skDecode(tc.in); err == nil {
					t.Fatal("skDecode accepted invalid private key")
				}
			})
		}
	})

	t.Run("rejects invalid output buffer", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			out  []byte
		}{
			{
				name: "short",
				out:  make([]byte, PrivateKeySize-1),
			},
			{
				name: "long",
				out:  make([]byte, PrivateKeySize+1),
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := skEncode(tc.out, f, g, ntruF); err == nil {
					t.Fatal("skEncode accepted invalid private key buffer")
				}
			})
		}
	})
}

func TestSignedMessageCodec(t *testing.T) {
	verifyRawKATs := readVerifyRawKATFixture(t).Tests

	t.Run("reference raw s2 vectors", func(t *testing.T) {
		// The s2 vectors are decoded from the Falcon reference implementation
		// KAT_SIG_1024 raw verify vectors. Those raw vectors use a 32-byte hash
		// seed, not the 40-byte nonce the signed message carries, so the seed
		// is zero-extended only to exercise this package's codec.
		// Source: https://falcon-sign.info/impl/test_falcon.c.html
		for _, tc := range verifyRawKATs {
			t.Run(tc.Message, func(t *testing.T) {
				var nonce [nonceSize]byte
				copy(nonce[:], mustDecodeHex(t, tc.NonceHex))
				wantS2 := decodeVerifyRawKATS2(t, mustDecodeHex(t, tc.SignatureHex))
				message := []byte(tc.Message)

				sm, err := signedMessageEncode(nonce, message, wantS2)
				if err != nil {
					t.Fatal(err)
				}

				comp := make([]byte, maxCompressedSignatureSize)
				compLen, err := compressedEncode(comp, wantS2)
				if err != nil {
					t.Fatal(err)
				}
				sigLen := headerSize + compLen
				if want := signedMessagePrefixSize + len(message) + sigLen; len(sm) != want {
					t.Fatalf("signed message length = %d, want %d", len(sm), want)
				}
				if got := int(sm[0])<<8 | int(sm[1]); got != sigLen {
					t.Fatalf("signature length field = %d, want %d", got, sigLen)
				}
				sigOffset := signedMessagePrefixSize + len(message)
				if sm[sigOffset] != signatureHeader {
					t.Fatalf("signature header = %#x, want %#x", sm[sigOffset], signatureHeader)
				}
				if !bytes.Equal(sm[sigOffset+headerSize:], comp[:compLen]) {
					t.Fatal("signed message does not end with the compressed polynomial")
				}

				gotNonce, gotMessage, gotS2, err := signedMessageDecode(sm)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(gotNonce, nonce[:]) {
					t.Fatal("signedMessageDecode returned unexpected nonce")
				}
				if !bytes.Equal(gotMessage, message) {
					t.Fatal("signedMessageDecode returned unexpected message")
				}
				if gotS2 != wantS2 {
					t.Fatal("signedMessageDecode returned unexpected s2")
				}
			})
		}
	})

	tc := verifyRawKATs[0]
	var nonce [nonceSize]byte
	copy(nonce[:], mustDecodeHex(t, tc.NonceHex))
	s2 := decodeVerifyRawKATS2(t, mustDecodeHex(t, tc.SignatureHex))
	message := []byte(tc.Message)
	reference, err := signedMessageEncode(nonce, message, s2)
	if err != nil {
		t.Fatal(err)
	}
	sigOffset := signedMessagePrefixSize + len(message)

	t.Run("rejects invalid input", func(t *testing.T) {
		mutate := func(f func(sm []byte) []byte) []byte { return f(bytes.Clone(reference)) }
		testCases := []struct {
			name string
			in   []byte
		}{
			{name: "nil", in: nil},
			{name: "shorter than the prefix", in: reference[:signedMessagePrefixSize-1]},
			{name: "prefix only", in: reference[:signedMessagePrefixSize]},
			{name: "truncated", in: reference[:len(reference)-1]},
			{name: "signature length beyond the end", in: mutate(func(sm []byte) []byte { sm[1]++; return sm })},
			{name: "signature length of zero", in: mutate(func(sm []byte) []byte { sm[0], sm[1] = 0, 0; return sm })},
			{name: "invalid header", in: mutate(func(sm []byte) []byte { sm[sigOffset] ^= 0xff; return sm })},
			{name: "padded signature header", in: mutate(func(sm []byte) []byte { sm[sigOffset] = 0x30 + logN; return sm })},
			{name: "trailing byte inside the signature", in: mutate(func(sm []byte) []byte {
				sigLen := int(sm[0])<<8 | int(sm[1]) + 1
				sm[0], sm[1] = byte(sigLen>>8), byte(sigLen)
				return append(sm, 0)
			})},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, _, err := signedMessageDecode(tc.in); err == nil {
					t.Fatal("signedMessageDecode accepted invalid signed message")
				}
			})
		}
	})

	t.Run("rejects non-zero trailing bits", func(t *testing.T) {
		// A polynomial whose compressed encoding ends with padding bits.
		var padded smallPolynomial
		padded[0] = 128
		sm, err := signedMessageEncode(nonce, message, padded)
		if err != nil {
			t.Fatal(err)
		}
		sm[len(sm)-1] |= 1
		if _, _, _, err := signedMessageDecode(sm); err == nil {
			t.Fatal("signedMessageDecode accepted non-zero trailing bits")
		}
	})

	t.Run("rejects out-of-range coefficients", func(t *testing.T) {
		var outOfRange smallPolynomial
		outOfRange[0] = maxCompressedCoefficient + 1
		if _, err := signedMessageEncode(nonce, message, outOfRange); !errors.Is(err, errCompressedCoefficientOutOfRange) {
			t.Fatalf("signedMessageEncode error = %v, want %v", err, errCompressedCoefficientOutOfRange)
		}
	})
}

func TestCompressedCodec(t *testing.T) {
	t.Run("reference raw s2 vectors", func(t *testing.T) {
		verifyRawKATs := readVerifyRawKATFixture(t).Tests

		// The expected lengths and digests were derived from the Falcon reference
		// implementation comp_encode applied to KAT_SIG_1024 s2 values.
		// Source: https://falcon-sign.info/impl/test_falcon.c.html
		expected := []struct {
			length int
			digest string
		}{
			{1231, "d44837d1e8addd9a6ff73afd7ff585dc82d17e07e9167dc6a567633acdc4fd92"},
			{1234, "9003f73ea73862807846698a9bf2e7bde2b14e312569324dc42c79f2ba49dab2"},
			{1232, "4937e0c409a0f0811f85047301d07b5db8eb5601265a49fb45aa570a25e9faeb"},
			{1227, "a90b61d2541872c90e3f44b6941c1d719509b0d3a661115cdb244ffaa108f839"},
			{1232, "5ba3c96353176f6e533a8ea6167d31ee50d4eb8b581203407ef8ff32568d0e92"},
			{1230, "2e7da586f788b28435f575119182c775a4b3e4f88acddd1d30c14483d3134a44"},
			{1229, "8be0da517c3ecc50e70156b4bdd620d896c168ad13fd6e94d3a8740fc961d97b"},
			{1229, "e382fc50731f464598e1e8768847a0bd60ce1944bc805cf8452aa870e538edf0"},
			{1232, "7bc474ae78e6f20776ea1682582c841186495fc58ce346ec4102231c00792100"},
			{1229, "1798601e97a4909b0f5291e17734de7ba4f23f6d1666e601912e4ab406cfdf9f"},
		}

		if len(expected) != len(verifyRawKATs) {
			t.Fatalf("expected = %d, verifyRawKATs = %d", len(expected), len(verifyRawKATs))
		}

		for i, tc := range verifyRawKATs {
			t.Run(tc.Message, func(t *testing.T) {
				s2 := decodeVerifyRawKATS2(t, mustDecodeHex(t, tc.SignatureHex))
				dst := make([]byte, maxCompressedSignatureSize)

				written, err := compressedEncode(dst, s2)
				if err != nil {
					t.Fatal(err)
				}
				if written != expected[i].length {
					t.Fatalf("compressed length = %d, want %d", written, expected[i].length)
				}

				digest := sha256.Sum256(dst[:written])
				if got := hex.EncodeToString(digest[:]); got != expected[i].digest {
					t.Fatalf("compressed digest = %s, want %s", got, expected[i].digest)
				}
			})
		}
	})

	t.Run("rejects invalid encode input", func(t *testing.T) {
		outOfRange := smallPolynomial{}
		outOfRange[0] = maxCompressedCoefficient + 1

		testCases := []struct {
			name string
			s2   smallPolynomial
			dst  []byte
			err  error
		}{
			{
				name: "out of range coefficient",
				s2:   outOfRange,
				dst:  make([]byte, maxCompressedSignatureSize),
				err:  errCompressedCoefficientOutOfRange,
			},
			{
				name: "tiny buffer",
				s2:   smallPolynomial{},
				dst:  make([]byte, 1),
				err:  errCompressedSignatureTooLarge,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := compressedEncode(tc.dst, tc.s2); !errors.Is(err, tc.err) {
					t.Fatalf("compressedEncode error = %v, want %v", err, tc.err)
				}
			})
		}
	})

	t.Run("rejects non-zero trailing bits", func(t *testing.T) {
		var s2 smallPolynomial
		s2[0] = 128

		buf := make([]byte, maxCompressedSignatureSize)
		written, err := compressedEncode(buf, s2)
		if err != nil {
			t.Fatal(err)
		}

		buf[written-1] |= 1
		if _, _, err := compressedDecode(buf[:written]); !errors.Is(err, errInvalidSignatureEncoding) {
			t.Fatalf("compressedDecode error = %v, want %v", err, errInvalidSignatureEncoding)
		}
	})

	t.Run("rejects invalid decode input", func(t *testing.T) {
		testCases := []struct {
			name string
			src  []byte
		}{
			{
				name: "truncated",
				src:  nil,
			},
			{
				name: "negative zero",
				src:  []byte{0x80, 0x80},
			},
			{
				name: "coefficient magnitude overflow",
				src:  []byte{0x7f, 0x00, 0x00},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, err := compressedDecode(tc.src); !errors.Is(err, errInvalidSignatureEncoding) {
					t.Fatalf("compressedDecode error = %v, want %v", err, errInvalidSignatureEncoding)
				}
			})
		}
	})
}

func TestTrimI8Encode(t *testing.T) {
	// The expected lengths and digests were derived from the Falcon reference
	// implementation trim_i8_encode applied to test_falcon.c ntru_*_1024 arrays.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	testCases := []struct {
		name   string
		p      smallPolynomial
		bits   int
		length int
		digest string
	}{
		{
			name:   "f",
			p:      mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex),
			bits:   fgBits,
			length: 640,
			digest: "0fd26e919032455f5e3a2c7ed5811cbb7bda70b453a538d18103b3620c082857",
		},
		{
			name:   "g",
			p:      mustDecodeSmallPolynomialHex(t, ntruSmallG1024Hex),
			bits:   fgBits,
			length: 640,
			digest: "b44b290bffb4bdb66b216c88d0de69e0fa877e4035d27e6ebf055d6844d01ee2",
		},
		{
			name:   "F",
			p:      mustDecodeSmallPolynomialHex(t, ntruF1024Hex),
			bits:   ntruFBits,
			length: 1024,
			digest: "b79fd83fac715a2942d4d76ad5c6b8b1ce62a9f35b4cdad78963db5c46c86939",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]byte, n)
			written, err := trimI8Encode(dst, tc.p, tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			if written != tc.length {
				t.Fatalf("trim_i8 length = %d, want %d", written, tc.length)
			}

			digest := sha256.Sum256(dst[:written])
			if got := hex.EncodeToString(digest[:]); got != tc.digest {
				t.Fatalf("trim_i8 digest = %s, want %s", got, tc.digest)
			}
		})
	}
}

func TestTrimI8RoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		p    smallPolynomial
		bits int
	}{
		{
			name: "fg",
			p:    mustDecodeSmallPolynomialHex(t, ntruSmallF1024Hex),
			bits: fgBits,
		},
		{
			name: "ntruF",
			p:    mustDecodeSmallPolynomialHex(t, ntruF1024Hex),
			bits: ntruFBits,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]byte, trimI8Len(tc.bits))
			written, err := trimI8Encode(dst, tc.p, tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			if written != len(dst) {
				t.Fatalf("trimI8Encode wrote %d bytes, want %d", written, len(dst))
			}

			got, consumed, err := trimI8Decode(dst, tc.bits)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != len(dst) {
				t.Fatalf("trimI8Decode consumed %d bytes, want %d", consumed, len(dst))
			}
			if got != tc.p {
				t.Fatal("trimI8Decode(trimI8Encode(p)) did not round-trip")
			}
		})
	}
}

func TestTrimI8EncodeRejectsInvalidInputs(t *testing.T) {
	outOfRange := smallPolynomial{}
	outOfRange[0] = int32(1 << (fgBits - 1))

	testCases := []struct {
		name string
		p    smallPolynomial
		bits int
		dst  []byte
	}{
		{
			name: "invalid bit width",
			bits: 7,
			dst:  make([]byte, trimI8Len(fgBits)),
		},
		{
			name: "short output buffer",
			bits: fgBits,
			dst:  make([]byte, trimI8Len(fgBits)-1),
		},
		{
			name: "out of range coefficient",
			p:    outOfRange,
			bits: fgBits,
			dst:  make([]byte, trimI8Len(fgBits)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := trimI8Encode(tc.dst, tc.p, tc.bits); err == nil {
				t.Fatal("trimI8Encode accepted invalid input")
			}
		})
	}
}

func TestTrimI8DecodeRejectsInvalidInputs(t *testing.T) {
	testCases := []struct {
		name string
		src  []byte
		bits int
	}{
		{
			name: "invalid bit width",
			src:  make([]byte, trimI8Len(fgBits)),
			bits: 7,
		},
		{
			name: "short input",
			src:  make([]byte, trimI8Len(fgBits)-1),
			bits: fgBits,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := trimI8Decode(tc.src, tc.bits); err == nil {
				t.Fatal("trimI8Decode accepted invalid input")
			}
		})
	}
}

func TestTrimI8DecodeRejectsForbiddenValues(t *testing.T) {
	testCases := []struct {
		name string
		bits int
		src  []byte
	}{
		{
			name: "fg",
			bits: fgBits,
			src: func() []byte {
				src := make([]byte, trimI8Len(fgBits))
				src[0] = 0x80 // first 5-bit field is 10000, i.e. forbidden -16.
				return src
			}(),
		},
		{
			name: "ntruF",
			bits: ntruFBits,
			src: func() []byte {
				src := make([]byte, trimI8Len(ntruFBits))
				src[0] = 0x80 // forbidden -128.
				return src
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := trimI8Decode(tc.src, tc.bits); err == nil {
				t.Fatal("trimI8Decode accepted forbidden value")
			}
		})
	}
}

func TestDetachedSignatureCodec(t *testing.T) {
	verifyRawKATs := readVerifyRawKATFixture(t).Tests

	t.Run("reference raw s2 vectors", func(t *testing.T) {
		for _, tc := range verifyRawKATs {
			t.Run(tc.Message, func(t *testing.T) {
				var nonce [nonceSize]byte
				copy(nonce[:], mustDecodeHex(t, tc.NonceHex))
				wantS2 := decodeVerifyRawKATS2(t, mustDecodeHex(t, tc.SignatureHex))

				sig, err := detachedSignatureEncode(nonce, wantS2)
				if err != nil {
					t.Fatal(err)
				}

				comp := make([]byte, maxDetachedCompressedSize)
				compLen, err := compressedEncode(comp, wantS2)
				if err != nil {
					t.Fatal(err)
				}
				if want := detachedSignaturePrefixSize + compLen; len(sig) != want {
					t.Fatalf("detached signature length = %d, want %d", len(sig), want)
				}
				if sig[0] != detachedSignatureHeader {
					t.Fatalf("header = %#x, want %#x", sig[0], detachedSignatureHeader)
				}
				if !bytes.Equal(sig[headerSize:detachedSignaturePrefixSize], nonce[:]) {
					t.Fatal("detached signature does not carry the nonce after the header")
				}
				if !bytes.Equal(sig[detachedSignaturePrefixSize:], comp[:compLen]) {
					t.Fatal("detached signature does not end with the compressed polynomial")
				}

				gotNonce, gotS2, err := detachedSignatureDecode(sig)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(gotNonce, nonce[:]) {
					t.Fatal("detachedSignatureDecode returned unexpected nonce")
				}
				if gotS2 != wantS2 {
					t.Fatal("detachedSignatureDecode returned unexpected s2")
				}
			})
		}
	})

	tc := verifyRawKATs[0]
	var nonce [nonceSize]byte
	copy(nonce[:], mustDecodeHex(t, tc.NonceHex))
	s2 := decodeVerifyRawKATS2(t, mustDecodeHex(t, tc.SignatureHex))
	reference, err := detachedSignatureEncode(nonce, s2)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("rejects invalid input", func(t *testing.T) {
		mutate := func(f func(sig []byte) []byte) []byte { return f(bytes.Clone(reference)) }
		for _, tc := range []struct {
			name string
			in   []byte
		}{
			{name: "nil", in: nil},
			{name: "shorter than the nonce", in: reference[:detachedSignaturePrefixSize-1]},
			{name: "no polynomial", in: reference[:detachedSignaturePrefixSize]},
			{name: "truncated", in: reference[:len(reference)-1]},
			{name: "trailing byte", in: append(bytes.Clone(reference), 0)},
			{name: "signed-message header", in: mutate(func(sig []byte) []byte { sig[0] = signatureHeader; return sig })},
			{name: "constant-time header", in: mutate(func(sig []byte) []byte { sig[0] = 0x50 + logN; return sig })},
			{name: "wrong degree", in: mutate(func(sig []byte) []byte { sig[0] = 0x30 + 9; return sig })},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, err := detachedSignatureDecode(tc.in); err == nil {
					t.Fatal("detachedSignatureDecode accepted invalid signature")
				}
			})
		}
	})

	t.Run("rejects non-zero trailing bits", func(t *testing.T) {
		var padded smallPolynomial
		padded[0] = 128
		sig, err := detachedSignatureEncode(nonce, padded)
		if err != nil {
			t.Fatal(err)
		}
		sig[len(sig)-1] |= 1
		if _, _, err := detachedSignatureDecode(sig); err == nil {
			t.Fatal("detachedSignatureDecode accepted non-zero trailing bits")
		}
	})

	t.Run("rejects out-of-range coefficients", func(t *testing.T) {
		var outOfRange smallPolynomial
		outOfRange[0] = maxCompressedCoefficient + 1
		if _, err := detachedSignatureEncode(nonce, outOfRange); !errors.Is(err, errCompressedCoefficientOutOfRange) {
			t.Fatalf("detachedSignatureEncode error = %v, want %v", err, errCompressedCoefficientOutOfRange)
		}
	})
}
