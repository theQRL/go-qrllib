package falcon1024

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestHashToPointReferenceVectors(t *testing.T) {
	verifyRawKATs := readVerifyRawKATFixture(t).Tests

	// The expected digests were derived from the Falcon reference
	// implementation hash_to_point_vartime applied to KAT_SIG_1024
	// nonce/message pairs. These are Falcon submission/reference vectors, not
	// official NIST/FIPS validation vectors. Digests are over 1024 big-endian
	// uint16 values.
	// Source: https://falcon-sign.info/impl/test_falcon.c.html
	expected := []string{
		"e8332e46eeaa30a54945a14a405fcad8ef8078a87657e50e18248076bab9ecb7",
		"5c8070d70b241263cac562873abc120d7ab1534df58675fd14bf423a3112262a",
		"a8cbf92a0cc62556390ad065413dee950f64823129137b9a9a421eb41b9917b4",
		"c4f713a7bea9306abfcef6c9649ddd7f2e67ecfea8af0d6d1c05818f97175adb",
		"aa27dacdb980b409fbdd42c4677b44ba6fea7dcb7737278e70dd893e1d2e1c39",
		"979a62214e9f56d75c92e47f6dcaaf820142afac083d8e7f9a9c93c97431d214",
		"c9d0d5942821d2f3bf2b3a2357a20725494672390b8c4e44b7f23ac39ce5de45",
		"708ccbe5cb4fbd41e62b19e62d617766db64a72bebe69b86e011ee2bda6430b7",
		"c4ff487ff47d860298beffcf7f2cb5fcf3b3d3cf268ebe4361dd08c27b08fd9c",
		"bbeca2dd0710cdcaad7d573f4a137d93a30ee81f47f8287aa9ff4f7f84d6d039",
	}

	if len(expected) != len(verifyRawKATs) {
		t.Fatalf("expected digests = %d, verifyRawKATs = %d", len(expected), len(verifyRawKATs))
	}

	for i, tc := range verifyRawKATs {
		t.Run(tc.Message, func(t *testing.T) {
			h := sha3.NewSHAKE256()
			_, _ = h.Write(mustDecodeHex(t, tc.NonceHex))
			_, _ = h.Write([]byte(tc.Message))

			p := hashToPoint(h)

			var b [2 * n]byte
			for j, x := range p {
				binary.BigEndian.PutUint16(b[2*j:], uint16(x))
			}
			digest := sha256.Sum256(b[:])
			if got := hex.EncodeToString(digest[:]); got != expected[i] {
				t.Fatalf("hashToPoint digest = %s, want %s", got, expected[i])
			}
		})
	}
}

func TestPolyByteEncodeDecode(t *testing.T) {
	var p ringElement
	for i := range p {
		p[i] = fieldElement((i*i + 17*i + 3) % q)
	}

	var enc [encodingSize14]byte
	polyByteEncode(enc[:], p)

	got, err := polyByteDecode(enc[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatal("polyByteDecode(polyByteEncode(p)) did not round-trip")
	}

	enc[0] = 0xFF
	enc[1] = 0xFC // first 14-bit coefficient is 0x3FFF, which is >= q.
	if _, err := polyByteDecode(enc[:]); err == nil {
		t.Fatal("polyByteDecode accepted coefficient greater than q")
	}

	if _, err := polyByteDecode(enc[:len(enc)-1]); err == nil {
		t.Fatal("polyByteDecode accepted short input")
	}
}

func TestFieldArithmetic(t *testing.T) {
	if got := fieldAdd(q-2, 5); got != 3 {
		t.Fatalf("fieldAdd = %d, want 3", got)
	}
	if got := fieldSub(3, 5); got != q-2 {
		t.Fatalf("fieldSub = %d, want %d", got, q-2)
	}
	if got := fieldMontgomeryMul(1234, 5678); got != 4248 {
		t.Fatalf("fieldMontgomeryMul = %d, want 4248", got)
	}
	if got := fieldCenteredMod(q/2 + 1); got != -6144 {
		t.Fatalf("fieldCenteredMod = %d, want -6144", got)
	}

	t.Run("inverse", func(t *testing.T) {
		for _, x := range []fieldElement{1, 2, 3, 1234, q - 1} {
			invMont := fieldInvMontgomery(x)
			if got := fieldMontgomeryMul(x, invMont); got != 1 {
				t.Fatalf("x * fieldInvMontgomery(%d) = %d, want 1", x, got)
			}
		}
	})

	t.Run("batched inverse", func(t *testing.T) {
		var numerator, denominator, want ringElement
		for i := range numerator {
			numerator[i] = fieldElement((7*i + 5) % q)
			denominator[i] = fieldElement((11*i+3)%(q-1) + 1)
		}
		want = numerator

		for i := range want {
			invMont := fieldInvMontgomery(denominator[i])
			want[i] = fieldMontgomeryMul(want[i], invMont)
		}

		if !divideNTTByBatchedInverse(numerator[:], denominator[:]) {
			t.Fatal("divideNTTByBatchedInverse rejected nonzero denominator")
		}
		if numerator != want {
			t.Fatal("divideNTTByBatchedInverse returned unexpected quotient")
		}

		denominator[17] = 0
		if divideNTTByBatchedInverse(numerator[:], denominator[:]) {
			t.Fatal("divideNTTByBatchedInverse accepted zero denominator")
		}
	})
}

func TestSignatureNormBounds(t *testing.T) {
	if signatureNormExceedsPartialBound(uint32(signatureNormBound), smallPolynomial{}) {
		t.Fatal("signatureNormExceedsPartialBound rejected norm at bound")
	}
	if !signatureNormExceedsPartialBound(uint32(signatureNormBound+1), smallPolynomial{}) {
		t.Fatal("signatureNormExceedsPartialBound accepted norm above bound")
	}

	var s2 smallPolynomial
	s2[0] = 1
	if signatureNormExceedsPartialBound(uint32(signatureNormBound-1), s2) {
		t.Fatal("signatureNormExceedsPartialBound rejected polynomial contribution at bound")
	}
	s2[0] = 3
	if !signatureNormExceedsPartialBound(uint32(signatureNormBound-4), s2) {
		t.Fatal("signatureNormExceedsPartialBound accepted polynomial contribution above bound")
	}

	var s1 smallPolynomial
	// 125^2 + 5889^2 + 5964^2 == signatureNormBound.
	s1[0] = 125
	s1[1] = 5889
	s1[2] = 5964
	if !signatureNormWithinBound(s1, smallPolynomial{}) {
		t.Fatal("signatureNormWithinBound rejected norm at bound")
	}
	s2 = smallPolynomial{}
	s2[0] = 1
	if signatureNormWithinBound(s1, s2) {
		t.Fatal("signatureNormWithinBound accepted norm above bound")
	}
}

func TestNTTRoundTrip(t *testing.T) {
	var p ringElement
	for i := range p {
		p[i] = fieldElement((3*i + 11) % q)
	}
	want := p

	ntt(p[:])
	inverseNTT(p[:])

	if p != want {
		t.Fatal("inverseNTT(ntt(p)) did not round-trip")
	}
}
