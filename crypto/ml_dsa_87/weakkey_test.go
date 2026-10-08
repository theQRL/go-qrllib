package ml_dsa_87

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// forgeWithHints is the strongest signature in the z = 0 family: it
// recomputes w = −c·2^D·t1 exactly as the verifier does, sets a hint on
// every coefficient a single hint can pull back to HighBits 0, and gives up
// if any coefficient cannot be corrected or more than OMEGA hints are
// needed. It returns whether the signature verified at the primitive.
func forgeWithHints(t *testing.T, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8, ctx, msg []uint8) bool {
	t.Helper()
	pre := append([]uint8{0, uint8(len(ctx))}, ctx...)
	var tr [TR_BYTES]uint8
	copy(tr[:], sha3.SumSHAKE256(pk[:], TR_BYTES))
	var mu [CRH_BYTES]uint8
	st := sha3.NewSHAKE256()
	_, _ = st.Write(tr[:])
	_, _ = st.Write(pre)
	_, _ = st.Write(msg)
	_, _ = st.Read(mu[:])
	var w1enc [K * POLY_W1_PACKED_BYTES]uint8
	var cTilde [C_TILDE_BYTES]uint8
	st.Reset()
	_, _ = st.Write(mu[:])
	_, _ = st.Write(w1enc[:])
	_, _ = st.Read(cTilde[:])

	var rho [SEED_BYTES]uint8
	var t1 polyVecK
	unpackPk(&rho, &t1, pk)
	var cp poly
	if err := polyChallenge(&cp, cTilde[:]); err != nil {
		t.Fatalf("polyChallenge: %v", err)
	}
	var w polyVecK
	polyNTT(&cp)
	polyVecKShiftL(&t1)
	polyVecKNTT(&t1)
	polyVecKPointWisePolyMontgomery(&t1, &cp, &t1)
	polyVecKSub(&w, &w, &t1)
	polyVecKReduce(&w)
	polyVecKInvNTTToMont(&w)
	polyVecKCAddQ(&w)

	var h polyVecK
	hints := 0
	for k := 0; k < K; k++ {
		for i := 0; i < N; i++ {
			a := w.vec[k].coeffs[i]
			var a0 int32
			if decompose(&a0, a) == 0 {
				continue
			}
			if useHint(a, 1) != 0 {
				return false
			}
			h.vec[k].coeffs[i] = 1
			hints++
		}
	}
	if hints > OMEGA {
		return false
	}
	var z polyVecL
	var sig [CRYPTO_BYTES]uint8
	if err := packSig(sig[:], cTilde, &z, &h); err != nil {
		return false
	}
	return Verify(ctx, msg, sig, rawPK(*pk))
}

type weakKeyVector struct {
	Name                    string `json:"name"`
	PK                      string `json:"pk"`
	LargeCoefficients       int    `json:"largeCoefficients"`
	Expected                string `json:"expected"`
	ZeroHintForgeryVerifies bool   `json:"zeroHintForgeryVerifies"`
}

// TestValidatePublicKey_Vectors runs the vectors shared with rust-qrllib,
// qrypto.js and wallet.js. For every vector the verdict and the large
// coefficient count must match; keys flagged as forgeable must accept the
// zero-hint signature at the primitive (the FIPS 204 behaviour that makes
// the rule necessary); accepted keys must reject it with and without hints.
func TestValidatePublicKey_Vectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/weak_public_key_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		LargeLow, LargeHighBelowHalf, LargeLowAboveHalf, LargeHigh, MinLargeCoefficients int
		Vectors                                                                          []weakKeyVector
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if doc.LargeLow != t1LargeLow || doc.LargeHighBelowHalf != t1LargeHighBelowHalf || doc.LargeLowAboveHalf != t1LargeLowAboveHalf || doc.LargeHigh != t1LargeHigh || doc.MinLargeCoefficients != t1MinLarge {
		t.Fatal("vector file constants do not match the implementation")
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	ctx, msg := []uint8("ZOND"), []uint8("shared weak-key vectors")
	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			b, err := hex.DecodeString(v.PK)
			if err != nil || len(b) != CRYPTO_PUBLIC_KEY_BYTES {
				t.Fatalf("bad pk hex (len %d, err %v)", len(b), err)
			}
			var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
			copy(pk[:], b)
			var rho [SEED_BYTES]uint8
			var t1 polyVecK
			unpackPk(&rho, &t1, &pk)
			if got := countLargeT1(&t1); got != v.LargeCoefficients {
				t.Fatalf("large count = %d, want %d", got, v.LargeCoefficients)
			}
			err = ValidatePublicKey(&pk)
			switch v.Expected {
			case "accept":
				if err != nil {
					t.Fatalf("expected accept, got %v", err)
				}
				if Verify(ctx, msg, forgeZeroT1Sig(t, &pk, ctx, msg), rawPK(pk)) || forgeWithHints(t, &pk, ctx, msg) {
					t.Fatal("accepted key admits the z = 0 forgery")
				}
			case "weak":
				if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
					t.Fatalf("expected ErrWeakPublicKey, got %v", err)
				}
			default:
				t.Fatalf("unknown expectation %q", v.Expected)
			}
			if v.ZeroHintForgeryVerifies && !Verify(ctx, msg, forgeZeroT1Sig(t, &pk, ctx, msg), rawPK(pk)) {
				t.Fatal("primitive rejected the zero-hint forgery this vector documents")
			}
		})
	}
}

// TestValidatePublicKey_HintBands documents the single-coefficient bands
// the rule is built on: [0,31] and [992,1023] forge with no hints, [32,63]
// and [960,991] forge with hints, everything from 64 to 959 does not. The
// rule rejects all of them, since one coefficient is never enough.
func TestValidatePublicKey_HintBands(t *testing.T) {
	var rho [SEED_BYTES]uint8
	for i := range rho {
		rho[i] = 0x2a
	}
	ctx, msg := []uint8("ZOND"), []uint8("band check")
	cases := []struct {
		v         int32
		noHints   bool
		withHints bool
	}{
		{31, true, true}, {32, false, true}, {63, false, true}, {64, false, false},
		{95, false, false}, {96, false, false}, {927, false, false}, {928, false, false},
		{959, false, false}, {960, false, true}, {991, false, true}, {992, true, true}, {1023, true, true},
	}
	for _, c := range cases {
		var t1 polyVecK
		t1.vec[0].coeffs[0] = c.v
		var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
		packPk(&pk, rho, &t1)
		if got := Verify(ctx, msg, forgeZeroT1Sig(t, &pk, ctx, msg), rawPK(pk)); got != c.noHints {
			t.Errorf("v=%d: zero-hint forgery verified = %v, want %v", c.v, got, c.noHints)
		}
		if got := forgeWithHints(t, &pk, ctx, msg); got != c.withHints {
			t.Errorf("v=%d: hinted forgery verified = %v, want %v", c.v, got, c.withHints)
		}
		if err := ValidatePublicKey(&pk); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
			t.Errorf("v=%d: single coefficient accepted: %v", c.v, err)
		}
	}
}

// TestValidatePublicKey_HonestKeysPass generates keys from fixed seeds and
// checks that every one passes with a large margin over the minimum.
func TestValidatePublicKey_HonestKeysPass(t *testing.T) {
	minCount := K * N
	for i := 0; i < 64; i++ {
		var seed [SEED_BYTES]uint8
		for j := range seed {
			seed[j] = uint8(i*7 + j)
		}
		d, err := NewMLDSA87FromSeed(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		pk := d.GetPK()
		if err := ValidatePublicKey(&pk); err != nil {
			t.Fatalf("seed %d: honest key rejected: %v", i, err)
		}
		var rho [SEED_BYTES]uint8
		var t1 polyVecK
		unpackPk(&rho, &t1, &pk)
		if n := countLargeT1(&t1); n < minCount {
			minCount = n
		}
	}
	if minCount < 1000 {
		t.Fatalf("honest keys have a minimum of %d large coefficients; expected well above 1000", minCount)
	}
}
